"""Redaction and restoration helpers for secrets in configuration documents."""
import logging
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple

import yaml

from controller.services import flow_drafts, profile_manager
from controller.services.flow_step_catalog import secret_param_names
from controller.services.tenant_config import tenant_dir as _tenant_dir

logger = logging.getLogger(__name__)

_REDACTED = profile_manager.REDACTED

_SECRET_S3_KEYS = ("secret_access_key", "access_key_id", "session_token")


def _redact_s3_config(s3_config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Strip credential material from an S3 config before returning it."""
    cfg = dict(s3_config or {})
    for key in _SECRET_S3_KEYS:
        if key in cfg:
            cfg[key] = _REDACTED
    return cfg


def _restore_tenant_s3_secrets(
    stored: Optional[Dict[str, Any]], incoming: Dict[str, Any]
) -> Dict[str, Any]:
    """Replace any secret still redacted with the stored value, so an edit that never revealed a credential cannot
    overwrite it with the sentinel. Returns a new dict; inputs are not mutated."""
    stored = stored or {}
    result = dict(incoming or {})
    for key in _SECRET_S3_KEYS:
        if result.get(key) == _REDACTED:
            if key in stored:
                result[key] = stored[key]
            else:
                # Placeholder for a key that was never stored: drop the sentinel instead of persisting it as a live
                # credential.
                result.pop(key, None)
    return result


# A Dispatcher webhook's url is itself a credential, so both url and secret are redacted from every API response.
_SECRET_WEBHOOK_KEYS = ("url", "secret")


def _redact_dispatcher_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of dispatcher.yaml with webhook url/secret redacted."""
    cfg = dict(config or {})
    hooks = cfg.get("webhooks")
    if isinstance(hooks, list):
        cfg["webhooks"] = [
            {**h, **{k: _REDACTED for k in _SECRET_WEBHOOK_KEYS if k in h}}
            if isinstance(h, dict) else h
            for h in hooks
        ]
    return cfg


def _redact_history(content: str, redact: Callable[[Dict[str, Any]], Dict[str, Any]], config_type: str) -> str:
    """Redact a raw history snapshot. A snapshot that is not a mapping comes back unchanged, and one that cannot be
    parsed comes back empty."""
    try:
        doc = yaml.safe_load(content)
        if not isinstance(doc, dict):
            return content
        return yaml.safe_dump(redact(doc), sort_keys=False)
    except Exception:
        logger.exception("could not redact %s history snapshot", config_type)
        return ""


def _read_stored_doc(tenant_id: str, filename: str, failure_message: str) -> Any:
    """The tenant's document as stored on disk, parsed; {} when it is missing, empty or unreadable."""
    path = _tenant_dir(tenant_id) / filename
    if not path.exists():
        return {}
    try:
        return yaml.safe_load(path.read_text()) or {}
    except (OSError, yaml.YAMLError):
        logger.exception(failure_message, tenant_id)
        return {}


def _restore_dispatcher_secrets(tenant_id: str, config_data: Dict[str, Any]) -> None:
    """Before saving dispatcher.yaml, replace any redacted webhook url or secret with the value currently on disk
    (matched by webhook name), so an edit that never revealed a secret cannot overwrite it with the sentinel."""
    hooks = config_data.get("webhooks")
    if not isinstance(hooks, list):
        return
    doc = _read_stored_doc(tenant_id, "dispatcher.yaml", "dispatcher: could not read existing webhooks for %s")
    stored: Dict[str, Dict[str, Any]] = {}
    for h in doc.get("webhooks", []) or []:
        if isinstance(h, dict) and h.get("name"):
            stored[h["name"]] = h
    for h in hooks:
        if not isinstance(h, dict):
            continue
        prior = stored.get(h.get("name"))
        for key in _SECRET_WEBHOOK_KEYS:
            if h.get(key) == _REDACTED:
                if prior and key in prior:
                    h[key] = prior[key]
                else:
                    # No stored value to restore (e.g. a new webhook), drop so validation can find missing url
                    h.pop(key, None)


# Flow nodes can hold live credentials (configure_accounts admin password, set_firmware_lock password);
# redacting flows.yaml is belt and braces since those are normally escrowed and revealed only via audited reveal.
def _iter_flow_nodes(doc: Any) -> List[Tuple[str, Dict[str, Any]]]:
    """(flow_id, node) for every node in the document, originals not copies."""
    if not isinstance(doc, dict):
        return []
    flows = []
    if isinstance(doc.get("flow"), dict):
        flows.append(doc["flow"])
    if isinstance(doc.get("flows"), list):
        flows.extend(f for f in doc["flows"] if isinstance(f, dict))
    out: List[Tuple[str, Dict[str, Any]]] = []
    for flow in flows:
        fid = str(flow.get("id") or "").strip()
        for node in (flow.get("nodes") or []):
            if isinstance(node, dict):
                out.append((fid, node))
    return out


def _node_secret_names(node: Dict[str, Any]) -> FrozenSet[str]:
    """A node's secret param names; empty for any type the catalog doesn't know. flows.yaml is hand-editable, so the
    type is not necessarily even a string."""
    return secret_param_names(node.get("type"))


def _redact_flow(flow: Any) -> Any:
    """Copy of one flow with every secret node param replaced by the sentinel."""
    if not isinstance(flow, dict) or not isinstance(flow.get("nodes"), list):
        return flow
    nodes = [flow_drafts.redact_node(node) if isinstance(node, dict) else node for node in flow["nodes"]]
    return {**flow, "nodes": nodes}


def _redact_flows_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of flows.yaml with static node passwords redacted."""
    cfg = dict(config or {})
    if isinstance(cfg.get("flow"), dict):
        cfg["flow"] = _redact_flow(cfg["flow"])
    if isinstance(cfg.get("flows"), list):
        cfg["flows"] = [_redact_flow(f) for f in cfg["flows"]]
    return cfg


def _restore_flow_secrets(tenant_id: str, config_data: Dict[str, Any]) -> None:
    """Before saving flows.yaml, replace any redacted node password with the value currently on disk (matched by flow_id
    and node_id), so an edit that never revealed a password cannot overwrite it."""
    incoming = _iter_flow_nodes(config_data)
    if not incoming:
        return
    doc = _read_stored_doc(tenant_id, "flows.yaml", "flows: could not read existing nodes for %s")
    stored: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for flow_id, node in _iter_flow_nodes(doc):
        if node.get("id") and isinstance(node.get("params"), dict):
            stored[(flow_id, str(node["id"]))] = node["params"]
    for flow_id, node in incoming:
        names = _node_secret_names(node)
        params = node.get("params")
        if not names or not isinstance(params, dict):
            continue
        prior = stored.get((flow_id, str(node.get("id")))) or {}
        for key in names:
            if params.get(key) != _REDACTED:
                continue
            if prior.get(key) not in (None, "", _REDACTED):
                params[key] = prior[key]
            else:
                params.pop(key, None)


# Members get profiles.yaml secret payload values (Wi-Fi PSK, 802.1X password, SCEP challenge, PKCS#12
# passphrase) redacted; admins get it as authored. profile_manager decides which keys count as secret.


def _redact_profiles_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of profiles.yaml with secret payload values redacted."""
    cfg = dict(config or {})
    profiles = cfg.get("profiles")
    if not isinstance(profiles, list):
        return cfg
    out = []
    for profile in profiles:
        if not isinstance(profile, dict):
            out.append(profile)
            continue
        item = dict(profile)
        for key in ("payloads", "payload"):
            if item.get(key) not in (None, "", [], {}):
                item[key] = profile_manager._redact_value(item[key], key, [])
        out.append(item)
    cfg["profiles"] = out
    return cfg


_DROP = object()


def _match_prior_payload(item: Any, prior_list: List[Any], index: int) -> Any:
    """The stored counterpart of one incoming payload, matched by PayloadUUID, then PayloadIdentifier, then type and
    display name, then type, then position with a matching type."""
    if isinstance(item, dict):
        for key in ("PayloadUUID", "PayloadIdentifier"):
            want = item.get(key)
            if not want:
                continue
            for prior in prior_list:
                if isinstance(prior, dict) and prior.get(key) == want:
                    return prior
        ptype = item.get("PayloadType")
        if ptype:
            same_type = [p for p in prior_list
                         if isinstance(p, dict) and p.get("PayloadType") == ptype]
            same_name = [p for p in same_type
                         if p.get("PayloadDisplayName") == item.get("PayloadDisplayName")]
            if len(same_name) == 1:
                return same_name[0]
            if len(same_type) == 1:
                return same_type[0]
    if index < len(prior_list):
        prior = prior_list[index]
        if not isinstance(item, dict) or not isinstance(prior, dict):
            return prior
        if item.get("PayloadType") == prior.get("PayloadType"):
            return prior
    return None


def _restore_redacted(incoming: Any, prior: Any) -> Any:
    """incoming with every sentinel replaced by the value at the same place in prior. A sentinel with nothing stored
    behind it is dropped, so the validator sees a missing value instead of a live credential reading ***redacted***."""
    if incoming == _REDACTED:
        return prior if prior not in (None, "", _REDACTED) else _DROP
    if isinstance(incoming, dict):
        prior = prior if isinstance(prior, dict) else {}
        out = {}
        for key, value in incoming.items():
            restored = _restore_redacted(value, prior.get(key))
            if restored is not _DROP:
                out[key] = restored
        return out
    if isinstance(incoming, list):
        prior_list = prior if isinstance(prior, list) else []
        out = []
        for i, value in enumerate(incoming):
            restored = _restore_redacted(
                value, _match_prior_payload(value, prior_list, i))
            if restored is not _DROP:
                out.append(restored)
        return out
    return incoming


def _restore_profile_secrets(tenant_id: str, config_data: Dict[str, Any]) -> None:
    """Before saving profiles.yaml, replace any redacted payload value with the value currently on disk (matched by
    profile id), so an edit that never revealed a secret cannot overwrite it with the sentinel."""
    incoming = config_data.get("profiles")
    if not isinstance(incoming, list):
        return
    doc = _read_stored_doc(tenant_id, "profiles.yaml", "profiles: could not read existing profiles for %s")
    stored: Dict[str, Dict[str, Any]] = {}
    for profile in doc.get("profiles", []) or []:
        if isinstance(profile, dict) and profile.get("id"):
            stored[str(profile["id"])] = profile
    for profile in incoming:
        if not isinstance(profile, dict):
            continue
        prior = stored.get(str(profile.get("id"))) or {}
        for key in ("payloads", "payload"):
            if key in profile:
                restored = _restore_redacted(profile[key], prior.get(key))
                if restored is _DROP:
                    profile.pop(key, None)
                else:
                    profile[key] = restored


_CONFIG_REDACTORS = {
    "dispatcher": _redact_dispatcher_config,
    "flows": _redact_flows_config,
    "profiles": _redact_profiles_config,
}

_SECRET_RESTORERS = {
    "dispatcher": _restore_dispatcher_secrets,
    "flows": _restore_flow_secrets,
    "profiles": _restore_profile_secrets,
}


def config_redactor(config_type: str, is_admin: bool) -> Optional[Callable[[Dict[str, Any]], Dict[str, Any]]]:
    """The redactor for a config type's document read by this caller, or None. Admins read profiles.yaml as authored."""
    if config_type == "profiles" and is_admin:
        return None
    return _CONFIG_REDACTORS.get(config_type)


def redact_config_history(config_type: str, content: str, is_admin: bool) -> str:
    """A history snapshot of a config type redacted the same way as the live document."""
    redact = config_redactor(config_type, is_admin)
    if not content or redact is None:
        return content
    return _redact_history(content, redact, config_type)


def restore_config_secrets(config_type: str, tenant_id: str, config_data: Dict[str, Any]) -> None:
    """Put back every secret an incoming config document carries as the sentinel."""
    restore = _SECRET_RESTORERS.get(config_type)
    if restore is not None:
        restore(tenant_id, config_data)
