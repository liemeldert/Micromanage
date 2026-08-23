import asyncio
import hashlib
import io
import json
import logging
import os
import re
import shutil
import tempfile
import time
import weakref
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Literal, Optional, Tuple

import yaml
from controller.utils.pkg_inspect import inspect_pkg
from controller.utils.yaml_validator import payload_identifier_prefix_error, YAMLValidator

try:
    # Round-trip YAML re-serializes a document without deleting its comments, which never reach the parsed structure.
    # Optional: every write below falls back to pyyaml's safe_dump when it is absent.
    from ruamel.yaml import YAML as RoundTripYAML
except ImportError:  # pragma: no cover - depends on the installed image
    RoundTripYAML = None
from fastapi import (
    FastAPI, HTTPException, Depends, Header, Request, Security, UploadFile, File,
    Query,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, validator
from tortoise.contrib.fastapi import register_tortoise

from controller.api.ids import (
    filter_device_id as _filter_device_id,
    require_uuid as _require_uuid,
)
from controller.auth import (
    ROLE_ADMIN,
    ROLE_MEMBER,
    ROLES,
    DESTRUCTIVE_COMMANDS,
    MEMBER_WRITABLE_CONFIG_TYPES,
)
from controller.auth.dependencies import Principal, get_current_principal, require_admin
from controller.auth.passwords import hash_password, password_policy_error, verify_password
from controller.auth.ratelimit import login_limiter, reveal_limiter, Verdict
from controller.auth.tokens import (
    issue_session_token, JWT_TTL_SECONDS, issue_mfa_pending_token,
    decode_mfa_pending_token
)
from controller.models.database import (
    DATABASE_URL, _pooled_url, database_url_error, schema_status
)
from controller.version import __version__
from controller.models.tenant import (
    Tenant,
    User,
    UserMFA,
    Device,
    Task,
    AppDeployment,
    ProfileDeployment,
    FlowRun,
    Alert,
    EnrollmentAttempt,
    AuditLog,
    DeviceSecret,
)
from controller.services.app_manager import AppManager, S3ConfigError, resolve_s3_settings
from controller.services.mdm_connector import MDMConnector
from controller.services.task_manager import FLOW_RUN_RETENTION_DAYS, TaskManager
from controller.services import enrollment as enrollment_svc, filevault_escrow, readiness, mfa
from controller.services.audit import record_audit, record_device_command, record_tag_change

# Disable the interactive docs by default
_API_DOCS_ENABLED = (os.getenv("MDM_ENABLE_API_DOCS", "") or "").strip().lower() in (
    "1", "true", "yes", "on")

app = FastAPI(
    title="Micromanage API",
    version=__version__,
    docs_url="/docs" if _API_DOCS_ENABLED else None,
    redoc_url="/redoc" if _API_DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _API_DOCS_ENABLED else None,
)

logger = logging.getLogger(__name__)

# ADE/DEP endpoint
from controller.api.dep import router as dep_router  # noqa: E402

app.include_router(dep_router)

from controller.api.ddm import public_router as ddm_public_router  # noqa: E402

app.include_router(ddm_public_router)

from controller.services.tenant_config import (  # noqa: E402
    tenant_dir as _tenant_dir,
    yaml_base as _yaml_base,
)

task_manager = TaskManager()

_cors_origins = [
    o.strip()
    for o in os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Tenant-Id"],
    expose_headers=["Content-Disposition"],
)


@app.on_event("startup")
async def _readiness_boot_check():
    """Log readiness warnings, and stop the process on a fatal one.

    Uses os._exit rather than raising; an unset DATABASE_URL is fatal too, since register_tortoise runs soon after.
    """
    readiness.log_boot_warnings()
    fatal = readiness.boot_error() or database_url_error()
    if fatal:
        logger.critical("Refusing to start: %s", fatal)
        logging.shutdown()
        os._exit(1)


_SECRET_S3_KEYS = ("secret_access_key", "access_key_id", "session_token")

# Precomputed hash used to equalize login timing when the user is missing or has no local password, so response latency
# doesn't reveal account existence.
_DUMMY_PASSWORD_HASH = hash_password("timing-equalization-placeholder")


def _redact_s3_config(s3_config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Strip credential material from an S3 config before returning it."""
    cfg = dict(s3_config or {})
    for key in _SECRET_S3_KEYS:
        if key in cfg:
            cfg[key] = "***redacted***"
    return cfg


_REDACTED = "***redacted***"


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


def _redact_dispatcher_history(content: str) -> str:
    """Redact webhook url/secret from a raw dispatcher.yaml history snapshot so the history-view endpoint can't leak a
    secret the live GET already hides. Fails safe (returns empty) if the snapshot can't be parsed."""
    try:
        doc = yaml.safe_load(content)
        if not isinstance(doc, dict):
            return content
        return yaml.safe_dump(_redact_dispatcher_config(doc), sort_keys=False)
    except Exception:
        logger.exception("could not redact dispatcher history snapshot")
        return ""


def _restore_dispatcher_secrets(tenant_id: str, config_data: Dict[str, Any]) -> None:
    """Before saving dispatcher.yaml, replace any redacted webhook url or secret with the value currently on disk
    (matched by webhook name), so an edit that never revealed a secret cannot overwrite it with the sentinel."""
    hooks = config_data.get("webhooks")
    if not isinstance(hooks, list):
        return
    existing_path = _tenant_dir(tenant_id) / "dispatcher.yaml"
    stored: Dict[str, Dict[str, Any]] = {}
    if existing_path.exists():
        try:
            doc = yaml.safe_load(existing_path.read_text()) or {}
            for h in doc.get("webhooks", []) or []:
                if isinstance(h, dict) and h.get("name"):
                    stored[h["name"]] = h
        except (OSError, yaml.YAMLError):
            logger.exception("dispatcher: could not read existing webhooks for %s", tenant_id)
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
@lru_cache(maxsize=1)
def _flow_secret_params() -> Dict[str, FrozenSet[str]]:
    """Node type -> the param names flow_step_catalog marks secret.

    Derived from the catalog's accessor so this and services.flow_drafts cannot disagree on which params are secret."""
    from controller.services.flow_step_catalog import (
        FLOW_STEP_CATALOG, secret_param_names,
    )

    by_type = {}
    for entry in FLOW_STEP_CATALOG:
        names = secret_param_names(entry["type"])
        if names:
            by_type[entry["type"]] = names
    return by_type


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
    node_type = node.get("type")
    if not isinstance(node_type, str):
        return frozenset()
    return _flow_secret_params().get(node_type) or frozenset()


def _redact_flow(flow: Any) -> Any:
    """Copy of one flow with every secret node param replaced by the sentinel."""
    if not isinstance(flow, dict) or not isinstance(flow.get("nodes"), list):
        return flow
    nodes = []
    for node in flow["nodes"]:
        params = node.get("params") if isinstance(node, dict) else None
        hits = ([k for k in _node_secret_names(node) if params.get(k)]
                if isinstance(params, dict) else [])
        if not hits:
            nodes.append(node)
            continue
        nodes.append({**node, "params": {**params, **{k: _REDACTED for k in hits}}})
    return {**flow, "nodes": nodes}


def _redact_flows_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of flows.yaml with static node passwords redacted."""
    cfg = dict(config or {})
    if isinstance(cfg.get("flow"), dict):
        cfg["flow"] = _redact_flow(cfg["flow"])
    if isinstance(cfg.get("flows"), list):
        cfg["flows"] = [_redact_flow(f) for f in cfg["flows"]]
    return cfg


def _redact_flows_history(content: str) -> str:
    """Redact static node passwords from a raw flows.yaml history snapshot, so an old version can't hand out a password
    the live GET hides. Fails safe (returns empty) if the snapshot can't be parsed."""
    try:
        doc = yaml.safe_load(content)
        if not isinstance(doc, dict):
            return content
        return yaml.safe_dump(_redact_flows_config(doc), sort_keys=False)
    except Exception:
        logger.exception("could not redact flows history snapshot")
        return ""


def _restore_flow_secrets(tenant_id: str, config_data: Dict[str, Any]) -> None:
    """Before saving flows.yaml, replace any redacted node password with the value currently on disk (matched by flow_id
    and node_id), so an edit that never revealed a password cannot overwrite it."""
    incoming = _iter_flow_nodes(config_data)
    if not incoming:
        return
    existing_path = _tenant_dir(tenant_id) / "flows.yaml"
    stored: Dict[Tuple[str, str], Dict[str, Any]] = {}
    if existing_path.exists():
        try:
            doc = yaml.safe_load(existing_path.read_text()) or {}
            for flow_id, node in _iter_flow_nodes(doc):
                if node.get("id") and isinstance(node.get("params"), dict):
                    stored[(flow_id, str(node["id"]))] = node["params"]
        except (OSError, yaml.YAMLError):
            logger.exception("flows: could not read existing nodes for %s", tenant_id)
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
    from controller.services.profile_manager import _redact_value

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
                item[key] = _redact_value(item[key], key, [])
        out.append(item)
    cfg["profiles"] = out
    return cfg


def _redact_profiles_history(content: str) -> str:
    """Redact payload secrets from a raw profiles.yaml history snapshot. Fails safe (returns empty) if the snapshot
    can't be parsed."""
    try:
        doc = yaml.safe_load(content)
        if not isinstance(doc, dict):
            return content
        return yaml.safe_dump(_redact_profiles_config(doc), sort_keys=False)
    except Exception:
        logger.exception("could not redact profiles history snapshot")
        return ""


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
    existing_path = _tenant_dir(tenant_id) / "profiles.yaml"
    stored: Dict[str, Dict[str, Any]] = {}
    if existing_path.exists():
        try:
            doc = yaml.safe_load(existing_path.read_text()) or {}
            for profile in doc.get("profiles", []) or []:
                if isinstance(profile, dict) and profile.get("id"):
                    stored[str(profile["id"])] = profile
        except (OSError, yaml.YAMLError):
            logger.exception("profiles: could not read existing profiles for %s", tenant_id)
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


def _atomic_write_yaml(path: Path, data: Dict[str, Any],
                       text: Optional[str] = None) -> None:
    """Write YAML to path atomically (write temp + os.replace).

    A supplied text is written verbatim to keep comments; otherwise data is dumped with sort_keys=False.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        if text is not None:
            f.write(text)
        else:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
    os.replace(tmp, path)


def _round_trip_yaml(source: str):
    """A ruamel handler indented the way source is, so a save does not reformat the whole document."""
    sequence, offset = 4, 2
    try:
        from ruamel.yaml.util import load_yaml_guess_indent
        _doc, guessed, guessed_offset = load_yaml_guess_indent(source)
        if guessed:
            sequence = guessed
        if guessed_offset is not None:
            offset = guessed_offset
    except Exception:
        # Only the indent width is at stake here, so the defaults are a fine answer.
        pass
    handler = RoundTripYAML()
    handler.preserve_quotes = True
    handler.width = 4096
    handler.indent(mapping=2, sequence=sequence, offset=offset)
    return handler


def _sequences_align(current: List[Any], incoming: List[Any]) -> bool:
    """True if two lists describe the same items in the same order.

    Only then is a per-item merge safe; otherwise the caller replaces the list outright.
    """
    if len(current) != len(incoming):
        return False
    for existing_item, new_item in zip(current, incoming):
        if not isinstance(existing_item, dict) or not isinstance(new_item, dict):
            return False
        for key in ("id", "name"):
            if existing_item.get(key) != new_item.get(key):
                return False
    return True


def _apply_mapping(target: Dict[str, Any], incoming: Dict[str, Any]) -> None:
    """Overwrite target with incoming in place, reusing the existing nodes, and their comments, wherever the two agree.
    """
    for key, value in incoming.items():
        current = target.get(key)
        if isinstance(value, dict) and isinstance(current, dict):
            _apply_mapping(current, value)
        elif (isinstance(value, list) and isinstance(current, list)
              and _sequences_align(current, value)):
            for existing_item, new_item in zip(current, value):
                _apply_mapping(existing_item, new_item)
        else:
            target[key] = value
    for key in [k for k in target if k not in incoming]:
        del target[key]


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses a mapping with a repeated key.

    pyyaml's default loader silently keeps only the last of a set of duplicate keys.
    """


def _no_duplicate_keys(loader, node, deep=False):
    seen = set()
    for key_node, _value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in seen
        except TypeError:  # unhashable key; SafeConstructor reports it below
            duplicate = False
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                f"found a duplicate key: {key!r}", key_node.start_mark)
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    lambda loader, node: _no_duplicate_keys(loader, node),
)


def _same_document(parsed: Any, data: Any) -> bool:
    """True if two parsed documents are the same document, types included.

    Python's == reads True as 1 and 1 as 1.0. Dumping both and comparing the text keeps those apart.
    """
    try:
        return (yaml.safe_dump(parsed, sort_keys=True, default_flow_style=False)
                == yaml.safe_dump(data, sort_keys=True, default_flow_style=False))
    except yaml.YAMLError:
        # Something in one of them has no safe representation, so they cannot be shown to be the same document.
        return False


def _round_trip_render(source: str, data: Dict[str, Any]) -> Optional[str]:
    """data rendered into the layout and comments of source, or None if the round trip could not be proven faithful
    (caller falls back to a plain dump; a document that keeps comments but not contents is worse than one with neither).
    """
    if RoundTripYAML is None:
        return None
    handler = _round_trip_yaml(source)
    try:
        document = handler.load(source)
    except Exception:
        logger.exception("config: round-trip load failed")
        return None
    if not isinstance(document, dict):
        return None
    buffer = io.StringIO()
    try:
        _apply_mapping(document, data)
        handler.dump(document, buffer)
    except Exception:
        logger.exception("config: round-trip render failed")
        return None
    rendered = buffer.getvalue()
    try:
        if _same_document(yaml.safe_load(rendered), data):
            return rendered
    except yaml.YAMLError:
        pass
    logger.warning("config: round-trip render did not reproduce the saved "
                   "document; writing a plain dump instead")
    return None


def _config_document_text(path: Path, data: Dict[str, Any],
                          yaml_text: Optional[str] = None) -> Optional[str]:
    """The exact text to write for data, keeping its comments.

    Tries the client-submitted text, then the on-disk text, then a ruamel.yaml round trip, in that order.
    """
    on_disk = None
    try:
        if path.exists():
            on_disk = path.read_text(encoding="utf-8")
    except (OSError, ValueError):
        logger.exception("config: cannot read %s for its comments", path)
    for source in (yaml_text, on_disk):
        if not source:
            continue
        try:
            parsed = yaml.load(source, Loader=_StrictLoader)
        except yaml.YAMLError:
            # Unparseable, or parseable only by taking one of a pair of duplicate keys. Either way it is not usable as a
            # rendering of anything.
            continue
        if _same_document(parsed, data):
            return source
        if not isinstance(parsed, dict):
            continue
        rendered = _round_trip_render(source, data)
        if rendered is not None:
            return rendered
    return None


def _tenant_config_doc(
    tenant: Tenant, existing: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """The config.yaml mirror of a tenant row, merged onto existing.

    Every key the sync loop (controller/main.py) reads back must be written here, or the field resets on the next tick.
    """
    doc = dict(existing or {})
    tcfg = dict(doc.get("tenant") or {})
    tcfg["id"] = tenant.id
    tcfg["name"] = tenant.name
    tcfg["allowed_users"] = list(tenant.allowed_users or [])
    tcfg["s3"] = tenant.s3_config or {}
    tcfg["dep"] = {**(tcfg.get("dep") or {}), "enabled": tenant.dep_enabled}
    tcfg["ddm"] = {**(tcfg.get("ddm") or {}), "enabled": tenant.ddm_enabled}
    tcfg["device_naming"] = tenant.device_naming or {}
    doc["tenant"] = tcfg
    return doc


def _truthy(value: Any) -> bool:
    """Interpret a command parameter (usually a string) as a boolean."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes", "on")


def _os_at_least(os_version: Optional[str], major: int) -> bool:
    """True if the device OS major version is >= major (False if unparseable)."""
    from packaging import version
    try:
        return version.parse(str(os_version or "")).major >= major
    except Exception:
        return False


# ReturnToService floors by model identifier prefix (iOS/iPadOS 17, tvOS 18, visionOS 26; never macOS/watchOS).
# https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/device.erase.yaml

_RTS_FLOORS = (
    ("iphone", "iOS", 17),
    ("ipad", "iPadOS", 17),
    ("ipod", "iOS", 17),
    ("appletv", "tvOS", 18),
    ("realitydevice", "visionOS", 26),
    ("watch", "watchOS", None),
)


def _rts_floor(device_model: Optional[str]) -> tuple:
    """(platform name, first OS major that has Return to Service)."""
    model = (device_model or "").lower().replace(" ", "")
    for prefix, platform, floor in _RTS_FLOORS:
        if model.startswith(prefix):
            return platform, floor
    # MacBook*, Macmini, MacPro, iMac, Mac14,2 and anything else with mac in it.
    if "mac" in model:
        return "macOS", None
    return None, None


# Stable identifiers for the Return-to-Service warnings, paired with the sentences below by position. The sentences are
# written for a person and may be reworded; these codes are the contract and do not change.
RTS_WARNING_NO_WIFI = "no_wifi"
RTS_WARNING_ACTIVATION_LOCK = "activation_lock"


def _rts_warnings(attributes: Dict[str, Any], wifi_ssid: str) -> List[tuple]:
    """What could make a Return-to-Service wipe fail, as (code, sentence) pairs in reading order.

    Both are conditional (warn, not refuse): Wi-Fi is only required when the device has no Ethernet/cellular.
    https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/device.erase.yaml
    """
    warnings: List[tuple] = []
    if not wifi_ssid:
        warnings.append((
            RTS_WARNING_NO_WIFI,
            "No Wi-Fi network was given. The wiped device will only get back to "
            "the server if it has Ethernet or cellular; otherwise it stops at "
            "setup with no way to re-enroll.",
        ))
    if attributes.get("IsActivationLockEnabled") is True:
        warnings.append((
            RTS_WARNING_ACTIVATION_LOCK,
            "Activation Lock is on for this device. It has to be turned off "
            "before the wipe, or the device stops at the activation screen and "
            "cannot re-enroll.",
        ))
    return warnings


# Base models
class LoginRequest(BaseModel):
    tenant_id: str
    user_email: str
    password: str


class UserCreate(BaseModel):
    email: str
    password: Optional[str] = None
    role: str = ROLE_MEMBER
    external_id: Optional[str] = None


class UserUpdate(BaseModel):
    password: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class TokenResponse(BaseModel):
    access_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: Optional[int] = None
    mfa_required: bool = False
    mfa_token: Optional[str] = None


class MFAVerifyRequest(BaseModel):
    mfa_token: str
    code: str


class MFAConfirmRequest(BaseModel):
    code: str


class MFADisableRequest(BaseModel):
    password: str


class TenantUpdate(BaseModel):
    name: Optional[str] = None
    allowed_users: Optional[List[str]] = None
    s3_config: Optional[Dict[str, Any]] = None
    dep_enabled: Optional[bool] = None
    ddm_enabled: Optional[bool] = None
    is_active: Optional[bool] = None
    # Tenant-default device-naming template applied at enrollment (services.naming):
    # {"template": "IT-{serial}", "apply_on_enroll": bool}. An empty dict clears it.
    device_naming: Optional[Dict[str, Any]] = None
    # Reverse-DNS base for composed PayloadIdentifiers ("com.acme.mdm")
    payload_identifier_prefix: Optional[str] = None

    apns_cert_expires_at: Optional[datetime] = None
    dep_token_expires_at: Optional[datetime] = None

    @validator("apns_cert_expires_at", "dep_token_expires_at", pre=True)
    def _coerce_bare_date(cls, v):
        """Accept a bare "YYYY-MM-DD" and an empty string, meaning no date, alongside a full ISO datetime. Pydantic v1's
        parser rejects both outright."""
        if isinstance(v, str):
            if not v.strip():
                return None
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
                return f"{v}T00:00:00Z"
        return v


class CommandRequest(BaseModel):
    command_type: str
    parameters: Dict[str, Any] = {}


# Auth endpoints
@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest, http_request: Request):
    """Authenticate a local user (email + password) and return a session token.

    Tenants on an external provider (OIDC) do not use this endpoint; their clients present a provider token directly.
    """
    throttle_key = f"{request.tenant_id}:{request.user_email}"
    if not login_limiter.check(throttle_key):
        raise HTTPException(status_code=429, detail="Too many attempts; try again later")

    # Generic to avoid enumeration
    invalid = HTTPException(status_code=401, detail="Invalid credentials")

    tenant = await Tenant.get_or_none(id=request.tenant_id)
    if not tenant or not tenant.is_active:
        raise invalid

    if tenant.auth_provider != "local":
        # Same generic refusal as a missing tenant: naming the provider would tell an anonymous caller that the tenant
        # exists and which IdP it sits behind. /api/v1/auth/discover answers that question for clients that need it.
        raise invalid

    user = await User.get_or_none(tenant=tenant, email=request.user_email)
    if user and user.is_active and user.password_hash:
        ok = verify_password(request.password, user.password_hash)
    else:
        # Always do the bcrypt work so timing doesn't show if a user exists
        verify_password(request.password, _DUMMY_PASSWORD_HASH)
        ok = False
    if not ok:
        raise invalid

    if await mfa.is_enabled(user):
        return TokenResponse(
            access_token=None,
            expires_in=None,
            mfa_required=True,
            mfa_token=issue_mfa_pending_token(user_id=str(user.id), tenant_id=tenant.id)
        )

    token = issue_session_token(
        user_id=str(user.id), tenant_id=tenant.id, email=user.email, role=user.role
    )
    return TokenResponse(access_token=token, expires_in=JWT_TTL_SECONDS)


@app.post("/api/v1/auth/mfa/verify", response_model=TokenResponse)
async def verify_mfa_login(request: MFAVerifyRequest, http_request: Request):
    claims = decode_mfa_pending_token(request.mfa_token)
    invalid = HTTPException(status_code=401, detail="Invalid credentials")
    if not claims:
        raise invalid

    user_id = claims["sub"]
    # Throttle based on user_id from the verified token
    if not login_limiter.check(str(user_id)):
        raise HTTPException(status_code=429, detail="Too many attempts; try again later")

    user = await User.get_or_none(id=user_id)
    if not user or not user.is_active:
        raise invalid

    if await mfa.verify_code(user, request.code):
        pass
    elif await mfa.verify_recovery_code(user, request.code):
        pass
    else:
        raise invalid

    token = issue_session_token(
        user_id=str(user.id), tenant_id=user.tenant_id, email=user.email, role=user.role
    )
    return TokenResponse(access_token=token, expires_in=JWT_TTL_SECONDS)


@app.post("/api/v1/auth/mfa/enroll")
async def enroll_mfa(principal: Principal = Depends(get_current_principal)):
    try:
        secret, uri = await mfa.begin_enrollment(principal.user)
        return {"secret": secret, "provisioning_uri": uri}
    except ValueError:
        raise HTTPException(status_code=409, detail="MFA is already confirmed")


@app.post("/api/v1/auth/mfa/confirm")
async def confirm_mfa(request: MFAConfirmRequest, principal: Principal = Depends(get_current_principal)):
    codes = await mfa.confirm_enrollment(principal.user, request.code)
    if codes is None:
        raise HTTPException(status_code=400, detail="Invalid code")

    await record_audit(
        principal,
        "user.mfa_confirm",
        target_id=str(principal.user.id),
        detail={}
    )
    return {"recovery_codes": codes}


@app.delete("/api/v1/auth/mfa", status_code=204)
async def disable_mfa(request: MFADisableRequest, principal: Principal = Depends(get_current_principal)):
    if principal.tenant.auth_provider != "local":
        raise HTTPException(status_code=400, detail="Cannot disable MFA for external provider")

    if not principal.user.password_hash or not verify_password(request.password, principal.user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")

    await mfa.disable(principal.user)

    await record_audit(
        principal,
        "user.mfa_disable",
        target_id=str(principal.user.id),
        detail={}
    )
    return Response(status_code=204)


@app.get("/api/v1/auth/mfa")
async def get_mfa_status(principal: Principal = Depends(get_current_principal)):
    mfa_record = await UserMFA.filter(user_id=principal.user.id).first()
    if mfa_record and mfa_record.confirmed_at:
        return {
            "enabled": True,
            "confirmed_at": mfa_record.confirmed_at.isoformat(),
            "recovery_codes_remaining": len(mfa_record.recovery_codes or [])
        }
    return {
        "enabled": False,
        "confirmed_at": None,
        "recovery_codes_remaining": 0
    }


@app.get("/api/v1/auth/me")
async def whoami(principal: Principal = Depends(get_current_principal)):
    """The authenticated principal: tenant, email, role, and whether it holds the admin role."""
    return {
        "tenant_id": principal.tenant.id,
        "email": principal.email,
        "role": principal.role,
        "is_admin": principal.is_admin,
        "has_password": bool(getattr(principal.user, "password_hash", None)),
    }


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


@app.post("/api/v1/auth/password", response_model=TokenResponse)
async def change_own_password(
    request: PasswordChangeRequest,
    principal: Principal = Depends(get_current_principal),
):
    """Change the signed-in user's own password after verifying the current one, ending every other session for
    the account."""
    tenant = principal.tenant
    if tenant.auth_provider != "local":
        raise HTTPException(
            status_code=400,
            detail=f"Tenant uses '{tenant.auth_provider}' authentication; "
                   f"passwords are managed by that provider",
        )
    user = principal.user
    if user is None or not user.password_hash:
        raise HTTPException(status_code=400, detail="This account has no local password")
    # Same limiter as sign-in: this route also confirms whether a given password is the right one.
    throttle_key = f"{tenant.id}:{user.email}"
    if not login_limiter.check(throttle_key):
        raise HTTPException(status_code=429, detail="Too many attempts; try again later")
    if not verify_password(request.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    problem = password_policy_error(request.new_password)
    if problem:
        raise HTTPException(status_code=400, detail=problem)
    if request.new_password == request.current_password:
        raise HTTPException(status_code=400, detail="New password must differ from the current one")

    user.password_hash = hash_password(request.new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    await user.save(update_fields=["password_hash", "password_changed_at"])
    await record_audit(
        principal, "user.password_change", target_type="user", target_id=str(user.id),
        detail={"email": user.email, "self": True},
    )
    token = issue_session_token(
        user_id=str(user.id), tenant_id=tenant.id, email=user.email, role=user.role
    )
    return TokenResponse(access_token=token, expires_in=JWT_TTL_SECONDS)


class DiscoverRequest(BaseModel):
    email: str


@app.post("/api/v1/auth/discover")
async def discover_login(request: DiscoverRequest, http_request: Request):
    """Look up which tenants an email address can sign in to and how, confirming to any caller that the address
    has access."""
    email = request.email.strip().lower()
    if not email or not login_limiter.check(f"discover:{email}"):
        raise HTTPException(status_code=429, detail="Too many attempts; try again later")

    users = await User.filter(email__iexact=email, is_active=True).prefetch_related("tenant")
    tenants = []
    for u in users:
        t = u.tenant
        if not t.is_active:
            continue
        cfg = t.auth_config or {}
        entry = {"tenant_id": t.id, "name": t.name, "provider": t.auth_provider}
        # External IdP tenants may configure where a client goes to obtain a provider token.
        if t.auth_provider != "local" and cfg.get("login_url"):
            entry["login_url"] = cfg["login_url"]
        tenants.append(entry)

    return {"tenants": tenants}


# User management (admin only)
@app.get("/api/v1/users")
async def list_users(admin: Principal = Depends(require_admin)):
    users = await User.filter(tenant=admin.tenant).all()
    return {
        "users": [
            {
                "id": str(u.id),
                "email": u.email,
                "role": u.role,
                "is_active": u.is_active,
                "has_password": bool(u.password_hash),
                "external_id": u.external_id,
            }
            for u in users
        ]
    }


@app.post("/api/v1/users", status_code=201)
async def create_user(payload: UserCreate, admin: Principal = Depends(require_admin)):
    if payload.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {sorted(ROLES)}")
    if await User.get_or_none(tenant=admin.tenant, email=payload.email):
        raise HTTPException(status_code=409, detail="User already exists")
    if admin.tenant.auth_provider == "local" and not payload.password:
        raise HTTPException(status_code=400, detail="password required for local-auth tenants")
    if payload.password is not None:
        problem = password_policy_error(payload.password)
        if problem:
            raise HTTPException(status_code=400, detail=problem)

    user = await User.create(
        tenant=admin.tenant,
        email=payload.email,
        role=payload.role,
        external_id=payload.external_id,
        password_hash=hash_password(payload.password) if payload.password else None,
        # Stamped from the outset so the column means when the current password was set, not whether it has ever been
        # replaced. Nothing predates it, so no live session is cut off.
        password_changed_at=(datetime.now(timezone.utc) if payload.password else None),
    )
    await record_audit(
        admin,
        "user.create",
        target_type="user",
        target_id=str(user.id),
        # Non-secret facts only: never the password itself.
        detail={
            "email": user.email,
            "role": user.role,
            "password_set": bool(payload.password),
            "external_id_set": bool(payload.external_id),
        },
    )
    return {"id": str(user.id), "email": user.email, "role": user.role}


@app.put("/api/v1/users/{user_id}")
async def update_user(user_id: str, payload: UserUpdate, admin: Principal = Depends(require_admin)):
    _require_uuid(user_id, "User not found")
    user = await User.get_or_none(id=user_id, tenant=admin.tenant)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if payload.role is not None:
        if payload.role not in ROLES:
            raise HTTPException(status_code=400, detail=f"role must be one of {sorted(ROLES)}")
        # lol I accidentally did this on accident
        if user.role == ROLE_ADMIN and payload.role != ROLE_ADMIN:
            if str(user.id) == str(admin.user.id):
                raise HTTPException(
                    status_code=400, detail="Cannot change your own role",
                )
            remaining_admins = await User.filter(
                tenant=admin.tenant, role=ROLE_ADMIN, is_active=True,
            ).exclude(id=user.id).count()
            if remaining_admins == 0:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot demote the last active admin in this tenant",
                )
        user.role = payload.role
    if payload.password is not None:
        problem = password_policy_error(payload.password)
        if problem:
            raise HTTPException(status_code=400, detail=problem)
        user.password_hash = hash_password(payload.password)
        # Stored to invalidate all existing sessions
        user.password_changed_at = datetime.now(timezone.utc)
    if payload.is_active is not None:
        # Don't let an admin deactivate themselves
        if not payload.is_active and str(user.id) == str(admin.user.id):
            raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
        if not payload.is_active and user.role == ROLE_ADMIN:
            remaining_admins = await User.filter(
                tenant=admin.tenant, role=ROLE_ADMIN, is_active=True,
            ).exclude(id=user.id).count()
            if remaining_admins == 0:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot deactivate the last active admin in this tenant",
                )
        user.is_active = payload.is_active
    await user.save()
    # Record which fields changed, as booleans. Never the new password itself.
    changed = {
        "role": payload.role is not None,
        "password": payload.password is not None,
        "is_active": payload.is_active is not None,
    }
    await record_audit(
        admin,
        "user.update",
        target_type="user",
        target_id=str(user.id),
        detail={"email": user.email, "changed": changed},
    )
    return {"message": "User updated"}


@app.delete("/api/v1/users/{user_id}")
async def delete_user(user_id: str, admin: Principal = Depends(require_admin)):
    _require_uuid(user_id, "User not found")
    user = await User.get_or_none(id=user_id, tenant=admin.tenant)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if str(user.id) == str(admin.user.id):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    deleted_email = user.email  # captured before deletion for the audit log
    deleted_role = user.role
    await user.delete()
    await record_audit(
        admin,
        "user.delete",
        target_type="user",
        target_id=user_id,
        detail={"email": deleted_email, "role": deleted_role},
    )
    return {"message": "User deleted"}


# Tenant management
@app.get("/api/v1/tenant", response_model=Dict[str, Any])
async def get_tenant_info(principal: Principal = Depends(get_current_principal)):
    """The caller's tenant: settings, feature flags and renewal reminders, with the S3 credentials redacted.
    Member-readable."""
    tenant = principal.tenant
    return {
        "id": tenant.id,
        "name": tenant.name,
        "allowed_users": tenant.allowed_users,
        "s3_config": _redact_s3_config(tenant.s3_config),
        # Read-only here: the operator sets it (tenant_cli tenant set-quota).
        "storage_quota_bytes": AppManager(tenant).storage_quota_bytes(),
        "auth_provider": tenant.auth_provider,
        "dep_enabled": tenant.dep_enabled,
        "ddm_enabled": tenant.ddm_enabled,
        "created_at": tenant.created_at,
        "is_active": tenant.is_active,
        # Admin-entered renewal reminders (manual-entry MVP; see models.tenant).
        "apns_cert_expires_at": tenant.apns_cert_expires_at,
        "dep_token_expires_at": tenant.dep_token_expires_at,
        "device_naming": tenant.device_naming or {},
        # Null when the built-in "com.mdm.<tenant id>" base is in use.
        "payload_identifier_prefix": tenant.payload_identifier_prefix,
        # Whether FileVault recovery-key escrow is set up, plus the certificate expiry. Booleans and dates only; the
        # private key never leaves the server and the certificate is fetched separately.
        "filevault_escrow": {
            "configured": filevault_escrow.is_configured(tenant),
            "cert_expires_at": (tenant.fv_escrow_cert_expires_at.isoformat()
                                if tenant.fv_escrow_cert_expires_at else None),
        },
    }


@app.put("/api/v1/tenant")
async def update_tenant(update: TenantUpdate, admin: Principal = Depends(require_admin)):
    """Update tenant settings (admin only)."""
    tenant = admin.tenant

    if update.name is not None:
        name = update.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="Tenant name cannot be empty")
        tenant.name = name
    if update.allowed_users is not None:
        tenant.allowed_users = update.allowed_users
    if update.s3_config is not None:
        incoming_s3 = update.s3_config

        def _s3_fresh(key: str) -> bool:
            return key in incoming_s3 and incoming_s3.get(key) != _REDACTED

        if _s3_fresh("access_key_id") != _s3_fresh("secret_access_key"):
            raise HTTPException(
                status_code=400,
                detail="S3 access key ID and secret access key must be set together",
            )
        # Don't overwrite with a redacted value from the UI
        tenant.s3_config = _restore_tenant_s3_secrets(tenant.s3_config, update.s3_config)
        try:
            resolve_s3_settings(tenant)
        except S3ConfigError as e:
            raise HTTPException(status_code=400, detail=str(e))
    if update.dep_enabled is not None:
        tenant.dep_enabled = update.dep_enabled
    if update.ddm_enabled is not None:
        tenant.ddm_enabled = update.ddm_enabled
    if update.payload_identifier_prefix is not None:
        prefix = update.payload_identifier_prefix.strip()
        if not prefix:
            tenant.payload_identifier_prefix = None
        else:
            err = payload_identifier_prefix_error(prefix)
            if err:
                raise HTTPException(
                    status_code=400,
                    detail=f"payload_identifier_prefix {err}")
            tenant.payload_identifier_prefix = prefix
    if update.device_naming is not None:
        # Normalise to {"template": str, "apply_on_enroll": bool}; an empty/blank template clears the tenant default
        # (stored as {}). Group-level templates still take precedence (services.naming.select_naming_config).
        dn = update.device_naming
        if not isinstance(dn, dict):
            raise HTTPException(status_code=400, detail="device_naming must be an object")
        template = str(dn.get("template") or "").strip()[:200]
        if template:
            tenant.device_naming = {
                "template": template,
                "apply_on_enroll": bool(dn.get("apply_on_enroll")),
            }
        else:
            tenant.device_naming = {}
    # The reminder dates are the one pair where null is a real value, so they key off whether the field was in the
    # request rather than whether it is None. That is what lets a client clear a date it set earlier.
    if "apns_cert_expires_at" in update.__fields_set__:
        tenant.apns_cert_expires_at = update.apns_cert_expires_at
    if "dep_token_expires_at" in update.__fields_set__:
        tenant.dep_token_expires_at = update.dep_token_expires_at
    if update.is_active is not None:
        # Guard against an admin locking the whole tenant out irrecoverably.
        if not update.is_active:
            raise HTTPException(
                status_code=400,
                detail="Deactivating a tenant via this API is not allowed; use admin tooling",
            )
        tenant.is_active = update.is_active

    await tenant.save()

    # Which fields the request touched, as booleans. Again, no secret values.
    await record_audit(
        admin,
        "tenant.update",
        target_type="tenant",
        target_id=tenant.id,
        detail={"changed": {
            "name": update.name is not None,
            "allowed_users": update.allowed_users is not None,
            "s3_config": update.s3_config is not None,
            "dep_enabled": update.dep_enabled is not None,
            "ddm_enabled": update.ddm_enabled is not None,
            "device_naming": update.device_naming is not None,
            "apns_cert_expires_at": "apns_cert_expires_at" in update.__fields_set__,
            "dep_token_expires_at": "dep_token_expires_at" in update.__fields_set__,
            "is_active": update.is_active is not None,
        }},
    )

    # Mirror the row into config.yaml for the tenants that already have one on disk.
    yaml_path = _tenant_dir(tenant.id) / "config.yaml"
    if yaml_path.exists():
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                existing = yaml.safe_load(f) or {}

            doc = _tenant_config_doc(tenant, existing)
            _atomic_write_yaml(yaml_path, doc,
                               text=_config_document_text(yaml_path, doc))
        except OSError as exc:
            # The DB row is already saved; only the on-disk mirror failed.
            logger.exception("Cannot mirror tenant config to %s", yaml_path)
            raise HTTPException(
                status_code=500,
                detail=f"Tenant saved, but updating its config file failed: {exc}",
            )

    return {"message": "Tenant updated successfully"}


#  FileVault recovery-key escrow keypair

@app.get("/api/v1/tenant/filevault-escrow")
async def get_filevault_escrow(admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    """The tenant's FileVault escrow keypair status, certificate included.

    The certificate is public (it is what the escrow payload carries to every Mac); the private key is never returned."""
    from controller.services import filevault_escrow
    return filevault_escrow.certificate_info(admin.tenant)


@app.post("/api/v1/tenant/filevault-escrow")
async def generate_filevault_escrow(
    replace: bool = Query(False),
    admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    """Generate the tenant's FileVault escrow keypair (admin only); replacing an existing one invalidates any escrow
    payload already on a Mac under the old certificate."""
    from controller.services import crypto_secrets, filevault_escrow
    try:
        await filevault_escrow.generate_keypair(admin.tenant, replace=replace)
    except crypto_secrets.SecretEncryptionUnavailable as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Encryption at rest is not configured, so the escrow private key "
                   f"cannot be stored. ({exc})")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    await record_audit(admin, "tenant.filevault_escrow.generate",
                       target_type="tenant", target_id=str(admin.tenant.id),
                       detail={"replace": replace})
    # A new certificate has to reach devices; re-serve profiles now rather than at the next scheduled sync.
    _spawn_tenant_reconcile(admin.tenant.id)
    from controller.services import filevault_escrow as _fve
    return _fve.certificate_info(admin.tenant)


@app.get("/api/v1/tenant/filevault-escrow/certificate")
async def download_filevault_escrow_cert(
    admin: Principal = Depends(require_admin)) -> Response:
    """The escrow certificate as a PEM download.

    The public half only, so it decrypts nothing; the private key is never exported."""
    from controller.services import filevault_escrow
    if not filevault_escrow.is_configured(admin.tenant):
        raise HTTPException(status_code=404, detail="No escrow keypair generated yet")
    return Response(
        content=admin.tenant.fv_escrow_cert_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition":
                     'attachment; filename="filevault-escrow-cert.pem"'},
    )


_EDITABLE_CONFIG_TYPES = ["groups", "apps", "profiles", "tags", "flows", "dispatcher",
                          "declarations"]
_READABLE_CONFIG_TYPES = _EDITABLE_CONFIG_TYPES + ["config"]

_OPTIONAL_CONFIG_FILES = ["tags.yaml", "flows.yaml", "dispatcher.yaml", "declarations.yaml"]

_RAW_YAML_KEY = "__yaml_text__"

_RAW_YAML_MAX_CHARS = 512 * 1024

_CONFIG_VERSION_HEADER = "X-Config-Version"


def _config_version(path: Path) -> Optional[str]:
    """Version of the config document on disk; None when there is no file."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        return None
    except OSError:
        logger.exception("config: cannot read %s to version it", path)
        return None


def _check_config_version(yaml_path: Path, if_match: Any) -> None:
    """Refuse a write whose base version is no longer the one on disk.

    A merge would be kinder than a refusal here, and has not been built.
    """
    expected = if_match.strip().strip('"') if isinstance(if_match, str) else ""
    if not expected:
        return
    current = _config_version(yaml_path)
    if current is None or current == expected:
        return
    raise HTTPException(status_code=409, detail={
        "error": "conflict",
        "message": ("This document was changed by someone else since you loaded "
                    "it. Reload and reapply your edits."),
        "current_version": current,
    })


def _set_config_version_header(response: Any, yaml_path: Path) -> None:
    """Report the version a write just produced, for the client to keep editing.

    response is None when the test suite calls the route function directly instead of serving it.
    """
    if response is None:
        return
    version = _config_version(yaml_path)
    if version:
        response.headers[_CONFIG_VERSION_HEADER] = version


@app.get("/api/v1/config/{config_type}")
async def get_yaml_config(
    config_type: str,
    raw: bool = False,
    principal: Principal = Depends(get_current_principal),
    response: Response = None,
):
    """Get one tenant's YAML configuration by type (groups, apps, profiles, config), or, with raw=true, the redacted
    document itself as text/plain."""
    if config_type not in _READABLE_CONFIG_TYPES:
        raise HTTPException(status_code=400, detail="Invalid config type")

    tenant = principal.tenant
    yaml_path = _tenant_dir(tenant.id) / f"{config_type}.yaml"

    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail="Configuration not found")

    with open(yaml_path, "r") as f:
        text = f.read()
    version = _config_version(yaml_path)
    config = yaml.safe_load(text) or {}

    # config.yaml embeds tenant.s3, which can carry credentials.
    redacted = False
    if config_type == "config" and isinstance(config.get("tenant"), dict):
        if "s3" in config["tenant"]:
            config["tenant"]["s3"] = _redact_s3_config(config["tenant"]["s3"])
            redacted = True
    # A dispatcher.yaml webhook url and secret are both credentials
    if config_type == "dispatcher":
        config = _redact_dispatcher_config(config)
        redacted = True
    # Static passwords authored onto flow nodes.
    if config_type == "flows":
        flows_redacted = _redact_flows_config(config)
        redacted = redacted or flows_redacted != config
        config = flows_redacted
    # Profile payloads can carry credentials, a SCEP challenge or a Wi-Fi PSK among them.
    if config_type == "profiles" and not principal.is_admin:
        profiles_redacted = _redact_profiles_config(config)
        redacted = redacted or profiles_redacted != config
        config = profiles_redacted

    if raw:
        # Serve the authored file verbatim (comments intact) unless redaction forced a re-render.
        body = yaml.safe_dump(config, default_flow_style=False, sort_keys=False) if redacted else text
        return Response(content=body, media_type="text/plain; charset=utf-8",
                        headers={_CONFIG_VERSION_HEADER: version} if version else None)

    if config_type == "flows":
        from controller.services.flow_step_catalog import normalize_flow_document
        flows, _warns = normalize_flow_document(config)
        config = {"version": 2, "flows": flows}

    if response is not None and version:
        response.headers[_CONFIG_VERSION_HEADER] = version
    return config


# Config history: every successful save snapshots the previous document, so a breaking change can be rolled back.
_HISTORY_LIMIT = 50
_HISTORY_ID_RE = re.compile(r"^\d{8}T\d{6,12}Z$")


def _history_dir(tenant_id: str, config_type: str) -> Path:
    return _tenant_dir(tenant_id) / "_history" / config_type


def _snapshot_config_history(tenant_id: str, config_type: str, user: str) -> Optional[str]:
    """Snapshot the current on-disk config before it is overwritten, best-effort so a history failure never blocks
    the save. Returns the snapshot's version id, or None if it was skipped or failed."""
    src = _tenant_dir(tenant_id) / f"{config_type}.yaml"
    if not src.exists():
        return None
    try:
        hdir = _history_dir(tenant_id, config_type)
        hdir.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc)
        vid = now.strftime("%Y%m%dT%H%M%S%fZ")
        (hdir / f"{vid}.json").write_text(json.dumps({
            "id": vid,
            "saved_at": now.isoformat(),
            "user": user,
            "content": src.read_text(),
        }))
        # Prune oldest beyond the cap (ids are lexicographically time-ordered).
        entries = sorted(hdir.glob("*.json"))
        for old in entries[:-_HISTORY_LIMIT]:
            old.unlink()
        return vid
    except (OSError, ValueError):
        # A non-UTF-8 outgoing file raises UnicodeDecodeError, which is a ValueError.
        logger.exception("config history snapshot failed for %s/%s", tenant_id, config_type)
        return None


def _autofill_rollout_starts(config_type: str, config_data: Dict[str, Any]) -> None:
    """Stamp rollout.start (now, UTC) on any rollout block that lacks one.

    Wave math needs a fixed start in the document to keep the runtime stateless; clearing it restarts the waves.
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    def fill(obj: Any) -> None:
        if not isinstance(obj, dict):
            return
        rollout = obj.get("rollout")
        if isinstance(rollout, dict) and rollout and not rollout.get("start"):
            rollout["start"] = now_iso

    if config_type == "profiles":
        for profile in config_data.get("profiles") or []:
            fill(profile)
    elif config_type == "declarations":
        # A declaration rollout without a start makes the coverage function fail open at 100%, so the whole fleet gets
        # it at once (services.ddm_manager).
        for declaration in config_data.get("declarations") or []:
            fill(declaration)
    elif config_type == "apps":
        for app_entry in config_data.get("apps") or []:
            if isinstance(app_entry, dict):
                for version in app_entry.get("versions") or []:
                    fill(version)


@app.put("/api/v1/config/{config_type}")
async def update_yaml_config(
    config_type: str,
    config_data: Dict[str, Any],
    principal: Principal = Depends(get_current_principal),
    dry_run: bool = False,
    acknowledge: Optional[str] = Query(None, description="Comma-separated gate finding codes to acknowledge"),
    if_match: Optional[str] = Header(None, alias="If-Match"),
    response: Response = None,
):
    """Replace one YAML config document after validating it (admin only outside MEMBER_WRITABLE_CONFIG_TYPES),
    supporting dry_run and If-Match concurrency control."""
    yaml_text = config_data.pop(_RAW_YAML_KEY, None)
    if not isinstance(yaml_text, str):
        yaml_text = None
    elif len(yaml_text) > _RAW_YAML_MAX_CHARS:
        logger.warning("config: %s text for %s is %d characters, over the %d "
                       "cap; saving the document without it",
                       _RAW_YAML_KEY, config_type, len(yaml_text), _RAW_YAML_MAX_CHARS)
        yaml_text = None
    if config_type not in _EDITABLE_CONFIG_TYPES:
        raise HTTPException(status_code=400, detail="Invalid config type")
    if config_type not in MEMBER_WRITABLE_CONFIG_TYPES and not principal.is_admin:
        raise HTTPException(
            status_code=403,
            detail=f"Editing '{config_type}' requires the admin role",
        )
    yaml_path = _tenant_dir(principal.tenant.id) / f"{config_type}.yaml"
    # Ahead of every side effect, so a conflict leaves no snapshot, no audit row and no reconcile behind.
    if not dry_run:
        _check_config_version(yaml_path, if_match)
    # Put back any secret that came back redacted, before validation and the write.
    if config_type == "dispatcher":
        _restore_dispatcher_secrets(principal.tenant.id, config_data)
    elif config_type == "flows":
        _restore_flow_secrets(principal.tenant.id, config_data)
    elif config_type == "profiles":
        _restore_profile_secrets(principal.tenant.id, config_data)

    acknowledged_set = (
        {c.strip() for c in acknowledge.split(",") if c.strip()}
        if isinstance(acknowledge, str)
        else set()
    )
    gate_findings: List[Dict[str, Any]] = []
    if config_type == "flows":
        from controller.services import flow_gate, tenant_config
        prior_doc = tenant_config._load(str(principal.tenant.id), "flows.yaml")
        findings = flow_gate.check_flows_document(
            config_data, profiles=_gate_profiles(principal), prior=prior_doc)
        gate_findings = [f.to_dict() for f in findings]
        blocking_findings = flow_gate.blocking(findings, acknowledged_set)
        if blocking_findings and not dry_run:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Flow save gate refused this document",
                    "gate_findings": gate_findings,
                },
            )

    result = await _apply_config_update(principal, config_type, config_data,
                                        dry_run=dry_run, yaml_text=yaml_text)
    if config_type == "flows":
        result["gate_findings"] = gate_findings
        if not dry_run and acknowledged_set:
            from controller.services.audit import record_audit
            effective_ack = [f["code"] for f in gate_findings if f["code"] in acknowledged_set]
            if effective_ack:
                await record_audit(
                    principal, "flow.gate_acknowledged",
                    target_type="config", target_id="flows",
                    detail={"codes": effective_ack},
                )
    if not dry_run:
        _set_config_version_header(response, yaml_path)
    return result


def _spawn_tenant_reconcile(tenant_id: str) -> None:
    """Ask for a reactive reconcile, coalesced per tenant (services.reconciler)."""
    from controller.services.reconciler import request_reconcile
    request_reconcile(tenant_id)


async def _apply_config_update(
    principal: Principal, config_type: str, config_data: Dict[str, Any],
    dry_run: bool = False, yaml_text: Optional[str] = None,
) -> Dict[str, Any]:
    """Shared validate, snapshot, write and reconcile path used by both a normal save and a history restore.

    dry_run stops after validation and reports the result instead of raising.
    """
    tenant = principal.tenant
    tenant_dir = _tenant_dir(tenant.id)
    # New rollout blocks get their wave clock started at save time.
    _autofill_rollout_starts(config_type, config_data)
    yaml_path = tenant_dir / f"{config_type}.yaml"
    # A tenant created through the console or bootstrap exists in the DB but may have no config dir on disk yet.
    try:
        if not dry_run:
            tenant_dir.mkdir(parents=True, exist_ok=True)
            config_yaml = tenant_dir / "config.yaml"
            if not config_yaml.exists():
                _atomic_write_yaml(config_yaml, _tenant_config_doc(tenant))
            from controller.services import atc_provision
            atc_provision.ensure_enrollment_flow(str(tenant.id))
    except OSError as exc:
        # Almost always permissions: the controller runs as uid 1000 and the yaml-configs volume is root-owned.
        logger.exception("Cannot prepare tenant config dir %s", tenant_dir)
        raise HTTPException(
            status_code=500,
            detail=(
                f"Server cannot write the config directory ({tenant_dir}): {exc}. "
                "The controller runs as uid 1000, so the yaml-configs volume needs "
                "to be owned by 1000:1000. The yaml-init service in "
                "docker-compose.prod.yml handles that."
            ),
        )

    # Validate the candidate against a private copy of the tenant dir, so cross-file checks run without touching a live
    # file until it is valid. validate_all() requires all four files, so any missing on disk get a minimal stub.
    stubs = {
        "config.yaml": {"tenant": {"id": tenant.id, "name": tenant.name, "allowed_users": []}},
        "groups.yaml": {"groups": []},
        "apps.yaml": {"apps": []},
        "profiles.yaml": {"profiles": []},
    }
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        for fn in ["config.yaml", "groups.yaml", "apps.yaml", "profiles.yaml"]:
            src = tenant_dir / fn
            if src.exists():
                shutil.copy(src, tdp / fn)
            else:
                with open(tdp / fn, "w") as f:
                    yaml.safe_dump(stubs[fn], f, default_flow_style=False)
        # Optional docs (e.g. tags.yaml) are copied when present so cross-document checks resolve during any save; they
        # have no required stub.
        for fn in _OPTIONAL_CONFIG_FILES:
            src = tenant_dir / fn
            if src.exists():
                shutil.copy(src, tdp / fn)
        # Overwrite the file being updated with the submitted candidate data (this wins even if the same file was copied
        # above as an optional doc).
        with open(tdp / f"{config_type}.yaml", "w") as f:
            yaml.safe_dump(config_data, f, default_flow_style=False)

        validator = YAMLValidator(
            tdp,
            filevault_escrow_configured=filevault_escrow.is_configured(tenant))
        valid, errors, warnings = validator.validate_all()
        flow_warnings = validator.flow_warnings

    if dry_run:
        return {"valid": valid, "errors": errors, "warnings": warnings,
                "flow_warnings": flow_warnings}

    if not valid:
        raise HTTPException(
            status_code=400, detail={"errors": errors, "warnings": warnings}
        )

    # Snapshot the outgoing document so this save can be rolled back.
    history_id = _snapshot_config_history(tenant.id, config_type, principal.email)

    try:
        _atomic_write_yaml(
            yaml_path, config_data,
            text=_config_document_text(yaml_path, config_data, yaml_text),
        )
    except OSError as exc:
        logger.exception("Cannot write %s", yaml_path)
        raise HTTPException(
            status_code=500,
            detail=f"Server failed to persist {config_type} configuration: {exc}",
        )

    # The history snapshot labels the OUTGOING document with the INCOMING saver's email; no document content in the
    # audit detail, since apps, profiles and flows can all carry secrets.
    await record_audit(
        principal,
        "config.update",
        target_type="config",
        target_id=config_type,
        detail={"warnings": len(warnings)} if warnings else None,
    )

    # Reconcile reactively so the change produces tasks now, not at the next scheduled sync (which remains the periodic
    # safety net).
    _spawn_tenant_reconcile(tenant.id)

    return {"message": f"{config_type} configuration updated",
            "warnings": warnings, "flow_warnings": flow_warnings,
            "history_id": history_id}


@app.post("/api/v1/config/validate")
async def validate_yaml_configs(principal: Principal = Depends(get_current_principal)):
    """Validate this tenant's config documents as they stand on disk, and return the errors, warnings and flow warnings.
    Writes nothing."""
    tenant = principal.tenant
    validator = YAMLValidator(
        _tenant_dir(tenant.id),
        filevault_escrow_configured=filevault_escrow.is_configured(tenant))

    valid, errors, warnings = validator.validate_all()

    return {"valid": valid, "errors": errors, "warnings": warnings,
            "flow_warnings": validator.flow_warnings}


def _load_history_entry(tenant_id: str, config_type: str, version_id: str) -> Dict[str, Any]:
    if config_type not in _EDITABLE_CONFIG_TYPES:
        raise HTTPException(status_code=400, detail="Invalid config type")
    if not _HISTORY_ID_RE.match(version_id):
        raise HTTPException(status_code=400, detail="Invalid version id")
    path = _history_dir(tenant_id, config_type) / f"{version_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Version not found")
    try:
        entry = json.loads(path.read_text())
    except (OSError, ValueError):
        logger.exception("unreadable history entry %s", path)
        raise HTTPException(status_code=500, detail="History entry is unreadable")
    if not isinstance(entry, dict):  # valid JSON, but not an object
        raise HTTPException(status_code=500, detail="History entry is malformed")
    return entry


@app.get("/api/v1/config/{config_type}/history")
async def list_config_history(
    config_type: str,
    principal: Principal = Depends(get_current_principal),
):
    """Previous versions of a config document (newest first)."""
    if config_type not in _EDITABLE_CONFIG_TYPES:
        raise HTTPException(status_code=400, detail="Invalid config type")
    hdir = _history_dir(principal.tenant.id, config_type)
    versions = []
    if hdir.exists():
        for path in sorted(hdir.glob("*.json"), reverse=True):
            try:
                entry = json.loads(path.read_text())
                if not isinstance(entry, dict):
                    raise ValueError("not a JSON object")
                versions.append({
                    "id": entry.get("id") or path.stem,
                    "saved_at": entry.get("saved_at"),
                    "user": entry.get("user"),
                    "size": len(entry.get("content") or ""),
                })
            except (OSError, ValueError):
                logger.warning("skipping unreadable history entry %s", path)
    return {"versions": versions}


@app.get("/api/v1/config/{config_type}/history/{version_id}")
async def get_config_history_version(
    config_type: str,
    version_id: str,
    principal: Principal = Depends(get_current_principal),
):
    """One historical config document, including its full YAML content."""
    entry = _load_history_entry(principal.tenant.id, config_type, version_id)
    content = entry.get("content") or ""
    # History snapshots store raw secrets (a restore needs them). Redact the response the same way the live GET does, so
    # an old version can't leak one.
    if content and config_type == "dispatcher":
        content = _redact_dispatcher_history(content)
    elif content and config_type == "flows":
        content = _redact_flows_history(content)
    elif content and config_type == "profiles" and not principal.is_admin:
        content = _redact_profiles_history(content)
    return {
        "id": entry.get("id") or version_id,
        "saved_at": entry.get("saved_at"),
        "user": entry.get("user"),
        "content": content,
    }


@app.post("/api/v1/config/{config_type}/history/{version_id}/restore")
async def restore_config_history_version(
    config_type: str,
    version_id: str,
    principal: Principal = Depends(get_current_principal),
    if_match: Optional[str] = Header(None, alias="If-Match"),
    response: Response = None,
):
    """Restore a historical config version through the same validate, snapshot, write and reconcile path as a normal
    save, checking If-Match against the live document rather than the version being restored."""
    # Unknown type is a 400 before the role check, matching update_yaml_config, so a typo does not come back as a
    # missing-admin-role refusal. _load_history_entry checks it again; this is only about the order.
    if config_type not in _EDITABLE_CONFIG_TYPES:
        raise HTTPException(status_code=400, detail="Invalid config type")
    if config_type not in MEMBER_WRITABLE_CONFIG_TYPES and not principal.is_admin:
        raise HTTPException(
            status_code=403,
            detail=f"Restoring '{config_type}' requires the admin role",
        )
    yaml_path = _tenant_dir(principal.tenant.id) / f"{config_type}.yaml"
    _check_config_version(yaml_path, if_match)
    entry = _load_history_entry(principal.tenant.id, config_type, version_id)
    content = entry.get("content") or ""
    try:
        config_data = yaml.safe_load(content) or {}
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Stored version is not valid YAML: {exc}")
    if not isinstance(config_data, dict):
        raise HTTPException(status_code=400, detail="Stored version is not a YAML mapping")
    # A hand-edited tenant file could carry the reserved key; drop it here too, since it is never document content.
    config_data.pop(_RAW_YAML_KEY, None)
    result = await _apply_config_update(principal, config_type, config_data,
                                        yaml_text=content)
    # _apply_config_update already logged config.update. This second row is what separates a rollback from an ordinary
    # save, and names the version so the restored content can be identified afterwards.
    await record_audit(
        principal,
        "config.restore",
        target_type="config",
        target_id=config_type,
        detail={"version_id": version_id},
    )
    result["message"] = f"{config_type} configuration restored from {version_id}"
    _set_config_version_header(response, yaml_path)
    return result


@app.post("/api/v1/sync")
async def sync_now(principal: Principal = Depends(get_current_principal)):
    """Reconcile this tenant's declared YAML state against its devices now (also triggered automatically after
    config saves)."""
    from controller.services.reconciler import reconcile_tenant

    summary = await reconcile_tenant(principal.tenant, _yaml_base())
    return {"message": "Sync complete", **summary}


# Map tiles: a same-origin proxy for OpenStreetMap raster tiles, so the device-location map works under the app's strict
# CSP (img-src 'self' blob:) and without a third-party CDN.
from collections import OrderedDict

_TILE_CACHE: "OrderedDict[str, bytes]" = OrderedDict()
_TILE_CACHE_MAX = 4096
_tile_client: Optional[Any] = None


def _get_tile_client():
    global _tile_client
    if _tile_client is None:
        import httpx
        _tile_client = httpx.AsyncClient(
            timeout=10.0,
            # OSM's tile usage policy requires an identifying User-Agent.
            headers={"User-Agent": "Micromanage/1.0 (self-hosted MDM; device location map)"},
        )
    return _tile_client


@app.get("/api/v1/map/tile/{z}/{x}/{y}")
async def map_tile(z: int, x: int, y: int, principal: Principal = Depends(get_current_principal)):
    """Proxy a single OSM raster tile (cached). Coordinates are strictly bounded to the standard slippy-map range, so
    this can only ever fetch public tiles."""
    if not (0 <= z <= 19):
        raise HTTPException(status_code=404, detail="bad zoom")
    n = 1 << z
    if not (0 <= x < n and 0 <= y < n):
        raise HTTPException(status_code=404, detail="tile out of range")

    key = f"{z}/{x}/{y}"
    data = _TILE_CACHE.get(key)
    if data is None:
        try:
            resp = await _get_tile_client().get(f"https://tile.openstreetmap.org/{z}/{x}/{y}.png")
            resp.raise_for_status()
            data = resp.content
        except Exception as exc:
            logger.warning(f"tile fetch failed for {key}: {exc}")
            raise HTTPException(status_code=502, detail="tile fetch failed")
        _TILE_CACHE[key] = data
        _TILE_CACHE.move_to_end(key)
        while len(_TILE_CACHE) > _TILE_CACHE_MAX:
            _TILE_CACHE.popitem(last=False)

    return Response(content=data, media_type="image/png",
                    headers={"Cache-Control": "private, max-age=86400"})


@app.on_event("shutdown")
async def _close_tile_client():
    """Close the tile proxy's httpx client on the way down.

    Built lazily and lives at module scope, so its sockets would otherwise leak across uvicorn reloads.
    """
    global _tile_client
    client, _tile_client = _tile_client, None
    if client is not None:
        try:
            await client.aclose()
        except Exception:
            logger.warning("tile client close failed", exc_info=True)


# Device Management
@app.get("/api/v1/commands/catalog")
async def get_command_catalog(principal: Principal = Depends(get_current_principal)):
    """Every device command this controller can send, with its parameters and the role each one takes."""
    from controller.services.command_catalog import catalog_for_role

    return {"commands": catalog_for_role(principal.is_admin)}


@app.get("/api/v1/flows/step-catalog")
async def get_flow_step_catalog(principal: Principal = Depends(get_current_principal)):
    """Every ATC flow node type with its parameters, plus the wait-signal registry.

    Same arrangement as GET /api/v1/commands/catalog: adding a node type only needs a catalog and engine change."""
    from controller.services.flow_step_catalog import catalog

    return catalog()


class CreateDraftRequest(BaseModel):
    note: str = ""


class PromoteDraftRequest(BaseModel):
    acknowledge: Optional[List[str]] = None
    force: bool = False


def _gate_profiles(principal: "Principal"):
    """The tenant's enrollment profiles for the flow gate's DEP cross-check.

    Returns None, never [], on a read failure; the gate treats None as unchecked and [] as checked and clear."""
    from controller.services import tenant_config

    try:
        return tenant_config.load_profiles(str(principal.tenant.id))
    except Exception:
        logger.exception("flows: could not read profiles for the save gate")
        return None


def _flows_document(tenant_id: str) -> Dict[str, Any]:
    """The tenant's flows.yaml as a v2 document, whatever form it takes on disk.

    Runs the same migration the engine and validator apply on read, or the draft endpoints see an empty list and 404.
    """
    from controller.services import tenant_config
    from controller.services.flow_step_catalog import normalize_flow_document

    raw = tenant_config._load(str(tenant_id), "flows.yaml") or {}
    flows, _warns = normalize_flow_document(raw)
    return {"version": 2, "flows": flows}


@app.get("/api/v1/flows/summary")
async def get_flows_summary(principal: Principal = Depends(get_current_principal)):
    """Summary of all ATC flows and drafts for the tenant, plus deployment limits.

    Tolerates a missing flows.yaml (returns empty list).
    """
    from controller.models.tenant import FlowRun
    from controller.services import flow_gate, tenant_config
    from controller.services.flow_step_catalog import (
        normalize_flow_document,
    )
    from controller.utils.yaml_validator import YAMLValidator

    tenant_id = str(principal.tenant.id)
    doc = tenant_config._load(tenant_id, "flows.yaml")
    limits = {
        "max_flows_per_tenant": flow_gate.MAX_FLOWS_PER_TENANT,
        "max_drafts_per_tenant": flow_gate.MAX_DRAFTS_PER_TENANT,
        "max_nodes_per_flow": flow_gate.MAX_NODES_PER_FLOW,
        "max_nodes_per_tenant": flow_gate.MAX_NODES_PER_TENANT,
        "max_schedule_starts_per_tenant": flow_gate.MAX_SCHEDULE_STARTS_PER_TENANT,
        "max_checkin_starts_per_tenant": flow_gate.MAX_CHECKIN_STARTS_PER_TENANT,
        "min_schedule_interval_minutes": flow_gate.MIN_SCHEDULE_INTERVAL_MINUTES,
        "min_checkin_cooldown_minutes": flow_gate.MIN_CHECKIN_COOLDOWN_MINUTES,
    }
    if not doc:
        return {"flows": [], "limits": limits, "retention_days": FLOW_RUN_RETENTION_DAYS}

    flows, _warns = normalize_flow_document(doc)
    # One pass with prior=doc, so the protection rules see a document that is not changing and stay silent; what is left
    # is scope, integrity and limits.
    gate_findings = flow_gate.check_flows_document(
        doc, profiles=_gate_profiles(principal), prior=doc)
    gate_by_flow: Dict[str, List[Dict[str, Any]]] = {}
    for f in gate_findings:
        if f.flow_id:
            gate_by_flow.setdefault(f.flow_id, []).append(f.to_dict())

    # One validator pass for semantic flow warnings
    tenant_dir = _tenant_dir(tenant_id)
    validator = YAMLValidator(tenant_dir, filevault_escrow_configured=filevault_escrow.is_configured(principal.tenant))
    validator.validate_all()
    warnings_by_flow: Dict[str, int] = {}
    for w in validator.flow_warnings:
        fid = getattr(w, "flow_id", None) or (w.get("flow_id") if isinstance(w, dict) else None)
        if fid:
            warnings_by_flow[fid] = warnings_by_flow.get(fid, 0) + 1

    # Run counts over the retention window in one grouped read; older rows are already deleted by
    # task_manager.cleanup_old_flow_runs. Keyed on started_at since FlowRun has no created_at column.
    cutoff = datetime.now(timezone.utc) - timedelta(days=FLOW_RUN_RETENTION_DAYS)
    runs_in_window_map: Dict[str, int] = {}
    active_runs_map: Dict[str, int] = {}
    failed_in_window_map: Dict[str, int] = {}
    last_run_at_map: Dict[str, str] = {}

    all_window_runs = await FlowRun.filter(
        tenant=principal.tenant,
        started_at__gte=cutoff,
    ).values("flow_id", "status", "started_at")

    for r in all_window_runs:
        fid = r.get("flow_id")
        if not fid:
            continue
        runs_in_window_map[fid] = runs_in_window_map.get(fid, 0) + 1
        st = r.get("status")
        if st in ("running", "waiting"):
            active_runs_map[fid] = active_runs_map.get(fid, 0) + 1
        elif st == "failed":
            failed_in_window_map[fid] = failed_in_window_map.get(fid, 0) + 1
        started = r.get("started_at")
        if started:
            started_iso = (started.isoformat() if hasattr(started, "isoformat")
                           else str(started))
            if fid not in last_run_at_map or started_iso > last_run_at_map[fid]:
                last_run_at_map[fid] = started_iso

    summary_list = []
    for flow in flows:
        fid = flow.get("id") or ""
        nodes = flow.get("nodes") or []
        start_kinds = [
            (n.get("params") or {}).get("kind")
            for n in nodes
            if n.get("type") == "start" and (n.get("params") or {}).get("kind")
        ]
        summary_list.append({
            "id": fid,
            "name": flow.get("name") or fid,
            "description": flow.get("description") or "",
            "enabled": flow.get("enabled", True),
            "permanent": flow.get("permanent", False),
            "draft_of": flow.get("draft_of"),
            "draft_note": flow.get("draft_note"),
            "draft_created_by": flow.get("draft_created_by"),
            "draft_created_at": flow.get("draft_created_at"),
            "node_count": len(nodes),
            "start_kinds": start_kinds,
            "runs_in_window": runs_in_window_map.get(fid, 0),
            "active_runs": active_runs_map.get(fid, 0),
            "failed_in_window": failed_in_window_map.get(fid, 0),
            "last_run_at": last_run_at_map.get(fid),
            "warning_count": warnings_by_flow.get(fid, 0),
            "gate_findings": gate_by_flow.get(fid, []),
        })

    return {
        "flows": summary_list,
        "limits": limits,
        "retention_days": FLOW_RUN_RETENTION_DAYS,
    }


@app.post("/api/v1/flows/{flow_id}/draft", status_code=201)
async def create_flow_draft(
    flow_id: str,
    body: CreateDraftRequest = CreateDraftRequest(),
    principal: Principal = Depends(get_current_principal),
    if_match: Optional[str] = Header(None, alias="If-Match"),
    response: Response = None,
):
    """Create a draft of an existing flow (admin only), copying its node params verbatim, plaintext passwords
    included, into a new <flow_id>--draft entry in flows.yaml."""
    if not principal.is_admin:
        raise HTTPException(status_code=403, detail="Admin role required")
    yaml_path = _tenant_dir(principal.tenant.id) / "flows.yaml"
    _check_config_version(yaml_path, if_match)
    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail="flows.yaml does not exist")

    from controller.services import flow_drafts, flow_gate
    doc = _flows_document(principal.tenant.id)
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        candidate = flow_drafts.create(
            doc, flow_id, note=body.note,
            actor=principal.email, at=now_iso,
        )
    except flow_drafts.DraftError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)

    profiles = _gate_profiles(principal)
    before = {(f.code, f.flow_id, f.node_id)
              for f in flow_gate.check_flows_document(doc, profiles=profiles, prior=doc)}
    introduced = [
        f for f in flow_gate.blocking(
            flow_gate.check_flows_document(candidate, profiles=profiles, prior=doc))
        if (f.code, f.flow_id, f.node_id) not in before
    ]
    if introduced:
        raise HTTPException(
            status_code=400,
            detail={"message": "Flow save gate refused this draft",
                    "gate_findings": [f.to_dict() for f in introduced]},
        )

    await _apply_config_update(principal, "flows", candidate)
    _set_config_version_header(response, yaml_path)
    draft_entry = [f for f in candidate.get("flows", []) if f.get("id") == f"{flow_id}--draft"]
    return _redact_flow(draft_entry[0]) if draft_entry else {}


@app.get("/api/v1/flows/{flow_id}/draft/diff")
async def get_flow_draft_diff(
    flow_id: str,
    principal: Principal = Depends(get_current_principal),
):
    """Semantic diff comparing a live flow against its draft.

    Redacts static secrets on both sides before comparison. Excludes ui.x/ui.y from changed count.
    """
    from controller.services import flow_drafts
    doc = _flows_document(principal.tenant.id)
    flows = list(doc.get("flows") or [])
    by_id = {str(f.get("id") or ""): f for f in flows if isinstance(f, dict)}
    target = by_id.get(flow_id)
    draft = by_id.get(f"{flow_id}--draft")
    if not target:
        raise HTTPException(status_code=404, detail=f"Flow '{flow_id}' not found")
    if not draft:
        raise HTTPException(status_code=404, detail=f"Draft for flow '{flow_id}' not found")

    return flow_drafts.diff(target, draft)


@app.post("/api/v1/flows/{flow_id}/promote-draft")
async def promote_flow_draft(
    flow_id: str,
    body: PromoteDraftRequest = PromoteDraftRequest(),
    principal: Principal = Depends(get_current_principal),
    if_match: Optional[str] = Header(None, alias="If-Match"),
    response: Response = None,
):
    """Promote a flow's <flow_id>--draft to replace it (admin only), checking draft_base_hash against the current
    hash unless force=true."""
    if not principal.is_admin:
        raise HTTPException(status_code=403, detail="Admin role required")
    yaml_path = _tenant_dir(principal.tenant.id) / "flows.yaml"
    _check_config_version(yaml_path, if_match)
    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail="flows.yaml does not exist")

    from controller.services import flow_drafts, flow_gate
    doc = _flows_document(principal.tenant.id)
    try:
        candidate, summary = flow_drafts.promote(doc, flow_id, force=body.force)
    except flow_drafts.DraftError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)

    profiles = _gate_profiles(principal)
    findings = flow_gate.check_flows_document(candidate, profiles=profiles, prior=doc)
    before = {(f.code, f.flow_id, f.node_id)
              for f in flow_gate.check_flows_document(doc, profiles=profiles, prior=doc)}
    introduced = [f for f in findings
                  if (f.code, f.flow_id, f.node_id) not in before]
    acknowledged_set = set(body.acknowledge or [])
    blocking = flow_gate.blocking(introduced, acknowledged_set)
    if blocking:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Promotion gate refused candidate document",
                "gate_findings": [f.to_dict() for f in findings],
            },
        )

    result = await _apply_config_update(principal, "flows", candidate)
    _set_config_version_header(response, yaml_path)

    from controller.services.audit import record_audit
    draft_entry = [f for f in doc.get("flows", []) if f.get("id") == f"{flow_id}--draft"]
    draft_note = draft_entry[0].get("draft_note") if draft_entry else ""
    # Recorded by what was actually waived, not what was sent: a code nobody raised waives nothing.
    waived = sorted({f.code for f in introduced if f.code in acknowledged_set
                     and f.acknowledgeable and not f.advisory})
    await record_audit(
        principal, "flow.promote_draft",
        target_type="flow", target_id=flow_id,
        detail={
            "draft_note": draft_note,
            "summary": summary,
            "history_id": result.get("history_id"),
            "acknowledged": waived,
            "force": bool(body.force),
            "base_drifted": bool(summary.get("base_drifted")),
        },
    )

    return {
        "promoted": True,
        "summary": summary,
        "history_id": result.get("history_id"),
        "gate_findings": [f.to_dict() for f in findings],
    }


@app.delete("/api/v1/flows/{flow_id}/draft")
async def discard_flow_draft(
    flow_id: str,
    principal: Principal = Depends(get_current_principal),
    if_match: Optional[str] = Header(None, alias="If-Match"),
    response: Response = None,
):
    """Discard <flow_id>--draft from flows.yaml. Admin only."""
    if not principal.is_admin:
        raise HTTPException(status_code=403, detail="Admin role required")
    yaml_path = _tenant_dir(principal.tenant.id) / "flows.yaml"
    _check_config_version(yaml_path, if_match)
    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail="flows.yaml does not exist")

    from controller.services import flow_drafts
    doc = _flows_document(principal.tenant.id)
    try:
        candidate = flow_drafts.discard(doc, flow_id)
    except flow_drafts.DraftError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)

    await _apply_config_update(principal, "flows", candidate)
    _set_config_version_header(response, yaml_path)
    return {"deleted": True}


@app.get("/api/v1/dispatcher/check-catalog")
async def get_dispatcher_check_catalog(principal: Principal = Depends(get_current_principal)):
    """The Dispatcher compliance checks with their parameters: curated ones plus the generic attribute check.

    Same arrangement as the command and flow-step catalogs."""
    from controller.services.compliance_catalog import catalog

    return catalog()


@app.get("/api/v1/naming/variables")
async def get_naming_variables(principal: Principal = Depends(get_current_principal)):
    """The device-state variables a naming template can use, at group or tenant level.

    One server-published registry, so nothing has to guess what the controller can resolve.
    """
    from controller.services.variables import VARIABLE_SPECS

    return {"variables": VARIABLE_SPECS}


# Exactly the Device columns _device_summary reads. Anything added to _device_summary belongs here too,
# display_name() included, or the name breaks silently for list rows; enforced by tests/verify_devices.py.
_DEVICE_SUMMARY_FIELDS = (
    "id", "udid", "name", "serial_number", "device_model", "os_version",
    "hostname", "groups", "tags", "enrollment_state", "management_type",
    "enrollment_date", "unenrolled_at", "last_seen",
    "last_polled_at", "poll_interval_minutes", "attributes",
)


def _device_summary(device: Device) -> Dict[str, Any]:
    """Identity + lifecycle fields shared by the list and detail responses."""
    from controller.services.naming import display_name
    return {
        "id": str(device.id),
        "udid": device.udid,
        "name": device.name,
        "display_name": display_name(device),
        "serial_number": device.serial_number,
        "device_model": device.device_model,
        "os_version": device.os_version,
        "hostname": device.hostname,
        "groups": device.groups,
        "tags": device.tags or [],
        "enrollment_state": device.enrollment_state,
        "management_type": device.management_type,
        "enrollment_date": device.enrollment_date,
        "unenrolled_at": device.unenrolled_at,
        "last_seen": device.last_seen,
        # Without these two, a stale last_seen cannot be told apart from the server having stopped asking.
        "last_polled_at": device.last_polled_at,
        "poll_interval_minutes": device.poll_interval_minutes,
    }


class PlaceholderDeviceCreate(BaseModel):
    serial_number: str
    device_model: Optional[str] = None
    management_type: str = "apple_mdm"
    groups: List[str] = []


@app.get("/api/v1/devices")
async def list_devices(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    group: Optional[str] = None,
    tag: Optional[str] = None,
    model: Optional[str] = None,
    os_version: Optional[str] = Query(None, alias="os"),
    search: Optional[str] = None,
    state: Optional[str] = Query(None, description="enrolled | unenrolled | pending"),
    principal: Principal = Depends(get_current_principal),
):
    """List devices, in every lifecycle state unless a filter narrows it."""
    tenant = principal.tenant

    query = Device.filter(tenant=tenant)

    if state in ("enrolled", "unenrolled", "pending"):
        query = query.filter(enrollment_state=state)
    if group:
        query = query.filter(groups__contains=[group])
    if tag:
        query = query.filter(tags__contains=[tag])
    if model:
        query = query.filter(device_model__icontains=model)
    if os_version:
        query = query.filter(os_version__icontains=os_version)
    if search:
        from tortoise.expressions import Q
        query = query.filter(
            Q(name__icontains=search)
            | Q(serial_number__icontains=search)
            | Q(hostname__icontains=search)
            | Q(device_model__icontains=search)
            | Q(udid__icontains=search)
        )

    total = await query.count()

    devices = (
        await query.order_by("enrollment_state", "-last_seen")
        .offset(skip).limit(limit).only(*_DEVICE_SUMMARY_FIELDS).all()
    )

    # Per-state counts, so a caller filtering by state needs no extra round-trip.
    from tortoise.functions import Count
    counts_raw = (
        await Device.filter(tenant=tenant)
        .annotate(count=Count("id")).group_by("enrollment_state")
        .values("enrollment_state", "count")
    )
    counts = {c["enrollment_state"]: c["count"] for c in counts_raw}

    return {
        "total": total,
        "counts": {
            "all": sum(counts.values()),
            "enrolled": counts.get("enrolled", 0),
            "unenrolled": counts.get("unenrolled", 0),
            "pending": counts.get("pending", 0),
        },
        "devices": [_device_summary(device) for device in devices],
    }


# TODO: bulk import (a CSV, say), reconciling against devices that already exist. One at a time does not
# scale past a handful.
@app.post("/api/v1/devices", status_code=201)
async def create_placeholder_device(
    body: PlaceholderDeviceCreate,
    admin: Principal = Depends(require_admin),
):
    """Pre-provision a device by serial before it enrolls (DEP, for instance).

    Group membership set here is applied when the physical device enrolls and is adopted by serial.
    """
    tenant = admin.tenant
    serial = body.serial_number.strip()
    if not serial:
        raise HTTPException(status_code=400, detail="serial_number is required")
    if len(serial) > 20:
        raise HTTPException(status_code=400, detail="serial_number too long (max 20 characters)")
    if body.management_type not in ("apple_mdm",):
        raise HTTPException(status_code=400, detail="unsupported management_type")

    existing = await Device.filter(tenant=tenant, serial_number=serial).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A device with serial {serial} already exists ({existing.enrollment_state})",
        )

    from tortoise.exceptions import IntegrityError
    try:
        device = await Device.create(
            tenant=tenant,
            udid=None,
            serial_number=serial,
            device_model=body.device_model or "",
            os_version="",
            hostname=None,
            enrollment_state="pending",
            management_type=body.management_type,
            groups=body.groups or [],
        )
    except IntegrityError:
        raise HTTPException(status_code=409, detail=f"A device with serial {serial} already exists")
    return _device_summary(device)


@app.delete("/api/v1/devices/{device_id}")
async def forget_device(
    device_id: str,
    admin: Principal = Depends(require_admin),
    # Plain default, not Query(): the unresolved Query marker object is truthy, which would turn this guard off for
    # any direct call.
    discard_secrets: bool = False,
):
    """Remove a device's record, deployments, tasks, flow runs, alerts and escrowed secrets from the console (admin
    only); refuses on an enrolled device, and on one with an unrevealed secret unless discard_secrets=true."""
    tenant = admin.tenant
    _require_uuid(device_id, "Device not found")
    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Both refusals below are 409; "code" is the contract the client checks, "message" is prose.
    if device.enrollment_state == "enrolled":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "device_enrolled",
                "message": (
                    "Device is enrolled; unenroll it or let it check out before "
                    "forgetting it, otherwise it will reappear on its next check-in."
                ),
            },
        )

    secrets = await DeviceSecret.filter(device=device).all()
    unrevealed = [s for s in secrets if s.revealed_at is None]
    if unrevealed and not discard_secrets:
        labels = sorted({s.kind_label for s in unrevealed})
        raise HTTPException(
            status_code=409,
            detail={
                "code": "unrevealed_secrets",
                "message": (
                    f"This device still holds {len(unrevealed)} escrowed secret(s) "
                    f"nobody has revealed ({', '.join(labels)}). Forgetting the device "
                    "destroys the only copy. Reveal what you need first, then retry "
                    "with discard_secrets=true to confirm."
                ),
                "unrevealed_count": len(unrevealed),
                "unrevealed_labels": labels,
            },
        )

    serial = device.serial_number  # captured before deletion for the audit log
    discarded_kinds = sorted({s.kind for s in secrets})

    # Child rows go explicitly, inside one transaction, rather than through DB-level ON DELETE CASCADE, so the cleanup
    # is the same whatever the schema's foreign keys were generated as.
    from tortoise.transactions import in_transaction

    async with in_transaction():
        await AppDeployment.filter(device=device).delete()
        await ProfileDeployment.filter(device=device).delete()
        await FlowRun.filter(device=device).delete()
        await Alert.filter(device=device).delete()
        await Task.filter(device=device).delete()
        await DeviceSecret.filter(device=device).delete()
        await device.delete()

    logger.info(
        "Forgot device %s (serial=%s) for tenant %s by %s (discarded secrets: %s)",
        device_id, serial, tenant.id, admin.email, discarded_kinds or "none",
    )
    await record_audit(
        admin,
        "device.forget",
        target_type="device",
        target_id=device_id,
        # Which kinds went, never their values.
        detail={
            "serial_number": serial,
            "discarded_secret_kinds": discarded_kinds,
            "unrevealed_secret_count": len(unrevealed),
        },
    )
    return {"message": "Device forgotten", "discarded_secret_kinds": discarded_kinds}


@app.get("/api/v1/devices/{device_id}")
async def get_device_details(device_id: str, principal: Principal = Depends(get_current_principal)):
    """One device in full: its summary fields, everything it has reported about itself, its app and profile deployments,
    and its ten most recent tasks."""
    tenant = principal.tenant
    _require_uuid(device_id, "Device not found")
    device = await Device.get_or_none(id=device_id, tenant=tenant)

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    apps = await AppDeployment.filter(device=device).all()
    profiles = await ProfileDeployment.filter(device=device).all()
    tasks = await Task.filter(device=device).order_by("-created_at").limit(10).all()

    last_failed_task = None
    failed_tasks = (
        await Task.filter(device=device, tenant=tenant, status="failed")
        .order_by("-created_at")
        .limit(10)
        .all()
    )
    if failed_tasks:
        completed_rows = (
            await Task.filter(
                device=device, tenant=tenant, status="completed",
                type__in=sorted({t.type for t in failed_tasks}),
            )
            .order_by("-created_at")
            .values("type", "created_at")
        )
        latest_completed: Dict[str, Any] = {}
        for row in completed_rows:
            latest_completed.setdefault(row["type"], row["created_at"])
        for candidate in failed_tasks:
            done = latest_completed.get(candidate.type)
            if done is None or done <= candidate.created_at:
                last_failed_task = candidate
                break
    last_task_error = (
        {
            "task_id": str(last_failed_task.id),
            "task_type": last_failed_task.type,
            "error": last_failed_task.error,
            "created_at": last_failed_task.created_at,
            "completed_at": last_failed_task.completed_at,
        }
        if last_failed_task
        else None
    )

    suggested_name = None
    try:
        from controller.services.group_manager import GroupManager
        from controller.services.naming import suggested_name_for
        from controller.services.tenant_config import load_groups
        groups_config = load_groups(tenant.id)
        group_names = GroupManager(tenant.id).evaluate_device_groups(device, groups_config)
        suggested_name = suggested_name_for(
            device, tenant.device_naming or {}, groups_config, group_names
        )
    except Exception:
        logger.exception("suggested_name computation failed for device %s", device_id)

    return {
        "device": {
            **_device_summary(device),
            "suggested_name": suggested_name,
            "attributes": device.attributes or {},
            "last_task_error": last_task_error,
        },
        "device_profiles": device.installed_profiles or [],
        "device_apps": device.installed_apps or [],
        "installed_apps": [app.to_dict() for app in apps],
        "installed_profiles": [profile.to_dict() for profile in profiles],
        "recent_tasks": [task.to_dict() for task in tasks],
    }


def _explain_scope(
    device: Device,
    device_groups: List[str],
    scope: Dict[str, Any],
    item_key: str,
    now: datetime,
) -> Dict[str, Any]:
    """Evaluate one profile or app-version scope against a device, and say why.

    Walks evaluate_scope's own precedence (exclude, include, groups+conditions, rollout) to name the deciding step.
    """
    from controller.services.scoping import (
        device_in_rollout,
        evaluate_condition,
        evaluate_scope,
        rollout_coverage,
    )

    serial = getattr(device, "serial_number", "") or ""
    exclude = scope.get("exclude_devices") or []
    if serial and serial in exclude:
        return {"matched": False, "reason": f"excluded: serial {serial} is in exclude_devices"}

    include = scope.get("include_devices") or []
    if serial and serial in include:
        matched = evaluate_scope(device, device_groups, scope)
        cherry_pick_reason = f"included: serial {serial} is cherry-picked in include_devices"
        if not matched:  # defensive; evaluate_scope agrees include wins outright
            return {"matched": False, "reason": cherry_pick_reason}
    else:
        groups = scope.get("groups") or []
        conditions = scope.get("conditions") or []
        if not groups and not conditions:
            return {
                "matched": False,
                "reason": "no groups or conditions configured on this scope "
                          "(include-only; this device was not cherry-picked)",
            }
        if groups and not any(g in device_groups for g in groups):
            return {
                "matched": False,
                "reason": f"not in any of the scoped groups: {', '.join(groups)}",
            }
        failing_condition = next(
            (c for c in conditions if not evaluate_condition(device, c, device_groups)),
            None,
        )
        if failing_condition is not None:
            neg = "negated " if failing_condition.get("negate") else ""
            return {
                "matched": False,
                "reason": (
                    f"{neg}condition did not match: {failing_condition.get('type')} "
                    f"{failing_condition.get('operator')} {failing_condition.get('value')!r}"
                ),
            }
        cherry_pick_reason = None

    # Groups, conditions or a cherry-pick matched; the rollout decides last.
    rollout = scope.get("rollout")
    if rollout:
        if not device_in_rollout(device, rollout, item_key, now):
            coverage = rollout_coverage(rollout, now)
            return {
                "matched": False,
                "reason": f"scoped, but held by gradual rollout (currently covering "
                          f"{coverage}% of devices; this device's wave hasn't opened yet)",
            }
        base = cherry_pick_reason or "matched by group/condition scope"
        return {"matched": True, "reason": f"{base}; in the current rollout wave"}

    return {"matched": True, "reason": cherry_pick_reason or "matched by group/condition scope"}


@app.get("/api/v1/devices/{device_id}/scope-explain")
async def explain_device_scope(
    device_id: str, principal: Principal = Depends(get_current_principal),
):
    """Explain why this device does or does not get each scoped profile, app, group and declaration (read-only,
    scoping only; GET /api/v1/devices/{device_id}/ddm answers whether a declaration actually reaches the device)."""
    tenant = principal.tenant
    _require_uuid(device_id, "Device not found")
    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    from controller.services.group_manager import GroupManager
    from controller.services.profile_manager import ProfileManager
    from controller.services.tenant_config import (
        load_apps, load_declarations, load_groups, load_profiles,
    )

    groups_config = load_groups(tenant.id)
    apps_config = load_apps(tenant.id)
    profiles_config = load_profiles(tenant.id)
    declarations_config = load_declarations(tenant.id).get("declarations") or []

    now = datetime.now(timezone.utc)
    device_groups = GroupManager(tenant.id).evaluate_device_groups(device, groups_config)
    device_platform = ProfileManager._device_platform(device)

    groups_out = []
    for group in groups_config:
        name = group.get("name")
        if not name:
            continue
        matched = name in device_groups
        if matched:
            reason = "matched by group's conditions (or a cherry-picked serial)"
        else:
            serial = getattr(device, "serial_number", "") or ""
            if serial and serial in (group.get("exclude_devices") or []):
                reason = f"excluded: serial {serial} is in exclude_devices"
            elif not (group.get("conditions") or []):
                reason = "group has no conditions (include-only; device not cherry-picked)"
            else:
                from controller.services.scoping import evaluate_condition
                failing = next(
                    (c for c in group.get("conditions") or []
                     if not evaluate_condition(device, c, device_groups)),
                    None,
                )
                if failing is not None:
                    neg = "negated " if failing.get("negate") else ""
                    reason = (
                        f"{neg}condition did not match: {failing.get('type')} "
                        f"{failing.get('operator')} {failing.get('value')!r}"
                    )
                else:
                    reason = "did not match this group's conditions"
        groups_out.append({"id": name, "name": name, "matched": matched, "reason": reason})

    profiles_out = []
    for profile in profiles_config:
        pid = profile.get("id")
        if not pid:
            continue
        if profile.get("dep_profile") or profile.get("type") == "enrollment":
            profiles_out.append({
                "id": pid, "name": profile.get("name", pid), "matched": False,
                "reason": "enrollment/DEP profile, not pushed as managed config",
            })
            continue
        platforms = profile.get("platforms")
        if platforms and device_platform not in platforms:
            profiles_out.append({
                "id": pid, "name": profile.get("name", pid), "matched": False,
                "reason": f"excluded by platform: device is {device_platform}, "
                          f"profile targets {', '.join(platforms)}",
            })
            continue
        outcome = _explain_scope(device, device_groups, profile, f"profile:{pid}", now)
        profiles_out.append({
            "id": pid, "name": profile.get("name", pid),
            "matched": outcome["matched"], "reason": outcome["reason"],
        })

    apps_out = []
    for app_entry in apps_config:
        app_id = app_entry.get("id")
        if not app_id:
            continue
        versions = app_entry.get("versions") or []
        chosen = None
        version_reasons = []
        for version in reversed(versions):
            outcome = _explain_scope(
                device, device_groups, version,
                f"app:{app_id}:{version.get('version')}", now,
            )
            version_reasons.append((version.get("version"), outcome))
            if outcome["matched"]:
                chosen = version
                break
        if chosen is not None:
            reason = f"version {chosen.get('version')} matched: {version_reasons[-1][1]['reason']}"
            apps_out.append({
                "id": app_id, "name": app_entry.get("name", app_id),
                "matched": True, "reason": reason,
            })
        elif version_reasons:
            # Nothing matched, so report the newest version's reason.
            newest_version, newest_outcome = version_reasons[0]
            apps_out.append({
                "id": app_id, "name": app_entry.get("name", app_id),
                "matched": False,
                "reason": f"no version matched (newest, {newest_version}: "
                          f"{newest_outcome['reason']})",
            })
        else:
            apps_out.append({
                "id": app_id, "name": app_entry.get("name", app_id),
                "matched": False, "reason": "app has no versions configured",
            })

    declarations_out = []
    for declaration in declarations_config:
        item_id = declaration.get("id")
        if not item_id or not declaration.get("type"):
            continue
        platforms = declaration.get("platforms")
        if platforms and device_platform not in platforms:
            declarations_out.append({
                "id": item_id, "name": declaration.get("name", item_id), "matched": False,
                "reason": f"excluded by platform: device is {device_platform}, "
                          f"declaration targets {', '.join(platforms)}",
            })
            continue
        # The rollout key has to be this exact string: it is what the build hashes to put the device in a wave, so a
        # different key here would describe a different wave from the one the device is in.
        outcome = _explain_scope(device, device_groups, declaration,
                                 f"declaration:{item_id}", now)
        declarations_out.append({
            "id": item_id, "name": declaration.get("name", item_id),
            "matched": outcome["matched"], "reason": outcome["reason"],
        })

    # The declarations the server manages for every device (activation, configuration set membership and the two status
    # subscriptions) are not in declarations.yaml and are not scoped, so there is no decision to explain about them.
    return {"profiles": profiles_out, "apps": apps_out, "groups": groups_out,
            "declarations": declarations_out}


class DeviceRename(BaseModel):
    name: str


@app.patch("/api/v1/devices/{device_id}/name")
async def rename_device(
    device_id: str,
    body: DeviceRename,
    principal: Principal = Depends(get_current_principal),
):
    """Set a device's managed name and, if it's enrolled, push the rename out via Settings/DeviceName. Supervised
    devices only."""
    tenant = principal.tenant
    _require_uuid(device_id, "Device not found")
    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name cannot be empty")
    if len(name) > 255:
        raise HTTPException(status_code=400, detail="Name too long (max 255 characters)")

    device.name = name
    await device.save(update_fields=["name"])

    # Push to the physical device when it has an active MDM channel. The rename only takes effect on a supervised
    # device; anywhere else the command errors and the task fails.
    task_id = None
    if device.enrollment_state == "enrolled" and device.udid:
        task = await task_manager.create_task(
            tenant=tenant, task_type="set_name",
            description=f"Rename {device.serial_number} to {name!r}",
            device=device, user=principal.email, details={},
        )
        mdm_connector = MDMConnector()
        try:
            result = await mdm_connector.set_device_name(device.udid, name)
            task.details["command_uuid"] = result.get("command_uuid")
            task.status = "running"
            await task.save()
            task_id = str(task.id)
        except Exception as exc:
            task.status = "failed"
            task.error = str(exc)
            # Terminal rows outside Task.update_progress have to stamp this themselves; retention keys its delete on
            # completed_at, so a row left NULL here is never reclaimed.
            task.completed_at = datetime.now(timezone.utc)
            await task.save()
            logger.error(f"Rename push failed for {device.udid}: {exc}")
        finally:
            await mdm_connector.close()

    return {"device": _device_summary(device), "pushed": task_id is not None, "task_id": task_id}


class DeviceTagsUpdate(BaseModel):
    add: List[str] = []
    remove: List[str] = []


@app.post("/api/v1/devices/{device_id}/tags")
async def update_device_tags(
    device_id: str,
    body: DeviceTagsUpdate,
    principal: Principal = Depends(get_current_principal),
):
    """Add and/or remove imperative tags on a device (member+).

    Since tags can drive group membership, the write is followed by a group recompute and reactive reconcile.
    """
    tenant = principal.tenant
    _require_uuid(device_id, "Device not found")
    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    def _clean(items: List[str]) -> List[str]:
        seen: List[str] = []
        for raw in items or []:
            s = str(raw).strip()
            if not s:
                continue
            if len(s) > 100:
                raise HTTPException(
                    status_code=400, detail=f"Tag too long (max 100 characters): {s[:20]}..."
                )
            if s not in seen:
                seen.append(s)
        return seen

    add = _clean(body.add)
    remove = _clean(body.remove)
    if not add and not remove:
        raise HTTPException(status_code=400, detail="No tags to add or remove")

    current = [str(t) for t in (device.tags or [])]
    before = set(current)
    remove_set = set(remove)
    # Preserve existing order; drop removals, then append the new tags.
    result = [t for t in current if t not in remove_set]
    for t in add:
        if t not in result:
            result.append(t)
    after = set(result)

    if after == before:
        # Nothing changed, so skip the write, the reconcile and the audit.
        return {"device": _device_summary(device), "changed": False,
                "added": [], "removed": []}

    device.tags = result
    await device.save(update_fields=["tags"])

    added = sorted(after - before)
    removed = sorted(before - after)

    # Recompute groups so profile and app scoping follows the new tags. Best effort: a malformed groups.yaml must not
    # fail the tag write.
    groups_changed = False
    try:
        from controller.services.group_manager import GroupManager
        from controller.services.tenant_config import load_groups
        groups_config = load_groups(tenant.id)
        new_groups = GroupManager(tenant.id).evaluate_device_groups(device, groups_config)
        # Compared as sets: a reorder of the same membership is not a change and must not produce a write or a
        # groups_changed of its own.
        if set(new_groups) != set(device.groups or []):
            device.groups = new_groups
            await device.save(update_fields=["groups"])
            groups_changed = True
    except Exception:
        logger.exception("group recompute after tag update failed for device %s", device_id)

    try:
        task = await task_manager.create_task(
            tenant=tenant, task_type="tag_update",
            description=f"Tags updated on {device.serial_number}",
            device=device, user=principal.email,
            details={"added": added, "removed": removed, "tags": result},
        )
        await task.update_progress(100, "completed")
    except Exception:
        logger.exception("tag_update audit task failed for device %s", device_id)

    await record_tag_change(
        device, added=added, removed=removed,
        source="console", principal=principal,
    )

    _spawn_tenant_reconcile(tenant.id)

    return {"device": _device_summary(device), "changed": True,
            "added": added, "removed": removed, "groups_changed": groups_changed}


# Declarative Device Management

_DDM_AUTO_NAMES = {
    "mm.cfg.status-subscriptions": "Status subscriptions",
    "mm.act.status-subscriptions": "Status subscriptions (activation)",
    "mm.mgmt.org-info": "Organization info",
    "mm.mgmt.properties": "Device properties",
    "mm.mgmt.server-capabilities": "Server capabilities",
}


def _ddm_desired_entry(decl: Dict[str, Any], names_by_id: Dict[str, str],
                       include_payload: bool) -> Dict[str, Any]:
    """One computed declaration as the API returns it: source is the yaml id for authored items and their paired
    activations, "auto" for the rest."""
    identifier = str(decl.get("Identifier") or "")
    source = "auto"
    if identifier not in _DDM_AUTO_NAMES:
        for prefix in ("mm.cfg.", "mm.act."):
            if identifier.startswith(prefix):
                source = identifier[len(prefix):]
                break
    if source != "auto":
        name = names_by_id.get(source) or source
    else:
        name = _DDM_AUTO_NAMES.get(identifier, identifier)
    entry = {
        "identifier": identifier,
        "type": decl.get("Type"),
        "server_token": decl.get("ServerToken"),
        "source": source,
        "name": name,
    }
    if include_payload:
        entry["payload"] = decl.get("Payload") or {}
    return entry


@app.get("/api/v1/devices/{device_id}/ddm")
async def get_device_ddm(
    device_id: str,
    include_payloads: bool = False,
    principal: Principal = Depends(get_current_principal),
):
    """DDM state for a device: the desired declaration set, computed now, joined with what the device last reported,
    plus the raw status-item tree. Payloads are omitted unless include_payloads=1, which keeps the response small."""
    tenant = principal.tenant
    _require_uuid(device_id, "Device not found")
    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    from controller.services import ddm_manager
    from controller.services.tenant_config import load_declarations

    desired_full = await ddm_manager.compute_device_declarations(device, tenant)
    names_by_id = {
        str(d.get("id")): d.get("name")
        for d in load_declarations(tenant.id).get("declarations") or []
        if isinstance(d, dict) and d.get("id")
    }
    reported = device.ddm_declaration_status or {}

    predicated = set()
    for d in desired_full:
        if d.get("Type") == "com.apple.activation.simple" \
            and (d.get("Payload") or {}).get("Predicate"):
            ident = d.get("Identifier") or ""
            predicated.add(ident)
            if ident.startswith("mm.act."):
                predicated.add("mm.cfg." + ident[len("mm.act."):])
    drift: List[str] = []
    if device.ddm_enabled_at:
        for d in desired_full:
            ident = d.get("Identifier")
            if (d.get("Type") or "").startswith("com.apple.management."):
                continue
            state = reported.get(ident)
            if not isinstance(state, dict):
                drift.append(ident)
            elif state.get("valid") == "invalid" \
                or (state.get("active") is not True and ident not in predicated):
                drift.append(ident)
    return {
        "supported": ddm_manager.device_supports_ddm(device),
        "tenant_enabled": tenant.ddm_enabled,
        "enabled_at": device.ddm_enabled_at,
        "last_sync_at": device.ddm_last_sync_at,
        "last_published_token": device.ddm_last_published_token,
        "desired": [_ddm_desired_entry(d, names_by_id, include_payloads)
                    for d in desired_full],
        "reported": reported,
        "status_items": device.ddm_status or {},
        "client_capabilities": device.ddm_client_capabilities or {},
        "drift": drift,
    }


@app.post("/api/v1/devices/{device_id}/ddm/sync")
async def force_device_ddm_sync(
    device_id: str,
    admin: Principal = Depends(require_admin),
):
    """Force a declarative sync now (admin only).

    Clears the published token (so an unchanged set still sends) and the recorded failure (so backoff is bypassed)."""
    tenant = admin.tenant
    _require_uuid(device_id, "Device not found")
    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.enrollment_state != "enrolled":
        raise HTTPException(
            status_code=409,
            detail=f"Device is {device.enrollment_state}; commands can only be sent to enrolled devices",
        )

    from controller.services import ddm_manager
    device.ddm_last_published_token = None
    device.attributes = {k: v for k, v in (device.attributes or {}).items()
                         if k != ddm_manager.SYNC_FAILURE_KEY}
    await device.save(update_fields=["ddm_last_published_token", "attributes"])
    queued = await ddm_manager.sync_device(device, reason="manual")
    failure = queued if isinstance(queued, ddm_manager.EnqueueFailed) else None
    await record_audit(
        admin,
        "device.ddm_sync",
        target_type="device",
        target_id=device_id,
        detail={"serial_number": device.serial_number,
                "queued": False if failure is not None else bool(queued),
                **({"error": failure.reason} if failure is not None else {})},
    )
    if failure is not None:
        raise HTTPException(
            status_code=502,
            detail=f"The declarative sync could not be queued: {failure.reason}",
        )
    return {"queued": bool(queued)}


_DECLARATION_SCOPE_FIELDS = (
    "id", "serial_number", "device_model", "os_version", "hostname",
    "enrollment_date", "tags", "attributes",
)


@app.get("/api/v1/declarations")
async def list_declarations(principal: Principal = Depends(get_current_principal)):
    """Declarations listing: parsed declarations.yaml plus, per item, how many enrolled devices its scope matches right
    now. Platform and unified scope only; rollout waves are not simulated here.
    """
    tenant = principal.tenant
    from controller.services import ddm_manager
    from controller.services.group_manager import GroupManager
    from controller.services.profile_manager import ProfileManager
    from controller.services.scoping import evaluate_scope
    from controller.services.tenant_config import load_declarations, load_groups

    cfg = load_declarations(tenant.id)
    groups_config = load_groups(tenant.id)
    devices = await Device.filter(
        tenant=tenant, enrollment_state="enrolled"
    ).only(*_DECLARATION_SCOPE_FIELDS).all()
    gm = GroupManager(tenant.id)
    memberships = []
    for d in devices:
        try:
            memberships.append((d, ProfileManager._device_platform(d),
                                gm.evaluate_device_groups(d, groups_config)))
        except Exception:
            logger.exception("declarations: group eval failed for %s", d.serial_number)

    items: List[Dict[str, Any]] = []
    for item in cfg.get("declarations") or []:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        platforms = item.get("platforms") or []
        scoped = 0
        for device, platform, device_groups in memberships:
            try:
                if platforms and platform not in platforms:
                    continue
                if evaluate_scope(device, device_groups, item):
                    scoped += 1
            except Exception:
                continue  # a bad condition skips the device, not the listing
        entry: Dict[str, Any] = {
            "id": str(item["id"]),
            "name": item.get("name") or str(item["id"]),
            "type": item.get("type"),
            "scope": {
                "platforms": platforms,
                "groups": item.get("groups") or [],
                "conditions": len(item.get("conditions") or []),
                "include_devices": len(item.get("include_devices") or []),
                "exclude_devices": len(item.get("exclude_devices") or []),
                "rollout": bool(item.get("rollout")),
            },
            "scoped_count": scoped,
        }
        blocked = ddm_manager.undeliverable_reason(item, tenant.id)
        if blocked:
            entry["not_served"] = blocked
        if item.get("description"):
            entry["description"] = item["description"]
        items.append(entry)
    return {"declarations": items, "ddm_enabled": tenant.ddm_enabled}


# ==Scope preview==

_SCOPE_KEYS = ("groups", "conditions", "include_devices", "exclude_devices")

SCOPE_PREVIEW_SCAN_CAP = 5000
SCOPE_PREVIEW_MAX_SAMPLE = 25

# Time budget for the walk, so a slow scope answers late rather than never.
SCOPE_PREVIEW_TIME_BUDGET_SECONDS = 2.0

_SCOPE_PREVIEW_FIELDS = (
    "id", "name", "serial_number", "device_model", "os_version", "hostname",
    "enrollment_date", "tags", "attributes", "groups", "dep_profile_uuid",
)


def _scope_is_empty(scope: Optional[Dict[str, Any]]) -> bool:
    """True when a scope is empty by the engines' own predicate.

    A copy of the same test in services.atc and services.dispatcher, kept in sync by the verify suite's agreement case.
    """
    scope = scope or {}
    return not any(scope.get(k) for k in _SCOPE_KEYS)


class ScopePreviewRequest(BaseModel):
    # The scope as authored. Passed verbatim to services.scoping.evaluate_scope.
    scope: Optional[Dict[str, Any]] = None
    # Required, no default: empty means every device to a flow start/dispatcher rule but none to a profile/app
    # version, so an undecided caller gets a 422 rather than a confident wrong number.
    empty_scope: Literal["all", "none"]
    # A flow start only runs for devices of its own trigger kind, which is narrower than every device. Absent means the
    # whole enrolled fleet.
    trigger_kind: Optional[
        Literal["enroll_dep", "enroll_profile", "checkin", "schedule"]
    ] = None
    sample_limit: int = 5


class _ScopePreviewExpired(Exception):
    """The preview walk ran out of time partway through one device."""


class _DeadlineConditions(list):
    """A scope's condition list that stops the walk once its budget is spent.

    Only safe where the caller treats a partial count as a floor, as this endpoint's truncated flag does.
    """

    def __init__(self, conditions: List[Any], deadline: float):
        super().__init__(conditions)
        self._deadline = deadline

    def __iter__(self):
        for condition in list.__iter__(self):
            if time.monotonic() > self._deadline:
                raise _ScopePreviewExpired()
            yield condition


def _walk_scope_preview(rows: List[Device], scope: Dict[str, Any], sample_limit: int):
    """Count the devices a non-empty scope matches, as (matched, scanned, sample, expired).

    Synchronous and CPU-bound, so the endpoint runs it through asyncio.to_thread; the rows arrive already loaded.
    """
    from controller.services.scoping import evaluate_scope

    deadline = time.monotonic() + SCOPE_PREVIEW_TIME_BUDGET_SECONDS
    walk_scope = dict(scope)
    conditions = walk_scope.get("conditions")
    if isinstance(conditions, list) and conditions:
        walk_scope["conditions"] = _DeadlineConditions(conditions, deadline)

    matched = 0
    scanned = 0
    sample: List[Device] = []
    for device in rows:
        if time.monotonic() > deadline:
            return matched, scanned, sample, True
        try:
            hit = evaluate_scope(device, list(device.groups or []), walk_scope)
        except _ScopePreviewExpired:
            return matched, scanned, sample, True
        scanned += 1
        if not hit:
            continue
        matched += 1
        if len(sample) < sample_limit:
            sample.append(device)
    return matched, scanned, sample, False


def _scope_preview_row(device: Device) -> Dict[str, Any]:
    """One named example of a matched device."""
    from controller.services.naming import display_name
    return {
        "id": str(device.id),
        "display_name": display_name(device),
        "serial_number": device.serial_number,
        "device_model": device.device_model,
    }


@app.post("/api/v1/scope/preview")
async def preview_scope(
    body: ScopePreviewRequest,
    principal: Principal = Depends(get_current_principal),
):
    """Count how many devices this scope matches right now, with a sample of them, computed the same way
    sweep_scheduled_starts does and read-only by construction."""
    tenant = principal.tenant
    from tortoise.expressions import Q
    from controller.services.scoping import MAX_SCOPE_CONDITIONS

    scope = body.scope or {}
    sample_limit = max(0, min(int(body.sample_limit), SCOPE_PREVIEW_MAX_SAMPLE))

    # kaboom goes the CPU
    conditions = scope.get("conditions")
    if isinstance(conditions, list) and len(conditions) > MAX_SCOPE_CONDITIONS:
        raise HTTPException(
            status_code=400,
            detail=(f"A scope preview accepts at most {MAX_SCOPE_CONDITIONS} conditions; "
                    f"this one has {len(conditions)}. Narrow it with a group instead."),
        )

    base = Device.filter(tenant=tenant, enrollment_state="enrolled")
    total = await base.count()

    eligible_q = base
    if body.trigger_kind == "enroll_dep":
        eligible_q = base.exclude(dep_profile_uuid__isnull=True).exclude(dep_profile_uuid="")
    elif body.trigger_kind == "enroll_profile":
        eligible_q = base.filter(Q(dep_profile_uuid__isnull=True) | Q(dep_profile_uuid=""))
    eligible = await eligible_q.count()

    is_empty = _scope_is_empty(scope)
    scanned = 0
    truncated = False
    sample_rows: List[Device] = []

    if is_empty:
        matched = eligible if body.empty_scope == "all" else 0
        if matched and sample_limit:
            sample_rows = (
                await eligible_q.order_by("id").limit(sample_limit)
                .only(*_SCOPE_PREVIEW_FIELDS).all()
            )
    else:
        rows = (
            await eligible_q.order_by("id").limit(SCOPE_PREVIEW_SCAN_CAP)
            .only(*_SCOPE_PREVIEW_FIELDS).all()
        )
        truncated = eligible > SCOPE_PREVIEW_SCAN_CAP
        matched, scanned, sample_rows, expired = await asyncio.to_thread(
            _walk_scope_preview, rows, scope, sample_limit)
        truncated = truncated or expired

    return {
        "matched": matched,
        "eligible": eligible,
        "total": total,
        # The reading that produced matched, echoed so the count cannot be attributed to the wrong one.
        "scope_is_empty": is_empty,
        "empty_scope": body.empty_scope,
        "trigger_kind": body.trigger_kind,
        # scanned and truncated describe the walk; truncated makes matched a floor rather than a total.
        "scanned": scanned,
        "truncated": truncated,
        "sample": [_scope_preview_row(d) for d in sample_rows],
    }


# ==ATC flow runs==

class FlowRunStart(BaseModel):
    start_node_id: str
    flow_id: Optional[str] = None


class GateDecision(BaseModel):
    edge: str


class AlertAction(BaseModel):
    action_key: str


FLOW_RUN_GUARD_SCAN_CAP = 1000


def _flow_run_row(run: FlowRun) -> Dict[str, Any]:
    """One row of the fleet run list; the device must be prefetched. Lighter than FlowRun.to_dict()."""
    ctx = run.context or {}
    gaps = ctx.get("gaps") or []
    device = run.device if run.device_id else None
    return {
        "id": str(run.id),
        "device_id": str(run.device_id) if run.device_id else None,
        "device": {
            "serial_number": device.serial_number,
            "hostname": device.hostname,
            "device_model": device.device_model,
        } if device else None,
        "flow_id": run.flow_id,
        "start_node": run.start_node,
        "event_kind": run.event_kind,
        "status": run.status,
        "current_node": run.current_node,
        "waiting_signal": run.waiting_signal,
        "waiting_ref": run.waiting_ref,
        "wait_deadline": run.wait_deadline.isoformat() if run.wait_deadline else None,
        "error": run.error,
        "released_unverified": bool(ctx.get("unverified")),
        "gap_count": len(gaps),
        "gap_grade": ("broken" if any(g.get("grade") == "broken" for g in gaps)
                      else ("policy" if gaps else None)),
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "updated_at": run.updated_at.isoformat() if run.updated_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
    }


@app.get("/api/v1/flow-runs")
async def list_flow_runs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    status: Optional[str] = Query(
        None,
        description="running | waiting | completed | failed | cancelled; "
                    "comma-separated for a set",
    ),
    flow: Optional[str] = None,
    event_kind: Optional[str] = Query(
        None, description="enroll_dep | enroll_profile | checkin | schedule"),
    device_id: Optional[str] = None,
    waiting_signal: Optional[str] = Query(
        None, description="what a parked run is waiting on; 'manual' is a human"),
    released_unverified: bool = False,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    parked_before: Optional[datetime] = None,
    principal: Principal = Depends(get_current_principal),
):
    """Flow runs across the whole tenant: counts by status, and a slice of the newest rows."""
    tenant = principal.tenant

    def population():
        """The rows this request is about, before the status filters narrow them."""
        q = FlowRun.filter(tenant=tenant)
        if flow:
            q = q.filter(flow_id=flow)
        if event_kind:
            q = q.filter(event_kind=event_kind)
        if device_id:
            q = _filter_device_id(q, device_id)
        if since:
            q = q.filter(started_at__gte=since)
        if until:
            q = q.filter(started_at__lte=until)
        return q

    from tortoise.functions import Count
    counts_raw = (
        await population().annotate(count=Count("id")).group_by("status")
        .values("status", "count")
    )
    counts = {c["status"]: c["count"] for c in counts_raw}
    summary = {
        "all": sum(counts.values()),
        "running": counts.get("running", 0),
        "waiting": counts.get("waiting", 0),
        "completed": counts.get("completed", 0),
        "failed": counts.get("failed", 0),
        "cancelled": counts.get("cancelled", 0),
        "on_gate": await population().filter(
            status="waiting", waiting_signal="manual").count(),
        "released_unverified": 0,
    }

    guard_ids: List[Any] = []
    scan_capped = False
    if summary["failed"]:
        scan = (
            await population().filter(status="failed").order_by("-started_at")
            .limit(FLOW_RUN_GUARD_SCAN_CAP + 1).only("id", "context").all()
        )
        scan_capped = len(scan) > FLOW_RUN_GUARD_SCAN_CAP
        guard_ids = [r.id for r in scan[:FLOW_RUN_GUARD_SCAN_CAP]
                     if (r.context or {}).get("unverified")]
        summary["released_unverified"] = len(guard_ids)

    query = population()
    states = [s.strip() for s in status.split(",") if s.strip()] if status else []
    if states:
        query = query.filter(status__in=states)
    if waiting_signal:
        query = query.filter(waiting_signal=waiting_signal)
    if parked_before:
        query = query.filter(status="waiting", updated_at__lt=parked_before)
    if released_unverified:
        # Back through SQL as an id set, so total and pagination stay exact rather than being counted over a Python
        # slice.
        query = query.filter(id__in=guard_ids)

    total = await query.count()
    runs = (
        await query.order_by("-started_at").offset(skip).limit(limit)
        .prefetch_related("device").all()
    )

    flow_ids = sorted(
        {f for f in await FlowRun.filter(tenant=tenant).order_by("flow_id").distinct()
        .values_list("flow_id", flat=True) if f}
    )
    from controller.services import atc
    doc_flows = atc._load_flows(str(tenant.id))
    flow_names = {f["id"]: f.get("name") or f["id"] for f in doc_flows if f.get("id")}

    return {
        "total": total,
        "counts": summary,
        # True when the failed set was longer than the guard scan reads, which makes released_unverified a floor instead
        # of a total. Narrow the window and it becomes exact again.
        "scan_capped": scan_capped,
        "retention_days": FLOW_RUN_RETENTION_DAYS,
        "flow_ids": flow_ids,
        "flow_names": flow_names,
        "flow_runs": [_flow_run_row(r) for r in runs],
    }


@app.get("/api/v1/devices/{device_id}/flow-runs")
async def list_device_flow_runs(
    device_id: str,
    principal: Principal = Depends(get_current_principal),
):
    """ATC flow runs for a device (most recent first)."""
    tenant = principal.tenant
    _require_uuid(device_id, "Device not found")
    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    runs = await FlowRun.filter(device=device).order_by("-started_at").limit(50).all()
    return {"flow_runs": [run.to_dict() for run in runs]}


@app.get("/api/v1/flow-runs/{run_id}")
async def get_flow_run(run_id: str, principal: Principal = Depends(get_current_principal)):
    """Get one flow run with the flow definition it executed, reported as pinned, current, edited or unavailable
    depending on whether flows.yaml still matches."""
    _require_uuid(run_id, "Flow run not found")
    run = await FlowRun.get_or_none(id=run_id, tenant=principal.tenant)
    if not run:
        raise HTTPException(status_code=404, detail="Flow run not found")
    data = run.to_dict()

    pinned = (run.context or {}).get("flow")
    if pinned:
        # Whatever the nodes held at the start, static passwords included, so it gets the same redaction as a read of
        # flows.yaml.
        data["flow"] = _redact_flow(pinned)
        data["flow_source"] = "pinned"
        return data

    from controller.services import atc

    current = atc._load_flow(str(run.tenant_id), str(run.flow_id))
    if current is None:
        data["flow"] = None
        data["flow_source"] = "unavailable"
        return data
    data["flow"] = _redact_flow(current)
    data["flow_source"] = "current" if atc._flow_hash(current) == run.flow_hash else "edited"
    return data


@app.post("/api/v1/devices/{device_id}/flow-runs", status_code=201)
async def start_device_flow_run(
    device_id: str,
    body: FlowRunStart,
    principal: Principal = Depends(get_current_principal),
):
    """Start a run from a named start node against one device, for a test or a re-run. The start's own scope is ignored,
    since the caller named the device."""
    tenant = principal.tenant
    _require_uuid(device_id, "Device not found")
    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.enrollment_state != "enrolled":
        raise HTTPException(
            status_code=409,
            detail=f"Device is {device.enrollment_state}; flows run only on enrolled devices",
        )
    from controller.services import atc
    start_id = body.start_node_id.strip()
    flow_id = body.flow_id.strip() if body.flow_id else None
    if flow_id is None:
        candidates = atc.flows_with_start(str(tenant.id), start_id)
        if len(candidates) > 1:
            raise HTTPException(
                status_code=409,
                detail=f"Start node '{start_id}' exists in flows {candidates}; pass flow_id",
            )
    run = await atc.start_run_from_start(device, start_id, flow_id)
    if run is None:
        raise HTTPException(
            status_code=400,
            detail=f"Start node '{body.start_node_id}' not found or is not a start node",
        )
    return run.to_dict()


@app.post("/api/v1/flow-runs/{run_id}/resume")
async def resume_flow_run(
    run_id: str,
    body: GateDecision,
    principal: Principal = Depends(get_current_principal),
):
    """Resume a run parked on a manual_gate down the chosen decision edge. The edge must be one the gate offers, and a
    run that is already decided is left as it is."""
    _require_uuid(run_id, "Flow run not found")
    run = await FlowRun.get_or_none(id=run_id, tenant=principal.tenant)
    if not run:
        raise HTTPException(status_code=404, detail="Flow run not found")
    from controller.services import atc
    result = await atc.resume_manual_gate(run_id, body.edge.strip(), principal.email)
    if result is None:
        raise HTTPException(status_code=400, detail="Could not resume run")
    return result.to_dict()


#  device specific escrowed secrets

@app.get("/api/v1/devices/{device_id}/secrets")
async def list_device_secrets(
    device_id: str,
    admin: Principal = Depends(require_admin),
):
    """A device's escrowed secrets (managed-admin, firmware and recovery-lock passwords), as metadata only. The values
    come from the reveal endpoint below. Admin only."""
    _require_uuid(device_id, "Device not found")
    device = await Device.get_or_none(id=device_id, tenant=admin.tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    from controller.services import device_secrets
    secrets = await device_secrets.list_for_device(device)
    return {"secrets": [s.to_dict() for s in secrets]}


def _reveal_throttle_message(verdict: Verdict) -> str:
    """The refusal text for a throttled reveal: how long the wait is, and the way round it."""
    minutes = max(1, round(verdict.retry_after / 60))
    return (
        f"Your account is throttled. You have revealed {verdict.count} secrets in "
        f"the last {reveal_limiter.window_minutes} minutes, which is the limit. "
        f"Wait about {minutes} minute{'s' if minutes != 1 else ''} for the window "
        f"to clear, or hand the rest of the list to another admin. For a recovery "
        f"bigger than the limit allows, raise BREAKGLASS_REVEAL_CEILING on the "
        f"controller."
    )


@app.post("/api/v1/devices/{device_id}/secrets/{kind}/reveal")
async def reveal_device_secret(
    device_id: str,
    kind: str,
    admin: Principal = Depends(require_admin),
):
    """Return an escrowed secret's plaintext (admin only); the reveal is audit-logged, alerts the device, and is
    rate-limited per admin with escalation and an outright ceiling."""
    if kind not in DeviceSecret.KINDS:
        raise HTTPException(status_code=400, detail="Unknown secret kind")
    _require_uuid(device_id, "Device not found")
    device = await Device.get_or_none(id=device_id, tenant=admin.tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    throttle = reveal_limiter.check(f"{admin.tenant.id}:{admin.user.id}")
    if not throttle.allowed:
        # Audited too. A refused reveal is the most interesting one in the log.
        await record_audit(
            admin, "device_secret.reveal_throttled",
            target_type="device", target_id=str(device.id),
            detail={"kind": kind, "serial_number": device.serial_number,
                    "reveals_in_window": throttle.count,
                    "window_minutes": reveal_limiter.window_minutes},
        )
        raise HTTPException(status_code=429, detail=_reveal_throttle_message(throttle),
                            headers={"Retry-After": str(throttle.retry_after)})

    secret = await DeviceSecret.get_or_none(device_id=device.id, kind=kind)
    if not secret:
        raise HTTPException(status_code=404, detail="No such secret is escrowed for this device")

    from controller.services import device_secrets
    plaintext = await device_secrets.reveal(
        secret, f"admin:{admin.email}",
        escalated=throttle.escalated, reveals_in_window=throttle.count)
    if plaintext is None:
        # The stored value could not be decrypted: corrupt, the key was rotated, or the row is bound to a different
        # device from the one it is filed under.
        raise HTTPException(
            status_code=409,
            detail="The escrowed secret could not be decrypted (encryption key "
                   "changed or the value is corrupt). Re-provision it.",
        )
    # Audit AFTER the reveal succeeded; the detail carries NO secret material.
    await record_audit(
        admin, "device_secret.reveal",
        target_type="device", target_id=str(device.id),
        detail={"kind": kind, "serial_number": device.serial_number,
                "reveal_count": secret.reveal_count,
                "reveals_in_window": throttle.count,
                "escalated": throttle.escalated},
    )
    return {
        "kind": kind,
        "kind_label": secret.kind_label,
        "label": secret.label,
        "value": plaintext,
        # public_meta, not meta: a rotation parks the ciphertext of the NEW password under pending_value_enc, and this
        # body is the one place the OLD one is handed over. Same projection DeviceSecret.to_dict uses.
        "meta": secret.public_meta(),
        "revealed_at": secret.revealed_at.isoformat() if secret.revealed_at else None,
        "reveal_count": secret.reveal_count,
    }


#  Dispatcher alerts

async def _enrich_alerts(alerts: List[Alert]) -> List[Dict[str, Any]]:
    """Alert dicts with a small device summary each, sorted by severity from black down to green, then by most recently
    updated."""
    from controller.services.dispatcher import SEVERITY_RANK
    from controller.services.naming import display_name

    device_ids = {a.device_id for a in alerts if a.device_id}
    devices = {
        str(d.id): d for d in await Device.filter(id__in=list(device_ids)).all()
    } if device_ids else {}
    out = []
    for a in alerts:
        item = a.to_dict()
        dev = devices.get(str(a.device_id))
        item["device"] = {
            "serial_number": dev.serial_number if dev else None,
            "display_name": display_name(dev) if dev else None,
        } if dev else None
        out.append(item)
    out.sort(key=lambda i: (SEVERITY_RANK.get(i["severity"], 0), i["updated_at"] or ""),
             reverse=True)
    return out


@app.get("/api/v1/alerts")
async def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    device_id: Optional[str] = None,
    principal: Principal = Depends(get_current_principal),
):
    """Compliance alerts, most severe and newest first."""
    query = Alert.filter(tenant=principal.tenant)
    if severity:
        query = query.filter(severity=severity)
    if status:
        query = query.filter(status=status)
    if device_id:
        query = _filter_device_id(query, device_id)
    alerts = await query.limit(1000).all()
    items = await _enrich_alerts(alerts)
    # Counts every unresolved alert by severity independent of the severity/status filters above (device filter
    # still applies), so selecting one severity does not zero the others. Grouped aggregate, not a row scan.
    count_q = Alert.filter(tenant=principal.tenant).exclude(status="resolved")
    if device_id:
        count_q = _filter_device_id(count_q, device_id)
    from tortoise.functions import Count
    counts_raw = (
        await count_q.annotate(count=Count("id")).group_by("severity")
        .values("severity", "count")
    )
    # The four known severities are always present and zero-filled. active totals every unresolved alert, including one
    # whose severity is outside that set, which a hand-edited dispatcher.yaml can produce.
    counts = {s: 0 for s in ("black", "red", "yellow", "green")}
    active = 0
    for row in counts_raw:
        active += row["count"]
        if row["severity"] in counts:
            counts[row["severity"]] = row["count"]
    return {"alerts": items, "counts": counts, "active": active}


@app.get("/api/v1/alerts/{alert_id}")
async def get_alert(alert_id: str, principal: Principal = Depends(get_current_principal)):
    _require_uuid(alert_id, "Alert not found")
    alert = await Alert.get_or_none(id=alert_id, tenant=principal.tenant)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return (await _enrich_alerts([alert]))[0]


@app.post("/api/v1/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, principal: Principal = Depends(get_current_principal)):
    """Mark an open alert as seen, without closing it."""
    _require_uuid(alert_id, "Alert not found")
    alert = await Alert.get_or_none(id=alert_id, tenant=principal.tenant)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status == "resolved":
        raise HTTPException(status_code=409, detail="Alert is already resolved")
    alert.status = "acknowledged"
    alert.acknowledged_at = datetime.now(timezone.utc)
    alert.acknowledged_by = principal.email
    await alert.save(update_fields=["status", "acknowledged_at", "acknowledged_by"])
    return alert.to_dict()


@app.post("/api/v1/alerts/{alert_id}/unacknowledge")
async def unacknowledge_alert(alert_id: str, principal: Principal = Depends(get_current_principal)):
    """Move an acknowledged alert back to open."""
    _require_uuid(alert_id, "Alert not found")
    alert = await Alert.get_or_none(id=alert_id, tenant=principal.tenant)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status == "resolved":
        raise HTTPException(status_code=409, detail="Alert is already resolved")
    if alert.status != "acknowledged":
        raise HTTPException(status_code=409, detail="Alert is not acknowledged")
    alert.status = "open"
    alert.acknowledged_at = None
    alert.acknowledged_by = None
    await alert.save(update_fields=["status", "acknowledged_at", "acknowledged_by"])
    return alert.to_dict()


class AlertResolve(BaseModel):
    reason: Optional[str] = None


@app.post("/api/v1/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    body: Optional[AlertResolve] = None,
    principal: Principal = Depends(get_current_principal),
):
    """Manually resolve an alert, reversing what can be reversed; a reveal alert needs an admin to dismiss and is
    audit-logged, though rotating the password via escrow is the usual way to close one."""
    _require_uuid(alert_id, "Alert not found")
    alert = await Alert.get_or_none(id=alert_id, tenant=principal.tenant)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status == "resolved":
        return alert.to_dict()

    from controller.services import device_secrets
    breakglass = device_secrets.is_breakglass_alert(alert)
    reason = ((body.reason if body else None) or "").strip()
    if breakglass:
        if not principal.is_admin:
            raise HTTPException(
                status_code=403,
                detail="Only an admin can dismiss a break-glass alert. It records "
                       "that a device password was handed to somebody, and it "
                       "closes on its own once that password is rotated.",
            )
        resolve_reason = (f"dismissed by {principal.email}: "
                          f"{reason or 'no reason stated'}")
    else:
        resolve_reason = f"resolved by {principal.email}"

    # A manual_gate alert dismissed without a decision must not leave its run parked forever, so the run is failed. A
    # real decision comes through the run's own resume path, which resolves the alert itself.
    detail = alert.detail or {}
    if detail.get("kind") == "atc_gate" and detail.get("flow_run_id"):
        from controller.services import atc
        await atc.fail_gate_run(detail["flow_run_id"], f"gate dismissed by {principal.email}")
    from controller.services import dispatcher
    device = await Device.get_or_none(id=alert.device_id)
    if device is not None:
        await dispatcher._resolve_alert(alert, device, resolve_reason)
    else:
        alert.detail = {**detail, "resolved_reason": resolve_reason}
        alert.status = "resolved"
        alert.resolved_at = datetime.now(timezone.utc)
        await alert.save(update_fields=["status", "resolved_at", "detail"])
    if breakglass:
        # The alert's own detail keeps the reveal record, but retention can age an alert row out and the audit log
        # outlives it.
        await record_audit(
            principal, "alert.breakglass_dismiss",
            target_type="alert", target_id=str(alert.id),
            detail={"device_id": str(alert.device_id) if alert.device_id else None,
                    "secret_kind": detail.get("secret_kind"),
                    "reveal_count": detail.get("reveal_count"),
                    "last_revealed_by": detail.get("last_revealed_by"),
                    "reason": reason or None},
        )
    return alert.to_dict()


@app.post("/api/v1/alerts/{alert_id}/action")
async def alert_action(
    alert_id: str,
    body: AlertAction,
    principal: Principal = Depends(get_current_principal),
):
    """Take a typed action on an ATC alert: release an ADE device from Setup Assistant for an in-setup alert, or make a
    manual_gate decision, where action_key is the gate edge."""
    _require_uuid(alert_id, "Alert not found")
    alert = await Alert.get_or_none(id=alert_id, tenant=principal.tenant)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    detail = alert.detail or {}
    kind = detail.get("kind")
    from controller.services import atc
    if kind == "atc_in_setup":
        if body.action_key != "release":
            raise HTTPException(status_code=400, detail="Unsupported action for this alert")
        device = await Device.get_or_none(id=alert.device_id, tenant=principal.tenant)
        if device is None:
            raise HTTPException(status_code=404, detail="Device not found")
        ok, reason = await atc.release_device_manual(device, principal.email)
        if not ok:
            # The helper's own reason: a generic "not enrolled" fallback would be wrong for a device that enrolled over
            # the air, which is enrolled and still cannot be released.
            raise HTTPException(
                status_code=409,
                detail=reason or "This device cannot be released from Setup Assistant.",
            )
        refreshed = await Alert.get_or_none(id=alert_id, tenant=principal.tenant)
        return {"message": "Release from Setup Assistant queued",
                "alert": refreshed.to_dict() if refreshed else None}
    if kind == "atc_gate":
        run_id = detail.get("flow_run_id")
        if not run_id:
            raise HTTPException(status_code=400, detail="Gate alert has no linked run")
        result = await atc.resume_manual_gate(run_id, body.action_key.strip(), principal.email)
        if result is None:
            raise HTTPException(status_code=400, detail="Could not resume run")
        return {"message": "Decision recorded", "run": result.to_dict()}
    raise HTTPException(status_code=400, detail="This alert has no typed actions")


class RemediateRequest(BaseModel):
    action_key: str


class RemediationRejectRequest(BaseModel):
    action_key: str
    # Optional free-text reason, stored on the audit row rather than the alert timeline.
    reason: Optional[str] = None


@app.post("/api/v1/alerts/{alert_id}/remediate")
async def approve_alert_remediation(
    alert_id: str,
    body: RemediateRequest,
    admin: Principal = Depends(require_admin),
):
    """Approve a queued destructive remediation for an alert (never sent automatically) through the audited command
    path, refusing a resolved alert whose approvals were not cleared."""
    _require_uuid(alert_id, "Alert not found")
    alert = await Alert.get_or_none(id=alert_id, tenant=admin.tenant)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status == "resolved":
        raise HTTPException(
            status_code=409,
            detail=(
                "Alert is resolved; its queued remediation can no longer be "
                "approved. Send the command directly if the device still needs it."
            ),
        )
    from controller.services import dispatcher
    try:
        result = await dispatcher.approve_remediation(alert, body.action_key, admin.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    # Names the rule that proposed the command, so this audit row explains itself without a second lookup.
    await record_audit(
        admin,
        "alert.remediation_approve",
        target_type="alert",
        target_id=str(alert.id),
        detail={"action_key": body.action_key, "rule_id": alert.rule_id,
                "device_id": str(alert.device_id) if alert.device_id else None,
                "outcome": result.get("outcome")},
    )
    return {"message": "Remediation approved", **result, "alert": alert.to_dict()}


@app.post("/api/v1/alerts/{alert_id}/remediation/reject")
async def reject_alert_remediation(
    alert_id: str,
    body: RemediationRejectRequest,
    admin: Principal = Depends(require_admin),
):
    """Veto a queued destructive remediation instead of approving it, recording the refusal; unlike approval, this is
    allowed on a resolved alert so a stale command can still be cleared."""
    _require_uuid(alert_id, "Alert not found")
    alert = await Alert.get_or_none(id=alert_id, tenant=admin.tenant)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if not ((alert.detail or {}).get("pending_approvals") or []):
        raise HTTPException(
            status_code=409,
            detail="This alert has no queued remediation waiting for a decision.",
        )

    from controller.services import dispatcher
    try:
        result = await dispatcher.reject_remediation(
            alert, body.action_key, admin.email, reason=body.reason)
    except ValueError as exc:
        # The alert has something pending, but not the thing that was named.
        raise HTTPException(status_code=400, detail=str(exc))

    await record_audit(
        admin,
        "alert.remediation_reject",
        target_type="alert",
        target_id=str(alert.id),
        detail={"action_key": body.action_key, "rule_id": alert.rule_id,
                "device_id": str(alert.device_id) if alert.device_id else None,
                **({"reason": body.reason} if body.reason else {})},
    )
    return {"message": "Remediation rejected", **(result or {}),
            "alert": alert.to_dict()}


@app.post("/api/v1/dispatcher/evaluate")
async def dispatcher_evaluate_now(principal: Principal = Depends(get_current_principal)):
    """Run a compliance sweep for this tenant now. The Dispatcher counterpart of POST /api/v1/sync."""
    from controller.services import dispatcher
    evaluated = await dispatcher.sweep(principal.tenant)
    return {"message": "Compliance sweep complete", "devices_evaluated": evaluated}


# Cap on how much of a transport failure's text a response or an audit row carries. The text is whatever the transport
# said, which on a bad day is a whole HTML error page.
_SEND_FAILURE_MAX_CHARS = 300


async def _send_failure_reason(exc: Exception, tenant: Tenant) -> Optional[str]:
    """What the transport actually said when a send failed, bounded, or None.

    Reads the cause off the failed Task row by the exception's task id, unless the exception carries its own reason.
    """
    reason = getattr(exc, "cause", None) or getattr(exc, "reason", None)
    task_id = getattr(exc, "task_id", None)
    if not reason and task_id:
        task = await Task.get_or_none(id=task_id, tenant=tenant)
        reason = getattr(task, "error", None)
    reason = " ".join(str(reason or "").split())
    if not reason:
        return None
    if len(reason) > _SEND_FAILURE_MAX_CHARS:
        return reason[:_SEND_FAILURE_MAX_CHARS - 3] + "..."
    return reason


def _push_failure_reason(outcome: Dict[str, Any]) -> Optional[str]:
    """Why the push failed for a command the server stored anyway: None if the push succeeded, "" if it failed
    silently."""
    result = outcome.get("result")
    if not isinstance(result, dict) or not result.get("push_failed"):
        return None
    errors = result.get("push_errors")
    if isinstance(errors, dict) and errors:
        return "; ".join(str(reason) for reason in errors.values() if reason)
    return ""


def _command_sent_message(outcome: Dict[str, Any]) -> str:
    """The message returned once a command has been sent.

    Plain "Command sent" for most commands; a failed push or a lock command each get their own line instead.
    """
    reason = _push_failure_reason(outcome)
    queued = (f"Queued. The push failed ({reason or 'no reason given'}), so the "
              "device acts on it at its next check-in.") if reason is not None else ""
    lock_change = outcome.get("lock_change")
    if not lock_change:
        return queued if reason is not None else "Command sent"
    noun = lock_change["label"].lower()
    if lock_change["rotating"]:
        sent = (f"New {noun} sent. Break-glass keeps serving the previous one "
                "until the Mac confirms the change.")
    else:
        sent = (f"{noun.capitalize()} escrowed. Read it back on the Summary or "
                "Security tab by breaking the glass.")
    return f"{queued} {sent}" if reason is not None else sent


@app.post("/api/v1/devices/{device_id}/command")
async def send_device_command(
    device_id: str,
    command: CommandRequest,
    principal: Principal = Depends(get_current_principal),
):
    """Send one command to an enrolled device; destructive commands require the admin role, and a command needing
    human judgment returns 400 with warning_codes until resent with acknowledge_warnings: true."""
    tenant = principal.tenant

    # Resolved first because every refusal below is recorded against the device; an unknown device id is the one
    # refusal that stays unrecorded, since there is nothing to attribute it to.
    _require_uuid(device_id, "Device not found")
    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    mdm_connector = MDMConnector()
    # Set by every path that writes its own audit row, so the refusal handler at the bottom does not write a second one
    # for the same command.
    audited = False

    try:
        # Destructive commands are admin-only. Checked inside the try so the refusal is recorded: a member attempting a
        # wipe is one of the things worth having in the log.
        if command.command_type in DESTRUCTIVE_COMMANDS and principal.role != ROLE_ADMIN:
            raise HTTPException(
                status_code=403,
                detail=f"'{command.command_type}' requires the admin role",
            )

        if device.enrollment_state != "enrolled":
            # Unenrolled/pending devices have no active MDM channel.
            raise HTTPException(
                status_code=409,
                detail=f"Device is {device.enrollment_state}; commands can only be sent to enrolled devices",
            )

        if command.command_type == "install_app":
            app_info = command.parameters.get("app_info")
            if not app_info:
                raise HTTPException(status_code=400, detail="app_info required")
            if not isinstance(app_info, dict):
                raise HTTPException(status_code=400, detail="app_info must be an object")
            # Checked here since the lines below subscript these keys; missing would be a KeyError/500 with the task
            # row already written.
            missing = [k for k in ("app_id", "name", "version") if not app_info.get(k)]
            if missing:
                raise HTTPException(
                    status_code=400,
                    detail=f"app_info is missing required field(s): {', '.join(missing)}",
                )

            task = await task_manager.create_task(
                tenant=tenant,
                task_type="app_install",
                description=f"Install {app_info['name']}",
                device=device,
                user=principal.email,
                details={"app_info": app_info},
            )

            # Linked now, not when the spawned handler reaches deploy_app, or a device that never answers would
            # leave the row with no attempt against it.
            await AppManager(tenant).ensure_deployment(device, app_info, str(task.id))

            from controller.services.task_handlers import handle_app_install_task
            from controller.services.reconciler import _spawn

            # _spawn keeps a strong reference; a bare asyncio.create_task can be garbage-collected before it finishes,
            # silently dropping the install.
            _spawn(task_manager.execute_task(task, handle_app_install_task))

            # Identity only, never the whole app_info: it carries the package location, which can be a signed URL.
            await record_device_command(
                principal, device, command.command_type,
                params={"app_id": app_info.get("id"), "app_name": app_info.get("name"),
                        "version": app_info.get("version")},
                task_id=str(task.id),
            )
            audited = True
            return {"task_id": str(task.id), "message": "App installation started"}

        elif command.command_type == "remove_app":
            app_id = command.parameters.get("app_id")
            bundle_id = command.parameters.get("bundle_id")

            if not app_id or not bundle_id:
                raise HTTPException(
                    status_code=400, detail="app_id and bundle_id required"
                )

            task = await task_manager.create_task(
                tenant=tenant,
                task_type="app_remove",
                description=f"Remove app {app_id}",
                device=device,
                user=principal.email,
                details={"app_id": app_id, "bundle_id": bundle_id},
            )

            from controller.services.task_handlers import handle_app_remove_task
            from controller.services.reconciler import _spawn

            # _spawn keeps a strong reference; a bare asyncio.create_task can be garbage-collected before it finishes,
            # silently dropping the removal.
            _spawn(task_manager.execute_task(task, handle_app_remove_task))

            await record_device_command(
                principal, device, command.command_type,
                params={"app_id": app_id, "bundle_id": bundle_id},
                task_id=str(task.id),
            )
            audited = True
            return {"task_id": str(task.id), "message": "App removal started"}

        # Direct commands that should be issued immediately
        params = command.parameters or {}
        pin = params.get("pin")
        if command.command_type in ("lock", "erase"):
            # macOS requires a 6-digit unlock PIN for DeviceLock/EraseDevice.
            is_mac = "mac" in (device.device_model or "").lower()
            if pin is not None and not re.fullmatch(r"\d{6}", str(pin)):
                raise HTTPException(status_code=400, detail="PIN must be exactly 6 digits")
            if is_mac and not pin:
                raise HTTPException(
                    status_code=400,
                    detail="Macs require a 6-digit PIN for this command (needed to unlock afterwards)",
                )
        rts_payload = None
        rts_warnings: List[tuple] = []
        if command.command_type == "erase" and _truthy(params.get("return_to_service")):
            attrs = device.attributes or {}
            platform, floor = _rts_floor(device.device_model)
            if floor is None:
                raise HTTPException(
                    status_code=400,
                    detail=(f"Return to Service isn't available on {platform}."
                            if platform else
                            "This device hasn't reported a model this server "
                            "recognizes, so there is no way to tell whether "
                            "Return to Service applies to it. Refresh its device "
                            "information and try again."),
                )
            if not _os_at_least(device.os_version, floor):
                raise HTTPException(
                    status_code=400,
                    detail=f"Return to Service requires {platform} {floor} or later "
                           f"(device reports {device.os_version or 'unknown'}).",
                )
            enroll_info = enrollment_svc.enrollment_details(tenant)
            if not enroll_info.get("configured"):
                raise HTTPException(
                    status_code=400,
                    detail="Enrollment isn't fully configured, so the re-enrollment profile "
                           "can't be built (check: "
                           f"{readiness.settings_to_check(enroll_info)}).",
                )
            wifi_ssid = (params.get("wifi_ssid") or "").strip()
            rts_warnings = _rts_warnings(attrs, wifi_ssid)
            if rts_warnings and not _truthy(params.get("acknowledge_warnings")):
                # Refused, but an admin can override it: the condition may be known and controlled.
                raise HTTPException(
                    status_code=400,
                    detail={"errors": [w for _code, w in rts_warnings],
                            "warnings": [w for _code, w in rts_warnings],
                            "warning_codes": [code for code, _w in rts_warnings],
                            "requires_confirmation": True},
                )
            rts_payload = {
                "enrollment_profile": enrollment_svc.build_enrollment_mobileconfig(tenant),
                "wifi_profile": enrollment_svc.build_wifi_mobileconfig(
                    wifi_ssid,
                    password=params.get("wifi_password") or None,
                    hidden=_truthy(params.get("wifi_hidden")),
                    org=tenant.name,
                ) if wifi_ssid else None,
            }

        from controller.services.device_commands import (
            CommandError, CommandSendError, dispatch_catalog_command,
        )
        try:
            outcome = await dispatch_catalog_command(
                device,
                command.command_type,
                params,
                user=principal.email,
                tenant=tenant,
                # The admin-role check above already authorized this; the helper's own check holds automated
                # callers (ATC, Dispatcher) back, since those pass allow_destructive=False.
                allow_destructive=True,
                rts_payload=rts_payload,
                mdm_connector=mdm_connector,
                # This endpoint writes its own rows, attributed to the admin who made the request. The helper's
                # machine-attributed row is for callers that have no principal to name.
                caller_audits=True,
            )
        except CommandSendError as exc:
            # The attempt is audited whether or not it reached the device, and both the answer and the row carry what
            # the transport said, not just that something went wrong.
            reason = await _send_failure_reason(exc, tenant)
            detail = f"{exc}: {reason}" if reason else str(exc)
            await record_device_command(
                principal, device, command.command_type, params=params,
                task_id=getattr(exc, "task_id", None), outcome="failed", error=detail,
            )
            audited = True
            raise HTTPException(status_code=502, detail=detail)
        except CommandError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        await record_device_command(
            principal, device, command.command_type, params=params,
            task_id=outcome["task_id"],
        )
        audited = True
        result = outcome["result"] if isinstance(outcome["result"], dict) else {}
        response = {"task_id": outcome["task_id"],
                    "message": _command_sent_message(outcome),
                    "result": outcome["result"],
                    # Lifted out of the transport's answer so a client does not have to parse it: the command is stored
                    # either way, but a failed push means the device only finds out at its next check-in.
                    "push_failed": bool(result.get("push_failed")),
                    "push_errors": result.get("push_errors") or {}}
        if rts_warnings:
            # Echoed back: the same two lists, in the same order, as the refusal that preceded this send.
            response["warnings"] = [w for _code, w in rts_warnings]
            response["warning_codes"] = [code for code, _w in rts_warnings]
        return response

    except HTTPException as exc:
        # A refusal is recorded, unless it's a confirmable-warning prompt (audited later on its own) or a send
        # failure already wrote its row above.
        if not audited and not isinstance(exc.detail, dict):
            await record_device_command(
                principal, device, command.command_type,
                params=command.parameters, outcome="refused", error=str(exc.detail),
            )
        raise
    finally:
        await mdm_connector.close()


# Task Management
@app.get("/api/v1/tasks")
async def list_tasks(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    status: Optional[str] = None,
    device_id: Optional[str] = None,
    serial: Optional[str] = None,
    user: Optional[str] = None,
    principal: Principal = Depends(get_current_principal),
):
    """List tasks, optionally filtered by status, an exact device_id, or a case-insensitive substring match on
    serial or user."""
    tenant = principal.tenant

    query = Task.filter(tenant=tenant)

    if status:
        query = query.filter(status=status)
    if device_id:
        query = _filter_device_id(query, device_id)
    if serial:
        query = query.filter(device__serial_number__icontains=serial)
    if user:
        # Case-insensitive substring, so a partial address finds rows. A full email still matches, since a string
        # contains itself.
        query = query.filter(user__icontains=user)

    total = await query.count()
    tasks = (
        await query.order_by("-created_at")
        .offset(skip)
        .limit(limit)
        .prefetch_related("device")
        .all()
    )

    return {"total": total, "tasks": [_task_with_device(task) for task in tasks]}


def _task_with_device(task: Task) -> Dict[str, Any]:
    """Task dict enriched with device identity (device is prefetched)."""
    d = task.to_dict()
    if task.device:
        d["device"] = {
            "serial_number": task.device.serial_number,
            "hostname": task.device.hostname,
            "device_model": task.device.device_model,
        }
    return d


@app.get("/api/v1/tasks/{task_id}")
async def get_task_details(task_id: str, principal: Principal = Depends(get_current_principal)):
    """One task, with the identity of the device it targets. Tenant-scoped."""
    tenant = principal.tenant
    _require_uuid(task_id, "Task not found")
    task = await Task.get_or_none(id=task_id, tenant=tenant).prefetch_related("device")

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return _task_with_device(task)


@app.post("/api/v1/tasks/{task_id}/cancel")
async def cancel_task(task_id: str, principal: Principal = Depends(get_current_principal)):
    """Cancel a pending or running task by flipping its stored status; a command already delivered to the device
    is not recalled."""
    tenant = principal.tenant
    _require_uuid(task_id, "Task not found")
    task = await Task.get_or_none(id=task_id, tenant=tenant)

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task.status not in ["pending", "running"]:
        raise HTTPException(
            status_code=400, detail=f"Task is already {task.status} and cannot be cancelled"
        )

    # Stop the in-process handler if this process owns it; nothing depends on it having one.
    await task_manager.cancel_task(str(task.id))

    task.status = "cancelled"
    task.completed_at = datetime.now(timezone.utc)
    await task.save(update_fields=["status", "completed_at"])

    return {"message": "Task cancelled"}


@app.post("/api/v1/tasks/{task_id}/retry")
async def retry_task(task_id: str, principal: Principal = Depends(get_current_principal)):
    """Retry a failed or cancelled task by re-dispatching it as a fresh Task row through its original handler,
    leaving the failed row in history."""
    tenant = principal.tenant
    _require_uuid(task_id, "Task not found")
    task = await Task.get_or_none(id=task_id, tenant=tenant).prefetch_related("device")

    if not task:
        # No task, so no device and nothing to attribute a row to.
        raise HTTPException(status_code=404, detail="Task not found")

    async def _refuse(status_code: int, detail: str):
        """Record the refusal against the device, then raise it.

        Only the retried task id goes into the row, since task details can hold a whole profile payload.
        """
        if task.device:
            await record_device_command(
                principal, task.device, task.type,
                params={"retry_of": str(task.id)},
                outcome="refused", error=detail,
            )
        raise HTTPException(status_code=status_code, detail=detail)

    if task.status not in ("failed", "cancelled"):
        await _refuse(
            409,
            f"Task is {task.status}; only failed or cancelled tasks can be retried",
        )

    from controller.services.task_handlers import TASK_HANDLERS

    handler = TASK_HANDLERS.get(task.type)
    if handler is None:
        await _refuse(
            400,
            f"Task type '{task.type}' has no re-runnable handler and cannot be retried",
        )

    # Copy the input details but drop command_uuid: the failed attempt wrote it to correlate a webhook with one device
    # command, and it means nothing on the new row until this handler issues its own.
    retry_details = dict(task.details or {})
    retry_details.pop("command_uuid", None)

    # One prefix, however many times the same task is retried.
    base_description = (task.description or "").strip()
    while base_description.startswith("Retry: "):
        base_description = base_description[len("Retry: "):]
    new_task = await task_manager.create_task(
        tenant=tenant,
        task_type=task.type,
        description=f"Retry: {base_description}",
        device=task.device,
        user=principal.email,
        details=retry_details,
    )

    # Same reasoning as send_device_command's install_app branch: link the deployment row to this retry now, not
    # whenever the spawned handler gets to it.
    if task.type == "app_install" and retry_details.get("app_info"):
        await AppManager(tenant).ensure_deployment(
            task.device, retry_details["app_info"], str(new_task.id)
        )
    elif task.type == "profile_install" and retry_details.get("profile_info"):
        from controller.services.profile_manager import ProfileManager

        await ProfileManager(tenant).ensure_deployment(
            task.device, retry_details["profile_info"], str(new_task.id)
        )

    from controller.services.reconciler import _spawn

    # _spawn keeps a strong reference; a bare asyncio.create_task can be garbage-collected before it finishes, silently
    # dropping the retry.
    _spawn(task_manager.execute_task(new_task, handler))

    if task.device:
        # Its own row pointing back at the retried task id, not a copy of its details (can hold a signed package URL).
        await record_device_command(
            principal, task.device, task.type,
            params={"retry_of": str(task.id)},
            task_id=str(new_task.id),
        )
    return {"task_id": str(new_task.id), "message": "Task retry started"}


# Reports and Statistics
@app.get("/api/v1/stats/overview")
async def get_overview_stats(principal: Principal = Depends(get_current_principal)):
    """Headline numbers for this tenant: device totals, task counts by status, and how many app and profile deployments
    are installed."""
    tenant = principal.tenant

    device_count = await Device.filter(tenant=tenant).count()
    active_devices = await Device.filter(
        tenant=tenant, last_seen__gte=datetime.now(timezone.utc) - timedelta(days=7)
    ).count()

    task_stats = await task_manager.get_task_stats(tenant)

    app_deployments = await AppDeployment.filter(
        tenant=tenant, status="installed"
    ).count()
    # Apps the device has taken the command for but has not installed (Apple acks InstallApplication before the
    # download starts).
    apps_in_flight = await AppDeployment.filter(
        tenant=tenant, status__in=("pending", "installing", "accepted")
    ).count()
    profile_deployments = await ProfileDeployment.filter(
        tenant=tenant, status="installed"
    ).count()

    return {
        "devices": {"total": device_count, "active_7d": active_devices},
        "tasks": task_stats,
        "deployments": {"apps": app_deployments,
                        "apps_in_flight": apps_in_flight,
                        "profiles": profile_deployments},
    }


@app.get("/api/v1/stats/rollout")
async def get_rollout_stats(kind: str = "app",
                            principal: Principal = Depends(get_current_principal)):
    """Per-app or per-profile deployment rollup across the fleet.

    Counts describe deployment rows, not scope: a device the reconciler has not rowed yet is counted nowhere.
    """
    tenant = principal.tenant
    if kind not in ("app", "profile"):
        raise HTTPException(status_code=400, detail="kind must be app or profile")

    from tortoise.functions import Count

    model = AppDeployment if kind == "app" else ProfileDeployment
    id_field = "app_id" if kind == "app" else "profile_id"
    base = model.filter(tenant=tenant)

    def bucket(items: Dict[str, Any], row_id: str) -> Dict[str, Any]:
        return items.setdefault(row_id, {
            "total": 0,
            "by_status": {},
            "by_device_model": {},
            **({"by_desired_version": {}, "by_reported_version": {}}
               if kind == "app" else {}),
        })

    items: Dict[str, Any] = {}
    status_rows = (await base.annotate(count=Count("id"))
                   .group_by(id_field, "status")
                   .values(id_field, "status", "count"))
    for r in status_rows:
        it = bucket(items, r[id_field])
        it["by_status"][r["status"]] = r["count"]
        it["total"] += r["count"]

    model_rows = (await base.annotate(count=Count("id"))
                  .group_by(id_field, "status", "device__device_model")
                  .values(id_field, "status", "count",
                          model_name="device__device_model"))
    for r in model_rows:
        it = bucket(items, r[id_field])
        per = it["by_device_model"].setdefault(r["model_name"] or "unknown", {})
        per[r["status"]] = per.get(r["status"], 0) + r["count"]

    if kind == "app":
        desired_rows = (await base.annotate(count=Count("id"))
                        .group_by(id_field, "app_version", "status")
                        .values(id_field, "app_version", "status", "count"))
        for r in desired_rows:
            it = bucket(items, r[id_field])
            per = it["by_desired_version"].setdefault(r["app_version"] or "unknown", {})
            per[r["status"]] = per.get(r["status"], 0) + r["count"]
        # A reported version only means something once the device has confirmed the app; before that the column is NULL
        # by design (models.AppDeployment).
        reported_rows = (await base.filter(status="installed")
                         .annotate(count=Count("id"))
                         .group_by(id_field, "reported_version")
                         .values(id_field, "reported_version", "count"))
        for r in reported_rows:
            it = bucket(items, r[id_field])
            it["by_reported_version"][r["reported_version"] or "unknown"] = r["count"]

    devices_enrolled = await Device.filter(
        tenant=tenant, enrollment_state="enrolled").count()
    return {
        "kind": kind,
        "counted_at": datetime.now(timezone.utc).isoformat(),
        "devices_enrolled": devices_enrolled,
        "items": items,
    }


@app.get("/api/v1/apps/{app_id}/deployments")
async def list_app_deployments(app_id: str,
                               status: Optional[str] = None,
                               principal: Principal = Depends(get_current_principal)):
    """List every deployment row for one app, present only for devices the reconciler has already evaluated."""
    tenant = principal.tenant
    query = AppDeployment.filter(tenant=tenant, app_id=app_id).select_related("device")
    if status:
        query = query.filter(status=status)

    rows = await query.order_by("device__hostname").limit(2000)
    devices = [{
        "device_id": str(r.device.id),
        "hostname": r.device.hostname,
        "serial_number": r.device.serial_number,
        "device_model": r.device.device_model,
        "status": r.status,
        "desired_version": r.app_version,
        "reported_version": r.reported_version,
        "last_error": r.last_error,
        "failed_attempts": r.failed_attempts,
        "install_date": r.install_date.isoformat() if r.install_date else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
    } for r in rows]

    return {
        "app_id": app_id,
        "counted_at": datetime.now(timezone.utc).isoformat(),
        "total": len(devices),
        "devices": devices,
    }


@app.get("/api/v1/stats/devices/by-model")
async def get_devices_by_model(principal: Principal = Depends(get_current_principal)):
    """Device counts grouped by model identifier."""
    tenant = principal.tenant

    from tortoise.functions import Count

    stats = (
        await Device.filter(tenant=tenant)
        .annotate(count=Count("id"))
        .group_by("device_model")
        .values("device_model", "count")
    )

    return stats


@app.get("/api/v1/stats/devices/by-os")
async def get_devices_by_os(principal: Principal = Depends(get_current_principal)):
    """Device counts grouped by the OS version each device last reported."""
    tenant = principal.tenant

    from tortoise.functions import Count

    stats = (
        await Device.filter(tenant=tenant)
        .annotate(count=Count("id"))
        .group_by("os_version")
        .values("os_version", "count")
    )

    return stats


# File Management
_SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# Single upload per tenant: the quota read and write are not atomic. Keyed per event loop too, like
# services.reconciler's semaphore.
_upload_locks: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def _upload_lock(tenant_id: str) -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    per_loop = _upload_locks.get(loop)
    if per_loop is None:
        per_loop = {}
        _upload_locks[loop] = per_loop
    lock = per_loop.get(tenant_id)
    if lock is None:
        lock = asyncio.Lock()
        per_loop[tenant_id] = lock
    return lock


@app.post("/api/v1/apps/upload")
async def upload_app_package(
    file: UploadFile = File(...),
    app_id: str = Query(..., min_length=1),
    version: str = Query(..., min_length=1),
    admin: Principal = Depends(require_admin),
):
    """Upload an app package to S3 (admin only); scoped devices install these bytes as root once apps.yaml points
    at the resulting key."""
    tenant = admin.tenant

    # Refuse anything that could escape the intended key namespace, by path or object injection or by overwriting
    # another app's package.
    if not _SAFE_KEY_RE.match(app_id) or not _SAFE_KEY_RE.match(version):
        raise HTTPException(
            status_code=400,
            detail="app_id and version may contain only letters, digits, '.', '_' and '-'",
        )

    file_extension = os.path.splitext(file.filename or "")[1]
    if file_extension and not _SAFE_KEY_RE.match(file_extension.lstrip(".")):
        raise HTTPException(status_code=400, detail="Unsupported file name")

    s3_key = f"{app_id}/{app_id}-{version}{file_extension}"

    app_manager = AppManager(tenant)

    # Last chance to warn: a component or unsigned package uploads and deploys fine, then fails on the device.
    warnings: List[str] = []
    if file_extension.lower() == ".pkg":
        try:
            warnings = inspect_pkg(file.file).get("warnings", [])
        except Exception:
            logger.exception("app upload: package inspection failed for %s", s3_key)
        finally:
            file.file.seek(0)

    # Bucket and key from the same resolver the reconciler uses to deploy this package: reading
    # tenant.s3_config["bucket"] directly would KeyError in ambient mode.
    try:
        bucket = app_manager._get_s3_bucket()
        full_s3_key = app_manager._build_s3_key(s3_key)
        # One upload at a time per tenant: usage is measured before the bytes go up, so two uploads that interleave
        # between the check and the put both see room only one of them has, and a 10 GB quota takes 20 GB.
        async with _upload_lock(tenant.id):
            # Checked against what is in the store now plus this file, less the object this upload replaces, so
            # re-uploading a version does not count twice. Objects other tools put in the bucket do count.
            quota = app_manager.storage_quota_bytes()
            replaced = 0
            if quota is not None:
                file.file.seek(0, os.SEEK_END)
                incoming = file.file.tell()
                file.file.seek(0)
                usage = await asyncio.to_thread(app_manager.storage_usage_bytes)
                replaced = await asyncio.to_thread(
                    _object_size_or_zero, app_manager, bucket, full_s3_key)
                if usage - replaced + incoming > quota:
                    raise HTTPException(
                        status_code=413,
                        detail=(f"This upload would put the tenant over its storage quota "
                                f"({_human_bytes(usage - replaced + incoming)} of "
                                f"{_human_bytes(quota)}). Delete unused packages first, or ask "
                                f"the operator to raise the quota."),
                    )
            # boto3 is synchronous, so this goes off the loop; otherwise a large .pkg stalls the whole API process.
            sha256 = await asyncio.to_thread(_sha256_fileobj, file.file)
            file.file.seek(0)
            await asyncio.to_thread(
                app_manager.s3_client.upload_fileobj, file.file, bucket, full_s3_key,
                {"Metadata": {AppManager.SHA256_METADATA_KEY: sha256}},
            )
            # Re-measure now the bytes are down, and take back only what this call created: an overwritten object
            # is a package devices install today.
            if quota is not None:
                settled = await asyncio.to_thread(app_manager.storage_usage_bytes)
                if settled > quota:
                    if not replaced:
                        try:
                            await asyncio.to_thread(
                                app_manager.s3_client.delete_object,
                                Bucket=bucket, Key=full_s3_key)
                        except Exception:
                            logger.exception(
                                "app upload: could not remove over-quota object %s", s3_key)
                    raise HTTPException(
                        status_code=413,
                        detail=(f"The store went over the tenant's quota while this "
                                f"upload was running ({_human_bytes(settled)} of "
                                f"{_human_bytes(quota)}). Delete unused packages first, "
                                f"or ask the operator to raise the quota."),
                    )
    except S3ConfigError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"App upload failed for tenant {tenant.id}: {e}")
        raise HTTPException(status_code=500, detail="Upload failed")

    await record_audit(
        admin,
        "app.upload",
        target_type="app",
        target_id=app_id,
        # Location and identity of the package only; no credentials.
        detail={"app_id": app_id, "version": version, "s3_key": s3_key},
    )
    return {"s3_key": s3_key, "sha256": sha256, "message": "File uploaded successfully",
            "warnings": warnings}


def _sha256_fileobj(fileobj) -> str:
    """sha256 of a file object from its current position, in 1 MB reads."""
    digest = hashlib.sha256()
    for chunk in iter(lambda: fileobj.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _object_size_or_zero(app_manager: AppManager, bucket: str, full_key: str) -> int:
    """Size of an object that may not exist. Synchronous boto3; use to_thread."""
    try:
        head = app_manager.s3_client.head_object(Bucket=bucket, Key=full_key)
        return int(head.get("ContentLength") or 0)
    except Exception:
        return 0


def _human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{n} B"


@app.get("/api/v1/apps/packages")
async def list_app_packages(admin: Principal = Depends(require_admin)):
    """List the packages already in this tenant's object store (admin only), including ones uploaded some other
    way; a null sha256 means POST /api/v1/apps/packages/checksum can compute it."""
    app_manager = AppManager(admin.tenant)
    try:
        packages = await asyncio.to_thread(app_manager.list_packages)
    except S3ConfigError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Listing packages failed for tenant {admin.tenant.id}: {e}")
        raise HTTPException(status_code=502, detail="Could not list the object store")
    usage = sum(int(p.get("size") or 0) for p in packages)
    return {"packages": packages, "usage_bytes": usage,
            "quota_bytes": app_manager.storage_quota_bytes()}


class PackageChecksumRequest(BaseModel):
    s3_key: str


@app.post("/api/v1/apps/packages/checksum")
async def checksum_app_package(
    body: PackageChecksumRequest,
    admin: Principal = Depends(require_admin),
):
    """sha256 of one object already in the store (admin only).

    Streams the object through the controller once and records the digest on it, so the next listing already has it.
    """
    key = (body.s3_key or "").strip()
    if not key or key.startswith("/") or ".." in key.split("/"):
        raise HTTPException(status_code=400, detail="s3_key must be a key inside the bucket")
    app_manager = AppManager(admin.tenant)
    try:
        sha256 = await asyncio.to_thread(app_manager.checksum_package, key)
    except S3ConfigError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        code = getattr(getattr(e, "response", None), "get", lambda *_: None)("Error") or {}
        if isinstance(code, dict) and code.get("Code") in ("NoSuchKey", "404"):
            raise HTTPException(status_code=404, detail="No such package in the store")
        logger.error(f"Checksum failed for tenant {admin.tenant.id} key {key}: {e}")
        raise HTTPException(status_code=502, detail="Could not read the package")
    return {"s3_key": key, "sha256": sha256}


# App Manifest Endpoints
async def _resolve_package(deployment_id: str):
    """The deployment, its tenant and the authored app version behind a device-facing package URL.

    Shared by the manifest and package endpoints so a missing sha256 is refused once, not independently in each.
    """
    _require_uuid(deployment_id, "Deployment not found")
    deployment = await AppDeployment.get_or_none(id=deployment_id).prefetch_related(
        "tenant", "device"
    )

    if not deployment:
        raise HTTPException(status_code=404, detail="Deployment not found")

    tenant = deployment.tenant
    yaml_path = _tenant_dir(tenant.id) / "apps.yaml"

    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail="App configuration not found")

    with open(yaml_path, "r", encoding="utf-8") as f:
        apps_config = yaml.safe_load(f)

    app_info = None
    for app in apps_config.get("apps", []):
        if app["id"] == deployment.app_id:
            for version in app.get("versions", []):
                if version["version"] == deployment.app_version:
                    app_info = {
                        "id": app["id"],
                        "name": app["name"],
                        "bundle_id": app["bundle_id"],
                        "version": version["version"],
                        "s3_key": version["s3_key"],
                        "sha256": version.get("sha256", ""),
                    }
                    break
            break

    if not app_info:
        raise HTTPException(status_code=404, detail="App version not found")

    # Integrity is mandatory: no device gets a download URL that cannot be bound to a known content hash.
    if not re.match(r"^[a-fA-F0-9]{64}$", app_info.get("sha256") or ""):
        logger.error(
            f"Refusing manifest for {deployment.app_id} {deployment.app_version}: missing sha256"
        )
        raise HTTPException(status_code=500, detail="App version is missing an integrity hash")

    return deployment, tenant, app_info


def _package_location(tenant: Tenant, s3_key: str):
    """(AppManager, bucket, full key) for an app package, or a 500.

    The S3 config error, which names the tenant and missing keys, is logged rather than returned to the caller.
    """
    app_manager = AppManager(tenant)
    try:
        return app_manager, app_manager._get_s3_bucket(), app_manager._build_s3_key(s3_key)
    except S3ConfigError as e:
        logger.error(f"Failed to locate package for tenant {tenant.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate download URL")
    except Exception as e:
        logger.error(f"Failed to locate package: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate download URL")


@app.api_route("/api/manifests/{deployment_id}/package", methods=["GET", "HEAD"])
async def get_app_package(deployment_id: str, request: Request):
    """Return the download address a manifest points a device at (unauthenticated, like the manifest)."""
    _deployment, tenant, app_info = await _resolve_package(deployment_id)
    app_manager, bucket, full_s3_key = _package_location(tenant, app_info["s3_key"])

    if request.method == "HEAD":
        try:
            head = await asyncio.to_thread(
                app_manager.s3_client.head_object, Bucket=bucket, Key=full_s3_key
            )
        except Exception as exc:
            code = str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))
            if code in ("404", "NoSuchKey", "NotFound"):
                logger.error(f"Package missing for deployment {deployment_id}: {full_s3_key}")
                raise HTTPException(status_code=404, detail="Package not found")
            logger.error(f"Could not read package metadata for {deployment_id}: {exc}")
            raise HTTPException(status_code=502, detail="Package metadata unavailable")
        # The number the device asked for, and the type it will store.
        return Response(
            status_code=200,
            headers={
                "Content-Length": str(head.get("ContentLength", 0)),
                "Content-Type": head.get("ContentType") or "application/octet-stream",
            },
        )

    try:
        download_url = app_manager.s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": full_s3_key},
            ExpiresIn=3600,  # 1 hour
        )
    except Exception as e:
        logger.error(f"Failed to generate presigned URL: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate download URL")
    # 302 and not 301: the presigned URL expires, so nothing about this redirect is permanent and nothing should cache
    # it as though it were.
    return Response(status_code=302, headers={"Location": download_url})


@app.get("/api/manifests/{deployment_id}")
async def get_app_manifest(deployment_id: str):
    """The InstallApplication manifest plist for one deployment, as a device fetches it. Unauthenticated, like the
    package endpoint above."""
    deployment, tenant, app_info = await _resolve_package(deployment_id)

    app_manager = AppManager(tenant)

    try:
        bucket = app_manager._get_s3_bucket()
        full_s3_key = app_manager._build_s3_key(app_info['s3_key'])
        download_url = app_manager.s3_client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": bucket,
                "Key": full_s3_key,
            },
            ExpiresIn=3600,  # 1 hour
        )
    except S3ConfigError as e:
        logger.error(f"Failed to generate presigned URL for tenant {tenant.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate download URL")
    except Exception as e:
        logger.error(f"Failed to generate presigned URL: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate download URL")

    # Points at this server's package endpoint, which answers HEAD and GET separately, instead of the presigned URL
    # directly. Falls back to the presigned URL when no public address is configured.
    public = readiness.public_api_url()
    asset_url = (f"{public}/api/manifests/{deployment_id}/package"
                 if public else download_url)

    manifest = {
        "items": [
            {
                "assets": [{"kind": "software-package", "url": asset_url}],
                "metadata": {
                    "bundle-identifier": app_info["bundle_id"],
                    "bundle-version": app_info["version"],
                    "kind": "software",
                    "title": app_info["name"],
                },
            }
        ]
    }

    # _resolve_package refuses a version without one, so this is always present.
    manifest["items"][0]["assets"][0]["sha256"] = app_info["sha256"]

    import plistlib

    plist_data = plistlib.dumps(manifest)

    return Response(
        content=plist_data,
        media_type="application/x-plist",
        headers={
            "Content-Disposition": (
                f"attachment; filename={app_info['id']}-{app_info['version']}.plist"
            )
        },
    )


@app.get("/api/manifests/{deployment_id}/info")
async def get_app_manifest_info(
    deployment_id: str, principal: Principal = Depends(get_current_principal)
):
    """One deployment described: which app and version, which device, where it got to, and the manifest URL the device
    is given. Requires a session and is tenant-scoped, unlike the device-facing manifest above.
    """
    _require_uuid(deployment_id, "Deployment not found")
    deployment = await AppDeployment.get_or_none(
        id=deployment_id, tenant=principal.tenant
    ).prefetch_related("device")

    if not deployment:
        raise HTTPException(status_code=404, detail="Deployment not found")

    return {
        "deployment_id": str(deployment.id),
        "app_id": deployment.app_id,
        "app_version": deployment.app_version,
        "device_id": str(deployment.device.id),
        "device_serial": deployment.device.serial_number,
        "status": deployment.status,
        "last_error": deployment.last_error,
        "last_task_id": str(deployment.last_task_id) if deployment.last_task_id else None,
        "created_at": deployment.created_at,
        # None when no public address is configured. A plain f-string would produce a URL beginning "None/" that a
        # client cannot tell apart from a real one.
        "manifest_url": (f"{readiness.public_api_url()}/api/manifests/{deployment_id}"
                         if readiness.public_api_url() else None),
    }


# Enrollment
@app.get("/api/v1/enrollment")
async def get_enrollment(principal: Principal = Depends(get_current_principal)):
    """Enrollment details for the current tenant (server URLs, topic, enroll URL)."""
    return enrollment_svc.enrollment_details(principal.tenant)


@app.get("/api/v1/enrollment-attempts")
async def list_enrollment_attempts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    outcome: Optional[str] = None,
    principal: Principal = Depends(get_current_principal),
):
    """List recent post-SCEP webhook check-ins for this tenant that could not become a device, readable by any
    authenticated member; a no_tenant drop never appears here, see list_unattributed_enrollment_attempts for those."""
    query = EnrollmentAttempt.filter(tenant=principal.tenant)
    if outcome:
        query = query.filter(outcome=outcome)
    total = await query.count()
    attempts = await query.order_by("-created_at").offset(skip).limit(limit).all()
    return {"total": total, "attempts": [a.to_dict() for a in attempts]}


@app.get("/api/v1/enrollment-attempts/unattributed")
async def list_unattributed_enrollment_attempts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    outcome: Optional[str] = None,
    admin: Principal = Depends(require_admin),
):
    """List the enrollment attempts that belong to no tenant (tenant IS NULL), admin only and shared across every
    tenant's admins on this host."""
    query = EnrollmentAttempt.filter(tenant_id__isnull=True)
    if outcome:
        query = query.filter(outcome=outcome)
    total = await query.count()
    attempts = await query.order_by("-created_at").offset(skip).limit(limit).all()
    return {"total": total, "attempts": [a.to_dict() for a in attempts]}


@app.get("/api/v1/audit-log")
async def list_audit_log(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    action: Optional[str] = None,
    actor: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    system: Optional[bool] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    admin: Principal = Depends(require_admin),
):
    """List this tenant's audit log entries (admin only), filterable by action, actor, target and a since/until
    window, newest first."""
    query = AuditLog.filter(tenant=admin.tenant)
    if action:
        query = query.filter(action=action)
    if actor:
        query = query.filter(actor_email=actor)
    if target_type:
        query = query.filter(target_type=target_type)
    if target_id:
        query = query.filter(target_id=target_id)
    if system is not None:
        query = query.filter(actor_email__isnull=system)
    if since:
        query = query.filter(created_at__gte=since)
    if until:
        query = query.filter(created_at__lte=until)
    total = await query.count()
    entries = await query.order_by("-created_at").offset(skip).limit(limit).all()
    return {"total": total, "entries": [e.to_dict() for e in entries]}


@app.get("/api/v1/enroll/{tenant_id}/{token}")
async def download_enrollment_profile(tenant_id: str, token: str, request: Request):
    """Serve the over-the-air enrollment .mobileconfig for a device to install, unauthenticated but keyed by a
    per-tenant token that returns the same 404 as an unknown tenant to avoid enumeration."""
    remote = request.client.host if request.client else None
    tenant = await Tenant.get_or_none(id=tenant_id)
    if not tenant or not tenant.is_active:
        enrollment_svc.log_token_refusal(
            "Enrollment download", tenant_id, "no such active tenant", remote)
        raise HTTPException(status_code=404, detail="Not found")
    if not enrollment_svc.verify_enrollment_token(tenant_id, token):
        enrollment_svc.log_token_refusal(
            "Enrollment download", tenant_id,
            "the enrollment token did not verify", remote)
        raise HTTPException(status_code=404, detail="Not found")

    # A profile with an empty APNs topic, SCEP challenge or URL is structurally valid and dead: it installs and never
    # checks in.
    details = enrollment_svc.enrollment_details(tenant)
    if not details["configured"]:
        raise HTTPException(
            status_code=503,
            # Names only, no reason: this answer goes to anyone holding an enrollment link.
            detail="Enrollment is not fully configured; check: "
                   f"{readiness.settings_to_check(details)}",
        )

    data = enrollment_svc.build_enrollment_mobileconfig(tenant)
    return Response(
        content=data,
        media_type="application/x-apple-aspen-config",
        headers={
            "Content-Disposition": f'attachment; filename="enroll-{tenant_id}.mobileconfig"'
        },
    )


# Readiness

# auto_error=False so a caller with no credentials reaches the handler below instead of being turned away by the
# security dependency with a 403. The 403 is the thing this endpoint must not answer: it confirms the endpoint exists.
_readiness_bearer = HTTPBearer(auto_error=False)


@app.get("/api/v1/readiness")
async def get_readiness(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(_readiness_bearer),
):
    """Report this deployment's readiness capability by capability (admin only, no secret values), returning 404
    rather than 401/403 to an unauthenticated caller so the route's existence stays unconfirmed to a scanner."""
    not_found = HTTPException(status_code=404, detail="Not found")
    if credentials is None:
        raise not_found
    try:
        principal = await get_current_principal(request, credentials)
    except HTTPException:
        raise not_found
    if not principal.is_admin:
        raise HTTPException(status_code=403, detail="Admin role required")
    # One warning reads this, so it stays quiet about cross-tenant enrollment on a deployment with only one tenant.
    active_tenants = await Tenant.filter(is_active=True).count()
    body = readiness.report(tenant=principal.tenant, active_tenants=active_tenants)
    # Which build this is and whether the database is at its schema. Admin only, like the rest of this body; /health
    # says only that the process is up.
    try:
        schema = await schema_status()
    except Exception:
        logger.exception("readiness: schema status failed")
        schema = None
    body["system"] = {"version": __version__, "schema": schema}
    return body


# deploy/healthcheck.py calls this together with the webhook process's /health and the scheduler's heartbeat
# file, so a container with any of the three dead reads unhealthy.
@app.get("/api/v1/health")
async def health_check():
    """Up, and able to reach the database."""
    from tortoise import Tortoise
    try:
        await Tortoise.get_connection("default").execute_query("SELECT 1")
    except Exception:
        logger.exception("health: database check failed")
        raise HTTPException(status_code=503, detail="database unreachable")
    return {"status": "healthy", "version": __version__,
            "timestamp": datetime.now(timezone.utc)}


# How long a clean shutdown waits for fire-and-forget handlers before letting the process die with the remainder
# undone. Must stay under supervisord's stopwaitsecs for [program:userapi] and the compose stop_grace_period.
_SHUTDOWN_DRAIN_SECONDS = float(os.getenv("MDM_API_SHUTDOWN_DRAIN_SECONDS", "15"))


# Registered before register_tortoise below: shutdown handlers run in registration order, and the drain must run
# while DB connections are still open, before register_tortoise's own shutdown hook closes them.
@app.on_event("shutdown")
async def _drain_spawned_handlers():
    """Give this process's spawned background work a bounded window to finish.

    Spawned via services.reconciler._spawn; past the window, the remainder is dropped rather than awaited further.
    """
    from controller.services.reconciler import drain_background_tasks
    try:
        await asyncio.wait_for(drain_background_tasks(), timeout=_SHUTDOWN_DRAIN_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(
            "shutdown: spawned handlers still running after %.0fs; dropping the remainder",
            _SHUTDOWN_DRAIN_SECONDS,
        )
    except Exception:
        logger.exception("shutdown: draining spawned handlers failed")


# _pooled_url, not the raw DSN, so this process honours DB_POOL_MAX_SIZE instead of asyncpg's default of five.
register_tortoise(
    app,
    db_url=_pooled_url(DATABASE_URL),
    modules={"models": ["controller.models.tenant"]},
    generate_schemas=False,
    add_exception_handlers=True,
)


# generate_schemas stays off above; init_schema does table creation and late-added columns under one advisory lock
# instead. Registered after register_tortoise so Tortoise.init has run first.
@app.on_event("startup")
async def _init_schema():
    from controller.models.database import init_schema
    await init_schema()
    from controller.services import atc_provision
    if atc_provision.ATC_PROVISION_EXISTING_TENANTS:
        try:
            tenants = await Tenant.filter(is_active=True).all()
            for t in tenants:
                atc_provision.ensure_enrollment_flow(str(t.id))
        except Exception:
            logger.exception("startup: provisioning existing tenants failed")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
