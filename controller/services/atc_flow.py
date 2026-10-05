"""ATC flow loading, hashing, graph indexing, and scope evaluation."""

import hashlib
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from controller.services import scoping, tenant_config
from controller.services.flow_step_catalog import DRAFT_KEYS
from controller.utils import coerce
from controller.utils.timeutil import as_utc, parse_iso_utc, utcnow

logger = logging.getLogger(__name__)

# Default gap between two check-in-started runs of one start on one device; without it a check-in-triggered
# install can re-fire itself forever.
CHECKIN_COOLDOWN_DEFAULT_MINUTES = 60

# Flow-level keys the fingerprint below ignores: they say where a flow sits in the document (permanent flag,
# draft review metadata), not what a device executes. Hashing them would flag a finished run as edited.
_UNHASHED_FLOW_KEYS = frozenset({"permanent"}) | frozenset(DRAFT_KEYS)

_now = utcnow


def _int(value: Any, default: int = 0) -> int:
    """Coerce a possibly-malformed value (flows.yaml can be hand-edited/restored outside the validated PUT) to int
    without raising."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_aware(value: Any) -> Optional[datetime]:
    """Normalize a started_at read back out of the database. Postgres hands back an aware datetime, but sqlite
    (the verify suites) can hand back naive or an ISO string; date arithmetic on that raises, and the sweep
    would swallow it per device and quietly never launch."""
    if isinstance(value, str):
        return parse_iso_utc(value)
    return as_utc(value) if isinstance(value, datetime) else None


def _load_all_flows(tenant_id: str) -> List[Dict[str, Any]]:
    """Every flow in a tenant's flows.yaml, drafts included, in document order. Not for the execution path; see
    _load_flows. Defensive: never raises, since this runs on the enroll/checkin/poll hot paths."""
    from controller.services.flow_step_catalog import normalize_flow_document
    try:
        data = tenant_config._load_readonly(tenant_id, "flows.yaml")
    except Exception:
        logger.exception("ATC: loading flows.yaml failed for tenant %s", tenant_id)
        return []
    flows, warns = normalize_flow_document(data)
    for w in warns:
        logger.info("ATC: %s", w)
    return flows


def _load_flows(tenant_id: str) -> List[Dict[str, Any]]:
    """The flows a device may actually run, permanent flow first. The only accessor on the execution path, and
    the only place drafts are filtered out, so relaxing this filter would let drafts run. Returned without a copy:
    callers that keep the document take their own."""
    from controller.services.flow_step_catalog import is_draft
    live = [f for f in _load_all_flows(tenant_id) if not is_draft(f)]
    # Stable, so document order survives inside each group.
    return sorted(live, key=lambda f: 0 if f.get("permanent") is True else 1)


def _enabled_flows(tenant_id: str) -> List[Dict[str, Any]]:
    """_load_flows minus the ones an admin has switched off."""
    return [f for f in _load_flows(tenant_id) if f.get("enabled", True)]


def _load_flow(tenant_id: str, flow_id: str) -> Optional[Dict[str, Any]]:
    """One flow by id, drafts included, for a caller that already knows which one it wants: the run viewer's fallback
    reads a finished run's flow_id through here, and the draft endpoints read a draft. Never decides what to run."""
    for flow in _load_all_flows(tenant_id):
        if str(flow.get("id")) == str(flow_id):
            return flow
    return None


def _flow_hash(flow: Dict[str, Any]) -> str:
    """Fingerprint of the definition a run executes, for saying whether the tenant's current flows.yaml is still that
    definition."""
    subject = {k: v for k, v in (flow or {}).items() if k not in _UNHASHED_FLOW_KEYS}
    return hashlib.sha256(
        json.dumps(subject, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _nodes_by_id(flow: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    # Keep the first definition of a duplicate id, matching how the validator builds its graph. A dict comprehension
    # would keep the last one and quietly disagree with what was reviewed.
    by_id: Dict[str, Dict[str, Any]] = {}
    for n in (flow.get("nodes") or []):
        if isinstance(n, dict) and n.get("id") and n["id"] not in by_id:
            by_id[n["id"]] = n
    return by_id


_scope_matches = scoping.matches_or_all


def _checkin_cooldown_minutes(params: Dict[str, Any]) -> int:
    """How long a check-in start waits between runs. An authored 0 is honoured; negative reads as zero. A bool
    takes the default rather than int()'s 1/0, since YAML turns a hand-typed yes into True."""
    value = params.get("cooldown_minutes")
    if isinstance(value, bool):
        return CHECKIN_COOLDOWN_DEFAULT_MINUTES
    minutes = _int(value, CHECKIN_COOLDOWN_DEFAULT_MINUTES)
    return max(minutes, 0)


_truthy_param = coerce.flag_param


def flows_with_start(tenant_id: str, start_node_id: str) -> List[str]:
    """Ids of the enabled flows holding this start node. The API uses it to say which flows an ambiguous manual start
    could have meant."""
    try:
        return [str(f.get("id")) for f in _enabled_flows(str(tenant_id))
                if (_nodes_by_id(f).get(start_node_id) or {}).get("type") == "start"]
    except Exception:
        logger.exception("ATC: start-node lookup failed for %s", start_node_id)
        return []


def _flow_has_release_node(flow: Dict[str, Any]) -> bool:
    return any(isinstance(n, dict) and n.get("type") == "release_device"
               for n in (flow.get("nodes") or []))
