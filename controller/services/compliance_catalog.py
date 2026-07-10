"""Catalog of Dispatcher compliance checks (curated + a generic escape hatch).

Single source of truth consumed by BOTH the validator (dispatcher.yaml check
params are checked against it) and the web UI (GET /api/v1/dispatcher/check-catalog),
so the rule editor renders its check picker + param forms data-driven -- same
philosophy as command_catalog / flow_step_catalog.

A check reads ONLY already-collected state (device.attributes from the webhook
inventory, device.last_seen, the deployment tables) -- the Dispatcher never
issues its own device queries. Evaluation is defensive: a missing attribute is
treated per-check and never raises. ``evaluate_check`` returns a *finding*
(``{"summary", "detail"}``) when the device is NON-COMPLIANT, else None.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Metadata for the UI check picker (curated checks + the generic `attribute`).
CHECK_CATALOG: List[Dict[str, Any]] = [
    {"type": "filevault_disabled", "label": "FileVault disabled",
     "description": "Full-disk encryption (FileVault) is not enabled (macOS).",
     "category": "Security", "params": []},
    {"type": "firewall_disabled", "label": "Firewall disabled",
     "description": "The application firewall is off (macOS).",
     "category": "Security", "params": []},
    {"type": "passcode_missing", "label": "No passcode",
     "description": "The device has no passcode set.",
     "category": "Security", "params": []},
    {"type": "os_below", "label": "OS below version",
     "description": "The OS version is below a minimum.",
     "category": "Posture",
     "params": [{"name": "min", "label": "Minimum version", "type": "string",
                 "required": True, "help": 'e.g. "17.0"'}]},
    {"type": "not_seen_for", "label": "Not seen recently",
     "description": "The device hasn't checked in for N days.",
     "category": "Posture",
     "params": [{"name": "days", "label": "Days", "type": "int", "required": True}]},
    {"type": "lost_mode_active", "label": "Lost Mode active",
     "description": "Managed Lost Mode is enabled on the device.",
     "category": "Status", "params": []},
    {"type": "unsupervised", "label": "Unsupervised",
     "description": "The device is not supervised.",
     "category": "Posture", "params": []},
    {"type": "missing_profile", "label": "Profile missing",
     "description": "A specific desired profile is not installed.",
     "category": "Drift",
     "params": [{"name": "profile_id", "label": "Profile id", "type": "string",
                 "required": True}]},
    {"type": "config_drift", "label": "Configuration drift",
     "description": "Any desired profile/app is missing or failed to install.",
     "category": "Drift", "params": []},
    {"type": "tagged", "label": "Carries a tag",
     "description": "The device carries any of the named tags.",
     "category": "Status",
     "params": [{"name": "tags", "label": "Tags", "type": "tags", "required": True}]},
    {"type": "attribute", "label": "Attribute (advanced)",
     "description": "Compare a dot-path into the device's reported attributes.",
     "category": "Advanced",
     "params": [
         {"name": "key", "label": "Attribute path", "type": "string", "required": True,
          "help": 'Dot path into device attributes, e.g. "SecurityInfo.SIPEnabled".'},
         {"name": "operator", "label": "Operator", "type": "select", "required": True,
          "options": ["equals", "not_equals", "exists", "gt", "lt", "regex"]},
         {"name": "value", "label": "Value", "type": "string", "required": False},
     ]},
]

_BY_TYPE = {c["type"]: c for c in CHECK_CATALOG}
VALID_CHECK_TYPES = frozenset(_BY_TYPE)


def get_check(check_type: str) -> Optional[Dict[str, Any]]:
    return _BY_TYPE.get(check_type)


def catalog() -> Dict[str, Any]:
    return {"checks": CHECK_CATALOG}


# ── Attribute access ─────────────────────────────────────────────────────────

def _sec(device: Any) -> Dict[str, Any]:
    attrs = getattr(device, "attributes", None) or {}
    sec = attrs.get("SecurityInfo")
    return sec if isinstance(sec, dict) else {}


def _dig(obj: Any, path: str) -> Any:
    """Dot-path lookup into a nested dict; None if any segment is missing."""
    cur = obj
    for part in str(path).split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


# ── Evaluation ───────────────────────────────────────────────────────────────

def evaluate_check(
    check: Dict[str, Any], device: Any, ctx: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    """Return a finding dict when the device is NON-COMPLIANT for ``check``, else
    None. Never raises: an evaluation error is logged and treated as compliant
    (fail-safe: a bad check must not spam alerts)."""
    ctx = ctx or {}
    ctype = check.get("type")
    params = check.get("params") or {k: v for k, v in check.items() if k not in ("type",)}
    try:
        return _EVALUATORS.get(ctype, lambda *_: None)(device, params, ctx)
    except Exception:
        logger.exception("compliance check %s failed for device %s", ctype,
                         getattr(device, "serial_number", "?"))
        return None


def _filevault(device, params, ctx):
    sec = _sec(device)
    val = sec.get("FDE_Enabled")
    if val is None:
        val = sec.get("FileVaultStatus")  # some agents report this instead
    # Fire only when we KNOW it's off (explicit False / "Off") -- an unreported
    # posture is "unknown", not "disabled", so a fresh device doesn't false-alarm.
    if val is False or (isinstance(val, str) and val.lower() in ("off", "false", "disabled")):
        return {"summary": "FileVault is disabled", "detail": {"FDE_Enabled": val}}
    return None


def _firewall(device, params, ctx):
    val = _sec(device).get("FirewallEnabled")
    if val is False:
        return {"summary": "Firewall is disabled", "detail": {"FirewallEnabled": val}}
    return None


def _passcode(device, params, ctx):
    val = _sec(device).get("PasscodePresent")
    if val is False:
        return {"summary": "No device passcode is set", "detail": {"PasscodePresent": val}}
    return None


def _os_below(device, params, ctx):
    from packaging import version
    minimum = str(params.get("min") or "").strip()
    dev = str(getattr(device, "os_version", "") or "").strip()
    if not minimum or not dev:
        return None
    try:
        if version.parse(dev) < version.parse(minimum):
            return {"summary": f"OS {dev} is below {minimum}",
                    "detail": {"os_version": dev, "min": minimum}}
    except Exception:
        return None
    return None


def _not_seen_for(device, params, ctx):
    try:
        days = float(params.get("days"))
    except (TypeError, ValueError):
        return None
    last_seen = getattr(device, "last_seen", None)
    if last_seen is None:
        return None
    now = datetime.now(timezone.utc)
    ls = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=timezone.utc)
    age_days = (now - ls).total_seconds() / 86400.0
    if age_days > days:
        return {"summary": f"Not seen for {age_days:.1f} days (limit {days:g})",
                "detail": {"last_seen": ls.isoformat(), "age_days": round(age_days, 1)}}
    return None


def _lost_mode(device, params, ctx):
    attrs = getattr(device, "attributes", None) or {}
    if attrs.get("IsMDMLostModeEnabled") is True:
        return {"summary": "Managed Lost Mode is active", "detail": {}}
    return None


def _unsupervised(device, params, ctx):
    attrs = getattr(device, "attributes", None) or {}
    if attrs.get("IsSupervised") is False:
        return {"summary": "Device is not supervised", "detail": {}}
    return None


def _missing_profile(device, params, ctx):
    pid = str(params.get("profile_id") or "").strip()
    if not pid:
        return None
    statuses = ctx.get("profile_status") or {}
    if statuses.get(pid) != "installed":
        return {"summary": f"Profile '{pid}' is not installed",
                "detail": {"profile_id": pid, "status": statuses.get(pid)}}
    return None


def _config_drift(device, params, ctx):
    problems = ctx.get("drift") or []
    if problems:
        return {"summary": f"{len(problems)} configuration item(s) missing or failed",
                "detail": {"problems": problems}}
    return None


def _tagged(device, params, ctx):
    want = params.get("tags")
    want = want if isinstance(want, list) else ([want] if want else [])
    have = set(getattr(device, "tags", []) or [])
    hit = [t for t in (str(x) for x in want if x) if t in have]
    if hit:
        return {"summary": f"Tagged {', '.join(hit)}", "detail": {"tags": hit}}
    return None


def _attribute(device, params, ctx):
    key = params.get("key")
    op = params.get("operator")
    expected = params.get("value")
    attrs = getattr(device, "attributes", None) or {}
    actual = _dig(attrs, key) if key else None
    fired = False
    if op == "exists":
        fired = actual is not None
    elif actual is None:
        # A missing/unreported attribute is "unknown", not "known-bad": no
        # comparison operator fires on it (mirrors the security checks, which
        # only fire on an explicit value). Only `exists` handles absence above.
        fired = False
    elif op == "equals":
        fired = str(actual) == str(expected)
    elif op == "not_equals":
        fired = str(actual) != str(expected)
    elif op == "regex":
        try:
            fired = actual is not None and re.search(str(expected), str(actual)) is not None
        except re.error:
            fired = False
    elif op in ("gt", "lt"):
        try:
            a, b = float(actual), float(expected)
            fired = a > b if op == "gt" else a < b
        except (TypeError, ValueError):
            fired = False
    if fired:
        return {"summary": f"{key} {op} {expected}".strip(),
                "detail": {"key": key, "operator": op, "value": expected, "actual": actual}}
    return None


_EVALUATORS = {
    "filevault_disabled": _filevault,
    "firewall_disabled": _firewall,
    "passcode_missing": _passcode,
    "os_below": _os_below,
    "not_seen_for": _not_seen_for,
    "lost_mode_active": _lost_mode,
    "unsupervised": _unsupervised,
    "missing_profile": _missing_profile,
    "config_drift": _config_drift,
    "tagged": _tagged,
    "attribute": _attribute,
}
