"""Catalog of Dispatcher compliance checks: a curated set plus two generic ones.

See docs/controller/services/compliance_catalog.md for design notes.
"""

import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ReDoS guard: pattern is admin-authored but subject is untrusted device data (see docs for details).
try:
    import regex as _regex_engine

    _HAS_REGEX_TIMEOUT = True
except ImportError:  # pragma: no cover - regex is pinned in requirements
    _regex_engine = re
    _HAS_REGEX_TIMEOUT = False
_REGEX_TIMEOUT = float(os.getenv("GROUP_REGEX_TIMEOUT_SECONDS", "2.0"))

# Per check type: the label and description shown to an admin, plus the params a rule may set.
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
    {"type": "user_approved_enrollment_missing", "label": "Enrollment not user-approved",
     "description": "Nobody at the Mac ever approved its management, so macOS ignores "
                    "the parts of a profile that depend on that approval (kernel "
                    "extension policy, privacy/PPPC settings) while still reporting "
                    "the profile installed.",
     "category": "Security", "params": []},
    {"type": "bootstrap_token_disallowed", "label": "Bootstrap token not usable",
     "description": "The Mac's Secure Enclave will not let secure operations use its "
                    "bootstrap token, so managed software updates and kernel extension "
                    "approval fail whenever they need it. The setting can be changed on "
                    "the Mac itself, in recoveryOS.",
     "category": "Security", "params": []},
    {"type": "remote_desktop_enabled", "label": "Remote Management enabled",
     "description": "Remote Management (Apple Remote Desktop screen sharing and "
                    "control) is switched on (macOS).",
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
    {"type": "declaration_drift", "label": "Declaration drift (DDM)",
     "description": "A desired DDM declaration is missing from the device's reported "
                    "state, inactive, or invalid. Devices without DDM enabled are "
                    "treated as compliant.",
     "category": "Drift",
     "params": [{"name": "ids", "label": "Declaration ids", "type": "tags",
                 "required": False,
                 "help": "Limit to specific declarations.yaml ids; empty checks the "
                         "whole desired set."}]},
    {"type": "tagged", "label": "Carries a tag",
     "description": "The device carries any of the named tags.",
     "category": "Status",
     "params": [{"name": "tags", "label": "Tags", "type": "tags", "required": True}]},
    {"type": "flow_parked_for", "label": "Flow run parked too long",
     "description": "An enrollment flow run has been waiting at the same step "
                    "for longer than N hours. A run parked with no deadline is "
                    "treated as compliant, because the engine puts it back on "
                    "the clock by itself.",
     "category": "Status",
     "params": [{"name": "hours", "label": "Hours parked", "type": "int",
                 "required": True}]},
    {"type": "ddm_status", "label": "DDM status item (advanced)",
     "description": "Compare a dot-path into the device's DDM status report. Devices "
                    "without DDM data are treated as compliant.",
     "category": "Advanced",
     "params": [
         {"name": "path", "label": "Status item path", "type": "string", "required": True,
          "help": 'Dot path into the DDM StatusItems tree, e.g. "softwareupdate.install-state".'},
         {"name": "operator", "label": "Operator", "type": "select", "required": True,
          "options": ["equals", "not_equals", "contains", "gte", "lte",
                      "exists", "not_exists"]},
         {"name": "value", "label": "Value", "type": "string", "required": False},
     ]},
    {"type": "attribute", "label": "Attribute (advanced)",
     "description": "Compare a dot-path into the device's reported attributes.",
     "category": "Advanced",
     "params": [
         {"name": "key", "label": "Attribute path", "type": "string", "required": True,
          "help": 'Dot path into device attributes, e.g. '
                  '"SecurityInfo.SystemIntegrityProtectionEnabled".'},
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


# ==Attribute access==

def _sec(device: Any) -> Dict[str, Any]:
    attrs = getattr(device, "attributes", None) or {}
    sec = attrs.get("SecurityInfo")
    return sec if isinstance(sec, dict) else {}


def _sec_group(device: Any, name: str) -> Dict[str, Any]:
    """One of SecurityInfo's nested dictionaries (FirewallSettings, ManagementStatus, SecureBoot), empty when the device
    didn't report it."""
    group = _sec(device).get(name)
    return group if isinstance(group, dict) else {}


def _dig(obj: Any, path: str) -> Any:
    """Dot-path lookup into a nested dict; None if any segment is missing."""
    cur = obj
    for part in str(path).split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _run_field(run: Any, name: str) -> Any:
    """One field off a flow run, which arrives either as a FlowRun row or as a plain mapping. The names are the model's
    own in both cases, so nothing needs translating on the way in."""
    if isinstance(run, dict):
        return run.get(name)
    return getattr(run, name, None)


def _text(value: Any) -> Optional[str]:
    """A value for a finding's detail, as text or as None. Alert detail is stored as JSON, so these stay scalar."""
    return None if value is None else str(value)


# ==Evaluation==

def evaluate_check(
    check: Dict[str, Any], device: Any, ctx: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    """Return a finding dict when the device is non-compliant for check, else None. Never raises: an evaluation error is
    logged and the device treated as compliant, so a broken check raises no alerts."""
    ctx = ctx if isinstance(ctx, dict) else {}
    if not isinstance(check, dict):
        logger.warning("compliance check is not a mapping, treating as compliant: %r", check)
        return None
    ctype = check.get("type")
    try:
        params = check.get("params") or {k: v for k, v in check.items() if k not in ("type",)}
        return _EVALUATORS.get(ctype, lambda *_: None)(device, params, ctx)
    except Exception:
        logger.exception("compliance check %s failed for device %s", ctype,
                         getattr(device, "serial_number", "?"))
        return None


def _filevault(device, params, ctx):
    # SecurityInfo answers with FDE_Enabled, and the inventory writer stores the response as the device sent it. See
    # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/information.security.yaml
    val = _sec(device).get("FDE_Enabled")
    # Only an explicit False or "Off" counts: an unreported posture is unknown rather than disabled.
    if val is False or (isinstance(val, str) and val.lower() in ("off", "false", "disabled")):
        return {"summary": "FileVault is disabled", "detail": {"FDE_Enabled": val}}
    return None


def _firewall(device, params, ctx):
    # macOS reports the application firewall inside SecurityInfo's FirewallSettings dictionary; there is no top-level
    # FirewallEnabled on a Mac. Older stored inventories hold the flat key, so it stays as a fallback read.
    val = _sec_group(device, "FirewallSettings").get("FirewallEnabled")
    path = "SecurityInfo.FirewallSettings.FirewallEnabled"
    if val is None:
        val = _sec(device).get("FirewallEnabled")
        path = "SecurityInfo.FirewallEnabled"
    if val is False:
        # The path goes in the detail: the fallback key means the inventory predates what devices report today.
        return {"summary": "Firewall is disabled",
                "detail": {"FirewallEnabled": val, "path": path}}
    return None


def _passcode(device, params, ctx):
    val = _sec(device).get("PasscodePresent")
    if val is False:
        return {"summary": "No device passcode is set", "detail": {"PasscodePresent": val}}
    return None


def _user_approved_enrollment(device, params, ctx):
    # ManagementStatus is a Mac-only sub-dictionary. Anything that does not report it (an iPhone, a Mac that has not
    # answered a SecurityInfo query yet) is unknown rather than unapproved, so only an explicit False counts.
    val = _sec_group(device, "ManagementStatus").get("UserApprovedEnrollment")
    if val is False:
        return {"summary": "MDM enrollment was never approved by a user",
                "detail": {"UserApprovedEnrollment": val}}
    return None


def _bootstrap_token(device, params, ctx):
    sec = _sec(device)
    val = sec.get("BootstrapTokenAllowedForAuthentication")
    # String value: "allowed", "disallowed", or "not supported". Only "disallowed" is a posture problem.
    if isinstance(val, str) and val.strip().lower() == "disallowed":
        return {
            "summary": "Bootstrap token use is disallowed on this Mac",
            "detail": {
                "BootstrapTokenAllowedForAuthentication": val,
                "BootstrapTokenRequiredForSoftwareUpdate":
                    sec.get("BootstrapTokenRequiredForSoftwareUpdate"),
                "BootstrapTokenRequiredForKernelExtensionApproval":
                    sec.get("BootstrapTokenRequiredForKernelExtensionApproval"),
            },
        }
    return None


def _remote_desktop(device, params, ctx):
    val = _sec(device).get("RemoteDesktopEnabled")
    if val is True:
        return {"summary": "Remote Management is enabled",
                "detail": {"RemoteDesktopEnabled": val}}
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


def _declaration_drift(device, params, ctx):
    # Only devices actually running DDM, which the first sync marks with ddm_enabled_at.
    if not getattr(device, "ddm_enabled_at", None):
        return None
    desired = ctx.get("ddm_desired") or []
    # Predicated declarations report active=false when predicate is false; only "invalid" counts as drift for those.
    predicated = set()
    for d in desired:
        if d.get("Type") == "com.apple.activation.simple" \
            and (d.get("Payload") or {}).get("Predicate"):
            ident = d.get("Identifier") or ""
            predicated.add(ident)
            if ident.startswith("mm.act."):
                predicated.add("mm.cfg." + ident[len("mm.act."):])
    ids = params.get("ids")
    ids = ids if isinstance(ids, list) else ([ids] if ids else [])
    if ids:
        wanted = {f"mm.cfg.{x}" for x in (str(i) for i in ids if i)}
        desired = [d for d in desired if d.get("Identifier") in wanted]
    reported = getattr(device, "ddm_declaration_status", None) or {}
    problems = []
    for d in desired:
        ident = d.get("Identifier")
        # management.* declarations always report active=false by design.
        if (d.get("Type") or "").startswith("com.apple.management."):
            continue
        state = reported.get(ident)
        if not isinstance(state, dict):
            problems.append({"identifier": ident, "status": "missing"})
            continue
        if state.get("valid") == "invalid" \
            or (state.get("active") is not True and ident not in predicated):
            reasons = state.get("reasons") or []
            code = reasons[0].get("code") if reasons and isinstance(reasons[0], dict) else None
            problems.append({
                "identifier": ident,
                "status": "invalid" if state.get("valid") == "invalid" else "inactive",
                **({"reason": code} if code else {}),
            })
    if problems:
        first_reason = next((p["reason"] for p in problems if p.get("reason")), None)
        summary = f"{len(problems)} declaration(s) missing or failed"
        if first_reason:
            summary += f" ({first_reason})"
        return {"summary": summary,
                "detail": {"problems": problems,
                           "identifiers": [p["identifier"] for p in problems]}}
    return None


def _ddm_status(device, params, ctx):
    status = getattr(device, "ddm_status", None) or {}
    # No DDM data means unknown, so nothing is reported, as in declaration_drift.
    if not getattr(device, "ddm_enabled_at", None) or not status:
        return None
    path = params.get("path")
    op = params.get("operator")
    expected = params.get("value")
    actual = _dig(status, path) if path else None
    fired = False
    if op == "exists":
        fired = actual is not None
    elif op == "not_exists":
        fired = actual is None
    elif actual is None:
        # An unreported status item is unknown: only the existence operators handle absence, as in the attribute check.
        fired = False
    elif op == "equals":
        fired = str(actual) == str(expected)
    elif op == "not_equals":
        fired = str(actual) != str(expected)
    elif op == "contains":
        if isinstance(actual, (list, tuple)):
            fired = any(str(x) == str(expected) for x in actual)
        else:
            fired = str(expected) in str(actual)
    elif op in ("gte", "lte"):
        try:
            a, b = float(actual), float(expected)
            fired = a >= b if op == "gte" else a <= b
        except (TypeError, ValueError):
            fired = False
    if fired:
        return {"summary": f"DDM {path} {op} {expected if expected is not None else ''}".strip(),
                "detail": {"path": path, "operator": op, "value": expected, "actual": actual}}
    return None


def _tagged(device, params, ctx):
    want = params.get("tags")
    want = want if isinstance(want, list) else ([want] if want else [])
    have = set(getattr(device, "tags", []) or [])
    hit = [t for t in (str(x) for x in want if x) if t in have]
    if hit:
        return {"summary": f"Tagged {', '.join(hit)}", "detail": {"tags": hit}}
    return None


def _flow_parked_for(device, params, ctx):
    """Flow runs that have sat at the same step longer than hours. Reads ctx["flow_runs"]."""
    try:
        hours = float(params.get("hours"))
    except (TypeError, ValueError):
        return None
    now = datetime.now(timezone.utc)
    stuck = []
    for run in ctx.get("flow_runs") or []:
        if _run_field(run, "status") != "waiting":
            continue
        # A park with no deadline is a legacy or hand-edited row, and atc._adopt_legacy_gate puts those back on the
        # escalation clock at the next sweep tick.
        if _run_field(run, "wait_deadline") is None:
            continue
        # updated_at is auto_now and a parked run writes on every partial arrival, so this measures how long the run has
        # been silent, the same reading parked_before uses in api/main.py.
        parked_since = _run_field(run, "updated_at")
        if not isinstance(parked_since, datetime):
            continue
        since = (parked_since if parked_since.tzinfo
                 else parked_since.replace(tzinfo=timezone.utc))
        parked = (now - since).total_seconds() / 3600.0
        if parked <= hours:
            continue
        entry = {
            "flow_id": _text(_run_field(run, "flow_id")),
            "node": _text(_run_field(run, "current_node")),
            "waiting_signal": _text(_run_field(run, "waiting_signal")),
            "hours_parked": round(parked, 1),
        }
        run_id = _run_field(run, "id")
        if run_id is not None:
            entry["run_id"] = str(run_id)
        stuck.append(entry)
    if not stuck:
        return None
    if len(stuck) == 1:
        one = stuck[0]
        summary = (f"Flow '{one['flow_id'] or '?'}' has been parked "
                   f"{one['hours_parked']:g} hours at "
                   f"'{one['node'] or '?'}' (limit {hours:g})")
    else:
        summary = f"{len(stuck)} flow runs parked longer than {hours:g} hours"
    return {"summary": summary, "detail": {"runs": stuck}}


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
        # A missing or unreported attribute is unknown: no comparison operator matches it, and only exists, above,
        # handles absence.
        fired = False
    elif op == "equals":
        fired = str(actual) == str(expected)
    elif op == "not_equals":
        fired = str(actual) != str(expected)
    elif op == "regex":
        # Timeout-bounded so a catastrophic-backtracking pattern against device-reported data cannot stall the loop.
        try:
            if _HAS_REGEX_TIMEOUT:
                fired = _regex_engine.search(
                    str(expected), str(actual), timeout=_REGEX_TIMEOUT
                ) is not None
            else:
                fired = re.search(str(expected), str(actual)) is not None
        except Exception:
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
    "user_approved_enrollment_missing": _user_approved_enrollment,
    "bootstrap_token_disallowed": _bootstrap_token,
    "remote_desktop_enabled": _remote_desktop,
    "os_below": _os_below,
    "not_seen_for": _not_seen_for,
    "lost_mode_active": _lost_mode,
    "unsupervised": _unsupervised,
    "missing_profile": _missing_profile,
    "config_drift": _config_drift,
    "declaration_drift": _declaration_drift,
    "ddm_status": _ddm_status,
    "tagged": _tagged,
    "flow_parked_for": _flow_parked_for,
    "attribute": _attribute,
}
