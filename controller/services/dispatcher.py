"""Compliance rules engine, alerting, and guarded auto-remediation.

Rules live in dispatcher.yaml: check a scoped device, raise/notify/auto-remediate on failure.
Auto-remediation guardrails (off by default, destructive commands need approval, audited
command path, dry_run + kill switches, cooldown/escalation, full ledger) live in
_attempt_remediation.
"""

import hashlib
import hmac
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Any, Dict, List, Optional, Set, Tuple

from controller.auth import DESTRUCTIVE_COMMANDS
from controller.models.tenant import (
    Alert,
    AppDeployment,
    Device,
    FlowRun,
    ProfileDeployment,
    Tenant,
)
from controller.services import tenant_config
from controller.services.compliance_catalog import evaluate_check
from controller.services.scoping import device_in_rollout, evaluate_scope
from controller.services.severity import RANK, escalate as _escalate_severity

logger = logging.getLogger(__name__)

# The shared severity table, read from this module by api.main and by the verify suites. Assigned rather than
# aliased on the import line, where an import optimizer sees a name this file never uses and drops it.
SEVERITY_RANK = RANK

# Rule id shape (mirrors yaml_validator.DispatcherRule.validate_id), used by _resolve_orphaned_alerts to tell a
# dispatcher-raised alert from one namespaced with a colon by the flow engine or break-glass.
_DISPATCHER_RULE_ID = re.compile(r'^[a-z0-9-_]+$')

# Board ranking: higher is more severe (black > red > yellow > green). Shared with services/severity.py so the two
# engines cannot drift apart.

# Check types whose evaluation reads the deployment tables (_build_ctx).
_DRIFT_CHECK_TYPES = frozenset({"missing_profile", "config_drift"})

# Check types whose evaluation reads the flow_runs table (_build_ctx).
_FLOW_CHECK_TYPES = frozenset({"flow_parked_for"})

# Flow-run fetch width: only the fields compliance_catalog._flow_parked_for and the prefetch below read. A run's
# pinned flow snapshot and step timeline are the biggest part of the row and no check reads them. A field missing
# here reads as None (getattr fallback) rather than raising, so a parked run silently stops looking parked; see
# docs/controller/services/dispatcher.md.
_FLOW_RUN_FIELDS = (
    "id", "device_id", "flow_id", "status", "current_node", "waiting_signal",
    "wait_deadline", "updated_at",
)

# Sweep fetch width: only the Device fields the evaluation path reads (checks, scoping, DDM desired-set, remediation,
# tag actions, notification payload); the full row's installed_apps/installed_profiles can be 100-400KB each and
# nothing here needs them. Any new device-field read on the evaluation path must join this list: an unfetched
# Tortoise partial field raises on direct read, but getattr fallbacks (including the DDM declaration cache
# fingerprint) silently treat a missing field as empty. verify_ddm
# asserts the subset mechanically.
_SWEEP_DEVICE_FIELDS = (
    "id", "tenant_id", "udid", "serial_number", "device_model", "os_version",
    "hostname", "name", "enrollment_state", "enrollment_date", "last_seen",
    "groups", "tags", "attributes", "ddm_enabled_at", "ddm_last_published_token",
    "ddm_status", "ddm_declaration_status", "ddm_client_capabilities",
)

# ==Tunable rates==
# Read fresh per call, not bound at import, so the environment and the running loop never disagree. _ENV_WARNED
# holds values already warned about, so a malformed setting is reported once, not once per device per sweep.
_ENV_WARNED: set = set()


def _env_number(name: str, default: Any) -> Any:
    """One tunable, read fresh, coerced to the type of its default.

    A value that will not convert falls back to the default and says so once. These are read on the per-device
    evaluation path, so raising there would turn one mistyped variable into a failure per device per sweep, and every
    one of these numbers is a pace rather than a permission.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return type(default)(raw)
    except (TypeError, ValueError):
        if (name, raw) not in _ENV_WARNED:
            _ENV_WARNED.add((name, raw))
            logger.warning("%s=%r is not a number; using %r", name, raw, default)
        return default


def _remediation_cooldown_minutes() -> int:
    """How long after a remediation runs before the same one may run again."""
    return _env_number("DISPATCHER_REMEDIATION_COOLDOWN_MINUTES", 60)


def _remediation_max_attempts() -> int:
    """Attempts on one (device, rule, action) before a human is required."""
    return _env_number("DISPATCHER_REMEDIATION_MAX_ATTEMPTS", 3)


def _webhook_timeout_seconds() -> float:
    """Per-request timeout for a rule's outbound webhook."""
    return _env_number("DISPATCHER_WEBHOOK_TIMEOUT_SECONDS", 10.0)


def _webhook_max_attempts() -> int:
    """Deliveries attempted for one webhook before it is given up on."""
    return _env_number("DISPATCHER_WEBHOOK_MAX_ATTEMPTS", 3)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _truthy(v: Any) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on") if v is not None else False


def _load_dispatcher(tenant_id: str) -> Dict[str, Any]:
    """dispatcher.yaml as a copy the caller owns.

    approve_remediation is the one caller that wants this rather than the readonly variant: it re-derives an action's
    params from the document and hands them to the audited command path, which builds a Task's details out of their
    values. Evaluation uses _load_dispatcher_readonly."""
    doc = tenant_config._load(tenant_id, "dispatcher.yaml")
    return doc if isinstance(doc, dict) else {}


def _load_dispatcher_readonly(tenant_id: str) -> Dict[str, Any]:
    """dispatcher.yaml for rule evaluation, without the deep copy.

    Everything evaluation does with this document is a read: rules, webhooks, scopes and checks are only inspected,
    evaluate_check builds its params fresh instead of writing into the check, and every value that reaches Alert.detail
    is a fresh dict of scalars. Sweep already loads once per tenant and hands the same object to every device it
    evaluates. Anything that stores part of the document must use _load_dispatcher instead."""
    doc = tenant_config._load_readonly(tenant_id, "dispatcher.yaml")
    return doc if isinstance(doc, dict) else {}


def _auto_remediation_enabled(doc: Dict[str, Any]) -> bool:
    """Effective kill switch: the env master switch and the per-document one, either of them false disabling every
    remediation for the tenant."""
    env_on = _truthy(os.getenv("DISPATCHER_AUTO_REMEDIATION_ENABLED", "true"))
    doc_on = doc.get("auto_remediation_enabled", True) is not False
    return env_on and doc_on


def _scope_matches(device: Device, device_groups: List[str], scope: Optional[Dict[str, Any]]) -> bool:
    """An empty scope matches every device; otherwise the shared scope engine decides."""
    scope = scope or {}
    if not any(scope.get(k) for k in
               ("groups", "conditions", "include_devices", "exclude_devices")):
        return True
    return evaluate_scope(device, device_groups, scope)


def _list(v: Any) -> List[str]:
    items = v if isinstance(v, list) else ([v] if v else [])
    return [str(x) for x in items if x]


def _action_key(action: Dict[str, Any]) -> str:
    """A stable, secret-free identifier for an action, used for cooldown and attempt tracking and as the approval key
    stored in Alert.detail. Secret command params are stripped so the key can go out over the API without carrying a
    wipe PIN or a password; the real params live only in dispatcher.yaml and are re-derived at approval time.
    """
    params = dict(action.get("params") or {})
    if action.get("type") == "send_command":
        from controller.services.command_catalog import get_command, secret_param_names
        entry = get_command(params.get("command")) or {}
        secret = secret_param_names(entry) | {"pin"}
        inner = {k: v for k, v in (params.get("params") or {}).items() if k not in secret}
        params = {**params, "params": inner}
    return json.dumps({"type": action.get("type"), "params": params},
                      sort_keys=True, default=str)


# ==Entry points==

async def evaluate_device(device: Device, reason: str = "event",
                          tenant: Optional[Tenant] = None,
                          doc: Optional[Dict[str, Any]] = None,
                          active_pairs: Optional[Set[Tuple[str, str]]] = None,
                          drift_ctx: Optional[Dict[str, Any]] = None,
                          flow_ctx: Optional[Dict[str, Any]] = None) -> None:
    """Evaluate every enabled rule for a device and reconcile its alerts. Best-effort: never raises into the caller,
    which is the webhook or the sweep.

    tenant/doc/active_pairs/drift_ctx/flow_ctx are sweep()'s pass-throughs and prefetches, never module state; the
    single-device webhook path passes none of them.
    """
    try:
        if tenant is None:
            tenant = await Tenant.get_or_none(id=device.tenant_id)
        if tenant is None:
            return
        if doc is None:
            doc = _load_dispatcher_readonly(str(tenant.id))
        rules = doc.get("rules") or []
        if not rules:
            return
        master_on = _auto_remediation_enabled(doc)
        webhooks = {w.get("name"): w for w in (doc.get("webhooks") or []) if isinstance(w, dict)}
        # Stored membership snapshot, for rule scoping below only; deliberately not handed to _build_ctx, which
        # derives membership fresh instead.
        device_groups = list(device.groups or [])
        ctx = await _build_ctx(device, tenant, rules, None, drift_ctx, flow_ctx)

        for rule in rules:
            try:
                if not isinstance(rule, dict) or not rule.get("enabled", True):
                    continue
                if not _scope_matches(device, device_groups, rule.get("scope")):
                    # Left the rule's scope -> its alert (if any) no longer applies.
                    await _resolve_if_active(device, rule, "out of scope", active_pairs)
                    continue
                finding = evaluate_check(rule.get("check") or {}, device, ctx)
                if finding:
                    await _handle_noncompliant(tenant, device, rule, finding, master_on, webhooks)
                else:
                    await _handle_compliant(device, rule, active_pairs)
            except Exception:
                logger.exception("dispatcher: rule %s failed for %s",
                                 (rule or {}).get("id"), device.serial_number)
    except Exception:
        logger.exception("dispatcher: evaluate_device failed for %s",
                         getattr(device, "serial_number", "?"))


async def sweep(tenant: Tenant) -> int:
    """Re-evaluate every enrolled device for a tenant, and return how many were evaluated. Covers the time-based checks
    (not_seen_for), grace-period expiry from pending to open, remediation cooldown and re-attempts, and alerts left
    behind by a retired rule."""
    try:
        doc = _load_dispatcher_readonly(str(tenant.id))
        rules = doc.get("rules") or []
    except Exception:
        logger.exception("dispatcher: sweep query failed for tenant %s", tenant.id)
        return 0
    # Optimization, not a precondition: on error, evaluation falls back to per-device queries. One query for the
    # whole sweep (every live alert) answers both active_pairs (evaluate_device's read-side filter) and which
    # alerts are orphaned, which is why it runs before the no-rules shortcut below.
    alert_rows: Optional[List[Dict[str, Any]]] = None
    active_pairs: Optional[Set[Tuple[str, str]]] = None
    try:
        alert_rows = await Alert.filter(tenant=tenant).exclude(
            status="resolved"
        ).values("id", "device_id", "rule_id")
        active_pairs = {(str(p["device_id"]), str(p["rule_id"])) for p in alert_rows}
    except Exception:
        logger.warning("dispatcher: alert prefetch failed for tenant %s; "
                       "falling back to per-device queries this sweep",
                       tenant.id, exc_info=True)
    if alert_rows is not None:
        # active_pairs keeps any pair resolved just below, which is safe: it is a read-side filter that may only be
        # stale in the permissive direction (evaluate_device says so), and the rule behind a resolved orphan is gone
        # from the document, so the per-rule loop never asks about it.
        try:
            await _resolve_orphaned_alerts(tenant, doc, alert_rows)
        except Exception:
            logger.exception("dispatcher: resolving orphaned alerts failed for "
                             "tenant %s", tenant.id)
    try:
        if not rules:
            return 0
        devices = await Device.filter(
            tenant=tenant, enrollment_state="enrolled"
        ).only(*_SWEEP_DEVICE_FIELDS)
    except Exception:
        logger.exception("dispatcher: sweep query failed for tenant %s", tenant.id)
        return 0
    drift_ctx: Optional[Dict[str, Any]] = None
    try:
        drift_ctx = await _prefetch_drift_ctx(tenant, rules)
    except Exception:
        logger.warning("dispatcher: deployment prefetch failed for tenant %s; "
                       "falling back to per-device queries this sweep",
                       tenant.id, exc_info=True)
    flow_ctx: Optional[Dict[str, Any]] = None
    try:
        flow_ctx = await _prefetch_flow_ctx(tenant, rules)
    except Exception:
        logger.warning("dispatcher: flow-run prefetch failed for tenant %s; "
                       "falling back to per-device queries this sweep",
                       tenant.id, exc_info=True)
    for device in devices:
        try:
            await evaluate_device(device, reason="sweep", tenant=tenant, doc=doc,
                                  active_pairs=active_pairs, drift_ctx=drift_ctx,
                                  flow_ctx=flow_ctx)
        except Exception:
            logger.exception("dispatcher: sweep eval failed for %s",
                             getattr(device, "serial_number", "?"))
    return len(devices)


async def sweep_all_tenants() -> None:
    for tenant in await Tenant.filter(is_active=True).all():
        try:
            await sweep(tenant)
        except Exception:
            logger.exception("dispatcher: sweep failed for tenant %s", tenant.id)


#  Context: the drift signal, read from the deployment tables (no new queries)

async def _prefetch_drift_ctx(tenant: Tenant,
                              rules: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Sweep-wide deployment prefetch: two tenant queries instead of one or two per device. None when no rule reads the
    deployment tables, so a posture-only tenant pays nothing. The rows are read-only here, and a sweep-start snapshot is
    as fresh as the device rows the sweep itself iterates."""
    check_types = {
        (r.get("check") or {}).get("type") for r in rules if isinstance(r, dict)
    }
    if not (check_types & _DRIFT_CHECK_TYPES):
        return None
    profiles: Dict[str, List[ProfileDeployment]] = {}
    for pd in await ProfileDeployment.filter(tenant=tenant).all():
        profiles.setdefault(str(pd.device_id), []).append(pd)
    failed_apps: Dict[str, List[AppDeployment]] = {}
    if "config_drift" in check_types:
        for ad in await AppDeployment.filter(tenant=tenant, status="failed").all():
            failed_apps.setdefault(str(ad.device_id), []).append(ad)
    return {"profiles": profiles, "failed_apps": failed_apps}


async def _prefetch_flow_ctx(tenant: Tenant,
                             rules: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Sweep-wide flow-run prefetch: one tenant query instead of one per device. None when no rule reads the flow runs,
    so a posture-only tenant pays nothing, as in _prefetch_drift_ctx above.

    Pre-filtered to parked runs, the only status flow_parked_for reports on, so the query returns a small slice of a
    busy tenant's flow_runs table rather than its history. The check filters by status again itself, so this is a
    narrowing and not a contract.

    The rows are read-only here, and a run that parks or unparks mid-sweep is judged on the next tick.
    """
    check_types = {
        (r.get("check") or {}).get("type") for r in rules if isinstance(r, dict)
    }
    if not (check_types & _FLOW_CHECK_TYPES):
        return None
    by_device: Dict[str, List[FlowRun]] = {}
    for run in await FlowRun.filter(tenant=tenant, status="waiting").only(
        *_FLOW_RUN_FIELDS):
        by_device.setdefault(str(run.device_id), []).append(run)
    return {"runs": by_device}


async def _build_ctx(device: Device, tenant: Tenant, rules: List[Dict[str, Any]],
                     device_groups: Optional[List[str]] = None,
                     drift_ctx: Optional[Dict[str, Any]] = None,
                     flow_ctx: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {}
    check_types = {
        (r.get("check") or {}).get("type") for r in rules if isinstance(r, dict)
    }
    # DDM desired set, in memory only, computed only when a declaration_drift rule exists and the device runs DDM,
    # through the cached wrapper (rollout bursts bring every acking device here). Called without device_groups so
    # drift is checked against freshly derived membership, matching api/ddm.py.
    if "declaration_drift" in check_types and getattr(device, "ddm_enabled_at", None):
        try:
            from controller.services import ddm_manager
            ctx["ddm_desired"] = await ddm_manager.compute_device_declarations_cached(
                device, tenant
            )
        except Exception:
            logger.exception("dispatcher: DDM desired-set computation failed for %s",
                             device.serial_number)
            ctx["ddm_desired"] = []
    # The device's parked flow runs, for flow_parked_for, queried only when a rule reads them, as with the deployment
    # tables below. It has to sit above the drift early return: a tenant can watch parked runs without watching profile
    # drift, and below that return this block would never run for them.
    if check_types & _FLOW_CHECK_TYPES:
        try:
            if flow_ctx is not None:
                ctx["flow_runs"] = flow_ctx["runs"].get(str(device.id)) or []
            else:
                ctx["flow_runs"] = await FlowRun.filter(
                    device_id=device.id, status="waiting"
                ).only(*_FLOW_RUN_FIELDS)
        except Exception:
            # An empty list reads as no parked runs, which the check treats as compliant: a transient DB error must not
            # invent an alert, the same direction every other check fails in.
            logger.exception("dispatcher: flow-run fetch failed for %s",
                             device.serial_number)
            ctx["flow_runs"] = []
    # Only touch the deployment tables when a rule actually reads them, so the common case (security/posture checks)
    # adds no DB work on the webhook path.
    if not (check_types & _DRIFT_CHECK_TYPES):
        return ctx
    try:
        if drift_ctx is not None:
            pds = drift_ctx["profiles"].get(str(device.id)) or []
        else:
            pds = await ProfileDeployment.filter(device=device).all()
        ctx["profile_status"] = {pd.profile_id: pd.status for pd in pds}
    except Exception:
        ctx["profile_status"] = {}
        pds = []
    if "config_drift" not in check_types:
        return ctx
    drift: List[Dict[str, Any]] = []
    try:
        from controller.services.profile_manager import ProfileManager
        profiles_config = tenant_config._load(str(tenant.id), "profiles.yaml").get("profiles", [])
        # evaluate_device_profiles reads groups.yaml only when device_groups is None (evaluate_device's case); a
        # caller that already derived membership should not pay for the walk or the deep copy twice.
        groups_config = ([] if device_groups is not None
                         else tenant_config.load_groups(str(tenant.id)))
        desired, _held = await ProfileManager(tenant).evaluate_device_profiles(
            device, profiles_config, groups_config, device_groups=device_groups
        )
        status = ctx["profile_status"]
        for p in desired:
            if status.get(p["id"]) != "installed":
                drift.append({"profile": p["id"], "status": status.get(p["id"])})
        for pd in pds:
            if pd.status == "failed":
                drift.append({"profile": pd.profile_id, "status": "failed"})
        if drift_ctx is not None:
            failed_ads = drift_ctx["failed_apps"].get(str(device.id)) or []
        else:
            failed_ads = await AppDeployment.filter(device=device, status="failed").all()
        for ad in failed_ads:
            drift.append({"app": ad.app_id, "status": "failed"})
    except Exception:
        logger.exception("dispatcher: drift computation failed for %s", device.serial_number)
    ctx["drift"] = drift
    return ctx


# ==Alert lifecycle==

async def _active_alert(device: Device, rule_id: str) -> Optional[Alert]:
    """The single active (non-resolved) alert for a (device, rule).

    At most one is enforced in code rather than by a DB constraint, since resolved rows accumulate. evaluate_device can
    run concurrently on the webhook and sweep paths and briefly create duplicates, so this keeps the oldest active row
    and resolves any extras, and the invariant reconverges on every evaluation."""
    active = await Alert.filter(device_id=device.id, rule_id=rule_id).exclude(
        status="resolved"
    ).order_by("first_detected_at").all()
    if not active:
        return None
    if len(active) > 1:
        for extra in active[1:]:
            extra.status = "resolved"
            extra.resolved_at = _now()
            d = extra.detail or {}
            d["resolved_reason"] = "deduplicated (concurrent create)"
            extra.detail = d
            try:
                await extra.save(update_fields=["status", "resolved_at", "detail"])
            except Exception:
                logger.exception("dispatcher: deduping alert %s failed", extra.id)
    return active[0]


async def _recent_remediation_state(device: Device, rule_id: str) -> Dict[str, Any]:
    """Loop-protection counters carried over from this (device, rule)'s last resolved alert, but only when it resolved
    inside the cooldown window. A fast resolve-then-reopen flap keeps accumulating attempts instead of resetting, while
    a device that stayed compliant past the cooldown gets a clean budget."""
    try:
        prev = await Alert.filter(
            device_id=device.id, rule_id=rule_id, status="resolved"
        ).order_by("-resolved_at").first()
    except Exception:
        return {}
    if prev is None or prev.resolved_at is None:
        return {}
    resolved_at = prev.resolved_at
    if resolved_at.tzinfo is None:
        resolved_at = resolved_at.replace(tzinfo=timezone.utc)
    if (_now() - resolved_at) > timedelta(minutes=_remediation_cooldown_minutes()):
        return {}
    d = prev.detail or {}
    return {k: d[k] for k in ("attempt_counts", "last_fired_at", "remediation_failed")
            if k in d}


async def _handle_noncompliant(tenant: Tenant, device: Device, rule: Dict[str, Any],
                               finding: Dict[str, Any], master_on: bool,
                               webhooks: Dict[str, Any]) -> None:
    alert = await _active_alert(device, str(rule["id"]))
    now = _now()
    summary = str(finding.get("summary") or rule.get("name") or rule["id"])[:255]

    if alert is None:
        # First sighting: a pending alert anchors the grace period, falling through to the grace check below rather
        # than returning (grace_minutes=0 opens it immediately).
        detail0 = {"check": finding.get("detail") or {}, "summary": summary,
                   "severity_original": str(rule.get("severity"))}
        # Carry loop-protection state forward across a recent resolve and reopen, so a flapping check cannot reset the
        # attempt budget and defeat guardrail 5.
        detail0.update(await _recent_remediation_state(device, str(rule["id"])))
        alert = await Alert.create(
            tenant=tenant, device=device, rule_id=str(rule["id"]),
            severity=str(rule.get("severity")), status="pending", summary=summary,
            detail=detail0,
        )

    detail = alert.detail or {}
    detail["check"] = finding.get("detail") or {}
    detail["summary"] = summary
    alert.summary = summary

    if alert.status == "pending":
        grace = int(rule.get("grace_minutes") or 0)
        anchor = alert.first_detected_at or now
        if anchor.tzinfo is None:
            anchor = anchor.replace(tzinfo=timezone.utc)
        # Fresh timestamp: first_detected_at is stamped during create (just after now), so comparing against now would
        # go slightly negative and a grace_minutes=0 rule would never open on first sighting.
        if (_now() - anchor) >= timedelta(minutes=grace):
            alert.status = "open"
            alert.opened_at = now
            alert.detail = detail
            await alert.save(update_fields=["status", "opened_at", "detail", "summary"])
            await _fire_actions(tenant, device, rule, alert, master_on, webhooks)
        else:
            alert.detail = detail
            await alert.save(update_fields=["detail", "summary"])
    else:
        # Already open or acknowledged and still non-compliant: notifications and reversible tags are idempotent, and
        # remediations re-attempt under cooldown.
        alert.detail = detail
        await alert.save(update_fields=["detail", "summary"])
        await _fire_actions(tenant, device, rule, alert, master_on, webhooks)


async def _handle_compliant(device: Device, rule: Dict[str, Any],
                            active_pairs: Optional[Set[Tuple[str, str]]] = None) -> None:
    # Read-side filter: no active alert at sweep start means nothing to resolve, so the per-rule query is skipped. A hit
    # still re-reads before writing.
    if active_pairs is not None \
        and (str(device.id), str(rule["id"])) not in active_pairs:
        return
    alert = await _active_alert(device, str(rule["id"]))
    if alert is None:
        return
    # A pending alert never opened, so a self-heal within grace always resolves (else its stale first_detected_at
    # would let a later violation open early). Open/acknowledged alerts respect auto_resolve.
    if alert.status == "pending" or rule.get("auto_resolve"):
        await _resolve_alert(alert, device, "compliant")
    # else: leave the opened alert for a human to resolve.


async def _resolve_if_active(device: Device, rule: Dict[str, Any], reason: str,
                             active_pairs: Optional[Set[Tuple[str, str]]] = None) -> None:
    # The device left scope, so the rule no longer applies and its alert is moot whatever auto_resolve says. Resolve it
    # and undo whatever can be undone.
    if active_pairs is not None \
        and (str(device.id), str(rule["id"])) not in active_pairs:
        return
    alert = await _active_alert(device, str(rule["id"]))
    if alert is not None:
        await _resolve_alert(alert, device, reason)


async def _resolve_orphaned_alerts(tenant: Tenant, doc: Dict[str, Any],
                                   alert_rows: List[Dict[str, Any]]) -> int:
    """Resolve the alerts a retired rule left behind. Returns how many.

    Without this, retiring a rule leaves its already-raised alerts (and any tag refcount they hold) stranded, since
    every other resolve path needs the rule to still be there. Only touches alerts whose rule_id is a dispatcher
    slug (never a colon-namespaced flow/break-glass alert), and does nothing unless the document carries a rules
    key.
    """
    rules = doc.get("rules")
    if not isinstance(rules, list):
        return 0
    live: Set[str] = set()
    disabled: Set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rule_id = str(rule.get("id") or "").strip()
        if not rule_id:
            continue
        (live if rule.get("enabled", True) else disabled).add(rule_id)

    orphan_ids = [
        row["id"] for row in alert_rows
        if _DISPATCHER_RULE_ID.match(str(row.get("rule_id") or ""))
           and str(row.get("rule_id")) not in live
    ]
    if not orphan_ids:
        return 0

    orphans = await Alert.filter(id__in=orphan_ids).exclude(status="resolved").all()
    if not orphans:
        return 0
    devices = {
        str(d.id): d
        for d in await Device.filter(id__in=[a.device_id for a in orphans])
    }
    resolved = 0
    for alert in orphans:
        device = devices.get(str(alert.device_id))
        if device is None:
            continue
        reason = "rule disabled" if str(alert.rule_id) in disabled else "rule removed"
        try:
            await _resolve_alert(alert, device, reason)
            resolved += 1
        except Exception:
            logger.exception("dispatcher: could not resolve orphaned alert %s (%s) "
                             "for %s", alert.id, alert.rule_id, device.serial_number)
    if resolved:
        logger.info("dispatcher: resolved %d alert(s) for tenant %s whose rule is "
                    "no longer active", resolved, tenant.id)
    return resolved


async def _resolve_alert(alert: Alert, device: Device, reason: str) -> None:
    """Resolve an alert and reverse what can be reversed, which is the tags this alert added. A sent command is not
    undone."""
    detail = alert.detail or {}
    revert = detail.get("reversible_tags") or []
    if revert:
        # Refcount: never strip a tag that another still-active alert on this device also added, since two rules can
        # share one tag.
        try:
            others = await Alert.filter(device_id=device.id).exclude(
                status="resolved"
            ).exclude(id=alert.id).all()
            still_needed = {
                t for o in others for t in (o.detail or {}).get("reversible_tags") or []
            }
            to_remove = [t for t in revert if t not in still_needed]
            if to_remove:
                # Resolve reason travels with it, not "remove_tag", so the audit trail doesn't read as a rule decision.
                await _apply_tags(device, to_remove, add=False, rule_id=str(alert.rule_id),
                                  reason=f"alert resolved ({reason})")
        except Exception:
            logger.exception("dispatcher: reverting tags on resolve failed for %s",
                             device.serial_number)
    alert.status = "resolved"
    alert.resolved_at = _now()
    detail["resolved_reason"] = reason
    alert.detail = detail
    await alert.save(update_fields=["status", "resolved_at", "detail"])


# ==Actions==

def _notified_severity(detail: Dict[str, Any], target: str) -> Optional[str]:
    """The severity the named webhook target was last notified at.

    Stored per target so a rule with several webhook actions notifies each of them; the old one-scalar-per-alert form
    starved every target after the first. A stored scalar (a pre-map row) reads as the answer for every target, so
    upgrading does not re-notify a fleet of long-open alerts."""
    ns = detail.get("notified_severity")
    if isinstance(ns, dict):
        return ns.get(target)
    return ns


def _stamp_notified(detail: Dict[str, Any], target: str, severity: str) -> None:
    ns = detail.get("notified_severity")
    if not isinstance(ns, dict):
        ns = {}
    ns[target] = severity
    detail["notified_severity"] = ns


async def _fire_actions(tenant: Tenant, device: Device, rule: Dict[str, Any],
                        alert: Alert, master_on: bool, webhooks: Dict[str, Any]) -> None:
    detail = alert.detail or {}
    for action in rule.get("actions") or []:
        atype = action.get("type")
        params = action.get("params") or {}
        try:
            if atype == "webhook":
                # Notify on first open, and again when severity changes (an escalation after remediation failed), but
                # not on every re-evaluation. Judged per target, so each webhook action answers for its own.
                target_name = str(params.get("target") or "")
                if _notified_severity(detail, target_name) != alert.severity:
                    _spawn_webhook(tenant, device, rule, alert, webhooks.get(params.get("target")))
                    _stamp_notified(detail, target_name, alert.severity)
            elif atype == "assign_tag":
                tags = _list(params.get("tags"))
                await _apply_tags(device, tags, add=True, rule_id=str(rule.get("id")))
                bucket = detail.setdefault("reversible_tags", [])
                for t in tags:
                    if t not in bucket:
                        bucket.append(t)
            elif atype == "remove_tag":
                await _apply_tags(device, _list(params.get("tags")), add=False,
                                  rule_id=str(rule.get("id")))
            elif atype in ("install_profiles", "install_apps", "send_command"):
                await _attempt_remediation(tenant, device, rule, alert, action, master_on, detail)
        except Exception:
            logger.exception("dispatcher: action %s failed for rule %s", atype, rule.get("id"))
    # Catches an escalation from remediation above so it's notified this pass, not a full cycle later.
    for act in rule.get("actions") or []:
        if act.get("type") != "webhook":
            continue
        act_params = act.get("params") or {}
        target_name = str(act_params.get("target") or "")
        if _notified_severity(detail, target_name) != alert.severity:
            _spawn_webhook(tenant, device, rule, alert,
                           webhooks.get(act_params.get("target")))
            _stamp_notified(detail, target_name, alert.severity)
    alert.detail = await _with_fresh_vetoes(alert, detail)
    await alert.save(update_fields=["detail", "severity"])


async def _with_fresh_vetoes(alert: Alert, detail: Dict[str, Any]) -> Dict[str, Any]:
    """The detail this pass is about to write, with any admin decision recorded while it was working folded back in.

    Alert.detail is one JSON column a whole pass reads then writes, so a concurrent decision would otherwise be
    lost (a dropped decline can mean a live command going out again). Only the declined/approved lists and the
    queued requests they cover are merged in; everything else belongs to this pass. Best-effort: a failed re-read
    leaves the pass writing what it had.
    """
    try:
        fresh = await Alert.filter(id=alert.id).values_list("detail", flat=True)
    except Exception:
        logger.exception("dispatcher: re-reading alert %s before write failed", alert.id)
        return detail
    stored = (fresh[0] if fresh else None) or {}
    declined = stored.get("declined_approvals") or []
    approved = stored.get("approved_approvals") or []
    if not declined and not approved:
        return detail
    declined_keys = {d.get("action_key") for d in declined}
    # Latest approval time per key. ISO-8601 strings from one clock, so the lexicographic comparison below is a time
    # comparison.
    approved_at: Dict[Any, str] = {}
    for a in approved:
        k = a.get("action_key")
        at = str(a.get("at") or "")
        if k is not None and at >= approved_at.get(k, ""):
            approved_at[k] = at

    def _covered(pa: Dict[str, Any]) -> bool:
        key = pa.get("action_key")
        if key in declined_keys:
            return True
        at = approved_at.get(key)
        if at is None:
            return False
        # A missing requested_at reads as old: never resurrect an executed one.
        return str(pa.get("requested_at") or "") <= at

    merged = dict(detail)
    if declined:
        merged["declined_approvals"] = declined
    if approved:
        merged["approved_approvals"] = approved
    merged["pending_approvals"] = [
        pa for pa in (detail.get("pending_approvals") or []) if not _covered(pa)
    ]
    return merged


async def _attempt_remediation(tenant: Tenant, device: Device, rule: Dict[str, Any],
                               alert: Alert, action: Dict[str, Any], master_on: bool,
                               detail: Dict[str, Any]) -> None:
    """Guarded remediation. Records every decision in the alert ledger."""
    now = _now()
    akey = _action_key(action)
    atype = action["type"]
    dry = bool(action.get("dry_run"))
    counts: Dict[str, int] = detail.setdefault("attempt_counts", {})
    last_fired: Dict[str, str] = detail.setdefault("last_fired_at", {})
    ledger: List[Dict[str, Any]] = detail.setdefault("remediations", [])

    def record(outcome: str, **extra: Any) -> None:
        ledger.append({"action": atype, "at": now.isoformat(), "dry_run": dry,
                       "outcome": outcome, **extra})
        del ledger[:-50]  # cap: keep only the most recent entries (bounded growth)

    # Guardrail 2: destructive commands never run automatically, they queue for approval.
    if atype == "send_command" and (action.get("params") or {}).get("command") in DESTRUCTIVE_COMMANDS:
        cmd = (action.get("params") or {}).get("command")
        # Not asked again on this alert once declined; covers only this alert, so a later episode is a fresh question.
        if _is_declined(detail, akey):
            return
        pending = detail.setdefault("pending_approvals", [])
        if not any(pa.get("action_key") == akey for pa in pending):
            pending.append({"action_key": akey, "command": cmd,
                            "params": _redact_action_params(action),
                            "requested_at": now.isoformat()})
            record("pending-approval", command=cmd)
        return

    # Guardrail 4, the tenant and env kill switch. Skipped quietly: recording every evaluation while remediation is
    # disabled only bloats the ledger.
    if not master_on:
        return

    # Guardrail 5: stop after N attempts, escalate, and leave it to a human.
    attempts = int(counts.get(akey, 0))
    if attempts >= _remediation_max_attempts():
        if not detail.get("remediation_failed"):
            detail["remediation_failed"] = True
            new_sev = _escalate_severity(alert.severity)
            if new_sev != alert.severity:
                alert.severity = new_sev
            record(f"halted after {attempts} attempts; escalated to {alert.severity}")
        return

    # Guardrail 5: cooldown window per (device, rule, action).
    lf = last_fired.get(akey)
    if lf:
        try:
            if (now - datetime.fromisoformat(lf)) < timedelta(minutes=_remediation_cooldown_minutes()):
                return  # within cooldown; skip quietly
        except ValueError:
            pass

    # Guardrail 4: dry_run records what would happen without doing it.
    if dry:
        record("dry-run (would remediate)")
        last_fired[akey] = now.isoformat()
        counts[akey] = attempts + 1
        return

    outcome, attempted = await _run_remediation(tenant, device, rule, action)
    record(outcome)
    if not attempted:
        # Unattempted (rollout wave not open, or ids name nothing) never counts, or it would escalate on work never tried.
        return
    last_fired[akey] = now.isoformat()
    counts[akey] = attempts + 1


async def _run_remediation(tenant: Tenant, device: Device, rule: Dict[str, Any],
                           action: Dict[str, Any]) -> Tuple[str, bool]:
    """Execute a real (non-destructive, non-dry-run) remediation.

    Returns the short outcome for the ledger and whether anything was attempted (the second value gates the attempt
    counter and cooldown; see the "unattempted" note in _attempt_remediation)."""
    atype = action["type"]
    params = action.get("params") or {}
    user = f"dispatcher:{rule['id']}"

    if atype == "send_command":
        from controller.services.device_commands import (
            CommandError, dispatch_catalog_command,
        )
        try:
            outcome = await dispatch_catalog_command(
                device, str(params.get("command")), params.get("params") or {},
                user=user, tenant=tenant, allow_destructive=False,
            )
            return f"sent {params.get('command')} (task {outcome['task_id']})", True
        except CommandError as exc:
            # A refused command counts as an attempt: the rule asked, the command path answered, and asking again on
            # every sweep is what the counter stops.
            return f"send failed: {exc}", True

    if atype == "install_profiles":
        n = await _queue_profile_installs(tenant, device, _list(params.get("profile_ids")),
                                          user, str(rule["id"]))
        return f"queued {n} profile install(s)", n > 0

    if atype == "install_apps":
        n = await _queue_app_installs(tenant, device, _list(params.get("app_ids")),
                                      user, str(rule["id"]))
        return f"queued {n} app install(s)", n > 0

    return "no-op", False


async def _queue_profile_installs(tenant: Tenant, device: Device,
                                  profile_ids: List[str], user: str,
                                  rule_id: str) -> int:
    """Queue the profile installs a compliance rule asked for.

    Every task is marked with profile_manager.INSTALL_SOURCE_KEY so the sync loop never takes a remediation profile
    straight back off the device; the mark persists as long as the rule exists. See
    docs/controller/services/dispatcher.md and reconciler._held_by_remediation.
    """
    from controller.services.profile_manager import (
        INSTALL_SOURCE_KEY, ProfileManager, remediation_source,
    )
    from controller.services.reconciler import _spawn
    from controller.services.task_handlers import handle_profile_install_task
    from controller.services.task_manager import TaskManager

    # Copying loader required: this dict is hashed, redacted and handed to a spawned handler, so a shared load
    # would leave this remediation's work on a cache entry every other reader sees.
    profiles = tenant_config._load(str(tenant.id), "profiles.yaml").get("profiles", [])
    by_id = {p.get("id"): p for p in profiles if isinstance(p, dict)}
    tm = TaskManager()
    queued = 0
    for pid in profile_ids:
        info = by_id.get(pid)
        if not info:
            continue
        task = await tm.create_task(
            tenant=tenant, task_type="profile_install",
            description=f"Dispatcher remediation: install profile {info.get('name', pid)}",
            device=device, user=user,
            # Redacted: a profile definition can hold the Wi-Fi PSK, 802.1X password, SCEP challenge (see
            # ProfileManager.install_task_details); the audit row must not keep the real values.
            details={**ProfileManager.install_task_details(
                info, ProfileManager.desired_hash(info)),
                     INSTALL_SOURCE_KEY: remediation_source(rule_id)},
        )
        # Bind device/tenant/definition directly; without them the handler re-reads both rows (see
        # task_handlers._resolve_device_tenant).
        _spawn(tm.execute_task(
            task, partial(handle_profile_install_task, device=device, tenant=tenant,
                          profile_info=info),
        ))
        queued += 1
    return queued


def _remediable_version(device: Device, app: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The version of an authored app a remediation may install on this device, in the form an app install task carries,
    or None when there is not one.

    Walks versions newest-first (stored oldest-first) like AppManager._get_applicable_version, but skips scope: a
    remediation is for reaching a device the app's own scope does not. Rollout waves are still honoured. See
    docs/controller/services/dispatcher.md.
    """
    for version in reversed(app.get("versions") or []):
        if not isinstance(version, dict):
            continue
        rollout = version.get("rollout")
        if rollout and not device_in_rollout(
            device, rollout, f"app:{app.get('id')}:{version.get('version')}"
        ):
            continue
        info = {
            "app_id": app.get("id"),
            "name": app.get("name"),
            "bundle_id": app.get("bundle_id"),
            "version": version.get("version"),
            "s3_key": version.get("s3_key"),
            "sha256": version.get("sha256"),
            "install_options": version.get("install_options", {}),
        }
        # Only carried when authored explicitly: an authored False must not be dropped, or the Mac refuses the
        # install with "No install paths present".
        if "install_as_managed" in app:
            info["install_as_managed"] = app["install_as_managed"]
        return info
    return None


async def _queue_app_installs(tenant: Tenant, device: Device,
                              app_ids: List[str], user: str,
                              rule_id: str) -> int:
    """Queue the app installs a compliance rule asked for.

    The app half of _queue_profile_installs, marked the same way so the sync loop does not retire a remediation
    install. Looked up in apps.yaml by id, never through the reconciler's scope-filtered pass (that would be a
    silent no-op for the one case this serves).
    """
    from controller.services.profile_manager import (
        INSTALL_SOURCE_KEY, remediation_source,
    )
    from controller.services.reconciler import _spawn
    from controller.services.task_handlers import handle_app_install_task
    from controller.services.task_manager import TaskManager

    # The copying loader is required here: the version's install_options is carried by reference into the dict below,
    # which is stored into Task.details.
    apps_config = tenant_config._load(str(tenant.id), "apps.yaml").get("apps", [])
    by_id = {a.get("id"): a for a in apps_config if isinstance(a, dict)}
    tm = TaskManager()
    queued = 0
    for aid in app_ids:
        app = by_id.get(aid)
        if not app:
            logger.warning("dispatcher: rule %s asked to install app '%s', which is "
                           "not in apps.yaml", rule_id, aid)
            continue
        info = _remediable_version(device, app)
        if info is None:
            logger.info("dispatcher: rule %s did not queue app '%s' for %s: no "
                        "version is released to this device yet", rule_id, aid,
                        device.serial_number)
            continue
        task = await tm.create_task(
            tenant=tenant, task_type="app_install",
            description=f"Dispatcher remediation: install {info.get('name', aid)}",
            device=device, user=user,
            details={"app_info": info,
                     INSTALL_SOURCE_KEY: remediation_source(rule_id)},
        )
        _spawn(tm.execute_task(
            task, partial(handle_app_install_task, device=device, tenant=tenant),
        ))
        queued += 1
    return queued


# ==Tags (additive/idempotent, mirrors the manual endpoint)==

async def _apply_tags(device: Device, tags: List[str], *, add: bool,
                      rule_id: Optional[str] = None, reason: Optional[str] = None) -> None:
    tags = _list(tags)
    if not tags:
        return
    current = [str(t) for t in (device.tags or [])]
    before = set(current)
    if add:
        result = current + [t for t in tags if t not in before]
    else:
        drop = set(tags)
        result = [t for t in current if t not in drop]
    if set(result) == before:
        return
    device.tags = result
    await device.save(update_fields=["tags"])
    from controller.services.audit import record_tag_change
    await record_tag_change(device, added=sorted(set(result) - before),
                            removed=sorted(before - set(result)),
                            source="dispatcher", source_ref=rule_id, reason=reason)
    # Recompute groups (tags can drive membership) and reconcile scoping.
    try:
        from controller.services.group_manager import GroupManager
        groups_before = set(device.groups or [])
        device.groups = GroupManager(str(device.tenant_id)).evaluate_device_groups(
            device, tenant_config.load_groups(str(device.tenant_id))
        )
        if set(device.groups or []) != groups_before:
            await device.save(update_fields=["groups"])
    except Exception:
        logger.exception("dispatcher: group recompute after tag change failed for %s",
                         device.serial_number)
    _spawn_reconcile(str(device.tenant_id))


def _spawn_reconcile(tenant_id: str) -> None:
    """Ask for a reconcile after a tag write, coalesced per tenant."""
    try:
        from controller.services.reconciler import request_reconcile
        request_reconcile(tenant_id)
    except Exception:
        logger.exception("dispatcher: scheduling reconcile failed for %s", tenant_id)


# ==Webhook notifications (signed, best-effort, bounded retry)==

def _redact_action_params(action: Dict[str, Any]) -> Dict[str, Any]:
    """A copy of a send_command action's params for the alert ledger, with the known-secret ones dropped. No secret is
    ever persisted to an alert."""
    params = (action.get("params") or {}).get("params") or {}
    from controller.services.command_catalog import get_command, secret_param_names
    entry = get_command((action.get("params") or {}).get("command")) or {}
    secret = secret_param_names(entry) | {"pin"}
    return {k: v for k, v in params.items() if k not in secret}


def _webhook_payload(tenant: Tenant, device: Device, rule: Dict[str, Any],
                     alert: Alert) -> Dict[str, Any]:
    return {
        "tenant": str(tenant.id),
        "device": {"id": str(device.id), "serial": device.serial_number, "name": device.name},
        "rule_id": str(rule.get("id")),
        "severity": alert.severity,
        "summary": alert.summary,
        "detail": (alert.detail or {}).get("check") or {},
        "status": alert.status,
        "timestamp": _now().isoformat(),
    }


def _spawn_webhook(tenant: Tenant, device: Device, rule: Dict[str, Any],
                   alert: Alert, target: Optional[Dict[str, Any]]) -> None:
    """Send the webhook in the background so delivery never blocks evaluation."""
    if not target or not target.get("url"):
        return
    payload = _webhook_payload(tenant, device, rule, alert)
    url = str(target.get("url"))
    secret = target.get("secret")
    try:
        from controller.services.reconciler import _spawn
        _spawn(_deliver_webhook(url, secret, payload, str(rule.get("id"))))
    except Exception:
        logger.exception("dispatcher: scheduling webhook failed for rule %s", rule.get("id"))


def _private_webhook_allowlist() -> Tuple[Set[str], List[Any]]:
    """DISPATCHER_WEBHOOK_PRIVATE_ALLOWLIST, parsed fresh per call so a change takes effect without a restart.
    Comma-separated IP/CIDR/hostname entries; returns (lowercased hostnames, parsed networks)."""
    import ipaddress
    hosts: Set[str] = set()
    nets: List[Any] = []
    for item in (os.getenv("DISPATCHER_WEBHOOK_PRIVATE_ALLOWLIST") or "").split(","):
        item = item.strip().lower()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            hosts.add(item)
    return hosts, nets


async def _webhook_target_blocked(url: str) -> bool:
    """SSRF guard: resolve the webhook host and refuse a private, loopback, link-local (including the cloud metadata
    address 169.254.169.254), reserved, or otherwise non-public address. Fails closed on any parse/resolution error.
    Internal collectors go in DISPATCHER_WEBHOOK_PRIVATE_ALLOWLIST; DISPATCHER_WEBHOOK_ALLOW_PRIVATE is a deprecated
    global bypass."""
    import asyncio
    import ipaddress
    import socket
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return True
        if _truthy(os.getenv("DISPATCHER_WEBHOOK_ALLOW_PRIVATE", "false")):
            if ("DISPATCHER_WEBHOOK_ALLOW_PRIVATE", "deprecated") not in _ENV_WARNED:
                _ENV_WARNED.add(("DISPATCHER_WEBHOOK_ALLOW_PRIVATE", "deprecated"))
                logger.warning(
                    "DISPATCHER_WEBHOOK_ALLOW_PRIVATE disables the webhook SSRF "
                    "guard for every tenant and is deprecated; list the internal "
                    "destinations in DISPATCHER_WEBHOOK_PRIVATE_ALLOWLIST instead")
            return False
        allowed_hosts, allowed_nets = _private_webhook_allowlist()
        host_allowed = parsed.hostname.lower() in allowed_hosts
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(parsed.hostname, port, proto=socket.IPPROTO_TCP)
        if not infos:
            return True
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
                if host_allowed or any(ip in net for net in allowed_nets):
                    continue
                return True
        return False
    except Exception:
        return True


async def _deliver_webhook(url: str, secret: Optional[str], payload: Dict[str, Any],
                           rule_id: str) -> None:
    import asyncio

    import httpx

    if await _webhook_target_blocked(url):
        logger.error("dispatcher webhook for rule %s blocked: non-public/invalid target",
                     rule_id)
        return

    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if secret:
        sig = hmac.new(str(secret).encode("utf-8"), body, hashlib.sha256).hexdigest()
        headers["X-Micromanage-Signature"] = f"sha256={sig}"

    # Read once for the whole sequence, so the attempt number and the bound in the log lines below cannot come from two
    # different readings of the setting.
    max_attempts = _webhook_max_attempts()
    # One client for the whole retry sequence, so a retry reuses the connection (and the TLS handshake) the first
    # attempt already paid for.
    async with httpx.AsyncClient(timeout=_webhook_timeout_seconds()) as client:
        for attempt in range(1, max_attempts + 1):
            try:
                resp = await client.post(url, content=body, headers=headers)
                if resp.status_code < 400:
                    return
                # Never log the url; it can be a secret in its own right, as a Slack hook is.
                logger.warning("dispatcher webhook for rule %s got HTTP %s (attempt %d/%d)",
                               rule_id, resp.status_code, attempt, max_attempts)
            except Exception as exc:
                logger.warning("dispatcher webhook for rule %s failed (attempt %d/%d): %s",
                               rule_id, attempt, max_attempts, type(exc).__name__)
            if attempt < max_attempts:
                await asyncio.sleep(min(2 ** attempt, 30))
    logger.error("dispatcher webhook for rule %s gave up after %d attempts",
                 rule_id, max_attempts)


# ==Admin-approved destructive remediation (from the API)==

# Retries for a conditional detail write before the caller gives up.
_DETAIL_WRITE_ATTEMPTS = 5


async def _claim_pending_approval(alert: Alert, action_key: str) -> Dict[str, Any]:
    """Atomically take one queued approval off the alert, or raise ValueError.

    Fresh read + conditional update keyed on updated_at each attempt, so exactly one of two concurrent approvals
    claims the entry, and a decline recorded in between is honoured too."""
    for _ in range(_DETAIL_WRITE_ATTEMPTS):
        fresh = await Alert.get_or_none(id=alert.id)
        if fresh is None:
            raise ValueError("Alert no longer exists")
        detail = fresh.detail or {}
        if _is_declined(detail, action_key):
            raise ValueError("This remediation was declined and can no longer be approved")
        pending = detail.get("pending_approvals") or []
        entry = next((pa for pa in pending if pa.get("action_key") == action_key), None)
        if entry is None:
            raise ValueError("No such pending remediation on this alert")
        detail["pending_approvals"] = [pa for pa in pending
                                       if pa.get("action_key") != action_key]
        claimed = await Alert.filter(id=alert.id, updated_at=fresh.updated_at).update(
            detail=detail, updated_at=_now())
        if claimed:
            return entry
    raise ValueError("The alert is being updated concurrently; try again")


async def _record_approval_outcome(alert: Alert, action_key: str, command: str,
                                   outcome: str, approver: str) -> None:
    """Write an executed approval to the alert with a fresh read-modify-write.

    Appends to the remediations ledger and to approved_approvals, the list _with_fresh_vetoes reads so an evaluation
    pass running during the dispatch cannot resurrect the entry the claim removed. Best-effort past the claim: losing
    this write loses a ledger line, never the once-only guard."""
    now_iso = _now().isoformat()
    for _ in range(_DETAIL_WRITE_ATTEMPTS):
        fresh = await Alert.get_or_none(id=alert.id)
        if fresh is None:
            return
        detail = fresh.detail or {}
        approved = detail.setdefault("approved_approvals", [])
        approved.append({"action_key": action_key, "command": command,
                         "at": now_iso, "approved_by": approver})
        del approved[:-50]  # same cap as the ledger: bounded growth
        ledger = detail.setdefault("remediations", [])
        ledger.append({"action": "send_command", "at": now_iso, "dry_run": False,
                       "outcome": outcome, "approved_by": approver,
                       "action_key": action_key, "command": command})
        del ledger[:-50]
        done = await Alert.filter(id=alert.id, updated_at=fresh.updated_at).update(
            detail=detail, updated_at=_now())
        if done:
            return
    logger.warning("dispatcher: alert %s was rewritten on every attempt to record "
                   "an approval outcome; the ledger line was dropped", alert.id)


async def approve_remediation(alert: Alert, action_key: str, approver: str) -> Dict[str, Any]:
    """Execute a queued destructive remediation after an admin approves it.

    Runs through the same audited command path with allow_destructive=True and records the outcome. Raises
    ValueError when the approval is not found. The pending entry is claimed atomically first
    (_claim_pending_approval), since the caller's in-memory alert can be stale; see
    docs/controller/services/dispatcher.md."""
    tenant = await Tenant.get_or_none(id=alert.tenant_id)
    device = await Device.get_or_none(id=alert.device_id)
    if tenant is None or device is None:
        raise ValueError("Alert device/tenant no longer exists")

    # Re-derived from dispatcher.yaml, not trusted from the client: real command params/secrets never leave disk.
    doc = _load_dispatcher(str(tenant.id))
    rule = next((r for r in (doc.get("rules") or [])
                 if isinstance(r, dict) and str(r.get("id")) == alert.rule_id), None)
    action = None
    if rule:
        for a in rule.get("actions") or []:
            if a.get("type") == "send_command" and _action_key(a) == action_key:
                action = a
                break
    if action is None:
        raise ValueError("The approved remediation is no longer defined in dispatcher.yaml")
    params = action.get("params") or {}
    command = str(params.get("command"))
    if command not in DESTRUCTIVE_COMMANDS:
        raise ValueError("Only a destructive remediation requires approval")

    # Claim first, dispatch second: once the conditional write lands, no other approval of the same entry can reach the
    # command path.
    await _claim_pending_approval(alert, action_key)

    from controller.services.device_commands import CommandError, dispatch_catalog_command
    outcome_str: str
    try:
        outcome = await dispatch_catalog_command(
            device, command, params.get("params") or {},
            user=f"dispatcher:{alert.rule_id} (approved by {approver})",
            tenant=tenant, allow_destructive=True,
        )
        outcome_str = f"approved + sent {command} (task {outcome['task_id']})"
    except CommandError as exc:
        outcome_str = f"approved but send failed: {exc}"

    await _record_approval_outcome(alert, action_key, command, outcome_str, approver)
    # The caller's object predates the claim; give it the row that was written.
    try:
        await alert.refresh_from_db()
    except Exception:
        logger.exception("dispatcher: refreshing alert %s after approval failed", alert.id)
    return {"outcome": outcome_str}


def _is_declined(detail: Dict[str, Any], action_key: str) -> bool:
    """Whether an admin already refused this queued remediation on this alert."""
    return any(d.get("action_key") == action_key
               for d in (detail.get("declined_approvals") or []))


async def reject_remediation(alert: Alert, action_key: str, rejector: str,
                             reason: Optional[str] = None) -> Dict[str, Any]:
    """Decline a queued destructive remediation, the counterpart of approve_remediation and the narrower of the two.

    Drops the entry from pending_approvals, ledgers the refusal, and remembers it so the next evaluation does not
    queue it again; the alert itself stays open and untouched otherwise, since no command was ever sent. Raises
    ValueError when the key names no queued remediation on this alert.
    """
    # Re-read before deciding: the alert handed in is milliseconds old, and a sweep evaluating this device in the
    # meantime rewrites the whole detail column.
    await alert.refresh_from_db()
    detail = alert.detail or {}
    pending = detail.get("pending_approvals") or []
    entry = next((pa for pa in pending if pa.get("action_key") == action_key), None)
    if entry is None:
        raise ValueError("No such pending remediation on this alert")

    command = entry.get("command")
    outcome_str = f"declined by {rejector}"
    if reason:
        outcome_str += f": {reason}"

    detail["pending_approvals"] = [pa for pa in pending
                                   if pa.get("action_key") != action_key]
    declined = detail.setdefault("declined_approvals", [])
    declined.append({"action_key": action_key, "command": command,
                     "at": _now().isoformat(), "declined_by": rejector,
                     **({"reason": reason} if reason else {})})
    del declined[:-50]  # same cap as the ledger: bounded growth on a JSON column
    ledger = detail.setdefault("remediations", [])
    ledger.append({
        "action": "send_command", "at": _now().isoformat(), "dry_run": False,
        "outcome": outcome_str, "command": command, "declined_by": rejector,
        **({"reason": reason} if reason else {}),
    })
    del ledger[:-50]  # the cap the sweep's own record() applies
    alert.detail = detail
    await alert.save(update_fields=["detail"])
    logger.info("dispatcher: %s declined the queued %s on alert %s",
                rejector, command, alert.id)
    return {"outcome": outcome_str, "command": command}
