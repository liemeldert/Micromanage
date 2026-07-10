"""Dispatcher: compliance rules engine + alerting + guarded auto-remediation.

Rules (dispatcher.yaml, validated by utils.yaml_validator) are declarative:
``when (scope + compliance check) is violated -> raise a severity-ranked alert
-> optionally notify (in-app + signed webhook) -> optionally auto-remediate``.
Evaluated continuously against ALREADY-OBSERVED device state (the engine never
issues its own device queries). Alerts have a lifecycle and auto-resolve when the
device becomes compliant again.

Auto-remediation is the high-risk surface; every guardrail from the spec is
enforced here (see _attempt_remediation):
  1. Off by default -- only actions explicitly present in a rule fire.
  2. Destructive commands NEVER auto-fire -- they become a pending-approval task
     an admin must confirm in the UI (also blocked in device_commands).
  3. Remediation reuses the SAME audited command path (device_commands), run as
     user "dispatcher:<rule>".
  4. dry_run per action + a tenant/env kill-switch disable remediation.
  5. Cooldown + N-attempts-then-escalate loop protection (tracked in Alert.detail).
  6. Everything is visible: a Task per real remediation + a ledger in Alert.detail.

Every entry point is best-effort/defensive: they run on the webhook + sweep
paths, so a bad rule fails only that rule and never breaks evaluation.
"""

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from controller.auth import DESTRUCTIVE_COMMANDS
from controller.models.tenant import (
    Alert,
    AppDeployment,
    Device,
    ProfileDeployment,
    Tenant,
)
from controller.services import tenant_config
from controller.services.compliance_catalog import evaluate_check
from controller.services.scoping import evaluate_scope

logger = logging.getLogger(__name__)

# Board ranking: higher is more severe (black > red > yellow > green).
SEVERITY_RANK = {"green": 1, "yellow": 2, "red": 3, "black": 4}
_ESCALATE = {"green": "yellow", "yellow": "red", "red": "black", "black": "black"}

REMEDIATION_COOLDOWN_MINUTES = int(os.getenv("DISPATCHER_REMEDIATION_COOLDOWN_MINUTES", "60"))
REMEDIATION_MAX_ATTEMPTS = int(os.getenv("DISPATCHER_REMEDIATION_MAX_ATTEMPTS", "3"))
WEBHOOK_TIMEOUT_SECONDS = float(os.getenv("DISPATCHER_WEBHOOK_TIMEOUT_SECONDS", "10"))
WEBHOOK_MAX_ATTEMPTS = int(os.getenv("DISPATCHER_WEBHOOK_MAX_ATTEMPTS", "3"))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _truthy(v: Any) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on") if v is not None else False


def _load_dispatcher(tenant_id: str) -> Dict[str, Any]:
    doc = tenant_config._load(tenant_id, "dispatcher.yaml")
    return doc if isinstance(doc, dict) else {}


def _auto_remediation_enabled(doc: Dict[str, Any]) -> bool:
    """Effective kill-switch: the env master switch AND the per-document switch
    (either set to false disables ALL remediation for the tenant)."""
    env_on = _truthy(os.getenv("DISPATCHER_AUTO_REMEDIATION_ENABLED", "true"))
    doc_on = doc.get("auto_remediation_enabled", True) is not False
    return env_on and doc_on


def _scope_matches(device: Device, device_groups: List[str], scope: Optional[Dict[str, Any]]) -> bool:
    """An empty scope matches every device (spec: 'Empty => all'); otherwise the
    unified scope engine decides."""
    scope = scope or {}
    if not any(scope.get(k) for k in
               ("groups", "conditions", "include_devices", "exclude_devices")):
        return True
    return evaluate_scope(device, device_groups, scope)


def _list(v: Any) -> List[str]:
    items = v if isinstance(v, list) else ([v] if v else [])
    return [str(x) for x in items if x]


def _action_key(action: Dict[str, Any]) -> str:
    """A stable, SECRET-FREE identifier for an action (used for cooldown/attempt
    tracking AND as the approval key stored in Alert.detail). Secret command
    params are stripped so the key can be exposed via the API without leaking a
    wipe PIN / password. The real (possibly-secret) params live only in
    dispatcher.yaml and are re-derived at approval time."""
    params = dict(action.get("params") or {})
    if action.get("type") == "send_command":
        from controller.services.command_catalog import get_command, secret_param_names
        entry = get_command(params.get("command")) or {}
        secret = secret_param_names(entry) | {"pin"}
        inner = {k: v for k, v in (params.get("params") or {}).items() if k not in secret}
        params = {**params, "params": inner}
    return json.dumps({"type": action.get("type"), "params": params},
                      sort_keys=True, default=str)


# ── Entry points ─────────────────────────────────────────────────────────────

async def evaluate_device(device: Device, reason: str = "event") -> None:
    """Evaluate every enabled rule for a device and reconcile its alerts.
    Best-effort: never raises into the caller (webhook / sweep hot paths)."""
    try:
        tenant = await Tenant.get_or_none(id=device.tenant_id)
        if tenant is None:
            return
        doc = _load_dispatcher(str(tenant.id))
        rules = doc.get("rules") or []
        if not rules:
            return
        master_on = _auto_remediation_enabled(doc)
        webhooks = {w.get("name"): w for w in (doc.get("webhooks") or []) if isinstance(w, dict)}
        ctx = await _build_ctx(device, tenant, rules)
        device_groups = list(device.groups or [])

        for rule in rules:
            try:
                if not isinstance(rule, dict) or not rule.get("enabled", True):
                    continue
                if not _scope_matches(device, device_groups, rule.get("scope")):
                    # Left the rule's scope -> its alert (if any) no longer applies.
                    await _resolve_if_active(device, rule, "out of scope")
                    continue
                finding = evaluate_check(rule.get("check") or {}, device, ctx)
                if finding:
                    await _handle_noncompliant(tenant, device, rule, finding, master_on, webhooks)
                else:
                    await _handle_compliant(device, rule)
            except Exception:
                logger.exception("dispatcher: rule %s failed for %s",
                                 (rule or {}).get("id"), device.serial_number)
    except Exception:
        logger.exception("dispatcher: evaluate_device failed for %s",
                         getattr(device, "serial_number", "?"))


async def sweep(tenant: Tenant) -> int:
    """Re-evaluate every enrolled device for a tenant. Covers time-based checks
    (not_seen_for), grace-period expiry (pending->open) and remediation
    cooldown/re-attempts. Returns the device count evaluated."""
    try:
        doc = _load_dispatcher(str(tenant.id))
        if not (doc.get("rules") or []):
            return 0
        devices = await Device.filter(tenant=tenant, enrollment_state="enrolled").all()
    except Exception:
        logger.exception("dispatcher: sweep query failed for tenant %s", tenant.id)
        return 0
    for device in devices:
        try:
            await evaluate_device(device, reason="sweep")
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


# ── Context (drift signal, read from deployment tables -- no new queries) ─────

async def _build_ctx(device: Device, tenant: Tenant, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {}
    check_types = {
        (r.get("check") or {}).get("type") for r in rules if isinstance(r, dict)
    }
    # Only touch the deployment tables when a rule actually reads them, so the
    # common case (security/posture checks) adds no DB work on the webhook path.
    if not (check_types & {"missing_profile", "config_drift"}):
        return ctx
    try:
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
        groups_config = tenant_config.load_groups(str(tenant.id))
        desired, _held = await ProfileManager(tenant).evaluate_device_profiles(
            device, profiles_config, groups_config
        )
        status = ctx["profile_status"]
        for p in desired:
            if status.get(p["id"]) != "installed":
                drift.append({"profile": p["id"], "status": status.get(p["id"])})
        for pd in pds:
            if pd.status == "failed":
                drift.append({"profile": pd.profile_id, "status": "failed"})
        for ad in await AppDeployment.filter(device=device, status="failed").all():
            drift.append({"app": ad.app_id, "status": "failed"})
    except Exception:
        logger.exception("dispatcher: drift computation failed for %s", device.serial_number)
    ctx["drift"] = drift
    return ctx


# ── Alert lifecycle ──────────────────────────────────────────────────────────

async def _active_alert(device: Device, rule_id: str) -> Optional[Alert]:
    """The single active (non-resolved) alert for a (device, rule).

    We enforce 'at most one' in code, not with a DB constraint (resolved rows
    accumulate). evaluate_device can run concurrently on the webhook and sweep
    paths and briefly create duplicates; self-heal by keeping the OLDEST active
    row and resolving any extras, so the invariant reconverges every evaluation."""
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
    """Loop-protection counters from the most-recently resolved alert for this
    (device, rule) IF it resolved within the cooldown window -- so a rapid
    resolve->reopen flap keeps accumulating attempts instead of resetting to 0,
    while a device compliant for longer than the cooldown gets a fresh budget."""
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
    if (_now() - resolved_at) > timedelta(minutes=REMEDIATION_COOLDOWN_MINUTES):
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
        # First sighting: a 'pending' alert anchors the grace period. It opens
        # (and fires actions) once non-compliant continuously for grace_minutes
        # -- which, for grace_minutes=0, is immediately (handled by the grace
        # check below, so we fall through rather than returning here).
        detail0 = {"check": finding.get("detail") or {}, "summary": summary,
                   "severity_original": str(rule.get("severity"))}
        # Carry loop-protection state forward across a recent resolve->reopen so a
        # flapping check can't reset the attempt budget and defeat guardrail 5.
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
        # Fresh timestamp: first_detected_at is stamped during create (just after
        # `now`), so comparing against `now` would go slightly negative and a
        # grace_minutes=0 rule would never open on first sighting.
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
        # Already open/acknowledged and still non-compliant: notifications and
        # reversible tags are idempotent; remediations re-attempt under cooldown.
        alert.detail = detail
        await alert.save(update_fields=["detail", "summary"])
        await _fire_actions(tenant, device, rule, alert, master_on, webhooks)


async def _handle_compliant(device: Device, rule: Dict[str, Any]) -> None:
    alert = await _active_alert(device, str(rule["id"]))
    if alert is None:
        return
    # A 'pending' alert never opened (no actions fired, nothing for a human to
    # see), so a violation that self-heals within grace must always resolve --
    # otherwise its stale first_detected_at anchor lets a later violation open
    # early (broken anti-flap). Opened/acknowledged alerts respect auto_resolve.
    if alert.status == "pending" or rule.get("auto_resolve"):
        await _resolve_alert(alert, device, "compliant")
    # else: leave the opened alert for a human to resolve.


async def _resolve_if_active(device: Device, rule: Dict[str, Any], reason: str) -> None:
    # The rule no longer applies to this device (left scope), so its alert is
    # moot regardless of auto_resolve -- resolve unconditionally and reverse any
    # reversible actions it took.
    alert = await _active_alert(device, str(rule["id"]))
    if alert is not None:
        await _resolve_alert(alert, device, reason)


async def _resolve_alert(alert: Alert, device: Device, reason: str) -> None:
    """Resolve an alert and reverse the reversible actions it took (remove the
    tags this alert added). Non-reversible actions (a sent command) are not undone."""
    detail = alert.detail or {}
    revert = detail.get("reversible_tags") or []
    if revert:
        # Refcount: don't strip a tag that another still-active alert on this
        # device also added (two rules can share a 'noncompliant' tag).
        try:
            others = await Alert.filter(device_id=device.id).exclude(
                status="resolved"
            ).exclude(id=alert.id).all()
            still_needed = {
                t for o in others for t in (o.detail or {}).get("reversible_tags") or []
            }
            to_remove = [t for t in revert if t not in still_needed]
            if to_remove:
                await _apply_tags(device, to_remove, add=False)
        except Exception:
            logger.exception("dispatcher: reverting tags on resolve failed for %s",
                             device.serial_number)
    alert.status = "resolved"
    alert.resolved_at = _now()
    detail["resolved_reason"] = reason
    alert.detail = detail
    await alert.save(update_fields=["status", "resolved_at", "detail"])


# ── Actions ──────────────────────────────────────────────────────────────────

async def _fire_actions(tenant: Tenant, device: Device, rule: Dict[str, Any],
                       alert: Alert, master_on: bool, webhooks: Dict[str, Any]) -> None:
    detail = alert.detail or {}
    for action in rule.get("actions") or []:
        atype = action.get("type")
        params = action.get("params") or {}
        try:
            if atype == "webhook":
                # Notify on first open, and again whenever severity changes (an
                # escalation after failed remediation) -- but not on every re-eval.
                if detail.get("notified_severity") != alert.severity:
                    _spawn_webhook(tenant, device, rule, alert, webhooks.get(params.get("target")))
                    detail["notified_severity"] = alert.severity
            elif atype == "assign_tag":
                tags = _list(params.get("tags"))
                await _apply_tags(device, tags, add=True)
                bucket = detail.setdefault("reversible_tags", [])
                for t in tags:
                    if t not in bucket:
                        bucket.append(t)
            elif atype == "remove_tag":
                await _apply_tags(device, _list(params.get("tags")), add=False)
            elif atype in ("install_profiles", "install_apps", "send_command"):
                await _attempt_remediation(tenant, device, rule, alert, action, master_on, detail)
        except Exception:
            logger.exception("dispatcher: action %s failed for rule %s", atype, rule.get("id"))
    # If a remediation escalated severity after the webhook action already ran
    # this pass, notify now so the escalation isn't delayed a full cycle (D4).
    if detail.get("notified_severity") != alert.severity:
        for act in rule.get("actions") or []:
            if act.get("type") == "webhook":
                _spawn_webhook(tenant, device, rule, alert,
                               webhooks.get((act.get("params") or {}).get("target")))
                detail["notified_severity"] = alert.severity
                break
    alert.detail = detail
    await alert.save(update_fields=["detail", "severity"])


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

    # Guardrail 2: destructive commands NEVER auto-fire -> queue for admin approval.
    if atype == "send_command" and (action.get("params") or {}).get("command") in DESTRUCTIVE_COMMANDS:
        cmd = (action.get("params") or {}).get("command")
        pending = detail.setdefault("pending_approvals", [])
        if not any(pa.get("action_key") == akey for pa in pending):
            pending.append({"action_key": akey, "command": cmd,
                            "params": _redact_action_params(action),
                            "requested_at": now.isoformat()})
            record("pending-approval", command=cmd)
        return

    # Guardrail 4: tenant/env kill-switch. Skip quietly -- recording every eval
    # while disabled just bloats the ledger; the state is derivable from config.
    if not master_on:
        return

    # Guardrail 5: stop after N attempts; escalate and require a human.
    attempts = int(counts.get(akey, 0))
    if attempts >= REMEDIATION_MAX_ATTEMPTS:
        if not detail.get("remediation_failed"):
            detail["remediation_failed"] = True
            new_sev = _ESCALATE.get(alert.severity, alert.severity)
            if new_sev != alert.severity:
                alert.severity = new_sev
            record(f"halted after {attempts} attempts; escalated to {alert.severity}")
        return

    # Guardrail 5: cooldown window per (device, rule, action).
    lf = last_fired.get(akey)
    if lf:
        try:
            if (now - datetime.fromisoformat(lf)) < timedelta(minutes=REMEDIATION_COOLDOWN_MINUTES):
                return  # within cooldown; skip quietly
        except ValueError:
            pass

    # Guardrail 4: dry_run records what WOULD happen without doing it.
    if dry:
        record("dry-run (would remediate)")
        last_fired[akey] = now.isoformat()
        counts[akey] = attempts + 1
        return

    outcome = await _run_remediation(tenant, device, rule, action)
    record(outcome)
    last_fired[akey] = now.isoformat()
    counts[akey] = attempts + 1


async def _run_remediation(tenant: Tenant, device: Device, rule: Dict[str, Any],
                          action: Dict[str, Any]) -> str:
    """Execute a real (non-destructive, non-dry-run) remediation. Every path
    produces an audited Task. Returns a short outcome for the ledger."""
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
            return f"sent {params.get('command')} (task {outcome['task_id']})"
        except CommandError as exc:
            return f"send failed: {exc}"

    if atype == "install_profiles":
        n = await _queue_profile_installs(tenant, device, _list(params.get("profile_ids")), user)
        return f"queued {n} profile install(s)"

    if atype == "install_apps":
        n = await _queue_app_installs(tenant, device, _list(params.get("app_ids")), user)
        return f"queued {n} app install(s)"

    return "no-op"


async def _queue_profile_installs(tenant: Tenant, device: Device,
                                 profile_ids: List[str], user: str) -> int:
    from controller.services.reconciler import _spawn
    from controller.services.task_handlers import handle_profile_install_task
    from controller.services.task_manager import TaskManager

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
            device=device, user=user, details={"profile_info": info},
        )
        _spawn(tm.execute_task(task, handle_profile_install_task))
        queued += 1
    return queued


async def _queue_app_installs(tenant: Tenant, device: Device,
                             app_ids: List[str], user: str) -> int:
    from controller.services.app_manager import AppManager
    from controller.services.reconciler import _spawn
    from controller.services.task_handlers import handle_app_install_task
    from controller.services.task_manager import TaskManager

    apps_config = tenant_config._load(str(tenant.id), "apps.yaml").get("apps", [])
    groups_config = tenant_config.load_groups(str(tenant.id))
    try:
        applicable = await AppManager(tenant).evaluate_device_apps(device, apps_config, groups_config)
    except Exception:
        logger.exception("dispatcher: evaluating apps failed for %s", device.serial_number)
        applicable = []
    by_id = {a["app_id"]: a for a in applicable}
    tm = TaskManager()
    queued = 0
    for aid in app_ids:
        info = by_id.get(aid)
        if not info:
            continue
        task = await tm.create_task(
            tenant=tenant, task_type="app_install",
            description=f"Dispatcher remediation: install {info.get('name', aid)}",
            device=device, user=user, details={"app_info": info},
        )
        _spawn(tm.execute_task(task, handle_app_install_task))
        queued += 1
    return queued


# ── Tags (additive/idempotent, mirrors the manual endpoint) ──────────────────

async def _apply_tags(device: Device, tags: List[str], *, add: bool) -> None:
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
    try:
        from controller.services.reconciler import _spawn, reconcile_tenant

        async def _run() -> None:
            try:
                t = await Tenant.get_or_none(id=tenant_id)
                if t:
                    await reconcile_tenant(t, tenant_config.yaml_base())
            except Exception:
                logger.exception("dispatcher: reconcile failed for tenant %s", tenant_id)

        _spawn(_run())
    except Exception:
        logger.exception("dispatcher: scheduling reconcile failed for %s", tenant_id)


# ── Webhook notifications (signed, best-effort, bounded retry) ────────────────

def _redact_action_params(action: Dict[str, Any]) -> Dict[str, Any]:
    """A safe copy of a send_command action's params for the alert ledger: drop
    known-secret params (never persist secrets to an alert)."""
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
    """Fire a webhook in the background so delivery never blocks evaluation."""
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


async def _webhook_target_blocked(url: str) -> bool:
    """SSRF guard: resolve the webhook host and refuse to POST to a private,
    loopback, link-local (incl. cloud metadata 169.254.169.254), reserved or
    otherwise non-public address. Fails closed on any parse/resolution error. A
    residual DNS-rebinding window remains between this check and the client's own
    connect; acceptable for an admin-configured target."""
    import asyncio
    import ipaddress
    import socket
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return True
        # Self-hosted single-tenant deployments may legitimately target an
        # internal collector; an explicit opt-out disables the private-range block
        # (kept OFF by default so a multi-tenant host isn't exposed to SSRF).
        if _truthy(os.getenv("DISPATCHER_WEBHOOK_ALLOW_PRIVATE", "false")):
            return False
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(parsed.hostname, port, proto=socket.IPPROTO_TCP)
        if not infos:
            return True
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                    or ip.is_multicast or ip.is_unspecified):
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

    for attempt in range(1, WEBHOOK_MAX_ATTEMPTS + 1):
        try:
            async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT_SECONDS) as client:
                resp = await client.post(url, content=body, headers=headers)
            if resp.status_code < 400:
                return
            # NEVER log the url (it can itself be a secret, e.g. a Slack webhook).
            logger.warning("dispatcher webhook for rule %s got HTTP %s (attempt %d/%d)",
                           rule_id, resp.status_code, attempt, WEBHOOK_MAX_ATTEMPTS)
        except Exception as exc:
            logger.warning("dispatcher webhook for rule %s failed (attempt %d/%d): %s",
                           rule_id, attempt, WEBHOOK_MAX_ATTEMPTS, type(exc).__name__)
        if attempt < WEBHOOK_MAX_ATTEMPTS:
            await asyncio.sleep(min(2 ** attempt, 30))
    logger.error("dispatcher webhook for rule %s gave up after %d attempts",
                 rule_id, WEBHOOK_MAX_ATTEMPTS)


# ── Admin-approved destructive remediation (from the API) ────────────────────

async def approve_remediation(alert: Alert, action_key: str, approver: str) -> Dict[str, Any]:
    """Execute a queued destructive remediation after an admin approves it.

    Runs through the SAME audited command path with allow_destructive=True (the
    admin authorized it), records the outcome, and clears the pending entry.
    Returns a small result dict. Raises ValueError if the approval isn't found."""
    detail = alert.detail or {}
    pending = detail.get("pending_approvals") or []
    entry = next((pa for pa in pending if pa.get("action_key") == action_key), None)
    if entry is None:
        raise ValueError("No such pending remediation on this alert")

    tenant = await Tenant.get_or_none(id=alert.tenant_id)
    device = await Device.get_or_none(id=alert.device_id)
    if tenant is None or device is None:
        raise ValueError("Alert device/tenant no longer exists")

    # Re-derive the action from dispatcher.yaml (the source of truth) rather than
    # trusting the client-supplied key: the real (possibly-secret) command params
    # live only on disk, never in the exposed alert detail. We match by the
    # secret-free key, and re-confirm it's a destructive send_command.
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

    detail["pending_approvals"] = [pa for pa in pending if pa.get("action_key") != action_key]
    detail.setdefault("remediations", []).append({
        "action": "send_command", "at": _now().isoformat(), "dry_run": False,
        "outcome": outcome_str, "approved_by": approver,
    })
    alert.detail = detail
    await alert.save(update_fields=["detail"])
    return {"outcome": outcome_str}
