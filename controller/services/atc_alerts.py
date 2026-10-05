"""ATC Dispatcher alerts for manual gates, in-setup status, and run failures."""

import logging
import os
from typing import Any, Dict, List, Optional

from controller.models.tenant import Alert, Device, FlowRun, Tenant
from controller.services.atc_flow import _flow_has_release_node, _now
# The triage ladder shared with the compliance board, which imports the same table from services/severity.py. An
# unrecognised value ranks below every real one there, where a local copy of the scale would tie it with green.
from controller.services.severity import escalate as _escalate_severity, rank as _severity_rank
# The one definition of which severity strings exist; restating it as a literal here would coerce every renamed value to
# "yellow" in _gate_severity. The validator's module body imports nothing from controller, so this is not a cycle.
from controller.utils.yaml_validator import VALID_SEVERITIES

logger = logging.getLogger(__name__)


def _parse_escalation_hours(raw: str) -> List[float]:
    """Parse the manual-gate ladder env var, a comma-separated list of hours. Anything malformed, including an
    empty segment ("4,,24"), falls back to the default rather than a shrunk ladder."""
    try:
        parts = [part.strip() for part in raw.split(",")]
        hours = [float(part) for part in parts if part]
        if hours and len(hours) == len(parts) and all(h > 0 for h in hours):
            return hours
    except (TypeError, ValueError):
        pass
    logger.warning("ATC: ATC_MANUAL_GATE_ESCALATION_HOURS=%r is not a list of "
                   "positive hours; using the default 4,24,168", raw)
    return [4.0, 24.0, 168.0]


# How long an unanswered manual gate may sit: comma-separated hours, one rung per entry. The default escalates
# at 4h and 24h, then fails at 168h (about 8 days total).
MANUAL_GATE_ESCALATION_HOURS: List[float] = _parse_escalation_hours(
    os.getenv("ATC_MANUAL_GATE_ESCALATION_HOURS", "4,24,168"))


def _gate_options(node: Dict[str, Any]) -> List[Dict[str, str]]:
    """The validated decision options for a manual_gate: [{label, edge}], keeping only options whose edge is a real gate
    handle and carries a label."""
    from controller.services.flow_step_catalog import GATE_EDGE_HANDLES
    out: List[Dict[str, str]] = []
    for o in ((node.get("params") or {}).get("options") or []):
        if isinstance(o, dict) and o.get("edge") in GATE_EDGE_HANDLES and o.get("label"):
            out.append({"label": str(o["label"]), "edge": str(o["edge"])})
    return out


def _gate_severity(node: Dict[str, Any]) -> str:
    """The severity a manual_gate's alert opens at. A value outside VALID_SEVERITIES came from a hand-edited
    document and falls back to the default rather than reach the board as an unrankable string. The allow-list
    is imported, never restated, so a scale that gains or renames a value has one place to change."""
    authored = str((node.get("params") or {}).get("severity") or "yellow")
    return authored if authored in VALID_SEVERITIES else "yellow"


async def _raise_gate_alert(device: Device, run: FlowRun, node: Dict[str, Any],
                            options: List[Dict[str, str]]) -> Optional[str]:
    """Open a Dispatcher alert for a manual_gate. rule_id is unique per run so the 'one active per (device, rule)'
    invariant allows exactly one gate per run."""
    params = node.get("params") or {}
    severity = _gate_severity(node)
    summary = str(params.get("summary") or "Flow paused for a decision")[:255]
    try:
        tenant = await Tenant.get_or_none(id=device.tenant_id)
        if tenant is None:
            return None
        alert = await Alert.create(
            tenant=tenant, device=device, rule_id=f"atc:gate:{run.id}",
            severity=severity, status="open", summary=summary,
            detail={"kind": "atc_gate", "flow_run_id": str(run.id),
                    "node_id": node.get("id"), "options": options},
        )
        return str(alert.id)
    except Exception:
        logger.exception("ATC: raising gate alert failed for run %s", run.id)
        return None


def _authored_gate_timeout(node: Dict[str, Any]) -> Optional[int]:
    """The gate's own timeout_minutes, if the author set a valid one. The validator hard-errors a malformed value, so
    anything else here came from a hand-edited document and is ignored rather than trusted."""
    raw = (node.get("params") or {}).get("timeout_minutes")
    if raw is None or isinstance(raw, bool):
        return None
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return None
    return val if val > 0 else None


def _gate_schedule(total_minutes: Optional[int]) -> List[float]:
    """Minutes from park time to each deadline of a manual gate. Every entry except the last is an escalation;
    the last one fails the run. An authored timeout_minutes replaces the ladder's total: rungs inside it still
    escalate, rungs past it are dropped, and the run fails at the authored time."""
    moments: List[float] = []
    acc = 0.0
    for h in MANUAL_GATE_ESCALATION_HOURS:
        acc += float(h) * 60.0
        moments.append(acc)
    fail_at = float(total_minutes) if total_minutes else moments[-1]
    return [m for m in moments if m < fail_at] + [fail_at]


def _duration_phrase(minutes: float) -> str:
    """A duration in words for timelines and alert summaries. Timeout precision is the poll tick, so prose rounds to the
    nearest sensible unit."""
    m = int(round(minutes))
    if m >= 2880:
        d = round(m / 1440)
        return f"{d} days"
    if m >= 60 and m % 60 == 0:
        h = m // 60
        return f"{h} hour" + ("s" if h != 1 else "")
    return f"{m} minute" + ("s" if m != 1 else "")


def _bump_severity(severity: str) -> str:
    """One step up the triage ladder, capped at black. Unknown values come back unchanged (the shared module's
    rule); authored values reach here already coerced by _gate_severity, so only a stored row can supply one."""
    return _escalate_severity(severity)


async def _escalate_gate_alert(device: Device, run: FlowRun, node: Dict[str, Any],
                               node_id: Optional[str], waited_minutes: float,
                               next_minutes: float, next_is_final: bool) -> Optional[str]:
    """Make the gate's decision alert one severity step louder because a rung expired with no decision. Keeps
    its options so a louder alert still carries the way to answer it, and is recreated if none is active."""
    waited = _duration_phrase(waited_minutes)
    nxt = _duration_phrase(next_minutes)
    tail = (f"The run fails in {nxt} unless someone decides."
            if next_is_final else f"It escalates again in {nxt}.")
    summary = (f"{device.serial_number}: flow '{run.flow_id}' has waited {waited} "
               f"at gate '{node_id}' for a decision. {tail}")[:255]
    try:
        from controller.services.dispatcher import _active_alert
        rule_id = f"atc:gate:{run.id}"
        alert = await _active_alert(device, rule_id)
        if alert is None:
            tenant = await Tenant.get_or_none(id=device.tenant_id)
            if tenant is None:
                return None
            authored = _gate_severity(node)
            alert = await Alert.create(
                tenant=tenant, device=device, rule_id=rule_id,
                severity=_bump_severity(authored), status="open", summary=summary,
                detail={"kind": "atc_gate", "flow_run_id": str(run.id),
                        "node_id": node_id, "options": _gate_options(node),
                        "escalations": 1},
            )
            return str(alert.id)
        alert.severity = _bump_severity(alert.severity)
        alert.summary = summary
        d = alert.detail or {}
        d["escalations"] = int(d.get("escalations") or 0) + 1
        d["last_escalated_at"] = _now().isoformat()
        alert.detail = d
        await alert.save(update_fields=["severity", "summary", "detail", "updated_at"])
        return str(alert.id)
    except Exception:
        logger.exception("ATC: escalating gate alert failed for run %s", run.id)
        return None


async def _resolve_gate_alert(run: FlowRun, reason: str) -> None:
    try:
        alerts = await Alert.filter(rule_id=f"atc:gate:{run.id}").exclude(
            status="resolved").all()
        for a in alerts:
            a.status = "resolved"
            a.resolved_at = _now()
            d = a.detail or {}
            d["resolved_reason"] = reason
            a.detail = d
            await a.save(update_fields=["status", "resolved_at", "detail"])
    except Exception:
        logger.exception("ATC: resolving gate alert failed for run %s", run.id)


async def _ensure_in_setup_alert(device: Device, run: FlowRun) -> None:
    """Open, once, the green "held in Setup Assistant" alert for an ADE device whose flow will release it."""
    if not getattr(device, "dep_profile_uuid", None):
        return
    if not _flow_has_release_node((run.context or {}).get("flow") or {}):
        return
    try:
        from controller.services.dispatcher import _active_alert
        existing = await _active_alert(device, "atc:in-setup")
        if existing is None:
            tenant = await Tenant.get_or_none(id=device.tenant_id)
            if tenant is None:
                return
            await Alert.create(
                tenant=tenant, device=device, rule_id="atc:in-setup",
                severity="green", status="open",
                summary=f"{device.serial_number} held in Setup Assistant"[:255],
                detail={"kind": "atc_in_setup", "flow_run_id": str(run.id),
                        "actions": [{"key": "release", "label": "Release from setup"}]},
            )
        # Flag the run so a terminal transition knows to resolve the alert.
        ctx = run.context or {}
        ctx["in_setup"] = True
        run.context = ctx
    except Exception:
        logger.exception("ATC: ensuring in-setup alert failed for %s", device.serial_number)


async def _resolve_in_setup_alert(device: Device, reason: str) -> None:
    try:
        alerts = await Alert.filter(
            device_id=device.id, rule_id="atc:in-setup"
        ).exclude(status="resolved").all()
        for a in alerts:
            a.status = "resolved"
            a.resolved_at = _now()
            d = a.detail or {}
            d["resolved_reason"] = reason
            a.detail = d
            await a.save(update_fields=["status", "resolved_at", "detail"])
    except Exception:
        logger.exception("ATC: resolving in-setup alert failed for %s", device.serial_number)


async def _escalate_in_setup_alert(device: Device, run: FlowRun, reason: str) -> None:
    """Make the in-setup alert louder instead of resolving it, because the run that was going to release this
    device is over and did not. One step, green to yellow, with the summary saying why; a device that fails
    the same flow every check-in must not ratchet the alert to black."""
    try:
        from controller.services.dispatcher import _active_alert
        alert = await _active_alert(device, "atc:in-setup")
        if alert is None:
            return
        if alert.severity == "green":
            alert.severity = "yellow"
        alert.summary = (f"{device.serial_number} is held in Setup Assistant and "
                         f"the flow that would release it {reason}")[:255]
        detail = alert.detail or {}
        detail["flow_run_id"] = str(run.id)
        detail["run_status"] = run.status
        detail["run_error"] = run.error
        alert.detail = detail
        await alert.save(update_fields=["severity", "summary", "detail", "updated_at"])
    except Exception:
        logger.exception("ATC: escalating in-setup alert failed for %s",
                         device.serial_number)


async def _settle_in_setup_on_terminal(run: FlowRun) -> None:
    """Close out the green in-setup alert when the run that opened it ends. Only a run that actually sent
    DeviceConfigured may resolve it; a run that ended without releasing left the device on the Remote
    Management screen, and resolving would delete the alert that says so."""
    ctx = run.context or {}
    if not ctx.get("in_setup"):
        return
    device = await Device.get_or_none(id=run.device_id)
    if device is None:
        return
    if ctx.get("released"):
        await _resolve_in_setup_alert(device, f"flow {run.status}")
        return
    if run.status == "failed":
        await _escalate_in_setup_alert(device, run, "failed")


def _run_failed_rule_id(flow_id: Any) -> str:
    """Board key for a failed run: one row per (device, flow), not per run, so a device failing the same flow
    every check-in doesn't open a fresh alert every tick; the one-active-alert-per-rule_id invariant coalesces
    repeat failures into the existing row with a count."""
    return f"atc:flow-failed:{flow_id}"[:100]


def _run_failed_summary(device: Device, run: FlowRun, node_id: Optional[str],
                        message: str, held_in_setup: bool, count: int) -> str:
    """One line naming the device, the flow, the node it died on, and whether a device is stuck behind it."""
    where = f" at node '{node_id}'" if node_id else ""
    unverified = (run.context or {}).get("unverified") or {}
    if unverified:
        # A released device is already out of Setup Assistant, so lead with that rather than with the node.
        head = (f"{device.serial_number} left Setup Assistant before flow "
                f"'{run.flow_id}' could confirm its configuration")
        body = str(unverified.get("body") or message)
        body = body[:1].upper() + body[1:]
    elif held_in_setup:
        head = f"{device.serial_number} is stuck in Setup Assistant: flow '{run.flow_id}' failed{where}"
        body = message
    else:
        head = f"{device.serial_number}: flow '{run.flow_id}' failed{where}"
        body = message
    repeat = f" ({count} failures so far)" if count > 1 else ""
    return f"{head}. {body}{repeat}"[:255]


async def _raise_run_failed_alert(run: FlowRun, node_id: Optional[str],
                                  message: str, held_in_setup: bool) -> None:
    """Put a failed run on the Dispatcher board with enough to act on: flow, node, error, device, link back to
    the run. Severity says what the failure cost: yellow if it failed doing nothing, red if it left a device on
    the Remote Management screen; a released-but-unverified run carries the grade the gap ledger gave it."""
    try:
        device = await Device.get_or_none(id=run.device_id)
        if device is None:
            logger.warning("ATC: run %s failed with no device row, so no alert: %s",
                           run.id, message)
            return
        tenant = await Tenant.get_or_none(id=run.tenant_id)
        if tenant is None:
            return
        from controller.services.dispatcher import _active_alert
        rule_id = _run_failed_rule_id(run.flow_id)
        alert = await _active_alert(device, rule_id)
        unverified = (run.context or {}).get("unverified") or {}
        severity = "red" if held_in_setup else "yellow"
        if unverified:
            severity = str(unverified.get("severity") or "yellow")
        now = _now()
        prior = (alert.detail if alert else None) or {}
        count = int(prior.get("failure_count") or 0) + 1
        summary = _run_failed_summary(device, run, node_id, message,
                                      held_in_setup, count)
        # Two lifetimes share this dict: failure_count/first_failed_at describe the ROW and are pulled from the
        # existing alert; everything else describes the RUN and is rebuilt, so released_unverified/gaps can't
        # leak into an unrelated later failure of the same flow.
        detail: Dict[str, Any] = {
            "failure_count": count,
            "first_failed_at": prior.get("first_failed_at") or now.isoformat(),
        }
        detail.update({
            "kind": "atc_run_failed",
            "flow_id": str(run.flow_id),
            "flow_run_id": str(run.id),
            "start_node": run.start_node,
            "event_kind": run.event_kind,
            "node_id": node_id,
            "error": message,
            "held_in_setup": held_in_setup,
            "last_failed_at": now.isoformat(),
            # This run's verdict, not the row's: true and populated only when this failure is the release guard
            # tripping, false and empty otherwise, regardless of what a prior run left behind.
            "released_unverified": bool(unverified),
            "gaps": (unverified.get("gaps") if unverified else None),
        })
        if alert is None:
            await Alert.create(
                tenant=tenant, device=device, rule_id=rule_id, severity=severity,
                status="open", summary=summary, detail=detail,
            )
            logger.info("ATC: run %s failed, alert opened for %s (%s)",
                        run.id, device.serial_number, rule_id)
            return
        # Status is left alone so an acknowledged alert does not reopen on the next check-in; severity only
        # ever climbs, so the run that stranded a device keeps the colour even if the next one fails harmlessly.
        alert.summary = summary
        alert.detail = detail
        if _severity_rank(severity) > _severity_rank(alert.severity):
            alert.severity = severity
        await alert.save(update_fields=["summary", "detail", "severity", "updated_at"])
    except Exception:
        logger.exception("ATC: raising the failure alert for run %s failed", run.id)


async def _resolve_run_failed_alert(run: FlowRun) -> None:
    """A run of this flow reached the end on this device, so clear the failure row the last one left."""
    try:
        alerts = await Alert.filter(
            device_id=run.device_id, rule_id=_run_failed_rule_id(run.flow_id)
        ).exclude(status="resolved").all()
        for a in alerts:
            a.status = "resolved"
            a.resolved_at = _now()
            d = a.detail or {}
            d["resolved_reason"] = f"a later run of '{run.flow_id}' completed"
            d["resolved_by_flow_run_id"] = str(run.id)
            a.detail = d
            await a.save(update_fields=["status", "resolved_at", "detail"])
    except Exception:
        logger.exception("ATC: resolving the failure alert for run %s failed", run.id)
