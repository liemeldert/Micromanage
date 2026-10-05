"""ATC (Air Traffic Control) flow execution engine.

Runs a flow from flows.yaml per device as an async state machine (FlowRun).
"""

import copy
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from controller.models.tenant import Device, FlowRun, Tenant
from controller.services import atc_alerts, atc_context, atc_flow, atc_node_effects, flow_gate
from controller.services.atc_alerts import (
    _authored_gate_timeout, _duration_phrase, _ensure_in_setup_alert, _escalate_gate_alert,
    _gate_options, _gate_schedule, _raise_gate_alert, _raise_run_failed_alert,
    _resolve_gate_alert, _resolve_run_failed_alert, _settle_in_setup_on_terminal,
)
from controller.services.atc_context import (
    _consume_expected, _drop_flow_snapshot, _gate_off, _is_ungated,
    _mark_visited, _prior_gap_grade, _record_gap, _record_satisfied,
    _record_unmet, _signal_expected, _str_list, _timeline,
)
from controller.services.atc_flow import _as_aware, _enabled_flows, _int, _nodes_by_id, _now
from controller.services.atc_node_effects import (
    _apply_tags, _configure_accounts, _install_apps, _install_profiles,
    _release_device, _set_firmware_lock, _set_name, _sync_declarations,
)
from controller.services.scoping import evaluate_condition
from tortoise.functions import Max

logger = logging.getLogger(__name__)

# The validator already proves a flow is a DAG, but cap how many nodes one
# _advance pass may execute anyway, so a bug can't spin forever.
MAX_NODES_PER_ADVANCE = 100

# A run marked 'running' long after an _advance pass finished was orphaned, usually by a dying process; it has
# no deadline, so only the sweep frees it.
STALE_RUNNING_MINUTES = int(os.getenv("ATC_STALE_RUNNING_MINUTES", "30"))

# Per-tenant cap on scheduled-start runs per sweep, so a big fleet all matching one schedule doesn't launch thousands of
# runs at once. Most-overdue go first and the rest catch up on later ticks.
SCHEDULE_MAX_LAUNCH_PER_TICK = int(os.getenv("ATC_SCHEDULE_MAX_LAUNCH_PER_TICK", "200"))

# How many unfinished runs one device may have at once, across every flow. Enrollment events are exempt, so this cap can
# never leave a device on the Remote Management screen with its onboarding flow refused a run.
MAX_ACTIVE_RUNS_PER_DEVICE = int(os.getenv("ATC_MAX_ACTIVE_RUNS_PER_DEVICE", "8"))

# Run states that count as "active" for supersede/dedup.
_ACTIVE_STATES = ["running", "waiting"]

# Events that supersede a device's prior run from the same start, since a fresh enroll re-runs onboarding. Everything
# else dedups instead, skipping while a run is active.
_SUPERSEDE_EVENTS = frozenset({"enroll_dep", "enroll_profile"})

# Names that external callers and tests read as atc.<name>
CHECKIN_COOLDOWN_DEFAULT_MINUTES = atc_flow.CHECKIN_COOLDOWN_DEFAULT_MINUTES
_flow_hash = atc_flow._flow_hash
_load_flow = atc_flow._load_flow
_load_flows = atc_flow._load_flows
_scope_matches = atc_flow._scope_matches
_checkin_cooldown_minutes = atc_flow._checkin_cooldown_minutes
_truthy_param = atc_flow._truthy_param
flows_with_start = atc_flow.flows_with_start

_REFLESS_SIGNALS = atc_context._REFLESS_SIGNALS

_gate_severity = atc_alerts._gate_severity
_bump_severity = atc_alerts._bump_severity
_severity_rank = atc_alerts._severity_rank

_send_command = atc_node_effects._send_command
release_device_manual = atc_node_effects.release_device_manual


# ==Entry points==

async def _has_active_run(device_id: Any, flow_id: str, start_id: str) -> bool:
    """True when this (device, flow, start) already has a running or waiting run. flow_id is part of the key because
    start node ids repeat across flows (per-flow counter); without it one flow's run would silence another's trigger."""
    try:
        return await FlowRun.filter(
            device_id=device_id, flow_id=flow_id, start_node=start_id,
            status__in=_ACTIVE_STATES,
        ).exists()
    except Exception:
        logger.exception("ATC: active-run check failed for start %s of flow %s",
                         start_id, flow_id)
        return False


async def _active_starts_for_device(device_id: Any) -> Set[Tuple[str, str]]:
    """Every (flow_id, start_node) this device has a running or waiting run for, as one query in place of an
    exists() per start node; start_flows_for_event walks every enabled flow's start nodes, so per-start queries
    would be paid once per flow per check-in on every device in the fleet."""
    rows = await FlowRun.filter(
        device_id=device_id, status__in=_ACTIVE_STATES
    ).values("flow_id", "start_node")
    return {(str(r["flow_id"]), str(r["start_node"])) for r in rows}


async def _prefetch_active_starts(tenant_id: Any, flow_id: str,
                                  start_id: str) -> Set[str]:
    """Devices with a run from this flow's start still running or waiting, as one tenant query in place of an
    exists() per device. Not filtered by event_kind, matching _has_active_run: a run from this start blocks a
    new one however it started."""
    rows = await FlowRun.filter(
        tenant_id=tenant_id, flow_id=flow_id, start_node=start_id,
        status__in=_ACTIVE_STATES,
    ).values("device_id")
    return {str(r["device_id"]) for r in rows}


async def _last_run_for_device(device_id: Any, flow_id: str, start_id: str,
                               event_kind: str) -> Optional[datetime]:
    """When this (device, start) last ran on this event kind, whatever state the run ended in. flow_id is required
    because start ids repeat across flows. A run already swept by retention is invisible here."""
    last = await FlowRun.filter(
        device_id=device_id, flow_id=flow_id, start_node=start_id,
        event_kind=event_kind,
    ).order_by("-started_at").first()
    return _as_aware(last.started_at) if last is not None else None


async def _last_scheduled_for_device(device_id: Any, flow_id: str,
                                     start_id: str) -> Optional[datetime]:
    """Newest schedule-started run for one device; only the fallback path uses this, when the grouped prefetch
    below could not run. Named rather than inline so a test can stub it and prove the fast path avoids it."""
    return await _last_run_for_device(device_id, flow_id, start_id, "schedule")


async def _checkin_start_is_due(device: Device, node: Dict[str, Any],
                                flow_id: str, start_id: str) -> bool:
    """Whether this check-in start may run now: once:true means at most one run ever, otherwise the cooldown measures
    from the last checkin-kind run (_last_run_for_device). A failed lookup answers no, unlike every other guard here."""
    params = node.get("params") or {}
    try:
        last = await _last_run_for_device(device.id, flow_id, start_id, "checkin")
    except Exception:
        logger.exception("ATC: check-in cooldown lookup failed for start %s on %s; "
                         "not starting a run this check-in", start_id, device.id)
        return False
    if last is None:
        return True
    if _truthy_param(params.get("once")):
        return False
    minutes = _checkin_cooldown_minutes(params)
    if minutes <= 0:
        return True
    return (_now() - last) >= timedelta(minutes=minutes)


async def _prefetch_last_scheduled(tenant_id: Any, flow_id: str,
                                   start_id: str) -> Dict[str, datetime]:
    """Newest schedule-started run per device for this flow's start node, as one grouped query in place of an
    order-by-then-first per device. A device missing from the result has never run this schedule, same as a
    None row from the per-device query."""
    rows = await FlowRun.filter(
        tenant_id=tenant_id, flow_id=flow_id, start_node=start_id,
        event_kind="schedule",
    ).annotate(last_started=Max("started_at")).group_by("device_id").values(
        "device_id", "last_started"
    )
    out: Dict[str, datetime] = {}
    for row in rows:
        started = _as_aware(row.get("last_started"))
        if started is not None:
            out[str(row["device_id"])] = started
    return out


async def _supersede(device_id: Any, flow_id: str, start_id: str) -> None:
    """Cancel active runs from this same flow and start on the device, since a fresh enroll re-runs onboarding. Row by
    row, not a bulk update, because dropping the pinned flow snapshot is a JSON column edit an UPDATE can't express."""
    try:
        runs = await FlowRun.filter(
            device_id=device_id, flow_id=flow_id, start_node=start_id,
            status__in=_ACTIVE_STATES,
        ).all()
        for run in runs:
            claimed = await FlowRun.filter(
                id=run.id, status__in=_ACTIVE_STATES
            ).update(status="cancelled", current_node=None, waiting_signal=None,
                     waiting_ref=None, wait_deadline=None, completed_at=_now())
            if claimed and _drop_flow_snapshot(run):
                await _persist_context(run)
    except Exception:
        logger.exception("ATC: superseding prior runs failed for start %s of flow %s", start_id, flow_id)


async def _start_run(device: Device, flow: Dict[str, Any], start_node: Dict[str, Any],
                     event_kind: str,
                     trigger_ref: Optional[str] = None) -> Optional[FlowRun]:
    """Create a FlowRun entering at start_node and advance it once. trigger_ref names whatever started the run
    for the kinds that have one (e.g. a compliance alert id); device-triggered kinds have nothing to point at
    and leave it None. Rides in context["trigger"], not a column, since only one screen reads it."""
    try:
        run = await FlowRun.create(
            tenant_id=device.tenant_id,
            device_id=device.id,
            flow_id=str(flow.get("id") or "flow"),
            start_node=str(start_node.get("id")),
            event_kind=event_kind,
            flow_hash=_flow_hash(flow),
            status="running",
            current_node=str(start_node.get("id")),
            # Own copy: _load_flows and a sweep hand out one shared/cached document, so without a deepcopy every
            # run's context would alias the same dict.
            context={"flow": copy.deepcopy(flow), "timeline": [], "visited": [],
                     "expected": {},
                     # Survives _drop_flow_snapshot (which only pops "flow"); on a finished run this is the only
                     # record of why the run existed.
                     "trigger": {"kind": event_kind, "at": _now().isoformat(),
                                 "ref": trigger_ref}},
        )
        _timeline(run, str(start_node.get("id")), f"started ({event_kind})")
        logger.info("ATC: started run %s for %s (start=%s, event=%s)",
                    run.id, device.serial_number, start_node.get("id"), event_kind)
        await _advance(run, device)
        return run
    except Exception:
        logger.exception("ATC: starting run failed for device %s", device.id)
        return None


async def start_flows_for_event(device: Device, event_kind: str) -> List[FlowRun]:
    """Start runs for every matching start node in every enabled flow. Enroll events supersede a prior run;
    everything else dedups against an active run. Best-effort: one bad flow/node does not stop the rest."""
    runs: List[FlowRun] = []
    flows = _enabled_flows(str(device.tenant_id))
    if not flows:
        return runs
    device_groups = list(device.groups or [])

    # One query for the whole device instead of one per candidate start; a failure here costs batching only,
    # since the per-start query below still stands.
    active: Optional[Set[Tuple[str, str]]] = None
    try:
        active = await _active_starts_for_device(device.id)
    except Exception:
        logger.warning("ATC: active-run prefetch failed for device %s; falling "
                       "back to per-start queries", device.id, exc_info=True)

    # Enrollment is exempt from the cap; see MAX_ACTIVE_RUNS_PER_DEVICE.
    if event_kind not in _SUPERSEDE_EVENTS and active is not None \
        and len(active) >= MAX_ACTIVE_RUNS_PER_DEVICE:
        logger.warning("ATC: device %s already has %d unfinished runs, at the ATC_MAX_ACTIVE_RUNS_PER_DEVICE cap; not "
                       "starting more for %s", device.id, len(active), event_kind)
        return runs

    for flow in flows:
        flow_id = str(flow.get("id") or "flow")
        try:
            for node in (flow.get("nodes") or []):
                try:
                    if (not isinstance(node, dict) or node.get("type") != "start"
                        or not node.get("id")):
                        continue
                    params = node.get("params") or {}
                    if params.get("kind") != event_kind:
                        continue
                    if not _scope_matches(device, device_groups, params.get("match")):
                        continue
                    start_id = str(node["id"])
                    if event_kind in _SUPERSEDE_EVENTS:
                        await _supersede(device.id, flow_id, start_id)
                    else:
                        if active is not None:
                            if (flow_id, start_id) in active:
                                continue  # dedup: a run from this start is still going
                        elif await _has_active_run(device.id, flow_id, start_id):
                            continue
                        if event_kind == "checkin" and not await _checkin_start_is_due(
                            device, node, flow_id, start_id):
                            continue
                    run = await _start_run(device, flow, node, event_kind)
                    if run is not None:
                        runs.append(run)
                        if active is not None:
                            active.add((flow_id, start_id))
                except Exception:
                    logger.exception("ATC: start node %r of flow %s failed for "
                                     "device %s", (node or {}).get("id"), flow_id,
                                     device.id)
        except Exception:
            logger.exception("ATC: flow %s failed for device %s", flow_id, device.id)
    return runs


async def start_run_from_start(device: Device, start_node_id: str,
                               flow_id: Optional[str] = None
                               ) -> Optional[FlowRun]:
    """Manually start a run from a specific start node (testing, API), superseding an active run from the same flow and
    start. Without flow_id every enabled flow is searched, and an id present in more than one is refused rather than
    guessed at. Returns None if the node does not exist, is not a start node, is ambiguous, or the start fails."""
    try:
        if flow_id is not None:
            flows = [f for f in _enabled_flows(str(device.tenant_id))
                     if str(f.get("id")) == str(flow_id)]
        else:
            flows = _enabled_flows(str(device.tenant_id))
        matches = [(f, _nodes_by_id(f).get(start_node_id)) for f in flows]
        matches = [(f, n) for f, n in matches if n and n.get("type") == "start"]
        if len(matches) != 1:
            if len(matches) > 1:
                logger.warning("ATC: start node %s is ambiguous across flows %s",
                               start_node_id,
                               [str(f.get("id")) for f, _ in matches])
            return None
        flow, node = matches[0]
        resolved = str(flow.get("id") or "flow")
        await _supersede(device.id, resolved, start_node_id)
        kind = (node.get("params") or {}).get("kind") or "manual"
        return await _start_run(device, flow, node, str(kind))
    except Exception:
        logger.exception("ATC: manual start of node %s failed for device %s",
                         start_node_id, device.id)
        return None


async def _claim_waiting(run_id: Any, **filters: Any) -> int:
    """Move a run still waiting (and matching filters) to running with its wait cleared. Returns the row count."""
    return await FlowRun.filter(id=run_id, status="waiting", **filters).update(
        status="running", waiting_signal=None, waiting_ref=None, wait_deadline=None,
    )


async def advance_on_signal(device_id: str, signal: str, ref: Optional[str] = None) -> None:
    """Resume waiting runs for a device when a device signal arrives. Best-effort: called from webhook handlers,
    so it swallows and logs any failure rather than breaking webhook processing."""
    try:
        device = await Device.get_or_none(id=device_id)
        if device is None:
            return
        # Also how a firmware rotation or managed-admin account is confirmed. Runs for every ack, not just a
        # flow's, since an admin can set a lock from a device page with no flow run involved.
        if signal == "command_ack" and ref:
            from controller.services import device_secrets
            await device_secrets.reconcile_command_ack(device, ref)
        runs = await FlowRun.filter(
            device_id=device_id, status="waiting", waiting_signal=signal
        ).all()
        for run in runs:
            try:
                if not _signal_expected(run, signal, ref):
                    continue
                if signal not in _REFLESS_SIGNALS:
                    # One piece of a barrier that may want several. Record the arrival before deciding anything: the
                    # rest of them come in on their own webhook calls, possibly after a restart.
                    arrived, total = await _record_satisfied(run, signal, ref)
                    if arrived < total:
                        _timeline(run, run.current_node,
                                  f"{signal}: {ref} arrived ({arrived} of {total}); "
                                  "still waiting")
                        await _persist_context(run)
                        continue
                node = _nodes_by_id((run.context or {}).get("flow") or {}).get(run.current_node)
                nxt = (node or {}).get("next")
                # Atomically claim the run (guards against the sweep or a second signal advancing the same run
                # concurrently).
                claimed = await _claim_waiting(run.id)
                if not claimed:
                    continue
                if not nxt:
                    await _fail(run, "wait_for node has no 'next' edge")
                    continue
                # The barrier is done, so clear what it wanted and what turned up. A later wait_for on the same signal
                # starts fresh rather than lifting on a stale ref from this one.
                _consume_expected(run, signal)
                run.status = "running"
                run.current_node = nxt
                _timeline(run, run.current_node, f"resumed on {signal}")
                await _advance(run, device)
            except Exception:
                logger.exception("ATC: advancing run %s on signal %s failed", run.id, signal)

        # A check-in can also start a checkin-triggered run. Do it after resuming existing waits, so the run we just
        # resumed counts as active and the dedup guard doesn't launch a duplicate from the same start.
        if signal == "checkin":
            try:
                await start_flows_for_event(device, "checkin")
            except Exception:
                logger.exception("ATC: checkin start dispatch failed for %s", device_id)
    except Exception:
        logger.exception("ATC: advance_on_signal(%s, %s) failed", device_id, signal)


async def sweep_timeouts(tenant: Tenant) -> int:
    """Resolve waiting runs whose deadline has passed: a wait_for takes its on_timeout edge or fails the run; a
    manual gate climbs its escalation ladder (a legacy gate with no deadline is adopted onto it first). Returns
    how many were swept."""
    swept = 0
    try:
        runs = await FlowRun.filter(
            tenant_id=tenant.id, status="waiting", wait_deadline__lte=_now()
        ).all()
    except Exception:
        logger.exception("ATC: timeout sweep query failed for tenant %s", tenant.id)
        return 0
    for run in runs:
        try:
            if run.waiting_signal == "manual":
                swept += await _sweep_manual_gate(run)
                continue
            node = _nodes_by_id((run.context or {}).get("flow") or {}).get(run.current_node)
            on_timeout = (node or {}).get("on_timeout")
            claimed = await _claim_waiting(run.id)
            if not claimed:
                continue
            swept += 1
            device = await Device.get_or_none(id=run.device_id)
            if on_timeout:
                waited_at = run.current_node
                signal = ((node or {}).get("params") or {}).get("signal")
                run.status = "running"
                run.current_node = on_timeout
                # Record what the deadline ran out on before the buckets are cleared, or release_device has
                # nothing left to look at.
                _record_unmet(run, waited_at, signal)
                _consume_expected(run, signal)
                _timeline(run, on_timeout, "wait timed out")
                if device is None:
                    await _fail(run, "device no longer exists")
                else:
                    await _advance(run, device)
            else:
                await _fail(run, f"timed out waiting for '{run.waiting_signal or 'signal'}'")
        except Exception:
            logger.exception("ATC: sweeping run %s failed", run.id)

    # A NULL deadline never satisfies the <= above, and pre-ladder code parked every manual gate with none, so
    # adopt those onto the ladder here; from the next tick on they age like any other gate.
    try:
        legacy = await FlowRun.filter(
            tenant_id=tenant.id, status="waiting", waiting_signal="manual",
            wait_deadline__isnull=True,
        ).all()
    except Exception:
        logger.exception("ATC: legacy gate query failed for tenant %s", tenant.id)
        legacy = []
    for run in legacy:
        try:
            swept += await _adopt_legacy_gate(run)
        except Exception:
            logger.exception("ATC: adopting legacy gate run %s failed", run.id)

    # Recover runs orphaned in 'running', usually a process that died mid-advance. They have no deadline and no waiting
    # row, so only this sweep frees them.
    try:
        stale_cut = _now() - timedelta(minutes=STALE_RUNNING_MINUTES)
        stuck = await FlowRun.filter(
            tenant_id=tenant.id, status="running", updated_at__lt=stale_cut
        ).all()
        message = "interrupted (run orphaned mid-execution)"
        for run in stuck:
            claimed = await FlowRun.filter(id=run.id, status="running").update(
                status="failed", error=message, completed_at=_now(),
            )
            if not claimed:
                continue
            swept += 1
            # The claim only moves the row to terminal; everything else _fail does is still owed. Settled here
            # rather than through _fail, whose full save would push this process's stale row back over the claim.
            try:
                orphan = await FlowRun.get_or_none(id=run.id)
                if orphan is None:
                    continue
                octx = orphan.context or {}
                held_in_setup = bool(octx.get("in_setup")) and not octx.get("released")
                failed_at = orphan.current_node
                _timeline(orphan, failed_at, f"failed: {message}")
                _drop_flow_snapshot(orphan)
                await _persist_context(orphan)
                await _settle_in_setup_on_terminal(orphan)
                await _raise_run_failed_alert(orphan, failed_at, message, held_in_setup)
            except Exception:
                logger.exception("ATC: settling orphaned run %s failed", run.id)
    except Exception:
        logger.exception("ATC: stale-running recovery failed for tenant %s", tenant.id)
    return swept


async def sweep_scheduled_starts(tenant: Tenant,
                                 devices: Optional[List[Device]] = None) -> int:
    """Launch runs for schedule start nodes whose interval has elapsed for an in-scope device. Called each poll tick;
    the interval, not the tick, sets the cadence. Most-overdue devices go first, under a per-tenant launch cap shared
    across flows (see the round-robin below)."""
    launched = 0
    flows = _enabled_flows(str(tenant.id))
    if not flows:
        return 0
    pairs = [
        (flow, node)
        for flow in flows
        for node in (flow.get("nodes") or [])
        if isinstance(node, dict) and node.get("type") == "start" and node.get("id")
           and (node.get("params") or {}).get("kind") == "schedule"
    ]
    if not pairs:
        return 0
    try:
        if devices is None:
            devices = await Device.filter(
                tenant_id=tenant.id, enrollment_state="enrolled"
            ).all()
    except Exception:
        logger.exception("ATC: schedule sweep device query failed for tenant %s", tenant.id)
        return 0

    now = _now()
    never_run_key = now - timedelta(days=3650)  # sort never-run devices first
    budget = SCHEDULE_MAX_LAUNCH_PER_TICK
    queues: List[Tuple[Dict[str, Any], Dict[str, Any], List[Device]]] = []

    for flow, node in pairs:
        params = node.get("params") or {}
        flow_id = str(flow.get("id") or "flow")
        start_id = str(node["id"])
        interval = _int(params.get("interval_minutes"), 0)
        if interval <= 0:
            continue
        floor = flow_gate.MIN_SCHEDULE_INTERVAL_MINUTES
        if interval < floor:
            # A document that did not come through services.flow_gate (hand edit, restored snapshot, config
            # management). Clamping is the safe reading, and it is logged because the author is looking at a number the
            # engine is not using.
            logger.warning("ATC: schedule start %s of flow %s asks for every %dm, below the "
                           "ATC_MIN_SCHEDULE_INTERVAL_MINUTES floor of %dm; running it at the floor",
                           start_id, flow_id, interval, floor)
            interval = floor
        match = params.get("match")
        # Two queries per start node, not two per device: the due-scan runs before the launch cap, so per-device
        # queries would cost every enrolled device a round-trip pair every tick just to find nothing due. An
        # optimization, not a guard, so each prefetch falls back on its own on a transient DB error.
        active: Optional[Set[str]] = None
        try:
            active = await _prefetch_active_starts(tenant.id, flow_id, start_id)
        except Exception:
            logger.warning("ATC: active-run prefetch failed for start %s of flow "
                           "%s; falling back to per-device queries this tick",
                           start_id, flow_id, exc_info=True)
        last_started: Optional[Dict[str, datetime]] = None
        try:
            last_started = await _prefetch_last_scheduled(tenant.id, flow_id, start_id)
        except Exception:
            logger.warning("ATC: last-run prefetch failed for start %s of flow %s; "
                           "falling back to per-device queries this tick",
                           start_id, flow_id, exc_info=True)
        due: List[Tuple[datetime, Device]] = []
        for d in devices:
            try:
                if not _scope_matches(d, list(d.groups or []), match):
                    continue
                if active is not None:
                    if str(d.id) in active:
                        continue
                elif await _has_active_run(d.id, flow_id, start_id):
                    continue
                if last_started is not None:
                    la = last_started.get(str(d.id))
                else:
                    la = await _last_scheduled_for_device(d.id, flow_id, start_id)
                if la is None:
                    due.append((never_run_key, d))
                    continue
                if (now - la) >= timedelta(minutes=interval):
                    due.append((la, d))
            except Exception:
                logger.exception("ATC: schedule eval failed for %s",
                                 getattr(d, "serial_number", "?"))
        if due:
            due.sort(key=lambda pair: pair[0])
            queues.append((flow, node, [d for _, d in due]))

    if not queues:
        return 0

    # Round-robin: one device from each start node's queue per pass, most overdue first inside a queue. A tenant at the
    # cap spreads it across every flow instead of spending it on whichever one happens to be first.
    taken = [0] * len(queues)
    progress = True
    while budget > 0 and progress:
        progress = False
        for slot, (flow, node, queue) in enumerate(queues):
            if budget <= 0:
                break
            index = taken[slot]
            if index >= len(queue):
                continue
            taken[slot] = index + 1
            progress = True
            budget -= 1
            if await _start_run(queue[index], flow, node, "schedule") is not None:
                launched += 1

    for slot, (flow, node, queue) in enumerate(queues):
        deferred = len(queue) - taken[slot]
        if deferred > 0:
            logger.info("ATC: schedule start %s of flow %s launched %d, deferred "
                        "%d to next tick", node.get("id"), flow.get("id"),
                        taken[slot], deferred)
    if budget <= 0:
        logger.info("ATC: schedule sweep hit the per-tick cap for tenant %s", tenant.id)
    return launched


# ==Execution==

async def _advance(run: FlowRun, device: Device) -> None:
    """Execute forward from run.current_node until the run parks (wait_for), completes (end) or fails. Never raises."""
    flow = (run.context or {}).get("flow") or {}
    nodes = _nodes_by_id(flow)
    steps = 0
    while steps < MAX_NODES_PER_ADVANCE:
        steps += 1
        nid = run.current_node
        node = nodes.get(nid)
        if node is None:
            await _fail(run, f"node '{nid}' not found in flow")
            return
        ntype = node.get("type")
        _mark_visited(run, nid)

        if ntype == "end":
            await _complete(run)
            return
        if ntype == "wait_for":
            # Check state before parking: closes the lost-wakeup window between the action and the park, and
            # stops the run waiting forever on a step that queued nothing.
            if await _wait_already_satisfied(run, device, node):
                nxt = node.get("next")
                if not nxt:
                    await _fail(run, "wait_for node has no 'next' edge")
                    return
                signal = (node.get("params") or {}).get("signal")
                # Two different events, kept apart in log and timeline: refs all arrived early (benign) versus
                # nothing was queued, which is how a device gets released before its config arrives.
                queued = len((run.context or {}).get("expected", {}).get(signal) or [])
                excused = _is_ungated(run, signal) or _gate_off(node.get("params") or {})
                grade = _prior_gap_grade(run, signal) or "broken"
                _consume_expected(run, signal)
                if queued:
                    _timeline(run, nid, f"wait skipped: all {queued} {signal} "
                                        "refs had already arrived")
                elif excused:
                    _timeline(run, nid,
                              f"wait skipped: nothing was queued for {signal}, and "
                              "this step is set not to hold the flow up")
                else:
                    _timeline(run, nid,
                              f"wait skipped: nothing was queued for {signal}, so "
                              "this barrier held nothing back")
                    logger.info("ATC: run %s skipped wait_for '%s': nothing was queued for %s", run.id, nid, signal)
                    _record_gap(run, nid, "barrier_empty", signal, grade=grade)
                run.current_node = nxt
                continue
            await _park(run, node)
            return
        if ntype == "manual_gate":
            # Raises an alert for someone to intervene.
            await _park_manual(run, device, node)
            return

        try:
            next_id = await _execute_node(run, device, node)
        except Exception as exc:
            logger.exception("ATC: node '%s' (%s) failed in run %s", nid, ntype, run.id)
            await _fail(run, f"node '{nid}' ({ntype}) failed: {exc}")
            return

        if not next_id:
            await _fail(run, f"node '{nid}' ({ntype}) has no outgoing edge")
            return
        run.current_node = next_id

    await _fail(run, "flow exceeded the node-per-advance cap (possible loop)")


async def _execute_node(run: FlowRun, device: Device, node: Dict[str, Any]) -> Optional[str]:
    """Run one non-terminal, non-waiting node's side effect; return the id of the next node to execute (branch picks
    on_true/on_false)."""
    ntype = node.get("type")
    params = node.get("params") or {}

    if ntype == "start":
        # Passthrough into the graph; scoping and dedup happened at dispatch.
        return node.get("next")
    if ntype == "assign_tag":
        await _apply_tags(run, device, _str_list(params.get("tags")), add=True)
        return node.get("next")
    if ntype == "remove_tag":
        await _apply_tags(run, device, _str_list(params.get("tags")), add=False)
        return node.get("next")
    if ntype == "set_name":
        await _set_name(run, device, str(params.get("template") or ""))
        return node.get("next")
    if ntype == "install_profiles":
        await _install_profiles(run, device, _str_list(params.get("profile_ids")),
                                gate=not _gate_off(params))
        return node.get("next")
    if ntype == "install_apps":
        await _install_apps(run, device, _str_list(params.get("app_ids")),
                            gate=not _gate_off(params))
        return node.get("next")
    if ntype == "send_command":
        await _send_command(run, device, params.get("command"), params.get("params") or {},
                            gate=not _gate_off(params))
        return node.get("next")
    if ntype == "release_device":
        await _release_device(run, device)
        return node.get("next")
    if ntype == "configure_accounts":
        await _configure_accounts(run, device, params)
        return node.get("next")
    if ntype == "set_firmware_lock":
        await _set_firmware_lock(run, device, params)
        return node.get("next")
    if ntype == "sync_declarations":
        await _sync_declarations(run, device, gate=not _gate_off(params))
        return node.get("next")
    if ntype == "branch":
        cond = params.get("condition") or {}
        result = evaluate_condition(device, cond, list(device.groups or []))
        _timeline(run, node.get("id"), f"branch -> {'true' if result else 'false'}")
        return node.get("on_true") if result else node.get("on_false")

    # Unknown node type: the validator rejects these, but fail safe at runtime.
    raise ValueError(f"unknown node type: {ntype}")


async def _park_manual(run: FlowRun, device: Device, node: Dict[str, Any]) -> None:
    """Park a run on a manual_gate: raise the decision alert and wait for resume_manual_gate. Carries the first
    deadline of the escalation ladder; each expiry makes the alert louder, and the run fails after the last rung."""
    options = _gate_options(node)
    if not options:
        await _fail(run, f"manual_gate '{node.get('id')}' has no valid options")
        return
    alert_id = await _raise_gate_alert(device, run, node, options)
    schedule = _gate_schedule(_authored_gate_timeout(node))
    ctx = run.context or {}
    ctx["gate_ladder"] = {"node": node.get("id"), "schedule": schedule, "step": 0}
    run.context = ctx
    run.status = "waiting"
    run.waiting_signal = "manual"
    run.waiting_ref = alert_id
    run.wait_deadline = _now() + timedelta(minutes=schedule[0])
    first = _duration_phrase(schedule[0])
    what = (f"the run fails in {first}" if len(schedule) == 1
            else f"the alert escalates in {first}")
    labels = " / ".join(o["label"] for o in options)
    _timeline(run, node.get("id"),
              f"awaiting admin decision: {labels}; {what} if nobody answers")
    await _persist(run)
    await _maybe_reconcile(run)


async def _sweep_manual_gate(run: FlowRun) -> int:
    """One expired rung of a parked manual gate. Escalate and re-park until the ladder runs out, then fail through the
    normal path so the run reaches a terminal state, retention can reap it and the snapshot is dropped."""
    # The deadline predicate pins the claim to the park the sweep actually saw: a gate decided and re-parked between the
    # sweep's fetch and this claim has a fresh future deadline, so the stale in-memory run cannot seize it.
    claimed = await _claim_waiting(run.id, waiting_signal="manual", wait_deadline__lte=_now())
    if not claimed:
        return 0
    prior_ref = run.waiting_ref
    run.status = "running"
    run.waiting_signal = None
    run.waiting_ref = None
    run.wait_deadline = None
    ctx = run.context or {}
    ladder = ctx.get("gate_ladder") or {}
    schedule = [float(m) for m in (ladder.get("schedule") or [])
                if isinstance(m, (int, float)) and not isinstance(m, bool) and m > 0]
    step = _int(ladder.get("step"), 0)
    node_id = ladder.get("node") or run.current_node
    if not schedule or step >= len(schedule) - 1:
        # The deadline that just expired was the last one. A deadline with no ladder behind it means the context was
        # hand-edited; fail rather than guess at a schedule.
        await _resolve_gate_alert(run, "nobody answered before the deadline")
        if schedule:
            total = _duration_phrase(schedule[-1])
            await _fail(run, f"nobody answered manual gate '{node_id}' within {total}")
        else:
            await _fail(run, f"manual gate '{node_id}' expired with no decision")
        return 1
    device = await Device.get_or_none(id=run.device_id)
    if device is None:
        await _fail(run, "device no longer exists")
        return 1
    next_step = step + 1
    interval = schedule[next_step] - schedule[step]
    if interval <= 0:
        interval = 1.0
    next_is_final = next_step == len(schedule) - 1
    node = _nodes_by_id(ctx.get("flow") or {}).get(run.current_node) or {}
    alert_id = await _escalate_gate_alert(device, run, node, node_id,
                                          schedule[step], interval, next_is_final)
    ladder["step"] = next_step
    ctx["gate_ladder"] = ladder
    run.context = ctx
    waited = _duration_phrase(schedule[step])
    nxt = _duration_phrase(interval)
    _timeline(run, node_id,
              f"no decision after {waited}; alert escalated, "
              + (f"the run fails in {nxt}" if next_is_final
                 else f"it escalates again in {nxt}"))
    run.status = "waiting"
    run.waiting_signal = "manual"
    run.waiting_ref = alert_id or prior_ref
    run.wait_deadline = _now() + timedelta(minutes=interval)
    await _persist(run)
    return 1


async def _adopt_legacy_gate(run: FlowRun) -> int:
    """Attach the escalation ladder to a gate parked by the pre-ladder code. Those rows carry
    waiting_signal='manual' with no deadline, so the sweep's deadline query never sees them and they wait
    forever. Adopted at rung 0, not failed, since the time to answer starts now."""
    claimed = await FlowRun.filter(
        id=run.id, status="waiting", waiting_signal="manual",
        wait_deadline__isnull=True,
    ).update(status="running")
    if not claimed:
        return 0
    ctx = run.context or {}
    node = _nodes_by_id(ctx.get("flow") or {}).get(run.current_node) or {}
    node_id = node.get("id") or run.current_node
    schedule = _gate_schedule(_authored_gate_timeout(node))
    ctx["gate_ladder"] = {"node": node_id, "schedule": schedule, "step": 0}
    run.context = ctx
    first = _duration_phrase(schedule[0])
    what = (f"the run fails in {first}" if len(schedule) == 1
            else f"the alert escalates in {first}")
    _timeline(run, node_id,
              "gate adopted onto the escalation ladder: it was parked with no "
              f"deadline by an older server; {what} if nobody answers")
    run.status = "waiting"
    run.waiting_signal = "manual"
    run.wait_deadline = _now() + timedelta(minutes=schedule[0])
    await _persist(run)
    logger.info("ATC: run %s adopted onto the manual-gate ladder", run.id)
    return 1


async def resume_manual_gate(run_id: Any, edge_handle: str, actor: str) -> Optional[FlowRun]:
    """Resume a manual_gate run down the chosen edge. Idempotent: a second call (double-click) after the run already
    advanced is a benign no-op."""
    try:
        run = await FlowRun.get_or_none(id=run_id)
        if run is None:
            return None
        if run.status != "waiting" or run.waiting_signal != "manual":
            return run  # already decided / not a gate
        node = _nodes_by_id((run.context or {}).get("flow") or {}).get(run.current_node) or {}
        valid_edges = {o["edge"] for o in _gate_options(node)}
        if edge_handle not in valid_edges:
            logger.warning("ATC: invalid gate edge %r for run %s", edge_handle, run_id)
            return run
        target = node.get(edge_handle)
        # Atomic claim so a concurrent decision / second click can't double-advance.
        claimed = await _claim_waiting(run_id, waiting_signal="manual")
        if not claimed:
            return await FlowRun.get_or_none(id=run_id)
        await _resolve_gate_alert(run, f"{actor} chose {edge_handle}")
        run.status = "running"
        run.waiting_signal = None
        run.waiting_ref = None
        run.wait_deadline = None
        if not target:
            await _fail(run, f"gate option '{edge_handle}' has no target node")
            return run
        run.current_node = str(target)
        _timeline(run, run.current_node, f"gate: {actor} chose {edge_handle}")
        device = await Device.get_or_none(id=run.device_id)
        if device is None:
            await _fail(run, "device no longer exists")
        else:
            await _advance(run, device)
        return run
    except Exception:
        logger.exception("ATC: resume_manual_gate(%s) failed", run_id)
        return None


async def fail_gate_run(run_id: Any, reason: str) -> None:
    """Fail a manual-gated run because its alert was dismissed without a decision (a plain resolve of the gate alert).
    Never leaves the run stuck waiting."""
    try:
        run = await FlowRun.get_or_none(id=run_id)
        if run is None or run.status != "waiting" or run.waiting_signal != "manual":
            return
        claimed = await _claim_waiting(run_id, waiting_signal="manual")
        if not claimed:
            return
        run.status = "running"
        run.waiting_signal = None
        run.waiting_ref = None
        run.wait_deadline = None
        await _fail(run, reason)
    except Exception:
        logger.exception("ATC: fail_gate_run(%s) failed", run_id)


async def _wait_already_satisfied(run: FlowRun, device: Device, node: Dict[str, Any]) -> bool:
    """Whether a wait_for's whole condition is already true at park time. Refless signals (device_info, checkin) wait
    for the next occurrence, so they are never pre-satisfied. A ref-based signal needs every ref the run queued (none
    queued counts as satisfied), read from the deployment and task tables since the device may already have answered."""
    signal = (node.get("params") or {}).get("signal")
    if signal in _REFLESS_SIGNALS:
        return False
    ctx = run.context or {}
    expected = {str(x) for x in ((ctx.get("expected") or {}).get(signal) or [])}
    if not expected:
        return True  # nothing queued -> nothing to wait for
    arrived = {str(x) for x in ((ctx.get("satisfied") or {}).get(signal) or [])}
    pending = sorted(expected - arrived)
    if not pending:
        return True
    from controller.models.tenant import AppDeployment, ProfileDeployment, Task
    try:
        if signal == "profile_installed":
            # One deployment row per (device, profile), so a count is a count of distinct profiles.
            return await ProfileDeployment.filter(
                device_id=device.id, profile_id__in=pending, status="installed"
            ).count() == len(pending)
        if signal == "app_installed":
            return await AppDeployment.filter(
                device_id=device.id, app_id__in=pending, status="installed"
            ).count() == len(pending)
        if signal == "command_ack":
            # Failed counts as answered: the device had its say about the command, even if what it said was no.
            return await Task.filter(
                id__in=pending, status__in=["completed", "failed"]
            ).count() == len(pending)
        if signal == "declaration_applied":
            # A fast sync can report the declarations active before the run parks, so read the stored status.
            reported = getattr(device, "ddm_declaration_status", None) or {}
            for ref in pending:
                state = reported.get(f"mm.cfg.{ref}") or reported.get(str(ref)) or {}
                if not (state.get("active") and state.get("valid") == "valid"):
                    return False
            return True
    except Exception:
        logger.exception("ATC: wait pre-check failed for signal %s", signal)
    return False


# ==State transitions==

async def _park(run: FlowRun, node: Dict[str, Any]) -> None:
    params = node.get("params") or {}
    signal = str(params.get("signal") or "")
    try:
        minutes = int(params.get("timeout_minutes") or 0)
    except (TypeError, ValueError):
        minutes = 0
    run.status = "waiting"
    run.waiting_signal = signal
    expected = (run.context or {}).get("expected", {}).get(signal) or []
    run.waiting_ref = (",".join(str(x) for x in expected)[:255] or None)
    if minutes <= 0:
        # The validator hard-errors a missing timeout_minutes, so this node came from a hand-edited flows.yaml
        # or a legacy migration. Timeline says the 60 was the engine's choice, not the author's.
        minutes = 60
        logger.warning("ATC: run %s parked on '%s' with no timeout in the flow document; defaulting to %dm (this flow "
                       "did not come through the validator)", run.id, node.get("id"), minutes)
        _timeline(run, node.get("id"),
                  "wait_for carries no timeout_minutes, so the engine applied its 60 minute default")
    run.wait_deadline = _now() + timedelta(minutes=minutes)
    _timeline(run, node.get("id"),
              f"waiting for all {len(expected)} {signal} refs (timeout {minutes}m)"
              if len(expected) > 1 else f"waiting for {signal} (timeout {minutes}m)")
    # An ADE device parked mid-flow is held in Setup Assistant, if the flow releases it later, so open the green alert
    # that carries a manual release.
    device = await Device.get_or_none(id=run.device_id)
    if device is not None:
        await _ensure_in_setup_alert(device, run)
    await _persist(run)
    await _maybe_reconcile(run)


async def _complete(run: FlowRun) -> None:
    ctx = run.context or {}
    unverified = ctx.get("unverified")
    if unverified:
        # The run let the device out of Setup Assistant while a barrier held less than the flow asked for.
        # Terminate as failed at the release node, not the end node, so the alert points at the step that did it.
        run.current_node = unverified.get("node") or run.current_node
        await _fail(run, "released the device from Setup Assistant before its "
                         f"configuration was confirmed: {unverified.get('body')}")
        return
    if ctx.get("in_setup") and not ctx.get("released"):
        # Opened an in-setup alert but finished without reaching release_device (usually a branch went the
        # other way). The device is still on Remote Management, so the alert stays open.
        _timeline(run, run.current_node,
                  "reached the end without releasing the device, which is still held in Setup Assistant")
    run.status = "completed"
    run.current_node = None
    run.waiting_signal = None
    run.waiting_ref = None
    run.wait_deadline = None
    run.completed_at = _now()
    _timeline(run, None, "completed")
    _drop_flow_snapshot(run)
    await _persist(run)
    await _settle_in_setup_on_terminal(run)
    await _resolve_run_failed_alert(run)
    await _maybe_reconcile(run)


async def _fail(run: FlowRun, message: str) -> None:
    ctx = run.context or {}
    # Whether this run was holding the device at the Remote Management screen when it died, which decides both the
    # alert's severity and whether the in-setup alert survives.
    held_in_setup = bool(ctx.get("in_setup")) and not ctx.get("released")
    failed_at = run.current_node
    run.status = "failed"
    run.error = message
    run.waiting_signal = None
    run.waiting_ref = None
    run.wait_deadline = None
    run.completed_at = _now()
    _timeline(run, failed_at, f"failed: {message}")
    logger.info("ATC: run %s failed: %s", run.id, message)
    _drop_flow_snapshot(run)
    await _persist(run)
    await _settle_in_setup_on_terminal(run)
    await _raise_run_failed_alert(run, failed_at, message, held_in_setup)
    await _maybe_reconcile(run)


async def _persist(run: FlowRun) -> None:
    """Full save of a FlowRun at a checkpoint. A run is only ever advanced by one caller at a time (the waiting->running
    claim is atomic), so a full save can't clobber a concurrent writer the way a Device row could."""
    try:
        await run.save()
    except Exception:
        logger.exception("ATC: persisting run %s failed", run.id)


async def _persist_context(run: FlowRun) -> None:
    """Save the context of a run that is staying exactly where it is.

    Narrower than _persist because a run recording a partial barrier is still parked and holds no claim on itself, so
    a full save could overwrite status or wait_deadline changed meanwhile by the sweep or another signal."""
    try:
        await run.save(update_fields=["context", "updated_at"])
    except Exception:
        logger.exception("ATC: persisting context of run %s failed", run.id)


async def _maybe_reconcile(run: FlowRun) -> None:
    """If the run changed device state that drives scoping (tags to groups), request a reconcile so profile and app
    deployment follows. Through the coalescer rather than a reconcile of its own: a fleet coming through enrollment
    finishes runs in bursts, and one tenant-wide pass covers all of them."""
    if not (run.context or {}).get("dirty"):
        return
    try:
        from controller.services.reconciler import request_reconcile
        request_reconcile(str(run.tenant_id))
    except Exception:
        logger.exception("ATC: scheduling reconcile failed for run %s", run.id)
