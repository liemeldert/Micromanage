"""ATC (Air Traffic Control) flow execution engine.

Runs a flow from flows.yaml per device as an async state machine (FlowRun).
"""

import copy
import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Any, Dict, List, Optional, Set, Tuple

from controller.models.tenant import Alert, Device, DeviceSecret, FlowRun, Tenant
from controller.services import tenant_config
# The one definition of which severity strings exist; restating it as a literal here would coerce every renamed value to
# "yellow" in _gate_severity. The validator's module body imports nothing from controller, so this is not a cycle.
from controller.services.flow_step_catalog import DRAFT_KEYS
from controller.services.scoping import (
    device_in_rollout, device_platform_category, evaluate_condition, evaluate_scope,
)
# The triage ladder shared with the compliance board, which imports the same table from services/severity.py. An
# unrecognised value ranks below every real one there, where a local copy of the scale would tie it with green.
from controller.services.severity import escalate as _escalate_severity, rank as _severity_rank
from controller.utils.yaml_validator import VALID_SEVERITIES
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

# Floor under a schedule start's interval, for a document that never went through flow_gate's save-time check
# (hand edit, restored snapshot, config management).
MIN_SCHEDULE_INTERVAL_MINUTES = int(
    os.getenv("ATC_MIN_SCHEDULE_INTERVAL_MINUTES", "15"))

# How many unfinished runs one device may have at once, across every flow. Enrollment events are exempt, so this cap can
# never leave a device on the Remote Management screen with its onboarding flow refused a run.
MAX_ACTIVE_RUNS_PER_DEVICE = int(os.getenv("ATC_MAX_ACTIVE_RUNS_PER_DEVICE", "8"))


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

# Run states that count as "active" for supersede/dedup.
_ACTIVE_STATES = ["running", "waiting"]

# Events that supersede a device's prior run from the same start, since a fresh enroll re-runs onboarding. Everything
# else dedups instead, skipping while a run is active.
_SUPERSEDE_EVENTS = frozenset({"enroll_dep", "enroll_profile"})

# Default gap between two check-in-started runs of one start on one device; without it a check-in-triggered
# install can re-fire itself forever.
CHECKIN_COOLDOWN_DEFAULT_MINUTES = 60

# Signals where any occurrence for the device resumes a wait_for. The rest have to match what the run queued in
# context['expected'], and every ref has to arrive before the barrier lifts.
_REFLESS_SIGNALS = frozenset({"device_info", "checkin", "ddm_status"})

# Ceiling on the gap ledger; a validated flow already bounds entries by node count, this is for a hand-edited one.
GAP_LEDGER_MAX = 100

# Ledger entry kinds: not_queued (a step named ids and queued fewer), barrier_empty (a wait_for was skipped),
# never_arrived (a barrier gave up on refs the device never reported).
GAP_KINDS = frozenset({"not_queued", "barrier_empty", "never_arrived"})

# How bad a gap is: policy means the device was never entitled (scope, rollout wave); broken means the engine
# could not deliver something the flow named.
GAP_GRADES = ("policy", "broken")


# ==Loading + hashing==

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
    the only place drafts are filtered out; relaxing this filter is not a refactor, see
    docs/controller/services/atc.md. Returned without a copy: callers that keep the document take their own."""
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


# Flow-level keys the fingerprint below ignores: they say where a flow sits in the document (permanent flag,
# draft review metadata), not what a device executes. Hashing them would flag a finished run as edited.
_UNHASHED_FLOW_KEYS = frozenset({"permanent"}) | frozenset(DRAFT_KEYS)


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


def _scope_matches(device: Device, device_groups: List[str],
                   scope: Optional[Dict[str, Any]]) -> bool:
    """A flow trigger's match scope. An empty match takes every device; otherwise the shared scope engine decides."""
    scope = scope or {}
    if not any(scope.get(k) for k in
               ("groups", "conditions", "include_devices", "exclude_devices")):
        return True
    return evaluate_scope(device, device_groups, scope)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _int(value: Any, default: int = 0) -> int:
    """Coerce a possibly-malformed value (flows.yaml can be hand-edited/restored outside the validated PUT) to int
    without raising."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ==Entry points==

async def _has_active_run(device_id: Any, flow_id: str, start_id: str) -> bool:
    """True when this (device, flow, start) already has a running or waiting run. flow_id is part of the key
    because start node ids repeat across flows (per-flow counter); without it one flow's run would silence
    another's trigger."""
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


def _as_aware(value: Any) -> Optional[datetime]:
    """Normalize a started_at read back out of the database. Postgres hands back an aware datetime, but sqlite
    (the verify suites) can hand back naive or an ISO string; date arithmetic on that raises, and the sweep
    would swallow it per device and quietly never launch."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


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
    """When this (device, start) last ran on this event kind, whatever state the run ended in; status is not
    filtered, since both callers just want how long it has been since this start last did anything. flow_id is
    required because start ids repeat across flows (per-flow counter, reused after deletion). Bounded by
    retention: a swept-away run is invisible here."""
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


def _checkin_cooldown_minutes(params: Dict[str, Any]) -> int:
    """How long a check-in start waits between runs. An authored 0 is honoured; negative reads as zero. A bool
    takes the default rather than int()'s 1/0, since YAML turns a hand-typed `yes` into True."""
    value = params.get("cooldown_minutes")
    if isinstance(value, bool):
        return CHECKIN_COOLDOWN_DEFAULT_MINUTES
    minutes = _int(value, CHECKIN_COOLDOWN_DEFAULT_MINUTES)
    return max(minutes, 0)


def _truthy_param(value: Any) -> bool:
    """A flows.yaml flag read as an author would mean it. Plain truthiness is wrong for a hand-edited document:
    a quoted "false" is a non-empty string. Strings are read as words; everything else keeps Python's answer."""
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "on", "1")
    return bool(value)


async def _checkin_start_is_due(device: Device, node: Dict[str, Any],
                                flow_id: str, start_id: str) -> bool:
    """Whether this check-in start may run now: once:true means at most one run ever, otherwise the cooldown
    measures from the last checkin-kind run (_last_run_for_device). A failed lookup answers no, unlike every
    other guard here."""
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
    """Cancel active runs from this same flow and start on the device, since a fresh enroll re-runs onboarding.
    Scoped to the one start, so a concurrent run from another flow or a schedule is left alone. Row by row, not
    a bulk update, because dropping the pinned flow snapshot needs a JSON column edit an UPDATE can't express;
    there is normally at most a handful of such runs."""
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
        logger.exception("ATC: superseding prior runs failed for start %s of "
                         "flow %s", start_id, flow_id)


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
        logger.warning("ATC: device %s already has %d unfinished runs, at the "
                       "ATC_MAX_ACTIVE_RUNS_PER_DEVICE cap; not starting more "
                       "for %s", device.id, len(active), event_kind)
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
    """Manually start a run from a specific start node (testing, API). Supersedes an active run from the same
    flow and start. Without flow_id every enabled flow is searched, and an id present in more than one is
    refused rather than guessed at, since picking one would run the wrong flow against a real device. Returns
    None if the node does not exist, is not a start node, is ambiguous, or the start fails."""
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


def flows_with_start(tenant_id: str, start_node_id: str) -> List[str]:
    """Ids of the enabled flows holding this start node. The API uses it to say which flows an ambiguous manual start
    could have meant."""
    try:
        return [str(f.get("id")) for f in _enabled_flows(str(tenant_id))
                if (_nodes_by_id(f).get(start_node_id) or {}).get("type") == "start"]
    except Exception:
        logger.exception("ATC: start-node lookup failed for %s", start_node_id)
        return []


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
                claimed = await FlowRun.filter(id=run.id, status="waiting").update(
                    status="running", waiting_signal=None, waiting_ref=None,
                    wait_deadline=None,
                )
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
            claimed = await FlowRun.filter(id=run.id, status="waiting").update(
                status="running", waiting_signal=None, waiting_ref=None, wait_deadline=None,
            )
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
    """Launch runs for schedule start nodes whose interval has elapsed for an in-scope device. Called each poll
    tick; the interval, not the tick, sets the cadence. Most-overdue devices go first, under a per-tenant launch
    cap shared across flows (see the round-robin below), which bounds what one tenant costs the poller rather
    than what one flow costs the tenant."""
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
        if interval < MIN_SCHEDULE_INTERVAL_MINUTES:
            # A document that did not come through services.flow_gate. Clamping is the safe reading, and it is logged
            # because the author is looking at a number the engine is not using.
            logger.warning("ATC: schedule start %s of flow %s asks for every %dm, "
                           "below the ATC_MIN_SCHEDULE_INTERVAL_MINUTES floor of "
                           "%dm; running it at the floor",
                           start_id, flow_id, interval, MIN_SCHEDULE_INTERVAL_MINUTES)
            interval = MIN_SCHEDULE_INTERVAL_MINUTES
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
                    logger.info("ATC: run %s skipped wait_for '%s': nothing was "
                                "queued for %s", run.id, nid, signal)
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


# ==Node side effects==

async def _apply_tags(run: FlowRun, device: Device, tags: List[str], *, add: bool) -> None:
    """Additive/idempotent tag write (mirrors the manual tag endpoint), then recompute groups so a later branch/scope
    sees fresh membership."""
    if not tags:
        return
    # Re-read tags immediately before the write: this copy is routinely stale (three processes write tags). Not
    # atomic even so; a tag written between this refresh and the save below is lost.
    fresh = await Device.get_or_none(id=device.id)
    if fresh is not None:
        device.tags = list(fresh.tags or [])
    current = [str(t) for t in (device.tags or [])]
    before = set(current)
    if add:
        result = current + [t for t in tags if t not in before]
    else:
        drop = set(tags)
        result = [t for t in current if t not in drop]
    if set(result) == before:
        _timeline(run, run.current_node, f"{'assign' if add else 'remove'}_tag: no change")
        return
    device.tags = result
    await device.save(update_fields=["tags"])
    # A tag change can shift scoping (a profile or group may key off a tag) even when group names are unchanged, so
    # always request a reconcile.
    _mark_dirty(run)
    # Persist recomputed groups only if membership actually shifted
    groups_before = set(device.groups or [])
    _recompute_groups(device)
    if set(device.groups or []) != groups_before:
        try:
            await device.save(update_fields=["groups"])
        except Exception:
            logger.exception("ATC: persisting groups after tag change failed")
    added = sorted(set(result) - before)
    removed = sorted(before - set(result))
    _timeline(run, run.current_node, f"tags added={added} removed={removed}")
    from controller.services.audit import record_tag_change
    await record_tag_change(device, added=added, removed=removed, source="atc",
                            source_ref=f"{run.flow_id}:{run.current_node}")


def _recompute_groups(device: Device) -> None:
    """Recompute device.groups in-memory from current tags/facts (best-effort)."""
    try:
        from controller.services.group_manager import GroupManager
        groups_config = tenant_config.load_groups(str(device.tenant_id))
        device.groups = GroupManager(str(device.tenant_id)).evaluate_device_groups(
            device, groups_config
        )
    except Exception:
        logger.exception("ATC: group recompute failed for %s", device.serial_number)


async def _set_name(run: FlowRun, device: Device, template: str) -> None:
    from controller.services.naming import resolve_name

    resolved = resolve_name(template, device)
    if not resolved:
        _timeline(run, run.current_node, "set_name: template rendered empty; skipped")
        return
    device.name = resolved
    await device.save(update_fields=["name"])
    _timeline(run, run.current_node, f"set_name -> {resolved!r}")
    # Pushed fire-and-forget: the MDM round-trip, up to the client timeout, must not block _advance on the enroll or
    # webhook hot path. set_name has no wait_for signal, so nothing in the flow depends on its completion.
    if device.enrollment_state != "enrolled" or not device.udid:
        return
    from controller.services.reconciler import _spawn
    _spawn(_push_device_name(device, resolved, run.flow_id))


async def _push_device_name(device: Device, resolved: str, flow_id: str) -> None:
    """Background SetName push and audit task, spawned by _set_name so the MDM round-trip never blocks the hot path."""
    from controller.services.mdm_connector import MDMConnector
    from controller.services.task_manager import TaskManager

    tenant = await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None:
        return
    task = await TaskManager().create_task(
        tenant=tenant, task_type="set_name",
        description=f"ATC rename {device.serial_number} to {resolved!r}",
        device=device, user=f"atc:{flow_id}", details={},
    )
    connector = MDMConnector()
    try:
        result = await connector.set_device_name(device.udid, resolved)
        task.details["command_uuid"] = result.get("command_uuid")
        task.status = "running"
        await task.save()
    except Exception as exc:
        task.status = "failed"
        task.error = str(exc)
        await task.save()
        logger.warning("ATC: set_name push failed for %s: %s", device.udid, exc)
    finally:
        await connector.close()


async def _install_profiles(run: FlowRun, device: Device, profile_ids: List[str],
                            gate: bool = True) -> None:
    """Queue InstallProfile for the named profiles, regardless of scope. Marked under
    profile_manager.INSTALL_SOURCE_KEY or the sync loop's removal pass would undo this node next cycle. With
    gate off nothing waits on these and misses don't reach the gap ledger."""
    from controller.services.profile_manager import (
        INSTALL_SOURCE_KEY, ProfileManager, flow_source,
    )
    from controller.services.reconciler import _spawn
    from controller.services.task_handlers import handle_profile_install_task
    from controller.services.task_manager import TaskManager

    if not profile_ids:
        return
    profiles = tenant_config._load(str(device.tenant_id), "profiles.yaml").get("profiles", [])
    by_id = {p.get("id"): p for p in profiles if isinstance(p, dict)}
    tenant = await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None:
        return
    tm = TaskManager()
    queued: List[str] = []
    skipped: List[Dict[str, str]] = []
    for pid in profile_ids:
        info = by_id.get(pid)
        if not info:
            # Unreachable through the product (the validator hard-errors on this); reaching here means something
            # skipped that path, so it goes to the log as well as the timeline.
            _timeline(run, run.current_node, f"install_profiles: unknown profile {pid}; skipped")
            logger.warning("ATC: run %s asked for profile '%s', which is not in "
                           "profiles.yaml; the flow bypassed validation",
                           run.id, pid)
            skipped.append({"id": pid, "grade": "broken",
                            "why": "no profile with that id is in profiles.yaml"})
            continue
        task = await tm.create_task(
            tenant=tenant, task_type="profile_install",
            description=f"ATC install profile {info.get('name', pid)}",
            device=device, user=f"atc:{run.flow_id}",
            # The task row outlives the install and a profile definition can carry a Wi-Fi PSK, 802.1X password
            # or SCEP challenge, so it gets those replaced plus a digest; see ProfileManager.install_task_details.
            details={**ProfileManager.install_task_details(
                info, ProfileManager.desired_hash(info)),
                     INSTALL_SOURCE_KEY: flow_source(run.flow_id)},
        )
        # Bind the device and the tenant fetched above, so the handler does not re-read both rows per queued profile,
        # and the definition itself, which the row no longer carries whole. See task_handlers._resolve_device_tenant for
        # what that snapshot covers.
        _spawn(tm.execute_task(
            task, partial(handle_profile_install_task, device=device, tenant=tenant,
                          profile_info=info),
        ))
        queued.append(pid)
    if not gate:
        _mark_ungated(run, "profile_installed")
    elif queued:
        _expect(run, "profile_installed", queued)
    if skipped and gate:
        _record_gap(run, run.current_node, "not_queued", "profile_installed",
                    items=skipped, grade="broken")
    if queued:
        _timeline(run, run.current_node, f"install_profiles queued={queued}"
                  + ("" if gate else " (gate off: nothing waits on these)"))
    else:
        # Nothing queued means a following wait_for(profile_installed) has an empty expectation and waves the run
        # straight through. Recorded here, where the reason is still visible, rather than several nodes later.
        _timeline(run, run.current_node,
                  f"install_profiles: none of {profile_ids} were queued, so a "
                  "following wait_for(profile_installed) has nothing to wait for")
        logger.info("ATC: run %s queued no profiles out of %s", run.id, profile_ids)


def _why_app_not_queued(device: Device, app_cfg: Optional[Dict[str, Any]],
                        groups: List[str]) -> Dict[str, str]:
    """Why an app the flow named did not get queued for this device: an unknown id, a device not scoped to any
    version, or a rollout wave that has not opened. Recomputed from app_manager's own primitives, since
    evaluate_device_apps returns what to install and not why it left the rest out."""
    if app_cfg is None:
        return {"grade": "broken", "why": "no app with that id is in apps.yaml"}
    versions = app_cfg.get("versions") or []
    if not versions:
        return {"grade": "broken", "why": "the app has no versions in apps.yaml"}
    now = _now()
    for version in reversed(versions):
        if not evaluate_scope(device, groups, version):
            continue
        rollout = version.get("rollout")
        if rollout and not device_in_rollout(
            device, rollout, f"app:{app_cfg.get('id')}:{version.get('version')}", now):
            return {"grade": "policy",
                    "why": "held back by a gradual rollout, so this device's wave "
                           "has not opened yet"}
    return {"grade": "policy",
            "why": "the device is not scoped into any version of it"}


async def _install_apps(run: FlowRun, device: Device, app_ids: List[str],
                        gate: bool = True) -> None:
    """Queue InstallApplication for the named apps, using the version the device is entitled to. Reuses the
    reconciler's evaluation so version and rollout stay consistent; an app not scoped in is skipped and logged.
    Gate off is how an author says a rolled-out app must not hold a device in Setup Assistant."""
    from controller.services.app_manager import AppManager
    from controller.services.profile_manager import INSTALL_SOURCE_KEY, flow_source
    from controller.services.reconciler import _spawn
    from controller.services.task_handlers import handle_app_install_task
    from controller.services.task_manager import TaskManager

    if not app_ids:
        return
    tenant = await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None:
        return
    apps_config = tenant_config._load(str(device.tenant_id), "apps.yaml").get("apps", [])
    groups_config = tenant_config.load_groups(str(device.tenant_id))
    by_cfg = {a.get("id"): a for a in apps_config if isinstance(a, dict)}
    try:
        applicable = await AppManager(tenant).evaluate_device_apps(device, apps_config, groups_config)
    except Exception:
        logger.exception("ATC: evaluating apps failed for %s", device.serial_number)
        applicable = []
    by_id = {a["app_id"]: a for a in applicable}
    tm = TaskManager()
    queued: List[str] = []
    skipped: List[Dict[str, str]] = []
    for aid in app_ids:
        info = by_id.get(aid)
        if not info:
            reason = _why_app_not_queued(device, by_cfg.get(aid), list(device.groups or []))
            _timeline(run, run.current_node,
                      f"install_apps: {aid} was not queued because {reason['why']}")
            skipped.append({"id": aid, **reason})
            continue
        task = await tm.create_task(
            tenant=tenant, task_type="app_install",
            description=f"ATC install {info.get('name', aid)} v{info.get('version')}",
            device=device, user=f"atc:{run.flow_id}",
            # Marked like the profile half, so a scope edited after install, or a rollout wave closing behind
            # the device, does not retire an app the flow put there and reported as delivered.
            details={"app_info": info,
                     INSTALL_SOURCE_KEY: flow_source(run.flow_id)},
        )
        _spawn(tm.execute_task(
            task, partial(handle_app_install_task, device=device, tenant=tenant),
        ))
        queued.append(aid)
    if not gate:
        _mark_ungated(run, "app_installed")
    elif queued:
        _expect(run, "app_installed", queued)
    if skipped and gate:
        _record_gap(run, run.current_node, "not_queued", "app_installed", items=skipped,
                    grade=("broken" if any(s["grade"] == "broken" for s in skipped)
                           else "policy"))
    if queued:
        _timeline(run, run.current_node, f"install_apps queued={queued}"
                  + ("" if gate else " (gate off: nothing waits on these)"))
    else:
        # Routine: an app under a gradual rollout is held back from most of the fleet on day one and this node skips it.
        # The knock-on is that a following wait_for(app_installed) then has an empty expectation and lets the run past.
        _timeline(run, run.current_node,
                  f"install_apps: none of {app_ids} were queued, so a following "
                  "wait_for(app_installed) has nothing to wait for")
        logger.info("ATC: run %s queued no apps out of %s (scope or rollout)",
                    run.id, app_ids)


async def _send_command(run: FlowRun, device: Device, command: Any,
                        params: Dict[str, Any], gate: bool = True) -> None:
    """Send a non-destructive catalog command through the shared audited path. Destructive commands are refused here as
    well as by the validator."""
    from controller.services.device_commands import (
        CommandError, CommandSendError, dispatch_catalog_command,
    )

    tenant = await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None:
        return
    if not gate:
        _mark_ungated(run, "command_ack")
    try:
        outcome = await dispatch_catalog_command(
            device, str(command), params or {},
            user=f"atc:{run.flow_id}", tenant=tenant, allow_destructive=False,
        )
        if gate:
            _expect(run, "command_ack", [outcome["task_id"]])
        _timeline(run, run.current_node, f"send_command {command} -> task {outcome['task_id']}")
    except CommandSendError as exc:
        # The transport failed but a failed audit task exists, so record it and a following wait_for(command_ack)
        # resolves at once instead of stalling.
        tid = getattr(exc, "task_id", None)
        if tid and gate:
            _expect(run, "command_ack", [tid])
        _timeline(run, run.current_node, f"send_command {command} failed to send: {exc}")
        logger.warning("ATC: send_command %s transport-failed in run %s: %s",
                       command, run.id, exc)
    except CommandError as exc:
        # Invalid command or missing param, so no task was created. A following wait_for(command_ack) then has an empty
        # expectation and is skipped.
        _timeline(run, run.current_node, f"send_command {command} rejected: {exc}")
        logger.warning("ATC: send_command %s rejected in run %s: %s", command, run.id, exc)
        if gate:
            _record_gap(run, run.current_node, "not_queued", "command_ack", grade="broken",
                        items=[{"id": str(command), "grade": "broken",
                                "why": f"the command was rejected before it was sent ({exc})"}])


async def _sync_declarations(run: FlowRun, device: Device, gate: bool = True) -> None:
    """Queue a DDM DeclarativeManagement sync for the device. sync_device answers four ways, three falsy: True
    (sent), EnqueueFailed, SyncHeldOff, or a plain False (already in sync); the two sentinels are tested by
    type, not truthiness, before anything reads the result, and only they count as gaps. The backoff is never
    bypassed for a flow."""
    from controller.services import ddm_manager

    tenant = await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None:
        return
    if not gate:
        _mark_ungated(run, "declaration_applied")
    if not tenant.ddm_enabled or device.enrollment_state != "enrolled" \
        or not device.udid or not ddm_manager.device_supports_ddm(device):
        _timeline(run, run.current_node,
                  "sync_declarations: DDM disabled or unsupported; skipped")
        if gate:
            _record_gap(run, run.current_node, "not_queued", "declaration_applied",
                        grade="policy",
                        items=[{"id": "declarations", "grade": "policy",
                                "why": "DDM is off for this tenant, or this device "
                                       "does not support it"}])
        return
    try:
        queued = await ddm_manager.sync_device(device, reason="flow")
    except Exception as exc:
        # Kept for a failure neither this node nor ddm_manager anticipated; a refused enqueue comes back as
        # EnqueueFailed below instead.
        _timeline(run, run.current_node,
                  f"sync_declarations: sync failed ({exc}); continuing")
        logger.warning("ATC: sync_declarations failed in run %s: %s", run.id, exc)
        if gate:
            _record_gap(run, run.current_node, "not_queued", "declaration_applied",
                        grade="broken",
                        items=[{"id": "declarations", "grade": "broken",
                                "why": f"the sync could not be queued ({exc})"}])
        return
    if isinstance(queued, (ddm_manager.EnqueueFailed, ddm_manager.SyncHeldOff)):
        # Nothing reached the device, so no expectation is registered and a following wait_for holds nothing.
        # Both sentinels get separate sentences: NanoMDM refusing now, vs. an earlier refusal still backing off.
        why = (f"an earlier refusal is still backing off ({queued.reason})"
               if isinstance(queued, ddm_manager.SyncHeldOff)
               else f"the sync could not be queued ({queued.reason})")
        _timeline(run, run.current_node, f"sync_declarations: {why}")
        if gate:
            _record_gap(run, run.current_node, "not_queued", "declaration_applied",
                        grade="broken",
                        items=[{"id": "declarations", "grade": "broken", "why": why}])
        return
    # Expect the yaml-authored declarations (bare ids) so a following wait_for(declaration_applied) resolves; with none
    # scoped the expectation stays empty and such a wait is vacuously satisfied.
    refs: List[str] = []
    try:
        declarations = await ddm_manager.compute_device_declarations(device, tenant)
        refs = [d["Identifier"][len("mm.cfg."):] for d in declarations
                if d["Identifier"].startswith("mm.cfg.")
                and d["Identifier"] != "mm.cfg.status-subscriptions"]
        if refs and gate:
            _expect(run, "declaration_applied", refs)
    except Exception:
        logger.exception("ATC: computing declaration refs failed for %s",
                         device.serial_number)
    if not refs and gate:
        _record_gap(run, run.current_node, "not_queued", "declaration_applied",
                    grade="policy",
                    items=[{"id": "declarations", "grade": "policy",
                            "why": "no declarations from declarations.yaml are scoped "
                                   "to this device"}])
    _timeline(run, run.current_node,
              "sync_declarations: sync queued" if queued
              else "sync_declarations: already in sync")


def _is_ade_device(device: Device) -> bool:
    """Whether this device came in through Automated Device Enrollment. Three signals, any one a yes:
    SecurityInfo.ManagementStatus.EnrolledViaDEP, a DEP server/profile from the ABM/ASM sync, or
    enrollment_source: ade. A yes from any source wins; a no is only the absence of all three, since staleness
    is asymmetric here."""
    attrs = getattr(device, "attributes", None) or {}
    sec = attrs.get("SecurityInfo")
    mgmt = (sec or {}).get("ManagementStatus") if isinstance(sec, dict) else None
    if isinstance(mgmt, dict) and mgmt.get("EnrolledViaDEP") is True:
        return True
    if getattr(device, "dep_server_id", None) or getattr(device, "dep_profile_uuid", None):
        return True
    return attrs.get("enrollment_source") == "ade"


async def _release_device(run: FlowRun, device: Device) -> None:
    """Send DeviceConfigured to release an ADE device from Setup Assistant. Apple accepts this only on ADE
    devices awaiting configuration (iOS 9+ supervised, macOS 10.11+, tvOS 10.2+ supervised); anything else is
    skipped with a reason in the timeline. Fire-and-forget, like set_name: the MDM round-trip must not block
    _advance, and nothing downstream depends on the ack."""
    if device.enrollment_state != "enrolled" or not device.udid:
        _timeline(run, run.current_node, "release_device: device not enrolled; skipped")
        return
    if not _is_ade_device(device):
        _timeline(run, run.current_node,
                  "release_device: not an Automated Enrollment device, so it was never "
                  "held in Setup Assistant; skipped")
        return
    from controller.services.reconciler import _spawn
    _spawn(_push_device_configured(device, f"atc:{run.flow_id}"))
    _timeline(run, run.current_node, "release_device: DeviceConfigured queued")
    # Only a run carrying this flag may resolve the in-setup alert when it ends. Without it, a run that failed halfway
    # would close the alert for a device still sitting at Remote Management.
    ctx = run.context or {}
    ctx["released"] = True
    run.context = ctx
    _guard_release(run, device)
    # Best-effort clear of the green in-setup alert; a no-op if none is open.
    await _resolve_in_setup_alert(device, "released by flow")


def _guard_release(run: FlowRun, device: Device) -> None:
    """Check the gap ledger at the moment a device is let out of Setup Assistant, the last point where anything
    still knows what the barriers above did not get. Does not hold the device back (a gradual rollout emptying
    a barrier is by design, not a break); instead it releases and fails the run with a board item naming what's
    missing. Red when the flow named something undeliverable, yellow when it's just policy holding an app back."""
    gaps = list((run.context or {}).get("gaps") or [])
    if not gaps:
        return
    severity = "red" if any(g.get("grade") == "broken" for g in gaps) else "yellow"
    body = _gap_body(gaps)
    ctx = run.context or {}
    ctx["unverified"] = {"node": run.current_node, "severity": severity,
                         "body": body, "gaps": gaps}
    run.context = ctx
    _timeline(run, run.current_node,
              "release_device: the device was released, but nothing had confirmed "
              f"its configuration: {body}")
    logger.warning("ATC: run %s released %s without confirming its configuration: %s",
                   run.id, device.serial_number, body)


async def release_device_manual(device: Device, actor: str) -> Tuple[bool, Optional[str]]:
    """Admin-triggered release from Setup Assistant, reusing the same audited DeviceConfigured push. Returns
    (True, None) when queued, or (False, reason): a device with no MDM channel needs looking at, while one that
    enrolled over the air was never held in Setup Assistant to begin with."""
    if device.enrollment_state != "enrolled" or not device.udid:
        return False, (f"Device is {device.enrollment_state}, so it has no MDM "
                       "channel to release it over.")
    if not _is_ade_device(device):
        logger.info("ATC: manual release skipped for %s (not an ADE device)",
                    device.serial_number)
        return False, ("This device did not come in through Automated Device "
                       "Enrollment, so it was never held in Setup Assistant and "
                       "there is nothing to release it from.")
    from controller.services.reconciler import _spawn
    _spawn(_push_device_configured(device, f"admin:{actor}"))
    await _resolve_in_setup_alert(device, f"released by {actor}")
    return True, None


async def _push_device_configured(device: Device, user: str) -> None:
    """Background DeviceConfigured push and audit task, spawned by callers so the MDM round-trip never blocks the hot
    path. user is the audit actor."""
    from controller.services.mdm_connector import MDMConnector
    from controller.services.task_manager import TaskManager

    tenant = await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None:
        return
    task = await TaskManager().create_task(
        tenant=tenant, task_type="device_configured",
        description=f"Release {device.serial_number} from Setup Assistant",
        device=device, user=user, details={},
    )
    connector = MDMConnector()
    try:
        result = await connector.device_configured(device.udid)
        task.details["command_uuid"] = result.get("command_uuid")
        task.status = "running"
        await task.save()
    except Exception as exc:
        task.status = "failed"
        task.error = str(exc)
        await task.save()
        logger.warning("ATC: DeviceConfigured push failed for %s: %s", device.udid, exc)
    finally:
        await connector.close()


#  Account + firmware provisioning (managed-secret escrow)

async def _configure_accounts(run: FlowRun, device: Device, params: Dict[str, Any]) -> None:
    """Send AccountConfiguration, escrowing credentials via services.device_secrets. Awaited inline, not
    spawned, so it lands before a later release_device's DeviceConfigured. Requires macOS, ADE origin, and
    AwaitingConfiguration (requiresdep: true per
    https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/account.configuration.yaml).
    Both non-admin primary modes need a managed admin or the node refuses (flow_step_catalog.ACCOUNT_ADMIN_REQUIREMENT).
    """
    if device.enrollment_state != "enrolled" or not device.udid:
        _timeline(run, run.current_node, "configure_accounts: device not enrolled; skipped")
        return

    platform = device_platform_category(getattr(device, "device_model", ""))
    if platform != "Mac":
        _timeline(run, run.current_node,
                  f"configure_accounts: macOS only, this is a {platform}; skipped")
        return

    if not _is_ade_device(device):
        _timeline(run, run.current_node,
                  "configure_accounts: this Mac did not enrol through Automated Device "
                  "Enrollment, so Setup Assistant never asked the server about its "
                  "accounts and nothing this step describes would be created; skipped")
        return

    from controller.services import account_hash, device_secrets
    from controller.services.flow_step_catalog import ACCOUNT_ADMIN_REQUIREMENT
    from controller.services.mdm_connector import MDMConnector
    from controller.services.task_manager import TaskManager

    tenant = await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None:
        return

    mode = params.get("primary_account")
    skip_primary = mode == "skip"
    set_regular = mode == "prompt_standard"
    lock_primary = bool(params.get("lock_primary_account"))
    full_name = str(params.get("primary_full_name") or "").strip() or None
    short_name = str(params.get("primary_short_name") or "").strip() or None

    auto_admins: Optional[List[Dict[str, Any]]] = None
    admin_short: Optional[str] = None
    admin_secret: Optional[DeviceSecret] = None
    prior_escrow: Optional[Dict[str, Any]] = None
    if params.get("managed_admin"):
        admin_short = str(params.get("managed_admin_shortname") or "").strip() or "mmadmin"
        admin_full = str(params.get("managed_admin_fullname") or "").strip() or "Managed Admin"
        hidden = params.get("managed_admin_hidden")
        hidden = True if hidden is None else bool(hidden)
        src = params.get("managed_admin_password_source") or "generate"
        password = (str(params.get("managed_admin_password") or "")
                    if src == "static" else account_hash.generate_password())
        if not password:
            _timeline(run, run.current_node,
                      "configure_accounts: managed-admin password empty; managed admin skipped")
        else:
            # A missing encryption key raises here and fails the node rather than strand an unreachable admin
            # account. Snapshot the row first: a re-enrolment overwrites a password the Mac may still be using,
            # and a failed send has to put it back.
            prior_escrow = await device_secrets.snapshot(
                device, DeviceSecret.KIND_MANAGED_ADMIN)
            admin_secret = await device_secrets.escrow(
                device, DeviceSecret.KIND_MANAGED_ADMIN, password,
                label=admin_short, created_by=f"atc:{run.flow_id}",
                meta={"account_shortname": admin_short},
            )
            auto_admins = [{
                "shortName": admin_short,
                "fullName": admin_full,
                "hidden": hidden,
                "passwordHash": account_hash.password_hash_blob(password),
            }]

    # Audit task: records the settings, never the password.
    task = await TaskManager().create_task(
        tenant=tenant, task_type="account_configuration",
        description=f"AccountConfiguration on {device.serial_number}",
        device=device, user=f"atc:{run.flow_id}",
        details={"primary_account": mode, "lock_primary_account": lock_primary,
                 "managed_admin": bool(auto_admins),
                 "managed_admin_shortname": admin_short},
    )

    if (skip_primary or set_regular) and not auto_admins:
        # Read off the outcome, not the intent: managed_admin can be on and still produce no admin when a static
        # password source was left empty. Nothing was escrowed, so nothing to roll back; sending would remove
        # the primary account and leave no administrator in its place.
        reason = (f"{ACCOUNT_ADMIN_REQUIREMENT}. This step is set to "
                  f"'{mode}' with no managed admin, so nothing was sent")
        task.status = "failed"
        task.error = reason
        await task.save()
        _timeline(run, run.current_node, f"configure_accounts: {reason}")
        _record_gap(run, run.current_node, "not_queued", None, grade="broken",
                    items=[{"id": "account_configuration", "grade": "broken",
                            "why": reason}])
        logger.warning("ATC: run %s refused AccountConfiguration on %s: %s",
                       run.id, device.serial_number, reason)
        return
    if admin_secret is not None:
        # The escrow is provisional until this task comes back acknowledged.
        await device_secrets.mark_unconfirmed(admin_secret, task.id)
    connector = MDMConnector()
    try:
        result = await connector.account_configuration(
            device.udid,
            skip_primary_setup=skip_primary,
            set_primary_as_regular=set_regular,
            lock_primary_account=lock_primary,
            primary_full_name=full_name,
            primary_short_name=short_name,
            auto_setup_admins=auto_admins,
        )
        task.details["command_uuid"] = result.get("command_uuid")
        task.status = "running"
        await task.save()
        note = f"sent (primary={mode})"
        if auto_admins:
            note += (f"; managed admin '{admin_short}' escrowed, unconfirmed until "
                     "the Mac acknowledges")
        _timeline(run, run.current_node, f"configure_accounts: {note}")
    except Exception as exc:
        task.status = "failed"
        task.error = str(exc)
        await task.save()
        if admin_secret is not None:
            # Nothing reached the Mac, so no account was created and the password we just stored opens nothing.
            await device_secrets.rollback(admin_secret, prior_escrow)
        _timeline(run, run.current_node,
                  f"configure_accounts: send failed ({exc})"
                  + ("; managed-admin escrow rolled back" if admin_secret is not None else ""))
        logger.warning("ATC: AccountConfiguration failed for %s: %s", device.udid, exc)
    finally:
        await connector.close()


async def _set_firmware_lock(run: FlowRun, device: Device, params: Dict[str, Any]) -> None:
    """Set the firmware or recovery lock and escrow its password. Apple silicon takes SetRecoveryLock, Intel
    SetFirmwarePassword; unreported gets neither. An auto-generated password does not rotate on re-run
    (rotate_existing=False): a Mac already escrowed gains nothing from a password it might not take."""
    if device.enrollment_state != "enrolled" or not device.udid:
        _timeline(run, run.current_node, "set_firmware_lock: device not enrolled; skipped")
        return

    from controller.services import account_hash, crypto_secrets, device_secrets
    from controller.services.mdm_connector import MDMConnector
    from controller.services.task_manager import TaskManager

    tenant = await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None:
        return

    src = params.get("password_source")
    new_pw = (str(params.get("password") or "") if src == "static"
              else account_hash.generate_password(style="alphanumeric"))

    try:
        change = await device_secrets.plan_lock_change(
            device, new_pw, actor=f"atc:{run.flow_id}",
            rotate_existing=(src == "static"),
        )
    except crypto_secrets.SecretEncryptionUnavailable as exc:
        _timeline(run, run.current_node,
                  f"set_firmware_lock: no encryption key, so nothing was sent ({exc})")
        logger.error("ATC: refusing to set a lock we cannot escrow on %s", device.udid)
        return
    if change.skipped:
        _timeline(run, run.current_node, f"set_firmware_lock: {change.skip_reason}; skipped")
        return

    fields: Dict[str, Any] = {"NewPassword": change.new_password}
    if change.current_password:
        # Apple requires CurrentPassword to change a lock that is already set.
        fields["CurrentPassword"] = change.current_password

    task = await TaskManager().create_task(
        tenant=tenant, task_type="set_firmware_lock",
        description=f"{change.label} on {device.serial_number}",
        device=device, user=f"atc:{run.flow_id}",
        details={"lock_type": change.request_type,  # never the password
                 "rotation": change.rotating},
    )
    await device_secrets.begin_lock_change(change, task.id)

    connector = MDMConnector()
    try:
        result = await connector.send_raw_command(device.udid, change.request_type, fields)
        task.details["command_uuid"] = result.get("command_uuid")
        task.status = "running"
        await task.save()
        _timeline(run, run.current_node,
                  f"set_firmware_lock: {change.label} rotation sent; the escrow keeps the "
                  "old password until the Mac acknowledges" if change.rotating
                  else f"set_firmware_lock: {change.label} sent + escrowed")
    except Exception as exc:
        task.status = "failed"
        task.error = str(exc)
        await task.save()
        # Nothing reached the device, so a parked password is dead and a first set's escrow opens nothing.
        await device_secrets.abort_lock_change(change)
        _timeline(run, run.current_node,
                  f"set_firmware_lock: send failed ({exc}); the escrow was rolled back")
        logger.warning("ATC: %s failed for %s: %s", change.request_type, device.udid, exc)
    finally:
        await connector.close()


# Dispatcher alerts

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


async def _sweep_manual_gate(run: FlowRun) -> int:
    """One expired rung of a parked manual gate. Escalate and re-park until the ladder runs out, then fail through the
    normal path so the run reaches a terminal state, retention can reap it and the snapshot is dropped."""
    # The deadline predicate pins the claim to the park the sweep actually saw: a gate decided and re-parked between the
    # sweep's fetch and this claim has a fresh future deadline, so the stale in-memory run cannot seize it.
    claimed = await FlowRun.filter(
        id=run.id, status="waiting", waiting_signal="manual",
        wait_deadline__lte=_now(),
    ).update(status="running", waiting_signal=None, waiting_ref=None,
             wait_deadline=None)
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
        claimed = await FlowRun.filter(
            id=run_id, status="waiting", waiting_signal="manual"
        ).update(status="running", waiting_signal=None, waiting_ref=None,
                 wait_deadline=None)
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
        claimed = await FlowRun.filter(
            id=run_id, status="waiting", waiting_signal="manual"
        ).update(status="running", waiting_signal=None, waiting_ref=None,
                 wait_deadline=None)
        if not claimed:
            return
        run.status = "running"
        run.waiting_signal = None
        run.waiting_ref = None
        run.wait_deadline = None
        await _fail(run, reason)
    except Exception:
        logger.exception("ATC: fail_gate_run(%s) failed", run_id)


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


def _flow_has_release_node(flow: Dict[str, Any]) -> bool:
    return any(isinstance(n, dict) and n.get("type") == "release_device"
               for n in (flow.get("nodes") or []))


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
        head = (f"{device.serial_number} is stuck in Setup Assistant: "
                f"flow '{run.flow_id}' failed{where}")
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


async def _wait_already_satisfied(run: FlowRun, device: Device, node: Dict[str, Any]) -> bool:
    """Whether a wait_for's whole condition is already true at park time. Refless signals (device_info, checkin)
    wait for the next occurrence, so they're never pre-satisfied. A ref-based signal wants every ref the run
    queued: nothing queued is vacuously satisfied, and outstanding refs are read straight out of the deployment
    and task tables, closing the window where the device answered between the action and the park."""
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
        logger.warning("ATC: run %s parked on '%s' with no timeout in the flow "
                       "document; defaulting to %dm (this flow did not come "
                       "through the validator)", run.id, node.get("id"), minutes)
        _timeline(run, node.get("id"),
                  "wait_for carries no timeout_minutes, so the engine applied its "
                  "60 minute default")
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
                  "reached the end without releasing the device, which is still "
                  "held in Setup Assistant")
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

    Narrower than _persist for a reason: a run recording a partial barrier is still parked and holds no claim on itself,
    so writing every column would push our copy of status and wait_deadline back over whatever the sweep or another
    signal has since done to the row."""
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


# ==Context helpers==

def _signal_expected(run: FlowRun, signal: str, ref: Optional[str]) -> bool:
    """Whether this arrival belongs to the barrier the run is parked on. It says nothing about whether the barrier is
    done; _record_satisfied answers that."""
    if signal in _REFLESS_SIGNALS:
        return True
    expected = (run.context or {}).get("expected", {}).get(signal) or []
    return ref is not None and str(ref) in [str(x) for x in expected]


def _mark_satisfied(run: FlowRun, signal: str, ref: Optional[str]) -> None:
    if ref is None:
        return
    ctx = run.context or {}
    bucket = ctx.setdefault("satisfied", {}).setdefault(signal, [])
    if str(ref) not in [str(x) for x in bucket]:
        bucket.append(str(ref))
    run.context = ctx


def _wait_progress(run: FlowRun, signal: str) -> Tuple[int, int]:
    """(arrived, expected) for a signal's barrier."""
    ctx = run.context or {}
    expected = {str(x) for x in ((ctx.get("expected") or {}).get(signal) or [])}
    arrived = {str(x) for x in ((ctx.get("satisfied") or {}).get(signal) or [])}
    return len(expected & arrived), len(expected)


async def _record_satisfied(run: FlowRun, signal: str,
                            ref: Optional[str]) -> Tuple[int, int]:
    """Record one arrival against the run's barrier and report where that leaves it.

    Re-reads the row first: two refs for the same barrier can arrive close enough together that this run object is
    already stale by the time it is written, and losing one would hold the barrier short for good."""
    try:
        fresh = await FlowRun.get_or_none(id=run.id)
        stored = ((fresh.context or {}).get("satisfied") or {}).get(signal) if fresh else None
        for r in (stored or []):
            _mark_satisfied(run, signal, r)
    except Exception:
        logger.exception("ATC: re-reading arrivals failed for run %s", run.id)
    _mark_satisfied(run, signal, ref)
    return _wait_progress(run, signal)


def _expect(run: FlowRun, signal: str, refs: List[str]) -> None:
    ctx = run.context or {}
    expected = ctx.setdefault("expected", {})
    bucket = expected.setdefault(signal, [])
    for r in refs:
        if str(r) not in [str(x) for x in bucket]:
            bucket.append(str(r))
    run.context = ctx


def _consume_expected(run: FlowRun, signal: Optional[str]) -> None:
    """Clear a just-left wait_for's barrier: the refs wanted, which turned up, and any gate:false exemption. A
    later wait_for on the same signal must start from empty or it inherits stale arrivals. The gap ledger is
    deliberately not cleared here."""
    if not signal:
        return
    ctx = run.context or {}
    changed = False
    for key in ("expected", "satisfied"):
        bucket = ctx.get(key)
        if isinstance(bucket, dict) and signal in bucket:
            bucket[signal] = []
            changed = True
    ungated = ctx.get("ungated")
    if isinstance(ungated, dict) and ungated.pop(signal, None) is not None:
        changed = True
    if changed:
        run.context = ctx


# ==The gap ledger==
#
# What a barrier did not get. Append-only, per run; the record release_device consults to know a wait step held nothing
# back.

def _gate_off(params: Optional[Dict[str, Any]]) -> bool:
    """True when the step carries gate: false in the flow document.

    Only a literal false counts. Anything else, including a truthy string hand-typed into flows.yaml, leaves the step
    holding the flow up, because the safe reading of an ambiguous value is the one that keeps the guard armed."""
    return (params or {}).get("gate") is False


def _mark_ungated(run: FlowRun, signal: str) -> None:
    """Record that the next barrier on this signal is allowed to hold nothing, because the step feeding it carries gate:
    false. _consume_expected drops the mark when that barrier is left, so it exempts one barrier and not the rest of the
    run."""
    ctx = run.context or {}
    ctx.setdefault("ungated", {})[signal] = True
    run.context = ctx


def _is_ungated(run: FlowRun, signal: Optional[str]) -> bool:
    return bool(((run.context or {}).get("ungated") or {}).get(signal))


def _record_gap(run: FlowRun, node_id: Optional[str], kind: str,
                signal: Optional[str], *, items: Optional[List[Dict[str, str]]] = None,
                grade: str = "policy", note: Optional[str] = None) -> None:
    """Append one gap to the run's ledger. items are the specific ids the step did not deliver, each with an
    actionable reason. An unrecognised kind is still written down rather than dropped, so a typo in a future
    caller cannot quietly disable this ledger."""
    ctx = run.context or {}
    ledger = ctx.setdefault("gaps", [])
    if kind not in GAP_KINDS:
        logger.warning("ATC: run %s recorded gap kind %r, which the board does not "
                       "know how to render", run.id, kind)
    if len(ledger) >= GAP_LEDGER_MAX:
        return
    entry: Dict[str, Any] = {
        "at": _now().isoformat(), "node": node_id, "kind": kind,
        "signal": signal, "grade": grade if grade in GAP_GRADES else "policy",
    }
    if items:
        entry["items"] = items[:50]
    if note:
        entry["note"] = note
    ledger.append(entry)
    run.context = ctx


def _prior_gap_grade(run: FlowRun, signal: Optional[str]) -> Optional[str]:
    """How the last step that under-delivered on this signal was graded, which an empty barrier inherits. A rollout
    holding an app back explains the empty barrier and grades policy; nothing explaining it means the flow declared a
    wait nothing feeds, which grades broken."""
    for entry in reversed((run.context or {}).get("gaps") or []):
        if entry.get("signal") == signal and entry.get("kind") != "barrier_empty":
            return entry.get("grade")
    return None


def _record_unmet(run: FlowRun, node_id: Optional[str], signal: Optional[str]) -> None:
    """Refs a barrier wanted and never got, written down before it is cleared. Called on the timeout edge, where the
    author has decided the run carries on without them, so the ledger is the only record left that they are missing."""
    if not signal or signal in _REFLESS_SIGNALS:
        return
    ctx = run.context or {}
    expected = [str(x) for x in ((ctx.get("expected") or {}).get(signal) or [])]
    arrived = {str(x) for x in ((ctx.get("satisfied") or {}).get(signal) or [])}
    missing = [r for r in expected if r not in arrived]
    if not missing:
        return
    _record_gap(run, node_id, "never_arrived", signal, grade="broken",
                items=[{"id": r, "why": "the device never reported it",
                        "grade": "broken"} for r in missing])


def _gap_body(gaps: List[Dict[str, Any]]) -> str:
    """The middle of an alert summary: what is missing and which wait step turned out to be holding nothing."""
    missing: List[str] = []
    empty: List[str] = []
    for g in gaps:
        if g.get("kind") == "barrier_empty":
            empty.append(f"'{g.get('node')}'")
        for item in (g.get("items") or []):
            missing.append(f"{item.get('id')} ({item.get('why')})")
    bits: List[str] = []
    if missing:
        bits.append("it did not get " + ", ".join(missing[:6]))
    if empty:
        bits.append(f"the wait at {', '.join(empty[:4])} had nothing to hold")
    return "; ".join(bits) or "the flow could not account for what it installed"


def _drop_flow_snapshot(run: FlowRun) -> bool:
    """Forget the pinned flow definition on a run that is finished with it; it's the biggest thing this table
    writes (a full document copy per run, static passwords included). flow_hash still records which definition
    ran."""
    ctx = run.context or {}
    if ctx.pop("flow", None) is None:
        return False
    run.context = ctx
    return True


def _timeline(run: FlowRun, node_id: Optional[str], message: str) -> None:
    ctx = run.context or {}
    ctx.setdefault("timeline", []).append({
        "at": _now().isoformat(), "node": node_id, "message": message,
    })
    run.context = ctx


def _mark_visited(run: FlowRun, node_id: str) -> None:
    ctx = run.context or {}
    visited = ctx.setdefault("visited", [])
    if node_id not in visited:
        visited.append(node_id)
    run.context = ctx


def _mark_dirty(run: FlowRun) -> None:
    ctx = run.context or {}
    ctx["dirty"] = True
    run.context = ctx


def _str_list(value: Any) -> List[str]:
    items = value if isinstance(value, list) else ([value] if value else [])
    return [str(x) for x in items if x]
