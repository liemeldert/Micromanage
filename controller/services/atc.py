"""ATC (Air Traffic Control) flow execution engine.

An ATC flow (flows.yaml, validated by utils.yaml_validator) runs per device as
an asynchronous state machine (models.FlowRun). MDM is asynchronous: a flow
executes forward until it hits a node that must wait for the device
(``wait_for``), then persists its position and resumes when the matching webhook
signal arrives, or when the timeout sweep fires. A flow is NOT a coroutine that
blocks on MDM round-trips.

Determinism under edits: the flow definition is snapshotted into
``FlowRun.context['flow']`` at start and fingerprinted by ``flow_hash``, so an
admin editing flows.yaml mid-run does not change the definition an in-flight run
executes.

Every public entry point is best-effort and defensive: they run on the
enrollment / webhook / poll hot paths, so a malformed flow or a node error fails
only that run (recorded on the FlowRun) and is never allowed to propagate into
the caller. Mirrors the ``try/except -> log -> continue`` discipline of
services.scoping.
"""

import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from controller.models.tenant import Alert, Device, FlowRun, Tenant
from controller.services import tenant_config
from controller.services.scoping import evaluate_condition, evaluate_scope

logger = logging.getLogger(__name__)

# Loop backstop: even though the validator proves a flow is a DAG, cap how many
# nodes a single _advance pass may execute so a bug can never spin forever.
MAX_NODES_PER_ADVANCE = 100

# A run is only 'running' for the brief span of an _advance pass. One still
# 'running' long past that was orphaned (e.g. the process died mid-advance): it
# has no waiting row and no deadline, so nothing else would ever touch it. The
# sweep fails such runs so they can't sit invisible forever.
STALE_RUNNING_MINUTES = int(os.getenv("ATC_STALE_RUNNING_MINUTES", "30"))

# Per-tenant cap on how many scheduled-start runs one sweep may launch, so a
# large fleet all matching a schedule can't launch thousands of runs at once
# (the most-overdue go first; the rest catch up on later ticks).
SCHEDULE_MAX_LAUNCH_PER_TICK = int(os.getenv("ATC_SCHEDULE_MAX_LAUNCH_PER_TICK", "200"))

# Run states that count as "active" for supersede/dedup.
_ACTIVE_STATES = ["running", "waiting"]

# Events that supersede a device's prior run from the same start (a fresh enroll
# re-runs onboarding); other events dedup instead (skip while one is active).
_SUPERSEDE_EVENTS = frozenset({"enroll_dep", "enroll_profile"})

# Signals a wait_for node resumes on that need no reference (any occurrence for
# the device satisfies them). The rest (profile_installed / app_installed /
# command_ack / declaration_applied) match against what the run itself queued
# (context['expected']).
_REFLESS_SIGNALS = frozenset({"device_info", "checkin", "ddm_status"})


#  Loading + hashing 

def _load_flow(tenant_id: str) -> Optional[Dict[str, Any]]:
    """The single flow from a tenant's flows.yaml (None if absent/malformed),
    normalized from the legacy multi-flow shape when needed. Defensive: never
    raises (runs on the enroll/checkin/poll hot paths)."""
    from controller.services.flow_step_catalog import normalize_flow_document
    try:
        data = tenant_config._load(tenant_id, "flows.yaml")
    except Exception:
        logger.exception("ATC: loading flows.yaml failed for tenant %s", tenant_id)
        return None
    flow, warns = normalize_flow_document(data)
    for w in warns:
        logger.info("ATC: %s", w)
    return flow


def _flow_hash(flow: Dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(flow, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _nodes_by_id(flow: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    # Keep the FIRST definition of a duplicate id, matching the validator's graph
    # build (a dict comprehension would keep the last and diverge from review).
    by_id: Dict[str, Dict[str, Any]] = {}
    for n in (flow.get("nodes") or []):
        if isinstance(n, dict) and n.get("id") and n["id"] not in by_id:
            by_id[n["id"]] = n
    return by_id


def _scope_matches(device: Device, device_groups: List[str],
                   scope: Optional[Dict[str, Any]]) -> bool:
    """A flow trigger's ``match`` scope. An empty match fires for every enroll;
    otherwise the unified scope engine decides."""
    scope = scope or {}
    if not any(scope.get(k) for k in
               ("groups", "conditions", "include_devices", "exclude_devices")):
        return True
    return evaluate_scope(device, device_groups, scope)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _int(value: Any, default: int = 0) -> int:
    """Coerce a possibly-malformed value (flows.yaml can be hand-edited/restored
    outside the validated PUT) to int without raising."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


#  Entry points 

async def _has_active_run(device_id: Any, start_id: str) -> bool:
    """Is a run from this (device, start) already running/waiting? Guards
    checkin/schedule starts from piling up a new run every event."""
    try:
        return await FlowRun.filter(
            device_id=device_id, start_node=start_id, status__in=_ACTIVE_STATES
        ).exists()
    except Exception:
        logger.exception("ATC: active-run check failed for start %s", start_id)
        return False


async def _supersede(device_id: Any, start_id: str) -> None:
    """Cancel active runs from the SAME start on this device (a fresh enroll
    re-runs onboarding). Scoped to the start, so concurrent runs from other
    starts (e.g. a schedule run) are left alone."""
    try:
        await FlowRun.filter(
            device_id=device_id, start_node=start_id, status__in=_ACTIVE_STATES
        ).update(status="cancelled", current_node=None, waiting_signal=None,
                 waiting_ref=None, wait_deadline=None, completed_at=_now())
    except Exception:
        logger.exception("ATC: superseding prior runs failed for start %s", start_id)


async def _start_run(device: Device, flow: Dict[str, Any], start_node: Dict[str, Any],
                     event_kind: str) -> Optional[FlowRun]:
    """Create a FlowRun entering at ``start_node`` and advance it once."""
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
            context={"flow": flow, "timeline": [], "visited": [], "expected": {}},
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
    """Start runs for every ``start`` node in the single flow that fires on
    ``event_kind`` and whose match scopes this device.

    Enroll events supersede a prior run from the same start; checkin/schedule
    events dedup (skip while a run from that start is still active). Best-effort:
    never raises into the enroll / checkin / schedule hot paths."""
    runs: List[FlowRun] = []
    flow = _load_flow(str(device.tenant_id))
    if not flow or not flow.get("enabled", True):
        return runs
    device_groups = list(device.groups or [])
    for node in (flow.get("nodes") or []):
        try:
            if not isinstance(node, dict) or node.get("type") != "start" or not node.get("id"):
                continue
            params = node.get("params") or {}
            if params.get("kind") != event_kind:
                continue
            if not _scope_matches(device, device_groups, params.get("match")):
                continue
            start_id = str(node["id"])
            if event_kind in _SUPERSEDE_EVENTS:
                await _supersede(device.id, start_id)
            elif await _has_active_run(device.id, start_id):
                continue  # dedup: a run from this start is already in flight
            run = await _start_run(device, flow, node, event_kind)
            if run is not None:
                runs.append(run)
        except Exception:
            logger.exception("ATC: start node %r failed for device %s",
                             (node or {}).get("id"), device.id)
    return runs


async def start_run_from_start(device: Device, start_node_id: str) -> Optional[FlowRun]:
    """Manually start a run from a specific ``start`` node (testing / API).

    Supersedes an active run from the same start. Returns None if the node
    doesn't exist, isn't a start node, the flow is malformed, or the start fails."""
    try:
        flow = _load_flow(str(device.tenant_id))
        if not flow:
            return None
        node = _nodes_by_id(flow).get(start_node_id)
        if not node or node.get("type") != "start":
            return None
        await _supersede(device.id, start_node_id)
        kind = (node.get("params") or {}).get("kind") or "manual"
        return await _start_run(device, flow, node, str(kind))
    except Exception:
        logger.exception("ATC: manual start of node %s failed for device %s",
                         start_node_id, device.id)
        return None


async def advance_on_signal(device_id: str, signal: str, ref: Optional[str] = None) -> None:
    """Resume waiting runs for a device when a device signal arrives.

    Best-effort: called from webhook handlers, so it swallows and logs any
    failure rather than breaking webhook processing."""
    try:
        device = await Device.get_or_none(id=device_id)
        if device is None:
            return
        runs = await FlowRun.filter(
            device_id=device_id, status="waiting", waiting_signal=signal
        ).all()
        for run in runs:
            try:
                if not _signal_satisfies(run, signal, ref):
                    continue
                node = _nodes_by_id((run.context or {}).get("flow") or {}).get(run.current_node)
                nxt = (node or {}).get("next")
                # Atomically claim the run (guards against the sweep or a second
                # signal advancing the same run concurrently).
                claimed = await FlowRun.filter(id=run.id, status="waiting").update(
                    status="running", waiting_signal=None, waiting_ref=None,
                    wait_deadline=None,
                )
                if not claimed:
                    continue
                if not nxt:
                    await _fail(run, "wait_for node has no 'next' edge")
                    continue
                # This barrier is done: clear its expected refs so a later
                # wait_for on the same signal starts fresh (not matched by a
                # stale ref from this one).
                _consume_expected(run, signal)
                run.status = "running"
                run.current_node = nxt
                _timeline(run, run.current_node, f"resumed on {signal}")
                await _advance(run, device)
            except Exception:
                logger.exception("ATC: advancing run %s on signal %s failed", run.id, signal)

        # A check-in can also START a checkin-triggered run. Do this AFTER resuming
        # existing waits so the just-resumed run counts as active and the dedup
        # guard doesn't launch a duplicate for the same start.
        if signal == "checkin":
            try:
                await start_flows_for_event(device, "checkin")
            except Exception:
                logger.exception("ATC: checkin start dispatch failed for %s", device_id)
    except Exception:
        logger.exception("ATC: advance_on_signal(%s, %s) failed", device_id, signal)


async def sweep_timeouts(tenant: Tenant) -> int:
    """Resolve waiting runs whose deadline has passed: take the ``on_timeout``
    edge, else fail the run. Returns how many were swept."""
    swept = 0
    try:
        runs = await FlowRun.filter(
            tenant_id=tenant.id, status="waiting", wait_deadline__lte=_now()
        ).exclude(waiting_signal="manual").all()
    except Exception:
        logger.exception("ATC: timeout sweep query failed for tenant %s", tenant.id)
        return 0
    for run in runs:
        try:
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
                run.status = "running"
                run.current_node = on_timeout
                _consume_expected(run, ((node or {}).get("params") or {}).get("signal"))
                _timeline(run, on_timeout, "wait timed out")
                if device is None:
                    await _fail(run, "device no longer exists")
                else:
                    await _advance(run, device)
            else:
                await _fail(run, f"timed out waiting for '{run.waiting_signal or 'signal'}'")
        except Exception:
            logger.exception("ATC: sweeping run %s failed", run.id)

    # Manual gates park with waiting_signal='manual' and no deadline, so the
    # deadline query above never returns them; an admin decision (not the sweep)
    # resumes them. (Guard kept explicit above via the query shape.)

    # Recover runs orphaned in 'running' (e.g. a process died mid-advance): they
    # carry no deadline and no waiting row, so only this sweep can free them.
    try:
        stale_cut = _now() - timedelta(minutes=STALE_RUNNING_MINUTES)
        stuck = await FlowRun.filter(
            tenant_id=tenant.id, status="running", updated_at__lt=stale_cut
        ).all()
        for run in stuck:
            claimed = await FlowRun.filter(id=run.id, status="running").update(
                status="failed", error="interrupted (run orphaned mid-execution)",
                completed_at=_now(),
            )
            if claimed:
                swept += 1
    except Exception:
        logger.exception("ATC: stale-running recovery failed for tenant %s", tenant.id)
    return swept


async def sweep_scheduled_starts(tenant: Tenant,
                                 devices: Optional[List[Device]] = None) -> int:
    """Launch runs for ``schedule`` start nodes whose interval has elapsed for an
    in-scope device. Called each poll tick; the interval (not the tick) throttles.
    Capped per tenant per sweep so a large fleet can't launch en masse -- the
    most-overdue devices go first; the rest catch up on later ticks."""
    launched = 0
    flow = _load_flow(str(tenant.id))
    if not flow or not flow.get("enabled", True):
        return 0
    schedule_starts = [
        n for n in (flow.get("nodes") or [])
        if isinstance(n, dict) and n.get("type") == "start" and n.get("id")
        and (n.get("params") or {}).get("kind") == "schedule"
    ]
    if not schedule_starts:
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
    for node in schedule_starts:
        if budget <= 0:
            logger.info("ATC: schedule sweep hit per-tick cap for tenant %s", tenant.id)
            break
        params = node.get("params") or {}
        start_id = str(node["id"])
        interval = _int(params.get("interval_minutes"), 0)
        if interval <= 0:
            continue
        match = params.get("match")
        due: List = []
        for d in devices:
            try:
                if not _scope_matches(d, list(d.groups or []), match):
                    continue
                if await _has_active_run(d.id, start_id):
                    continue
                last = await FlowRun.filter(
                    device_id=d.id, start_node=start_id, event_kind="schedule"
                ).order_by("-started_at").first()
                if last is None or last.started_at is None:
                    due.append((never_run_key, d))
                    continue
                la = last.started_at
                if la.tzinfo is None:
                    la = la.replace(tzinfo=timezone.utc)
                if (now - la) >= timedelta(minutes=interval):
                    due.append((la, d))
            except Exception:
                logger.exception("ATC: schedule eval failed for %s", getattr(d, "serial_number", "?"))
        due.sort(key=lambda t: t[0])
        take = due[:budget]
        for _, d in take:
            run = await _start_run(d, flow, node, "schedule")
            if run is not None:
                launched += 1
                budget -= 1
        deferred = len(due) - len(take)
        if deferred > 0:
            logger.info("ATC: schedule start %s launched %d, deferred %d to next tick",
                        start_id, len(take), deferred)
    return launched


#  Execution 

async def _advance(run: FlowRun, device: Device) -> None:
    """Execute forward from ``run.current_node`` until the run parks (wait_for),
    completes (end) or fails. Never raises."""
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
            # State-check before parking: if the awaited condition is already
            # true (the device answered before we parked) or nothing was queued
            # to wait for, skip the barrier instead of parking. This closes the
            # lost-wakeup window between triggering an action and parking, and
            # avoids waiting forever on a step that queued nothing.
            if await _wait_already_satisfied(run, device, node):
                nxt = node.get("next")
                if not nxt:
                    await _fail(run, "wait_for node has no 'next' edge")
                    return
                signal = (node.get("params") or {}).get("signal")
                _consume_expected(run, signal)
                _timeline(run, nid, f"wait skipped ({signal} already satisfied)")
                run.current_node = nxt
                continue
            await _park(run, node)
            return
        if ntype == "manual_gate":
            # Escalate to a human: raise a Dispatcher alert and park until an
            # admin picks an option (never times out on its own).
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
    """Run one non-terminal, non-waiting node's side effect; return the id of the
    next node to execute (branch picks on_true/on_false)."""
    ntype = node.get("type")
    params = node.get("params") or {}

    if ntype == "start":
        # Entry point: pure passthrough into the graph (scoping/dedup happened at
        # dispatch). No side effect.
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
        await _install_profiles(run, device, _str_list(params.get("profile_ids")))
        return node.get("next")
    if ntype == "install_apps":
        await _install_apps(run, device, _str_list(params.get("app_ids")))
        return node.get("next")
    if ntype == "send_command":
        await _send_command(run, device, params.get("command"), params.get("params") or {})
        return node.get("next")
    if ntype == "release_device":
        await _release_device(run, device)
        return node.get("next")
    if ntype == "sync_declarations":
        await _sync_declarations(run, device)
        return node.get("next")
    if ntype == "branch":
        cond = params.get("condition") or {}
        result = evaluate_condition(device, cond, list(device.groups or []))
        _timeline(run, node.get("id"), f"branch -> {'true' if result else 'false'}")
        return node.get("on_true") if result else node.get("on_false")

    # Unknown node type: the validator rejects these, but fail safe at runtime.
    raise ValueError(f"unknown node type: {ntype}")


#  Node side effects 

async def _apply_tags(run: FlowRun, device: Device, tags: List[str], *, add: bool) -> None:
    """Additive/idempotent tag write (mirrors the manual tag endpoint), then
    recompute groups so a later branch/scope sees fresh membership."""
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
        _timeline(run, run.current_node, f"{'assign' if add else 'remove'}_tag: no change")
        return
    device.tags = result
    await device.save(update_fields=["tags"])
    # A tag change can shift scoping (a profile/group may key off a tag) even when
    # group *names* are unchanged, so always request a reconcile.
    _mark_dirty(run)
    # Persist recomputed groups only if membership actually shifted -- compare new
    # groups against the OLD GROUPS (not the old tag set).
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
    # Push to the device fire-and-forget: the MDM round-trip (up to the client
    # timeout) must not block _advance on the enroll/webhook hot path. set_name
    # has no wait_for signal, so nothing in the flow depends on its completion.
    if device.enrollment_state != "enrolled" or not device.udid:
        return
    from controller.services.reconciler import _spawn
    _spawn(_push_device_name(device, resolved, run.flow_id))


async def _push_device_name(device: Device, resolved: str, flow_id: str) -> None:
    """Background SetName push + audit task (spawned by _set_name so the MDM
    round-trip never blocks the enroll/webhook hot path)."""
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


async def _install_profiles(run: FlowRun, device: Device, profile_ids: List[str]) -> None:
    """Queue InstallProfile for the named profiles (imperative: installed
    regardless of scope, since the flow asked for them explicitly)."""
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
    for pid in profile_ids:
        info = by_id.get(pid)
        if not info:
            _timeline(run, run.current_node, f"install_profiles: unknown profile {pid}; skipped")
            continue
        task = await tm.create_task(
            tenant=tenant, task_type="profile_install",
            description=f"ATC install profile {info.get('name', pid)}",
            device=device, user=f"atc:{run.flow_id}", details={"profile_info": info},
        )
        _spawn(tm.execute_task(task, handle_profile_install_task))
        queued.append(pid)
    if queued:
        _expect(run, "profile_installed", queued)
        _timeline(run, run.current_node, f"install_profiles queued={queued}")


async def _install_apps(run: FlowRun, device: Device, app_ids: List[str]) -> None:
    """Queue InstallApplication for the named apps, using the version the device
    is entitled to (reuses the reconciler's evaluation so version/rollout are
    consistent). An app the device is not scoped into is skipped and logged."""
    from controller.services.app_manager import AppManager
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
    wanted = set(app_ids)
    try:
        applicable = await AppManager(tenant).evaluate_device_apps(device, apps_config, groups_config)
    except Exception:
        logger.exception("ATC: evaluating apps failed for %s", device.serial_number)
        applicable = []
    by_id = {a["app_id"]: a for a in applicable}
    tm = TaskManager()
    queued: List[str] = []
    for aid in app_ids:
        info = by_id.get(aid)
        if not info:
            _timeline(run, run.current_node,
                      f"install_apps: {aid} not scoped to this device (no applicable version); skipped")
            continue
        task = await tm.create_task(
            tenant=tenant, task_type="app_install",
            description=f"ATC install {info.get('name', aid)} v{info.get('version')}",
            device=device, user=f"atc:{run.flow_id}", details={"app_info": info},
        )
        _spawn(tm.execute_task(task, handle_app_install_task))
        queued.append(aid)
    _ = wanted  # (documented intent: only entitled apps are installed)
    if queued:
        _expect(run, "app_installed", queued)
        _timeline(run, run.current_node, f"install_apps queued={queued}")


async def _send_command(run: FlowRun, device: Device, command: Any, params: Dict[str, Any]) -> None:
    """Send a non-destructive catalog command through the shared audited path.
    Destructive commands are refused (defence in depth behind the validator)."""
    from controller.services.device_commands import (
        CommandError, CommandSendError, dispatch_catalog_command,
    )

    tenant = await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None:
        return
    try:
        outcome = await dispatch_catalog_command(
            device, str(command), params or {},
            user=f"atc:{run.flow_id}", tenant=tenant, allow_destructive=False,
        )
        _expect(run, "command_ack", [outcome["task_id"]])
        _timeline(run, run.current_node, f"send_command {command} -> task {outcome['task_id']}")
    except CommandSendError as exc:
        # Transport failed but a (failed) audit task exists: record it so a
        # following wait_for(command_ack) resolves at once instead of stalling.
        tid = getattr(exc, "task_id", None)
        if tid:
            _expect(run, "command_ack", [tid])
        _timeline(run, run.current_node, f"send_command {command} failed to send: {exc}")
        logger.warning("ATC: send_command %s transport-failed in run %s: %s",
                       command, run.id, exc)
    except CommandError as exc:
        # Invalid command / missing param: no task created. A following
        # wait_for(command_ack) then has an empty expectation and is skipped.
        _timeline(run, run.current_node, f"send_command {command} rejected: {exc}")
        logger.warning("ATC: send_command %s rejected in run %s: %s", command, run.id, exc)


async def _sync_declarations(run: FlowRun, device: Device) -> None:
    """Queue a DDM DeclarativeManagement sync for the device.

    A DDM-disabled tenant or an unsupported device is a skipped timeline note,
    never a run failure -- a mixed fleet shares one flow. Like send_command, the
    enqueue is awaited inline (it is a single NanoMDM call)."""
    from controller.services import ddm_manager

    tenant = await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None:
        return
    if not tenant.ddm_enabled or device.enrollment_state != "enrolled" \
            or not device.udid or not ddm_manager.device_supports_ddm(device):
        _timeline(run, run.current_node,
                  "sync_declarations: DDM disabled or unsupported; skipped")
        return
    try:
        queued = await ddm_manager.sync_device(device, reason="flow")
    except Exception as exc:
        _timeline(run, run.current_node,
                  f"sync_declarations: sync failed ({exc}); continuing")
        logger.warning("ATC: sync_declarations failed in run %s: %s", run.id, exc)
        return
    # Expect the yaml-authored declarations (bare ids) so a following
    # wait_for(declaration_applied) resolves; with none scoped the expectation
    # stays empty and such a wait is vacuously satisfied.
    try:
        declarations = await ddm_manager.compute_device_declarations(device, tenant)
        refs = [d["Identifier"][len("mm.cfg."):] for d in declarations
                if d["Identifier"].startswith("mm.cfg.")
                and d["Identifier"] != "mm.cfg.status-subscriptions"]
        if refs:
            _expect(run, "declaration_applied", refs)
    except Exception:
        logger.exception("ATC: computing declaration refs failed for %s",
                         device.serial_number)
    _timeline(run, run.current_node,
              "sync_declarations: sync queued" if queued
              else "sync_declarations: already in sync")


async def _release_device(run: FlowRun, device: Device) -> None:
    """Send DeviceConfigured to release an ADE device from Setup Assistant.

    Fire-and-forget (like set_name): the MDM round-trip must not block _advance on
    the enroll/webhook hot path, and nothing downstream in the flow depends on the
    ack. A no-op for a device that never enrolled or has no udid."""
    if device.enrollment_state != "enrolled" or not device.udid:
        _timeline(run, run.current_node, "release_device: device not enrolled; skipped")
        return
    from controller.services.reconciler import _spawn
    _spawn(_push_device_configured(device, f"atc:{run.flow_id}"))
    _timeline(run, run.current_node, "release_device: DeviceConfigured queued")
    # The device is no longer held in Setup Assistant: clear the green in-setup
    # alert (best-effort; a no-op if none is open).
    await _resolve_in_setup_alert(device, "released by flow")


async def release_device_manual(device: Device, actor: str) -> bool:
    """Admin-triggered release from Setup Assistant (from the green in-setup alert
    on the board). Reuses the same audited DeviceConfigured push, and resolves the
    in-setup alert. Returns False for a device that can't be released."""
    if device.enrollment_state != "enrolled" or not device.udid:
        return False
    from controller.services.reconciler import _spawn
    _spawn(_push_device_configured(device, f"admin:{actor}"))
    await _resolve_in_setup_alert(device, f"released by {actor}")
    return True


async def _push_device_configured(device: Device, user: str) -> None:
    """Background DeviceConfigured push + audit task (spawned by callers so the
    MDM round-trip never blocks the hot path). ``user`` is the audit actor."""
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


#  Human decision gate + Dispatcher alerts 

def _gate_options(node: Dict[str, Any]) -> List[Dict[str, str]]:
    """The validated decision options for a manual_gate: [{label, edge}], keeping
    only options whose edge is a real gate handle and carries a label."""
    from controller.services.flow_step_catalog import GATE_EDGE_HANDLES
    out: List[Dict[str, str]] = []
    for o in ((node.get("params") or {}).get("options") or []):
        if isinstance(o, dict) and o.get("edge") in GATE_EDGE_HANDLES and o.get("label"):
            out.append({"label": str(o["label"]), "edge": str(o["edge"])})
    return out


async def _raise_gate_alert(device: Device, run: FlowRun, node: Dict[str, Any],
                            options: List[Dict[str, str]]) -> Optional[str]:
    """Open a Dispatcher alert for a manual_gate. rule_id is unique per run so the
    'one active per (device, rule)' invariant allows exactly one gate per run."""
    params = node.get("params") or {}
    severity = str(params.get("severity") or "yellow")
    if severity not in ("black", "red", "yellow", "green"):
        severity = "yellow"
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


async def _park_manual(run: FlowRun, device: Device, node: Dict[str, Any]) -> None:
    """Park a run on a manual_gate: raise the decision alert and wait (no
    deadline) until an admin resumes it via resume_manual_gate."""
    options = _gate_options(node)
    if not options:
        await _fail(run, f"manual_gate '{node.get('id')}' has no valid options")
        return
    alert_id = await _raise_gate_alert(device, run, node, options)
    run.status = "waiting"
    run.waiting_signal = "manual"
    run.waiting_ref = alert_id
    run.wait_deadline = None
    _timeline(run, node.get("id"),
              f"awaiting admin decision: {[o['label'] for o in options]}")
    await _persist(run)
    await _maybe_reconcile(run)


async def resume_manual_gate(run_id: Any, edge_handle: str, actor: str) -> Optional[FlowRun]:
    """Resume a manual_gate run down the chosen edge. Idempotent: a second call
    (double-click) after the run already advanced is a benign no-op."""
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
    """Fail a manual-gated run because its alert was dismissed without a decision
    (a plain resolve of the gate alert). Never leaves the run stuck waiting."""
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
    """Open (once) the green 'held in Setup Assistant' alert for an ADE device
    whose flow will release it. The board renders a 'Release from setup' action."""
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


async def _resolve_in_setup_on_terminal(run: FlowRun) -> None:
    """On a run reaching a terminal state, clear the green in-setup alert it
    opened. If another active run is still holding the device it will reopen the
    alert on its next park (self-healing)."""
    if not (run.context or {}).get("in_setup"):
        return
    device = await Device.get_or_none(id=run.device_id)
    if device is not None:
        await _resolve_in_setup_alert(device, f"flow {run.status}")


async def _wait_already_satisfied(run: FlowRun, device: Device, node: Dict[str, Any]) -> bool:
    """Is a wait_for's condition already true at park time?

    Refless signals (device_info / checkin) are "wait for the next occurrence",
    so never pre-satisfied. Ref-based signals check the durable state the run
    queued: if nothing was queued (empty expectation) the barrier is vacuously
    satisfied; otherwise we check the deployment/task tables directly, which
    closes the race where the device answered before the run parked."""
    signal = (node.get("params") or {}).get("signal")
    if signal in _REFLESS_SIGNALS:
        return False
    expected = (run.context or {}).get("expected", {}).get(signal) or []
    if not expected:
        return True  # nothing queued -> nothing to wait for
    from controller.models.tenant import AppDeployment, ProfileDeployment, Task
    try:
        if signal == "profile_installed":
            return await ProfileDeployment.filter(
                device_id=device.id, profile_id__in=expected, status="installed"
            ).exists()
        if signal == "app_installed":
            return await AppDeployment.filter(
                device_id=device.id, app_id__in=expected, status="installed"
            ).exists()
        if signal == "command_ack":
            return await Task.filter(
                id__in=expected, status__in=["completed", "failed"]
            ).exists()
        if signal == "declaration_applied":
            # The device may have reported the declaration active before the
            # run parked (a fast sync); check the stored declaration status.
            reported = getattr(device, "ddm_declaration_status", None) or {}
            for ref in expected:
                state = reported.get(f"mm.cfg.{ref}") or reported.get(str(ref)) or {}
                if state.get("active") and state.get("valid") == "valid":
                    return True
            return False
    except Exception:
        logger.exception("ATC: wait pre-check failed for signal %s", signal)
    return False


#  State transitions 

async def _park(run: FlowRun, node: Dict[str, Any]) -> None:
    params = node.get("params") or {}
    signal = str(params.get("signal") or "")
    try:
        minutes = int(params.get("timeout_minutes") or 0)
    except (TypeError, ValueError):
        minutes = 0
    run.status = "waiting"
    run.waiting_signal = signal
    # For ref-based signals, remember what this run is waiting on (display + a
    # human hint; the actual match is against context['expected']).
    expected = (run.context or {}).get("expected", {}).get(signal) or []
    # Display hint only (matching is against context['expected']); cap to the
    # column width so a long ref list can't make the park-time save throw and
    # leave the run un-parked.
    run.waiting_ref = (",".join(str(x) for x in expected)[:255] or None)
    run.wait_deadline = _now() + timedelta(minutes=minutes if minutes > 0 else 60)
    _timeline(run, node.get("id"), f"waiting for {signal} (timeout {minutes}m)")
    # An ADE device parked mid-flow is being held in Setup Assistant (if the flow
    # releases it later): surface a green board alert with a manual release.
    device = await Device.get_or_none(id=run.device_id)
    if device is not None:
        await _ensure_in_setup_alert(device, run)
    await _persist(run)
    await _maybe_reconcile(run)


async def _complete(run: FlowRun) -> None:
    run.status = "completed"
    run.current_node = None
    run.waiting_signal = None
    run.waiting_ref = None
    run.wait_deadline = None
    run.completed_at = _now()
    _timeline(run, None, "completed")
    await _persist(run)
    await _resolve_in_setup_on_terminal(run)
    await _maybe_reconcile(run)


async def _fail(run: FlowRun, message: str) -> None:
    run.status = "failed"
    run.error = message
    run.waiting_signal = None
    run.waiting_ref = None
    run.wait_deadline = None
    run.completed_at = _now()
    _timeline(run, run.current_node, f"failed: {message}")
    logger.info("ATC: run %s failed: %s", run.id, message)
    await _persist(run)
    await _resolve_in_setup_on_terminal(run)
    await _maybe_reconcile(run)


async def _persist(run: FlowRun) -> None:
    """Full save of a FlowRun at a checkpoint. A run is only ever advanced by one
    caller at a time (the waiting->running claim is atomic), so a full save can't
    clobber a concurrent writer the way a Device row could."""
    try:
        await run.save()
    except Exception:
        logger.exception("ATC: persisting run %s failed", run.id)


async def _maybe_reconcile(run: FlowRun) -> None:
    """If the run changed device state that drives scoping (tags -> groups),
    kick a reactive reconcile so profile/app deployment follows."""
    if not (run.context or {}).get("dirty"):
        return
    try:
        from controller.services.reconciler import _spawn, reconcile_tenant

        async def _run() -> None:
            try:
                tenant = await Tenant.get_or_none(id=run.tenant_id)
                if tenant:
                    await reconcile_tenant(tenant, tenant_config.yaml_base())
            except Exception:
                logger.exception("ATC: post-flow reconcile failed for tenant %s", run.tenant_id)

        _spawn(_run())
    except Exception:
        logger.exception("ATC: scheduling reconcile failed for run %s", run.id)


#  Context helpers 

def _signal_satisfies(run: FlowRun, signal: str, ref: Optional[str]) -> bool:
    if signal in _REFLESS_SIGNALS:
        return True
    expected = (run.context or {}).get("expected", {}).get(signal) or []
    return ref is not None and str(ref) in [str(x) for x in expected]


def _expect(run: FlowRun, signal: str, refs: List[str]) -> None:
    ctx = run.context or {}
    expected = ctx.setdefault("expected", {})
    bucket = expected.setdefault(signal, [])
    for r in refs:
        if str(r) not in [str(x) for x in bucket]:
            bucket.append(str(r))
    run.context = ctx


def _consume_expected(run: FlowRun, signal: Optional[str]) -> None:
    """Clear the refs a just-left wait_for was waiting on (resumed / skipped /
    timed out) so a later wait_for on the SAME signal starts with a fresh
    expectation instead of being satisfied by a stale ref from the earlier one."""
    if not signal:
        return
    ctx = run.context or {}
    expected = ctx.get("expected")
    if isinstance(expected, dict) and signal in expected:
        expected[signal] = []
        run.context = ctx


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
