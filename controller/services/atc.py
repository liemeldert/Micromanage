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

from controller.models.tenant import Device, FlowRun, Tenant
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

# Signals a wait_for node resumes on that need no reference (any occurrence for
# the device satisfies them). The rest (profile_installed / app_installed /
# command_ack) match against what the run itself queued (context['expected']).
_REFLESS_SIGNALS = frozenset({"device_info", "checkin"})


# ── Loading + hashing ────────────────────────────────────────────────────────

def _load_flows(tenant_id: str) -> List[Dict[str, Any]]:
    """The ``flows`` list from a tenant's flows.yaml (empty if absent/malformed)."""
    flows = tenant_config._load(tenant_id, "flows.yaml").get("flows", [])
    return flows if isinstance(flows, list) else []


def _flow_hash(flow: Dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(flow, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _nodes_by_id(flow: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        n["id"]: n
        for n in (flow.get("nodes") or [])
        if isinstance(n, dict) and n.get("id")
    }


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


# ── Entry points ─────────────────────────────────────────────────────────────

async def start_flows_for_enroll(device: Device) -> Optional[FlowRun]:
    """Start the single best-matching enroll flow for a freshly (re)enrolled
    device. Best-effort: never raises into the enroll path."""
    try:
        flows = _load_flows(str(device.tenant_id))
    except Exception:
        logger.exception("ATC: loading flows failed for tenant %s", device.tenant_id)
        return None

    device_groups = list(device.groups or [])
    matches: List[Dict[str, Any]] = []
    for flow in flows:
        try:
            if not isinstance(flow, dict) or not flow.get("enabled", True):
                continue
            trigger = flow.get("trigger") or {}
            if trigger.get("on") != "enroll":
                continue
            if _scope_matches(device, device_groups, trigger.get("match")):
                matches.append(flow)
        except Exception:
            logger.exception("ATC: trigger evaluation failed for flow %r",
                             (flow or {}).get("id"))
            continue

    if not matches:
        return None

    # Highest priority wins; ties broken by id (stable, matches the spec).
    flow = sorted(matches, key=lambda f: (-(f.get("priority") or 0), str(f.get("id"))))[0]
    flow_id = str(flow.get("id"))
    start = flow.get("start")
    nodes = _nodes_by_id(flow)
    if start not in nodes:
        logger.error("ATC: flow %r start node %r missing; not starting", flow_id, start)
        return None

    # A re-enroll supersedes any still-active run of the same flow on this device.
    try:
        await FlowRun.filter(
            device_id=device.id, flow_id=flow_id, status__in=["running", "waiting"]
        ).update(status="cancelled", current_node=None, waiting_signal=None,
                 waiting_ref=None, wait_deadline=None, completed_at=_now())
    except Exception:
        logger.exception("ATC: superseding prior runs failed for flow %s", flow_id)

    run = await FlowRun.create(
        tenant_id=device.tenant_id,
        device_id=device.id,
        flow_id=flow_id,
        flow_hash=_flow_hash(flow),
        status="running",
        current_node=start,
        context={"flow": flow, "timeline": [], "visited": [], "expected": {}},
    )
    logger.info("ATC: started flow %s for %s (run %s)", flow_id, device.serial_number, run.id)
    await _advance(run, device)
    return run


async def start_flow_by_id(device: Device, flow_id: str) -> Optional[FlowRun]:
    """Manually start a specific flow against a device (testing / API).

    Ignores the trigger match (an operator asked for this flow explicitly) but
    still supersedes an active run of the same flow. Returns None if the flow
    doesn't exist or is malformed."""
    flows = _load_flows(str(device.tenant_id))
    flow = next((f for f in flows if isinstance(f, dict) and str(f.get("id")) == flow_id), None)
    if flow is None:
        return None
    start = flow.get("start")
    if start not in _nodes_by_id(flow):
        return None
    await FlowRun.filter(
        device_id=device.id, flow_id=flow_id, status__in=["running", "waiting"]
    ).update(status="cancelled", current_node=None, waiting_signal=None,
             waiting_ref=None, wait_deadline=None, completed_at=_now())
    run = await FlowRun.create(
        tenant_id=device.tenant_id, device_id=device.id, flow_id=flow_id,
        flow_hash=_flow_hash(flow), status="running", current_node=start,
        context={"flow": flow, "timeline": [], "visited": [], "expected": {}, "manual": True},
    )
    await _advance(run, device)
    return run


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
                run.status = "running"
                run.current_node = nxt
                _timeline(run, run.current_node, f"resumed on {signal}")
                await _advance(run, device)
            except Exception:
                logger.exception("ATC: advancing run %s on signal %s failed", run.id, signal)
    except Exception:
        logger.exception("ATC: advance_on_signal(%s, %s) failed", device_id, signal)


async def sweep_timeouts(tenant: Tenant) -> int:
    """Resolve waiting runs whose deadline has passed: take the ``on_timeout``
    edge, else fail the run. Returns how many were swept."""
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
                _timeline(run, on_timeout, "wait timed out")
                if device is None:
                    await _fail(run, "device no longer exists")
                else:
                    await _advance(run, device)
            else:
                await _fail(run, f"timed out waiting for '{run.waiting_signal or 'signal'}'")
        except Exception:
            logger.exception("ATC: sweeping run %s failed", run.id)

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


# ── Execution ────────────────────────────────────────────────────────────────

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
                _timeline(run, nid, f"wait skipped ({signal} already satisfied)")
                run.current_node = nxt
                continue
            await _park(run, node)
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
    if ntype == "branch":
        cond = params.get("condition") or {}
        result = evaluate_condition(device, cond, list(device.groups or []))
        _timeline(run, node.get("id"), f"branch -> {'true' if result else 'false'}")
        return node.get("on_true") if result else node.get("on_false")

    # Unknown node type: the validator rejects these, but fail safe at runtime.
    raise ValueError(f"unknown node type: {ntype}")


# ── Node side effects ────────────────────────────────────────────────────────

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
    from controller.services.mdm_connector import MDMConnector
    from controller.services.naming import resolve_name
    from controller.services.task_manager import TaskManager

    resolved = resolve_name(template, device)
    if not resolved:
        _timeline(run, run.current_node, "set_name: template rendered empty; skipped")
        return
    device.name = resolved
    await device.save(update_fields=["name"])
    _timeline(run, run.current_node, f"set_name -> {resolved!r}")
    # Push to the device (supervised only actually applies); fire-and-forget.
    if device.enrollment_state != "enrolled" or not device.udid:
        return
    tenant = await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None:
        return
    task = await TaskManager().create_task(
        tenant=tenant, task_type="set_name",
        description=f"ATC rename {device.serial_number} to {resolved!r}",
        device=device, user=f"atc:{run.flow_id}", details={},
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
    except Exception:
        logger.exception("ATC: wait pre-check failed for signal %s", signal)
    return False


# ── State transitions ────────────────────────────────────────────────────────

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


# ── Context helpers ──────────────────────────────────────────────────────────

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
