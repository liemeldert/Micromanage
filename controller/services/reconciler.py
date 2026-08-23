"""Desired-state reconciliation: YAML definitions to MDM tasks.

Called by the periodic sync service and reactively via request_reconcile after a config save or POST
/api/v1/sync. Per device, computes group membership and the desired profile/app set, then queues installs,
removals and retries per _needs_deploy, and retires what a device is no longer scoped into.
"""

import asyncio
import logging
import os
import weakref
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from typing import Any, Dict, List, Optional

from controller.models.tenant import (
    AppDeployment, DEDUP_KEY_TYPES, Device, ProfileDeployment, Task, task_dedup_key, Tenant
)
from controller.services import tenant_config
from controller.services.app_manager import AppManager
from controller.services.group_manager import GroupManager
from controller.services.profile_manager import (flow_source_id, ProfileManager, remediation_rule_id)
from controller.services.task_manager import TaskManager

logger = logging.getLogger(__name__)

# How long an enqueued command may sit unanswered before we resend it, and the first interval between two attempts at
# something that failed.
RETRY_MINUTES = int(os.getenv("MDM_COMMAND_RETRY_MINUTES", "30"))
# The longest that interval may grow to.
RETRY_MAX_MINUTES = int(os.getenv("MDM_COMMAND_RETRY_MAX_MINUTES", "1440"))
# How long an app may sit at 'accepted' before the silence is treated as a failure. Only an inventory report
# naming the bundle id confirms a macOS install; the ack itself says nothing.
APP_CONFIRM_MINUTES = int(os.getenv("MDM_APP_CONFIRM_MINUTES", "60"))
# How long a task may stay pending/running before it is failed as timed out.
TASK_TIMEOUT_HOURS = int(os.getenv("MDM_TASK_TIMEOUT_HOURS", "24"))
# Ceiling on handler coroutines running at once, across every _spawn caller. Bounds contention for
# DB_POOL_MAX_SIZE connections (models.database).
MAX_CONCURRENT_TASKS = int(os.getenv("MDM_MAX_CONCURRENT_TASKS", "25"))

# Strong references to background handler tasks: asyncio only holds weak references to Tasks, so an unreferenced one can
# be garbage-collected mid-run.
_background_tasks: set = set()

# Per-event-loop, so a process that tears its loop down and builds a new one (tests, a worker restart) doesn't reuse a
# primitive bound to the dead one.
_semaphores: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def _semaphore() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    sem = _semaphores.get(loop)
    if sem is None:
        sem = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
        _semaphores[loop] = sem
    return sem


async def _bounded(coro) -> None:
    async with _semaphore():
        await coro


def _spawn(coro) -> None:
    """Run a coroutine in the background, bounded to MAX_CONCURRENT_TASKS at a time.

    Contract for callers (dispatcher, atc, api/main all rely on it): returns immediately, never raises, keeps a strong
    reference so the task survives GC. The coroutine waits its turn at the semaphore before it starts.
    """
    t = asyncio.create_task(_bounded(coro))
    _background_tasks.add(t)
    t.add_done_callback(_background_tasks.discard)


async def drain_background_tasks() -> None:
    """Wait for every spawned handler to finish, including ones spawned while waiting.

    Called under a timeout by the controller's shutdown path; the webhook process has its own drain over the
    same set (webhook_handler.drain_deferred).
    """
    while _background_tasks:
        await asyncio.gather(*list(_background_tasks), return_exceptions=True)


# ==Reactive reconcile coalescing==
# One worker per tenant runs at most one reconcile at a time; requests arriving mid-run set a dirty flag and
# collapse into exactly one more run, so a burst of triggers costs one run instead of one each.

_reconcile_dirty: Dict[str, bool] = {}
_reconcile_workers: Dict[str, asyncio.Task] = {}


async def _reconcile_worker(tenant_id: str) -> None:
    try:
        # No await between the pop and the loop exit, so on a single-threaded event loop a request can't slip in after
        # we decide we're done.
        while _reconcile_dirty.pop(tenant_id, False):
            try:
                tenant = await Tenant.get_or_none(id=tenant_id)
                if tenant is None:
                    return
                await reconcile_tenant(tenant, tenant_config.yaml_base())
            except Exception:
                logger.exception("reactive reconcile failed for tenant %s", tenant_id)
    finally:
        _reconcile_workers.pop(tenant_id, None)


def request_reconcile(tenant_id: str) -> None:
    """Ask for a reconcile of a tenant, coalescing a burst into one run.

    Returns at once; a failure is logged rather than reaching the caller. The scheduled sync calls
    reconcile_tenant directly instead of going through here.
    """
    tenant_id = str(tenant_id)
    try:
        _reconcile_dirty[tenant_id] = True
        if tenant_id in _reconcile_workers:
            return  # already running or queued; the dirty flag carries this one
        task = asyncio.create_task(_reconcile_worker(tenant_id))
        _reconcile_workers[tenant_id] = task
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)
    except Exception:
        logger.exception("scheduling reconcile failed for tenant %s", tenant_id)


def _load_yaml(path: Path) -> Dict[str, Any]:
    """Read one YAML file through the shared tenant_config cache.

    Path-shaped rather than (tenant, filename) since reconcile_tenant already holds a yaml_base.
    """
    return tenant_config.load_file(path)


def _task_key(device_id: Any, task_type: str, details: Dict[str, Any]) -> tuple:
    """The dedup identity of one task: (device, type, key part).

    Mirrors models.tenant.task_dedup_key, the same function Task.save uses to fill dedup_key, so the lookup key
    here and the stored key can never disagree.
    """
    return (str(device_id), task_type, task_dedup_key(task_type, details))


# The types _active_task_keys keys on. ddm_sync earns a key from its type alone (one sync per device) and is
# absent from models.tenant's DEDUP_KEY_TYPES list; composed from that list so the two cannot drift apart.
_KEYED_TASK_TYPES = (*DEDUP_KEY_TYPES, "ddm_sync")


async def _active_task_keys(tenant: Tenant) -> set:
    """Keys of the tasks still outstanding, to avoid queueing duplicates.

    Reads the mirrored dedup_key column rather than recomputing from the details JSONB, which would move and
    detoast thousands of multi-KB documents every cycle for no reason.
    """
    keys = set()
    active = await Task.filter(
        tenant=tenant, status__in=["pending", "running"]
    ).values("device_id", "type", "dedup_key")
    unmirrored = False
    for t in active:
        ttype = t["type"]
        if ttype not in _KEYED_TASK_TYPES:
            continue
        if t["dedup_key"] is None and ttype in DEDUP_KEY_TYPES:
            # Recomputed below rather than dropped: a missing key reads as nothing outstanding and queues a
            # duplicate of a task that is already running.
            unmirrored = True
            continue
        keys.add((str(t["device_id"]), ttype, t["dedup_key"]))
    if unmirrored:
        keys |= await _unmirrored_task_keys(tenant)
    return keys


async def _unmirrored_task_keys(tenant: Tenant) -> set:
    """The details-JSONB derivation of the key, for rows whose column is still NULL."""
    return {
        (str(t["device_id"]), t["type"], task_dedup_key(t["type"], t["details"]))
        for t in await Task.filter(
            tenant=tenant,
            status__in=["pending", "running"],
            type__in=list(DEDUP_KEY_TYPES),
            dedup_key__isnull=True,
        ).values("device_id", "type", "details")
    }


# Prefix matters: webhook_handler._dispatch_command_response tests for it to tell a task this sweep failed apart from
# one a device or a handler failed, and lets a late device response supersede only the former.
TIMEOUT_ERROR = (
    f"Timed out: no device response within {TASK_TIMEOUT_HOURS}h. "
    "The device may be offline or the command was lost."
)

# What a deployment row's status may be when its own attempt times out. 'failed' and 'accepted' are excluded.
_TIMEOUT_WRITEBACK_STATUSES = ["pending", "installing", "installed"]

# The status an app row takes when the device acknowledged InstallApplication and nothing has confirmed the app is on
# the device.
APP_ACCEPTED_STATUS = "accepted"

# What such a row is failed with when no inventory ever names the app.
APP_UNCONFIRMED_ERROR = (
    "the device accepted the install but the app never appeared in its inventory. On macOS that is usually the package:"
    " a component package rather than a distribution archive, an unsigned or untrusted signature, or a managed install "
    "of a package that installs no application bundle (set install_as_managed: false on the app for that last one)"
)


async def _fail_timed_out_tasks(tenant: Tenant) -> int:
    """Fail tasks that have waited too long for a device response, and mark what they were installing as failed
    too, since a row left alone would keep claiming success nobody confirmed.

    Only touches rows whose last_task_id is one of the tasks failed here, so a deployment since retried under
    a newer task keeps that task's state. A late device response still overwrites this via the webhook.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=TASK_TIMEOUT_HOURS)
    stale = await Task.filter(
        tenant=tenant, status__in=["pending", "running"], created_at__lt=cutoff
    ).values("id", "type")
    if not stale:
        return 0
    ids = [row["id"] for row in stale]
    # One UPDATE, not one per row. After a long outage this can be the whole fleet's worth of queued commands, and the
    # rows are identical apart from their ids. tenant stays on the filter even though the ids are already tenant-scoped.
    await Task.filter(tenant=tenant, id__in=ids).update(
        status="failed",
        completed_at=now,
        error=TIMEOUT_ERROR,
    )

    # The deployment write-back the same way: one statement per model, keyed on the tasks just failed. updated_at is set
    # explicitly because a queryset update does not fire auto_now, and _needs_deploy measures the retry wait from it.
    for task_type, model in (("app_install", AppDeployment),
                             ("profile_install", ProfileDeployment)):
        typed = [row["id"] for row in stale if row["type"] == task_type]
        if not typed:
            continue
        await model.filter(
            tenant=tenant, last_task_id__in=typed,
            status__in=_TIMEOUT_WRITEBACK_STATUSES,
        ).update(status="failed", last_error=TIMEOUT_ERROR, updated_at=now)

    logger.warning("reconcile[%s]: timed out %d task(s)", tenant.id, len(ids))
    return len(ids)


async def _fail_unconfirmed_apps(tenant: Tenant) -> int:
    """Fail app rows the device accepted and never confirmed. Returns how many.

    Does NOT count the attempt itself; _note_attempt counts the re-push that follows, so the ladder advances
    once per round rather than twice. Nothing may clear the counter on a device acknowledgement, which is the
    event immediately before every one of these failures; clearing belongs with the promotion to installed.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=APP_CONFIRM_MINUTES)
    unconfirmed = await AppDeployment.filter(
        tenant=tenant, status=APP_ACCEPTED_STATUS, updated_at__lt=cutoff
    ).update(status="failed", last_error=APP_UNCONFIRMED_ERROR, updated_at=now)
    if unconfirmed:
        logger.warning(
            "reconcile[%s]: %d app install(s) were accepted by their device and "
            "never appeared in an inventory within %dm; failing them so they "
            "retry", tenant.id, unconfirmed, APP_CONFIRM_MINUTES)
    return unconfirmed


# .only() width for the tenant-wide deployment prefetches below. Every field here is read by the device loop;
# a new field the loop needs must be added to these lists, since an unfetched field raises AttributeError on a
# Tortoise partial. These partial instances must never be save()d: deployment writes stay on the fully-loaded
# rows the ensure_deployment / deploy paths fetch themselves.
_PROFILE_PREFETCH_FIELDS = (
    "id", "device_id", "profile_id", "status", "payload_hash", "updated_at",
    "failed_attempts", "install_source",
)
_APP_PREFETCH_FIELDS = (
    "id", "device_id", "app_id", "status", "app_version", "updated_at",
    "failed_attempts", "install_source",
)


async def _prefetch_profile_deployments(
    tenant: Tenant,
) -> Dict[str, List[ProfileDeployment]]:
    """Tenant-wide ProfileDeployment rows grouped by device id: one query per cycle instead of one per device."""
    grouped: Dict[str, List[ProfileDeployment]] = {}
    for row in await ProfileDeployment.filter(tenant=tenant).only(
        *_PROFILE_PREFETCH_FIELDS
    ):
        grouped.setdefault(str(row.device_id), []).append(row)
    return grouped


async def _prefetch_app_deployments(
    tenant: Tenant,
) -> Dict[str, List[AppDeployment]]:
    """The app half of _prefetch_profile_deployments; same contract."""
    grouped: Dict[str, List[AppDeployment]] = {}
    for row in await AppDeployment.filter(tenant=tenant).only(
        *_APP_PREFETCH_FIELDS
    ):
        grouped.setdefault(str(row.device_id), []).append(row)
    return grouped


# The reason string for a re-push that has nothing new to say: the same content already rejected, tried again
# because enough time has passed. The one reason that spends a retry, so _note_attempt keys on it.
RETRY_AFTER_FAILURE = "previous attempt failed"


def _retry_delay_minutes(failed_attempts: int) -> int:
    """How long to leave a failed deployment alone before attempting it again: RETRY_MINUTES after the first
    failure, doubling per consecutive failure, capped at RETRY_MAX_MINUTES. Exponent is clamped so months of failures cannot turn this into a bignum multiplication.
    """
    attempts = max(int(failed_attempts or 0), 0)
    return min(RETRY_MINUTES * (2 ** min(attempts, 20)), RETRY_MAX_MINUTES)


def _needs_deploy(
    deployment: Optional[Any], *, up_to_date: bool, definition_changed: bool,
    changed_reason: str, now: datetime,
) -> Optional[str]:
    """Return a reason string if this deployment should be (re)pushed, else None.

    One rule for apps and profiles; up_to_date and definition_changed are the kind-specific halves the callers
    compute (payload_hash for profiles, version for apps).
    """
    if deployment is None:
        return "not deployed"
    if deployment.status == "failed":
        # A definition that has moved on since the failure is not the thing that failed, so it goes now instead of
        # waiting out a backoff meant to stop us re-sending what was just rejected.
        if definition_changed:
            return changed_reason
        # Otherwise back off, further each time, so a persistent failure (device broken, NanoMDM down, nothing to serve
        # the package from) does not spawn a new task every sync cycle for the rest of the device's life.
        updated = deployment.updated_at
        wait = _retry_delay_minutes(deployment.failed_attempts)
        if updated and updated > now - timedelta(minutes=wait):
            return None
        return RETRY_AFTER_FAILURE
    if deployment.status in ("pending", "installing"):
        updated = deployment.updated_at
        if updated and updated < now - timedelta(minutes=RETRY_MINUTES):
            return f"no device response for {RETRY_MINUTES}m; retrying"
        return None  # attempt outstanding
    if deployment.status == APP_ACCEPTED_STATUS:
        # Outstanding like 'installing', but waits on its own clock (_fail_unconfirmed_apps) instead of a
        # retry.
        return None
    if deployment.status == "installed":
        return None if up_to_date else changed_reason
    if deployment.status == "unscoped":
        # Scoped out and now scoped back in. The row records what was true when the device left scope and nothing since,
        # so there is nothing to compare against and the install goes.
        return "back in scope"
    return None


def _profile_needs_deploy(
    deployment: Optional[ProfileDeployment], desired_hash: str, now: datetime
) -> Optional[str]:
    # A missing payload_hash reads as out of date but NOT changed, else a row that never recorded a hash would
    # get an immediate retry every cycle instead of the normal backoff.
    return _needs_deploy(
        deployment, now=now,
        up_to_date=deployment is not None and deployment.payload_hash == desired_hash,
        definition_changed=(deployment is not None
                            and deployment.payload_hash is not None
                            and deployment.payload_hash != desired_hash),
        changed_reason="profile definition changed",
    )


def _app_needs_deploy(
    deployment: Optional[AppDeployment], desired_version: str, now: datetime
) -> Optional[str]:
    """The app half of the same rule. A version is recorded at row creation, so unlike a profile's payload_hash
    it always says something and not-current/changed collapse into one question here."""
    changed = deployment is not None and deployment.app_version != desired_version
    return _needs_deploy(
        deployment, now=now,
        up_to_date=not changed and deployment is not None,
        definition_changed=changed,
        changed_reason="app version changed",
    )


async def _note_attempt(model: Any, deployment: Optional[Any],
                        reason: Optional[str]) -> None:
    """Keep a deployment's failure counter in step with what this cycle decided.

    Uses a queryset UPDATE, not save(), since the rows the loop holds are partial prefetch instances. Does not
    touch updated_at, the clock the backoff measures from.
    """
    if deployment is None:
        return
    attempts = deployment.failed_attempts
    if reason == RETRY_AFTER_FAILURE:
        await model.filter(id=deployment.id).update(failed_attempts=attempts + 1)
        deployment.failed_attempts = attempts + 1
        return
    if not attempts:
        return
    if (deployment.status == "failed" and reason) or deployment.status == "installed":
        await model.filter(id=deployment.id).update(failed_attempts=0)
        deployment.failed_attempts = 0


def _remediation_rule_ids(tenant_path: Path) -> Optional[set]:
    """Ids of the compliance rules this tenant currently defines, or None when the document does not say.

    None is not an empty set: an unreadable dispatcher.yaml must not be mistaken for one with no rules, or every
    remediation hold in the tenant releases over a bad save. dispatcher._resolve_orphaned_alerts uses
    the same test.
    """
    doc = _load_yaml(tenant_path / "dispatcher.yaml")
    rules = doc.get("rules")
    if not isinstance(rules, list):
        return None
    return {
        str(rule["id"]) for rule in rules
        if isinstance(rule, dict) and rule.get("id") is not None
    }


def _flow_ids(tenant_path: Path) -> Optional[set]:
    """Ids of the flows this tenant currently defines, or None when the document does not say.

    The flow half of _remediation_rule_ids, same evidence rule. Both authored formats count (current: a flow
    mapping, legacy: a flows list); an unnamed flow takes the literal id "flow" to match services.atc.
    """
    doc = _load_yaml(tenant_path / "flows.yaml")
    flow = doc.get("flow")
    if isinstance(flow, dict) and flow:
        return {str(flow.get("id") or "flow")}
    legacy = doc.get("flows")
    if not isinstance(legacy, list):
        return None
    return {
        str(entry.get("id") or "flow") for entry in legacy
        if isinstance(entry, dict)
    }


def _any_install_mark(reader: Any,
                      *grouped: Optional[Dict[str, List[Any]]]) -> bool:
    """Whether any prefetched deployment row was installed by an engine outside the device's scope, of the
    kind reader recognises. Only asked when the document for that kind said nothing, so the warning reaches a
    tenant that actually has such rows. A failed prefetch is None and is skipped.
    """
    for rows_by_device in grouped:
        if not rows_by_device:
            continue
        for rows in rows_by_device.values():
            for row in rows:
                if reader(getattr(row, "install_source", None)):
                    return True
    return False


def _held_by_remediation(deployment: Any, rule_ids: Optional[set],
                         flow_ids: Optional[set] = None) -> bool:
    """Whether a deployment the device's scope does not ask for stays anyway.

    One rule for profiles and apps and for both engines (compliance rules, flows) that install outside a
    scope; without this the removal pass would take such an install off on the next cycle and the two engines
    would take turns re-adding and removing it. A row is held for as long as what installed it
    (install_source) is still defined; rule_ids/flow_ids of None holds everything that kind marked.
    """
    source = getattr(deployment, "install_source", None)
    for holder_id, defined in ((remediation_rule_id(source), rule_ids),
                               (flow_source_id(source), flow_ids)):
        if holder_id is None:
            continue
        if defined is None:
            return True  # nothing said it is gone, so nothing comes off
        return holder_id in defined
    return False


# What an app deployment row becomes when its device leaves the app's scope.
APP_UNSCOPED_STATUS = "unscoped"


async def _unscope_apps(rows: List[AppDeployment], desired_app_ids: set,
                        now: datetime, rule_ids: Optional[set] = None,
                        flow_ids: Optional[set] = None) -> int:
    """Retire the app deployment rows a device is no longer scoped into.

    Unlike profiles, no RemoveApplication is sent: Apple's RemoveApplication only takes back an app installed
    and still held as managed, so sending one for a user-installed or pre-enrolment app either no-ops or takes
    away something nobody asked us to. A failed/pending row is deleted; an installed/installing/accepted row
    is marked unscoped instead, since the app may still be on the device. Held rows (see _held_by_remediation)
    are skipped. Writes go through the
    queryset so a prefetched partial row is never save()d.
    """
    retired = 0
    for row in rows:
        if row.app_id in desired_app_ids or row.status == APP_UNSCOPED_STATUS:
            continue
        if _held_by_remediation(row, rule_ids, flow_ids):
            continue
        if row.status in ("failed", "pending"):
            await row.delete()
        else:
            # Cleared so a device coming back into scope doesn't start its backoff part-way up an old ladder.
            await AppDeployment.filter(id=row.id).update(
                status=APP_UNSCOPED_STATUS, last_error=None, failed_attempts=0,
                updated_at=now)
            row.status = APP_UNSCOPED_STATUS
        retired += 1
    return retired


async def reconcile_tenant(tenant: Tenant, yaml_base: Path) -> Dict[str, int]:
    """Reconcile one tenant's declared YAML state against its devices.

    The returned summary counts what this cycle did; apps_blocked is the one entry that counts work NOT done.
    """
    tenant_path = yaml_base / "tenants" / tenant.id
    groups_config = _load_yaml(tenant_path / "groups.yaml").get("groups", [])
    apps_config = _load_yaml(tenant_path / "apps.yaml").get("apps", [])
    profiles_config = _load_yaml(tenant_path / "profiles.yaml").get("profiles", [])
    # For the retirement passes; None holds everything (see _remediation_rule_ids).
    remediation_rule_ids = _remediation_rule_ids(tenant_path)
    flow_ids = _flow_ids(tenant_path)

    for group in groups_config:
        if not group.get("conditions"):
            logger.warning(
                f"reconcile[{tenant.id}]: group '{group.get('name')}' has no conditions "
                "and will match no devices"
            )

    summary = {"profiles_queued": 0, "removals_queued": 0, "apps_queued": 0,
               "apps_blocked": 0, "apps_unscoped": 0, "apps_unconfirmed": 0,
               "ddm_syncs_queued": 0, "tasks_timed_out": 0, "devices": 0,
               "errors": 0}

    summary["tasks_timed_out"] = await _fail_timed_out_tasks(tenant)
    # Before the prefetch, so a row failed here starts its retry ladder this cycle rather than next.
    summary["apps_unconfirmed"] = await _fail_unconfirmed_apps(tenant)

    # Only enrolled devices can receive commands. only() avoids pulling installed_apps/installed_profiles/
    # ddm_status (tens of MB of TOAST per cycle at 2000 devices); every field kept here is read either by
    # scoping/DDM below or by the spawned task handler off this same partial instance.
    devices = await Device.filter(tenant=tenant, enrollment_state="enrolled").only(
        "id", "tenant_id", "udid", "serial_number", "device_model", "os_version",
        "hostname", "name", "enrollment_state", "enrollment_date", "groups", "tags",
        "attributes", "ddm_enabled_at", "ddm_last_published_token",
        "ddm_client_capabilities",
    )
    summary["devices"] = len(devices)
    if not devices:
        return summary

    active = await _active_task_keys(tenant)
    now = datetime.now(timezone.utc)

    # Optimization, never a precondition: None means the prefetch failed and the loop falls back per-device; a
    # device missing from a built dict just has no rows. The two must never be confused.
    profile_rows: Optional[Dict[str, List[ProfileDeployment]]] = None
    try:
        profile_rows = await _prefetch_profile_deployments(tenant)
    except Exception:
        logger.warning("reconcile[%s]: profile deployment prefetch failed; "
                       "falling back to per-device queries this cycle",
                       tenant.id, exc_info=True)
    app_rows: Optional[Dict[str, List[AppDeployment]]] = None
    try:
        app_rows = await _prefetch_app_deployments(tenant)
    except Exception:
        logger.warning("reconcile[%s]: app deployment prefetch failed; "
                       "falling back to per-device queries this cycle",
                       tenant.id, exc_info=True)

    # Once for the tenant, not once per device, and only when there is something to say: rows a rule installed are being
    # kept because dispatcher.yaml could not be read.
    for defined, reader, document, key in (
            (remediation_rule_ids, remediation_rule_id, "dispatcher.yaml", "rules"),
            (flow_ids, flow_source_id, "flows.yaml", "flow")):
        if defined is None and _any_install_mark(reader, profile_rows, app_rows):
            logger.warning(
                "reconcile[%s]: %s carries no %s, so it cannot say what still "
                "exists. Everything installed from it stays where it is this "
                "cycle. Check that %s parses; an authored empty one is still an "
                "answer and does release them.",
                tenant.id, document, key, document)

    # Hashed once per profile instead of once per device x profile, since the definitions are per-cycle
    # constants. .get() so a malformed entry stays a per-device error rather than aborting the whole cycle.
    profile_hashes = {
        p["id"]: ProfileManager.desired_hash(p)
        for p in profiles_config
        if isinstance(p, dict) and p.get("id") is not None
    }

    profile_manager = ProfileManager(tenant)
    app_manager = AppManager(tenant)
    task_manager = TaskManager()
    group_manager = GroupManager(tenant.id)

    # Whether this tenant can serve an app package at all, asked once for the cycle instead of once per
    # device install (which would repeat the same failed task and warning per device per retry window).
    apps_blocked = app_manager.package_store_error() if apps_config else None
    if apps_blocked:
        logger.warning("reconcile[%s]: holding app installs this cycle. %s",
                       tenant.id, apps_blocked)

    # DDM config is read once per cycle rather than once per device, since sync_device would otherwise re-read
    # declarations.yaml and groups.yaml off disk for every device and look the tenant up again on top.
    ddm = None
    declarations_config = None
    if tenant.ddm_enabled:
        from controller.services import ddm_manager as ddm
        declarations_config = tenant_config.normalize_declarations(
            _load_yaml(tenant_path / "declarations.yaml")
        )

    from controller.services.task_handlers import (
        handle_app_install_task,
        handle_profile_install_task,
        handle_profile_remove_task,
        shared_connector,
    )

    for device in devices:
        try:
            # Computed once, threaded through profile/app scoping and DDM so all consumers use one answer.
            # Not cached across devices or cycles; see group_manager for why a longer-lived cache is wrong.
            device_groups = group_manager.evaluate_device_groups(device, groups_config)

            # ==Profiles: desired set==
            # held_ids are scoped to this device but frozen behind a rollout wave it hasn't reached. They still count as
            # desired, so nothing uninstalls them, but they don't get installed or updated yet.
            desired, held_ids = await profile_manager.evaluate_device_profiles(
                device, profiles_config, groups_config, device_groups=device_groups
            )
            desired_ids = {p["id"] for p in desired} | held_ids

            # The device's deployments, indexed by profile. Normally a dict lookup into the cycle-wide prefetch, where a
            # missing key is the no-rows answer; only a failed prefetch pays the per-device query, which fetches full
            # rows, so the degraded path never handles a partial instance.
            if profile_rows is not None:
                device_profile_rows = profile_rows.get(str(device.id), [])
            else:
                device_profile_rows = await ProfileDeployment.filter(device=device).all()
            deployments = {d.profile_id: d for d in device_profile_rows}

            for profile in desired:
                # Keyed on the definition itself, which is what the created row keys on: the key part is the profile id,
                # and the details stored are this same definition with its secrets replaced.
                key = _task_key(device.id, "profile_install", {"profile_info": profile})
                if key in active:
                    continue
                existing = deployments.get(profile["id"])
                desired_hash = (profile_hashes.get(profile["id"])
                                or ProfileManager.desired_hash(profile))
                reason = _profile_needs_deploy(existing, desired_hash, now)
                await _note_attempt(ProfileDeployment, existing, reason)
                if not reason:
                    continue
                task = await task_manager.create_task(
                    tenant=tenant,
                    task_type="profile_install",
                    description=f"Install profile: {profile.get('name', profile['id'])} ({reason})",
                    device=device,
                    user="system",
                    # A digest and a redacted copy, not the payload itself (see ProfileManager.install_task_details).
                    # The handler below is handed the real definition directly and never reads this back.
                    details=ProfileManager.install_task_details(profile, desired_hash),
                )
                # Bind the device/tenant already in hand, sparing the handler a re-read (~20,000 queries on a
                # first reconcile of 2000 devices x 5 profiles otherwise). partial() captures by value.
                _spawn(task_manager.execute_task(
                    task,
                    partial(handle_profile_install_task, device=device,
                            tenant=tenant, profile_info=profile),
                ))
                active.add(key)
                summary["profiles_queued"] += 1

            # ==Profiles: remove what is installed but no longer desired==
            for deployment in deployments.values():
                if deployment.profile_id in desired_ids:
                    continue
                if _held_by_remediation(deployment, remediation_rule_ids, flow_ids):
                    continue
                if deployment.status in ("failed", "pending"):
                    # Nothing reliably on the device, so just drop the record.
                    await deployment.delete()
                    continue
                key = _task_key(device.id, "profile_remove",
                                {"profile_id": deployment.profile_id})
                if key in active:
                    continue
                task = await task_manager.create_task(
                    tenant=tenant,
                    task_type="profile_remove",
                    description=f"Remove profile: {deployment.profile_id} (no longer scoped to this device)",
                    device=device,
                    user="system",
                    details={"profile_id": deployment.profile_id},
                )
                _spawn(task_manager.execute_task(
                    task,
                    partial(handle_profile_remove_task, device=device, tenant=tenant),
                ))
                active.add(key)
                summary["removals_queued"] += 1

            # ==Apps==
            apps_to_install = await app_manager.evaluate_device_apps(
                device, apps_config, groups_config, device_groups=device_groups
            )
            # This device's app rows, keyed by app_id, mirroring the profile pass above. Keyed by app rather than by
            # (app, version) because the table holds one row per (device, app_id): a version bump rewrites that row, so
            # the row at the old version is the same row and the staleness rule has to see it.
            if app_rows is not None:
                device_app_rows = app_rows.get(str(device.id), [])
            else:
                device_app_rows = await AppDeployment.filter(device=device).all()
            app_deployments = {d.app_id: d for d in device_app_rows}
            for app in apps_to_install:
                key = _task_key(device.id, "app_install", {"app_info": app})
                if key in active:
                    continue
                existing = app_deployments.get(app["app_id"])
                reason = _app_needs_deploy(existing, app["version"], now)
                if apps_blocked:
                    # Nothing to send, so nothing is attempted: no task, no row write, no failure counted against a
                    # device that did nothing wrong. Only the tally of what fixing the tenant setting would release.
                    if reason:
                        summary["apps_blocked"] += 1
                    continue
                await _note_attempt(AppDeployment, existing, reason)
                if not reason:
                    continue
                task = await task_manager.create_task(
                    tenant=tenant,
                    task_type="app_install",
                    description=f"Install {app['name']} v{app['version']} ({reason})",
                    device=device,
                    user="system",
                    details={"app_info": app},
                )
                _spawn(task_manager.execute_task(
                    task,
                    partial(handle_app_install_task, device=device, tenant=tenant),
                ))
                active.add(key)
                summary["apps_queued"] += 1

            # ==Apps: retire what the device is no longer scoped into==
            # Scoped and waiting counts as scoped, so a rollout that has not yet reached this device is not
            # retired as unwanted. Nothing is retired while apps.yaml is empty either: an empty list and an
            # unreadable file are indistinguishable here, and treating them alike would delete every app row
            # in the tenant on one bad read.
            if apps_config:
                summary["apps_unscoped"] += await _unscope_apps(
                    device_app_rows,
                    {a["app_id"] for a in apps_to_install}
                    | app_manager.scoped_app_ids(device, apps_config, device_groups),
                    now,
                    remediation_rule_ids,
                    flow_ids,
                )

            # ==DDM: re-sync declarations when the published token is stale==
            # One path handles first enablement, declaration and profile edits, tag or group changes (the properties
            # declaration re-tokens) and rollout progression. sync_device no-ops when nothing moved.
            if ddm is not None:
                ddm_key = _task_key(device.id, "ddm_sync", {})
                if ddm_key not in active and ddm.device_supports_ddm(device):
                    # Hand in the shared connector; left to itself sync_device builds and tears down an httpx client per
                    # device.
                    outcome = await ddm.sync_device(
                        device, reason="reconcile", mdm_connector=shared_connector(),
                        tenant=tenant, declarations_config=declarations_config,
                        groups_config=groups_config, device_groups=device_groups,
                    )
                    if outcome:
                        active.add(ddm_key)
                        summary["ddm_syncs_queued"] += 1
                    elif isinstance(outcome, ddm.EnqueueFailed):
                        # sync_device returns a refused enqueue as an outcome, having already logged it, filed a failed
                        # ddm_sync task and started its backoff, so only the summary is left to keep honest. It counts
                        # attempts that were made and refused; devices inside a backoff window are not counted.
                        summary["errors"] += 1

        except Exception:
            summary["errors"] += 1
            logger.exception(
                f"reconcile[{tenant.id}]: device {device.serial_number or device.udid} failed"
            )

    if any(summary[k] for k in ("profiles_queued", "removals_queued", "apps_queued",
                                "apps_blocked", "apps_unscoped", "apps_unconfirmed",
                                "ddm_syncs_queued", "tasks_timed_out")):
        logger.info(f"reconcile[{tenant.id}]: {summary}")
    return summary
