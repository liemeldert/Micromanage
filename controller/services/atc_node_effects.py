"""ATC node execution side effects for profiles, apps, commands, accounts, and locks."""

import logging
from functools import partial
from typing import Any, Dict, List, Optional, Tuple

from controller.models.tenant import Device, DeviceSecret, FlowRun, Tenant
from controller.services import tenant_config
from controller.services.atc_alerts import _resolve_in_setup_alert
from controller.services.atc_context import (
    _expect, _gap_body, _mark_dirty, _mark_ungated, _record_gap, _timeline,
)
from controller.services.atc_flow import _now
from controller.services.device_tags import write_tags
from controller.services.scoping import (
    device_in_rollout, device_platform_category, evaluate_scope,
)

logger = logging.getLogger(__name__)


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
    written = await write_tags(device, add=tags) if add else await write_tags(device, remove=tags)
    if written is None:
        _timeline(run, run.current_node, f"{'assign' if add else 'remove'}_tag: no change")
        return
    _, added, removed = written
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
    _timeline(run, run.current_node, f"tags added={added} removed={removed}")
    from controller.services.audit import record_tag_change
    await record_tag_change(device, added=added, removed=removed, source="atc",
                            source_ref=f"{run.flow_id}:{run.current_node}")


def _recompute_groups(device: Device) -> None:
    """Recompute device.groups in-memory from current tags/facts (best-effort)."""
    try:
        from controller.services.group_manager import current_groups
        device.groups = current_groups(device)
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
        await task.mark_sent(result.get("command_uuid"))
    except Exception as exc:
        await task.mark_push_failed(str(exc))
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
        # and the definition itself, which the task row holds only with secrets redacted. See
        # task_handlers._resolve_device_tenant for what that snapshot covers.
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
                    "why": "held back by a gradual rollout, so this device's wave has not opened yet"}
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
    """Queue a DDM DeclarativeManagement sync for the device. ddm_manager.sync_device can return EnqueueFailed or
    SyncHeldOff, which are falsy like a plain False (already in sync), so they are tested by type; only they count as
    gaps. A flow never bypasses the backoff."""
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
                                "why": "DDM is off for this tenant, or this device does not support it"}])
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
                            "why": "no declarations from declarations.yaml are scoped to this device"}])
    _timeline(run, run.current_node,
              "sync_declarations: sync queued" if queued
              else "sync_declarations: already in sync")


def _is_ade_device(device: Device) -> bool:
    """Whether this device came in through Automated Device Enrollment. Three signals, any one a yes:
    SecurityInfo.ManagementStatus.EnrolledViaDEP, a DEP server/profile from the ABM/ASM sync, or enrollment_source of
    ade. A no is only the absence of all three, since a stale no costs more than a stale yes."""
    attrs = getattr(device, "attributes", None) or {}
    sec = attrs.get("SecurityInfo")
    mgmt = (sec or {}).get("ManagementStatus") if isinstance(sec, dict) else None
    if isinstance(mgmt, dict) and mgmt.get("EnrolledViaDEP") is True:
        return True
    if getattr(device, "dep_server_id", None) or getattr(device, "dep_profile_uuid", None):
        return True
    return attrs.get("enrollment_source") == "ade"


async def _release_device(run: FlowRun, device: Device) -> None:
    """Send DeviceConfigured to release an ADE device from Setup Assistant. Apple accepts this only on ADE devices
    awaiting configuration (iOS 9+ supervised, macOS 10.11+, tvOS 10.2+ supervised); anything else is skipped with a
    reason in the timeline. Fire-and-forget, like set_name, so the MDM round-trip does not block _advance."""
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
    """Check the gap ledger as the device is let out of Setup Assistant, the last point where it is still known what the
    barriers did not get. The device is still released (a gradual rollout emptying a barrier is by design). Any gap is
    recorded as unverified, so the run later fails with an alert, red if any gap is broken, else yellow."""
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
        return False, ("This device did not come in through Automated Device Enrollment, so it was never held in Setup "
                       "Assistant and there is nothing to release it from.")
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
        await task.mark_sent(result.get("command_uuid"))
    except Exception as exc:
        await task.mark_push_failed(str(exc))
        logger.warning("ATC: DeviceConfigured push failed for %s: %s", device.udid, exc)
    finally:
        await connector.close()


# ==Account + firmware provisioning (managed-secret escrow)==

async def _configure_accounts(run: FlowRun, device: Device, params: Dict[str, Any]) -> None:
    """Send AccountConfiguration, escrowing credentials via services.device_secrets. Awaited inline, not spawned, so it
    is sent before a later release_device's DeviceConfigured. Both non-admin primary modes need a managed admin or the
    node refuses (flow_step_catalog.ACCOUNT_ADMIN_REQUIREMENT). Requires macOS, ADE origin and AwaitingConfiguration:
    https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/account.configuration.yaml
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
                  "configure_accounts: this Mac did not enrol through Automated Device Enrollment, so Setup Assistant "
                  "never asked the server about its accounts and nothing this step describes would be created; skipped")
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
        await task.mark_sent(result.get("command_uuid"))
        note = f"sent (primary={mode})"
        if auto_admins:
            note += (f"; managed admin '{admin_short}' escrowed, unconfirmed until "
                     "the Mac acknowledges")
        _timeline(run, run.current_node, f"configure_accounts: {note}")
    except Exception as exc:
        await task.mark_push_failed(str(exc))
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
        await task.mark_sent(result.get("command_uuid"))
        _timeline(run, run.current_node,
                  f"set_firmware_lock: {change.label} rotation sent; the escrow keeps the "
                  "old password until the Mac acknowledges" if change.rotating
                  else f"set_firmware_lock: {change.label} sent + escrowed")
    except Exception as exc:
        await task.mark_push_failed(str(exc))
        # Nothing reached the device, so a parked password is dead and a first set's escrow opens nothing.
        await device_secrets.abort_lock_change(change)
        _timeline(run, run.current_node,
                  f"set_firmware_lock: send failed ({exc}); the escrow was rolled back")
        logger.warning("ATC: %s failed for %s: %s", change.request_type, device.udid, exc)
    finally:
        await connector.close()
