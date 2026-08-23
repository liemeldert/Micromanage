"""E2E checks for deployment state vs task state, on in-memory sqlite.

Run: PYTHONPATH=. ./.venv/bin/python tests/verify_deployment_state.py
See docs/tests/verify_deployment_state.md for section details and background.
"""
import asyncio
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import yaml
from tortoise import Tortoise

PASS, FAIL = [], []
REPO = Path(__file__).resolve().parent.parent


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def write_configs(base: Path, tenant_id: str = "default") -> None:
    tdir = base / "tenants" / tenant_id
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "config.yaml").write_text(yaml.safe_dump(
        {"tenant": {"id": tenant_id, "name": tenant_id, "allowed_users": []}}))
    (tdir / "groups.yaml").write_text(yaml.safe_dump({"groups": [
        {"name": "all-macs", "conditions": [
            {"type": "platform", "operator": "in", "value": ["Mac"]}]}]}))
    (tdir / "apps.yaml").write_text(yaml.safe_dump({"apps": [
        {"id": "slack", "name": "Slack", "bundle_id": "com.tinyspeck.slackmacgap",
         "versions": [{"version": "1.0", "s3_key": "apps/slack-1.0.pkg",
                       "sha256": "a" * 64, "groups": ["all-macs"]}]},
    ]}))
    (tdir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": [
        {"id": "wifi", "name": "Corporate Wi-Fi", "groups": ["all-macs"],
         "payload": {"PayloadType": "com.apple.wifi", "SSID_STR": "CorpNet"}},
    ]}))


async def main():
    base = Path(tempfile.mkdtemp())
    os.environ["YAML_CONFIG_PATH"] = str(base)
    os.environ["PUBLIC_API_URL"] = "https://mdm.example.com"
    # A deployment that can serve app packages. With no bucket the reconciler withholds every app install as a
    # tenant-level configuration error (section 16), which the app sections below are not about.
    os.environ["AWS_S3_BUCKET"] = "verify-packages"
    write_configs(base)

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    from controller.auth.dependencies import Principal
    from controller.models.tenant import (
        AppDeployment, AuditLog, Device, ProfileDeployment, Task, Tenant, User,
    )
    from controller.services import audit, reconciler, webhook_handler
    from controller.api.main import get_device_details, get_app_manifest_info

    # Device signals and compliance runs are other subsystems' business; record them instead of running them.
    signals = []

    async def fake_signal(device_id, signal, ref=None):
        signals.append((signal, ref))

    async def fake_dispatch(device):
        return None

    webhook_handler._atc_signal = fake_signal
    webhook_handler._dispatcher_eval = fake_dispatch

    tenant = await Tenant.create(id="default", name="Default")
    admin_user = await User.create(tenant=tenant, email="admin@default", role="admin")
    admin = Principal(tenant=tenant, user=admin_user, email="admin@default", role="admin")

    async def new_device(serial):
        return await Device.create(
            tenant=tenant, udid=f"UDID-{serial}", serial_number=serial,
            device_model="MacBookPro18,3", os_version="15.5", hostname=serial.lower(),
            enrollment_state="enrolled", groups=[], tags=[])

    async def old_task(device, ttype, *, command_uuid, details=None, hours=25):
        """A task created long enough ago that the sweep will time it out."""
        task = await Task.create(
            tenant=tenant, type=ttype, status="pending", device=device,
            user="system", description=f"{ttype} on {device.serial_number}",
            details={"command_uuid": command_uuid, **(details or {})})
        await Task.filter(id=task.id).update(
            created_at=datetime.now(timezone.utc) - timedelta(hours=hours))
        return await Task.get(id=task.id)

    handler = webhook_handler.WebhookHandler()
    app_info = {"app_id": "slack", "name": "Slack", "version": "1.0",
                "bundle_id": "com.tinyspeck.slackmacgap", "s3_key": "apps/slack-1.0.pkg"}
    profile_info = {"id": "wifi", "name": "Corporate Wi-Fi"}

    print("\n== 1. A timed-out install stops reading as installed ==")
    dev = await new_device("SN-TIMEOUT")
    app_task = await old_task(dev, "app_install", command_uuid="cmd-app-1",
                              details={"app_info": app_info})
    profile_task = await old_task(dev, "profile_install", command_uuid="cmd-prof-1",
                                  details={"profile_info": profile_info})
    app_row = await AppDeployment.create(
        tenant=tenant, device=dev, app_id="slack", app_version="1.0",
        status="installed", install_date=datetime.now(timezone.utc),
        last_task_id=app_task.id)
    profile_row = await ProfileDeployment.create(
        tenant=tenant, device=dev, profile_id="wifi", status="installing",
        last_task_id=profile_task.id)

    # A second device whose deployment has already been retried under a newer task: the dead task must not drag it back
    # down with it.
    other = await new_device("SN-RETRIED")
    dead_task = await old_task(other, "app_install", command_uuid="cmd-app-dead",
                               details={"app_info": app_info})
    newer_task = await Task.create(
        tenant=tenant, type="app_install", status="running", device=other,
        user="system", description="Install Slack v1.0", details={})
    retried_row = await AppDeployment.create(
        tenant=tenant, device=other, app_id="slack", app_version="1.0",
        status="installing", last_task_id=newer_task.id)

    # And a row that already failed with a real reason from the device.
    specific = await new_device("SN-SPECIFIC")
    specific_task = await old_task(specific, "app_install", command_uuid="cmd-app-spec",
                                   details={"app_info": app_info})
    specific_row = await AppDeployment.create(
        tenant=tenant, device=specific, app_id="slack", app_version="1.0",
        status="failed", last_error="Not enough disk space",
        last_task_id=specific_task.id)

    timed_out = await reconciler._fail_timed_out_tasks(tenant)
    check("sweep failed every stale task", timed_out == 4)

    app_row = await AppDeployment.get(id=app_row.id)
    profile_row = await ProfileDeployment.get(id=profile_row.id)
    check("app deployment no longer reads installed", app_row.status == "failed")
    check("app deployment says why",
          (app_row.last_error or "").startswith("Timed out: no device response"))
    check("profile deployment failed too", profile_row.status == "failed")
    check("profile deployment says why",
          (profile_row.last_error or "").startswith("Timed out: no device response"))

    retried_row = await AppDeployment.get(id=retried_row.id)
    check("a row owned by a newer attempt is untouched", retried_row.status == "installing")
    check("...and keeps its own attempt", retried_row.last_task_id == newer_task.id)

    specific_row = await AppDeployment.get(id=specific_row.id)
    check("an already-failed row keeps its specific reason",
          specific_row.last_error == "Not enough disk space")

    app_task = await Task.get(id=app_task.id)
    check("the task itself is failed", app_task.status == "failed")
    check("task error keeps the prefix the webhook tests for",
          (app_task.error or "").startswith("Timed out"))

    print("\n== 2. A late device answer corrects the row ==")
    # The device was offline for two days and answers now. The webhook accepts a response for a task the sweep failed;
    # that has to reach the deployment row as well, or the console goes on showing a failure for an installed app.
    await handler._dispatch_command_response(dev, "cmd-app-1", "Acknowledged", {})
    app_row = await AppDeployment.get(id=app_row.id)
    app_task = await Task.get(id=app_task.id)
    # Acknowledged doesn't distinguish installed from rejected; wait for inventory.
    check("late Acknowledged takes the app out of failure", app_row.status == "accepted")
    check("late Acknowledged clears the timeout error", app_row.last_error is None)
    check("late Acknowledged stamps an install date", app_row.install_date is not None)
    check("late Acknowledged completes the task", app_task.status == "completed")
    check("late Acknowledged clears the task error", app_task.error is None)
    # Signals go through the deferred fan-out, so settle it before asserting.
    await webhook_handler.drain_deferred()
    check("no app_installed signal on the acknowledgement alone",
          ("app_installed", "slack") not in signals)

    await handler._dispatch_command_response(dev, "cmd-prof-1", "Acknowledged", {})
    profile_row = await ProfileDeployment.get(id=profile_row.id)
    check("late Acknowledged puts the profile back to installed",
          profile_row.status == "installed")
    check("late Acknowledged clears the profile error", profile_row.last_error is None)

    # The other direction: a superseded attempt reporting failure must not overwrite a row a newer attempt already owns.
    stale_dev = await new_device("SN-SUPERSEDED")
    stale_task = await old_task(stale_dev, "app_install", command_uuid="cmd-app-stale",
                                details={"app_info": app_info})
    current_task = await Task.create(
        tenant=tenant, type="app_install", status="running", device=stale_dev,
        user="system", description="Install Slack v1.0",
        details={"command_uuid": "cmd-app-current", "app_info": app_info})
    stale_row = await AppDeployment.create(
        tenant=tenant, device=stale_dev, app_id="slack", app_version="1.0",
        status="installed", install_date=datetime.now(timezone.utc),
        last_task_id=current_task.id)
    await reconciler._fail_timed_out_tasks(tenant)
    stale_row = await AppDeployment.get(id=stale_row.id)
    check("the superseded row was not swept", stale_row.status == "installed")
    await handler._dispatch_command_response(
        stale_dev, "cmd-app-stale", "Error",
        {"ErrorChain": [{"LocalizedDescription": "Could not fetch the package"}]})
    stale_row = await AppDeployment.get(id=stale_row.id)
    stale_task = await Task.get(id=stale_task.id)
    check("a superseded attempt's failure does not overwrite the row",
          stale_row.status == "installed" and stale_row.last_error is None)
    check("...but the superseded task still records its own error",
          stale_task.status == "failed" and "package" in (stale_task.error or ""))

    # A failure from the attempt the row IS tracking does apply.
    await handler._dispatch_command_response(
        stale_dev, "cmd-app-current", "Error",
        {"ErrorChain": [{"LocalizedDescription": "Signature check failed"}]})
    stale_row = await AppDeployment.get(id=stale_row.id)
    check("the current attempt's failure does apply", stale_row.status == "failed")
    check("...with the device's own message",
          stale_row.last_error == "Signature check failed")

    print("\n== 3. Apps follow the profile staleness rule ==")
    now = datetime.now(timezone.utc)

    def row(status, minutes_ago, version="1.0", failed_attempts=0):
        return SimpleNamespace(status=status, app_version=version,
                               failed_attempts=failed_attempts,
                               updated_at=now - timedelta(minutes=minutes_ago))

    check("nothing deployed -> install",
          reconciler._app_needs_deploy(None, "1.0", now) == "not deployed")
    check("installing and fresh -> leave it running",
          reconciler._app_needs_deploy(row("installing", 5), "1.0", now) is None)
    check("installing past the retry window -> re-queue",
          reconciler._app_needs_deploy(row("installing", reconciler.RETRY_MINUTES + 1),
                                       "1.0", now) is not None)
    check("pending past the retry window -> re-queue",
          reconciler._app_needs_deploy(row("pending", reconciler.RETRY_MINUTES + 1),
                                       "1.0", now) is not None)
    check("a fresh failure backs off",
          reconciler._app_needs_deploy(row("failed", 1), "1.0", now) is None)
    check("an old failure retries",
          reconciler._app_needs_deploy(row("failed", reconciler.RETRY_MINUTES + 1),
                                       "1.0", now) == "previous attempt failed")
    check("installed at the desired version -> nothing to do",
          reconciler._app_needs_deploy(row("installed", 60), "1.0", now) is None)
    check("installed at an older version -> upgrade",
          reconciler._app_needs_deploy(row("installed", 60, version="0.9"), "1.0", now)
          == "app version changed")
    check("apps and profiles share one rule",
          reconciler._app_needs_deploy(row("installing", reconciler.RETRY_MINUTES + 1),
                                       "1.0", now)
          == reconciler._profile_needs_deploy(
              SimpleNamespace(status="installing", payload_hash="h",
                              failed_attempts=0,
                              updated_at=now - timedelta(minutes=reconciler.RETRY_MINUTES + 1)),
              "h", now))

    # And the reconciler really consults it: a stuck app install gets a new task.
    stuck = await new_device("SN-STUCK")
    await AppDeployment.create(
        tenant=tenant, device=stuck, app_id="slack", app_version="1.0",
        status="installing")
    await ProfileDeployment.create(
        tenant=tenant, device=stuck, profile_id="wifi", status="installed",
        payload_hash="whatever")
    spawned = []
    real_spawn = reconciler._spawn
    original_retry = reconciler.RETRY_MINUTES

    def capture_spawn(coro):
        spawned.append(coro)
        coro.close()  # never talk to NanoMDM from a test

    reconciler._spawn = capture_spawn
    try:
        reconciler.RETRY_MINUTES = 30
        summary = await reconciler.reconcile_tenant(tenant, base)
        check("a fresh in-flight install is left alone", summary["apps_queued"] == 0)
        # No grace at all, so the row written a moment ago reads as stale.
        reconciler.RETRY_MINUTES = 0
        summary = await reconciler.reconcile_tenant(tenant, base)
        check("a stuck install is re-queued", summary["apps_queued"] >= 1)
    finally:
        reconciler.RETRY_MINUTES = original_retry
        reconciler._spawn = real_spawn

    queued = await Task.filter(device=stuck, type="app_install").first()
    check("the retry task exists and says why it was queued",
          queued is not None and "retrying" in (queued.description or ""))

    print("\n== 4. last_error reaches the API ==")
    detail = await get_device_details(str(stale_dev.id), admin)
    app_payload = next(a for a in detail["installed_apps"] if a["app_id"] == "slack")
    check("device detail serializes last_error",
          app_payload["last_error"] == "Signature check failed")
    check("device detail serializes the correlated task",
          app_payload["last_task_id"] == str(current_task.id))
    check("device detail still serializes status and version",
          app_payload["status"] == "failed" and app_payload["version"] == "1.0")
    profile_detail = await get_device_details(str(dev.id), admin)
    check("profile rows carry last_error too",
          "last_error" in profile_detail["installed_profiles"][0])
    manifest = await get_app_manifest_info(str(stale_row.id), admin)
    check("manifest info exposes last_error",
          manifest["last_error"] == "Signature check failed")

    print("\n== 5. device_apps is a list from end to end ==")
    check("model default is a list", isinstance(stuck.installed_apps, list))
    reported = [
        {"Identifier": "com.tinyspeck.slackmacgap", "Name": "Slack",
         "Version": "4.38.125", "ShortVersion": "4.38.125"},
    ]
    app_list_task = await Task.create(
        tenant=tenant, type="app_list", status="running", device=stuck,
        user="system", description="List installed apps", details={})
    await handler._persist_inventory(
        app_list_task, {"InstalledApplicationList": reported})
    refreshed = await Device.get(id=stuck.id)
    check("the webhook stores what the device reported, as a list",
          refreshed.installed_apps == reported)
    detail = await get_device_details(str(stuck.id), admin)
    check("the endpoint hands the same list back", detail["device_apps"] == reported)
    check("an un-queried device reports an empty list, not a dict",
          (await get_device_details(str(dev.id), admin))["device_apps"] == [])

    print("\n== 6. A rejected command is still an answer ==")
    signals.clear()
    rejected = await Task.create(
        tenant=tenant, type="set_firmware_lock", status="running", device=dev,
        user="admin@default", description="Set firmware password",
        details={"command_uuid": "cmd-lock-1"})
    await handler._dispatch_command_response(
        dev, "cmd-lock-1", "Error",
        {"ErrorChain": [{"LocalizedDescription": "Not supported on this Mac"}]})
    rejected = await Task.get(id=rejected.id)
    check("a rejected command fails its task", rejected.status == "failed")
    await webhook_handler.drain_deferred()
    check("...and still emits command_ack, so barriers and escrows hear about it",
          ("command_ack", str(rejected.id)) in signals)

    print("\n== 7. Automated tag changes are auditable ==")
    await audit.record_tag_change(
        dev, added=["quarantined"], removed=[],
        source="dispatcher", source_ref="filevault-required")
    rows = await AuditLog.filter(action=audit.TAG_ACTION).all()
    check("an automated tag change writes one row", len(rows) == 1)
    if rows:
        r = rows[0]
        check("row is machine-attributed", r.actor_email is None and r.actor_role is None)
        check("row is scoped to the device's own tenant", str(r.tenant_id) == "default")
        check("row names the source and what moved",
              r.detail.get("source") == "dispatcher"
              and r.detail.get("source_ref") == "filevault-required"
              and r.detail.get("added") == ["quarantined"])
    await audit.record_tag_change(
        dev, added=["corp"], removed=[], source="console", principal=admin)
    console_row = await AuditLog.filter(
        action=audit.TAG_ACTION, actor_email="admin@default").first()
    check("a console tag change is attributed to the admin", console_row is not None)
    before = await AuditLog.filter(action=audit.TAG_ACTION).count()
    await audit.record_tag_change(dev, added=[], removed=[], source="atc")
    check("a no-op tag change writes nothing",
          await AuditLog.filter(action=audit.TAG_ACTION).count() == before)

    # "How did this device get this tag" has to be one query, or the console goes back to reading flow-run prose.
    from controller.api.main import list_audit_log

    listed = await list_audit_log(
        skip=0, limit=100, action=audit.TAG_ACTION, target_type="device",
        target_id=str(dev.id), admin=admin)
    check("the audit endpoint filters tag history down to one device",
          listed["total"] == 2 and all(e["target_id"] == str(dev.id)
                                       for e in listed["entries"]))
    other_device = await list_audit_log(
        skip=0, limit=100, action=audit.TAG_ACTION, target_id=str(stuck.id), admin=admin)
    check("another device's tag history is excluded", other_device["total"] == 0)

    print("\n== 8. Both API processes register a pooled DSN ==")
    from controller.models.database import _pooled_url

    check("pool sizing is injected into a bare Postgres DSN",
          "maxsize=" in _pooled_url("postgres://u:p@h:5432/db"))
    check("an explicit maxsize is left alone",
          "maxsize=50" in _pooled_url("postgres://u:p@h:5432/db?maxsize=50"))
    check("other DSN parameters survive",
          "ssl=require" in _pooled_url("postgres://u:p@h/db?ssl=require"))
    check("sqlite is passed through untouched",
          _pooled_url("sqlite://:memory:") == "sqlite://:memory:")
    # Both processes register their own pooled DSN; raw DSN fails silently at runtime.
    for module in ("controller/api/main.py", "controller/api/webhook.py"):
        src = (REPO / module).read_text()
        check(f"{module} registers a pooled DSN",
              "db_url=_pooled_url(DATABASE_URL)" in src
              and "db_url=DATABASE_URL" not in src)
        # Neither file generates schemas; init_schema() holds the advisory lock.
        check(f"{module} leaves schema generation to init_schema",
              "generate_schemas=False" in src
              and "generate_schemas=True" not in src
              and "await init_schema()" in src)

    # asyncpg's Pool.__init__ raises if min_size > max_size; tortoise builds lazily.
    import controller.models.database as _db_mod

    def _pool_sizes(dsn):
        from urllib.parse import parse_qs, urlsplit
        q = parse_qs(urlsplit(dsn).query)
        return int(q["minsize"][0]), int(q["maxsize"][0])

    # init_schema pins one connection; composed minimum must fit under maximum.
    _saved_pool_max = _db_mod.DB_POOL_MAX
    try:
        _db_mod.DB_POOL_MAX = 1
        composed = _pool_sizes(_pooled_url("postgres://u:p@h/db"))
        check("DB_POOL_MAX_SIZE=1 is floored to what the schema phase needs",
              composed[1] == _db_mod._MIN_POOL_MAX)
        check("and the composed minimum still fits under it", composed[0] <= composed[1])
    finally:
        _db_mod.DB_POOL_MAX = _saved_pool_max
    # The DSN route: same floor, same fit.
    from_dsn = _pool_sizes(_pooled_url("postgres://u:p@h/db?maxsize=1"))
    check("an explicit maxsize=1 in the DSN is floored too",
          from_dsn[1] == _db_mod._MIN_POOL_MAX and from_dsn[0] <= from_dsn[1])
    # Hand-written minsize is preserved; maxsize is still floored.
    check("a hand-written minsize>maxsize pair keeps the minimum as written",
          "minsize=5" in _pooled_url("postgres://u:p@h/db?minsize=5&maxsize=1"))

    print("\n== 9. ensure_deployment stamps the link before deploy_app ever runs ==")
    # ensure_deployment stamps last_task_id synchronously, before deploy_app runs.
    from controller.services.app_manager import AppManager
    from controller.services.profile_manager import ProfileManager
    from controller.api.main import send_device_command, retry_task, CommandRequest

    # 9a. The building block on its own.
    never_ran = await new_device("SN-NEVER-RAN")
    early_task = await old_task(never_ran, "app_install", command_uuid="cmd-early",
                                details={"app_info": app_info})
    early_row = await AppManager(tenant).ensure_deployment(never_ran, app_info, str(early_task.id))
    check("ensure_deployment creates the row up front",
          early_row.status == "pending" and early_row.last_task_id == early_task.id)
    await reconciler._fail_timed_out_tasks(tenant)
    early_row = await AppDeployment.get(id=early_row.id)
    check("...and the sweep fails it on a task deploy_app never touched",
          early_row.status == "failed"
          and (early_row.last_error or "").startswith("Timed out: no device response"))

    # 9b. End to end through the real ad-hoc install_app command, with the spawned handler intercepted so deploy_app
    # provably never runs.
    spawned.clear()
    reconciler._spawn = capture_spawn
    try:
        never_answers = await new_device("SN-INSTALL-NOANS")
        result = await send_device_command(
            str(never_answers.id),
            CommandRequest(command_type="install_app", parameters={"app_info": app_info}),
            admin,
        )
        check("install_app returns a task_id immediately", "task_id" in result)
        check("deploy_app was queued but never actually run", len(spawned) == 1)
        row = await AppDeployment.get_or_none(device=never_answers, app_id="slack")
        check("the deployment row exists before deploy_app runs",
              row is not None and str(row.last_task_id) == result["task_id"])
        await Task.filter(id=result["task_id"]).update(
            created_at=datetime.now(timezone.utc) - timedelta(hours=25))
        await reconciler._fail_timed_out_tasks(tenant)
        row = await AppDeployment.get(id=row.id)
        check("a device that never answers still ends up failed, not silent",
              row.status == "failed")
    finally:
        reconciler._spawn = real_spawn

    # 9c. The same for tasks/{id}/retry's profile_install branch, where the attempt has already gone wrong once.
    retry_dev = await new_device("SN-RETRY-PROFILE")
    dead_profile_task = await Task.create(
        tenant=tenant, type="profile_install", status="failed", device=retry_dev,
        user="system", description="Install profile: Corporate Wi-Fi",
        error="Timed out: no device response within 24h. The device may be offline.",
        details={"profile_info": profile_info})
    spawned.clear()
    reconciler._spawn = capture_spawn
    try:
        retry_result = await retry_task(str(dead_profile_task.id), admin)
        check("retry returns a fresh task_id", "task_id" in retry_result)
        check("deploy_profile was queued but never actually run for the retry",
              len(spawned) == 1)
        prow = await ProfileDeployment.get_or_none(device=retry_dev, profile_id="wifi")
        check("the retry links the new deployment row immediately",
              prow is not None and str(prow.last_task_id) == retry_result["task_id"])
    finally:
        reconciler._spawn = real_spawn

    print("\n== 10. Webhook fan-out is deferred, equivalent, and fault-isolated ==")
    # Settle everything earlier sections spawned, so nothing stale appends to signals while this section asserts on
    # exact contents.
    await webhook_handler.drain_deferred()

    # 10a. _spawn_deferred takes device lock before semaphore.
    import logging as _logging

    deferred = []
    real_spawn_deferred = webhook_handler._spawn_deferred
    webhook_handler._spawn_deferred = deferred.append
    try:
        defer_dev = await new_device("SN-DEFERRED")
        defer_task = await Task.create(
            tenant=tenant, type="app_install", status="running", device=defer_dev,
            user="system", description="Install Slack v1.0",
            details={"command_uuid": "cmd-defer-1", "app_info": app_info})
        defer_row = await AppDeployment.create(
            tenant=tenant, device=defer_dev, app_id="slack", app_version="1.0",
            status="installing", last_task_id=defer_task.id)
        signals.clear()
        await handler._dispatch_command_response(defer_dev, "cmd-defer-1", "Acknowledged", {})
        defer_task = await Task.get(id=defer_task.id)
        defer_row = await AppDeployment.get(id=defer_row.id)
        check("task completed inline, before any fan-out ran",
              defer_task.status == "completed")
        check("deployment row updated inline too", defer_row.status == "accepted")
        check("no signal ran on the request path", signals == [])
        check(f"the fan-out was deferred rather than run ({len(deferred)})",
              len(deferred) >= 1)

        # 10b. Running the deferred coroutines produces the signals the inline path used to emit. app_installed is not
        # among them: it waits for the inventory that confirms the app, not for the command being taken.
        for coro in deferred:
            await coro
        check("deferred fan-out emits checkin",
              ("checkin", None) in signals)
        check("...and not app_installed, which waits for confirmation",
              ("app_installed", "slack") not in signals)
    finally:
        webhook_handler._spawn_deferred = real_spawn_deferred
        deferred.clear()

    # 10c. A fan-out failure is logged with device context and does not poison the spawn machinery for later webhooks.
    class _CaptureLog(_logging.Handler):
        def __init__(self):
            super().__init__()
            self.messages = []

        def emit(self, record):
            self.messages.append(record.getMessage())

    async def exploding_signal(device_id, signal, ref=None):
        raise RuntimeError("boom")

    capture = _CaptureLog()
    webhook_handler.logger.addHandler(capture)
    webhook_handler._atc_signal = exploding_signal
    try:
        boom_task = await Task.create(
            tenant=tenant, type="restart", status="running", device=defer_dev,
            user="system", description="Restart",
            details={"command_uuid": "cmd-boom-1"})
        await handler._dispatch_command_response(defer_dev, "cmd-boom-1", "Acknowledged", {})
        boom_task = await Task.get(id=boom_task.id)
        check("the webhook still completes its task despite the doomed fan-out",
              boom_task.status == "completed")
        await webhook_handler.drain_deferred()
        check("the spawned failure is logged with the device id",
              any("deferred fan-out failed" in m and str(defer_dev.id) in m
                  for m in capture.messages))
    finally:
        webhook_handler._atc_signal = fake_signal
        webhook_handler.logger.removeHandler(capture)

    # The next webhook for the same device still works and still signals.
    signals.clear()
    after_task = await Task.create(
        tenant=tenant, type="restart", status="running", device=defer_dev,
        user="system", description="Restart",
        details={"command_uuid": "cmd-after-1"})
    await handler._dispatch_command_response(defer_dev, "cmd-after-1", "Acknowledged", {})
    await webhook_handler.drain_deferred()
    after_task = await Task.get(id=after_task.id)
    check("a later webhook is unaffected by the earlier failure",
          after_task.status == "completed"
          and ("command_ack", str(after_task.id)) in signals)

    print("\n== 11. The webhook app drains deferred fan-out on shutdown ==")
    # The shutdown hook gives the deferred backlog a bounded window, then lets the process die rather than hang on a
    # wedged task.
    import controller.api.webhook as webhook_api

    ran = []

    async def slow_signal(device_id, signal, ref=None):
        await asyncio.sleep(0.05)
        ran.append(signal)

    webhook_handler._atc_signal = slow_signal
    try:
        shutdown_task = await Task.create(
            tenant=tenant, type="restart", status="running", device=defer_dev,
            user="system", description="Restart",
            details={"command_uuid": "cmd-shutdown-1"})
        await handler._dispatch_command_response(
            defer_dev, "cmd-shutdown-1", "Acknowledged", {})
        await webhook_api._drain_deferred_fanout()
        check("queued fan-out runs to completion during shutdown",
              ran == ["checkin", "command_ack"])
        check("...for a task the response path had already completed",
              (await Task.get(id=shutdown_task.id)).status == "completed")
    finally:
        webhook_handler._atc_signal = fake_signal

    # 11b. The window is bounded: a wedged coroutine cannot hold the restart hostage; past the window the remainder is
    # dropped.
    hung = asyncio.Event()

    async def wedged():
        await hung.wait()

    real_window = webhook_api._SHUTDOWN_DRAIN_SECONDS
    webhook_api._SHUTDOWN_DRAIN_SECONDS = 0.2
    try:
        webhook_handler._defer(defer_dev.id, wedged())
        t0 = asyncio.get_running_loop().time()
        await webhook_api._drain_deferred_fanout()
        elapsed = asyncio.get_running_loop().time() - t0
        check("a wedged deferred task cannot stall shutdown past the window",
              0.15 <= elapsed < 5)
    finally:
        webhook_api._SHUTDOWN_DRAIN_SECONDS = real_window
        hung.set()
    # The timed-out drain cancelled the wedged task; nothing may leak into the next drain, or the loop teardown would
    # warn about pending tasks.
    await webhook_handler.drain_deferred()
    check("the cancelled remainder is gone from the background set",
          not reconciler._background_tasks)

    print("\n== 12. Correlation is an exact lookup on Task.command_uuid ==")
    # 12a. save() mirrors uuid into command_uuid column.
    corr_dev = await new_device("SN-CORRELATE")
    created_with = await Task.create(
        tenant=tenant, type="ddm_sync", status="running", device=corr_dev,
        user="system", description="Declarative sync",
        details={"command_uuid": "cmd-col-create"})
    check("Task.create with a details uuid fills the column",
          (await Task.get(id=created_with.id)).command_uuid == "cmd-col-create")

    dispatched = await Task.create(
        tenant=tenant, type="restart", status="pending", device=corr_dev,
        user="system", description="Restart", details={})
    check("a task that enqueued nothing keeps a NULL column",
          (await Task.get(id=dispatched.id)).command_uuid is None)
    dispatched.details["command_uuid"] = "cmd-col-dispatch"
    dispatched.status = "running"
    await dispatched.save()
    check("the dispatch-time full save fills the column",
          (await Task.get(id=dispatched.id)).command_uuid == "cmd-col-dispatch")

    fields_task = await Task.create(
        tenant=tenant, type="restart", status="pending", device=corr_dev,
        user="system", description="Restart", details={})
    fields_task.details["command_uuid"] = "cmd-col-fields"
    await fields_task.save(update_fields=["details"])
    check("an update_fields save persists the mirror too",
          (await Task.get(id=fields_task.id)).command_uuid == "cmd-col-fields")
    await fields_task.update_progress(50, "running")
    check("later lifecycle saves leave the column alone",
          (await Task.get(id=fields_task.id)).command_uuid == "cmd-col-fields")

    # The mirror is symmetric: details are the source of truth, so a row that sheds the key must shed the column, or a
    # response could correlate to a task whose details disowned that command.
    shed = await Task.create(
        tenant=tenant, type="restart", status="running", device=corr_dev,
        user="system", description="Restart",
        details={"command_uuid": "cmd-col-shed"})
    check("the shed-test row starts correlated",
          (await Task.get(id=shed.id)).command_uuid == "cmd-col-shed")
    shed.details.pop("command_uuid")
    await shed.save(update_fields=["details"])
    check("a row whose details shed the uuid clears the column",
          (await Task.get(id=shed.id)).command_uuid is None)
    await handler._dispatch_command_response(corr_dev, "cmd-col-shed", "Acknowledged", {})
    check("...and no longer correlates after save",
          (await Task.get(id=shed.id)).status == "running")

    # 12b. The webhook correlates through the column, not by scanning rows.
    filter_calls = []
    real_task_filter = Task.filter

    def spy_filter(*args, **kwargs):
        filter_calls.append(kwargs)
        return real_task_filter(*args, **kwargs)

    Task.filter = spy_filter
    try:
        await handler._dispatch_command_response(
            corr_dev, "cmd-col-dispatch", "Acknowledged", {})
    finally:
        del Task.filter  # restore the classmethod inherited from Model
    check("the lookup filters on the column",
          any("command_uuid" in c for c in filter_calls))
    check("the exact lookup completed the task",
          (await Task.get(id=dispatched.id)).status == "completed")
    webhook_src = (REPO / "controller" / "services" / "webhook_handler.py").read_text()
    check("the 50-row lookback is gone from the webhook",
          ".limit(50)" not in webhook_src)

    # 12c. A late answer with sixty newer tasks behind it. A 50-row lookback would push the answered command out of
    # range, dropping the acknowledgement and leaving the task running forever.
    late = await Task.create(
        tenant=tenant, type="restart", status="running", device=corr_dev,
        user="system", description="Restart",
        details={"command_uuid": "cmd-col-late"})
    for i in range(60):
        await Task.create(
            tenant=tenant, type="refresh_info", status="running", device=corr_dev,
            user="system", description=f"noise {i}",
            details={"command_uuid": f"cmd-col-noise-{i}"})
    await handler._dispatch_command_response(corr_dev, "cmd-col-late", "Acknowledged", {})
    check("an answer older than the old 50-task window still correlates",
          (await Task.get(id=late.id)).status == "completed")
    # Widening the window must not widen the state semantics: a finished task is still not resurrected by a duplicate or
    # contradictory answer.
    await handler._dispatch_command_response(
        corr_dev, "cmd-col-late", "Error",
        {"ErrorChain": [{"LocalizedDescription": "nope"}]})
    late = await Task.get(id=late.id)
    check("a finished task is not resurrected by a duplicate answer",
          late.status == "completed" and late.error is None)

    # 12d. A pre-column row (details uuid, NULL column). The upgrade path is the _AUX_DDL backfill rather than a JSONB
    # fallback in the lookup, so before the backfill the row must not correlate.
    legacy = await Task.create(
        tenant=tenant, type="restart", status="running", device=corr_dev,
        user="system", description="Restart",
        details={"command_uuid": "cmd-col-legacy"})
    # Queryset update bypasses the save() mirror, like a row written before the column existed.
    await Task.filter(id=legacy.id).update(command_uuid=None)
    await handler._dispatch_command_response(corr_dev, "cmd-col-legacy", "Acknowledged", {})
    check("no JSONB fallback: an unbackfilled row does not correlate",
          (await Task.get(id=legacy.id)).status == "running")
    # The sqlite equivalent of the Postgres backfill statement in _AUX_DDL.
    conn = Tortoise.get_connection("default")
    await conn.execute_script(
        "UPDATE tasks SET command_uuid = json_extract(details, '$.command_uuid') "
        "WHERE command_uuid IS NULL "
        "AND json_extract(details, '$.command_uuid') IS NOT NULL")
    await handler._dispatch_command_response(corr_dev, "cmd-col-legacy", "Acknowledged", {})
    check("after the backfill the same answer correlates",
          (await Task.get(id=legacy.id)).status == "completed")
    await webhook_handler.drain_deferred()

    print("\n== 13. one deployment query per table per reconcile ==")
    # One deployment query per table per tenant; failed prefetch degrades to per-device.
    from controller.services import tenant_config
    from tortoise import connections

    async def sp13_fixture(tid):
        """A tenant with 3 devices: one with a current profile row, one with a current app row, one with no deployment
        rows at all."""
        write_configs(base, tid)
        t = await Tenant.create(id=tid, name=tid)
        devs = []
        for i in range(3):
            devs.append(await Device.create(
                tenant=t, udid=f"UDID-{tid}-{i}", serial_number=f"{tid.upper()}-{i}",
                device_model="MacBookPro18,3", os_version="15.5",
                hostname=f"{tid}-{i}", enrollment_state="enrolled",
                groups=[], tags=[]))
        wifi = tenant_config.load_profiles(tid)[0]
        await ProfileDeployment.create(
            tenant=t, device=devs[0], profile_id="wifi", status="installed",
            payload_hash=ProfileManager.desired_hash(wifi))
        await AppDeployment.create(
            tenant=t, device=devs[1], app_id="slack", app_version="1.0",
            status="installed", install_date=datetime.now(timezone.utc))
        # Removal pass works against prefetched partial rows.
        await ProfileDeployment.create(
            tenant=t, device=devs[0], profile_id="ghost-installed",
            status="installed", payload_hash="stale")
        await ProfileDeployment.create(
            tenant=t, device=devs[0], profile_id="ghost-pending",
            status="pending")
        return t, devs

    # Fixtures built before the spies go in, so setup queries are not counted.
    ten_a, devs_a = await sp13_fixture("sp13a")
    ten_b, _devs_b = await sp13_fixture("sp13b")
    ten_c, _devs_c = await sp13_fixture("sp13c")

    conn = connections.get("default")
    counts = {"profile_deployments": 0, "app_deployments": 0}

    def _tally(sql):
        if sql.lstrip().upper().startswith("SELECT"):
            for table in counts:
                if f'"{table}"' in sql:
                    counts[table] += 1

    # Prefetches use execute_query; failure injection arms there.
    fail_tables = set()
    orig_q, orig_qd = conn.execute_query, conn.execute_query_dict

    async def spy_q(sql, values=None):
        if sql.lstrip().upper().startswith("SELECT"):
            for table in list(fail_tables):
                if f'"{table}"' in sql:
                    fail_tables.discard(table)
                    raise RuntimeError("injected prefetch failure")
        _tally(sql)
        return await orig_q(sql, values)

    async def spy_qd(sql, values=None):
        _tally(sql)
        return await orig_qd(sql, values)

    hash_calls = {"n": 0}
    real_hash = ProfileManager.desired_hash

    def counting_hash(profile_info):
        hash_calls["n"] += 1
        return real_hash(profile_info)

    spawned.clear()
    reconciler._spawn = capture_spawn
    ProfileManager.desired_hash = staticmethod(counting_hash)
    conn.execute_query, conn.execute_query_dict = spy_q, spy_qd
    try:
        summary_a = await reconciler.reconcile_tenant(ten_a, base)
        batched = dict(counts)
        hashes_batched = hash_calls["n"]

        for k in counts:
            counts[k] = 0
        fail_tables.add("profile_deployments")
        summary_b = await reconciler.reconcile_tenant(ten_b, base)
        degraded_profiles = dict(counts)

        for k in counts:
            counts[k] = 0
        fail_tables.add("app_deployments")
        summary_c = await reconciler.reconcile_tenant(ten_c, base)
        degraded_apps = dict(counts)
    finally:
        conn.execute_query, conn.execute_query_dict = orig_q, orig_qd
        # staticmethod(), not the bare function: assigning the plain function back would make it an instance method, and
        # deploy_profile calls it through self.
        ProfileManager.desired_hash = staticmethod(real_hash)
        reconciler._spawn = real_spawn

    expected = {"profiles_queued": 2, "removals_queued": 1, "apps_queued": 2,
                "apps_blocked": 0, "apps_unscoped": 0, "apps_unconfirmed": 0,
                "ddm_syncs_queued": 0, "tasks_timed_out": 0, "devices": 3,
                "errors": 0}
    # errors == 0 means the removal pass ran delete() on a prefetched partial row without a partial-instance failure;
    # that would have been caught by the per-device except and bumped errors.
    check(f"batched cycle outcome is right ({summary_a})", summary_a == expected)
    check("the no-longer-desired pending row was delete()d off a partial",
          await ProfileDeployment.filter(
              device=devs_a[0], profile_id="ghost-pending").count() == 0)
    check("the no-longer-desired installed row queued a removal and stayed",
          await Task.filter(device=devs_a[0], type="profile_remove").count() == 1
          and await ProfileDeployment.filter(
              device=devs_a[0], profile_id="ghost-installed").count() == 1)
    check(f"batched: one profile-deployment query for the whole tenant "
          f"(got {batched['profile_deployments']})",
          batched["profile_deployments"] == 1)
    check(f"batched: one app-deployment query for the whole tenant "
          f"(got {batched['app_deployments']})",
          batched["app_deployments"] == 1)
    # The no-rows device rode the prefetch's missing-key path (the count above proves no fallback query fired for it)
    # and still got both installs.
    check("a device with no deployment rows still gets its profile queued",
          await Task.filter(device=devs_a[2], type="profile_install").count() == 1)
    check("...and its app queued",
          await Task.filter(device=devs_a[2], type="app_install").count() == 1)
    check("the current-state devices were left alone",
          await Task.filter(device=devs_a[0], type="profile_install").count() == 0
          and await Task.filter(device=devs_a[1], type="app_install").count() == 0)
    check(f"desired_hash ran once per profile, not per device x profile "
          f"(got {hashes_batched} for 1 profile x 3 devices)",
          hashes_batched == 1)
    check("a failed profile prefetch degrades to per-device queries "
          f"(got {degraded_profiles['profile_deployments']} for 3 devices)",
          degraded_profiles["profile_deployments"] == 3)
    check("...while the app prefetch it does not share still batches "
          f"(got {degraded_profiles['app_deployments']})",
          degraded_profiles["app_deployments"] == 1)
    check("the profile-degraded cycle produced an identical summary",
          summary_b == expected)
    check("a failed app prefetch degrades independently too "
          f"(apps {degraded_apps['app_deployments']}, "
          f"profiles {degraded_apps['profile_deployments']})",
          degraded_apps["app_deployments"] == 3
          and degraded_apps["profile_deployments"] == 1)
    check("the app-degraded cycle produced an identical summary",
          summary_c == expected)

    print("\n== 14. The startup schema phase is one advisory-locked section ==")
    # Schema phase guarded by advisory lock; racers die on unique index.
    import ast
    import hashlib

    db_src = (REPO / "controller/models/database.py").read_text()
    db_tree = ast.parse(db_src)
    db_funcs = {n.name: n for n in ast.walk(db_tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

    def _calls_in(node):
        """Every called name inside node, attribute calls by their attribute."""
        names = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                if isinstance(sub.func, ast.Attribute):
                    names.append(sub.func.attr)
                elif isinstance(sub.func, ast.Name):
                    names.append(sub.func.id)
        return names

    def _mentions(node, text):
        return text in (ast.get_source_segment(db_src, node) or "")

    # (1) Unlock in finally, not on happy path.
    lock_fn = db_funcs.get("_schema_lock")

    def _unlock_calls(node):
        return [sub for sub in ast.walk(node) if isinstance(sub, ast.Call)
                and _mentions(sub, "pg_advisory_unlock")]

    guarded = []
    for node in ast.walk(lock_fn) if lock_fn else []:
        if not isinstance(node, ast.Try):
            continue
        yields = any(isinstance(sub, ast.Yield)
                     for stmt in node.body for sub in ast.walk(stmt))
        finals = [sub for stmt in node.finalbody for sub in _unlock_calls(stmt)]
        if yields and finals:
            guarded.append(node)
    # Every unlock in the function has to be one of those finally-body calls, so an unlock added on the happy path fails
    # this even while the guarded one stays where it is.
    protected = {id(sub) for t in guarded for stmt in t.finalbody
                 for sub in _unlock_calls(stmt)}
    all_unlocks = _unlock_calls(lock_fn) if lock_fn else []
    check("the advisory unlock sits in the finally that wraps the yield",
          len(guarded) == 1 and bool(all_unlocks)
          and all(id(call) in protected for call in all_unlocks))

    # (2) Lock key from hashlib, not hash(); key must match across processes.
    check("the lock key is the pinned sha256 derivation, not a picked number",
          _db_mod._AUX_DDL_LOCK_KEY == int.from_bytes(
              hashlib.sha256(
                  b"micromanage.controller.models.database._AUX_DDL").digest()[:8],
              "big", signed=True))

    # (3) _AUX_DDL is the schema the app requires and stays loud; only _BEST_EFFORT_DDL swallows. A try/except added
    # to the first loop would turn a real DDL failure into a warning nobody reads and a column nothing created.
    ddl_loops = {}
    for node in ast.walk(db_funcs["_apply_aux_ddl"]):
        if isinstance(node, ast.For) and isinstance(node.iter, ast.Name):
            ddl_loops[node.iter.id] = node

    def _loop_has_try(name):
        loop = ddl_loops.get(name)
        return bool(loop) and any(isinstance(sub, ast.Try)
                                  for stmt in loop.body for sub in ast.walk(stmt))

    check("the _AUX_DDL loop still has no try/except",
          "_AUX_DDL" in ddl_loops and not _loop_has_try("_AUX_DDL"))
    check("the _BEST_EFFORT_DDL loop still has one",
          "_BEST_EFFORT_DDL" in ddl_loops and _loop_has_try("_BEST_EFFORT_DDL"))

    # (5) One lock; nesting would deadlock on second connection.
    init_fn = db_funcs["init_schema"]
    lock_withs = [w for w in ast.walk(init_fn) if isinstance(w, ast.AsyncWith)
                  and any(isinstance(item.context_expr, ast.Call)
                          and getattr(item.context_expr.func, "id", None) == "_schema_lock"
                          for item in w.items)]
    inside = []
    for w in lock_withs:
        for stmt in w.body:
            inside.extend(_calls_in(stmt))
    whole = _calls_in(init_fn)
    phases = ("generate_schemas", "get_schema_sql", "_apply_aux_ddl")
    check("init_schema takes the schema lock exactly once", len(lock_withs) == 1)
    check("both schema phases run inside that one hold",
          all(name in inside for name in phases)
          and all(whole.count(name) == inside.count(name) for name in phases))
    check("neither entry point spells the lock itself any more",
          not _mentions(init_fn, "pg_advisory_lock")
          and not _mentions(db_funcs["ensure_aux_columns"], "pg_advisory_lock"))

    # (4), (7) run on sqlite; dialect check catches wrong routing.
    schema_conn = Tortoise.get_connection("default")
    saved_aux, saved_best = _db_mod._AUX_DDL, _db_mod._BEST_EFFORT_DDL
    aux_error = init_error = None
    try:
        _db_mod._AUX_DDL, _db_mod._BEST_EFFORT_DDL = [], []
        try:
            await _db_mod.ensure_aux_columns()
        except Exception as exc:
            aux_error = exc
        try:
            await _db_mod.init_schema()
        except Exception as exc:
            init_error = exc
        tables = await schema_conn.execute_query_dict(
            "SELECT name FROM sqlite_master WHERE type='table'")
    finally:
        _db_mod._AUX_DDL, _db_mod._BEST_EFFORT_DDL = saved_aux, saved_best

    check(f"ensure_aux_columns skips the lock on sqlite ({aux_error})",
          aux_error is None)
    check(f"init_schema skips it too ({init_error})", init_error is None)
    check("init_schema still built the schema on sqlite",
          any(row["name"] == "devices" for row in tables))

    # (7) Nested lock hangs without cycle; guard runs before dialect check.
    flag_start = _db_mod._IN_SCHEMA_LOCK.get()
    async with _db_mod._schema_lock(schema_conn) as pinned:
        plain_pinned, flag_inside = pinned, _db_mod._IN_SCHEMA_LOCK.get()
    check("a plain acquisition is admitted and yields no pinned connection on sqlite",
          flag_start is False and plain_pinned is None and flag_inside is True)
    check("the flag is clean after the plain acquisition",
          _db_mod._IN_SCHEMA_LOCK.get() is False)

    nested_error = None
    try:
        async with _db_mod._schema_lock(schema_conn):
            async with _db_mod._schema_lock(schema_conn):
                pass
    except Exception as exc:
        nested_error = exc
    # The message is part of the assertion, not decoration: RecursionError is itself a RuntimeError, so a guard-less
    # version of this file can satisfy the isinstance alone by simply recursing until the stack runs out.
    check("a nested acquisition raises instead of hanging",
          isinstance(nested_error, RuntimeError)
          and "nested schema advisory lock" in str(nested_error))
    check("the flag is clean after the raising case too",
          _db_mod._IN_SCHEMA_LOCK.get() is False)

    # The exact future mistake, provoked: init_schema reaching for ensure_aux_columns from inside its own hold.
    saved_apply = _db_mod._apply_aux_ddl

    async def _apply_via_ensure(execute, log):
        await _db_mod.ensure_aux_columns()

    reentry_error = None
    try:
        _db_mod._apply_aux_ddl = _apply_via_ensure
        await _db_mod.init_schema()
    except Exception as exc:
        reentry_error = exc
    finally:
        _db_mod._apply_aux_ddl = saved_apply
    check("init_schema calling ensure_aux_columns from inside the hold is refused",
          isinstance(reentry_error, RuntimeError)
          and "nested schema advisory lock" in str(reentry_error))

    # Parallel init_schema() is OK; nesting inside one call is the bug.
    admitted = []

    async def _concurrent_entry(marker):
        async with _db_mod._schema_lock(schema_conn):
            admitted.append(marker)
            await asyncio.sleep(0)

    concurrent_error = None
    try:
        await asyncio.gather(_concurrent_entry(1), _concurrent_entry(2))
    except Exception as exc:
        concurrent_error = exc
    check("two concurrent tasks are both admitted",
          concurrent_error is None and sorted(admitted) == [1, 2])

    print("\n== 15. the duplicate guard reads a column, not the blob ==")
    # JSONB scan is expensive; save() mirrors key to Task.dedup_key column.
    from controller.models.tenant import DEDUP_KEY_SEP, task_dedup_key

    # 15a. The mirror, in both directions, through every save idiom. A tenant of its own, because 15c counts the queries
    # the guard issues per tenant and the shared one is full of earlier tasks with deliberately sparse details.
    dk_tenant = await Tenant.create(id="sp12", name="sp12")
    dk_dev = await Device.create(
        tenant=dk_tenant, udid="UDID-SN-DEDUP", serial_number="SN-DEDUP",
        device_model="MacBookPro18,3", os_version="15.5", hostname="sn-dedup",
        enrollment_state="enrolled", groups=[], tags=[])
    dk_profile = {"id": "wifi", "name": "Corporate Wi-Fi"}
    keyed = await Task.create(
        tenant=dk_tenant, type="profile_install", status="pending", device=dk_dev,
        user="system", description="Install profile",
        details={"profile_info": dk_profile})
    check("Task.create mirrors the key out of details",
          (await Task.get(id=keyed.id)).dedup_key == "wifi")

    app_keyed = await Task.create(
        tenant=dk_tenant, type="app_install", status="pending", device=dk_dev,
        user="system", description="Install app", details={"app_info": app_info})
    check("an app key is the two parts joined by the unit separator",
          (await Task.get(id=app_keyed.id)).dedup_key
          == "slack" + DEDUP_KEY_SEP + "1.0")

    ddm_keyed = await Task.create(
        tenant=dk_tenant, type="ddm_sync", status="pending", device=dk_dev,
        user="system", description="Declarative sync",
        details={"command_uuid": "cmd-ddm-key"})
    check("ddm_sync is keyed by its type alone, so the column stays NULL",
          (await Task.get(id=ddm_keyed.id)).dedup_key is None)

    unkeyed = await Task.create(
        tenant=dk_tenant, type="refresh_info", status="pending", device=dk_dev,
        user="system", description="Refresh", details={"profile_info": dk_profile})
    check("an unkeyed type gets no key even carrying a keyed type's details",
          (await Task.get(id=unkeyed.id)).dedup_key is None)

    keyed.details["profile_info"] = {"id": "vpn", "name": "VPN"}
    await keyed.save()
    check("a full save moves the column with the details",
          (await Task.get(id=keyed.id)).dedup_key == "vpn")
    keyed.details["profile_info"] = {"id": "wifi", "name": "Corporate Wi-Fi"}
    await keyed.save(update_fields=["details"])
    check("an update_fields save widens to carry the column too",
          (await Task.get(id=keyed.id)).dedup_key == "wifi")
    await keyed.update_progress(50, "running")
    check("a lifecycle save leaves the column alone",
          (await Task.get(id=keyed.id)).dedup_key == "wifi")

    # Details are source of truth; stale key is worse than missing.
    keyed.details.pop("profile_info")
    await keyed.save(update_fields=["details"])
    check("a row whose details shed the key clears the column",
          (await Task.get(id=keyed.id)).dedup_key is None)
    await Task.filter(id=app_keyed.id).update(dedup_key="not-the-key")
    app_keyed = await Task.get(id=app_keyed.id)
    await app_keyed.save()
    check("a column written behind the mirror is corrected on the next save",
          (await Task.get(id=app_keyed.id)).dedup_key
          == "slack" + DEDUP_KEY_SEP + "1.0")
    # Restore shed row for counting; NULL key reaches fallback.
    keyed.details["profile_info"] = dk_profile
    await keyed.save(update_fields=["details"])

    # 15b. Key must match row-scanning logic; differ silently = duplicate or suppressed.
    def head_row_key(ttype, details):
        details = details or {}
        if ttype == "profile_install" and details.get("profile_info"):
            return (ttype, details["profile_info"].get("id"))
        elif ttype == "profile_remove" and details.get("profile_id"):
            return (ttype, details["profile_id"])
        elif ttype == "app_install" and details.get("app_info"):
            info = details["app_info"]
            return (ttype, info.get("app_id"), info.get("version"))
        elif ttype == "ddm_sync":
            return (ttype,)
        return None

    def canonical(head_key):
        if head_key is None or len(head_key) == 1:
            return None
        if len(head_key) == 3:
            return str(head_key[1]) + DEDUP_KEY_SEP + str(head_key[2])
        return str(head_key[1])

    edges = [
        ("normal profile", "profile_install", {"profile_info": {"id": "wifi"}}),
        ("profile_info missing", "profile_install", {}),
        ("profile_info empty dict", "profile_install", {"profile_info": {}}),
        ("profile without an id", "profile_install", {"profile_info": {"name": "n"}}),
        ("profile id empty string", "profile_install", {"profile_info": {"id": ""}}),
        ("profile id None", "profile_install", {"profile_info": {"id": None}}),
        ("profile id int", "profile_install", {"profile_info": {"id": 7}}),
        ("details None", "profile_install", None),
        ("normal remove", "profile_remove", {"profile_id": "wifi"}),
        ("remove id empty", "profile_remove", {"profile_id": ""}),
        ("remove id missing", "profile_remove", {}),
        ("normal app", "app_install", {"app_info": {"app_id": "a", "version": "1"}}),
        ("app_info missing", "app_install", {}),
        ("app without a version", "app_install", {"app_info": {"app_id": "a"}}),
        ("app without an app_id", "app_install", {"app_info": {"version": "1"}}),
        ("app version float", "app_install", {"app_info": {"app_id": "a", "version": 1.5}}),
        ("ddm_sync", "ddm_sync", {"command_uuid": "x"}),
        ("unkeyed type", "refresh_info", {"command_uuid": "x"}),
    ]
    diverged = [label for label, ttype, details in edges
                if canonical(head_row_key(ttype, details))
                != task_dedup_key(ttype, details)]
    check(f"the key matches the previous reader on all {len(edges)} edge shapes "
          f"(diverged: {diverged})", not diverged)
    # The empty string is a real key and not the absence of one: the old reader tested profile_info for truth and never
    # the id, so an empty id still produced a key. NULL and '' mean different things in the column.
    check("an empty profile id is an empty key, not a missing one",
          task_dedup_key("profile_install", {"profile_info": {"id": ""}}) == ""
          and task_dedup_key("profile_install", {"profile_info": {}}) is None)
    # Row-scanning reader crashes on bad input; task_dedup_key never raises.
    crashers = [
        ("profile_info is a string", "profile_install",
         {"profile_info": "wifi"}, AttributeError),
        ("details is a list", "profile_install", ["not", "an", "object"], AttributeError),
        ("details is a string", "profile_remove", "not-an-object", AttributeError),
        ("profile id is a list", "profile_install",
         {"profile_info": {"id": ["a", "b"]}}, TypeError),
        ("app version is an object", "app_install",
         {"app_info": {"app_id": "a", "version": {"n": 1}}}, TypeError),
    ]
    still_raises, wrong_class = [], []
    for label, ttype, details, want in crashers:
        got = None
        try:
            {head_row_key(ttype, details)}
        except Exception as exc:
            got = type(exc)
        if got is not want:
            wrong_class.append(label)
        try:
            task_dedup_key(ttype, details)
        except Exception:
            still_raises.append(label)
    check(f"the old reader crashed on all {len(crashers)} of these shapes "
          f"(unconfirmed: {wrong_class})", not wrong_class)
    check(f"the new one raises on none of them (raised: {still_raises})",
          not still_raises)

    # str() collapse: 1, 1.0, True become three keys; 1 and "1" become one.
    old_merged = {head_row_key("profile_install", {"profile_info": {"id": v}})
                  for v in (1, 1.0, True)}
    new_split = {task_dedup_key("profile_install", {"profile_info": {"id": v}})
                 for v in (1, 1.0, True)}
    check("1 / 1.0 / True were one old key and are three new ones",
          len(old_merged) == 1 and new_split == {"1", "1.0", "True"})
    old_split = {head_row_key("profile_install", {"profile_info": {"id": v}})
                 for v in (1, "1")}
    new_merged = {task_dedup_key("profile_install", {"profile_info": {"id": v}})
                  for v in (1, "1")}
    check("int 1 and str '1' were two old keys and are one new one",
          len(old_split) == 2 and len(new_merged) == 1)
    # Accepted residual: a unit separator inside a component aliases two app keys into one. No authoring path puts a
    # control character in a bundle id or a version.
    aliased = {task_dedup_key("app_install", {"app_info": {"app_id": a, "version": v}})
               for a, v in (("a" + DEDUP_KEY_SEP + "b", "c"),
                            ("a", "b" + DEDUP_KEY_SEP + "c"))}
    check("a separator inside a component aliases two app keys (known residual)",
          len(aliased) == 1)

    # 15b-bis. No length bounds; over-long id causes startup outage.
    long_id = "p" * 300
    long_task = long_err = None
    try:
        long_task = await Task.create(
            tenant=dk_tenant, type="profile_install", status="completed",
            device=dk_dev, user="system", description="over-long profile id",
            details={"profile_info": {"id": long_id, "name": "n"}})
    except Exception as exc:
        long_err = exc
    check(f"a 300 character profile id is storable, not a save-time error "
          f"({type(long_err).__name__ if long_err else 'no error'})", long_err is None)
    check("...and its key is kept whole rather than truncated",
          long_task is not None
          and (await Task.get(id=long_task.id)).dedup_key == long_id)
    check("the model column carries no length bound",
          getattr(Task._meta.fields_map["dedup_key"], "max_length", None) in (None, 0))
    check("and neither does the column _AUX_DDL adds",
          'ALTER TABLE "tasks" ADD COLUMN IF NOT EXISTS "dedup_key" TEXT NULL'
          in _db_mod._AUX_DDL)

    # 15b-ter. Details that are not an object at all. A JSONField holds whatever was put in it, and details or {} does
    # not cover a truthy non-dict, so an unhandled list reaches .get() and raises out of save() and the guard.
    list_details_err = list_task = None
    try:
        list_task = await Task.create(
            tenant=dk_tenant, type="profile_install", status="pending",
            device=dk_dev, user="system", description="list details",
            details=["not", "an", "object"])
    except Exception as exc:
        list_details_err = exc
    check(f"a task whose details are a list is still creatable "
          f"({type(list_details_err).__name__ if list_details_err else 'no error'})",
          list_details_err is None)
    check("...with no key rather than an exception",
          list_task is not None
          and (await Task.get(id=list_task.id)).dedup_key is None)
    guard_err = None
    try:
        await reconciler._active_task_keys(dk_tenant)
    except Exception as exc:
        guard_err = exc
    check(f"and the guard survives reading it, fallback included "
          f"({type(guard_err).__name__ if guard_err else 'no error'})",
          guard_err is None)
    # Off the pending list again, so 15c counts a fully mirrored tenant.
    if list_task is not None:
        await Task.filter(id=list_task.id).delete()

    # 15c. What the guard asks the database for. The projection must not name details, so that is what is asserted.
    dk_sqls = []
    dk_real_qd = conn.execute_query_dict

    async def dk_spy(sql, values=None):
        dk_sqls.append(sql)
        return await dk_real_qd(sql, values)

    conn.execute_query_dict = dk_spy
    try:
        dk_sqls.clear()
        mirrored_keys = await reconciler._active_task_keys(dk_tenant)
        task_reads = [s for s in dk_sqls if 'FROM "tasks"' in s]
        check(f"the guard is one query when every row is mirrored "
              f"(got {len(task_reads)})", len(task_reads) == 1)
        check("and it never asks for the details blob",
              bool(task_reads) and '"details"' not in task_reads[0]
              and '"dedup_key"' in task_reads[0])
        check("the app task's key came back through the column",
              (str(dk_dev.id), "app_install",
               "slack" + DEDUP_KEY_SEP + "1.0") in mirrored_keys)

        # A row written by a process that predates the column, or one the backfill declined to express in SQL. Queryset
        # update bypasses the mirror, like a writer that does not know the column exists.
        await Task.filter(id=app_keyed.id).update(dedup_key=None)
        dk_sqls.clear()
        fallback_keys = await reconciler._active_task_keys(dk_tenant)
        task_reads = [s for s in dk_sqls if 'FROM "tasks"' in s]
        check(f"an un-mirrored row costs one extra query (got {len(task_reads)})",
              len(task_reads) == 2)
        check("and that one does read details",
              len(task_reads) == 2 and '"details"' in task_reads[1])
        check("the un-mirrored row's key is recovered identically",
              fallback_keys == mirrored_keys)
    finally:
        conn.execute_query_dict = dk_real_qd

    # 15d. The upgrade path is the _AUX_DDL backfill. The sqlite equivalent of the Postgres statement, run against a row
    # that really has no mirror.
    await conn.execute_script(
        "UPDATE tasks SET dedup_key = "
        "json_extract(details, '$.app_info.app_id') || char(31) || "
        "json_extract(details, '$.app_info.version') "
        "WHERE dedup_key IS NULL AND type = 'app_install' "
        "AND json_extract(details, '$.app_info.app_id') IS NOT NULL")
    check("the backfill fills a row the mirror never saw",
          (await Task.get(id=app_keyed.id)).dedup_key
          == "slack" + DEDUP_KEY_SEP + "1.0")

    # jsonb_typeof stops wrong-type keys; NULL is safe.
    backfills = [d for d in _db_mod._AUX_DDL
                 if d.startswith('UPDATE "tasks" SET "dedup_key"')]
    check("there is exactly one dedup_key backfill in _AUX_DDL",
          len(backfills) == 1)
    backfill_sql = backfills[0] if backfills else ""
    check("it only fills rows whose every component is a JSON string",
          backfill_sql.count("jsonb_typeof") == 4
          and backfill_sql.count("= 'string'") == 4)
    check("it skips rows that already have a key",
          '"dedup_key" IS NULL' in backfill_sql)
    check("it joins the app key with the same separator Python uses",
          "E'\\x1f'" in backfill_sql and DEDUP_KEY_SEP == "\x1f")
    check("the column is added before it is backfilled",
          any(d.startswith('ALTER TABLE "tasks" ADD COLUMN IF NOT EXISTS "dedup_key"')
              for d in _db_mod._AUX_DDL)
          and _db_mod._AUX_DDL.index(backfill_sql) > _db_mod._AUX_DDL.index(
              'ALTER TABLE "tasks" ADD COLUMN IF NOT EXISTS "dedup_key" TEXT NULL'))

    # 15e. Guard and lookup must use same key string.
    spawned.clear()
    reconciler._spawn = capture_spawn
    saved_fallback = reconciler._unmirrored_task_keys
    try:
        second = await reconciler.reconcile_tenant(ten_a, base)
        check(f"a second cycle queues nothing while the first is still in progress. "
              f"({second})",
              second["profiles_queued"] == 0 and second["apps_queued"] == 0
              and second["removals_queued"] == 0 and second["errors"] == 0)

        # Now the upgrade case, for real: every in-flight row un-mirrored, the way a database that has not run the
        # backfill yet looks.
        await Task.filter(tenant=ten_a, status__in=["pending", "running"]).update(
            dedup_key=None)
        third = await reconciler.reconcile_tenant(ten_a, base)
        check(f"an un-backfilled tenant still suppresses duplicates ({third})",
              third["profiles_queued"] == 0 and third["apps_queued"] == 0
              and third["removals_queued"] == 0)

        # With the fallback stubbed out, the same un-backfilled rows stop suppressing and the cycle queues the whole set
        # again.
        async def _no_fallback(_tenant):
            return set()

        reconciler._unmirrored_task_keys = _no_fallback
        fourth = await reconciler.reconcile_tenant(ten_a, base)
        check(f"without the fallback the same cycle re-queues everything "
              f"({fourth})",
              fourth["profiles_queued"] == 2 and fourth["apps_queued"] == 2
              and fourth["removals_queued"] == 1)
    finally:
        reconciler._unmirrored_task_keys = saved_fallback
        reconciler._spawn = real_spawn

    print("\n== 16. A failure that keeps failing waits longer each time ==")
    # Interval doubles per consecutive failure up to ceiling.
    saved_first = reconciler.RETRY_MINUTES
    saved_ceiling = reconciler.RETRY_MAX_MINUTES
    try:
        reconciler.RETRY_MINUTES = 30
        reconciler.RETRY_MAX_MINUTES = 1440
        schedule = [reconciler._retry_delay_minutes(n) for n in range(8)]
        check(f"the interval doubles and stops at the ceiling ({schedule})",
              schedule == [30, 60, 120, 240, 480, 960, 1440, 1440])
        check("the first interval is still exactly RETRY_MINUTES",
              reconciler._retry_delay_minutes(0) == reconciler.RETRY_MINUTES)
        # The exponent is clamped, so a row that has been failing since the install cannot turn this into an arbitrarily
        # large shift.
        check("a count no row could reach is still the ceiling",
              reconciler._retry_delay_minutes(10 ** 6) == 1440)
        reconciler.RETRY_MAX_MINUTES = 5
        check("a ceiling below the first interval wins",
              reconciler._retry_delay_minutes(0) == 5)
        reconciler.RETRY_MAX_MINUTES = 1440

        # The rule reads the counter rather than assuming one interval.
        def failed_app(minutes_ago, failed_attempts=0):
            return SimpleNamespace(
                status="failed", app_version="1.0", failed_attempts=failed_attempts,
                updated_at=now - timedelta(minutes=minutes_ago))

        check("a second failure is not retried at the first interval",
              reconciler._app_needs_deploy(failed_app(45, 1), "1.0", now) is None)
        check("...and is retried once the doubled interval has passed",
              reconciler._app_needs_deploy(failed_app(61, 1), "1.0", now)
              == reconciler.RETRY_AFTER_FAILURE)
        check("a row that has never failed keeps the old behaviour exactly",
              reconciler._app_needs_deploy(failed_app(31), "1.0", now)
              == reconciler.RETRY_AFTER_FAILURE
              and reconciler._app_needs_deploy(failed_app(29), "1.0", now) is None)

        # End to end, through a real cycle: the counter has to be written, read back on the next cycle, and cleared when
        # the row recovers.
        bo_tenant = await Tenant.create(id="backoff", name="backoff")
        write_configs(base, "backoff")
        bo_dev = await Device.create(
            tenant=bo_tenant, udid="UDID-BACKOFF", serial_number="SN-BACKOFF",
            device_model="MacBookPro18,3", os_version="15.5", hostname="backoff",
            enrollment_state="enrolled", groups=[], tags=[])
        bo_wifi = tenant_config.load_profiles("backoff")[0]
        await ProfileDeployment.create(
            tenant=bo_tenant, device=bo_dev, profile_id="wifi", status="installed",
            payload_hash=ProfileManager.desired_hash(bo_wifi))
        bo_row = await AppDeployment.create(
            tenant=bo_tenant, device=bo_dev, app_id="slack", app_version="1.0",
            status="failed", last_error="No S3 bucket is configured")

        async def bo_failed_minutes_ago(minutes):
            """Put the row back to a failure that old, task list cleared."""
            await Task.filter(tenant=bo_tenant, type="app_install").update(
                status="completed")
            await AppDeployment.filter(id=bo_row.id).update(
                status="failed",
                updated_at=datetime.now(timezone.utc) - timedelta(minutes=minutes))

        spawned.clear()
        reconciler._spawn = capture_spawn
        try:
            await bo_failed_minutes_ago(31)
            first = await reconciler.reconcile_tenant(bo_tenant, base)
            counted = await AppDeployment.get(id=bo_row.id)
            check(f"a failure past the first interval is retried ({first})",
                  first["apps_queued"] == 1)
            check("...and the attempt is counted on the row",
                  counted.failed_attempts == 1)

            await bo_failed_minutes_ago(31)
            second = await reconciler.reconcile_tenant(bo_tenant, base)
            check(f"the same age no longer earns a retry ({second})",
                  second["apps_queued"] == 0)
            check("...and nothing was counted for a cycle that queued nothing",
                  (await AppDeployment.get(id=bo_row.id)).failed_attempts == 1)

            await bo_failed_minutes_ago(61)
            third = await reconciler.reconcile_tenant(bo_tenant, base)
            check(f"the doubled interval does earn one ({third})",
                  third["apps_queued"] == 1)
            check("...and the count moves again",
                  (await AppDeployment.get(id=bo_row.id)).failed_attempts == 2)

            # A row that recovers starts its next bad patch from the first interval rather than from wherever it left
            # off.
            await Task.filter(tenant=bo_tenant, type="app_install").update(
                status="completed")
            await AppDeployment.filter(id=bo_row.id).update(
                status="installed", app_version="1.0", failed_attempts=4)
            recovered = await reconciler.reconcile_tenant(bo_tenant, base)
            check(f"an installed row queues nothing ({recovered})",
                  recovered["apps_queued"] == 0)
            check("...and its failure count is cleared",
                  (await AppDeployment.get(id=bo_row.id)).failed_attempts == 0)
        finally:
            reconciler._spawn = real_spawn
    finally:
        reconciler.RETRY_MINUTES = saved_first
        reconciler.RETRY_MAX_MINUTES = saved_ceiling

    print("\n== 17. A corrected definition does not serve out the backoff ==")
    # The backoff stops re-sending what just failed. A definition edited since the failure is not that, so the interval
    # does not hold it back.
    cor_tenant = await Tenant.create(id="corrected", name="corrected")
    write_configs(base, "corrected")
    cor_dev = await Device.create(
        tenant=cor_tenant, udid="UDID-CORRECTED", serial_number="SN-CORRECTED",
        device_model="MacBookPro18,3", os_version="15.5", hostname="corrected",
        enrollment_state="enrolled", groups=[], tags=[])
    cor_wifi = tenant_config.load_profiles("corrected")[0]
    cor_row = await ProfileDeployment.create(
        tenant=cor_tenant, device=cor_dev, profile_id="wifi", status="failed",
        payload_hash="the-hash-of-what-the-device-rejected", failed_attempts=3,
        last_error="The profile could not be installed")
    await AppDeployment.create(
        tenant=cor_tenant, device=cor_dev, app_id="slack", app_version="1.0",
        status="installed")

    check("the rule says so on its own, with the failure a minute old",
          reconciler._profile_needs_deploy(
              SimpleNamespace(status="failed", payload_hash="old", failed_attempts=3,
                              updated_at=now - timedelta(minutes=1)),
              "new", now) == "profile definition changed")
    # A profile whose enqueue failed never got as far as recording a hash. No hash must not read as changed, or every
    # enqueue failure retries on every cycle and the backoff is off.
    check("a failure with no recorded hash still backs off",
          reconciler._profile_needs_deploy(
              SimpleNamespace(status="failed", payload_hash=None, failed_attempts=0,
                              updated_at=now - timedelta(minutes=1)),
              "new", now) is None)
    check("...and is still retried once its interval is up",
          reconciler._profile_needs_deploy(
              SimpleNamespace(status="failed", payload_hash=None, failed_attempts=0,
                              updated_at=now - timedelta(minutes=reconciler.RETRY_MINUTES + 1)),
              "new", now) == reconciler.RETRY_AFTER_FAILURE)

    spawned.clear()
    reconciler._spawn = capture_spawn
    try:
        corrected = await reconciler.reconcile_tenant(cor_tenant, base)
        check(f"a fresh failure whose definition has moved on is queued now "
              f"({corrected})", corrected["profiles_queued"] == 1)
        cor_task = await Task.filter(device=cor_dev, type="profile_install").first()
        check("...and the task says which of the two reasons it was",
              cor_task is not None
              and "definition changed" in (cor_task.description or ""))
        check("...and the failure count starts over with the new definition",
              (await ProfileDeployment.get(id=cor_row.id)).failed_attempts == 0)
    finally:
        reconciler._spawn = real_spawn

    print("\n== 18. A tenant that cannot serve packages queues no app installs ==")
    # Missing tenant setting creates one failed task per device per cycle.
    nb_tenant = await Tenant.create(id="nobucket", name="nobucket")
    write_configs(base, "nobucket")
    nb_devs = [await Device.create(
        tenant=nb_tenant, udid=f"UDID-NOBUCKET-{i}", serial_number=f"SN-NOBUCKET-{i}",
        device_model="MacBookPro18,3", os_version="15.5", hostname=f"nobucket-{i}",
        enrollment_state="enrolled", groups=[], tags=[]) for i in range(3)]

    nb_capture = _CaptureLog()
    reconciler.logger.addHandler(nb_capture)
    nb_counts = {"app_deployments": 0}
    nb_real_q, nb_real_qd = conn.execute_query, conn.execute_query_dict

    def nb_tally(sql):
        if sql.lstrip().upper().startswith("SELECT") and '"app_deployments"' in sql:
            nb_counts["app_deployments"] += 1

    async def nb_spy_q(sql, values=None):
        nb_tally(sql)
        return await nb_real_q(sql, values)

    async def nb_spy_qd(sql, values=None):
        nb_tally(sql)
        return await nb_real_qd(sql, values)

    saved_bucket = os.environ.pop("AWS_S3_BUCKET")
    spawned.clear()
    reconciler._spawn = capture_spawn
    conn.execute_query, conn.execute_query_dict = nb_spy_q, nb_spy_qd
    try:
        blocked = await reconciler.reconcile_tenant(nb_tenant, base)
    finally:
        conn.execute_query, conn.execute_query_dict = nb_real_q, nb_real_qd
        reconciler._spawn = real_spawn
        reconciler.logger.removeHandler(nb_capture)

    check(f"no app install is queued for a tenant with nowhere to serve from "
          f"({blocked})", blocked["apps_queued"] == 0)
    check("...and the summary says how much work the fix would release",
          blocked["apps_blocked"] == 3)
    check("...and no device is given a task for it",
          await Task.filter(tenant=nb_tenant, type="app_install").count() == 0)
    check("...nor a deployment row that would read as a failure",
          await AppDeployment.filter(tenant=nb_tenant).count() == 0)
    check("profiles are not collateral", blocked["profiles_queued"] == 3)
    warnings = [m for m in nb_capture.messages if "app install" in m]
    check(f"exactly one warning for the tenant, not one per device "
          f"(got {len(warnings)})", len(warnings) == 1)
    check("...and it names the setting to change",
          bool(warnings) and "AWS_S3_BUCKET" in warnings[0])
    check(f"the precondition costs no per-device queries "
          f"(got {nb_counts['app_deployments']} for 3 devices)",
          nb_counts["app_deployments"] == 1)

    os.environ["AWS_S3_BUCKET"] = saved_bucket
    spawned.clear()
    reconciler._spawn = capture_spawn
    try:
        unblocked = await reconciler.reconcile_tenant(nb_tenant, base)
    finally:
        reconciler._spawn = real_spawn
    check(f"the cycle after the setting lands proceeds normally ({unblocked})",
          unblocked["apps_queued"] == 3 and unblocked["apps_blocked"] == 0)

    print("\n== 19. Unscoping an app retires its row instead of leaving it ==")
    # A profile that stops being scoped is removed or dropped. Without this, an app's row would sit in the device's app
    # list at whatever status it last had for as long as the device existed.
    us_tenant = await Tenant.create(id="unscope", name="unscope")
    write_configs(base, "unscope")
    us_dir = base / "tenants" / "unscope"

    def us_apps(include_slack):
        """apps.yaml for this tenant: 'held' is scoped but its only version is behind a rollout nobody has reached,
        which is not the same thing as no longer being wanted."""
        apps = [{"id": "held", "name": "Held", "bundle_id": "com.example.held",
                 "versions": [{"version": "2.0", "s3_key": "apps/held-2.0.pkg",
                               "groups": ["all-macs"],
                               # A wave that has not opened yet. percent 0 would not do it: rollout_coverage fails open
                               # on a nonsense percentage, so the hold has to come from a start date in the future.
                               "rollout": {"percent": 10,
                                           "start": "2099-01-01T00:00:00Z"}}]}]
        if include_slack:
            apps.insert(0, {"id": "slack", "name": "Slack",
                            "bundle_id": "com.tinyspeck.slackmacgap",
                            "versions": [{"version": "1.0",
                                          "s3_key": "apps/slack-1.0.pkg",
                                          "groups": ["all-macs"]}]})
        (us_dir / "apps.yaml").write_text(yaml.safe_dump({"apps": apps}))
        tenant_config.invalidate("unscope")

    us_installed = await Device.create(
        tenant=us_tenant, udid="UDID-UNSCOPE-1", serial_number="SN-UNSCOPE-1",
        device_model="MacBookPro18,3", os_version="15.5", hostname="unscope-1",
        enrollment_state="enrolled", groups=[], tags=[])
    us_failed = await Device.create(
        tenant=us_tenant, udid="UDID-UNSCOPE-2", serial_number="SN-UNSCOPE-2",
        device_model="MacBookPro18,3", os_version="15.5", hostname="unscope-2",
        enrollment_state="enrolled", groups=[], tags=[])
    us_row = await AppDeployment.create(
        tenant=us_tenant, device=us_installed, app_id="slack", app_version="1.0",
        status="installed", install_date=datetime.now(timezone.utc),
        failed_attempts=3)
    us_dead = await AppDeployment.create(
        tenant=us_tenant, device=us_failed, app_id="slack", app_version="1.0",
        status="failed", last_error="No S3 bucket is configured for tenant 'unscope'")
    us_held = await AppDeployment.create(
        tenant=us_tenant, device=us_installed, app_id="held", app_version="2.0",
        status="installed", install_date=datetime.now(timezone.utc))

    us_apps(include_slack=True)
    spawned.clear()
    reconciler._spawn = capture_spawn
    try:
        still_scoped = await reconciler.reconcile_tenant(us_tenant, base)
        check(f"a version nobody's wave has reached is not an unscoping "
              f"({still_scoped})", still_scoped["apps_unscoped"] == 0)
        check("...and the held app's row is untouched",
              (await AppDeployment.get(id=us_held.id)).status == "installed")

        us_apps(include_slack=False)
        retired = await reconciler.reconcile_tenant(us_tenant, base)
        check(f"leaving an app's scope retires its rows ({retired})",
              retired["apps_unscoped"] == 2)
        us_row = await AppDeployment.get(id=us_row.id)
        check("an installed app stops claiming a managed state",
              us_row.status == "unscoped")
        check("...and is not deleted, because it may still be on the device",
              us_row.install_date is not None)
        check("...and carries nothing forward from a state it no longer claims",
              us_row.last_error is None and us_row.failed_attempts == 0)
        check("a row that never reached the device is dropped outright",
              await AppDeployment.filter(id=us_dead.id).count() == 0)
        check("no RemoveApplication is sent for either of them",
              await Task.filter(tenant=us_tenant, type="app_remove").count() == 0)
        check("the held app is still not touched",
              (await AppDeployment.get(id=us_held.id)).status == "installed")

        again = await reconciler.reconcile_tenant(us_tenant, base)
        check(f"a retired row is retired once, not every cycle ({again})",
              again["apps_unscoped"] == 0)

        # Coming back into scope has to work, or retiring a row means never installing that app on that device again.
        us_apps(include_slack=True)
        rescoped = await reconciler.reconcile_tenant(us_tenant, base)
        check(f"both devices are installable again ({rescoped})",
              rescoped["apps_queued"] == 2)
        rescoped_task = await Task.filter(
            device=us_installed, type="app_install").first()
        check("...and the retired row's install says why it was queued",
              rescoped_task is not None
              and "back in scope" in (rescoped_task.description or ""))

        # Parse failure produces empty list; don't retire app estate.
        (us_dir / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
        tenant_config.invalidate("unscope")
        before_rows = await AppDeployment.filter(tenant=us_tenant).count()
        emptied = await reconciler.reconcile_tenant(us_tenant, base)
        check(f"an empty apps.yaml retires nothing ({emptied})",
              emptied["apps_unscoped"] == 0)
        check("...and every row it would have touched is still there",
              await AppDeployment.filter(tenant=us_tenant).count() == before_rows)
        us_apps(include_slack=True)
    finally:
        reconciler._spawn = real_spawn

    print("\n== 20. A task does not publish the payload it installed ==")
    # A profile definition is where a Wi-Fi PSK, an 802.1X password and a SCEP challenge live, and a task is readable by
    # anyone who can list tasks and outlives the install by the retention window.
    import json

    from controller.services.profile_manager import REDACTED
    from controller.services import task_handlers

    secret_profile = {
        "id": "corp-wifi", "name": "Corp Wi-Fi",
        "groups": ["all-macs"],
        "payloads": [
            {"PayloadType": "com.apple.wifi.managed",
             "PayloadIdentifier": "com.example.wifi",
             "SSID_STR": "CorpNet", "EncryptionType": "WPA",
             "Password": "hunter2-the-actual-psk",
             "EAPClientConfiguration": {"UserName": "svc",
                                        "UserPassword": "nested-secret"}},
            {"PayloadType": "com.apple.security.scep",
             "PayloadContent": {"URL": "https://ca.example.com/scep",
                                "Challenge": "scep-challenge-value"}},
            {"PayloadType": "com.apple.security.pkcs12",
             "PayloadIdentifier": "com.example.identity",
             "PayloadContent": "BASE64-IDENTITY-BLOB",
             "Password": "p12-passphrase"},
        ],
    }
    secret_values = ["hunter2-the-actual-psk", "nested-secret",
                     "scep-challenge-value", "BASE64-IDENTITY-BLOB",
                     "p12-passphrase"]
    real_hash = ProfileManager.desired_hash(secret_profile)
    stored = ProfileManager.install_task_details(secret_profile, real_hash)
    as_json = json.dumps(stored, sort_keys=True, default=str)
    leaked = [v for v in secret_values if v in as_json]
    check(f"no secret survives into what gets stored (leaked: {leaked})", not leaked)
    check("every one of them is replaced rather than dropped",
          as_json.count(REDACTED) == len(secret_values))
    digest = stored["payload_digest"]
    check("the digest carries the hash the deployment row is stamped with",
          digest["sha256"] == real_hash)
    check("...and the size of the definition as authored",
          digest["bytes"] == len(json.dumps(secret_profile, sort_keys=True,
                                            default=str).encode()))
    check("...and the identity of each payload",
          digest["payloads"] == [
              {"PayloadIdentifier": "com.example.wifi",
               "PayloadType": "com.apple.wifi.managed"},
              {"PayloadType": "com.apple.security.scep"},
              {"PayloadIdentifier": "com.example.identity",
               "PayloadType": "com.apple.security.pkcs12"}])
    check("...and names what it is missing",
          sorted(digest["redacted"]) == sorted([
              "payloads[0].Password",
              "payloads[0].EAPClientConfiguration.UserPassword",
              "payloads[1].PayloadContent.Challenge",
              "payloads[2].PayloadContent",
              "payloads[2].Password"]))
    check("the readable half of the definition is left alone",
          stored["profile_info"]["id"] == "corp-wifi"
          and stored["profile_info"]["name"] == "Corp Wi-Fi"
          and stored["profile_info"]["payloads"][0]["SSID_STR"] == "CorpNet")
    # The dedup key is the profile id, so redaction that touched it would queue a duplicate install every cycle.
    check("the key the guard looks up survives redaction",
          task_dedup_key("profile_install", stored)
          == task_dedup_key("profile_install", {"profile_info": secret_profile}))
    # A profile with nothing to hide is stored exactly as authored, which is what every reader comparing a task against
    # the YAML relies on.
    plain = {"id": "plain", "name": "Plain", "payload": {"PayloadType": "com.example"}}
    check("a definition with no secret in it is stored unchanged",
          ProfileManager.install_task_details(
              plain, ProfileManager.desired_hash(plain))["profile_info"] == plain)

    # End to end. The device must receive the real payload, and the row must be stamped with the hash of the real
    # definition, or the sync loop would find it out of date on every cycle and re-push it forever.
    (base / "tenants" / "secrets").mkdir(parents=True, exist_ok=True)
    write_configs(base, "secrets")
    (base / "tenants" / "secrets" / "profiles.yaml").write_text(
        yaml.safe_dump({"profiles": [secret_profile]}))
    (base / "tenants" / "secrets" / "apps.yaml").write_text(
        yaml.safe_dump({"apps": []}))
    tenant_config.invalidate("secrets")
    sec_tenant = await Tenant.create(id="secrets", name="Secrets")
    sec_dev = await Device.create(
        tenant=sec_tenant, udid="UDID-SECRETS", serial_number="SN-SECRETS",
        device_model="MacBookPro18,3", os_version="15.5", hostname="secrets",
        enrollment_state="enrolled", groups=[], tags=[])

    pushed = []

    class _FakeConnector:
        async def install_profile(self, udid, payload):
            pushed.append(payload)
            return {"command_uuid": f"cmd-secret-{len(pushed)}"}

    sec_spawned = []

    def sec_spawn(coro):
        sec_spawned.append(coro)

    real_connector = task_handlers.shared_connector
    task_handlers.shared_connector = lambda: _FakeConnector()
    reconciler._spawn = sec_spawn
    try:
        sec_summary = await reconciler.reconcile_tenant(sec_tenant, base)
        for coro in sec_spawned:
            await coro
    finally:
        reconciler._spawn = real_spawn
        task_handlers.shared_connector = real_connector

    sec_task = await Task.filter(tenant=sec_tenant, type="profile_install").first()
    sec_row = await ProfileDeployment.get(tenant=sec_tenant, profile_id="corp-wifi")
    check(f"the profile was queued and delivered ({sec_summary})",
          sec_summary["profiles_queued"] == 1 and len(pushed) == 1)
    delivered = json.dumps(pushed[0], sort_keys=True, default=str) if pushed else ""
    check("the device is sent the real payload, not the sentinel",
          all(v in delivered for v in secret_values) and REDACTED not in delivered)
    stored_task = json.dumps(sec_task.details, sort_keys=True, default=str)
    check("...while the task row it came from carries none of it",
          not [v for v in secret_values if v in stored_task])
    check("the deployment row is stamped with the hash of the real definition",
          sec_row.payload_hash == ProfileManager.desired_hash(
              tenant_config.load_profiles("secrets")[0]))
    # That last one is what stops a re-push loop: an install that stamped the hash of the redacted copy would read as
    # out of date on the next cycle.
    reconciler._spawn = capture_spawn
    try:
        await Task.filter(tenant=sec_tenant).update(status="completed")
        await ProfileDeployment.filter(id=sec_row.id).update(status="installed")
        settled = await reconciler.reconcile_tenant(sec_tenant, base)
    finally:
        reconciler._spawn = real_spawn
    check(f"an installed profile is not re-pushed on the next cycle ({settled})",
          settled["profiles_queued"] == 0)

    # The retry path has only the row: no bound definition, and a stored copy it must not send. It recovers the authored
    # definition instead.
    pushed.clear()
    retry_src = await Task.create(
        tenant=sec_tenant, type="profile_install", status="failed", device=sec_dev,
        user="system", description="Install profile: Corp Wi-Fi",
        error="The profile could not be installed", details=sec_task.details)
    sec_user = await User.create(tenant=sec_tenant, email="admin@secrets", role="admin")
    sec_admin = Principal(tenant=sec_tenant, user=sec_user,
                          email="admin@secrets", role="admin")
    task_handlers.shared_connector = lambda: _FakeConnector()
    reconciler._spawn = capture_spawn
    try:
        retried = await retry_task(str(retry_src.id), sec_admin)
        retry_row = await Task.get(id=retried["task_id"])
        await task_handlers.handle_profile_install_task(retry_row)
    finally:
        task_handlers.shared_connector = real_connector
        reconciler._spawn = real_spawn
    retry_payload = json.dumps(pushed[0], sort_keys=True, default=str) if pushed else ""
    check("a retry sends the authored payload rather than the stored copy",
          len(pushed) == 1 and all(v in retry_payload for v in secret_values)
          and REDACTED not in retry_payload)
    check("...and the retry's own task row still carries no secret",
          not [v for v in secret_values
               if v in json.dumps((await Task.get(id=retry_row.id)).details,
                                  sort_keys=True, default=str)])

    # And when there is nothing to recover from, it says so instead of installing a profile made of sentinels.
    (base / "tenants" / "secrets" / "profiles.yaml").write_text(
        yaml.safe_dump({"profiles": []}))
    tenant_config.invalidate("secrets")
    pushed.clear()
    gone = await Task.create(
        tenant=sec_tenant, type="profile_install", status="pending", device=sec_dev,
        user="system", description="Install profile: Corp Wi-Fi",
        details=sec_task.details)
    task_handlers.shared_connector = lambda: _FakeConnector()
    try:
        await task_handlers.handle_profile_install_task(gone)
    finally:
        task_handlers.shared_connector = real_connector
    gone = await Task.get(id=gone.id)
    check("a definition that is gone fails the task instead of sending a stub",
          gone.status == "failed" and not pushed
          and "no longer in this tenant's configuration" in (gone.error or ""))

    print("\n== 21. A refused declarative sync is counted, not raised ==")
    # EnqueueFailed is falsy but distinct from steady-state False.
    import plistlib

    from controller.services import ddm_manager

    ddm_tenant = await Tenant.create(id="ddmcount", name="DDM Count",
                                     ddm_enabled=True)
    write_configs(base, "ddmcount")
    (base / "tenants" / "ddmcount" / "declarations.yaml").write_text(
        yaml.safe_dump({"declarations": []}))
    tenant_config.invalidate("ddmcount")
    ddm_dev = await Device.create(
        tenant=ddm_tenant, udid="UDID-DDMCOUNT", serial_number="SN-DDMCOUNT",
        device_model="MacBookPro18,3", os_version="15.5", hostname="sn-ddmcount",
        enrollment_state="enrolled", groups=[], tags=[])

    real_sync = ddm_manager.sync_device
    tracebacks = []

    class _TracebackSpy(_logging.Handler):
        def emit(self, record):
            if record.exc_info:
                tracebacks.append(record.getMessage())

    async def run_cycle(answer):
        async def fake_sync(device, **kw):
            return answer

        spy = _TracebackSpy()
        ddm_manager.sync_device = fake_sync
        reconciler.logger.addHandler(spy)
        try:
            return await reconciler.reconcile_tenant(ddm_tenant, base)
        finally:
            ddm_manager.sync_device = real_sync
            reconciler.logger.removeHandler(spy)

    refused = await run_cycle(ddm_manager.EnqueueFailed("NanoMDM said no"))
    check(f"a refused enqueue counts one error ({refused})",
          refused["errors"] == 1)
    check("...and does not count as a queued sync",
          refused["ddm_syncs_queued"] == 0)
    check("...and leaves no traceback behind, since nothing raised",
          not tracebacks)
    check("...and queues no ddm_sync task of its own, so the next cycle retries",
          await Task.filter(tenant=ddm_tenant, type="ddm_sync").count() == 0)

    tracebacks.clear()
    idle = await run_cycle(False)
    check(f"a device already in sync is not an error ({idle})",
          idle["errors"] == 0 and idle["ddm_syncs_queued"] == 0)
    tracebacks.clear()
    queued = await run_cycle(True)
    check(f"a queued sync counts once and reports no error ({queued})",
          queued["ddm_syncs_queued"] == 1 and queued["errors"] == 0)
    check("the refused device stays eligible, so a later cycle attempts it again",
          (await Device.get(id=ddm_dev.id)).enrollment_state == "enrolled")

    print("\n== 22. FileVault2 Enable reaches the device as Apple's string ==")
    # Unquoted Enable becomes YAML boolean; plist gets On/Off string.
    # https://raw.githubusercontent.com/apple/device-management/release/mdm/profiles/com.apple.MCX.FileVault2.yaml
    fv_pm = ProfileManager(tenant)

    def built(payload):
        return fv_pm._build_profile_payload(
            {"id": "fv", "name": "FileVault", "payloads": [payload]}
        )["PayloadContent"][0]

    fv_on = built({"PayloadType": "com.apple.MCX.FileVault2", "Enable": True,
                   "Defer": True})
    fv_off = built({"PayloadType": "com.apple.MCX.FileVault2", "Enable": False})
    check("an unquoted On (parsed True) ships as the string 'On'",
          fv_on["Enable"] == "On")
    check("an unquoted Off (parsed False) ships as the string 'Off'",
          fv_off["Enable"] == "Off")
    check("...and the plist carries <string>, not <true/>",
          b"<string>On</string>" in plistlib.dumps(fv_on)
          and b"<true/>" not in plistlib.dumps({"Enable": fv_on["Enable"]}))
    check("a quoted Enable is left exactly as authored",
          built({"PayloadType": "com.apple.MCX.FileVault2",
                 "Enable": "Off"})["Enable"] == "Off")
    check("the coercion is scoped to FileVault2, so other payloads keep their booleans",
          built({"PayloadType": "com.apple.MCX.FileVault2.Recovery",
                 "Enable": True})["Enable"] is True)
    check("...and Defer, which Apple really does type as a boolean, is untouched",
          fv_on["Defer"] is True)

    print("\n== 23. An edited profile whose enqueue keeps failing still backs off ==")
    # Hash records attempt, not success; enables immediate retry on edit.
    lad_tenant = await Tenant.create(id="ladder", name="ladder")
    write_configs(base, "ladder")
    (base / "tenants" / "ladder" / "apps.yaml").write_text(
        yaml.safe_dump({"apps": []}))
    tenant_config.invalidate("ladder")
    lad_dev = await Device.create(
        tenant=lad_tenant, udid="UDID-LADDER", serial_number="SN-LADDER",
        device_model="MacBookPro18,3", os_version="15.5", hostname="ladder",
        enrollment_state="enrolled", groups=[], tags=[])
    lad_wifi = tenant_config.load_profiles("ladder")[0]
    # Installed once, then edited: the row holds the hash of the old definition.
    lad_row = await ProfileDeployment.create(
        tenant=lad_tenant, device=lad_dev, profile_id="wifi", status="failed",
        payload_hash="the-hash-from-before-the-edit",
        last_error="NanoMDM has no enrollment for this device")

    class _RefusingConnector:
        async def install_profile(self, udid, payload):
            raise RuntimeError("NanoMDM has no enrollment for this device")

    lad_real_connector = task_handlers.shared_connector
    task_handlers.shared_connector = lambda: _RefusingConnector()

    async def lad_cycle():
        """One cycle with its handlers actually run, so the failure reaches the row the way it does in the product."""
        coros = []
        reconciler._spawn = coros.append
        try:
            summary = await reconciler.reconcile_tenant(lad_tenant, base)
        finally:
            reconciler._spawn = real_spawn
        for coro in coros:
            await coro
        return summary

    async def lad_age(minutes):
        await ProfileDeployment.filter(id=lad_row.id).update(
            updated_at=datetime.now(timezone.utc) - timedelta(minutes=minutes))

    try:
        first = await lad_cycle()
        check(f"the edit earns its immediate retry ({first})",
              first["profiles_queued"] == 1)
        after = await ProfileDeployment.get(id=lad_row.id)
        check("the failed enqueue records the definition it attempted",
              after.payload_hash == ProfileManager.desired_hash(lad_wifi))
        check("...and the row is failed with the enqueue's own reason",
              after.status == "failed"
              and "no enrollment" in (after.last_error or ""))

        second = await lad_cycle()
        third = await lad_cycle()
        check(f"the next cycles wait instead of queueing again "
              f"({second['profiles_queued']}, {third['profiles_queued']})",
              second["profiles_queued"] == 0 and third["profiles_queued"] == 0)

        await lad_age(reconciler.RETRY_MINUTES + 1)
        fourth = await lad_cycle()
        check(f"the first interval earns one retry ({fourth})",
              fourth["profiles_queued"] == 1)
        check("...and it is counted, so the interval doubles",
              (await ProfileDeployment.get(id=lad_row.id)).failed_attempts == 1)

        await lad_age(reconciler.RETRY_MINUTES + 1)
        fifth = await lad_cycle()
        check(f"the same wait no longer earns one ({fifth})",
              fifth["profiles_queued"] == 0)
        await lad_age(reconciler.RETRY_MINUTES * 2 + 1)
        sixth = await lad_cycle()
        check(f"the doubled interval does ({sixth})", sixth["profiles_queued"] == 1)
        check(f"six cycles against a device that cannot be reached cost three "
              f"tasks, not six",
              await Task.filter(tenant=lad_tenant, type="profile_install").count() == 3)

        # A genuine edit, made while the row is failing, still goes immediately.
        edited = dict(lad_wifi)
        edited["payload"] = {**lad_wifi["payload"], "SSID_STR": "CorpNet-2"}
        (base / "tenants" / "ladder" / "profiles.yaml").write_text(
            yaml.safe_dump({"profiles": [edited]}))
        tenant_config.invalidate("ladder")
        corrected = await lad_cycle()
        check(f"a real edit still does not wait ({corrected})",
              corrected["profiles_queued"] == 1)
        check("...and starts the count over",
              (await ProfileDeployment.get(id=lad_row.id)).failed_attempts == 0)
    finally:
        task_handlers.shared_connector = lad_real_connector

    print("\n== 24. Queued but not pushed is not a failure ==")
    # Failed push leaves command; device applies at next check-in.
    from controller.services.profile_manager import push_failure_note

    check("a result with no push keys reads as nothing to say",
          push_failure_note({"command_uuid": "x"}) is None)
    check("a result that is not a mapping is not an error either",
          push_failure_note(None) is None and push_failure_note("x") is None)
    check("a push failure with no detail still says what happened",
          "next check-in" in (push_failure_note({"push_failed": True}) or ""))

    push_tenant = await Tenant.create(id="pushfail", name="pushfail")
    write_configs(base, "pushfail")
    push_dev = await Device.create(
        tenant=push_tenant, udid="UDID-PUSHFAIL", serial_number="SN-PUSHFAIL",
        device_model="MacBookPro18,3", os_version="15.5", hostname="pushfail",
        enrollment_state="enrolled", groups=[], tags=[])

    class _UnpushedConnector:
        async def install_profile(self, udid, payload):
            return {"command_uuid": "cmd-unpushed-1", "push_failed": True,
                    "push_errors": {udid: "APNs 410: device token unregistered"}}

        async def install_app(self, udid, manifest_url, management_flags=1,
                              install_as_managed=True):
            return {"command_uuid": "cmd-unpushed-2", "push_failed": True,
                    "push_errors": {udid: "no push certificate configured"}}

    class _QuietConnector:
        """What today's connector returns: no push keys at all."""

        async def install_profile(self, udid, payload):
            return {"command_uuid": "cmd-quiet-1"}

    push_profile_info = tenant_config.load_profiles("pushfail")[0]
    push_row = await ProfileManager(push_tenant).deploy_profile(
        push_dev, push_profile_info, _UnpushedConnector())
    check("a profile whose push failed is still on its way, not failed",
          push_row.status == "installing")
    check("...and the row says why it may sit there a while",
          "token unregistered" in (push_row.last_error or "")
          and "next check-in" in (push_row.last_error or ""))

    push_row = await ProfileManager(push_tenant).deploy_profile(
        push_dev, push_profile_info, _QuietConnector())
    check("an attempt that pushed cleanly clears the note",
          push_row.status == "installing" and push_row.last_error is None)

    # The app half, through the real deploy_app. Credentials are set so a stray S3 client build would still be local;
    # deploy_app itself reaches nothing.
    saved_creds = {k: os.environ.get(k) for k in
                   ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")}
    os.environ["AWS_ACCESS_KEY_ID"] = "AKIA-VERIFY"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "verify-secret"
    try:
        push_app_row = await AppManager(push_tenant).deploy_app(
            push_dev, app_info, _UnpushedConnector())
    finally:
        for key, value in saved_creds.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    check("an app whose push failed is on its way too",
          push_app_row.status == "installing")
    check("...and reads the connector's answer the same way",
          "no push certificate" in (push_app_row.last_error or "")
          and "next check-in" in (push_app_row.last_error or ""))

    print("\n== 25. A device waiting out its sync backoff is not an error ==")
    # Two falsy answers mean opposite things; tell apart by type.
    from controller.services import ddm_manager as held_ddm

    held_tenant = await Tenant.create(id="ddmheld", name="DDM Held",
                                      ddm_enabled=True)
    write_configs(base, "ddmheld")
    held_dir = base / "tenants" / "ddmheld"
    # No profiles and no apps, so every cycle here reports the same thing and the summaries below can be compared to
    # each other rather than read.
    (held_dir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": []}))
    (held_dir / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
    (held_dir / "declarations.yaml").write_text(
        yaml.safe_dump({"declarations": []}))
    tenant_config.invalidate("ddmheld")
    held_dev = await Device.create(
        tenant=held_tenant, udid="UDID-DDMHELD", serial_number="SN-DDMHELD",
        device_model="MacBookPro18,3", os_version="15.5", hostname="sn-ddmheld",
        enrollment_state="enrolled", groups=[], tags=[])

    held_real_sync = held_ddm.sync_device
    held_tracebacks = []

    class _HeldTracebackSpy(_logging.Handler):
        def emit(self, record):
            if record.exc_info:
                held_tracebacks.append(record.getMessage())

    async def held_cycle(answer):
        async def fake_sync(device, **kw):
            return answer

        spy = _HeldTracebackSpy()
        held_ddm.sync_device = fake_sync
        reconciler.logger.addHandler(spy)
        try:
            return await reconciler.reconcile_tenant(held_tenant, base)
        finally:
            held_ddm.sync_device = held_real_sync
            reconciler.logger.removeHandler(spy)

    hold = held_ddm.SyncHeldOff("waiting out the backoff from a refused enqueue",
                                retry_at=datetime.now(timezone.utc) + timedelta(hours=1))
    check("a hold is falsy, so a caller asking only what went out reads it as "
          "nothing", not hold)
    check("...and is not a refusal, which is what keeps it out of the error count",
          not isinstance(hold, held_ddm.EnqueueFailed))

    quiet = await held_cycle(False)
    held_tracebacks.clear()
    held = await held_cycle(hold)
    check(f"a held-off device counts no error ({held})", held["errors"] == 0)
    check("...and no queued sync, because nothing was sent",
          held["ddm_syncs_queued"] == 0)
    check("...and leaves no traceback, since nothing raised", not held_tracebacks)
    check("...and files no task of its own",
          await Task.filter(tenant=held_tenant, type="ddm_sync").count() == 0)
    check(f"a cycle full of held devices reads exactly like a quiet one "
          f"({held} vs {quiet})", held == quiet)

    # The contrast, in the same fixture, so "count nothing at all" cannot pass these checks: the refusal that starts the
    # backoff is still an error.
    refused_cycle = await held_cycle(held_ddm.EnqueueFailed("NanoMDM said no"))
    check(f"the refusal that starts the backoff is still counted "
          f"({refused_cycle})", refused_cycle["errors"] == 1)

    print("\n== 26. A profile a compliance rule installed is not taken back off ==")
    # Rule can install out-of-scope profile; row marked and held.
    from controller.services.profile_manager import (
        INSTALL_SOURCE_KEY, remediation_rule_id, remediation_source,
    )

    check("the mark round-trips through one spelling",
          remediation_rule_id(remediation_source("filevault-required"))
          == "filevault-required")
    check("anything that is not a remediation mark reads as ordinary",
          remediation_rule_id(None) is None
          and remediation_rule_id("scope") is None
          and remediation_rule_id(remediation_source("")) is None)

    rem_tenant = await Tenant.create(id="remediation", name="remediation")
    write_configs(base, "remediation")
    rem_dir = base / "tenants" / "remediation"
    (rem_dir / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
    # A profile no device is scoped into, which is the only kind a rule ever has cause to install, alongside the
    # ordinary scoped one write_configs makes.
    rem_profiles = tenant_config.load_profiles("remediation") + [
        {"id": "fv-enforce", "name": "Enforce FileVault",
         "groups": ["nobody-is-in-this-group"],
         "payload": {"PayloadType": "com.apple.MCX.FileVault2", "Enable": "On"}},
    ]
    (rem_dir / "profiles.yaml").write_text(
        yaml.safe_dump({"profiles": rem_profiles}))

    def rem_rules(present):
        (rem_dir / "dispatcher.yaml").write_text(yaml.safe_dump(
            {"rules": [{"id": "filevault-required", "name": "FileVault required"}]}
            if present else {"rules": []}))
        tenant_config.invalidate("remediation")

    rem_rules(present=True)
    rem_dev = await Device.create(
        tenant=rem_tenant, udid="UDID-REMEDIATION", serial_number="SN-REMEDIATION",
        device_model="MacBookPro18,3", os_version="15.5", hostname="remediation",
        enrollment_state="enrolled", groups=[], tags=[])

    # The rule's install, through the path a rule actually uses: a task carrying the mark in its details, and the
    # handler that reads it back out.
    rem_info = [p for p in rem_profiles if p["id"] == "fv-enforce"][0]
    rem_details = ProfileManager.install_task_details(
        rem_info, ProfileManager.desired_hash(rem_info),
        source=remediation_source("filevault-required"))
    check("the mark is in the details a rule's task is created with",
          rem_details[INSTALL_SOURCE_KEY] == "remediation:filevault-required")
    rem_task = await Task.create(
        tenant=rem_tenant, type="profile_install", status="pending", device=rem_dev,
        user="dispatcher:filevault-required",
        description="Dispatcher remediation: install profile Enforce FileVault",
        details=rem_details)

    rem_pushed = []

    class _RemConnector:
        async def install_profile(self, udid, payload):
            rem_pushed.append(payload)
            return {"command_uuid": f"cmd-rem-{len(rem_pushed)}"}

    rem_real_connector = task_handlers.shared_connector
    task_handlers.shared_connector = lambda: _RemConnector()
    try:
        await task_handlers.handle_profile_install_task(
            rem_task, device=rem_dev, tenant=rem_tenant, profile_info=rem_info)
    finally:
        task_handlers.shared_connector = rem_real_connector

    rem_row = await ProfileDeployment.get(tenant=rem_tenant, profile_id="fv-enforce")
    check("the install reaches the device", len(rem_pushed) == 1)
    check("...and the row records which rule asked for it",
          rem_row.install_source == "remediation:filevault-required")

    # The other way a rule meets a row: one that already exists with no mark, which is what a second remediation attempt
    # finds after a failed first. The mark has to reach it too, or the hold only covers rows nothing had tried before.
    rem_dev2 = await Device.create(
        tenant=rem_tenant, udid="UDID-REMEDIATION-2", serial_number="SN-REMEDIATION-2",
        device_model="MacBookPro18,3", os_version="15.5", hostname="remediation-2",
        enrollment_state="enrolled", groups=[], tags=[])
    rem_existing = await ProfileDeployment.create(
        tenant=rem_tenant, device=rem_dev2, profile_id="fv-enforce",
        status="failed", last_error="the first attempt was refused")
    check("fixture: that row starts with no mark on it",
          rem_existing.install_source is None)
    rem_task2 = await Task.create(
        tenant=rem_tenant, type="profile_install", status="pending", device=rem_dev2,
        user="dispatcher:filevault-required",
        description="Dispatcher remediation: install profile Enforce FileVault",
        details=rem_details)
    task_handlers.shared_connector = lambda: _RemConnector()
    try:
        await task_handlers.handle_profile_install_task(
            rem_task2, device=rem_dev2, tenant=rem_tenant, profile_info=rem_info)
    finally:
        task_handlers.shared_connector = rem_real_connector
    check("a row that already existed is marked by the rule's install",
          (await ProfileDeployment.get(id=rem_existing.id)).install_source
          == "remediation:filevault-required")
    # The device answers, so the row is installed rather than pending, which is the state the removal pass acts on.
    await ProfileDeployment.filter(id=rem_row.id).update(
        status="installed", install_date=datetime.now(timezone.utc))

    spawned.clear()
    reconciler._spawn = capture_spawn
    try:
        held_cycle_1 = await reconciler.reconcile_tenant(rem_tenant, base)
        check(f"the next cycle does not take it back off ({held_cycle_1})",
              held_cycle_1["removals_queued"] == 0)
        check("...and the row is still there, still installed",
              (await ProfileDeployment.get(id=rem_row.id)).status == "installed")
        check("...and no RemoveProfile was queued for it",
              await Task.filter(tenant=rem_tenant, type="profile_remove").count() == 0)

        # A held profile is not the same as one that was re-pushed; it is simply outside the desired set.
        for _ in range(3):
            await reconciler.reconcile_tenant(rem_tenant, base)
        check("three more cycles queue nothing for it, in either direction",
              await Task.filter(device=rem_dev, type="profile_install",
                                dedup_key="fv-enforce").count() == 1
              and await Task.filter(tenant=rem_tenant, type="profile_remove").count() == 0)

        # A profile the scope stopped asking for still goes, so the hold is a hold and not the removal pass switched
        # off.
        stray = await ProfileDeployment.create(
            tenant=rem_tenant, device=rem_dev, profile_id="wifi-old",
            status="installed", payload_hash="whatever")
        unscoped_cycle = await reconciler.reconcile_tenant(rem_tenant, base)
        check(f"an ordinary unscoped profile is still removed ({unscoped_cycle})",
              unscoped_cycle["removals_queued"] == 1)
        check("...and it is the unmarked one",
              await Task.filter(tenant=rem_tenant, type="profile_remove").count() == 1
              and (await ProfileDeployment.get(id=rem_row.id)).status == "installed")
        await ProfileDeployment.filter(id=stray.id).delete()
        await Task.filter(tenant=rem_tenant, type="profile_remove").delete()

        # And deleting the rule releases the hold, which is the one signal that says the policy itself is gone.
        rem_rules(present=False)
        released = await reconciler.reconcile_tenant(rem_tenant, base)
        check(f"deleting the rule releases the hold, on every device it held "
              f"({released})", released["removals_queued"] == 2)
        check("...and the profile is taken off them properly, with a task each",
              await Task.filter(tenant=rem_tenant, type="profile_remove").count() == 2)

        # A parse failure does not mean the rules were deleted, so installed profiles must not be stripped.
        await Task.filter(tenant=rem_tenant, type="profile_remove").delete()
        await ProfileDeployment.filter(
            tenant=rem_tenant, profile_id="fv-enforce").update(
            status="installed", install_date=datetime.now(timezone.utc),
            install_source=remediation_source("filevault-required"))
        (rem_dir / "dispatcher.yaml").write_text("rules: [ this is not\n  valid: yaml")
        tenant_config.invalidate("remediation")
        check("an unparseable document answers unknown, not 'no rules exist'",
              reconciler._remediation_rule_ids(rem_dir) is None)
        unreadable = await reconciler.reconcile_tenant(rem_tenant, base)
        check(f"...so the hold stands and nothing comes off ({unreadable})",
              unreadable["removals_queued"] == 0)
        check("...and the rows are all still there",
              await ProfileDeployment.filter(
                  tenant=rem_tenant, profile_id="fv-enforce").count() == 2)

        rem_capture = _CaptureLog()
        reconciler.logger.addHandler(rem_capture)
        try:
            await reconciler.reconcile_tenant(rem_tenant, base)
        finally:
            reconciler.logger.removeHandler(rem_capture)
        rules_warnings = [m for m in rem_capture.messages if "carries no rules" in m]
        check(f"...and it is said once for the tenant, not once per device "
              f"(got {len(rules_warnings)} for 2 devices)", len(rules_warnings) == 1)

        # A document that parses and carries an empty rules list IS evidence, so emptying the rules through the product
        # still releases.
        (rem_dir / "dispatcher.yaml").write_text(yaml.safe_dump({"rules": []}))
        tenant_config.invalidate("remediation")
        check("an authored empty rules list is a rules list",
              reconciler._remediation_rule_ids(rem_dir) == set())
        emptied = await reconciler.reconcile_tenant(rem_tenant, base)
        check(f"...and releases the hold ({emptied})", emptied["removals_queued"] == 2)
    finally:
        reconciler._spawn = real_spawn

    print("\n== 27. An app a compliance rule installed is not retired either ==")
    # Rule-installed app not in desired set; unmarked row retired.
    ra_tenant = await Tenant.create(id="remapps", name="remapps")
    write_configs(base, "remapps")
    ra_dir = base / "tenants" / "remapps"
    (ra_dir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": []}))
    # An app no device is scoped into, beside the ordinary scoped one.
    (ra_dir / "apps.yaml").write_text(yaml.safe_dump({"apps": [
        {"id": "slack", "name": "Slack", "bundle_id": "com.tinyspeck.slackmacgap",
         "versions": [{"version": "1.0", "s3_key": "apps/slack-1.0.pkg",
                       "sha256": "a" * 64, "groups": ["all-macs"]}]},
        {"id": "endpoint-agent", "name": "Endpoint Agent",
         "bundle_id": "com.example.agent",
         "versions": [{"version": "3.0", "s3_key": "apps/agent-3.0.pkg",
                       "groups": ["nobody-is-in-this-group"]}]},
    ]}))
    (ra_dir / "dispatcher.yaml").write_text(yaml.safe_dump(
        {"rules": [{"id": "agent-required", "name": "Endpoint agent required"}]}))
    tenant_config.invalidate("remapps")
    ra_dev = await Device.create(
        tenant=ra_tenant, udid="UDID-REMAPPS", serial_number="SN-REMAPPS",
        device_model="MacBookPro18,3", os_version="15.5", hostname="remapps",
        enrollment_state="enrolled", groups=[], tags=[])

    ra_info = {"app_id": "endpoint-agent", "name": "Endpoint Agent", "version": "3.0",
               "bundle_id": "com.example.agent", "s3_key": "apps/agent-3.0.pkg"}
    ra_task = await Task.create(
        tenant=ra_tenant, type="app_install", status="pending", device=ra_dev,
        user="dispatcher:agent-required",
        description="Dispatcher remediation: install Endpoint Agent",
        details={"app_info": ra_info,
                 INSTALL_SOURCE_KEY: remediation_source("agent-required")})

    class _RaConnector:
        async def install_app(self, udid, manifest_url, management_flags=1,
                              install_as_managed=True):
            return {"command_uuid": "cmd-remapp-1"}

    ra_creds = {k: os.environ.get(k) for k in
                ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")}
    os.environ["AWS_ACCESS_KEY_ID"] = "AKIA-VERIFY"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "verify-secret"
    ra_real_connector = task_handlers.shared_connector
    task_handlers.shared_connector = lambda: _RaConnector()
    try:
        await task_handlers.handle_app_install_task(
            ra_task, device=ra_dev, tenant=ra_tenant)
    finally:
        task_handlers.shared_connector = ra_real_connector
        for key, value in ra_creds.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    ra_row = await AppDeployment.get(tenant=ra_tenant, app_id="endpoint-agent")
    check("the app row records which rule asked for it",
          ra_row.install_source == "remediation:agent-required")

    # Unmarked existing row found on second attempt.
    ra_dev2 = await Device.create(
        tenant=ra_tenant, udid="UDID-REMAPPS-2", serial_number="SN-REMAPPS-2",
        device_model="MacBookPro18,3", os_version="15.5", hostname="remapps-2",
        enrollment_state="enrolled", groups=[], tags=[])
    ra_existing = await AppDeployment.create(
        tenant=ra_tenant, device=ra_dev2, app_id="endpoint-agent",
        app_version="3.0", status="failed", last_error="the first attempt failed")
    check("fixture: that row starts with no mark on it",
          ra_existing.install_source is None)
    await AppManager(ra_tenant).ensure_deployment(
        ra_dev2, ra_info, None, source=remediation_source("agent-required"))
    check("an app row that already existed is marked by the rule's install",
          (await AppDeployment.get(id=ra_existing.id)).install_source
          == "remediation:agent-required")
    await AppDeployment.filter(id=ra_existing.id).delete()
    await Device.filter(id=ra_dev2.id).delete()
    await AppDeployment.filter(id=ra_row.id).update(
        status="installed", install_date=datetime.now(timezone.utc))

    spawned.clear()
    reconciler._spawn = capture_spawn
    try:
        ra_held = await reconciler.reconcile_tenant(ra_tenant, base)
        check(f"the next cycle does not retire it ({ra_held})",
              ra_held["apps_unscoped"] == 0)
        check("...and the row still reads as installed",
              (await AppDeployment.get(id=ra_row.id)).status == "installed")

        # An ordinary app that left scope is still retired in the same cycle.
        ra_stray = await AppDeployment.create(
            tenant=ra_tenant, device=ra_dev, app_id="retired-app",
            app_version="1.0", status="installed",
            install_date=datetime.now(timezone.utc))
        ra_mixed = await reconciler.reconcile_tenant(ra_tenant, base)
        check(f"an ordinary unscoped app is still retired ({ra_mixed})",
              ra_mixed["apps_unscoped"] == 1)
        check("...and it is the unmarked one",
              (await AppDeployment.get(id=ra_stray.id)).status == "unscoped"
              and (await AppDeployment.get(id=ra_row.id)).status == "installed")

        (ra_dir / "dispatcher.yaml").write_text(yaml.safe_dump({"rules": []}))
        tenant_config.invalidate("remapps")
        ra_released = await reconciler.reconcile_tenant(ra_tenant, base)
        check(f"deleting the rule releases the app too ({ra_released})",
              ra_released["apps_unscoped"] == 1)
        check("...and the row stops claiming a managed state",
              (await AppDeployment.get(id=ra_row.id)).status == "unscoped")
    finally:
        reconciler._spawn = real_spawn

    print("\n== 28. The console can say who asked for a deployment ==")

    # A device holding a profile or an app that no group explains is a support call unless the row says where it came
    # from.
    async def principal_for(a_tenant):
        """get_device_details answers about the caller's own tenant only."""
        user = await User.create(tenant=a_tenant, email=f"admin@{a_tenant.id}",
                                 role="admin")
        return Principal(tenant=a_tenant, user=user,
                         email=f"admin@{a_tenant.id}", role="admin")

    detail = await get_device_details(str(rem_dev.id), await principal_for(rem_tenant))
    rem_profile_payload = next(
        p for p in detail["installed_profiles"] if p["profile_id"] == "fv-enforce")
    check("a profile row carries its install source to the API",
          rem_profile_payload["install_source"] == "remediation:filevault-required")
    ra_detail = await get_device_details(str(ra_dev.id), await principal_for(ra_tenant))
    ra_payload = next(
        a for a in ra_detail["installed_apps"] if a["app_id"] == "endpoint-agent")
    check("an app row carries it too",
          ra_payload["install_source"] == "remediation:agent-required")
    ordinary = next(
        a for a in ra_detail["installed_apps"] if a["app_id"] == "retired-app")
    check("...and an ordinary deployment says so by carrying nothing",
          ordinary["install_source"] is None)

    print("\n== 29. An app the device took but never showed is not installed ==")

    # macOS acknowledgement can't tell installed from refused.
    def accepted_row(minutes_ago, version="1.0"):
        return SimpleNamespace(
            status=reconciler.APP_ACCEPTED_STATUS, app_version=version,
            failed_attempts=0,
            updated_at=now - timedelta(minutes=minutes_ago))

    check("an accepted row is in progress, so nothing is re-pushed",
          reconciler._app_needs_deploy(accepted_row(5), "1.0", now) is None)
    check("...and a version that moved underneath it also does not re-push.",
          reconciler._app_needs_deploy(accepted_row(5, version="0.9"), "1.0", now)
          is None
          and reconciler._app_needs_deploy(
              SimpleNamespace(status="installing", app_version="0.9",
                              failed_attempts=0,
                              updated_at=now - timedelta(minutes=5)),
              "1.0", now) is None)
    check("...and the wait is its own, not the command retry window",
          reconciler._app_needs_deploy(
              accepted_row(reconciler.RETRY_MINUTES + 1), "1.0", now) is None)

    acc_tenant = await Tenant.create(id="accepted", name="accepted")
    write_configs(base, "accepted")
    (base / "tenants" / "accepted" / "profiles.yaml").write_text(
        yaml.safe_dump({"profiles": []}))
    tenant_config.invalidate("accepted")
    acc_dev = await Device.create(
        tenant=acc_tenant, udid="UDID-ACCEPTED", serial_number="SN-ACCEPTED",
        device_model="MacBookPro18,3", os_version="15.5", hostname="accepted",
        enrollment_state="enrolled", groups=[], tags=[])
    acc_row = await AppDeployment.create(
        tenant=acc_tenant, device=acc_dev, app_id="slack", app_version="1.0",
        status=reconciler.APP_ACCEPTED_STATUS,
        install_date=datetime.now(timezone.utc))

    spawned.clear()
    reconciler._spawn = capture_spawn
    try:
        fresh = await reconciler.reconcile_tenant(acc_tenant, base)
        check(f"a fresh acceptance is left alone ({fresh})",
              fresh["apps_unconfirmed"] == 0 and fresh["apps_queued"] == 0)
        check("...and the row still says accepted",
              (await AppDeployment.get(id=acc_row.id)).status
              == reconciler.APP_ACCEPTED_STATUS)

        await AppDeployment.filter(id=acc_row.id).update(
            updated_at=datetime.now(timezone.utc)
                       - timedelta(minutes=reconciler.APP_CONFIRM_MINUTES + 1))
        expired = await reconciler.reconcile_tenant(acc_tenant, base)
        acc_row = await AppDeployment.get(id=acc_row.id)
        check(f"an acceptance nothing confirmed is failed and counted ({expired})",
              expired["apps_unconfirmed"] == 1)
        check("...and the row says exactly what happened",
              acc_row.status == "failed"
              and acc_row.last_error == reconciler.APP_UNCONFIRMED_ERROR)
        check("...and it joins the ordinary ladder rather than retrying at once, "
              "since the failure is as of now",
              expired["apps_queued"] == 0
              and (await AppDeployment.get(id=acc_row.id)).failed_attempts == 0)

        # And the ladder really is the ordinary one: the first interval earns a retry, and the row is not swept a second
        # time for a status it left.
        await AppDeployment.filter(id=acc_row.id).update(
            updated_at=datetime.now(timezone.utc)
                       - timedelta(minutes=reconciler.RETRY_MINUTES + 1))
        again = await reconciler.reconcile_tenant(acc_tenant, base)
        check(f"the first interval then earns a retry ({again})",
              again["apps_queued"] == 1 and again["apps_unconfirmed"] == 0)
        check("...counted, so the next wait doubles",
              (await AppDeployment.get(id=acc_row.id)).failed_attempts == 1)

        # Ladder climbs across rounds: accepted, failed, re-pushed, accepted.
        await Task.filter(tenant=acc_tenant, type="app_install").delete()
        await AppDeployment.filter(id=acc_row.id).update(
            status=reconciler.APP_ACCEPTED_STATUS, failed_attempts=0,
            last_error=None, updated_at=datetime.now(timezone.utc))

        async def unconfirmed_round(expected_rung):
            """One acceptance nobody confirms, from timeout to the next push."""
            # Nothing happens while the confirmation window is open.
            waiting = await reconciler.reconcile_tenant(acc_tenant, base)
            fresh_row = await AppDeployment.get(id=acc_row.id)
            # The window passes with no inventory naming the app.
            await AppDeployment.filter(id=acc_row.id).update(
                updated_at=datetime.now(timezone.utc)
                           - timedelta(minutes=reconciler.APP_CONFIRM_MINUTES + 1))
            swept = await reconciler.reconcile_tenant(acc_tenant, base)
            # The row now waits out its own rung; one minute short of it is still silence, and a minute past it is the
            # re-push.
            rung = reconciler._retry_delay_minutes(
                (await AppDeployment.get(id=acc_row.id)).failed_attempts)
            await AppDeployment.filter(id=acc_row.id).update(
                updated_at=datetime.now(timezone.utc)
                           - timedelta(minutes=rung - 1))
            early = await reconciler.reconcile_tenant(acc_tenant, base)
            await AppDeployment.filter(id=acc_row.id).update(
                updated_at=datetime.now(timezone.utc)
                           - timedelta(minutes=rung + 1))
            pushed = await reconciler.reconcile_tenant(acc_tenant, base)
            # The device takes the command again, which is all an ack means.
            await Task.filter(tenant=acc_tenant, type="app_install").delete()
            await AppDeployment.filter(id=acc_row.id).update(
                status=reconciler.APP_ACCEPTED_STATUS,
                updated_at=datetime.now(timezone.utc))
            counted = (await AppDeployment.get(id=acc_row.id)).failed_attempts
            return {"rung": rung, "waiting": waiting, "swept": swept,
                    "early": early, "pushed": pushed, "counted": counted,
                    "was_accepted": fresh_row.status}

        rounds = [await unconfirmed_round(n) for n in (1, 2, 3)]
        check(f"each unconfirmed round waits a longer rung than the last "
              f"({[r['rung'] for r in rounds]})",
              [r["rung"] for r in rounds]
              == [reconciler.RETRY_MINUTES,
                  reconciler.RETRY_MINUTES * 2,
                  reconciler.RETRY_MINUTES * 4])
        check("...and three rounds leave the row on the third rung",
              rounds[-1]["counted"] == 3)
        check("every round re-pushes exactly once, when its rung is up",
              all(r["pushed"]["apps_queued"] == 1 for r in rounds)
              and all(r["early"]["apps_queued"] == 0 for r in rounds))
        check("...and nothing is queued while the device is still inside the "
              "confirmation window",
              all(r["waiting"]["apps_queued"] == 0
                  and r["waiting"]["apps_unconfirmed"] == 0 for r in rounds))
        check("...and each round fails the acceptance exactly once",
              all(r["swept"]["apps_unconfirmed"] == 1 for r in rounds))
        # The counter has one writer. The sweep failing the row must not also charge it a rung, or an unconfirmed app
        # climbs twice as fast as a profile that fails the same number of times.
        check("the sweep itself counts nothing, so a round costs one rung",
              [r["counted"] for r in rounds] == [1, 2, 3])

        # Counter must not clear on ack, must clear on confirmation.
        ladder_task = await Task.create(
            tenant=acc_tenant, type="app_install", status="running", device=acc_dev,
            user="system", description="Install Slack v1.0",
            details={"command_uuid": "cmd-acc-ladder", "app_info": app_info})
        await AppDeployment.filter(id=acc_row.id).update(
            status="installing", failed_attempts=3, last_task_id=ladder_task.id,
            app_version="1.0")
        await handler._dispatch_command_response(
            acc_dev, "cmd-acc-ladder", "Acknowledged", {})
        await webhook_handler.drain_deferred()
        acked = await AppDeployment.get(id=acc_row.id)
        check("an acknowledgement accepts the row and leaves the ladder where "
              "it was, since taking a command is not evidence of anything",
              acked.status == reconciler.APP_ACCEPTED_STATUS
              and acked.failed_attempts == 3)

        list_task = await Task.create(
            tenant=acc_tenant, type="app_list", status="running", device=acc_dev,
            user="system", description="List installed apps",
            details={"command_uuid": "cmd-acc-list"})
        await handler._dispatch_command_response(
            acc_dev, "cmd-acc-list", "Acknowledged",
            {"InstalledApplicationList": [
                {"Identifier": "com.tinyspeck.slackmacgap", "Name": "Slack",
                 "Version": "1.0", "ShortVersion": "1.0"}]})
        await webhook_handler.drain_deferred()
        confirmed = await AppDeployment.get(id=acc_row.id)
        check(f"a confirming inventory installs the row and starts the ladder "
              f"over ({confirmed.status}, {confirmed.failed_attempts})",
              confirmed.status == "installed" and confirmed.failed_attempts == 0)
        check("fixture: that task really was the one the row was tracking",
              str((await Task.get(id=list_task.id)).status) == "completed")

        # Retiring an accepted row keeps it, like an install still pending: the device took the command and may have
        # finished the job.
        await AppDeployment.filter(id=acc_row.id).update(
            status=reconciler.APP_ACCEPTED_STATUS,
            updated_at=datetime.now(timezone.utc))
        (base / "tenants" / "accepted" / "apps.yaml").write_text(
            yaml.safe_dump({"apps": [
                {"id": "other", "name": "Other", "bundle_id": "com.example.other",
                 "versions": [{"version": "1.0", "s3_key": "apps/other-1.0.pkg",
                               "groups": ["nobody"]}]}]}))
        tenant_config.invalidate("accepted")
        retired = await reconciler.reconcile_tenant(acc_tenant, base)
        acc_row = await AppDeployment.get(id=acc_row.id)
        check(f"an unscoped acceptance is retired, not deleted ({retired})",
              retired["apps_unscoped"] == 1
              and acc_row.status == reconciler.APP_UNSCOPED_STATUS)
    finally:
        reconciler._spawn = real_spawn

    print("\n== 30. A flow holds what it installed, like a rule does ==")
    from controller.services.profile_manager import flow_source, flow_source_id

    check("the two marks are told apart by their prefix",
          flow_source_id(flow_source("onboard")) == "onboard"
          and flow_source_id(remediation_source("r")) is None
          and remediation_rule_id(flow_source("onboard")) is None)

    fl_tenant = await Tenant.create(id="flowhold", name="flowhold")
    write_configs(base, "flowhold")
    fl_dir = base / "tenants" / "flowhold"
    (fl_dir / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
    fl_profiles = tenant_config.load_profiles("flowhold") + [
        {"id": "lab-flow", "name": "Lab flow profile",
         "groups": ["nobody-is-in-this-group"],
         "payload": {"PayloadType": "com.example.flow"}},
    ]
    (fl_dir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": fl_profiles}))

    def fl_flows(document):
        (fl_dir / "flows.yaml").write_text(document if isinstance(document, str)
                                           else yaml.safe_dump(document))
        tenant_config.invalidate("flowhold")

    fl_flows({"flow": {"id": "onboard", "name": "Onboarding", "nodes": []}})
    fl_dev = await Device.create(
        tenant=fl_tenant, udid="UDID-FLOWHOLD", serial_number="SN-FLOWHOLD",
        device_model="MacBookPro18,3", os_version="15.5", hostname="flowhold",
        enrollment_state="enrolled", groups=[], tags=[])
    fl_row = await ProfileDeployment.create(
        tenant=fl_tenant, device=fl_dev, profile_id="lab-flow", status="installed",
        payload_hash="whatever", install_source=flow_source("onboard"))

    check("the reader finds the flow the document defines",
          reconciler._flow_ids(fl_dir) == {"onboard"})
    check("an unnamed flow is the id the engine gives it",
          reconciler._flow_ids(fl_dir) is not None)

    spawned.clear()
    reconciler._spawn = capture_spawn
    try:
        fl_held = await reconciler.reconcile_tenant(fl_tenant, base)
        check(f"a flow-installed profile is not removed ({fl_held})",
              fl_held["removals_queued"] == 0)
        check("...and the row is still there",
              await ProfileDeployment.filter(id=fl_row.id).count() == 1)

        # An unreadable flows.yaml is not evidence the flow is gone.
        fl_flows("flow: [ this is not\n  valid: yaml")
        check("an unparseable flows.yaml says nothing rather than nothing exists",
              reconciler._flow_ids(fl_dir) is None)
        unreadable = await reconciler.reconcile_tenant(fl_tenant, base)
        check(f"...so the hold stands ({unreadable})",
              unreadable["removals_queued"] == 0
              and await ProfileDeployment.filter(id=fl_row.id).count() == 1)

        # A different flow is not this flow.
        fl_flows({"flow": {"id": "offboard", "name": "Offboarding", "nodes": []}})
        replaced = await reconciler.reconcile_tenant(fl_tenant, base)
        check(f"a document that defines another flow releases this one "
              f"({replaced})", replaced["removals_queued"] == 1)
        check("...with a proper removal task",
              await Task.filter(tenant=fl_tenant, type="profile_remove").count() == 1)
    finally:
        reconciler._spawn = real_spawn

    print("\n== 31. A package that installs no app bundle can say so ==")
    # A managed install requires the package to install an application bundle. The device examines and refuses anything
    # else with nothing reported back, so an app entry can turn the key off.
    from controller.services.app_manager import AppManager as _AM

    ias_tenant = await Tenant.create(id="managedflag", name="managedflag")
    ias_mac = await Device.create(
        tenant=ias_tenant, udid="UDID-IAS-MAC", serial_number="SN-IAS-MAC",
        device_model="MacBookPro18,3", os_version="15.5", hostname="ias-mac",
        enrollment_state="enrolled", groups=[], tags=[])
    ias_ipad = await Device.create(
        tenant=ias_tenant, udid="UDID-IAS-IPAD", serial_number="SN-IAS-IPAD",
        device_model="iPad13,1", os_version="17.5", hostname="ias-ipad",
        enrollment_state="enrolled", groups=[], tags=[])

    ias_groups = [{"name": "everyone", "conditions": [
        {"type": "platform", "operator": "in", "value": ["Mac", "iPad"]}]}]
    ias_apps = [
        {"id": "bundled", "name": "Bundled", "bundle_id": "com.example.bundled",
         "versions": [{"version": "1.0", "s3_key": "apps/b.pkg",
                       "groups": ["everyone"]}]},
        {"id": "driverpkg", "name": "Driver", "bundle_id": "com.example.driver",
         "install_as_managed": False,
         "versions": [{"version": "1.0", "s3_key": "apps/d.pkg",
                       "groups": ["everyone"]}]},
    ]
    evaluated = {a["app_id"]: a
                 for a in await _AM(ias_tenant).evaluate_device_apps(
            ias_mac, ias_apps, ias_groups)}
    check("fixture: both apps are scoped to the Mac",
          set(evaluated) == {"bundled", "driverpkg"})
    check("an app that says nothing carries nothing",
          "install_as_managed" not in evaluated["bundled"])
    check("...and one that says so carries it",
          evaluated["driverpkg"]["install_as_managed"] is False)

    ias_sent = []

    class _IasConnector:
        async def install_app(self, udid, manifest_url, management_flags=1,
                              install_as_managed=True):
            ias_sent.append((udid, install_as_managed))
            return {"command_uuid": f"cmd-ias-{len(ias_sent)}"}

    ias_creds = {k: os.environ.get(k) for k in
                 ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")}
    os.environ["AWS_ACCESS_KEY_ID"] = "AKIA-VERIFY"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "verify-secret"
    try:
        await _AM(ias_tenant).deploy_app(ias_mac, evaluated["bundled"],
                                         _IasConnector())
        await _AM(ias_tenant).deploy_app(ias_mac, evaluated["driverpkg"],
                                         _IasConnector())
        await _AM(ias_tenant).deploy_app(ias_ipad, evaluated["bundled"],
                                         _IasConnector())
    finally:
        for key, value in ias_creds.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    check("a Mac install is managed by default, as every apps.yaml so far means",
          ias_sent[0] == (ias_mac.udid, True))
    check("...and unmanaged when the app says so, which is what lets a driver "
          "or a script-only package install at all",
          ias_sent[1] == (ias_mac.udid, False))
    check("...while an iPad never carries the macOS-only key either way",
          ias_sent[2] == (ias_ipad.udid, False))

    print("\n== 32. A data key inside a container still reaches the device as <data> ==")
    # Nested manifest fields; walk must copy, not mutate.
    import base64 as _b64
    import copy as _copy

    dk_tenant = await Tenant.create(id="datakeys", name="datakeys")
    dk_pm = ProfileManager(dk_tenant)
    fingerprint = bytes.fromhex("0a1b2c3d4e5f60718293a4b5c6d7e8f9")
    cert_body = b"-----BEGIN CERTIFICATE-----\nnot a real one\n"

    scep_info = {
        "id": "scep", "name": "Corp SCEP", "payloads": [{
            "PayloadType": "com.apple.security.scep",
            "PayloadContent": {
                "URL": "https://ca.example.com/scep",
                "Name": "corp-ca",
                "Keysize": 2048,
                "Challenge": "s3cret",
                "CAFingerprint": _b64.b64encode(fingerprint).decode(),
            },
        }],
    }
    scep_authored = _copy.deepcopy(scep_info)
    scep_hash_before = ProfileManager.desired_hash(scep_info)
    scep_built = dk_pm._build_profile_payload(scep_info)["PayloadContent"][0]
    check("a CAFingerprint authored inside PayloadContent is decoded to bytes",
          scep_built["PayloadContent"]["CAFingerprint"] == fingerprint)
    check("...so the plist carries <data> where the device demands it",
          b"<data>" in plistlib.dumps(scep_built))
    check("...and the rest of the container is copied through as authored",
          scep_built["PayloadContent"]["URL"] == "https://ca.example.com/scep"
          and scep_built["PayloadContent"]["Keysize"] == 2048
          and scep_built["PayloadContent"]["Challenge"] == "s3cret")

    top_info = {
        "id": "root", "name": "Corp Root", "payloads": [{
            "PayloadType": "com.apple.security.root",
            "PayloadContent": _b64.b64encode(cert_body).decode(),
        }],
    }
    top_built = dk_pm._build_profile_payload(top_info)["PayloadContent"][0]
    check("a top-level data key decodes the way it always did",
          top_built["PayloadContent"] == cert_body)

    junk_info = {
        "id": "junk", "name": "Junk", "payloads": [{
            "PayloadType": "com.apple.security.scep",
            "PayloadContent": {"CAFingerprint": "not base64 at all!"},
        }, {
            "PayloadType": "com.apple.security.root",
            "PayloadContent": "also not base64!",
        }],
    }
    junk_built = dk_pm._build_profile_payload(junk_info)["PayloadContent"]
    check("a nested value that is not base64 is left for the device to reject",
          junk_built[0]["PayloadContent"]["CAFingerprint"] == "not base64 at all!")
    check("...and so is a top-level one",
          junk_built[1]["PayloadContent"] == "also not base64!")

    # The hash guard. deploy_profile builds first and hashes after, so a build that reached into the caller's nested
    # dicts would stamp every row with a hash the next cycle cannot match.
    check("building leaves the caller's definition exactly as authored",
          scep_info == scep_authored)
    check("...so the hash taken after the build is the hash taken before it",
          ProfileManager.desired_hash(scep_info) == scep_hash_before)

    dk_dev = await Device.create(
        tenant=dk_tenant, udid="UDID-DATAKEYS", serial_number="SN-DATAKEYS",
        device_model="MacBookPro18,3", os_version="15.5", hostname="datakeys",
        enrollment_state="enrolled", groups=[], tags=[])

    class _DkConnector:
        async def install_profile(self, udid, payload):
            return {"command_uuid": "cmd-datakeys-1"}

    dk_row = await dk_pm.deploy_profile(dk_dev, scep_info, _DkConnector())
    check("a deployed row records the hash of the YAML definition, not of bytes",
          dk_row.payload_hash == ProfileManager.desired_hash(scep_authored))

    print("\n== 32a. A profile's data_keys declaration reaches the device as <data> ==")
    # Only declared data_keys decode; others stay as authored text.
    blob = bytes(range(32))
    vendor_payload = {
        "PayloadType": "com.acme.sensor",
        "DeviceCert": _b64.b64encode(blob).decode(),
        "CustomerID": "Q3VzdG9tZXItMDA3",  # decodes cleanly, still a string
        "Settings": {"SigningKey": _b64.b64encode(b"key material").decode()},
    }
    decl_info = {
        "id": "vendor", "name": "Vendor",
        "data_keys": ["DeviceCert", "SigningKey"],
        "payloads": [_copy.deepcopy(vendor_payload)],
    }
    decl_authored = _copy.deepcopy(decl_info)
    decl_hash_before = ProfileManager.desired_hash(decl_info)
    decl_built = dk_pm._build_profile_payload(decl_info)["PayloadContent"][0]
    check("a declared top-level key decodes to bytes",
          decl_built["DeviceCert"] == blob)
    check("...and a declared key inside a container does too",
          decl_built["Settings"]["SigningKey"] == b"key material")
    check("...so the plist carries <data> for a payload no manifest describes",
          plistlib.dumps(decl_built).count(b"<data>") == 2)
    check("an undeclared base64-shaped sibling stays the string it was authored as",
          decl_built["CustomerID"] == "Q3VzdG9tZXItMDA3")
    check("building leaves the declaring profile's definition as authored",
          decl_info == decl_authored)
    check("...and its desired hash where it was",
          ProfileManager.desired_hash(decl_info) == decl_hash_before)

    # No declaration, no decoding: an unknown payload type with no data_keys keeps its base64 values as strings.
    plain_info = {"id": "vendor-plain", "name": "Vendor",
                  "payloads": [_copy.deepcopy(vendor_payload)]}
    plain_built = dk_pm._build_profile_payload(plain_info)["PayloadContent"][0]
    for meta in ("PayloadUUID", "PayloadIdentifier", "PayloadVersion",
                 "PayloadDisplayName"):
        plain_built.pop(meta)
    check("a profile with no data_keys builds an identical plist",
          plistlib.dumps(plain_built) == plistlib.dumps(vendor_payload))

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run

run(main)
