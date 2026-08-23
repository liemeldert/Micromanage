"""Backend E2E for the Dispatcher compliance engine, on in-memory sqlite.

Covers grace-then-open, severity ranking, ack and resolve, auto-resolve with reversible-tag removal, single-alert dedup,
audited non-destructive remediation, dry-run recording without acting, destructive commands queued for approval, loop
protection and escalation, and an HMAC-signed webhook whose failure does not block evaluation. Also webhook secret
redaction, a remediation's profile payload reaching the tasks table redacted, and the cooldown, attempt and webhook
rates being read per call rather than bound at import.

Run:  PYTHONPATH=. ./.venv/bin/python tests/verify_dispatcher.py
"""

import asyncio
import copy
import hashlib
import hmac
import inspect
import json
import os
import tempfile
from pathlib import Path

# Tighten the remediation limits for the loop-protection checks, before any section runs. The dispatcher reads them per
# call, which section 22 pins.
os.environ["DISPATCHER_REMEDIATION_COOLDOWN_MINUTES"] = "0"
os.environ["DISPATCHER_REMEDIATION_MAX_ATTEMPTS"] = "2"
os.environ["DISPATCHER_AUTO_REMEDIATION_ENABLED"] = "true"

import yaml
from tortoise import Tortoise

_FAILURES = []
CAPTURED = []
WEBHOOK_CODE = [200]  # mutable: flip to 500 to simulate delivery failure

# The password on the profile a remediation installs. Distinctive, so a search of the stored task row cannot match by
# accident.
FV_PROFILE_PASSWORD = "fv-open-directory-pw-4d1f"


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        _FAILURES.append(name)


class FakeConnector:
    def __init__(self, *a, **k):
        pass

    async def install_profile(self, udid, payload):
        return {"command_uuid": "u-prof"}

    async def remove_profile(self, udid, ident):
        return {"command_uuid": "u-prof-rm"}

    async def get_device_info(self, udid):
        return {"command_uuid": "u-info"}

    async def erase_device(self, udid, pin=None, return_to_service=None):
        return {"command_uuid": "u-erase"}

    async def send_raw_command(self, udid, rt, fields):
        return {"command_uuid": "u-raw"}

    async def close(self):
        pass


class FakeResp:
    def __init__(self, code):
        self.status_code = code


class FakeAsyncClient:
    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, content=None, headers=None):
        CAPTURED.append({"url": url, "content": content, "headers": headers or {}})
        return FakeResp(WEBHOOK_CODE[0])


DISPATCHER_DOC = {
    "webhooks": [{"name": "slack", "url": "https://hooks.slack.com/secret", "secret": "topsecret"}],
    "rules": [
        {  # alert lifecycle + webhook + reversible tag + auto-resolve
            "id": "fv-alert", "name": "FileVault required", "enabled": True, "severity": "red",
            "scope": {"conditions": [{"type": "platform", "operator": "in", "value": ["Mac"]}]},
            "check": {"type": "filevault_disabled"}, "grace_minutes": 10,
            "actions": [
                {"type": "webhook", "params": {"target": "slack"}},
                {"type": "assign_tag", "params": {"tags": ["noncompliant-fv"]}},
            ],
            "auto_resolve": True,
        },
        {  # real remediation that never fixes compliance -> loop protection
            "id": "fv-remediate", "name": "FileVault remediation", "severity": "yellow",
            "check": {"type": "filevault_disabled"}, "grace_minutes": 0,
            "actions": [{"type": "install_profiles", "params": {"profile_ids": ["enforce-fv"]}}],
            "auto_resolve": False,
        },
        {  # dry-run remediation records without acting
            "id": "dry", "name": "Dry run", "severity": "green",
            "check": {"type": "filevault_disabled"}, "grace_minutes": 0,
            "actions": [{"type": "send_command", "params": {"command": "refresh_info"}, "dry_run": True}],
            "auto_resolve": False,
        },
        {  # destructive remediation -> queued for approval, never auto-fired
            "id": "risky-wipe", "name": "Wipe risky", "severity": "black",
            "check": {"type": "tagged", "tags": ["risky"]}, "grace_minutes": 0,
            # A Mac erase needs a 6-digit PIN (enforced in the shared command path so an approved wipe can't brick the
            # device); it is a secret param.
            "actions": [{"type": "send_command", "params": {
                "command": "erase", "params": {"pin": "123456"}}}],
            "auto_resolve": False,
        },
        {  # destructive remediation WITH a secret param -> must not leak it
            "id": "recovery", "name": "Set recovery lock", "severity": "black",
            "check": {"type": "tagged", "tags": ["risky"]}, "grace_minutes": 0,
            "actions": [{"type": "send_command", "params": {
                "command": "set_recovery_lock", "params": {"new_password": "supersecret"}}}],
            "auto_resolve": False,
        },
        {  # grace_minutes > 0 and no auto_resolve: a pending alert that self-heals within grace still resolves,
            # so a later violation cannot reuse its first_detected_at anchor.
            "id": "flaky-tag", "name": "Flaky tag grace", "severity": "yellow",
            "check": {"type": "tagged", "tags": ["flaky"]}, "grace_minutes": 30,
            "actions": [],
            "auto_resolve": False,
        },
    ],
}


def _write_configs(base: Path):
    tdir = base / "tenants" / "default"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "config.yaml").write_text(yaml.safe_dump({"tenant": {"id": "default", "name": "D", "allowed_users": []}}))
    (tdir / "groups.yaml").write_text(yaml.safe_dump({"groups": []}))
    (tdir / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
    # The payload carries a password on purpose: this is the profile a remediation queues, so it is what proves the
    # tasks table never holds the value.
    (tdir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": [
        {"id": "enforce-fv", "name": "Enforce FileVault",
         "payload": {"PayloadType": "com.apple.MCX.FileVault2",
                     "Username": "fvadmin", "Password": FV_PROFILE_PASSWORD}}]}))
    (tdir / "dispatcher.yaml").write_text(yaml.safe_dump(DISPATCHER_DOC))


async def main():
    base = Path(tempfile.mkdtemp())
    os.environ["YAML_CONFIG_PATH"] = str(base)
    _write_configs(base)

    import controller.services.mdm_connector as mc
    mc.MDMConnector = FakeConnector
    import httpx
    httpx.AsyncClient = FakeAsyncClient

    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    from controller.models.tenant import Tenant, Device, Alert, Task, AuditLog
    from controller.services import dispatcher
    from datetime import datetime, timedelta, timezone

    tenant = await Tenant.create(id="default", name="Default")
    dev = await Device.create(
        tenant=tenant, udid="UDID-1", serial_number="MACX", device_model="MacBookPro18,3",
        os_version="14.5", enrollment_state="enrolled", groups=[], tags=[],
        attributes={"SecurityInfo": {"FDE_Enabled": False}},  # FileVault OFF
    )

    async def fv_alert():
        return await Alert.get_or_none(device_id=dev.id, rule_id="fv-alert")

    print("1) violation creates a pending alert during grace (no actions yet)")
    await dispatcher.evaluate_device(dev)
    a = await fv_alert()
    check("pending alert created", a is not None and a.status == "pending")
    check("no webhook fired during grace", len(CAPTURED) == 0)
    await dev.refresh_from_db()
    check("no reversible tag applied during grace", "noncompliant-fv" not in dev.tags)

    print("2) after grace, alert opens and fires actions")
    a.first_detected_at = datetime.now(timezone.utc) - timedelta(minutes=11)
    await a.save()
    await dispatcher.evaluate_device(dev)
    await asyncio.sleep(0.2)  # let the spawned webhook run
    a = await fv_alert()
    await dev.refresh_from_db()
    check("alert opened", a.status == "open")
    check("Red severity", a.severity == "red")
    check("noncompliant-fv tag applied", "noncompliant-fv" in dev.tags)
    check("webhook delivered once", len(CAPTURED) == 1)
    # valid HMAC signature over the exact body with the configured secret
    cap = CAPTURED[0]
    sig = cap["headers"].get("X-Micromanage-Signature", "")
    expected = "sha256=" + hmac.new(b"topsecret", cap["content"], hashlib.sha256).hexdigest()
    check("webhook carries a valid HMAC signature", sig == expected)
    # The assign_tag action wrote through record_tag_change: one audit row, naming the rule behind it.
    tag_rows = await AuditLog.filter(action="device.tags", target_id=str(dev.id)).all()
    check("assign_tag wrote exactly one audit row", len(tag_rows) == 1)
    if tag_rows:
        d = tag_rows[0].detail or {}
        check("audit row has no actor (machine write)",
              tag_rows[0].actor_email is None and tag_rows[0].actor_role is None)
        check("audit row names the rule that added the tag",
              d.get("source") == "dispatcher" and d.get("source_ref") == "fv-alert")
        check("audit row records the tag as added", d.get("added") == ["noncompliant-fv"])

    print("3) repeated evaluations keep a single alert (no duplicates)")
    await dispatcher.evaluate_device(dev)
    await dispatcher.evaluate_device(dev)
    n = await Alert.filter(device_id=dev.id, rule_id="fv-alert").count()
    check("still exactly one fv-alert row", n == 1)
    # _fire_actions runs assign_tag again on every re-evaluation of an open alert, but the tag is already there, so
    # _apply_tags' before/after guard must keep this at one audit row.
    still_tag_rows = await AuditLog.filter(action="device.tags", target_id=str(dev.id)).count()
    check("repeated no-change evaluations wrote no additional audit row",
          still_tag_rows == 1)

    print("4) dry-run remediation records but sends no command")
    dry = await Alert.get_or_none(device_id=dev.id, rule_id="dry")
    ledger = (dry.detail or {}).get("remediations", []) if dry else []
    check("dry-run recorded in the ledger", any("dry-run" in r.get("outcome", "") for r in ledger))
    refreshed = await Task.filter(device=dev, type="refresh_info").count()
    check("no refresh_info command task created by dry-run", refreshed == 0)

    print("5) real remediation runs through the audited path as dispatcher:<rule>")
    await asyncio.sleep(0.2)
    rem_tasks = await Task.filter(device=dev, type="profile_install", user="dispatcher:fv-remediate").all()
    check("profile_install task created by remediation", len(rem_tasks) >= 1)

    # 5b) The task row a remediation leaves behind is kept for TASK_RETENTION_DAYS and readable by anyone who can list
    # tasks. It records which profile went out, not the passwords inside it.
    print("5b) the queued profile reaches the tasks table redacted")
    details = (rem_tasks[0].details or {}) if rem_tasks else {}
    stored = json.dumps(details, default=str)
    check("the profile's password is not in the stored row",
          bool(rem_tasks) and FV_PROFILE_PASSWORD not in stored)
    digest = details.get("payload_digest") or {}
    check("the row carries a digest of the real definition instead",
          bool(digest.get("sha256")) and digest.get("bytes"))
    check("and names the value it replaced",
          any("Password" in path for path in (digest.get("redacted") or [])))
    check("what is still readable is which profile went out",
          (details.get("profile_info") or {}).get("id") == "enforce-fv")
    check("and the non-secret keys beside it survive",
          ((details.get("profile_info") or {}).get("payload") or {}).get("Username")
          == "fvadmin")

    # Mark sits in the task details so a retry from the row alone carries it.
    print("5c) the queued profile records which rule asked for it")
    from controller.models.tenant import ProfileDeployment as _PD
    from controller.services import profile_manager as _pm

    source = details.get(_pm.INSTALL_SOURCE_KEY)
    check("the task names the rule as the install source",
          source == _pm.remediation_source("fv-remediate"))
    check("and it is written in the form the sync loop reads back",
          _pm.remediation_rule_id(source) == "fv-remediate")
    dep = await _PD.filter(device=dev, profile_id="enforce-fv").first()
    check("the deployment row the handler created carries it too",
          dep is not None and _pm.remediation_rule_id(dep.install_source) == "fv-remediate")
    check("a profile the scope asked for is left unmarked, so only remediation is held",
          all(_pm.remediation_rule_id(d.install_source) is None
              for d in await _PD.filter(device=dev).exclude(
              profile_id="enforce-fv")))

    print("6) loop protection halts after N attempts and escalates")
    # cooldown=0, max=2. It already attempted once in step 2/5. Drive more evals.
    for _ in range(4):
        await dispatcher.evaluate_device(dev)
        await asyncio.sleep(0.05)
    rem = await Alert.get_or_none(device_id=dev.id, rule_id="fv-remediate")
    detail = rem.detail or {}
    check("remediation marked failed after max attempts", detail.get("remediation_failed") is True)
    check("severity escalated above yellow",
          dispatcher.SEVERITY_RANK.get(rem.severity, 0) > dispatcher.SEVERITY_RANK["yellow"])

    print("7) destructive remediation is queued for approval, not auto-fired")
    # Add rather than replace: overwriting dev.tags would drop the noncompliant-fv tag step 2 applied, and step 8's
    # resolve would become a no-op that proves nothing about the revert path.
    dev.tags = sorted(set(dev.tags or []) | {"risky"})
    await dev.save(update_fields=["tags"])
    await dispatcher.evaluate_device(dev)
    risky = await Alert.get_or_none(device_id=dev.id, rule_id="risky-wipe")
    pend = (risky.detail or {}).get("pending_approvals", []) if risky else []
    erase_tasks = await Task.filter(device=dev, type="erase").count()
    check("erase queued as pending approval", len(pend) == 1 and pend[0]["command"] == "erase")
    check("erase NOT auto-executed", erase_tasks == 0)
    # admin approves -> now it runs through the audited path
    result = await dispatcher.approve_remediation(risky, pend[0]["action_key"], "admin@example.com")
    await risky.refresh_from_db()
    erase_after = await Task.filter(device=dev, type="erase").count()
    check("approval executes the erase (audited)", erase_after == 1)
    check("pending approval cleared after approval",
          not (risky.detail or {}).get("pending_approvals"))
    # secret leak: a destructive remediation's secret param must never appear in the alert detail exposed by GET /alerts
    # (action_key + params both redacted).
    import json as _json
    rec = await Alert.get_or_none(device_id=dev.id, rule_id="recovery")
    detail_json = _json.dumps(rec.detail or {}) if rec else ""
    check("queued (pending approval exists for recovery)",
          bool((rec.detail or {}).get("pending_approvals")) if rec else False)
    check("secret param NOT leaked into alert detail", "supersecret" not in detail_json)

    print("8) becoming compliant auto-resolves and removes the reversible tag")
    dev.attributes = {"SecurityInfo": {"FDE_Enabled": True}}  # FileVault ON now
    await dev.save(update_fields=["attributes"])
    await dispatcher.evaluate_device(dev)
    a = await fv_alert()
    await dev.refresh_from_db()
    check("fv-alert auto-resolved", a.status == "resolved")
    check("noncompliant-fv tag removed on resolve", "noncompliant-fv" not in dev.tags)
    # The revert path in _resolve_alert also goes through record_tag_change, naming the same rule as the row that added
    # the tag but carrying a reason, so a resolve is distinguishable from a rule dropping the tag outright.
    revert_rows = await AuditLog.filter(action="device.tags", target_id=str(dev.id)).all()
    check("resolve added a second audit row for this device", len(revert_rows) == 2)
    revert_row = next((r for r in revert_rows if (r.detail or {}).get("removed")), None)
    check("a row exists recording the tag removal", revert_row is not None)
    if revert_row:
        d = revert_row.detail or {}
        check("removal row names the same rule", d.get("source") == "dispatcher"
              and d.get("source_ref") == "fv-alert")
        check("removal row records the tag as removed", d.get("removed") == ["noncompliant-fv"])
        check("removal row's reason distinguishes it from a plain rule action",
              "alert resolved" in (d.get("reason") or "") and "compliant" in (d.get("reason") or ""))

    print("9) a failing webhook does not block evaluation")
    WEBHOOK_CODE[0] = 500
    dev.attributes = {"SecurityInfo": {"FDE_Enabled": False}}  # violate again
    await dev.save(update_fields=["attributes"])
    a2 = await fv_alert()  # resolved row exists; a NEW pending should be created
    await dispatcher.evaluate_device(dev)
    fresh = await Alert.filter(device_id=dev.id, rule_id="fv-alert").exclude(status="resolved").first()
    check("a new alert is created after re-violation", fresh is not None)
    fresh.first_detected_at = datetime.now(timezone.utc) - timedelta(minutes=11)
    await fresh.save()
    await dispatcher.evaluate_device(dev)  # should open despite webhook 500
    await asyncio.sleep(0.3)
    await fresh.refresh_from_db()
    check("alert opens even though the webhook fails", fresh.status == "open")

    print("10) webhook url/secret are redacted from API responses")
    import controller.api.main as apimain
    red = apimain._redact_dispatcher_config(
        {"webhooks": [{"name": "x", "url": "https://secret", "secret": "s"}]}
    )
    check("url redacted", red["webhooks"][0]["url"] == "***redacted***")
    check("secret redacted", red["webhooks"][0]["secret"] == "***redacted***")

    # Rule flaky-tag has grace_minutes=30 and auto_resolve off. A still-pending alert resolves on compliance regardless,
    # so a later violation cannot inherit its stale first_detected_at anchor.
    print("11) REGRESSION: a pending alert resolves on a compliant interlude, "
          "so a later violation gets a fresh grace anchor")
    dev2 = await Device.create(
        tenant=tenant, udid="UDID-2", serial_number="MACY", device_model="MacBookPro18,3",
        os_version="14.5", enrollment_state="enrolled", groups=[], tags=[],
    )

    async def flaky_alert():
        return await Alert.get_or_none(device_id=dev2.id, rule_id="flaky-tag")

    # Violate: tag applied -> a pending alert anchors the grace period.
    dev2.tags = ["flaky"]
    await dev2.save(update_fields=["tags"])
    await dispatcher.evaluate_device(dev2)
    first = await flaky_alert()
    check("violation creates a pending alert", first is not None and first.status == "pending")
    first_id = first.id

    # Compliant again well inside the 30-minute window: the alert never opened, so only the resolve-on-pending path can
    # clear it.
    dev2.tags = []
    await dev2.save(update_fields=["tags"])
    await dispatcher.evaluate_device(dev2)
    resolved = await flaky_alert()
    check("pending alert resolved on compliant interlude (not left pending)",
          resolved is not None and resolved.status == "resolved")

    # Violate again immediately: must NOT reuse the resolved row or its old first_detected_at anchor.
    t_violation2 = datetime.now(timezone.utc)
    dev2.tags = ["flaky"]
    await dev2.save(update_fields=["tags"])
    await dispatcher.evaluate_device(dev2)
    second = await Alert.filter(
        device_id=dev2.id, rule_id="flaky-tag"
    ).exclude(status="resolved").first()
    check("a NEW pending alert exists for the second violation", second is not None)
    check("the new alert is a distinct row from the first", second is not None and second.id != first_id)
    second_anchor = second.first_detected_at if second else None
    if second_anchor is not None and second_anchor.tzinfo is None:
        second_anchor = second_anchor.replace(tzinfo=timezone.utc)
    check("the new alert's first_detected_at is fresh (>= the second violation, "
          "not inherited from the first)",
          second_anchor is not None and second_anchor >= t_violation2 - timedelta(seconds=5))

    # Resolving does not clear pending_approvals, so the endpoint checks the alert status: an erase queued days ago must
    # not reach a device that has come back into compliance.
    print("12) approving a queued remediation on a resolved alert is refused")
    from fastapi import HTTPException
    from controller.auth.dependencies import Principal
    from controller.models.tenant import User

    admin_user = await User.create(tenant=tenant, email="admin@default", role="admin")
    admin = Principal(tenant=tenant, user=admin_user, email="admin@default", role="admin")
    stale = await Alert.create(
        tenant=tenant, device=dev, rule_id="risky-wipe", severity="red",
        status="resolved", summary="long since resolved",
        detail={"pending_approvals": [{"action_key": "k", "command": "erase"}]},
    )
    erase_before = await Task.filter(device=dev, type="erase").count()
    try:
        await apimain.approve_alert_remediation(
            str(stale.id), apimain.RemediateRequest(action_key="k"), admin)
        check("resolved alert raises", False)
    except HTTPException as e:
        check("resolved alert -> 409", e.status_code == 409)
    check("no erase fired from the resolved alert",
          await Task.filter(device=dev, type="erase").count() == erase_before)

    print("13) a webhook inventory response defers dispatcher evaluation; the alert still raises")
    from controller.services import webhook_handler

    dev3 = await Device.create(
        tenant=tenant, udid="UDID-3", serial_number="MACZ", device_model="MacBookPro18,3",
        os_version="14.5", enrollment_state="enrolled", groups=[], tags=[],
    )
    sec_task = await Task.create(
        tenant=tenant, type="security_info", status="running", device=dev3,
        user="system", description="Query security info",
        details={"command_uuid": "cmd-sec-3"})
    await webhook_handler.WebhookHandler()._dispatch_command_response(
        dev3, "cmd-sec-3", "Acknowledged", {"SecurityInfo": {"FDE_Enabled": False}})
    await dev3.refresh_from_db()
    await sec_task.refresh_from_db()
    check("SecurityInfo persisted inline, before any rule ran",
          (dev3.attributes or {}).get("SecurityInfo", {}).get("FDE_Enabled") is False)
    check("the task row completed inline", sec_task.status == "completed")
    await webhook_handler.drain_deferred()
    fv3 = await Alert.get_or_none(device_id=dev3.id, rule_id="fv-alert")
    check("the deferred evaluation raised the alert the inline path used to",
          fv3 is not None and fv3.status == "pending")

    # The batched sweep (alert-pair prefetch plus .only() device rows) must produce the same alert outcomes as the
    # per-device path, including on a device carrying the rich inventory blobs the .only() fetch leaves behind.
    print("14) sweep parity: prefetched + narrowed sweep matches per-device evaluation")
    import logging as _logging

    SWEEP_DOC = {
        "rules": [
            {"id": "sw-fv", "name": "FV", "severity": "red", "grace_minutes": 0,
             "check": {"type": "filevault_disabled"},
             "actions": [
                 {"type": "assign_tag", "params": {"tags": ["sw-fv-bad"]}},
                 {"type": "send_command", "params": {"command": "refresh_info"}},
             ],
             "auto_resolve": True},
            {"id": "sw-os", "name": "OS floor", "severity": "yellow",
             "grace_minutes": 0, "check": {"type": "os_below", "min": "15.0"},
             "actions": [], "auto_resolve": True},
            {"id": "sw-tag", "name": "Risky", "severity": "green", "grace_minutes": 0,
             "check": {"type": "tagged", "tags": ["risky"]},
             "actions": [], "auto_resolve": True},
            {"id": "sw-scope", "name": "Mac scoped", "severity": "yellow",
             "grace_minutes": 0,
             "scope": {"conditions": [{"type": "platform", "operator": "in",
                                       "value": ["Mac"]}]},
             "check": {"type": "tagged", "tags": ["scoped-tag"]},
             "actions": [], "auto_resolve": False},
            {"id": "sw-ddm", "name": "DDM family", "severity": "green",
             "grace_minutes": 0,
             "check": {"type": "ddm_status", "path": "device.operating-system.family",
                       "operator": "equals", "value": "macOS"},
             "actions": [], "auto_resolve": True},
            {"id": "sw-decl", "name": "Declaration drift", "severity": "yellow",
             "grace_minutes": 0, "check": {"type": "declaration_drift"},
             "actions": [], "auto_resolve": True},
        ],
    }

    def _tenant_configs(tid, doc):
        d = base / "tenants" / tid
        d.mkdir(parents=True, exist_ok=True)
        (d / "config.yaml").write_text(yaml.safe_dump(
            {"tenant": {"id": tid, "name": tid, "allowed_users": []}}))
        (d / "groups.yaml").write_text(yaml.safe_dump({"groups": []}))
        (d / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
        (d / "profiles.yaml").write_text(yaml.safe_dump({"profiles": []}))
        (d / "dispatcher.yaml").write_text(yaml.safe_dump(doc))

    _tenant_configs("sweeptest", SWEEP_DOC)
    sw_tenant = await Tenant.create(id="sweeptest", name="Sweep Test")
    rich_blobs = {
        "installed_apps": [{"Identifier": f"com.example.app{i}", "Name": f"App {i}",
                            "Version": "1.0"} for i in range(200)],
        "installed_profiles": [{"PayloadIdentifier": f"com.example.p{i}"}
                               for i in range(40)],
        "ddm_status": {"device": {"operating-system": {"family": "macOS"}}},
    }
    swA = await Device.create(
        tenant=sw_tenant, udid="UDID-SW-A", serial_number="SW-A",
        device_model="MacBookPro18,3", os_version="14.5", enrollment_state="enrolled",
        groups=[], tags=["scoped-tag"],
        attributes={"SecurityInfo": {"FDE_Enabled": False}},
        ddm_enabled_at=datetime.now(timezone.utc), **rich_blobs)
    swB = await Device.create(
        tenant=sw_tenant, udid="UDID-SW-B", serial_number="SW-B",
        device_model="MacBookPro18,3", os_version="16.1", enrollment_state="enrolled",
        groups=[], tags=[], attributes={"SecurityInfo": {"FDE_Enabled": True}})
    swC = await Device.create(
        tenant=sw_tenant, udid="UDID-SW-C", serial_number="SW-C",
        device_model="iPad13,8", os_version="17.0", enrollment_state="enrolled",
        groups=[], tags=["risky"], attributes={})

    async def _alert_state():
        rows = await Alert.filter(tenant=sw_tenant).exclude(status="resolved").all()
        by_dev = {swA.id: "SW-A", swB.id: "SW-B", swC.id: "SW-C"}
        return {(by_dev.get(r.device_id, "?"), r.rule_id, r.status, r.severity)
                for r in rows}

    # Unbatched pass: the webhook path, full rows, no prefetch.
    for d in (swA, swB, swC):
        await dispatcher.evaluate_device(d)
    expected_state = await _alert_state()
    await swA.refresh_from_db()
    expected_tags = sorted(swA.tags or [])
    check("unbatched pass raised the expected (device, rule) pairs",
          expected_state == {
              ("SW-A", "sw-fv", "open", "red"),
              ("SW-A", "sw-os", "open", "yellow"),
              ("SW-A", "sw-scope", "open", "yellow"),
              ("SW-A", "sw-ddm", "open", "green"),
              ("SW-C", "sw-tag", "open", "green"),
          })
    check("unbatched remediation sent refresh_info once",
          await Task.filter(tenant=sw_tenant, type="refresh_info",
                            user="dispatcher:sw-fv").count() == 1)

    # Reset to the pre-evaluation world, then run the batched sweep.
    await Alert.filter(tenant=sw_tenant).delete()
    await Task.filter(tenant=sw_tenant).delete()
    swA.tags = ["scoped-tag"]
    await swA.save(update_fields=["tags"])

    sweep_errors = []

    class _Capture(_logging.Handler):
        def emit(self, record):
            if record.levelno >= _logging.ERROR:
                sweep_errors.append(record.getMessage())

    # The wide net matters: an AttributeError on a lazily-excluded field can surface, and be swallowed into a log line,
    # in compliance_catalog, scoping, ddm_manager or the command path, not only in dispatcher.
    cap_handler = _Capture()
    _logging.getLogger("controller").addHandler(cap_handler)
    swept = await dispatcher.sweep(sw_tenant)
    _logging.getLogger("controller").removeHandler(cap_handler)

    check("sweep evaluated all three devices", swept == 3)
    check("sweep logged no errors (no lazy-field access blew up on partial rows)",
          sweep_errors == [])
    check("sweep alerts match the unbatched pass exactly",
          await _alert_state() == expected_state)
    await swA.refresh_from_db()
    check("sweep applied the same reversible tag",
          sorted(swA.tags or []) == expected_tags)
    check("sweep remediation sent the same refresh_info",
          await Task.filter(tenant=sw_tenant, type="refresh_info",
                            user="dispatcher:sw-fv").count() == 1)
    check("rich JSONB blobs survived the partial-row sweep untouched",
          len(swA.installed_apps or []) == 200
          and len(swA.installed_profiles or []) == 40
          and (swA.ddm_status or {}).get("device") is not None)

    # Resolution parity through the prefetch map: compliant pairs with a live alert are hits, re-read fresh and then
    # resolved, and compliant pairs with no alert are misses that skip the per-rule query.
    swA.attributes = {"SecurityInfo": {"FDE_Enabled": True}}
    swA.os_version = "16.0"
    swA.ddm_status = {"device": {"operating-system": {"family": "iOS"}}}
    await swA.save(update_fields=["attributes", "os_version", "ddm_status"])
    swC.tags = []
    await swC.save(update_fields=["tags"])
    await dispatcher.sweep(sw_tenant)
    check("auto-resolve rules resolved via map hits; the no-auto-resolve alert stayed",
          await _alert_state() == {("SW-A", "sw-scope", "open", "yellow")})
    await swA.refresh_from_db()
    check("reversible tag removed by the sweep resolve",
          "sw-fv-bad" not in (swA.tags or []))

    # Out-of-scope resolution through the map: the device leaves the rule's platform scope, so its alert resolves.
    swA.device_model = "iPad13,8"
    await swA.save(update_fields=["device_model"])
    await dispatcher.sweep(sw_tenant)
    check("leaving scope resolves the remaining alert via the prefetch map",
          await _alert_state() == set())
    gone = await Alert.filter(device_id=swA.id, rule_id="sw-scope",
                              status="resolved").first()
    check("out-of-scope resolve carries its reason",
          gone is not None
          and (gone.detail or {}).get("resolved_reason") == "out of scope")

    # On an all-compliant steady-state fleet the unbatched path costs D x R alert lookups plus per-device deployment
    # reads, where the batched sweep costs one query per table.
    print("15) sweep query counts: D x R alert lookups collapse to one prefetch")
    COUNT_DOC = {"rules": [dict(r, actions=[]) for r in SWEEP_DOC["rules"]] + [
        {"id": "sw-drift", "name": "Drift", "severity": "yellow", "grace_minutes": 0,
         "check": {"type": "config_drift"}, "actions": [], "auto_resolve": True},
    ]}
    _tenant_configs("sweepcount", COUNT_DOC)
    qc_tenant = await Tenant.create(id="sweepcount", name="Sweep Count")
    qc_devices = []
    for i in range(5):
        qc_devices.append(await Device.create(
            tenant=qc_tenant, udid=f"UDID-QC-{i}", serial_number=f"QC-{i}",
            device_model="MacBookPro18,3", os_version="16.0",
            enrollment_state="enrolled", groups=[], tags=[],
            attributes={"SecurityInfo": {"FDE_Enabled": True}}))

    from tortoise import connections
    conn = connections.get("default")
    counts = {"alerts": 0, "devices": 0, "profile_deployments": 0,
              "app_deployments": 0}

    def _tally(sql):
        if sql.lstrip().upper().startswith("SELECT"):
            for table in counts:
                if f'"{table}"' in sql:
                    counts[table] += 1

    orig_q, orig_qd = conn.execute_query, conn.execute_query_dict

    async def spy_q(sql, values=None):
        _tally(sql)
        return await orig_q(sql, values)

    # Fallback probe: fail the alert-pair prefetch (a .values() query, so it goes through execute_query_dict) once. The
    # sweep degrades to per-device alert queries for the cycle rather than aborting the tenant.
    fail_next_alert_values = {"armed": False}

    async def spy_qd_failable(sql, values=None):
        if (fail_next_alert_values["armed"]
            and sql.lstrip().upper().startswith("SELECT") and '"alerts"' in sql):
            fail_next_alert_values["armed"] = False
            raise RuntimeError("injected prefetch failure")
        _tally(sql)
        return await orig_qd(sql, values)

    conn.execute_query, conn.execute_query_dict = spy_q, spy_qd_failable
    try:
        for d in qc_devices:
            await dispatcher.evaluate_device(d)
        unbatched = dict(counts)
        for k in counts:
            counts[k] = 0
        await dispatcher.sweep(qc_tenant)
        batched = dict(counts)
        for k in counts:
            counts[k] = 0
        fail_next_alert_values["armed"] = True
        degraded_n = await dispatcher.sweep(qc_tenant)
        degraded = dict(counts)
    finally:
        conn.execute_query, conn.execute_query_dict = orig_q, orig_qd

    n_rules = len(COUNT_DOC["rules"])
    check(f"unbatched: one alert query per (device, rule) "
          f"({unbatched['alerts']} for 5 x {n_rules})",
          unbatched["alerts"] == 5 * n_rules)
    check("unbatched: one profile-deployment query per device",
          unbatched["profile_deployments"] == 5)
    check("unbatched: one app-deployment query per device",
          unbatched["app_deployments"] == 5)
    check(f"batched sweep: exactly one alert prefetch (got {batched['alerts']})",
          batched["alerts"] == 1)
    check("batched sweep: one device fetch", batched["devices"] == 1)
    check("batched sweep: one profile-deployment prefetch",
          batched["profile_deployments"] == 1)
    check("batched sweep: one app-deployment prefetch",
          batched["app_deployments"] == 1)
    check("no alerts raised on the all-compliant fixture (parity)",
          await Alert.filter(tenant=qc_tenant).count() == 0)
    check("a failed alert prefetch degrades to per-device queries, not a "
          f"skipped sweep (swept {degraded_n}, {degraded['alerts']} alert queries)",
          degraded_n == 5 and degraded["alerts"] == 5 * n_rules)
    check("degraded sweep still used the deployment prefetch",
          degraded["profile_deployments"] == 1 and degraded["app_deployments"] == 1)
    check("degraded sweep raised no alerts either (parity preserved)",
          await Alert.filter(tenant=qc_tenant).count() == 0)

    # DDM build runs on .only() partial rows; cache dropped between passes and every build recorded.
    print("16) drift-context hits + DDM build on partial rows: full parity")
    DRIFT_DOC = {
        "rules": [
            {"id": "d-miss", "name": "Base profile", "severity": "yellow",
             "grace_minutes": 0, "check": {"type": "missing_profile",
                                           "profile_id": "base"},
             "actions": [], "auto_resolve": True},
            {"id": "d-drift", "name": "Config drift", "severity": "red",
             "grace_minutes": 0, "check": {"type": "config_drift"},
             "actions": [], "auto_resolve": True},
            {"id": "d-decl", "name": "Declaration drift", "severity": "yellow",
             "grace_minutes": 0, "check": {"type": "declaration_drift"},
             "actions": [], "auto_resolve": True},
        ],
    }
    _tenant_configs("sweepdrift", DRIFT_DOC)
    ddir = base / "tenants" / "sweepdrift"
    (ddir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": [
        {"id": "base", "name": "Base profile",
         "conditions": [{"type": "platform", "operator": "in", "value": ["Mac"]}],
         "payload": {"PayloadType": "com.example.base"}},
    ]}))
    (ddir / "declarations.yaml").write_text(yaml.safe_dump({"declarations": [
        {"id": "note1", "type": "com.apple.configuration.passcode.settings",
         "conditions": [{"type": "platform", "operator": "in", "value": ["Mac"]}],
         "payload": {"MinimumLength": 6}},
    ]}))
    dr_tenant = await Tenant.create(id="sweepdrift", name="Sweep Drift",
                                    ddm_enabled=True)
    from controller.models.tenant import AppDeployment, ProfileDeployment
    drA = await Device.create(
        tenant=dr_tenant, udid="UDID-DR-A", serial_number="DR-A",
        device_model="MacBookPro18,3", os_version="14.5",
        enrollment_state="enrolled", groups=[], tags=[], attributes={},
        ddm_enabled_at=datetime.now(timezone.utc), ddm_declaration_status={},
        installed_apps=[{"Identifier": f"com.dr.app{i}"} for i in range(120)])
    drB = await Device.create(
        tenant=dr_tenant, udid="UDID-DR-B", serial_number="DR-B",
        device_model="MacBookPro18,3", os_version="14.5",
        enrollment_state="enrolled", groups=[], tags=[], attributes={})
    drC = await Device.create(
        tenant=dr_tenant, udid="UDID-DR-C", serial_number="DR-C",
        device_model="MacBookPro18,3", os_version="14.5",
        enrollment_state="enrolled", groups=[], tags=[], attributes={})
    pdA = await ProfileDeployment.create(tenant=dr_tenant, device=drA,
                                         profile_id="base", status="installed")
    adA = await AppDeployment.create(tenant=dr_tenant, device=drA, app_id="tool",
                                     app_version="1.0", status="failed")
    pdB = await ProfileDeployment.create(tenant=dr_tenant, device=drB,
                                         profile_id="base", status="failed")

    dr_serial = {drA.id: "DR-A", drB.id: "DR-B", drC.id: "DR-C"}

    async def _drift_state():
        rows = await Alert.filter(tenant=dr_tenant).exclude(status="resolved").all()
        state = {(dr_serial.get(r.device_id, "?"), r.rule_id, r.status, r.severity)
                 for r in rows}
        details = {(dr_serial.get(r.device_id, "?"), r.rule_id):
                       (r.detail or {}).get("check") for r in rows}
        return state, details

    from controller.services import ddm_manager

    ddm_build_rows = []
    _orig_ddm_build = ddm_manager.DDMManager.build_device_declarations

    async def _recording_ddm_build(self, device, *args, **kwargs):
        ddm_build_rows.append(device)
        return await _orig_ddm_build(self, device, *args, **kwargs)

    def _row_is_partial(row):
        """True for a .only() row: reading a field it did not fetch raises. installed_apps sits outside
        _SWEEP_DEVICE_FIELDS, so a full row answers with the list instead."""
        try:
            row.installed_apps
        except AttributeError:
            return True
        return False

    ddm_manager.DDMManager.build_device_declarations = _recording_ddm_build
    ddm_manager.invalidate_declaration_cache()
    try:
        for d in (drA, drB, drC):
            await dispatcher.evaluate_device(d)
    finally:
        ddm_manager.DDMManager.build_device_declarations = _orig_ddm_build
    unbatched_rows = list(ddm_build_rows)
    check("the unbatched pass built the desired set once, on a full row "
          "(DR-A is the only device on the DDM path)",
          len(unbatched_rows) == 1 and not _row_is_partial(unbatched_rows[0]))
    expected_dr_state, expected_dr_details = await _drift_state()
    check("unbatched drift pass raised the expected pairs",
          expected_dr_state == {
              ("DR-A", "d-drift", "open", "red"),
              ("DR-A", "d-decl", "open", "yellow"),
              ("DR-B", "d-miss", "open", "yellow"),
              ("DR-B", "d-drift", "open", "red"),
              ("DR-C", "d-miss", "open", "yellow"),
              ("DR-C", "d-drift", "open", "red"),
          })
    check("unbatched declaration_drift names the desired declaration",
          "mm.cfg.note1" in ((expected_dr_details.get(("DR-A", "d-decl")) or {})
                             .get("identifiers") or []))

    await Alert.filter(tenant=dr_tenant).delete()
    dr_errors = []

    class _DriftCapture(_logging.Handler):
        def emit(self, record):
            if record.levelno >= _logging.ERROR:
                dr_errors.append(record.getMessage())

    dr_handler = _DriftCapture()
    _logging.getLogger("controller").addHandler(dr_handler)
    # Cold, so the sweep builds against its own .only() rows rather than the entry the full-row pass cached.
    ddm_manager.invalidate_declaration_cache()
    ddm_build_rows.clear()
    ddm_manager.DDMManager.build_device_declarations = _recording_ddm_build
    try:
        await dispatcher.sweep(dr_tenant)
    finally:
        ddm_manager.DDMManager.build_device_declarations = _orig_ddm_build
    _logging.getLogger("controller").removeHandler(dr_handler)
    sweep_rows = list(ddm_build_rows)
    check("the sweep ran the DDM build itself, on a partial .only() row",
          len(sweep_rows) == 1 and _row_is_partial(sweep_rows[0]))
    check("drift sweep logged no errors (DDM build ran clean on partial rows)",
          dr_errors == [])
    sweep_dr_state, sweep_dr_details = await _drift_state()
    check("drift verdicts identical between batched and unbatched paths",
          sweep_dr_state == expected_dr_state)
    check("drift detail['check'] payloads identical between paths",
          sweep_dr_details == expected_dr_details)

    # Fix the fleet, then let the sweep resolve every alert through map hits, drift context rebuilt from clean rows.
    pdB.status = "installed"
    await pdB.save(update_fields=["status"])
    await ProfileDeployment.create(tenant=dr_tenant, device=drC,
                                   profile_id="base", status="installed")
    await adA.delete()
    drA.ddm_enabled_at = None
    await drA.save(update_fields=["ddm_enabled_at"])
    await dispatcher.sweep(dr_tenant)
    check("a clean fleet resolves every drift alert through the prefetch maps",
          (await _drift_state())[0] == set())

    # Scoped against derived membership, not stale device.groups column.
    print("17) declaration drift is judged against the set the device was served")
    SG_DOC = {"rules": [
        {"id": "sg-decl", "name": "Declaration drift", "severity": "yellow",
         "grace_minutes": 0, "check": {"type": "declaration_drift"},
         "actions": [], "auto_resolve": True},
    ]}
    _tenant_configs("stalegroups", SG_DOC)
    sgdir = base / "tenants" / "stalegroups"
    (sgdir / "groups.yaml").write_text(yaml.safe_dump({"groups": [
        {"name": "kiosks",
         "conditions": [{"type": "tag", "operator": "in", "value": ["kiosk"]}]},
    ]}))
    (sgdir / "declarations.yaml").write_text(yaml.safe_dump({"declarations": [
        {"id": "note1", "type": "com.apple.configuration.passcode.settings",
         "conditions": [{"type": "platform", "operator": "in", "value": ["Mac"]}],
         "payload": {"MinimumLength": 6}},
        {"id": "kiosk-only", "type": "com.apple.configuration.passcode.settings",
         "groups": ["kiosks"], "payload": {"MinimumLength": 8}},
    ]}))
    sg_tenant = await Tenant.create(id="stalegroups", name="Stale Groups",
                                    ddm_enabled=True)

    async def _sg_device(serial, groups, tags):
        return await Device.create(
            tenant=sg_tenant, udid=f"UDID-{serial}", serial_number=serial,
            device_model="MacBookPro18,3", os_version="14.5",
            enrollment_state="enrolled", groups=groups, tags=tags, attributes={},
            ddm_enabled_at=datetime.now(timezone.utc), ddm_declaration_status={})

    # Membership derives from the kiosk tag, so the stored column can disagree with it in either direction.
    sgA = await _sg_device("SG-A", ["kiosks"], [])  # column names a group it left
    sgB = await _sg_device("SG-B", [], [])  # column accurate, real drift
    sgC = await _sg_device("SG-C", [], ["kiosk"])  # column missed a group it joined

    async def _reported(device, missing=()):
        """What a device reports once it holds exactly what it was served. management.* declarations always report
        active=false and the check exempts them, so they are left out here."""
        served = await ddm_manager.compute_device_declarations(device, sg_tenant)
        return {d["Identifier"]: {"active": True, "valid": "valid"}
                for d in served
                if not (d.get("Type") or "").startswith("com.apple.management.")
                and d["Identifier"] not in missing}

    sgA.ddm_declaration_status = await _reported(sgA)
    await sgA.save(update_fields=["ddm_declaration_status"])
    sgB.ddm_declaration_status = await _reported(sgB)
    sgB.ddm_declaration_status["mm.cfg.note1"] = {
        "active": True, "valid": "invalid",
        "reasons": [{"code": "Error.ConfigurationCannotBeApplied"}]}
    await sgB.save(update_fields=["ddm_declaration_status"])
    sgC.ddm_declaration_status = await _reported(
        sgC, missing=("mm.cfg.kiosk-only", "mm.act.kiosk-only"))
    await sgC.save(update_fields=["ddm_declaration_status"])

    sg_derived_A = {d["Identifier"] for d
                    in await ddm_manager.compute_device_declarations(sgA, sg_tenant)}
    sg_stale_A = {d["Identifier"] for d in await ddm_manager.compute_device_declarations(
        sgA, sg_tenant, device_groups=list(sgA.groups or []))}
    check("fixture: the two membership views really do build different sets",
          "mm.cfg.kiosk-only" not in sg_derived_A
          and "mm.cfg.kiosk-only" in sg_stale_A)

    sg_serial = {sgA.id: "SG-A", sgB.id: "SG-B", sgC.id: "SG-C"}

    async def _sg_alerts():
        rows = await Alert.filter(tenant=sg_tenant).exclude(status="resolved").all()
        return {sg_serial.get(r.device_id, "?"): (r.detail or {}).get("check") or {}
                for r in rows}

    _orig_cached = ddm_manager.compute_device_declarations_cached

    async def _pre_fix_cached(device, tenant=None):
        """Drift judged against the stored membership column, handed in rather than derived."""
        return await ddm_manager.compute_device_declarations(
            device, tenant, device_groups=list(device.groups or []))

    ddm_manager.compute_device_declarations_cached = _pre_fix_cached
    ddm_manager.invalidate_declaration_cache()
    try:
        for d in (sgA, sgB, sgC):
            await dispatcher.evaluate_device(d)
    finally:
        ddm_manager.compute_device_declarations_cached = _orig_cached
    sg_before = await _sg_alerts()
    check("BEFORE the fix: a stale column raised drift on a device that is fine",
          "mm.cfg.kiosk-only" in (sg_before.get("SG-A") or {}).get("identifiers", []))
    check("BEFORE the fix: a stale column hid drift the device really has",
          "SG-C" not in sg_before)
    check("BEFORE the fix: membership-independent drift fired either way",
          "SG-B" in sg_before)

    await Alert.filter(tenant=sg_tenant).delete()
    ddm_manager.invalidate_declaration_cache()
    for d in (sgA, sgB, sgC):
        await dispatcher.evaluate_device(d)
    sg_after = await _sg_alerts()
    check("a stale groups column no longer raises a drift alert",
          "SG-A" not in sg_after)
    check("real drift still fires, with its reason code intact",
          (sg_after.get("SG-B") or {}).get("identifiers") == ["mm.cfg.note1"]
          and (sg_after["SG-B"]["problems"][0].get("reason")
               == "Error.ConfigurationCannotBeApplied"))
    check("drift the stale column used to hide is now visible",
          "mm.cfg.kiosk-only" in (sg_after.get("SG-C") or {}).get("identifiers", []))

    # Cold drift build must be stored in the cache entry that api/ddm.py serves from.
    ddm_manager.invalidate_declaration_cache()
    sg_served = await ddm_manager.compute_device_declarations_cached(sgA)
    sg_ctx = await dispatcher._build_ctx(
        sgA, sg_tenant, [{"check": {"type": "declaration_drift"}}],
        list(sgA.groups or []))
    check("the drift check's desired set is byte-equal to what the "
          "device-facing serve path computes for the same device",
          bool(sg_ctx.get("ddm_desired"))
          and ddm_manager._canonical_json(sg_ctx.get("ddm_desired"))
          == ddm_manager._canonical_json(sg_served))
    check("and is the same cached object, so the two paths share one entry",
          sg_ctx.get("ddm_desired") is sg_served)
    ddm_manager.invalidate_declaration_cache()

    # One rank table for both engines, not a local copy: a one-based copy against ATC's zero-based one sorted the same
    # unrecognised severity below green here and level with it there. verify_atc section 36 is the other half.
    print("18) the board's rank table is the shared one")
    from controller.services import severity as _severity

    check("dispatcher.SEVERITY_RANK is the shared table object",
          dispatcher.SEVERITY_RANK is _severity.RANK)
    check("higher is still more severe, with black on top",
          dispatcher.SEVERITY_RANK["black"] > dispatcher.SEVERITY_RANK["red"]
          > dispatcher.SEVERITY_RANK["yellow"] > dispatcher.SEVERITY_RANK["green"])
    check("an unrecognised severity sorts below every real one",
          dispatcher.SEVERITY_RANK.get("mauve", 0) < dispatcher.SEVERITY_RANK["green"])
    check("remediation escalation walks the shared ladder and pins the top",
          [dispatcher._escalate_severity(s)
           for s in ("green", "yellow", "red", "black")]
          == ["yellow", "red", "black", "black"])
    check("and leaves an unrecognised severity where it found it",
          dispatcher._escalate_severity("mauve") == "mauve")
    disp_src = Path(dispatcher.__file__).read_text()
    local_tables = [
        ln for ln in disp_src.splitlines()
        if not ln.strip().startswith("#")
           and len({n for n in ("black", "red", "yellow", "green")
                    if f'"{n}"' in ln or f"'{n}'" in ln}) >= 3
    ]
    check("dispatcher.py defines no severity table of its own", local_tables == [])

    # Rule evaluation reads dispatcher.yaml without copying it, while the two sites that store config into Task.details
    # do copy. The sweep loads once per tenant and hands one object to every device, so nothing may mutate it.
    print("19) rule evaluation reads the shared dispatcher.yaml")
    from controller.services import tenant_config as _tc

    _tid = str(tenant.id)
    # Re-parse from disk first: earlier sections have already evaluated against this document, so a snapshot of the
    # cache entry would bake in any mutation they made and the comparison would run against itself.
    _tc.invalidate(_tid)
    disp_before = copy.deepcopy(_tc._load_readonly(_tid, "dispatcher.yaml"))
    disp_shared = _tc._load_readonly(_tid, "dispatcher.yaml")
    loads = {"ro": 0, "copy": 0}
    real_ro, real_copy = (dispatcher._load_dispatcher_readonly,
                          dispatcher._load_dispatcher)

    def _counted_ro(tid):
        loads["ro"] += 1
        return real_ro(tid)

    def _counted_copy(tid):
        loads["copy"] += 1
        return real_copy(tid)

    dispatcher._load_dispatcher_readonly = _counted_ro
    dispatcher._load_dispatcher = _counted_copy
    try:
        await dispatcher.evaluate_device(dev)
        await dispatcher.sweep(tenant)
    finally:
        dispatcher._load_dispatcher_readonly = real_ro
        dispatcher._load_dispatcher = real_copy
    await webhook_handler.drain_deferred()

    check("evaluation and sweep both went through the readonly loader",
          loads["ro"] >= 2 and loads["copy"] == 0)
    check("a full evaluation pass left the shared dispatcher.yaml untouched",
          _tc._load_readonly(_tid, "dispatcher.yaml") == disp_before)
    check("...and it is still the same cache entry, so that comparison was "
          "made against the object evaluation actually read",
          _tc._load_readonly(_tid, "dispatcher.yaml") is disp_shared)
    check("the readonly loader shares one doc; the copying loader still hands "
          "out a fresh one every call",
          _tc._load_readonly(_tid, "dispatcher.yaml")
          is _tc._load_readonly(_tid, "dispatcher.yaml")
          and dispatcher._load_dispatcher(_tid)
          is not dispatcher._load_dispatcher(_tid)
          and dispatcher._load_dispatcher(_tid) == disp_before)
    # The unsafe sites, pinned structurally. Each stores a piece of a config document into Task.details, which outlives
    # the call, so each has to keep calling the copying loader.
    for fn in (dispatcher._queue_profile_installs, dispatcher._queue_app_installs,
               dispatcher.approve_remediation):
        src = inspect.getsource(fn)
        check(f"{fn.__name__} still loads config through the copying loader",
              "_readonly" not in src
              and ("tenant_config._load(" in src or "_load_dispatcher(" in src))

    # Loaded only when membership is None; production path passes None.
    group_loads = {"n": 0}
    real_groups = _tc.load_groups

    def _counted_groups(tid):
        group_loads["n"] += 1
        return real_groups(tid)

    # Section 16 left this fleet clean, so put one profile back into a failed state: no drift either way would pass
    # without the branches having agreed about anything.
    pdB.status = "failed"
    await pdB.save(update_fields=["status"])
    _tc.load_groups = _counted_groups
    try:
        drift_rules = [{"check": {"type": "config_drift"}}]
        ctx_supplied = await dispatcher._build_ctx(
            drB, dr_tenant, drift_rules, list(drB.groups or []))
        supplied_loads = group_loads["n"]
        ctx_derived = await dispatcher._build_ctx(drB, dr_tenant, drift_rules, None)
    finally:
        _tc.load_groups = real_groups
        pdB.status = "installed"
        await pdB.save(update_fields=["status"])
    check("a config_drift pass with membership supplied loads no groups.yaml",
          supplied_loads == 0)
    check("the no-membership branch, which is now production's, loads it once",
          group_loads["n"] == 1)
    check("and both reach the same drift verdict, which is not the empty one",
          bool(ctx_supplied.get("drift"))
          and ctx_supplied.get("drift") == ctx_derived.get("drift"))

    # Scoped against derived membership that reconciler uses (reconciler.py:529).
    print("20) profile drift is judged against the membership the reconciler enforces")
    import json as _json
    from controller.services import reconciler as _reconciler
    from controller.services.group_manager import GroupManager
    from controller.services.profile_manager import ProfileManager as _PM

    SP_DOC = {"rules": [
        {"id": "sp-drift", "name": "Config drift", "severity": "red",
         "grace_minutes": 0, "check": {"type": "config_drift"},
         "actions": [], "auto_resolve": True},
        {"id": "sp-decl", "name": "Declaration drift", "severity": "yellow",
         "grace_minutes": 0, "check": {"type": "declaration_drift"},
         "actions": [], "auto_resolve": True},
    ]}
    SP_GROUPS = {"groups": [
        {"name": "labs",
         "conditions": [{"type": "tag", "operator": "in", "value": ["lab"]}]},
    ]}
    # base is membership-independent and lab-only rides the group, so the stored column and derived membership disagree
    # about the desired set and about nothing else.
    SP_PROFILES = {"profiles": [
        {"id": "base", "name": "Base profile",
         "conditions": [{"type": "platform", "operator": "in", "value": ["Mac"]}],
         "payload": {"PayloadType": "com.example.base"}},
        {"id": "lab-only", "name": "Lab profile", "groups": ["labs"],
         "payload": {"PayloadType": "com.example.lab"}},
    ]}
    _tenant_configs("staleprofiles", SP_DOC)
    spdir = base / "tenants" / "staleprofiles"
    (spdir / "groups.yaml").write_text(yaml.safe_dump(SP_GROUPS))
    (spdir / "profiles.yaml").write_text(yaml.safe_dump(SP_PROFILES))
    # The DDM half of the fixture: note1 is served to every Mac and lab-decl only to the group, so a clear declaration
    # alert means the device holds what it was served rather than holding nothing.
    (spdir / "declarations.yaml").write_text(yaml.safe_dump({"declarations": [
        {"id": "note1", "type": "com.apple.configuration.passcode.settings",
         "conditions": [{"type": "platform", "operator": "in", "value": ["Mac"]}],
         "payload": {"MinimumLength": 6}},
        {"id": "lab-decl", "type": "com.apple.configuration.passcode.settings",
         "groups": ["labs"], "payload": {"MinimumLength": 8}},
    ]}))
    sp_tenant = await Tenant.create(id="staleprofiles", name="Stale Profiles",
                                    ddm_enabled=True)

    async def _sp_device(tenant_row, serial, groups, tags, ddm=False):
        return await Device.create(
            tenant=tenant_row, udid=f"UDID-{serial}", serial_number=serial,
            device_model="MacBookPro18,3", os_version="14.5",
            enrollment_state="enrolled", groups=groups, tags=tags, attributes={},
            ddm_enabled_at=datetime.now(timezone.utc) if ddm else None,
            ddm_declaration_status={})

    # Membership derives from the lab tag, so the stored column can disagree with it in either direction.
    spA = await _sp_device(sp_tenant, "SP-A", ["labs"], [], ddm=True)
    spB = await _sp_device(sp_tenant, "SP-B", [], [])
    spC = await _sp_device(sp_tenant, "SP-C", [], ["lab"])
    await ProfileDeployment.create(tenant=sp_tenant, device=spA,
                                   profile_id="base", status="installed")
    await ProfileDeployment.create(tenant=sp_tenant, device=spC,
                                   profile_id="base", status="installed")
    # SP-B has no row for base at all: drift both membership views agree on.

    # SP-A holds exactly what its derived membership was served, with its declaration alert clear while its profile
    # alert is raised on the one stale column. management.* declarations always report active=false and are left out.
    sp_served_A = await ddm_manager.compute_device_declarations(spA, sp_tenant)
    spA.ddm_declaration_status = {
        d["Identifier"]: {"active": True, "valid": "valid"} for d in sp_served_A
        if not (d.get("Type") or "").startswith("com.apple.management.")}
    await spA.save(update_fields=["ddm_declaration_status"])

    sp_pm = _PM(sp_tenant)
    sp_derived_A, _ = await sp_pm.evaluate_device_profiles(
        spA, SP_PROFILES["profiles"], SP_GROUPS["groups"])
    sp_stale_A, _ = await sp_pm.evaluate_device_profiles(
        spA, SP_PROFILES["profiles"], SP_GROUPS["groups"],
        device_groups=list(spA.groups or []))
    check("fixture: the two membership views really do build different "
          "profile sets",
          {p["id"] for p in sp_derived_A} == {"base"}
          and {p["id"] for p in sp_stale_A} == {"base", "lab-only"})
    check("fixture: and the DDM half of it is not vacuous either",
          {d["Identifier"] for d in sp_served_A} >= {"mm.cfg.note1"}
          and "mm.cfg.lab-decl" not in {d["Identifier"] for d in sp_served_A}
          and bool(spA.ddm_declaration_status))

    sp_serial = {spA.id: "SP-A", spB.id: "SP-B", spC.id: "SP-C"}

    async def _sp_alerts():
        rows = await Alert.filter(tenant=sp_tenant).exclude(status="resolved").all()
        return {(sp_serial.get(r.device_id, "?"), r.rule_id):
                    (r.detail or {}).get("check") or {} for r in rows}

    def _sp_profiles(payload):
        return [p.get("profile") for p in (payload or {}).get("problems") or []]

    _orig_build_ctx = dispatcher._build_ctx

    async def _pre_fix_build_ctx(device, tenant, rules, device_groups=None,
                                 drift_ctx=None, flow_ctx=None):
        """Drift judged against the stored membership column, handed in rather than derived."""
        return await _orig_build_ctx(device, tenant, rules,
                                     list(device.groups or []), drift_ctx,
                                     flow_ctx)

    dispatcher._build_ctx = _pre_fix_build_ctx
    ddm_manager.invalidate_declaration_cache()
    try:
        for d in (spA, spB, spC):
            await dispatcher.evaluate_device(d)
    finally:
        dispatcher._build_ctx = _orig_build_ctx
    sp_before = await _sp_alerts()
    check("BEFORE the fix: a stale column raised profile drift on a device "
          "that is fine",
          _sp_profiles(sp_before.get(("SP-A", "sp-drift"))) == ["lab-only"])
    check("BEFORE the fix: the DDM alert on that same stale column was already "
          "clear, so an admin watched the two disagree",
          ("SP-A", "sp-decl") not in sp_before)
    check("BEFORE the fix: membership-independent drift fired either way",
          _sp_profiles(sp_before.get(("SP-B", "sp-drift"))) == ["base"])
    check("BEFORE the fix: a stale column hid profile drift the device "
          "really has",
          ("SP-C", "sp-drift") not in sp_before)

    await Alert.filter(tenant=sp_tenant).delete()
    ddm_manager.invalidate_declaration_cache()
    for d in (spA, spB, spC):
        await dispatcher.evaluate_device(d)
    sp_after = await _sp_alerts()
    check("a stale groups column no longer raises a profile drift alert, and "
          "the two drift alerts now agree about the same device",
          ("SP-A", "sp-drift") not in sp_after
          and ("SP-A", "sp-decl") not in sp_after)
    check("real profile drift still fires, naming the profile and its status",
          _sp_profiles(sp_after.get(("SP-B", "sp-drift"))) == ["base"]
          and (sp_after[("SP-B", "sp-drift")]["problems"][0].get("status")
               is None))
    check("profile drift the stale column used to hide is now visible",
          _sp_profiles(sp_after.get(("SP-C", "sp-drift"))) == ["lab-only"])

    # Separate tenant: reconciler would repair the staleness fixture induces via evaluate_device_apps (app_manager.py:253).
    _tenant_configs("profilereconcile", SP_DOC)
    prdir = base / "tenants" / "profilereconcile"
    (prdir / "groups.yaml").write_text(yaml.safe_dump(SP_GROUPS))
    (prdir / "profiles.yaml").write_text(yaml.safe_dump(SP_PROFILES))
    pr_tenant = await Tenant.create(id="profilereconcile", name="Profile Reconcile")
    spD = await _sp_device(pr_tenant, "SP-D", [], ["lab"])
    pr_stale_column = list(spD.groups or [])

    sp_judged = []
    _orig_eval = _PM.evaluate_device_profiles

    async def _recording_eval(self, device, profiles_config, groups_config,
                              device_groups=None):
        desired, held = await _orig_eval(self, device, profiles_config,
                                         groups_config,
                                         device_groups=device_groups)
        sp_judged.append((device.serial_number, device_groups, desired))
        return desired, held

    _PM.evaluate_device_profiles = _recording_eval
    try:
        await dispatcher.evaluate_device(spD)
    finally:
        _PM.evaluate_device_profiles = _orig_eval
    judged = [r for r in sp_judged if r[0] == "SP-D"]
    judged_groups = judged[-1][1] if judged else "never called"
    judged_desired = judged[-1][2] if judged else []

    pr_spawned = []
    _real_spawn = _reconciler._spawn

    def _capture_spawn(coro):
        pr_spawned.append(coro)
        coro.close()  # never talk to an MDM from here

    _reconciler._spawn = _capture_spawn
    try:
        pr_summary = await _reconciler.reconcile_tenant(pr_tenant, base)
    finally:
        _reconciler._spawn = _real_spawn
    pr_tasks = await Task.filter(tenant=pr_tenant, type="profile_install").all()
    enforced = [(t.details or {}).get("profile_info") or {} for t in pr_tasks]

    def _canon(profiles):
        return _json.dumps(sorted(profiles, key=lambda p: str(p.get("id"))),
                           sort_keys=True, default=str)

    pr_derived_D = GroupManager(str(pr_tenant.id)).evaluate_device_groups(
        spD, SP_GROUPS["groups"])
    check("fixture: SP-D's stored column disagreed with its real membership "
          "while the check ran",
          pr_stale_column == [] and pr_derived_D == ["labs"])
    check("the check scoped the desired set by deriving, not by reading the "
          "stored column",
          judged_groups is None
          and {p["id"] for p in judged_desired} == {"base", "lab-only"})
    check("the drift check judged the same profile set the reconciler "
          "enforces, byte for byte",
          bool(judged_desired) and len(enforced) == len(judged_desired)
          and _canon(judged_desired) == _canon(enforced))
    pr_alert = await Alert.filter(
        tenant=pr_tenant, device_id=spD.id, rule_id="sp-drift"
    ).exclude(status="resolved").first()
    check("and the alert it raised names exactly the profiles the reconciler "
          "queued",
          pr_alert is not None
          and sorted(_sp_profiles((pr_alert.detail or {}).get("check")))
          == sorted(p["id"] for p in enforced)
          and pr_summary["profiles_queued"] == len(enforced))

    # Two ways it goes silent: read skipped, or field dropped from .only() (returns None via getattr default).
    print("21) parked flow runs reach the check, gated and prefetched")
    import re as _re

    from controller.models.tenant import FlowRun
    from controller.services import compliance_catalog as _cc

    FLOW_DOC = {"rules": [
        {"id": "fl-parked", "name": "Parked too long", "severity": "yellow",
         "grace_minutes": 0, "check": {"type": "flow_parked_for", "hours": 4},
         "actions": [], "auto_resolve": True},
    ]}
    # The same fleet under a tenant with no rule of this type: the negative case, and the half that costs a query when
    # it breaks.
    NOFLOW_DOC = {"rules": [
        {"id": "nf-tag", "name": "Risky", "severity": "green", "grace_minutes": 0,
         "check": {"type": "tagged", "tags": ["risky"]},
         "actions": [], "auto_resolve": True},
    ]}
    _tenant_configs("sweepflow", FLOW_DOC)
    _tenant_configs("sweepnoflow", NOFLOW_DOC)
    fl_tenant = await Tenant.create(id="sweepflow", name="Flow Parked")
    nf_tenant = await Tenant.create(id="sweepnoflow", name="No Flow Rule")

    async def _fl_device(t, serial):
        return await Device.create(
            tenant=t, udid=f"UDID-{serial}", serial_number=serial,
            device_model="MacBookPro18,3", os_version="16.0",
            enrollment_state="enrolled", groups=[], tags=[],
            attributes={"SecurityInfo": {"FDE_Enabled": True}})

    async def _fl_run(t, dev, *, status, hours_ago, deadline):
        r = await FlowRun.create(
            tenant=t, device=dev, flow_id="onboarding", flow_hash="h" * 8,
            status=status, current_node="await-approval",
            waiting_signal="manual_gate", wait_deadline=deadline)
        # updated_at is auto_now, so every save restamps it and this check reads how long a run has been silent.
        # Backdated out of band, the way verify_flow_runs ages its parked_before fixtures.
        await FlowRun.filter(id=r.id).update(
            updated_at=datetime.now(timezone.utc) - timedelta(hours=hours_ago))
        await r.refresh_from_db()
        return r

    flA = await _fl_device(fl_tenant, "FL-A")  # parked 6h, past the 4h limit
    flB = await _fl_device(fl_tenant, "FL-B")  # parked 1h, inside the limit
    flC = await _fl_device(fl_tenant, "FL-C")  # no runs at all
    # A live rung of the escalation ladder, set in the future on purpose: the check judges silence rather than expiry,
    # so a run can be well past the rule's threshold with its own deadline not yet due.
    fl_soon = datetime.now(timezone.utc) + timedelta(minutes=30)
    fl_runA = await _fl_run(fl_tenant, flA, status="waiting", hours_ago=6,
                            deadline=fl_soon)
    await _fl_run(fl_tenant, flB, status="waiting", hours_ago=1, deadline=fl_soon)
    # A finished run carrying a stale deadline, aged past the limit. Artificial, since atc._complete nulls the deadline,
    # but it puts a row the prefetch reads into the table that must not become an alert.
    await _fl_run(fl_tenant, flB, status="completed", hours_ago=6,
                  deadline=fl_soon)
    nfA = await _fl_device(nf_tenant, "NF-A")
    nf_run = await _fl_run(nf_tenant, nfA, status="waiting", hours_ago=6,
                           deadline=fl_soon)

    fl_names = {flA.id: "FL-A", flB.id: "FL-B", flC.id: "FL-C"}

    async def _fl_alerts():
        rows = await Alert.filter(tenant=fl_tenant).exclude(status="resolved").all()
        return {(fl_names.get(r.device_id, "?"), r.rule_id):
                    (r.detail or {}).get("check") or {} for r in rows}

    def _fl_runs(payload):
        """The stable half of a finding's run list. hours_parked moves with the clock, so it is asserted against a bound
        rather than compared."""
        return [{k: r.get(k) for k in ("run_id", "flow_id", "node", "waiting_signal")}
                for r in (payload or {}).get("runs") or []]

    fl_check = {"type": "flow_parked_for", "hours": 4}
    fl_expect = [{"run_id": str(fl_runA.id), "flow_id": "onboarding",
                  "node": "await-approval", "waiting_signal": "manual_gate"}]

    # The webhook single-device path first: no prefetch, so _build_ctx reads the runs itself.
    for d in (flA, flB, flC):
        await dispatcher.evaluate_device(d)
    fl_unbatched = await _fl_alerts()
    fl_detail = fl_unbatched.get(("FL-A", "fl-parked"))
    check("the check fires end to end on the parked-overdue device, and only there",
          set(fl_unbatched) == {("FL-A", "fl-parked")})
    check("the alert names the parked run, its flow and the node it sits on",
          _fl_runs(fl_detail) == fl_expect)
    check("and carries how long it has been silent",
          len((fl_detail or {}).get("runs") or []) == 1
          and (fl_detail or {})["runs"][0].get("hours_parked") >= 5.9)

    await Alert.filter(tenant=fl_tenant).delete()

    from tortoise import connections as _fl_connections
    fl_conn = _fl_connections.get("default")
    fl_counts = {"n": 0}
    fl_fail = {"armed": False}
    fl_orig_q, fl_orig_qd = fl_conn.execute_query, fl_conn.execute_query_dict

    def _fl_is_run_select(sql):
        return sql.lstrip().upper().startswith("SELECT") and '"flow_runs"' in sql

    # Both fetch model instances via execute_query; execute_query_dict serves the .values() queries.
    async def _fl_spy_q(sql, values=None):
        if fl_fail["armed"] and _fl_is_run_select(sql):
            fl_fail["armed"] = False
            raise RuntimeError("injected flow-run prefetch failure")
        if _fl_is_run_select(sql):
            fl_counts["n"] += 1
        return await fl_orig_q(sql, values)

    async def _fl_spy_qd(sql, values=None):
        if _fl_is_run_select(sql):
            fl_counts["n"] += 1
        return await fl_orig_qd(sql, values)

    fl_conn.execute_query, fl_conn.execute_query_dict = _fl_spy_q, _fl_spy_qd
    try:
        fl_swept = await dispatcher.sweep(fl_tenant)
        fl_batched_q = fl_counts["n"]
        fl_batched = await _fl_alerts()

        # No rule of this type anywhere in the document, so neither entry point may touch the table.
        fl_counts["n"] = 0
        await dispatcher.sweep(nf_tenant)
        await dispatcher.evaluate_device(nfA)
        nf_q = fl_counts["n"]
        nf_alerts = await Alert.filter(tenant=nf_tenant).count()

        # A failed sweep-wide prefetch costs the cycle its batching, not the tenant its rules.
        await Alert.filter(tenant=fl_tenant).delete()
        fl_counts["n"] = 0
        fl_fail["armed"] = True
        fl_degraded_n = await dispatcher.sweep(fl_tenant)
        fl_degraded_q = fl_counts["n"]
        fl_degraded = await _fl_alerts()
    finally:
        fl_conn.execute_query, fl_conn.execute_query_dict = fl_orig_q, fl_orig_qd

    check("the batched sweep reaches the same verdicts as the per-device pass",
          fl_swept == 3 and set(fl_batched) == set(fl_unbatched)
          and _fl_runs(fl_batched.get(("FL-A", "fl-parked"))) == fl_expect)
    check(f"and pays one flow-run query for the whole sweep, not one per device "
          f"(got {fl_batched_q} for 3 devices)",
          fl_batched_q == 1)
    check(f"a tenant with no flow_parked_for rule never reads the table at all "
          f"(got {nf_q} queries)",
          nf_q == 0 and nf_alerts == 0)
    check("fixture: that tenant's own run would fire under a rule of this type, "
          "so the silence above is the gate and not an empty fixture",
          _cc.evaluate_check(fl_check, nfA, {"flow_runs": [nf_run]}) is not None)
    check(f"a failed prefetch degrades to per-device queries "
          f"(swept {fl_degraded_n}, {fl_degraded_q} queries)",
          fl_degraded_n == 3 and fl_degraded_q == 3)
    check("and the degraded sweep still raised the finding, naming the same run",
          set(fl_degraded) == set(fl_unbatched)
          and _fl_runs(fl_degraded.get(("FL-A", "fl-parked"))) == fl_expect)

    # Dropped fields read as None via getattr default, so check goes silent if field is missing from _FLOW_RUN_FIELDS.
    fl_reads = set(_re.findall(r'_run_field\(run,\s*"([a-z_]+)"\)',
                               inspect.getsource(_cc._flow_parked_for)))
    check(f"fixture: the read set really came out of the evaluator's source "
          f"({sorted(fl_reads)})",
          {"status", "wait_deadline", "updated_at", "flow_id",
           "current_node", "waiting_signal", "id"} <= fl_reads)
    fl_missing = sorted(fl_reads - set(dispatcher._FLOW_RUN_FIELDS))
    check(f"_FLOW_RUN_FIELDS covers every field the evaluator reads "
          f"(missing: {fl_missing})",
          not fl_missing)
    fl_full_row = await FlowRun.get(id=fl_runA.id)
    fl_partial_row = await FlowRun.filter(id=fl_runA.id).only(
        *dispatcher._FLOW_RUN_FIELDS).first()
    fl_from_full = _cc.evaluate_check(fl_check, flA, {"flow_runs": [fl_full_row]})
    fl_from_partial = _cc.evaluate_check(fl_check, flA,
                                         {"flow_runs": [fl_partial_row]})
    check("a narrowed row reaches the same verdict as the full row",
          _fl_runs((fl_from_full or {}).get("detail")) == fl_expect
          and _fl_runs((fl_from_partial or {}).get("detail")) == fl_expect)

    print("22) the tunable rates are read per call, not bound at import")
    # A knob bound at import keeps its startup value for the life of the process, so the environment and the number the
    # loop paces itself by can disagree silently.
    knobs = [
        (dispatcher._remediation_cooldown_minutes,
         "DISPATCHER_REMEDIATION_COOLDOWN_MINUTES", 60, "45", 45),
        (dispatcher._remediation_max_attempts,
         "DISPATCHER_REMEDIATION_MAX_ATTEMPTS", 3, "7", 7),
        (dispatcher._webhook_timeout_seconds,
         "DISPATCHER_WEBHOOK_TIMEOUT_SECONDS", 10.0, "2.5", 2.5),
        (dispatcher._webhook_max_attempts,
         "DISPATCHER_WEBHOOK_MAX_ATTEMPTS", 3, "5", 5),
    ]
    for fn, name, default, override, want in knobs:
        prior = os.environ.get(name)
        try:
            os.environ.pop(name, None)
            check(f"{name} unset reads as {default!r}",
                  fn() == default and type(fn()) is type(default))
            os.environ[name] = override
            check(f"...and {override!r} set after import is seen immediately",
                  fn() == want)
            os.environ[name] = "not-a-number"
            check("...and an unreadable value falls back to the default",
                  fn() == default)
        finally:
            if prior is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = prior
    check("the tightened limits this suite set before import still apply",
          dispatcher._remediation_cooldown_minutes() == 0
          and dispatcher._remediation_max_attempts() == 2)

    # == 23. Retiring a rule resolves the alerts it left behind ==
    # Out-of-scope and compliant resolves run per-rule; deleted or disabled rules never get visited.
    print("23) an alert whose rule was retired is resolved, and lets its tag go")

    def _orphan_rule(rule_id, tags=None, enabled=True):
        rule = {"id": rule_id, "name": rule_id, "severity": "yellow",
                "grace_minutes": 0, "check": {"type": "filevault_disabled"},
                "actions": [], "auto_resolve": False}
        if enabled is not True:
            rule["enabled"] = enabled
        if tags:
            rule["actions"] = [{"type": "assign_tag", "params": {"tags": tags}}]
        return rule

    # Two rules assign the same tag, so the refcount has something to hold, and a third stays live throughout as the
    # near miss.
    _tenant_configs("orphans", {"rules": [_orphan_rule("orph-gone", tags=["orphan-tag"]),
                                          _orphan_rule("orph-off", tags=["orphan-tag"]),
                                          _orphan_rule("orph-live")]})
    or_tenant = await Tenant.create(id="orphans", name="Orphans")
    or_dev = await Device.create(
        tenant=or_tenant, udid="UDID-ORPH", serial_number="ORPH-1",
        device_model="MacBookPro18,3", os_version="16.0",
        enrollment_state="enrolled", groups=[], tags=[],
        attributes={"SecurityInfo": {"FDE_Enabled": False}})
    # An alert from another engine on the same device, so the sweep has to tell what it raised from what it did not.
    await Alert.create(tenant=or_tenant, device=or_dev, rule_id="atc:in-setup",
                       severity="green", status="open",
                       summary="Held in Setup Assistant", detail={})

    async def or_alert(rule_id):
        return await Alert.filter(device_id=or_dev.id, rule_id=rule_id).first()

    async def or_sweep(doc=None):
        if doc is not None:
            _tenant_configs("orphans", doc)
            _tc.invalidate("orphans")
        await dispatcher.sweep(or_tenant)
        await webhook_handler.drain_deferred()
        await or_dev.refresh_from_db()

    await or_sweep()
    opened = [await or_alert(r) for r in ("orph-gone", "orph-off", "orph-live")]
    check("all three rules opened an alert", all(a is not None for a in opened))
    check("and the tag both taggers asked for is on the device",
          "orphan-tag" in (or_dev.tags or []))

    # Retire two of the three: one deleted outright, one turned off.
    await or_sweep({"rules": [_orphan_rule("orph-off", tags=["orphan-tag"], enabled=False),
                              _orphan_rule("orph-live")]})
    gone, off, live = (await or_alert("orph-gone"), await or_alert("orph-off"),
                       await or_alert("orph-live"))
    check("the deleted rule's alert is resolved",
          gone is not None and gone.status == "resolved")
    check("with a reason that says the rule is gone, not that the device was fixed",
          gone is not None and (gone.detail or {}).get("resolved_reason") == "rule removed")
    check("the disabled rule's alert is resolved too",
          off is not None and off.status == "resolved")
    check("and its reason tells the two cases apart",
          off is not None and (off.detail or {}).get("resolved_reason") == "rule disabled")
    check("near miss: the rule that is still on keeps its alert open",
          live is not None and live.status == "open")
    check("the tag comes off, because nothing holds it any more",
          "orphan-tag" not in (or_dev.tags or []))
    check("an alert from another engine on the same device is left alone",
          (await or_alert("atc:in-setup")).status == "open")

    print("23a) the refcount still holds a tag a live alert also asked for")
    await or_sweep({"rules": [_orphan_rule("orph-gone2", tags=["shared-tag"]),
                              _orphan_rule("orph-live2", tags=["shared-tag"])]})
    check("both rules opened and the shared tag is on", "shared-tag" in (or_dev.tags or []))

    await or_sweep({"rules": [_orphan_rule("orph-live2", tags=["shared-tag"])]})
    check("the retired rule's alert resolves",
          (await or_alert("orph-gone2")).status == "resolved")
    check("but the tag stays, because the live alert still asks for it",
          "shared-tag" in (or_dev.tags or []))

    print("23b) an unreadable document resolves nothing")
    # An absent or malformed dispatcher.yaml parses to {}, indistinguishable from a document whose rules were all
    # deleted, and one unparseable save must not resolve a tenant's whole board.
    (base / "tenants" / "orphans" / "dispatcher.yaml").write_text("rules: [{{{")
    _tc.invalidate("orphans")
    await dispatcher.sweep(or_tenant)
    await webhook_handler.drain_deferred()
    check("the live rule's alert survives a document that would not parse",
          (await or_alert("orph-live2")).status == "open")

    print("23c) an authored empty rule list does resolve")
    await or_sweep({"rules": []})
    check("deleting the last rule still cleans up after itself",
          (await or_alert("orph-live2")).status == "resolved")
    check("and the tag it held is released", "shared-tag" not in (or_dev.tags or []))
    check("the other engine's alert is still not this sweep's business",
          (await or_alert("atc:in-setup")).status == "open")

    # == 24. An admin can decline a queued destructive remediation ==
    # Without refusal route: only resolve (false compliance) or delete rule (answers for fleet).
    print("24) declining a queued remediation drops it and records the veto")
    rec_alert = await Alert.get_or_none(device_id=dev.id, rule_id="recovery")
    rec_pending = (rec_alert.detail or {}).get("pending_approvals") or []
    rec_key = rec_pending[0]["action_key"] if rec_pending else None
    status_before = rec_alert.status if rec_alert else None
    sev_before = rec_alert.severity if rec_alert else None
    lock_before = await Task.filter(device=dev, type="set_recovery_lock").count()

    result = await dispatcher.reject_remediation(
        rec_alert, rec_key, "admin@example.com", reason="not this machine")
    await rec_alert.refresh_from_db()
    rec_detail = rec_alert.detail or {}
    check("the queued request is gone", not rec_detail.get("pending_approvals"))
    check("the outcome names who declined it and why",
          "admin@example.com" in result["outcome"] and "not this machine" in result["outcome"])
    check("the veto is on the same ledger the approvals use",
          any(r.get("declined_by") == "admin@example.com"
              for r in rec_detail.get("remediations") or []))
    check("nothing was sent to the device",
          await Task.filter(device=dev, type="set_recovery_lock").count() == lock_before)
    check("the alert is not resolved: the device is still failing the check",
          rec_alert.status == status_before and rec_alert.status != "resolved")
    check("and its severity is left where it was",
          rec_alert.severity == sev_before)

    print("24a) the refusal sticks: the next evaluation does not ask again")
    # Without this the refusal would read as honoured while the request sat queued again a second later.
    await dispatcher.evaluate_device(dev)
    await webhook_handler.drain_deferred()
    await rec_alert.refresh_from_db()
    check("no new pending approval on the next pass",
          not (rec_alert.detail or {}).get("pending_approvals"))
    check("and the refusal is remembered on the alert",
          any(d.get("action_key") == rec_key
              for d in (rec_alert.detail or {}).get("declined_approvals") or []))

    print("24a-i) a veto that lands mid-sweep is not overwritten by it")
    # Refusal arriving between read and write must survive the older copy it overwrites.
    stale = await Alert.filter(device_id=dev.id, rule_id="risky-wipe").exclude(
        status="resolved").first()
    seeded = copy.deepcopy(stale.detail or {})
    seeded.setdefault("pending_approvals", []).append(
        {"action_key": "k-mid-sweep", "command": "erase",
         "requested_at": dispatcher._now().isoformat()})
    await Alert.filter(id=stale.id).update(detail=seeded)

    real_attempt = dispatcher._attempt_remediation
    vetoed = {"done": False}

    async def veto_mid_pass(tenant_, device_, rule_, alert_, action_, master_, detail_):
        # The refusal arrives while this pass holds its own copy of detail, and goes through the service to the row.
        if not vetoed["done"] and str(alert_.rule_id) == "risky-wipe":
            vetoed["done"] = True
            await dispatcher.reject_remediation(
                await Alert.get(id=alert_.id), "k-mid-sweep", "admin@example.com")
        return await real_attempt(tenant_, device_, rule_, alert_, action_,
                                  master_, detail_)

    dispatcher._attempt_remediation = veto_mid_pass
    try:
        await dispatcher.evaluate_device(dev)
        await webhook_handler.drain_deferred()
    finally:
        dispatcher._attempt_remediation = real_attempt
    await stale.refresh_from_db()
    after = stale.detail or {}
    check("the veto really landed while the pass was working", vetoed["done"])
    check("the pass does not resurrect the declined request",
          not any(pa.get("action_key") == "k-mid-sweep"
                  for pa in after.get("pending_approvals") or []))
    check("and the record of the refusal survives the pass writing over it",
          any(d.get("action_key") == "k-mid-sweep"
              for d in after.get("declined_approvals") or []))

    print("24b) declining twice is an error, not a second ledger line")
    try:
        await dispatcher.reject_remediation(rec_alert, rec_key, "admin@example.com")
        check("a second decline raises", False)
    except ValueError:
        check("a second decline raises", True)
    try:
        await dispatcher.approve_remediation(rec_alert, rec_key, "admin@example.com")
        check("and a declined request can no longer be approved", False)
    except ValueError:
        check("and a declined request can no longer be approved", True)

    # == 25. An app remediation can reach an app the device is not scoped into ==
    # Reconciler's check would no-op in-scope apps; counter still climbs, escalating a rule that queued nothing.
    print("25) an install_apps remediation reaches an out-of-scope app")
    APP_RULE = {"id": "app-remedy", "name": "App Remedy", "severity": "yellow",
                "grace_minutes": 0, "check": {"type": "filevault_disabled"},
                "actions": [{"type": "install_apps", "params": {"app_ids": ["lab-app"]}}],
                "auto_resolve": False}
    ap_dir = base / "tenants" / "apps-remedy"
    AP_APPS = {"apps": [
        # Scoped to a group this device is not in.
        {"id": "lab-app", "name": "Lab App", "bundle_id": "com.example.lab",
         "versions": [{"version": "1.0", "s3_key": "apps/lab-1.0.pkg",
                       "sha256": "e" * 64, "groups": ["teachers"]}]},
        # Its only version is still behind a wave that has not opened.
        {"id": "held-app", "name": "Held App", "bundle_id": "com.example.held",
         "versions": [{"version": "2.0", "s3_key": "apps/held-2.0.pkg",
                       "sha256": "f" * 64, "groups": ["teachers"],
                       "rollout": {"percent": 10, "interval_hours": 24,
                                   "start": "2099-01-01T00:00:00+00:00"}}]},
        # Installs outside /Applications, so it carries the escape hatch. Without an app that has this key, a key-set
        # assertion passes while the key is being dropped.
        {"id": "agent-app", "name": "Endpoint Agent", "bundle_id": "com.example.agent",
         "install_as_managed": False,
         "versions": [{"version": "3.0", "s3_key": "apps/agent-3.0.pkg",
                       "sha256": "a" * 64, "groups": ["teachers"]}]},
    ]}

    def _apps_remedy_configs(doc):
        # _tenant_configs rewrites every file in the directory, so the apps and
        # groups this section needs go back afterwards, not before.
        _tenant_configs("apps-remedy", doc)
        (ap_dir / "groups.yaml").write_text(yaml.safe_dump({"groups": [
            {"name": "teachers", "conditions": [
                {"type": "tag", "operator": "in", "value": ["teacher"]}]}]}))
        (ap_dir / "apps.yaml").write_text(yaml.safe_dump(AP_APPS))
        _tc.invalidate("apps-remedy")

    _apps_remedy_configs({"rules": [APP_RULE]})
    ap_tenant = await Tenant.create(id="apps-remedy", name="Apps Remedy")
    ap_dev = await Device.create(
        tenant=ap_tenant, udid="UDID-APPREM", serial_number="APPREM-1",
        device_model="MacBookPro18,3", os_version="16.0",
        enrollment_state="enrolled", groups=[], tags=[],
        attributes={"SecurityInfo": {"FDE_Enabled": False}})

    await dispatcher.evaluate_device(ap_dev, tenant=ap_tenant)
    await webhook_handler.drain_deferred()
    ap_tasks = await Task.filter(device=ap_dev, type="app_install").all()
    check("the remediation queued the app the device is not scoped into",
          len(ap_tasks) == 1)
    ap_details = (ap_tasks[0].details or {}) if ap_tasks else {}
    check("the task carries the version from apps.yaml",
          (ap_details.get("app_info") or {}).get("version") == "1.0")
    check("in the shape the install handler reads",
          set(ap_details.get("app_info") or {}) ==
          {"app_id", "name", "bundle_id", "version", "s3_key", "sha256",
           "install_options"})
    check("and it names the rule as the install source, so the hold applies",
          _pm.remediation_rule_id(ap_details.get(_pm.INSTALL_SOURCE_KEY)) == "app-remedy")
    ap_alert = await Alert.get_or_none(device_id=ap_dev.id, rule_id="app-remedy")
    check("the ledger says one install, not zero",
          any("queued 1 app install" in (r.get("outcome") or "")
              for r in (ap_alert.detail or {}).get("remediations") or []))

    print("25-i) an app that installs outside /Applications keeps its escape hatch")
    # Without install_as_managed false, such packages are refused by the Mac after acknowledgment.
    _apps_remedy_configs({"rules": [dict(APP_RULE, id="app-remedy-agent", actions=[
        {"type": "install_apps", "params": {"app_ids": ["agent-app"]}}])]})
    agent_dev = await Device.create(
        tenant=ap_tenant, udid="UDID-APPAGENT", serial_number="APPAGENT-1",
        device_model="MacBookPro18,3", os_version="16.0",
        enrollment_state="enrolled", groups=[], tags=[],
        attributes={"SecurityInfo": {"FDE_Enabled": False}})
    await dispatcher.evaluate_device(agent_dev, tenant=ap_tenant)
    await webhook_handler.drain_deferred()
    agent_task = await Task.filter(device=agent_dev, type="app_install").first()
    agent_info = (agent_task.details or {}).get("app_info") if agent_task else None
    check("the remediation queued it", agent_task is not None)
    check("and carried install_as_managed through as authored",
          (agent_info or {}).get("install_as_managed") is False)
    check("the key set matches what the scoped path builds for the same app",
          set(agent_info or {}) ==
          {"app_id", "name", "bundle_id", "version", "s3_key", "sha256",
           "install_options", "install_as_managed"})

    print("25a) a rollout wave is still honoured, because scope and pace are "
          "different questions")
    _apps_remedy_configs({"rules": [dict(APP_RULE, id="app-remedy-held", actions=[
        {"type": "install_apps", "params": {"app_ids": ["held-app"]}}])]})
    held_dev = await Device.create(
        tenant=ap_tenant, udid="UDID-APPHELD", serial_number="APPHELD-1",
        device_model="MacBookPro18,3", os_version="16.0",
        enrollment_state="enrolled", groups=[], tags=[],
        attributes={"SecurityInfo": {"FDE_Enabled": False}})
    await dispatcher.evaluate_device(held_dev, tenant=ap_tenant)
    await webhook_handler.drain_deferred()
    check("an app whose only version is still held queues nothing",
          await Task.filter(device=held_dev, type="app_install").count() == 0)

    print("25a-i) and queuing nothing does not walk the rule to escalation")
    # Held wave is configuration; counting it escalates a yellow to red over untried work.
    held_alert = await Alert.get_or_none(device_id=held_dev.id,
                                         rule_id="app-remedy-held")
    sev_first = held_alert.severity if held_alert else None
    for _ in range(4):
        await dispatcher.evaluate_device(held_dev, tenant=ap_tenant)
    await webhook_handler.drain_deferred()
    await held_alert.refresh_from_db()
    held_detail = held_alert.detail or {}
    check("no attempt is counted for a wave that has not opened",
          not any(v for v in (held_detail.get("attempt_counts") or {}).values()))
    check("the alert is not marked as a failed remediation",
          not held_detail.get("remediation_failed"))
    check("and its severity is where the check put it",
          held_alert.severity == sev_first)
    check("while the ledger still says what happened each pass",
          any("queued 0 app install" in (r.get("outcome") or "")
              for r in held_detail.get("remediations") or []))

    print("25a-ii) near miss: a remediation that did queue still counts")
    ap_alert2 = await Alert.get_or_none(device_id=ap_dev.id, rule_id="app-remedy")
    check("the successful install counted its attempt",
          any(v for v in ((ap_alert2.detail or {}).get("attempt_counts") or {}).values()))

    print("25b) an app id that is not in apps.yaml queues nothing")
    _apps_remedy_configs({"rules": [dict(APP_RULE, id="app-remedy-ghost", actions=[
        {"type": "install_apps", "params": {"app_ids": ["no-such-app"]}}])]})
    ghost_dev = await Device.create(
        tenant=ap_tenant, udid="UDID-APPGHOST", serial_number="APPGHOST-1",
        device_model="MacBookPro18,3", os_version="16.0",
        enrollment_state="enrolled", groups=[], tags=[],
        attributes={"SecurityInfo": {"FDE_Enabled": False}})
    await dispatcher.evaluate_device(ghost_dev, tenant=ap_tenant)
    await webhook_handler.drain_deferred()
    check("an unknown app id is a no-op, not a crash",
          await Task.filter(device=ghost_dev, type="app_install").count() == 0)

    # == 26. A rule with two webhook targets notifies both ==
    # notified_severity is per-target map; one target's delivery cannot starve another.
    print("26) a rule with two webhook targets notifies both")
    WEBHOOK_CODE[0] = 200
    MW_DOC = {
        "webhooks": [
            {"name": "hook-a", "url": "https://hooks.slack.com/a", "secret": "sa"},
            {"name": "hook-b", "url": "https://hooks.slack.com/b", "secret": "sb"},
        ],
        "rules": [
            {"id": "mw-rule", "name": "Multi webhook", "severity": "yellow",
             "grace_minutes": 0, "check": {"type": "filevault_disabled"},
             "actions": [
                 {"type": "webhook", "params": {"target": "hook-a"}},
                 {"type": "webhook", "params": {"target": "hook-b"}},
             ],
             "auto_resolve": True},
        ],
    }
    _tenant_configs("multiwebhook", MW_DOC)
    mw_tenant = await Tenant.create(id="multiwebhook", name="Multi Webhook")
    mw_dev = await Device.create(
        tenant=mw_tenant, udid="UDID-MW", serial_number="MW-1",
        device_model="MacBookPro18,3", os_version="16.0",
        enrollment_state="enrolled", groups=[], tags=[],
        attributes={"SecurityInfo": {"FDE_Enabled": False}})

    def _mw_hits():
        # Filtered to this section's two exact URLs: retries of earlier sections' failed deliveries can still arrive.
        return [c["url"] for c in CAPTURED
                if c["url"] in ("https://hooks.slack.com/a",
                                "https://hooks.slack.com/b")]

    await dispatcher.evaluate_device(mw_dev, tenant=mw_tenant)
    await asyncio.sleep(0.3)
    check("both webhook targets were notified when the alert opened",
          sorted(_mw_hits()) == ["https://hooks.slack.com/a",
                                 "https://hooks.slack.com/b"])
    mw_alert = await Alert.get_or_none(device_id=mw_dev.id, rule_id="mw-rule")
    mw_ns = (mw_alert.detail or {}).get("notified_severity")
    check("notification state is tracked per target",
          isinstance(mw_ns, dict) and mw_ns.get("hook-a") == "yellow"
          and mw_ns.get("hook-b") == "yellow")

    mw_before = len(_mw_hits())
    await dispatcher.evaluate_device(mw_dev, tenant=mw_tenant)
    await asyncio.sleep(0.2)
    check("a re-evaluation at the same severity re-notifies neither target",
          len(_mw_hits()) == mw_before)

    print("26a) only a target whose own state is stale is re-notified")
    mw_detail = dict(mw_alert.detail or {})
    mw_detail["notified_severity"] = {"hook-a": "yellow", "hook-b": "green"}
    await Alert.filter(id=mw_alert.id).update(detail=mw_detail)
    await dispatcher.evaluate_device(mw_dev, tenant=mw_tenant)
    await asyncio.sleep(0.2)
    mw_new = _mw_hits()[mw_before:]
    check("the stale target was caught up and the current one left alone",
          mw_new == ["https://hooks.slack.com/b"])

    print("26b) a pre-map scalar reads as the answer for every target")
    # Alerts written before the map carry one scalar, which must not re-notify a long-open alert on upgrade.
    mw_detail = dict(mw_alert.detail or {})
    mw_detail["notified_severity"] = "yellow"
    await Alert.filter(id=mw_alert.id).update(detail=mw_detail)
    mw_before = len(_mw_hits())
    await dispatcher.evaluate_device(mw_dev, tenant=mw_tenant)
    await asyncio.sleep(0.2)
    check("a scalar at the current severity notifies nobody again",
          len(_mw_hits()) == mw_before)

    # == 27. Approval races: the pending entry is claimed before dispatch ==
    # Claimed on stored row, not caller's copy; stale approve cannot erase refusal or double-execute.
    print("27) an approve holding a stale copy honours a decline that landed first")
    RACE_DOC = {"rules": [
        {"id": "race-wipe", "name": "Wipe race", "severity": "black",
         "grace_minutes": 0, "check": {"type": "tagged", "tags": ["race"]},
         "actions": [{"type": "send_command", "params": {
             "command": "erase", "params": {"pin": "654321"}}}],
         "auto_resolve": False},
    ]}
    _tenant_configs("appraces", RACE_DOC)
    race_tenant = await Tenant.create(id="appraces", name="Approval Races")
    race_dev = await Device.create(
        tenant=race_tenant, udid="UDID-RACE-1", serial_number="RACE-1",
        device_model="MacBookPro18,3", os_version="16.0",
        enrollment_state="enrolled", groups=[], tags=["race"], attributes={})
    await dispatcher.evaluate_device(race_dev, tenant=race_tenant)
    race_alert = await Alert.get_or_none(device_id=race_dev.id, rule_id="race-wipe")
    race_key = (race_alert.detail or {})["pending_approvals"][0]["action_key"]
    # Loaded BEFORE the decline, the way a second admin's request would be.
    stale_approve_copy = await Alert.get(id=race_alert.id)
    await dispatcher.reject_remediation(
        await Alert.get(id=race_alert.id), race_key, "admin@example.com",
        reason="wrong machine")
    try:
        await dispatcher.approve_remediation(stale_approve_copy, race_key,
                                             "admin2@example.com")
        check("approving from the stale copy raises", False)
    except ValueError:
        check("approving from the stale copy raises", True)
    check("and the vetoed erase never went out",
          await Task.filter(device=race_dev, type="erase").count() == 0)
    fresh_race = await Alert.get(id=race_alert.id)
    check("the record of the decline survives the attempt",
          any(d.get("action_key") == race_key
              for d in (fresh_race.detail or {}).get("declined_approvals") or []))

    print("27a) two concurrent approvals execute the command once")
    race_dev2 = await Device.create(
        tenant=race_tenant, udid="UDID-RACE-2", serial_number="RACE-2",
        device_model="MacBookPro18,3", os_version="16.0",
        enrollment_state="enrolled", groups=[], tags=["race"], attributes={})
    await dispatcher.evaluate_device(race_dev2, tenant=race_tenant)
    race_alert2 = await Alert.get_or_none(device_id=race_dev2.id, rule_id="race-wipe")
    race_key2 = (race_alert2.detail or {})["pending_approvals"][0]["action_key"]
    copy1 = await Alert.get(id=race_alert2.id)
    copy2 = await Alert.get(id=race_alert2.id)
    outcomes = await asyncio.gather(
        dispatcher.approve_remediation(copy1, race_key2, "one@example.com"),
        dispatcher.approve_remediation(copy2, race_key2, "two@example.com"),
        return_exceptions=True)
    oks = [r for r in outcomes if isinstance(r, dict)]
    errs = [r for r in outcomes if isinstance(r, ValueError)]
    check("exactly one approval won the claim", len(oks) == 1 and len(errs) == 1)
    check("the erase was dispatched once",
          await Task.filter(device=race_dev2, type="erase").count() == 1)
    await race_alert2.refresh_from_db()
    race_detail2 = race_alert2.detail or {}
    check("the pending entry is gone", not race_detail2.get("pending_approvals"))
    check("the executed approval is on the alert's own record",
          any(a.get("action_key") == race_key2
              for a in race_detail2.get("approved_approvals") or []))
    check("and on the ledger, naming who approved",
          any(r.get("approved_by") in ("one@example.com", "two@example.com")
              for r in race_detail2.get("remediations") or []))

    print("27b) a pass in flight during the approval does not resurrect it")
    # The pass's copy of detail predates the claim and still carries the entry, so the end-of-pass merge has to fold the
    # removal back in.
    pass_detail = copy.deepcopy(race_detail2)
    pass_detail["pending_approvals"] = [
        {"action_key": race_key2, "command": "erase",
         "requested_at": "2020-01-01T00:00:00+00:00"}]
    merged = await dispatcher._with_fresh_vetoes(race_alert2, pass_detail)
    check("the merged write drops the executed entry",
          not any(pa.get("action_key") == race_key2
                  for pa in merged.get("pending_approvals") or []))
    check("and carries the approval record forward",
          any(a.get("action_key") == race_key2
              for a in merged.get("approved_approvals") or []))
    # A request queued AFTER the approval is a new question and survives.
    later_entry = {"action_key": race_key2, "command": "erase",
                   "requested_at": dispatcher._now().isoformat()}
    merged2 = await dispatcher._with_fresh_vetoes(
        race_alert2, {"pending_approvals": [later_entry]})
    check("a request queued after the approval survives the merge",
          any(pa.get("action_key") == race_key2
              for pa in merged2.get("pending_approvals") or []))

    # == 28. The private-webhook opt-out is scoped, not global ==
    # Allowlist names what's deliverable; ALLOW_PRIVATE turns off SSRF guard for all tenants at once.
    print("28) the private-address allowlist admits only what it names")
    prior_allow = os.environ.pop("DISPATCHER_WEBHOOK_ALLOW_PRIVATE", None)
    prior_list = os.environ.pop("DISPATCHER_WEBHOOK_PRIVATE_ALLOWLIST", None)
    try:
        check("a private target is blocked by default",
              await dispatcher._webhook_target_blocked("http://10.0.0.5/hook") is True)
        os.environ["DISPATCHER_WEBHOOK_PRIVATE_ALLOWLIST"] = \
            "10.0.0.5, 192.168.1.0/24"
        check("a listed private ip is deliverable",
              await dispatcher._webhook_target_blocked("http://10.0.0.5/hook") is False)
        check("a private ip inside a listed CIDR is deliverable",
              await dispatcher._webhook_target_blocked("http://192.168.1.7/hook") is False)
        check("an unlisted private ip stays blocked",
              await dispatcher._webhook_target_blocked("http://10.9.9.9/hook") is True)
        check("a public target needs no listing",
              await dispatcher._webhook_target_blocked("https://8.8.8.8/hook") is False)
        os.environ["DISPATCHER_WEBHOOK_PRIVATE_ALLOWLIST"] = "localhost"
        check("a listed hostname is deliverable wherever it resolves",
              await dispatcher._webhook_target_blocked("http://localhost:9099/hook")
              is False)
        check("and does not admit an unrelated private ip",
              await dispatcher._webhook_target_blocked("http://10.0.0.5/hook") is True)
        os.environ.pop("DISPATCHER_WEBHOOK_PRIVATE_ALLOWLIST", None)
        os.environ["DISPATCHER_WEBHOOK_ALLOW_PRIVATE"] = "true"
        check("the deprecated global boolean still delivers everywhere",
              await dispatcher._webhook_target_blocked("http://10.0.0.5/hook") is False)
    finally:
        if prior_allow is None:
            os.environ.pop("DISPATCHER_WEBHOOK_ALLOW_PRIVATE", None)
        else:
            os.environ["DISPATCHER_WEBHOOK_ALLOW_PRIVATE"] = prior_allow
        if prior_list is None:
            os.environ.pop("DISPATCHER_WEBHOOK_PRIVATE_ALLOWLIST", None)
        else:
            os.environ["DISPATCHER_WEBHOOK_PRIVATE_ALLOWLIST"] = prior_list

    await webhook_handler.drain_deferred()
    await Tortoise.close_connections()

    print()
    if _FAILURES:
        print(f"FAILED ({len(_FAILURES)}): {_FAILURES}")
        return 1
    print("ALL DISPATCHER E2E CHECKS PASSED")
    return 0


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
