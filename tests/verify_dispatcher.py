"""Backend E2E for the Dispatcher compliance engine, on in-memory sqlite.

Covers the spec's acceptance criteria (2.8): grace -> open, severity ranking,
ack/resolve, auto-resolve + reversible-tag removal, single-alert dedup, audited
non-destructive remediation, dry-run records-without-acting, destructive ->
queued-for-approval (never auto), loop-protection + escalation, and a signed
(HMAC) webhook whose failure never blocks evaluation. Also checks webhook
secret redaction.

Run:  PYTHONPATH=. ./.venv/bin/python tests/verify_dispatcher.py
"""

import asyncio
import hashlib
import hmac
import os
import sys
import tempfile
from pathlib import Path

# Tighten remediation limits for the loop-protection test BEFORE importing the
# dispatcher (it reads these at import time).
os.environ["DISPATCHER_REMEDIATION_COOLDOWN_MINUTES"] = "0"
os.environ["DISPATCHER_REMEDIATION_MAX_ATTEMPTS"] = "2"
os.environ["DISPATCHER_AUTO_REMEDIATION_ENABLED"] = "true"

import yaml
from tortoise import Tortoise

_FAILURES = []
CAPTURED = []
WEBHOOK_CODE = [200]  # mutable: flip to 500 to simulate delivery failure


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
            "actions": [{"type": "send_command", "params": {"command": "erase"}}],
            "auto_resolve": False,
        },
        {  # destructive remediation WITH a secret param -> must not leak it
            "id": "recovery", "name": "Set recovery lock", "severity": "black",
            "check": {"type": "tagged", "tags": ["risky"]}, "grace_minutes": 0,
            "actions": [{"type": "send_command", "params": {
                "command": "set_recovery_lock", "params": {"new_password": "supersecret"}}}],
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
    (tdir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": [
        {"id": "enforce-fv", "name": "Enforce FileVault", "payload": {"PayloadType": "com.apple.MCX.FileVault2"}}]}))
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

    from controller.models.tenant import Tenant, Device, Alert, Task
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

    # ── 1) grace: first eval -> pending (no actions), not open ────────────────
    print("1) violation creates a pending alert during grace (no actions yet)")
    await dispatcher.evaluate_device(dev)
    a = await fv_alert()
    check("pending alert created", a is not None and a.status == "pending")
    check("no webhook fired during grace", len(CAPTURED) == 0)
    await dev.refresh_from_db()
    check("no reversible tag applied during grace", "noncompliant-fv" not in dev.tags)

    # ── 2) grace elapses -> open, fires webhook (signed) + tag ────────────────
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

    # ── 3) dedup: repeated evals update ONE alert, never spam ─────────────────
    print("3) repeated evaluations keep a single alert (no duplicates)")
    await dispatcher.evaluate_device(dev)
    await dispatcher.evaluate_device(dev)
    n = await Alert.filter(device_id=dev.id, rule_id="fv-alert").count()
    check("still exactly one fv-alert row", n == 1)

    # ── 4) dry-run remediation records without acting ─────────────────────────
    print("4) dry-run remediation records but sends no command")
    dry = await Alert.get_or_none(device_id=dev.id, rule_id="dry")
    ledger = (dry.detail or {}).get("remediations", []) if dry else []
    check("dry-run recorded in the ledger", any("dry-run" in r.get("outcome", "") for r in ledger))
    refreshed = await Task.filter(device=dev, type="refresh_info").count()
    check("no refresh_info command task created by dry-run", refreshed == 0)

    # ── 5) audited non-destructive remediation runs as dispatcher:<rule> ──────
    print("5) real remediation runs through the audited path as dispatcher:<rule>")
    await asyncio.sleep(0.2)
    rem_tasks = await Task.filter(device=dev, type="profile_install", user="dispatcher:fv-remediate").all()
    check("profile_install task created by remediation", len(rem_tasks) >= 1)

    # ── 6) loop protection: halts after N attempts and escalates ──────────────
    print("6) loop protection halts after N attempts and escalates")
    # cooldown=0, max=2. It already attempted once in step 2/5. Drive more evals.
    for _ in range(4):
        await dispatcher.evaluate_device(dev)
        await asyncio.sleep(0.05)
    rem = await Alert.get_or_none(device_id=dev.id, rule_id="fv-remediate")
    detail = rem.detail or {}
    check("remediation marked failed after max attempts", detail.get("remediation_failed") is True)
    check("severity escalated above yellow", dispatcher.SEVERITY_RANK.get(rem.severity, 0) > dispatcher.SEVERITY_RANK["yellow"])

    # ── 7) destructive remediation is queued for approval, never auto-fired ───
    print("7) destructive remediation is queued for approval, not auto-fired")
    dev.tags = ["risky"]
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
    # secret leak: a destructive remediation's secret param must never appear in
    # the alert detail exposed by GET /alerts (action_key + params both redacted).
    import json as _json
    rec = await Alert.get_or_none(device_id=dev.id, rule_id="recovery")
    detail_json = _json.dumps(rec.detail or {}) if rec else ""
    check("queued (pending approval exists for recovery)",
          bool((rec.detail or {}).get("pending_approvals")) if rec else False)
    check("secret param NOT leaked into alert detail", "supersecret" not in detail_json)

    # ── 8) auto-resolve: compliant device resolves alert + removes tag ────────
    print("8) becoming compliant auto-resolves and removes the reversible tag")
    dev.attributes = {"SecurityInfo": {"FDE_Enabled": True}}  # FileVault ON now
    await dev.save(update_fields=["attributes"])
    await dispatcher.evaluate_device(dev)
    a = await fv_alert()
    await dev.refresh_from_db()
    check("fv-alert auto-resolved", a.status == "resolved")
    check("noncompliant-fv tag removed on resolve", "noncompliant-fv" not in dev.tags)

    # ── 9) webhook failure never blocks evaluation ────────────────────────────
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

    # ── 10) webhook secret redaction (unit) ───────────────────────────────────
    print("10) webhook url/secret are redacted from API responses")
    import controller.api.main as apimain
    red = apimain._redact_dispatcher_config(
        {"webhooks": [{"name": "x", "url": "https://secret", "secret": "s"}]}
    )
    check("url redacted", red["webhooks"][0]["url"] == "***redacted***")
    check("secret redacted", red["webhooks"][0]["secret"] == "***redacted***")

    await asyncio.sleep(0.2)
    await Tortoise.close_connections()

    print()
    if _FAILURES:
        print(f"FAILED ({len(_FAILURES)}): {_FAILURES}")
        return 1
    print("ALL DISPATCHER E2E CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
