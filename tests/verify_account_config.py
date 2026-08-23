"""Backend E2E for the account-config and firmware-lock ATC nodes and device secret escrow, on in-memory sqlite (no
docker, no MDM network).

Covers account_hash.password_hash_blob (SALTED-SHA512-PBKDF2, 128, 32) and that the on-wire passwordHash verifies
against the escrowed password. Then the configure_accounts node: AccountConfiguration keys for standard/admin/skip,
managed-admin provisioning and escrow, and password redaction from the audit task. Then set_firmware_lock choosing
SetRecoveryLock on Apple silicon, SetFirmwarePassword on Intel and nothing on an unknown architecture, each escrowing
its password. Finally device_secrets.reveal, which returns the plaintext, stamps the ledger and raises a single
Dispatcher alert, and the flows.yaml validator for both node types.

Run:  PYTHONPATH=. ./.venv/bin/python tests/verify_account_config.py Exits non-zero if any check fails.
"""

import hashlib
import os
import plistlib
import tempfile
from pathlib import Path

# Encryption-at-rest must be configured before crypto_secrets is first used (escrow refuses to store plaintext).
# crypto_secrets reads the env lazily.
from cryptography.fernet import Fernet

os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import yaml
from tortoise import Tortoise

_FAILURES = []

# Captured MDM commands (the fake connector appends here).
ACCOUNT_CMDS = []  # list of kwargs dicts from account_configuration
RAW_CMDS = []  # list of (request_type, fields) from send_raw_command


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        _FAILURES.append(name)


class FakeConnector:
    def __init__(self, *a, **k):
        pass

    async def account_configuration(self, udid, **kwargs):
        ACCOUNT_CMDS.append({"udid": udid, **kwargs})
        return {"command_uuid": "u-acct"}

    async def send_raw_command(self, udid, request_type, fields):
        RAW_CMDS.append((request_type, fields))
        return {"command_uuid": "u-raw"}

    async def close(self):
        pass


def _write_configs(base: Path, flow: dict):
    tdir = base / "tenants" / "default"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "config.yaml").write_text(yaml.safe_dump(
        {"tenant": {"id": "default", "name": "Default", "allowed_users": []}}))
    (tdir / "groups.yaml").write_text(yaml.safe_dump({"groups": []}))
    (tdir / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
    (tdir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": []}))
    (tdir / "flows.yaml").write_text(yaml.safe_dump({"flow": flow}))
    return tdir


FLOW = {
    "id": "acct",
    "name": "Account flow",
    "enabled": True,
    "nodes": [
        {"id": "s", "type": "start", "params": {"kind": "enroll_dep"}, "next": "cfg"},
        {"id": "cfg", "type": "configure_accounts", "next": "fw", "params": {
            "primary_account": "prompt_standard",
            "lock_primary_account": True,
            "managed_admin": True,
            "managed_admin_shortname": "mmadmin",
            "managed_admin_password_source": "generate",
        }},
        {"id": "fw", "type": "set_firmware_lock", "next": "e",
         "params": {"password_source": "generate"}},
        {"id": "e", "type": "end", "params": {}},
    ],
}


async def main():
    base = Path(tempfile.mkdtemp())
    os.environ["YAML_CONFIG_PATH"] = str(base)
    tdir = _write_configs(base, FLOW)

    import controller.services.mdm_connector as mc
    mc.MDMConnector = FakeConnector

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    from controller.models.tenant import Tenant, Device, Task, Alert, DeviceSecret
    from controller.services import account_hash, atc, device_secrets
    from controller.utils.yaml_validator import YAMLValidator

    tenant = await Tenant.create(id="default", name="Default")

    #  0) account_hash unit checks
    print("0) account_hash builds a valid SALTED-SHA512-PBKDF2 blob")
    blob = account_hash.password_hash_blob("hunter2", salt=b"\x01" * 32)
    parsed = plistlib.loads(blob)
    inner = parsed.get("SALTED-SHA512-PBKDF2", {})
    check("passwordHash has the SALTED-SHA512-PBKDF2 key", bool(inner))
    check("entropy is 128 bytes", len(inner.get("entropy", b"")) == 128)
    check("salt is 32 bytes", len(inner.get("salt", b"")) == 32)
    check("iterations is 40000", inner.get("iterations") == 40000)
    recomputed = hashlib.pbkdf2_hmac("sha512", b"hunter2", b"\x01" * 32, 40000, dklen=128)
    check("entropy == PBKDF2-HMAC-SHA512(pw, salt, iters, 128)", inner["entropy"] == recomputed)
    pw = account_hash.generate_password(length=20)
    check("generate_password honours length", len(pw) == 20)
    check("generate_password includes a digit", any(c.isdigit() for c in pw))

    async def new_device(serial, *, apple_silicon=None):
        attrs = {}
        if apple_silicon is not None:
            attrs["IsAppleSilicon"] = apple_silicon
        return await Device.create(
            tenant=tenant, udid=f"UDID-{serial}", serial_number=serial,
            device_model="MacBookPro18,3", os_version="14.5",
            enrollment_state="enrolled", groups=[], tags=[], attributes=attrs,
            dep_profile_uuid=f"DEP-{serial}")

    #  1) configure_accounts sends AccountConfiguration + escrows the admin
    print("1) configure_accounts: standard primary + managed admin, escrowed")
    dev = await new_device("MAC-1", apple_silicon=True)
    runs = await atc.start_flows_for_event(dev, "enroll_dep")
    check("one run started and completed", len(runs) == 1 and runs[0].status == "completed")

    check("AccountConfiguration was sent", len(ACCOUNT_CMDS) == 1)
    ac = ACCOUNT_CMDS[0]
    check("standard user -> set_primary_as_regular=True", ac.get("set_primary_as_regular") is True)
    check("not skipping primary account", ac.get("skip_primary_setup") is False)
    check("lock_primary_account passed through", ac.get("lock_primary_account") is True)
    admins = ac.get("auto_setup_admins") or []
    check("one managed admin provisioned", len(admins) == 1)
    check("managed admin short name", admins and admins[0].get("shortName") == "mmadmin")
    check("managed admin hidden by default", admins and admins[0].get("hidden") is True)
    check("managed admin carries a passwordHash <data> blob",
          admins and isinstance(admins[0].get("passwordHash"), (bytes, bytearray)))

    secret = await DeviceSecret.get_or_none(device_id=dev.id,
                                            kind=DeviceSecret.KIND_MANAGED_ADMIN)
    check("managed-admin password escrowed", secret is not None)
    check("escrow starts unrevealed", secret and secret.revealed_at is None)
    check("escrow value is not stored in plaintext",
          secret and secret.value_enc and "mmadmin" not in secret.value_enc)

    task = await Task.filter(device_id=dev.id, type="account_configuration").first()
    check("audit task created", task is not None)
    check("audit task details carry NO password",
          task is not None and "password" not in yaml.safe_dump(task.details or {}).lower())

    #  2) the on-wire passwordHash verifies against the escrowed password
    print("2) escrowed password reproduces the on-wire passwordHash")
    revealed = await device_secrets.reveal(secret, "admin:tester@example.com")
    check("reveal returns a plaintext", bool(revealed))
    ph = plistlib.loads(bytes(admins[0]["passwordHash"]))["SALTED-SHA512-PBKDF2"]
    recomputed = hashlib.pbkdf2_hmac("sha512", (revealed or "").encode(),
                                     ph["salt"], ph["iterations"], dklen=128)
    check("passwordHash entropy matches PBKDF2(revealed_password)", recomputed == ph["entropy"])

    #  3) reveal ledger and dispatcher alert
    print("3) break the glass stamps the ledger and raises one alert")
    await secret.refresh_from_db()
    check("reveal stamped the ledger (count=1, broken)",
          secret.reveal_count == 1 and secret.revealed_at is not None)
    check("reveal recorded the actor", secret.revealed_by == "admin:tester@example.com")
    alert = await Alert.filter(device_id=dev.id,
                               rule_id="breakglass:managed_admin_password").first()
    check("break-glass alert raised", alert is not None and alert.status == "open")
    check("alert detail marks break_glass", alert and (alert.detail or {}).get("kind") == "break_glass")

    revealed2 = await device_secrets.reveal(secret, "admin:other@example.com")
    await secret.refresh_from_db()
    check("second reveal returns the same secret", revealed2 == revealed)
    check("second reveal bumps the count to 2", secret.reveal_count == 2)
    alerts = await Alert.filter(device_id=dev.id,
                                rule_id="breakglass:managed_admin_password").count()
    check("still a single break-glass alert (updated, not duplicated)", alerts == 1)

    #  4) set_firmware_lock: Apple silicon -> SetRecoveryLock (escrowed)
    print("4) set_firmware_lock chooses the command by architecture")
    rl = await DeviceSecret.get_or_none(device_id=dev.id, kind=DeviceSecret.KIND_RECOVERY_LOCK)
    check("recovery-lock password escrowed for Apple silicon", rl is not None)
    recovery_cmds = [f for (rt, f) in RAW_CMDS if rt == "SetRecoveryLock"]
    check("SetRecoveryLock sent for Apple silicon", len(recovery_cmds) == 1)
    check("SetRecoveryLock carries a NewPassword", recovery_cmds and "NewPassword" in recovery_cmds[0])

    #  Intel device -> SetFirmwarePassword
    RAW_CMDS.clear()
    dev_intel = await new_device("MAC-INTEL", apple_silicon=False)
    await atc.start_flows_for_event(dev_intel, "enroll_dep")
    fw_cmds = [f for (rt, f) in RAW_CMDS if rt == "SetFirmwarePassword"]
    check("SetFirmwarePassword sent for Intel", len(fw_cmds) == 1)
    check("firmware password escrowed for Intel",
          await DeviceSecret.get_or_none(device_id=dev_intel.id,
                                         kind=DeviceSecret.KIND_FIRMWARE) is not None)

    #  Unknown architecture -> skipped, no command, no escrow
    RAW_CMDS.clear()
    dev_unknown = await new_device("MAC-UNK", apple_silicon=None)
    await atc.start_flows_for_event(dev_unknown, "enroll_dep")
    check("no firmware command sent when architecture unknown", len(RAW_CMDS) == 0)
    check("no firmware secret escrowed when architecture unknown",
          (await DeviceSecret.filter(device_id=dev_unknown.id,
                                     kind__in=[DeviceSecret.KIND_FIRMWARE,
                                               DeviceSecret.KIND_RECOVERY_LOCK]).count()) == 0)

    #  5) validator accepts the good flow, rejects malformed nodes
    print("5) flows.yaml validator handles the new node types")
    valid, errors, warnings = YAMLValidator(tdir).validate_all()
    check("baseline flow with both new nodes validates", valid, )
    if not valid:
        print("      errors:", errors)

    def _validate_flow(flow):
        _write_configs(base, flow)
        return YAMLValidator(base / "tenants" / "default").validate_all()

    bad_primary = {**FLOW, "nodes": [
        {"id": "s", "type": "start", "params": {"kind": "enroll_dep"}, "next": "c"},
        {"id": "c", "type": "configure_accounts", "next": "e",
         "params": {"primary_account": "bogus"}},
        {"id": "e", "type": "end", "params": {}},
    ]}
    v, errs, _ = _validate_flow(bad_primary)
    check("bad primary_account rejected",
          not v and any("primary_account" in e for e in errs))

    bad_static = {**FLOW, "nodes": [
        {"id": "s", "type": "start", "params": {"kind": "enroll_dep"}, "next": "c"},
        {"id": "c", "type": "set_firmware_lock", "next": "e",
         "params": {"password_source": "static"}},  # static but no password
        {"id": "e", "type": "end", "params": {}},
    ]}
    v, errs, _ = _validate_flow(bad_static)
    check("static firmware lock without a password rejected",
          not v and any("password" in e for e in errs))

    #  6) a static password in a flow node never leaves through the config API
    print("6) flows.yaml static passwords are redacted on every read path")
    # The import position doesn't matter here; api.main resolves the YAML base per call.
    from controller.auth.dependencies import Principal
    from controller.models.tenant import FlowRun, User
    from controller.api.main import (
        _REDACTED, _redact_flows_history, _restore_flow_secrets,
        get_config_history_version, get_flow_run, get_yaml_config,
        _snapshot_config_history,
    )

    SECRET_PW = "Sup3rSecret-BreakGlass"
    static_flow = {**FLOW, "nodes": [
        {"id": "s", "type": "start", "params": {"kind": "enroll_dep"}, "next": "cfg"},
        {"id": "cfg", "type": "configure_accounts", "next": "fw", "params": {
            "primary_account": "prompt_standard",
            "managed_admin": True,
            "managed_admin_password_source": "static",
            "managed_admin_password": SECRET_PW,
        }},
        {"id": "fw", "type": "set_firmware_lock", "next": "e",
         "params": {"password_source": "static", "password": SECRET_PW}},
        {"id": "e", "type": "end", "params": {}},
    ]}
    _write_configs(base, static_flow)

    member_user = await User.create(tenant=tenant, email="member@default", role="member")
    member = Principal(tenant=tenant, user=member_user, email="member@default",
                       role="member")

    doc = await get_yaml_config("flows", False, member)
    flow_obj = doc.get("flow") or (doc.get("flows") or [{}])[0]
    node_params = {n["id"]: n.get("params", {}) for n in flow_obj.get("nodes", [])}
    check("GET /config/flows redacts the managed-admin password",
          node_params["cfg"]["managed_admin_password"] == _REDACTED)
    check("GET /config/flows redacts the firmware password",
          node_params["fw"]["password"] == _REDACTED)
    check("GET /config/flows keeps non-secret params",
          node_params["cfg"]["primary_account"] == "prompt_standard")

    raw = await get_yaml_config("flows", True, member)
    body = raw.body.decode()
    check("GET /config/flows?raw=true has no plaintext password", SECRET_PW not in body)
    check("GET /config/flows?raw=true still carries the sentinel", _REDACTED in body)

    _snapshot_config_history("default", "flows", "tester@example.com")
    versions = sorted((tdir / "_history" / "flows").glob("*.json"))
    hist = await get_config_history_version("flows", versions[-1].stem, member)
    check("history snapshot on disk keeps the real password",
          SECRET_PW in versions[-1].read_text())
    check("GET /config/flows/history/{id} redacts it", SECRET_PW not in hist["content"])
    check("unparseable history snapshot fails closed",
          _redact_flows_history("{[not yaml") == "")

    run = await FlowRun.create(
        tenant=tenant, device=dev, flow_id="acct", flow_hash="x" * 64,
        status="completed", context={"flow": static_flow},
    )
    run_data = await get_flow_run(str(run.id), member)
    run_params = {n["id"]: n.get("params", {}) for n in run_data["flow"]["nodes"]}
    check("GET /flow-runs/{id} redacts the pinned snapshot",
          run_params["fw"]["password"] == _REDACTED
          and run_params["cfg"]["managed_admin_password"] == _REDACTED)
    check("a run that still has a snapshot is reported as pinned",
          run_data["flow_source"] == "pinned")
    await run.refresh_from_db()
    check("redacting the response leaves the stored snapshot intact",
          run.context["flow"]["nodes"][2]["params"]["password"] == SECRET_PW)

    #  6a) once a run's snapshot is gone, the run viewer falls back to flows.yaml and reports whether that
    #      fallback still matches what ran.
    print("6a) GET /flow-runs/{id} falls back to flows.yaml once the snapshot is gone")
    pinned_hash = atc._flow_hash(static_flow)

    waiting_run = await FlowRun.create(
        tenant=tenant, device=dev, flow_id="acct", flow_hash=pinned_hash,
        status="waiting", context={"flow": static_flow, "timeline": []},
    )
    waiting_data = await get_flow_run(str(waiting_run.id), member)
    check("a waiting run still returns its pinned definition",
          waiting_data["flow_source"] == "pinned" and waiting_data["flow"] is not None)

    snapshot_free_run = await FlowRun.create(
        tenant=tenant, device=dev, flow_id="acct", flow_hash=pinned_hash,
        status="completed", context={"timeline": []},  # no 'flow' key: dropped at _complete
    )
    current_data = await get_flow_run(str(snapshot_free_run.id), member)
    check("a snapshot-free terminal run gets a fallback flow, not null",
          current_data["flow"] is not None)
    check("an unedited fallback is reported as matching what ran",
          current_data["flow_source"] == "current")
    current_params = {n["id"]: n.get("params", {}) for n in current_data["flow"]["nodes"]}
    check("the fallback flow gets the same redaction as any other read",
          current_params["fw"]["password"] == _REDACTED)

    # flows.yaml edited after the run's flow_hash was pinned: same run, different current document.
    _write_configs(base, {**static_flow, "name": "Account flow (edited)"})
    edited_data = await get_flow_run(str(snapshot_free_run.id), member)
    check("a fallback edited since the run executed is reported as edited",
          edited_data["flow_source"] == "edited" and edited_data["flow"] is not None)

    # The tenant's flow was since deleted entirely: null, not a raise.
    (tdir / "flows.yaml").unlink()
    gone_data = await get_flow_run(str(snapshot_free_run.id), member)
    check("a run whose flow no longer exists returns a null flow without raising",
          gone_data["flow"] is None and gone_data["flow_source"] == "unavailable")

    _write_configs(base, static_flow)  # restore flows.yaml for the checks below

    # A save that echoes the sentinel back must not overwrite the stored password.
    echoed = {"flow": {**static_flow, "nodes": [
        {**n, "params": {**n.get("params", {}),
                         **({"password": _REDACTED} if n["id"] == "fw" else {}),
                         **({"managed_admin_password": _REDACTED} if n["id"] == "cfg" else {})}}
        for n in static_flow["nodes"]
    ]}}
    _restore_flow_secrets("default", echoed)
    restored = {n["id"]: n.get("params", {}) for n in echoed["flow"]["nodes"]}
    check("PUT restores an echoed-back firmware password",
          restored["fw"]["password"] == SECRET_PW)
    check("PUT restores an echoed-back managed-admin password",
          restored["cfg"]["managed_admin_password"] == SECRET_PW)

    orphan = {"flow": {**static_flow, "nodes": [
        {"id": "s", "type": "start", "params": {"kind": "enroll_dep"}, "next": "new"},
        {"id": "new", "type": "set_firmware_lock", "next": "e",
         "params": {"password_source": "static", "password": _REDACTED}},
        {"id": "e", "type": "end", "params": {}},
    ]}}
    _restore_flow_secrets("default", orphan)
    check("sentinel on an unknown node is dropped, never persisted",
          "password" not in orphan["flow"]["nodes"][1]["params"])

    await Tortoise.close_connections()
    print()
    if _FAILURES:
        print(f"FAILED ({len(_FAILURES)}): " + "; ".join(_FAILURES))
        return 1
    print("All account-config and secret-escrow checks passed.")
    return 0


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
