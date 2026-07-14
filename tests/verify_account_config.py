"""Backend E2E for the account-config + firmware-lock ATC nodes and the
Break-The-Glass secret escrow, on in-memory sqlite (no docker, no MDM network).

Covers:
  * account_hash.password_hash_blob shape (SALTED-SHA512-PBKDF2 / 128 / 32) and
    that the on-wire passwordHash actually verifies against the escrowed password.
  * the configure_accounts node: AccountConfiguration keys for standard/admin/skip,
    managed-admin provisioning + escrow, and password redaction from the audit task.
  * the set_firmware_lock node: SetRecoveryLock (Apple Silicon) vs SetFirmwarePassword
    (Intel) vs skip (unknown architecture), each escrowing its password.
  * Break-The-Glass: device_secrets.reveal returns the plaintext, stamps the
    ledger, and raises (then bumps) a single Dispatcher alert.
  * the flows.yaml validator for the two new node types.

Run:  PYTHONPATH=. ./.venv/bin/python tests/verify_account_config.py
Exits non-zero if any check fails.
"""

import asyncio
import hashlib
import os
import plistlib
import sys
import tempfile
from pathlib import Path

# Encryption-at-rest must be configured before crypto_secrets is first used
# (escrow refuses to store plaintext). crypto_secrets reads the env lazily.
from cryptography.fernet import Fernet
os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import yaml
from tortoise import Tortoise

_FAILURES = []

# Captured MDM commands (the fake connector appends here).
ACCOUNT_CMDS = []   # list of kwargs dicts from account_configuration
RAW_CMDS = []       # list of (request_type, fields) from send_raw_command


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
    check("escrow is sealed (glass intact) initially", secret and secret.revealed_at is None)
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

    #  3) Break-The-Glass ledger + dispatcher alert
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

    #  4) set_firmware_lock: Apple Silicon -> SetRecoveryLock (escrowed)
    print("4) set_firmware_lock chooses the command by architecture")
    rl = await DeviceSecret.get_or_none(device_id=dev.id, kind=DeviceSecret.KIND_RECOVERY_LOCK)
    check("recovery-lock password escrowed for Apple Silicon", rl is not None)
    recovery_cmds = [f for (rt, f) in RAW_CMDS if rt == "SetRecoveryLock"]
    check("SetRecoveryLock sent for Apple Silicon", len(recovery_cmds) == 1)
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

    await Tortoise.close_connections()
    print()
    if _FAILURES:
        print(f"FAILED ({len(_FAILURES)}): " + "; ".join(_FAILURES))
        return 1
    print("All account-config / break-the-glass checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
