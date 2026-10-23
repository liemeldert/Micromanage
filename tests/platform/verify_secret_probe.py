"""The secrets readiness capability (controller/services/secret_probe.py), on in-memory sqlite. It is Blocked when a
stored secret does not decrypt with the current key, names columns and variables only, and changes no other answer.

Run: PYTHONPATH=. ./.venv/bin/python tests/platform/verify_secret_probe.py
"""

import json
import logging
import os
import tempfile
from datetime import timedelta
from pathlib import Path

os.environ["JWT_SECRET"] = "verify-secret-probe-jwt-secret-long-enough"
os.environ.pop("SECRET_ENCRYPTION_KEY", None)

from cryptography.fernet import Fernet  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from tortoise import Tortoise  # noqa: E402

from controller.api.anonymous import require_enrollment_configured  # noqa: E402
from controller.models.tenant import (  # noqa: E402
    DepServer, Device, DeviceAgent, DeviceSecret, EnrollmentLink, IdentityCutover, SecretProbe, Tenant, User, UserMFA,
)
from controller.services import crypto_secrets, enrollment, identity, readiness, secret_probe  # noqa: E402
from controller.utils.timeutil import utcnow  # noqa: E402
from tests._verify_harness import LogCapture, make_check, run  # noqa: E402

PASS, FAIL = [], []

check = make_check(FAIL, PASS)

KEY_A = Fernet.generate_key().decode()
KEY_B = Fernet.generate_key().decode()
JWT_A = "verify-secret-probe-jwt-secret-long-enough"
JWT_B = "verify-secret-probe-other-jwt-secret-value"

_SECRET_DIR = Path(tempfile.mkdtemp())
WEBHOOK_SECRET_FILE = _SECRET_DIR / "scep_webhook_secret"
WEBHOOK_SECRET_FILE.write_text("dmVyaWZ5LXNlY3JldC1wcm9iZS1zY2VwLXNlY3JldA==")

# A deployment where enrollment is ready, so case 6 can show it stays ready.
CONFIGURED = {
    "MDM_TOPIC": "com.apple.mgmt.External.verify",
    "SCEP_WEBHOOK_SECRET_FILE": str(WEBHOOK_SECRET_FILE),
    "PUBLIC_API_URL": "https://mdm.example.test",
    "MDM_HOSTNAME": "mdm.example.test",
    "MDM_SERVER_URL": None,
    "SCEP_URL": None,
    "MDM_EMBED_CA_CERT_PATH": None,
    "NANOMDM_API_KEY": "verify-nanomdm-key",
    "WEBHOOK_SECRET": "verify-webhook-secret",
    "WEBHOOK_HMAC_KEY": "verify-webhook-hmac-key",
    "DDM_HMAC_SECRET": "verify-ddm-secret",
    "AWS_S3_BUCKET": "verify-packages",
    "AWS_ACCESS_KEY_ID": "AKIA-VERIFY",
    "AWS_SECRET_ACCESS_KEY": "VERIFY-SECRET",
    "DEP_ADE_REQUIRE_APPLE_SIGNATURE": "true",
}

LABELS = [f"{model._meta.db_table}.{column}" for model, column, _order in secret_probe.COLUMNS]

# Every plaintext and ciphertext this suite stores, for case 5.
STORED = {"plaintexts": set(), "tokens": set()}


class _Env:
    """Set environment variables for a block and put them back afterwards."""

    def __init__(self, **values):
        self._values = values
        self._saved = {}

    def __enter__(self):
        for name, value in self._values.items():
            self._saved[name] = os.environ.get(name)
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        return self

    def __exit__(self, *exc):
        for name, saved in self._saved.items():
            if saved is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = saved
        return False


def explicit(key):
    return _Env(SECRET_ENCRYPTION_KEY=key, JWT_SECRET=JWT_A)


def derived(jwt):
    return _Env(SECRET_ENCRYPTION_KEY=None, JWT_SECRET=jwt)


async def clear(tenant):
    """Remove every stored secret and the probe row, and forget the cached result."""
    for model in (DeviceAgent, DeviceSecret, Device, EnrollmentLink, DepServer, UserMFA, SecretProbe):
        await model.all().delete()
    await Tenant.filter(id=tenant.id).update(fv_escrow_private_key_enc=None, profile_signing_key_enc=None)
    readiness.forget_secrets_probe()


def seal(label):
    """A stored plaintext for one column, encrypted under the current key."""
    plaintext = f"verify stored plaintext for {label}"
    token = crypto_secrets.encrypt(plaintext, aad=f"verify/{label}")
    STORED["plaintexts"].add(plaintext)
    STORED["tokens"].add(token)
    return token


async def store_everywhere(tenant, user):
    """One value in every column COLUMNS samples, under the current key."""
    await Tenant.filter(id=tenant.id).update(fv_escrow_private_key_enc=seal("tenants.fv_escrow_private_key_enc"),
                                             profile_signing_key_enc=seal("tenants.profile_signing_key_enc"))
    await UserMFA.create(user=user, secret_enc=seal("user_mfa.secret_enc"))
    device = await Device.create(tenant=tenant, serial_number="VERIFYPROBE1", device_model="Mac", os_version="26.0",
                                 push_token_enc=seal("devices.push_token_enc"),
                                 bootstrap_token_enc=seal("devices.bootstrap_token_enc"))
    await EnrollmentLink.create(tenant=tenant, token_enc=seal("enrollment_links.token_enc"), token_hash="0" * 64,
                                created_by="verify", expires_at=utcnow() + timedelta(days=1))
    await DepServer.create(tenant=tenant, name="verify", private_key_enc=seal("dep_servers.private_key_enc"),
                           token_enc=seal("dep_servers.token_enc"))
    await DeviceSecret.create(tenant=tenant, device=device, kind="verify", value_enc=seal("device_secrets.value_enc"))
    await DeviceAgent.create(tenant=tenant, device=device, token_prefix="verify", token_issued_at=utcnow(),
                             pending_token_enc=seal("device_agents.pending_token_enc"),
                             pending_token_issued_at=utcnow(), enrolled_at=utcnow(), reported_serial="VERIFYPROBE1",
                             reported_hardware_uuid="verify-hardware-uuid", agent_version="1.0")


async def secrets_status():
    await readiness.probe_secrets()
    return readiness.check("secrets")


async def case_fresh_database(tenant):
    print("\n1) a fresh database gets the probe and secrets is ready")
    await clear(tenant)
    with explicit(KEY_A):
        check("ensure_probe writes the row", await secret_probe.ensure_probe())
        row = await SecretProbe.get_or_none(id=1)
        check("...as id 1, under its binding",
              row is not None and crypto_secrets.decrypt(row.token, aad=secret_probe.PROBE_BINDING)
              == secret_probe.PROBE_PLAINTEXT)
        STORED["tokens"].add(row.token if row else "")
        status = await secrets_status()
        check("secrets is ready", status.ready and status.warnings == ())
        check("secrets is reported by the registry", "secrets" in readiness.CAPABILITIES)


async def case_every_column(tenant, user):
    print("\n2) a value in every column under the right key")
    await clear(tenant)
    with explicit(KEY_A):
        await store_everywhere(tenant, user)
        check("every column is sampled and opens", await secret_probe.sample_failures() == [])
        result = await secret_probe.run_check()
        check("run_check writes the probe when every column opens", result.ok and result.probe_written)
        STORED["tokens"].add((await SecretProbe.get(id=1)).token)
        readiness.forget_secrets_probe()
        check("secrets is ready", (await secrets_status()).ready)


async def case_key_changed(tenant, user, logs):
    print("\n3) the key changed after storing")
    await clear(tenant)
    with explicit(KEY_A):
        await store_everywhere(tenant, user)
        check("ready under the key that stored them", (await secrets_status()).ready)
    mark = len(logs.records)
    with explicit(KEY_B):
        readiness.forget_secrets_probe()
        status = await secrets_status()
        check("a new SECRET_ENCRYPTION_KEY blocks secrets", not status.ready and status.scope == "deployment")
        check("the reason names every column and the probe", all(label in status.reason for label in LABELS)
              and secret_probe.PROBE_COLUMN in status.reason, status.reason)
        check("...and the variable", status.broken == ("SECRET_ENCRYPTION_KEY",) and status.missing == ()
              and "SECRET_ENCRYPTION_KEY" in status.reason)
        readiness._SECRETS_PROBE["checked_at"] -= 2 * readiness._PROBE_TTL_SECONDS
        await readiness.probe_secrets()
        records = logs.records[mark:]
        errors = [r for r in records if r.levelno >= logging.ERROR and "readiness[secrets]" in r.getMessage()]
        check("the failure is logged once across two refreshes", len(errors) == 1, str(len(errors)))
        check("no decryption warning is logged per refresh",
              not any("Secret decryption failed" in r.getMessage() for r in records))

    await clear(tenant)
    with derived(JWT_A):
        await store_everywhere(tenant, user)
        check("ready under the derived key that stored them", (await secrets_status()).ready)
    with derived(JWT_B):
        readiness.forget_secrets_probe()
        status = await secrets_status()
        check("a new JWT_SECRET blocks secrets when the key is derived",
              not status.ready and status.broken == ("JWT_SECRET",) and "derived from JWT_SECRET" in status.reason)
        check("...naming the columns", all(label in status.reason for label in LABELS), status.reason)


async def case_upgrade(tenant, user):
    print("\n4) an upgrade with stored secrets and no probe row")
    await clear(tenant)
    with explicit(KEY_A):
        await store_everywhere(tenant, user)
    with explicit(KEY_B):
        status = await secrets_status()
        check("a changed key is blocked", not status.ready and secret_probe.PROBE_COLUMN not in status.reason)
        check("...and writes no probe row", not await SecretProbe.exists())
        check("ensure_probe refuses under the changed key", not await secret_probe.ensure_probe()
              and not await SecretProbe.exists())
    with explicit(KEY_A):
        readiness.forget_secrets_probe()
        check("the original key is ready", (await secrets_status()).ready)
        row = await SecretProbe.get_or_none(id=1)
        check("...and writes the probe", row is not None)
        if row:
            STORED["tokens"].add(row.token)


async def case_nothing_leaks(tenant, user, logs):
    print("\n5) no plaintext, ciphertext or key in the logs or the report")
    await clear(tenant)
    with explicit(KEY_A):
        await store_everywhere(tenant, user)
        await secrets_status()
        STORED["tokens"].add((await SecretProbe.get(id=1)).token)
    with explicit(KEY_B):
        readiness.forget_secrets_probe()
        await secrets_status()
        body = json.dumps(readiness.report())
    check("the report is blocked on secrets", '"capability": "secrets", "ready": false' in body)
    text = "\n".join(logs.messages) + "\n" + body
    forbidden = {secret_probe.PROBE_PLAINTEXT, KEY_A, KEY_B, JWT_A, JWT_B} | STORED["plaintexts"] | STORED["tokens"]
    check(f"none of {len(forbidden)} plaintexts, ciphertexts and keys appear", bool(logs.records)
          and not any(value and value in text for value in forbidden))


async def case_nothing_else_changes(tenant, user):
    print("\n6) while secrets is blocked, enrollment and every other capability answer as before")
    await clear(tenant)
    with _Env(**CONFIGURED), explicit(KEY_A):
        await store_everywhere(tenant, user)
        others = [name for name in readiness.CAPABILITIES if name != "secrets"]
        before = {name: readiness.check(name, tenant=tenant) for name in others}
        configured_before = enrollment.enrollment_details(tenant)["configured"]
    with _Env(**CONFIGURED), explicit(KEY_B):
        readiness.forget_secrets_probe()
        check("secrets is blocked", not (await secrets_status()).ready)
        check("enroll is ready and unchanged", readiness.check("enroll", tenant=tenant) == before["enroll"]
              and before["enroll"].ready)
        check("every other capability is unchanged",
              {name: readiness.check(name, tenant=tenant) for name in others} == before)
        check("enrollment_details configured is unchanged",
              enrollment.enrollment_details(tenant)["configured"] is configured_before is True)
        try:
            require_enrollment_configured(tenant, enrollment)
            refused = None
        except HTTPException as exc:
            refused = exc.status_code
        check("require_enrollment_configured raises nothing", refused is None, str(refused))


async def case_unchecked(tenant):
    print("\n7) a failed query and a missing key both answer ready")
    real = secret_probe.run_check

    async def failing():
        raise RuntimeError("database unavailable")

    readiness.forget_secrets_probe()
    secret_probe.run_check = failing
    try:
        status = await secrets_status()
    finally:
        secret_probe.run_check = real
    check("a failed query is ready with a warning", status.ready and status.warnings
          == ("Stored secrets could not be checked because the database query failed. Check the controller's "
              "database connection.",))
    await clear(tenant)
    with _Env(SECRET_ENCRYPTION_KEY=None, JWT_SECRET=None):
        status = await secrets_status()
        check("no key is ready, as escrow reports it", status.ready and not await SecretProbe.exists())
    readiness.forget_secrets_probe()


async def main():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()
    await IdentityCutover.create(id=1, cutover_at=utcnow(), snapshot_done=True)
    await identity.cutover_done()
    tenant = await Tenant.create(id="secret-probe", name="Secret Probe Inc", auth_config={"provider": "local"})
    user = await User.create(tenant=tenant, email="admin@example.test", role="admin", password_hash="x")

    logs = LogCapture()
    root = logging.getLogger()
    root.addHandler(logs)
    logging.getLogger("controller").setLevel(logging.DEBUG)
    try:
        await case_fresh_database(tenant)
        await case_every_column(tenant, user)
        await case_key_changed(tenant, user, logs)
        await case_upgrade(tenant, user)
        await case_nothing_leaks(tenant, user, logs)
        await case_nothing_else_changes(tenant, user)
        await case_unchecked(tenant)
    finally:
        root.removeHandler(logs)

    await Tortoise.close_connections()

    print()
    if FAIL:
        print(f"FAILED: {len(FAIL)} check(s):")
        for f in FAIL:
            print(f"  - {f}")
        return 1
    print(f"All secret probe checks passed ({len(PASS)}).")
    return 0


run(main)
