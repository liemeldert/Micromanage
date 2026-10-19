"""Applies the schema to a fresh Postgres and checks it, including a rerun against an older schema. The sqlite suites
never execute models.database._AUX_DDL, so this is where that DDL is exercised.

DATABASE_URL names any database on the server; the check creates its own database, drops it afterwards, and refuses one
that holds tenants:

    DATABASE_URL=postgres://postgres:pw@localhost:5432/postgres \\
        PYTHONPATH=. python tests/pg_schema_check.py
"""
import asyncio
import os
import secrets
import sys
import traceback
from urllib.parse import urlsplit, urlunsplit

from tests._verify_harness import make_check

FAILED = []

check = make_check(FAILED)


async def _value(value):
    return value


def _prune(associations, keep):
    removed = 0
    for udid, hashes in keep.items():
        before = associations.get(udid, set())
        associations[udid] = before & hashes
        removed += len(before - hashes)
    return removed


async def _holds_tenants(conn) -> bool:
    if await conn.fetchval("SELECT to_regclass('tenants')") is None:
        return False
    return await conn.fetchval("SELECT EXISTS (SELECT 1 FROM tenants)")


async def main() -> int:
    url = os.environ.get("DATABASE_URL", "")
    if not url.startswith("postgres"):
        print("DATABASE_URL must point at a Postgres database", file=sys.stderr)
        return 2
    import asyncpg

    parts = urlsplit(url)
    admin = await asyncpg.connect(urlunsplit(("postgresql", parts.netloc, parts.path, "", "")))
    try:
        if await _holds_tenants(admin):
            print(f"Database {parts.path.lstrip('/')} holds tenants. Point DATABASE_URL at an empty database such as "
                  "postgres.", file=sys.stderr)
            return 2
        dbname = f"pg_schema_check_{secrets.token_hex(4)}"
        await admin.execute(f'CREATE DATABASE "{dbname}"')
        try:
            # models.database reads DATABASE_URL once at import, so it is set before run_checks imports it.
            os.environ["DATABASE_URL"] = urlunsplit((parts.scheme, parts.netloc, f"/{dbname}", parts.query, ""))
            # init_schema runs the identity cutover against NanoMDM's database, derived from DATABASE_URL by default.
            # Point it at a database that does not exist, so this check never prunes a real NanoMDM on the server.
            os.environ["NANOMDM_DATABASE_URL"] = urlunsplit(
                ("postgresql", parts.netloc, "/pg_schema_check_no_nanomdm", "", ""))
            return await run_checks(os.environ["DATABASE_URL"])
        finally:
            from tortoise import Tortoise
            try:
                await Tortoise.close_connections()
            except Exception:  # noqa: BLE001
                pass  # Tortoise was never initialized
            await admin.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')
    finally:
        await admin.close()


async def run_checks(url: str) -> int:
    from tortoise import Tortoise
    from controller.models import database as db
    from controller.models.tenant import Device, IdentityCutover, SchemaState, Tenant

    if db.DATABASE_URL != url:
        print("controller.models.database was imported before DATABASE_URL named the check's own database",
              file=sys.stderr)
        return 2

    print("1) fresh database: init_db creates the schema")
    await db.init_db()
    conn = Tortoise.get_connection("default")
    tables = {
        r["table_name"] for r in await conn.execute_query_dict(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()")
    }
    for name in ("tenants", "users", "devices", "tasks", "audit_logs", "flow_runs",
                 "alerts", "dep_servers", "device_secrets", "schema_state", "service_tokens",
                 "enrollment_links", "scep_challenges", "legacy_identities", "identity_cutover",
                 "device_agents", "agent_enrollment_codes", "agent_tasks", "agent_elevation_requests",
                 "agent_events"):
        check(f"table {name} exists", name in tables)

    # Three processes run this at once at startup, and every restart runs it again.
    print("2) a second init_schema is a no-op")
    try:
        await db.init_schema()
        check("init_schema ran again without raising", True)
    except Exception as exc:  # noqa: BLE001
        traceback.print_exc()
        check(f"init_schema ran again without raising ({exc})", False)

    print("3) schema_state carries the running code's fingerprint")
    status = await db.schema_status()
    check("a state row was recorded", status["recorded_fingerprint"] is not None)
    check("and it matches what this build expects", status["current"])
    check("exactly one row for one schema", await SchemaState.all().count() == 1)

    print("4) the aux DDL's columns and indexes are present")
    cols = {
        (r["table_name"], r["column_name"]) for r in await conn.execute_query_dict(
            "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = current_schema()")
    }
    for table, col in (("tasks", "command_uuid"), ("tasks", "dedup_key"),
                       ("devices", "tags"), ("devices", "attributes"),
                       ("devices", "enrollment_state"),
                       ("devices", "bootstrap_token_escrowed"),
                       ("tenants", "device_naming"),
                       ("tenants", "agent_policy"),
                       ("tenants", "fv_escrow_private_key_enc"),
                       ("tenants", "fv_escrow_cert_pem"),
                       ("tenants", "fv_escrow_cert_expires_at"),
                       ("tenants", "profile_signing_cert_expires_at"),
                       ("users", "mfa_changed_at"),
                       ("devices", "reenrollment_allowed_until"),
                       ("devices", "erase_acked_at"),
                       ("devices", "push_token_enc"),
                       ("devices", "identity_sha256"),
                       ("devices", "identity_pem"),
                       ("devices", "bootstrap_token_enc")):
        check(f"{table}.{col} exists", (table, col) in cols)
    check("table user_mfa exists", "user_mfa" in tables)
    for col in ("id", "user_id", "secret_enc", "confirmed_at", "last_step",
                "recovery_codes", "failed_attempts", "lockout_until",
                "created_at", "updated_at"):
        check(f"user_mfa.{col} exists", ("user_mfa", col) in cols)
    for col in ("id", "tenant_id", "token_enc", "token_hash", "label", "created_by", "created_at",
                "expires_at", "max_downloads", "downloads", "revoked_at"):
        check(f"enrollment_links.{col} exists", ("enrollment_links", col) in cols)
    for col in ("id", "tenant_id", "link_id", "serial", "expected_udid", "device_id", "task_id",
                "challenge_hash", "subject_cn", "remote_addr", "created_at", "usable_from", "expires_at",
                "consumed_at", "transaction_id", "csr_hash", "spki_hash", "cert_sha256", "bound_at", "bound_udid",
                "previous_pem", "origin"):
        check(f"scep_challenges.{col} exists", ("scep_challenges", col) in cols)
    for col in ("id", "udid", "cert_sha256", "snapshot_at"):
        check(f"legacy_identities.{col} exists", ("legacy_identities", col) in cols)
    for col in ("id", "cutover_at", "snapshot_done"):
        check(f"identity_cutover.{col} exists", ("identity_cutover", col) in cols)
    indexes = {
        r["indexname"] for r in await conn.execute_query_dict(
            "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()")
    }
    for name in ("idx_tasks_command_uuid", "idx_appdeploy_tenant_status",
                 "idx_profiledeploy_tenant", "idx_service_tokens_tenant_hash",
                 "idx_scep_challenges_open_renewal", "idx_device_agents_tenant_seen",
                 "idx_agent_tasks_device_status_created", "idx_agent_elevation_tenant_status_created",
                 "idx_agent_elevation_device_user_status", "idx_agent_enrollment_codes_device",
                 "idx_agent_events_device_received"):
        check(f"{name} exists", name in indexes)
    check("an unreachable NanoMDM leaves the identity cutover unstamped",
          not await IdentityCutover.exists())

    print("5) JSONB filters the API uses work here")
    tenant = await Tenant.create(id="pgcheck", name="pg check")
    dev = await Device.create(tenant=tenant, serial_number="PGCHECK1", udid="pg-udid-1",
                              device_model="Mac", os_version="15.0",
                              groups=["g1"], tags=["lab"], attributes={"os": "x"})
    check("groups__contains finds the device",
          await Device.filter(tenant=tenant, groups__contains=["g1"]).exists())
    check("tags__contains finds the device",
          await Device.filter(tenant=tenant, tags__contains=["lab"]).exists())
    check("and misses on a tag it does not have",
          not await Device.filter(tenant=tenant, tags__contains=["nope"]).exists())
    from datetime import datetime, timedelta, timezone
    from tortoise.exceptions import IntegrityError
    from controller.models.tenant import ScepChallenge
    later = datetime.now(timezone.utc) + timedelta(days=1)
    await ScepChallenge.create(tenant=tenant, device=dev, origin="renewal", challenge_hash="1" * 64,
                               subject_cn="mm a", expires_at=later)
    try:
        await ScepChallenge.create(tenant=tenant, device=dev, origin="renewal", challenge_hash="2" * 64,
                                   subject_cn="mm b", expires_at=later)
        check("a second open renewal challenge for one device is refused", False)
    except IntegrityError:
        check("a second open renewal challenge for one device is refused", True)
    await ScepChallenge.filter(device=dev).update(consumed_at=datetime.now(timezone.utc))
    await ScepChallenge.create(tenant=tenant, device=dev, origin="renewal", challenge_hash="3" * 64,
                               subject_cn="mm c", expires_at=later)
    check("a consumed one does not count", await ScepChallenge.filter(device=dev).count() == 2)
    await ScepChallenge.filter(device=dev).delete()

    print("5b) take_download's UPDATE ... RETURNING holds the download cap")
    from controller.models.tenant import EnrollmentLink
    from controller.services import enrollment_links
    link = await EnrollmentLink.create(tenant=tenant, token_enc="sealed", token_hash="4" * 64, created_by="pgcheck",
                                       expires_at=later, max_downloads=2)
    taken = [await enrollment_links.take_download(link) for _ in range(3)]
    check("two downloads count and the third is refused", taken == [True, True, False], str(taken))
    await link.refresh_from_db()
    check("downloads stops at the cap", link.downloads == 2, str(link.downloads))
    past = datetime.now(timezone.utc) - timedelta(minutes=1)
    expired = await EnrollmentLink.create(tenant=tenant, token_enc="sealed", token_hash="5" * 64,
                                          created_by="pgcheck", expires_at=past)
    check("an expired link is refused", not await enrollment_links.take_download(expired))
    await EnrollmentLink.filter(tenant=tenant).delete()

    print("5c) run_cutover writes the snapshot and the stamp through asyncpg")
    from controller.models.tenant import LegacyIdentity
    from controller.services import identity, nanomdm_store
    from controller.services.nanomdm_store import Identity

    sha = {c: c * 64 for c in "abcd"}
    associations = {"pg-c1": {sha["a"], sha["b"]}, "pg-c2": {sha["c"], sha["d"]}}
    pruned = []
    stubbed = {
        "list_identities": lambda udids=None: _value({"pg-c1": Identity(sha["a"], sha["a"], "pg MDM Device x",
                                                                        later)}),
        "list_all_associations": lambda: _value({u: set(h) for u, h in associations.items()}),
        "prune_associations_bulk": lambda keep: pruned.append(keep) or _value(_prune(associations, keep)),
    }
    originals = {name: getattr(nanomdm_store, name) for name in stubbed}
    try:
        for name, fn in stubbed.items():
            setattr(nanomdm_store, name, fn)
        await LegacyIdentity.create(udid="pg-c2", cert_sha256=sha["c"])
        await IdentityCutover.all().delete()
        identity.reset_cutover_cache()
        check("the stubbed cutover runs", await identity.run_cutover() is True)
        check("and prunes through the stubs", len(pruned) == 1 and associations["pg-c1"] == {sha["a"]}
              and associations["pg-c2"] == {sha["c"], sha["d"]}, f"{pruned} {associations}")
        snapshot = set(await LegacyIdentity.all().values_list("udid", "cert_sha256"))
        check("the snapshot holds what remains, and an existing row is not an error",
              snapshot == {("pg-c1", sha["a"]), ("pg-c2", sha["c"]), ("pg-c2", sha["d"])}, str(snapshot))
        check("the stamp is row 1", await IdentityCutover.filter(id=1, snapshot_done=True).exists())
        await IdentityCutover.all().delete()
        identity.reset_cutover_cache()
        check("a rerun over the same snapshot also succeeds", await identity.run_cutover() is True
              and await LegacyIdentity.all().count() == 3)
    finally:
        for name, fn in originals.items():
            setattr(nanomdm_store, name, fn)
        await LegacyIdentity.all().delete()
        await IdentityCutover.all().delete()
        identity.reset_cutover_cache()

    await dev.delete()
    await tenant.delete()

    print("6) upgrade direction: an older schema converges on a rerun")
    # Step 2 only reruns against a schema that is already current. Every deployment runs this DDL against a database
    # missing part of it, so drop four columns, the index one of them carries, and narrow the column the guarded DO
    # block widens, then check the rerun restores all of it.
    await conn.execute_script('ALTER TABLE "tasks" DROP COLUMN IF EXISTS "command_uuid"')
    await conn.execute_script('ALTER TABLE "devices" DROP COLUMN IF EXISTS "tags"')
    await conn.execute_script('ALTER TABLE "scep_challenges" DROP COLUMN IF EXISTS "origin"')
    await conn.execute_script('ALTER TABLE "scep_challenges" DROP COLUMN IF EXISTS "previous_pem"')
    await conn.execute_script('ALTER TABLE "dep_servers" ALTER COLUMN "sync_cursor" TYPE VARCHAR(255)')
    try:
        await db.init_schema()
        check("init_schema ran against the older schema without raising", True)
    except Exception as exc:  # noqa: BLE001
        traceback.print_exc()
        check(f"init_schema ran against the older schema without raising ({exc})", False)
    cols = {
        (r["table_name"], r["column_name"]) for r in await conn.execute_query_dict(
            "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = current_schema()")
    }
    check("tasks.command_uuid came back", ("tasks", "command_uuid") in cols)
    check("devices.tags came back", ("devices", "tags") in cols)
    check("scep_challenges.origin came back", ("scep_challenges", "origin") in cols)
    check("scep_challenges.previous_pem came back", ("scep_challenges", "previous_pem") in cols)
    indexes = {
        r["indexname"] for r in await conn.execute_query_dict(
            "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()")
    }
    check("idx_tasks_command_uuid came back", "idx_tasks_command_uuid" in indexes)
    cursor_type = (await conn.execute_query_dict(
        "SELECT data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = "
        "'dep_servers' AND column_name = 'sync_cursor'"))[0]["data_type"]
    check(f"dep_servers.sync_cursor is text again (is {cursor_type})", cursor_type == "text")
    # The fingerprint did not move, so the converged run records no second row.
    check("still exactly one schema_state row", await SchemaState.all().count() == 1)

    print(f"\nRESULT: {'PASS' if not FAILED else 'FAIL'} ({len(FAILED)} failed)")
    return 1 if FAILED else 0


if __name__ == "__main__":
    try:
        code = asyncio.run(main())
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        code = 1
    # asyncpg holds no non-daemon threads, but exit explicitly all the same.
    sys.exit(code)
