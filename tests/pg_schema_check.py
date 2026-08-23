"""Bring a fresh Postgres to the schema and prove it holds up.

Run against a throwaway database:

    DATABASE_URL=postgres://postgres:pw@localhost:5432/mdm_iac \\
        PYTHONPATH=. python tests/pg_schema_check.py

Kept out of the verify_*.py set: those run on in-memory sqlite, where the models already carry every column and nothing
runs models.database._AUX_DDL, the hand-written Postgres DDL every process executes at startup. A typo there takes all
three processes down on boot, and nothing else runs that DDL before production. CI gives this a postgres service.
"""
import asyncio
import os
import sys
import traceback

FAILED = []


def check(label, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        FAILED.append(label)


async def main() -> int:
    url = os.environ.get("DATABASE_URL", "")
    if not url.startswith("postgres"):
        print("DATABASE_URL must point at a Postgres database", file=sys.stderr)
        return 2

    from tortoise import Tortoise
    from controller.models import database as db
    from controller.models.tenant import Device, SchemaState, Tenant

    print("1) fresh database: init_db creates the schema")
    await db.init_db()
    conn = Tortoise.get_connection("default")
    tables = {
        r["table_name"] for r in await conn.execute_query_dict(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()")
    }
    for name in ("tenants", "users", "devices", "tasks", "audit_logs", "flow_runs",
                 "alerts", "dep_servers", "device_secrets", "schema_state"):
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
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema()")
    }
    for table, col in (("tasks", "command_uuid"), ("tasks", "dedup_key"),
                       ("devices", "tags"), ("devices", "attributes"),
                       ("devices", "enrollment_state"), ("tenants", "device_naming"),
                       ("tenants", "fv_escrow_private_key_enc"),
                       ("tenants", "fv_escrow_cert_pem"),
                       ("tenants", "fv_escrow_cert_expires_at"),
                       ("users", "mfa_changed_at")):
        check(f"{table}.{col} exists", (table, col) in cols)
    check("table user_mfa exists", "user_mfa" in tables)
    for col in ("id", "user_id", "secret_enc", "confirmed_at", "last_step",
                "recovery_codes", "failed_attempts", "lockout_until",
                "created_at", "updated_at"):
        check(f"user_mfa.{col} exists", ("user_mfa", col) in cols)
    indexes = {
        r["indexname"] for r in await conn.execute_query_dict(
            "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()")
    }
    for name in ("idx_tasks_command_uuid", "idx_appdeploy_tenant_status",
                 "idx_profiledeploy_tenant"):
        check(f"{name} exists", name in indexes)

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
    await dev.delete()
    await tenant.delete()

    print("6) upgrade direction: an older schema converges on a rerun")
    # Step 2 only reruns against a schema that is already current. Every deployment runs this DDL against a database
    # missing part of it, so drop two columns, the index one of them carries, and narrow the column the guarded DO block
    # widens, then check the rerun restores all of it.
    await conn.execute_script('ALTER TABLE "tasks" DROP COLUMN IF EXISTS "command_uuid"')
    await conn.execute_script('ALTER TABLE "devices" DROP COLUMN IF EXISTS "tags"')
    await conn.execute_script('ALTER TABLE "dep_servers" ALTER COLUMN "sync_cursor" TYPE VARCHAR(255)')
    try:
        await db.init_schema()
        check("init_schema ran against the older schema without raising", True)
    except Exception as exc:  # noqa: BLE001
        traceback.print_exc()
        check(f"init_schema ran against the older schema without raising ({exc})", False)
    cols = {
        (r["table_name"], r["column_name"]) for r in await conn.execute_query_dict(
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema()")
    }
    check("tasks.command_uuid came back", ("tasks", "command_uuid") in cols)
    check("devices.tags came back", ("devices", "tags") in cols)
    indexes = {
        r["indexname"] for r in await conn.execute_query_dict(
            "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()")
    }
    check("idx_tasks_command_uuid came back", "idx_tasks_command_uuid" in indexes)
    cursor_type = (await conn.execute_query_dict(
        "SELECT data_type FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND table_name = 'dep_servers' "
        "AND column_name = 'sync_cursor'"))[0]["data_type"]
    check(f"dep_servers.sync_cursor is text again (is {cursor_type})", cursor_type == "text")
    # The fingerprint did not move, so the converged run records no second row.
    check("still exactly one schema_state row", await SchemaState.all().count() == 1)

    await Tortoise.close_connections()
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
