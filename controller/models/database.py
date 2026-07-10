from tortoise import Tortoise
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgres://postgres:password@localhost:5432/mdm_iac")

# Columns added after the initial schema. Tortoise's generate_schemas() only
# CREATEs missing tables -- it never ALTERs existing ones -- so late-added model
# fields must be ensured explicitly. Statements must be idempotent.
_AUX_DDL = [
    'ALTER TABLE "profile_deployments" ADD COLUMN IF NOT EXISTS "payload_hash" VARCHAR(64)',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "attributes" JSONB NOT NULL DEFAULT \'{}\'::jsonb',
    # Device lifecycle across enrollments (retain history; support DEP placeholders).
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "enrollment_state" VARCHAR(20) NOT NULL DEFAULT \'enrolled\'',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "management_type" VARCHAR(30) NOT NULL DEFAULT \'apple_mdm\'',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "unenrolled_at" TIMESTAMPTZ NULL',
    # udid becomes nullable so pre-provisioned placeholders (serial only) can exist.
    'ALTER TABLE "devices" ALTER COLUMN "udid" DROP NOT NULL',
    # Managed device name + per-tenant dynamic naming template.
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "name" VARCHAR(255) NULL',
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "device_naming" JSONB NOT NULL DEFAULT \'{}\'::jsonb',
]


# Best-effort DDL: applied if it can be, logged (not fatal) if it can't -- used
# for constraints that pre-existing data might violate.
_BEST_EFFORT_DDL = [
    # A physical device is uniquely identified within a tenant by its serial.
    # Enforces one record per serial so placeholder adoption / re-enroll can't
    # create duplicates. Excludes blank serials (placeholders always have one).
    'CREATE UNIQUE INDEX IF NOT EXISTS "devices_tenant_serial_uniq" '
    "ON \"devices\" (tenant_id, serial_number) WHERE serial_number <> ''",
]


async def ensure_aux_columns():
    """Apply idempotent post-create DDL. Call after Tortoise is initialized."""
    import logging
    conn = Tortoise.get_connection("default")
    for ddl in _AUX_DDL:
        await conn.execute_script(ddl)
    for ddl in _BEST_EFFORT_DDL:
        try:
            await conn.execute_script(ddl)
        except Exception as exc:
            # e.g. legacy duplicate serials from before soft-unenroll existed;
            # app-level dedup still applies (adoption tolerates duplicates).
            logging.getLogger(__name__).warning("aux DDL skipped (%s): %s", ddl[:60], exc)


async def init_db():
    await Tortoise.init(
        db_url=DATABASE_URL,
        modules={"models": ["controller.models.tenant"]}
    )
    await Tortoise.generate_schemas()
    await ensure_aux_columns()

async def close_db():
    await Tortoise.close_connections()
