from tortoise import Tortoise
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgres://postgres:password@localhost:5432/mdm_iac")

# Columns added after the initial schema. Tortoise's generate_schemas() only
# CREATEs missing tables — it never ALTERs existing ones — so late-added model
# fields must be ensured explicitly. Statements must be idempotent.
_AUX_DDL = [
    'ALTER TABLE "profile_deployments" ADD COLUMN IF NOT EXISTS "payload_hash" VARCHAR(64)',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "attributes" JSONB NOT NULL DEFAULT \'{}\'::jsonb',
]


async def ensure_aux_columns():
    """Apply idempotent post-create DDL. Call after Tortoise is initialized."""
    conn = Tortoise.get_connection("default")
    for ddl in _AUX_DDL:
        await conn.execute_script(ddl)


async def init_db():
    await Tortoise.init(
        db_url=DATABASE_URL,
        modules={"models": ["controller.models.tenant"]}
    )
    await Tortoise.generate_schemas()
    await ensure_aux_columns()

async def close_db():
    await Tortoise.close_connections()
