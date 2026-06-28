from tortoise import Tortoise
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgres://postgres:password@localhost:5432/mdm_iac")

async def init_db():
    await Tortoise.init(
        db_url=DATABASE_URL,
        modules={"models": ["controller.models.tenant"]}
    )
    await Tortoise.generate_schemas()

async def close_db():
    await Tortoise.close_connections()