"""FastAPI application assembly and lifecycle handlers."""
import asyncio
import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from tortoise.contrib.fastapi import register_tortoise

from controller.api.ddm import public_router as ddm_public_router
from controller.api.dep import router as dep_router
from controller.api.routes.alerts import router as alerts_router
from controller.api.routes.audit import router as audit_router
from controller.api.routes.auth import router as auth_router
from controller.api.routes.catalogs import router as catalogs_router
from controller.api.routes.commands import router as commands_router
from controller.api.routes.config import router as config_router
from controller.api.routes.declarations import router as declarations_router
from controller.api.routes.devices import router as devices_router
from controller.api.routes.enrollment import router as enrollment_router
from controller.api.routes.files import router as files_router
from controller.api.routes.flow_runs import router as flow_runs_router
from controller.api.routes.flows import router as flows_router
from controller.api.routes.integrations import router as integrations_router
from controller.api.routes.manifests import router as manifests_router
from controller.api.routes.readiness import router as readiness_router
from controller.api.routes.reports import router as reports_router
from controller.api.routes.secrets import router as secrets_router
from controller.api.routes.tasks import router as tasks_router
from controller.api.routes.tenants import router as tenants_router
from controller.api.routes.tiles import _close_tile_client, router as tiles_router
from controller.api.routes.users import router as users_router
from controller.models.database import (
    DATABASE_URL,
    _pooled_url,
    database_url_error,
)
from controller.models.tenant import Tenant
from controller.services import readiness
from controller.utils.coerce import env_flag
from controller.version import __version__

# Disable the interactive docs by default
_API_DOCS_ENABLED = env_flag("MDM_ENABLE_API_DOCS")

app = FastAPI(
    title="Micromanage API",
    version=__version__,
    docs_url="/docs" if _API_DOCS_ENABLED else None,
    redoc_url="/redoc" if _API_DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _API_DOCS_ENABLED else None,
)

logger = logging.getLogger(__name__)

# Middleware
_cors_origins = [
    o.strip()
    for o in os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Tenant-Id"],
    expose_headers=["Content-Disposition"],
)


@app.on_event("startup")
async def _readiness_boot_check():
    """Log readiness warnings, and stop the process on a fatal one.

    Uses os._exit rather than raising; an unset DATABASE_URL is fatal too, since register_tortoise runs soon after.
    """
    readiness.log_boot_warnings()
    fatal = readiness.boot_error() or database_url_error()
    if fatal:
        logger.critical("Refusing to start: %s", fatal)
        logging.shutdown()
        os._exit(1)


# FastAPI matches routes in the order they are included, so this order is part of the API.
app.include_router(dep_router)
app.include_router(ddm_public_router)
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(tenants_router)
app.include_router(config_router)
app.include_router(tiles_router)
app.include_router(catalogs_router)
app.include_router(flows_router)
app.include_router(devices_router)
app.include_router(declarations_router)
app.include_router(flow_runs_router)
app.include_router(secrets_router)
app.include_router(alerts_router)
app.include_router(commands_router)
app.include_router(tasks_router)
app.include_router(reports_router)
app.include_router(files_router)
app.include_router(manifests_router)
app.include_router(enrollment_router)
app.include_router(audit_router)
app.include_router(integrations_router)
app.include_router(readiness_router)

app.add_event_handler("shutdown", _close_tile_client)

# How long a clean shutdown waits for fire-and-forget handlers before letting the process die with the remainder
# undone. Must stay under supervisord's stopwaitsecs for [program:userapi] and the compose stop_grace_period.
_SHUTDOWN_DRAIN_SECONDS = float(os.getenv("MDM_API_SHUTDOWN_DRAIN_SECONDS", "15"))


# Registered before register_tortoise below: shutdown handlers run in registration order, and the drain must run
# while DB connections are still open, before register_tortoise's own shutdown hook closes them.
@app.on_event("shutdown")
async def _drain_spawned_handlers():
    """Give this process's spawned background work a bounded window to finish.

    Spawned via services.reconciler._spawn; past the window, the remainder is dropped rather than awaited further.
    """
    from controller.services.reconciler import drain_background_tasks
    try:
        await asyncio.wait_for(drain_background_tasks(), timeout=_SHUTDOWN_DRAIN_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(
            "shutdown: spawned handlers still running after %.0fs; dropping the remainder",
            _SHUTDOWN_DRAIN_SECONDS,
        )
    except Exception:
        logger.exception("shutdown: draining spawned handlers failed")


# _pooled_url, not the raw DSN, so this process honours DB_POOL_MAX_SIZE instead of asyncpg's default of five.
register_tortoise(
    app,
    db_url=_pooled_url(DATABASE_URL),
    modules={"models": ["controller.models.tenant"]},
    generate_schemas=False,
    add_exception_handlers=True,
)


# generate_schemas stays off above; init_schema does table creation and late-added columns under one advisory lock
# instead. Registered after register_tortoise so Tortoise.init has run first.
@app.on_event("startup")
async def _init_schema():
    from controller.models.database import init_schema
    await init_schema()
    from controller.services import atc_provision
    if atc_provision.ATC_PROVISION_EXISTING_TENANTS:
        try:
            tenants = await Tenant.filter(is_active=True).all()
            for t in tenants:
                atc_provision.ensure_enrollment_flow(str(t.id))
        except Exception:
            logger.exception("startup: provisioning existing tenants failed")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
