"""Readiness and health check endpoints."""
from datetime import datetime, timezone
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from controller.auth.dependencies import get_current_principal
from controller.models.database import schema_status
from controller.models.tenant import Tenant
from controller.services import readiness
from controller.version import __version__

logger = logging.getLogger(__name__)

router = APIRouter()

# auto_error=False so a caller with no credentials reaches the handler below instead of being turned away by the
# security dependency with a 403. The 403 is the thing this endpoint must not answer: it confirms the endpoint exists.
_readiness_bearer = HTTPBearer(auto_error=False)


@router.get("/api/v1/readiness")
async def get_readiness(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(_readiness_bearer),
):
    """Report this deployment's readiness capability by capability (admin only, no secret values), returning 404
    rather than 401/403 to an unauthenticated caller so the route's existence stays unconfirmed to a scanner."""
    not_found = HTTPException(status_code=404, detail="Not found")
    if credentials is None:
        raise not_found
    try:
        principal = await get_current_principal(request, credentials)
    except HTTPException:
        raise not_found
    if not principal.is_admin:
        raise HTTPException(status_code=403, detail="Admin role required")
    # One warning reads this, so it stays quiet about cross-tenant enrollment on a deployment with only one tenant.
    active_tenants = await Tenant.filter(is_active=True).count()
    body = readiness.report(tenant=principal.tenant, active_tenants=active_tenants)
    # Which build this is and whether the database is at its schema. Admin only, like the rest of this body; /health
    # says only that the process is up.
    try:
        schema = await schema_status()
    except Exception:
        logger.exception("readiness: schema status failed")
        schema = None
    body["system"] = {"version": __version__, "schema": schema}
    return body


# deploy/healthcheck.py calls this together with the webhook process's /health and the scheduler's heartbeat
# file, so a container with any of the three dead reads unhealthy.
@router.get("/api/v1/health")
async def health_check():
    """Up, and able to reach the database."""
    from tortoise import Tortoise
    try:
        await Tortoise.get_connection("default").execute_query("SELECT 1")
    except Exception:
        logger.exception("health: database check failed")
        raise HTTPException(status_code=503, detail="database unreachable")
    return {"status": "healthy", "version": __version__,
            "timestamp": datetime.now(timezone.utc)}
