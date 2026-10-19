"""Mac agent credentials: bearer tokens, enrollment codes, the require_agent dependency and token rotation."""

import hashlib
import logging
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from fastapi import HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from tortoise.expressions import Q

from controller.models.tenant import Device, DeviceAgent, Tenant
from controller.services import alerts, crypto_secrets
from controller.services.audit import record_system_audit
from controller.utils.coerce import env_flag
from controller.utils.timeutil import as_utc, utcnow

logger = logging.getLogger(__name__)

TOKEN_PREFIX = "mm_ag_"
CODE_PREFIX = "mm_ec_"
DISPLAY_PREFIX_LENGTH = 12
_TOKEN_FORMAT = re.compile(r"mm_ag_[0-9a-f]{64}")
_CODE_FORMAT = re.compile(r"mm_ec_[0-9a-f]{32}")

# Details the daemon shows in the menu bar app. Tests assert on these constants.
AGENT_ERRORS = {
    "token_invalid": "This Mac's agent credential is not valid. Push a new agent configuration to enroll it again.",
    "tenant_inactive": "This Mac's organization is inactive. Reactivate the organization to resume agent check-ins.",
    "code_invalid": "The enrollment code is not valid. Push a new agent configuration to this Mac.",
    "not_mdm_enrolled": "This Mac is not enrolled in MDM for this organization. Enroll it in MDM, then push a new "
                        "agent configuration.",
    "task_not_found": "This Mac has no such task.",
    "task_closed": "This task already has a result.",
    "remove_self": "This bundle contains the agent and cannot be removed by an agent task.",
    "body_too_large": "The request body is larger than the server accepts.",
}

VIA_CURRENT = "current"
VIA_PENDING = "pending"
VIA_PREVIOUS = "previous"

TOKEN_REUSE_RULE = "agent:token_reuse"

# The stamp of last_seen_at, last_ip and user_agent is written at most this often per agent row.
_STAMP_INTERVAL = timedelta(minutes=1)

_agent_bearer = HTTPBearer(auto_error=False)


def env_int(name: str, default: int) -> int:
    """A positive int from the environment, read at call time, falling back to default."""
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return max(1, int(raw))
    except ValueError:
        return default


def agent_enabled() -> bool:
    return env_flag("MDM_AGENT_ENABLED")


def enrollment_code_ttl() -> timedelta:
    return timedelta(hours=env_int("AGENT_ENROLLMENT_CODE_TTL_HOURS", 24))


def token_rotate_after() -> timedelta:
    return timedelta(days=env_int("AGENT_TOKEN_ROTATE_DAYS", 30))


def token_grace() -> timedelta:
    """How long a superseded token stays valid for task results."""
    return timedelta(minutes=env_int("AGENT_TOKEN_GRACE_MINUTES", 360))


def token_overlap() -> timedelta:
    """How long a superseded token stays valid on every route."""
    return timedelta(minutes=env_int("AGENT_TOKEN_OVERLAP_MINUTES", 10))


def generate_agent_token() -> str:
    return f"{TOKEN_PREFIX}{secrets.token_hex(32)}"


def generate_enrollment_code() -> str:
    return f"{CODE_PREFIX}{secrets.token_hex(16)}"


def hash_secret(value: str) -> str:
    """sha256 hex of a token or code, the value stored and looked up."""
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def display_prefix(value: str) -> str:
    return value[:DISPLAY_PREFIX_LENGTH]


def is_agent_token(value: Optional[str]) -> bool:
    return isinstance(value, str) and _TOKEN_FORMAT.fullmatch(value) is not None


def is_enrollment_code(value: Optional[str]) -> bool:
    return isinstance(value, str) and _CODE_FORMAT.fullmatch(value) is not None


def _pending_aad(agent_id) -> str:
    return f"device_agent/{agent_id}/pending"


def cleared_credential() -> dict:
    """Column values for a revoke or a re-enrollment, applied with an update. Every token hash and the sealed pending
    token are nulled together."""
    return {
        "token_hash": None, "pending_token_hash": None, "pending_token_issued_at": None, "pending_token_enc": None,
        "previous_token_hash": None, "previous_token_valid_until": None, "previous_promoted_at": None,
        "rotation_requested_at": None,
    }


@dataclass
class AgentPrincipal:
    agent: DeviceAgent
    device: Device
    tenant: Tenant
    via: str  # current | pending | previous


def _token_invalid() -> HTTPException:
    return HTTPException(status_code=401, detail=AGENT_ERRORS["token_invalid"])


def _remote(request: Request) -> Optional[str]:
    return request.client.host[:64] if request.client and request.client.host else None


async def _agent_audit(tenant: Tenant, device: Device, action: str, detail: dict) -> None:
    await record_system_audit(tenant, action, target_type="device", target_id=str(device.id),
                              detail={"actor": "agent", "serial_number": device.serial_number, **detail})


async def _promote_pending(agent: DeviceAgent, token: str, token_hash: str, tenant: Tenant, device: Device,
                           now: datetime) -> str:
    """Make the pending token current and keep the old one as previous. Returns how the request authenticated."""
    old_prefix = agent.token_prefix
    promoted = await DeviceAgent.filter(id=agent.id, pending_token_hash=token_hash, token_hash=agent.token_hash).update(
        previous_token_hash=agent.token_hash, previous_promoted_at=now, previous_token_valid_until=now + token_grace(),
        token_hash=token_hash, token_prefix=display_prefix(token), token_issued_at=now, pending_token_hash=None,
        pending_token_issued_at=None, pending_token_enc=None, rotation_requested_at=None,
    )
    await agent.refresh_from_db()
    if promoted == 1:
        await _agent_audit(tenant, device, "agent.token.rotate",
                           {"old_prefix": old_prefix, "new_prefix": agent.token_prefix})
        return VIA_PENDING
    if agent.token_hash == token_hash:
        # A concurrent request with the same token promoted it first.
        return VIA_CURRENT
    raise _token_invalid()


async def _check_previous(agent: DeviceAgent, request: Request, tenant: Tenant, device: Device, now: datetime,
                          allow_until_grace: bool) -> None:
    """Accept a superseded token inside the overlap window, or on the result route until the grace window ends.
    Any other use raises 401 and records the reuse."""
    promoted_at = as_utc(agent.previous_promoted_at) if agent.previous_promoted_at else None
    valid_until = as_utc(agent.previous_token_valid_until) if agent.previous_token_valid_until else None
    if promoted_at is not None and now <= promoted_at + token_overlap():
        return
    if allow_until_grace and valid_until is not None and now <= valid_until:
        return
    remote = _remote(request)
    route = request.url.path
    await alerts.raise_or_bump(
        device, TOKEN_REUSE_RULE, "agent_token_reuse",
        f"{device.serial_number} presented an older agent credential; pushing a new agent configuration restores it",
        {"route": route, "remote_addr": remote}, severity="red",
    )
    await _agent_audit(tenant, device, "agent.token.reuse",
                       {"prefix": agent.token_prefix, "route": route, "remote_addr": remote})
    raise _token_invalid()


async def _stamp(agent: DeviceAgent, request: Request, now: datetime) -> None:
    remote = _remote(request)
    user_agent = (request.headers.get("user-agent") or "")[:128] or None
    stamped = await DeviceAgent.filter(
        Q(last_seen_at__isnull=True) | Q(last_seen_at__lt=now - _STAMP_INTERVAL), id=agent.id,
    ).update(last_seen_at=now, last_ip=remote, user_agent=user_agent)
    if stamped:
        agent.last_seen_at, agent.last_ip, agent.user_agent = now, remote, user_agent


async def authenticate_agent(request: Request, credentials: Optional[HTTPAuthorizationCredentials], *,
                             allow_previous_until_grace: bool) -> AgentPrincipal:
    """Resolve the agent behind a bearer token, applying the rotation rules. allow_previous_until_grace is set on the
    task result route only. Never issues a rotation token."""
    if not agent_enabled():
        raise HTTPException(status_code=404, detail="Not Found")
    token = credentials.credentials if credentials is not None else None
    if not is_agent_token(token):
        raise _token_invalid()
    token_hash = hash_secret(token)
    agent = await DeviceAgent.filter(
        Q(token_hash=token_hash) | Q(pending_token_hash=token_hash) | Q(previous_token_hash=token_hash)
    ).first()
    if agent is None or agent.status == "revoked":
        raise _token_invalid()
    device = await Device.get_or_none(id=agent.device_id)
    # A device that left MDM, or whose row now belongs to another tenant, keeps no agent credential.
    if device is None or device.enrollment_state != "enrolled" or device.tenant_id != agent.tenant_id:
        raise _token_invalid()
    tenant = await Tenant.get_or_none(id=agent.tenant_id)
    if tenant is None:
        raise _token_invalid()
    if not tenant.is_active:
        raise HTTPException(status_code=403, detail=AGENT_ERRORS["tenant_inactive"])

    now = utcnow()
    if token_hash == agent.token_hash:
        via = VIA_CURRENT
    elif token_hash == agent.pending_token_hash:
        via = await _promote_pending(agent, token, token_hash, tenant, device, now)
    else:
        await _check_previous(agent, request, tenant, device, now, allow_previous_until_grace)
        via = VIA_PREVIOUS
    await _stamp(agent, request, now)
    return AgentPrincipal(agent=agent, device=device, tenant=tenant, via=via)


async def require_agent(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(_agent_bearer),
) -> AgentPrincipal:
    """The agent for the heartbeat and elevation request routes."""
    return await authenticate_agent(request, credentials, allow_previous_until_grace=False)


async def require_agent_result(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(_agent_bearer),
) -> AgentPrincipal:
    """The agent for the task result route, which also accepts a superseded token until the grace window ends."""
    return await authenticate_agent(request, credentials, allow_previous_until_grace=True)


def rotation_due(agent: DeviceAgent, now: datetime) -> bool:
    if agent.rotation_requested_at is not None:
        return True
    return now - as_utc(agent.token_issued_at) >= token_rotate_after()


def _read_pending(agent: DeviceAgent) -> Optional[str]:
    token = crypto_secrets.decrypt(agent.pending_token_enc, aad=_pending_aad(agent.id))
    if token is None or hash_secret(token) != agent.pending_token_hash:
        logger.warning("agent %s: the pending rotation token is unreadable; rotation waits", agent.id)
        return None
    return token


async def rotation_token(principal: AgentPrincipal, now: datetime, using_db=None) -> Optional[str]:
    """The rotate_token for a heartbeat response, or None. A pending token is sent again until the daemon uses it; a
    new one is issued only when rotation is due and none is pending, and never for a request with the previous token.
    """
    agent = principal.agent
    if principal.via == VIA_PREVIOUS or agent.status != "active" or agent.token_hash is None:
        return None
    if agent.pending_token_hash:
        return _read_pending(agent)
    if not rotation_due(agent, now):
        return None
    token = generate_agent_token()
    try:
        sealed = crypto_secrets.encrypt(token, aad=_pending_aad(agent.id))
    except Exception:
        logger.exception("agent %s: could not seal a rotation token", agent.id)
        return None
    token_hash = hash_secret(token)
    queryset = DeviceAgent.filter(id=agent.id, pending_token_hash__isnull=True, token_hash=agent.token_hash)
    if using_db is not None:
        queryset = queryset.using_db(using_db)
    issued = await queryset.update(pending_token_hash=token_hash, pending_token_issued_at=now,
                                   pending_token_enc=sealed)
    if issued == 1:
        agent.pending_token_hash, agent.pending_token_issued_at, agent.pending_token_enc = token_hash, now, sealed
        return token
    await agent.refresh_from_db(using_db=using_db)
    return _read_pending(agent) if agent.pending_token_hash else None
