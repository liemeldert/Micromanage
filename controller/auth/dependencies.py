"""FastAPI dependencies that establish and authorize the calling principal.

See docs/controller/auth/dependencies.md for full details on authorization flow and timestamp comparisons.
"""

import logging
from dataclasses import dataclass
from datetime import timezone
from typing import Any, Dict, Optional

import jwt
from controller.auth import ROLE_ADMIN
from controller.auth.providers import ExternalAuthError, ExternalJWTProvider
from controller.auth.tokens import decode_session_token
from controller.models.tenant import Tenant, User
from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)

security = HTTPBearer()


@dataclass
class Principal:
    tenant: Tenant
    user: User
    email: str
    role: str

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN


async def _resolve_external(token: str, tenant_hint: Optional[str]) -> Optional[Principal]:
    """Verify an external provider token and map it to a local user."""
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None

    iss = unverified.get("iss")

    if tenant_hint:
        tenants = await Tenant.filter(id=tenant_hint, is_active=True)
    else:
        # No hint: consider active tenants configured for external auth and match on issuer. Fine for modest tenant
        # counts.
        tenants = await Tenant.filter(is_active=True)

    for tenant in tenants:
        cfg = tenant.auth_config or {}
        provider = cfg.get("provider", "local")
        if provider not in ("clerk", "oidc"):
            continue
        cfg_issuer = cfg.get("issuer")
        if cfg_issuer and iss and cfg_issuer.rstrip("/") != iss.rstrip("/"):
            continue
        try:
            prov = ExternalJWTProvider(provider, cfg)
            claims = await prov.verify(token)
        except (ExternalAuthError, jwt.PyJWTError):
            continue
        except Exception as exc:  # a network or JWKS failure must not 500 the request
            logger.warning("External auth verification error for tenant %s: %s", tenant.id, exc)
            continue

        sub = claims.get(prov.sub_claim)
        email = claims.get(prov.email_claim)

        user = None
        # Primary, safe binding: the provider subject ("sub") is a stable, IdP-controlled identifier and must be
        # pre-provisioned on the user row.
        if sub:
            user = await User.get_or_none(tenant=tenant, external_id=sub)
        # Email fallback is only safe when the IdP asserts the email is verified. Many IdPs let a user set an arbitrary,
        # unverified email on their own account, so matching an unverified email would allow account takeover.
        if user is None and email and claims.get("email_verified") is True:
            user = await User.get_or_none(tenant=tenant, email=email)

        if user and user.is_active:
            # Bind the external subject on first login so future lookups are stable even if the email changes.
            if sub and not user.external_id:
                user.external_id = sub
                await user.save()
            return Principal(tenant=tenant, user=user, email=user.email, role=user.role)
    return None


def _superseded_by_timestamp(claims: Dict[str, Any], changed_at) -> bool:
    """Whether this session was minted before the given user-row timestamp.

    See docs/controller/auth/dependencies.md for timestamp comparison details.
    """
    if not changed_at:
        return False
    issued_at = claims.get("iat")
    if issued_at is None:
        # decode_session_token requires iat, so this is unreachable for a valid session token. A token that cannot be
        # placed in time is refused.
        return True
    if changed_at.tzinfo is None:
        changed_at = changed_at.replace(tzinfo=timezone.utc)
    return int(issued_at) < int(changed_at.timestamp())


def _superseded_by_password_change(claims: Dict[str, Any], user: User) -> bool:
    """Whether this session was minted before the user's password was last changed.

    See _superseded_by_timestamp for how the comparison works.
    """
    return _superseded_by_timestamp(claims, getattr(user, "password_changed_at", None))


def _superseded_by_mfa_change(claims: Dict[str, Any], user: User) -> bool:
    """Whether this session was minted before the user's MFA settings were last changed.

    See _superseded_by_timestamp for how the comparison works.
    """
    return _superseded_by_timestamp(claims, getattr(user, "mfa_changed_at", None))


async def get_current_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> Principal:
    token = credentials.credentials

    # 1. Controller-issued session token (local auth).
    claims = decode_session_token(token)
    if claims:
        tenant = await Tenant.get_or_none(id=claims.get("tenant_id"))
        if not tenant or not tenant.is_active:
            raise HTTPException(status_code=401, detail="Invalid tenant")
        user = await User.get_or_none(id=claims.get("sub"), tenant=tenant)
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not authorized")
        if _superseded_by_password_change(claims, user):
            raise HTTPException(
                status_code=401,
                detail="This session ended when the password was changed. Sign in "
                       "again with the new password.",
            )
        if _superseded_by_mfa_change(claims, user):
            raise HTTPException(
                status_code=401,
                detail="This session ended when two-factor authentication was "
                       "changed. Sign in again.",
            )
        return Principal(tenant=tenant, user=user, email=user.email, role=user.role)

    # 2. Externally-issued provider token (Clerk / OIDC).
    tenant_hint = request.headers.get("X-Tenant-Id")
    principal = await _resolve_external(token, tenant_hint)
    if principal:
        return principal

    raise HTTPException(status_code=401, detail="Invalid or unsupported token")


async def require_admin(
    principal: Principal = Depends(get_current_principal),
) -> Principal:
    if principal.role != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="Admin role required")
    return principal
