"""FastAPI dependencies that establish and authorize the calling principal.

``get_current_principal`` accepts either a controller-issued session token
(local auth) or an externally-issued provider token (Clerk/OIDC), resolves it
to a local ``User`` + ``Tenant``, and returns a ``Principal``. ``require_admin``
layers the admin-role check on top.
"""

import logging
from dataclasses import dataclass
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from controller.auth import ROLE_ADMIN
from controller.auth.providers import ExternalAuthError, ExternalJWTProvider
from controller.auth.tokens import decode_session_token
from controller.models.tenant import Tenant, User

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
        # No hint: consider active tenants configured for external auth and
        # match on issuer. Fine for modest tenant counts.
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
        except Exception as exc:  # network/JWKS failures shouldn't 500 the request
            logger.warning("External auth verification error for tenant %s: %s", tenant.id, exc)
            continue

        sub = claims.get(prov.sub_claim)
        email = claims.get(prov.email_claim)

        user = None
        # Primary, safe binding: the provider subject ("sub") is a stable,
        # IdP-controlled identifier and must be pre-provisioned on the user row.
        if sub:
            user = await User.get_or_none(tenant=tenant, external_id=sub)
        # Email fallback is only safe when the IdP asserts the email is verified.
        # Many IdPs let a user set an arbitrary, unverified email on their own
        # account, so matching an unverified email would allow account takeover.
        if user is None and email and claims.get("email_verified") is True:
            user = await User.get_or_none(tenant=tenant, email=email)

        if user and user.is_active:
            # Bind the external subject on first login so future lookups are
            # stable even if the email changes.
            if sub and not user.external_id:
                user.external_id = sub
                await user.save()
            return Principal(tenant=tenant, user=user, email=user.email, role=user.role)
    return None


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
