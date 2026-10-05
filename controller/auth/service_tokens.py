"""Service token generation, hashing, verification, and audit tracking."""

import hashlib
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from controller.models.tenant import ServiceToken, Tenant
from controller.services.audit import record_system_audit
from controller.utils.timeutil import as_utc

logger = logging.getLogger(__name__)

TOKEN_PREFIX = "mm_st_"
SCOPES = ("inventory:read",)
_TOKEN_BODY = re.compile(r"[0-9a-f]{64}")


def generate_service_token() -> str:
    """Generate a high-entropy opaque service token string."""
    return f"{TOKEN_PREFIX}{secrets.token_hex(32)}"


def hash_service_token(token: str) -> str:
    """Compute the SHA-256 digest of a service token for lookup."""
    return hashlib.sha256(token.encode("ascii")).hexdigest()


async def create_service_token(
    tenant: Tenant,
    name: str,
    scopes: List[str],
    expires_at: datetime,
    created_by: Optional[str] = None,
) -> Tuple[ServiceToken, str]:
    """Create a new service token, returning the persisted row and the raw plaintext token."""
    if not expires_at:
        raise ValueError("expires_at is mandatory for service tokens")
    unknown = sorted(set(scopes) - set(SCOPES))
    if not scopes or unknown:
        raise ValueError(f"Unknown or missing scopes: {', '.join(unknown) or 'none given'}. "
                         f"Valid scopes: {', '.join(SCOPES)}")

    now = datetime.now(timezone.utc)
    exp = as_utc(expires_at)
    if exp <= now:
        raise ValueError("expires_at must be in the future")

    raw_token = generate_service_token()
    token_hash = hash_service_token(raw_token)

    token = await ServiceToken.create(
        tenant=tenant,
        name=name,
        token_hash=token_hash,
        scopes=list(scopes),
        expires_at=exp,
        created_by=created_by,
    )

    await record_system_audit(
        tenant,
        "service_token.created",
        target_type="service_token",
        target_id=str(token.id),
        detail={
            "name": name,
            "scopes": scopes,
            "expires_at": exp.isoformat(),
            "created_by": created_by,
        },
    )

    return token, raw_token


async def revoke_service_token(
    token: ServiceToken,
    revoked_by: Optional[str] = None,
) -> ServiceToken:
    """Revoke an active service token by stamping revoked_at."""
    if token.revoked_at is None:
        token.revoked_at = datetime.now(timezone.utc)
        await token.save(update_fields=["revoked_at"])
        tenant = await token.tenant
        await record_system_audit(
            tenant,
            "service_token.revoked",
            target_type="service_token",
            target_id=str(token.id),
            detail={"name": token.name, "revoked_by": revoked_by},
        )
    return token


async def verify_service_token(
    raw_token: str,
    required_scope: Optional[str] = None,
) -> Optional[ServiceToken]:
    """Validate a raw service token, enforcing expiration, revocation, tenant active state, and scopes."""
    if not raw_token or not raw_token.startswith(TOKEN_PREFIX):
        return None
    if not _TOKEN_BODY.fullmatch(raw_token[len(TOKEN_PREFIX):]):
        return None

    token_hash = hash_service_token(raw_token)
    token = await ServiceToken.get_or_none(token_hash=token_hash).prefetch_related("tenant")
    if not token or token.revoked_at is not None:
        return None

    now = datetime.now(timezone.utc)
    exp = as_utc(token.expires_at)
    if exp <= now:
        return None

    tenant = await token.tenant
    if not tenant or not tenant.is_active:
        return None

    if required_scope:
        token_scopes = token.scopes or []
        if required_scope not in token_scopes:
            return None

    should_audit = False
    if token.last_used_at is None:
        should_audit = True
    else:
        if (now - as_utc(token.last_used_at)) >= timedelta(days=1):
            should_audit = True

    if should_audit:
        await record_system_audit(
            tenant,
            "service_token.used",
            target_type="service_token",
            target_id=str(token.id),
            detail={"name": token.name, "scope": required_scope},
        )

    token.last_used_at = now
    await token.save(update_fields=["last_used_at"])
    return token
