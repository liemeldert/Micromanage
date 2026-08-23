"""Issuing and verifying controller-issued session JWTs (local auth)."""

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt
# Safe at module scope: services.readiness imports nothing from controller at its own import time.
from controller.services.readiness import is_placeholder

JWT_ALGORITHM = "HS256"
JWT_ISSUER = os.getenv("JWT_ISSUER", "micromanage-controller")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "micromanage-api")
JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", "12"))
JWT_TTL_SECONDS = JWT_EXPIRATION_HOURS * 3600

# Marks a token as controller-issued so verification can distinguish it from externally-issued provider tokens without a
# trial signature check.
TOKEN_TYPE = "session"
MFA_PENDING_TOKEN_TYPE = "mfa_pending"
MFA_PENDING_TTL_SECONDS = 300


class AuthConfigError(RuntimeError):
    """Raised when required auth configuration (e.g. JWT_SECRET) is missing."""


def _secret() -> str:
    """The signing secret, or raise AuthConfigError if unset or a placeholder."""
    secret = os.getenv("JWT_SECRET")
    if not secret or is_placeholder(secret):
        raise AuthConfigError(
            "JWT_SECRET is not configured. Set a strong random value in the "
            "environment (the controller refuses to sign/verify tokens without it)."
        )
    return secret


def issue_session_token(*, user_id: str, tenant_id: str, email: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "typ": TOKEN_TYPE,
        "sub": str(user_id),
        "tenant_id": tenant_id,
        "email": email,
        "role": role,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(hours=JWT_EXPIRATION_HOURS),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALGORITHM)


def decode_session_token(token: str) -> Optional[Dict[str, Any]]:
    """Return validated claims for a controller-issued session token, or None if invalid or provider-issued."""
    try:
        claims = jwt.decode(
            token,
            _secret(),
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            # iat is required: a password change ends every session issued before it (auth.dependencies).
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            leeway=10,
        )
    except (jwt.PyJWTError, AuthConfigError):
        return None
    if claims.get("typ") != TOKEN_TYPE:
        return None
    return claims


def issue_mfa_pending_token(*, user_id: str, tenant_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "typ": MFA_PENDING_TOKEN_TYPE,
        "sub": str(user_id),
        "tenant_id": tenant_id,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=MFA_PENDING_TTL_SECONDS),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALGORITHM)


def decode_mfa_pending_token(token: str) -> Optional[Dict[str, Any]]:
    """Return validated claims for a pending-MFA token, else None."""
    try:
        claims = jwt.decode(
            token,
            _secret(),
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            leeway=10,
        )
    except (jwt.PyJWTError, AuthConfigError):
        return None
    if claims.get("typ") != MFA_PENDING_TOKEN_TYPE:
        return None
    return claims
