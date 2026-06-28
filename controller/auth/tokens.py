"""Issuing and verifying controller-issued session JWTs (local auth).

These are short-lived HS256 tokens minted by the controller after a successful
local password login. They carry an issuer/audience/jti so they can be told
apart from externally-issued (Clerk/OIDC) tokens and validated strictly.

The signing secret is required: there is intentionally no insecure built-in
default. If ``JWT_SECRET`` is unset the controller fails closed at token time.
"""

import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

import jwt

JWT_ALGORITHM = "HS256"
JWT_ISSUER = os.getenv("JWT_ISSUER", "micromanage-controller")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "micromanage-api")
JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", "12"))
JWT_TTL_SECONDS = JWT_EXPIRATION_HOURS * 3600

# Marks a token as controller-issued so verification can distinguish it from
# externally-issued provider tokens without a trial signature check.
TOKEN_TYPE = "session"


class AuthConfigError(RuntimeError):
    """Raised when required auth configuration (e.g. JWT_SECRET) is missing."""


def _secret() -> str:
    secret = os.getenv("JWT_SECRET")
    if not secret or secret == "your-secret-key-change-in-production":
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
    """Return validated claims for a controller-issued session token, else None.

    Returns None (rather than raising) for anything that isn't a valid,
    in-date, correctly-scoped controller session token — including externally
    issued provider tokens, which are handled by a different code path.
    """
    try:
        claims = jwt.decode(
            token,
            _secret(),
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iss", "aud", "sub"]},
            leeway=10,
        )
    except (jwt.PyJWTError, AuthConfigError):
        return None
    if claims.get("typ") != TOKEN_TYPE:
        return None
    return claims
