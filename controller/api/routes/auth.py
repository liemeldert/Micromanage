"""Authentication, MFA, and password management endpoints."""
from datetime import datetime, timedelta, timezone
import logging
from typing import Hashable, NoReturn, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Security
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel

from controller.auth.dependencies import Principal, get_current_principal, security
from controller.auth.passwords import hash_password, password_policy_error, verify_password
from controller.auth.ratelimit import (
    discover_limiter,
    lockout_audit_limiter,
    login_address_failures,
    login_address_warned,
    login_failures,
)
from controller.auth.tokens import (
    decode_mfa_pending_token,
    decode_session_token,
    TOKEN_LEEWAY_SECONDS,
    issue_mfa_pending_token,
    issue_session_token,
    JWT_TTL_SECONDS,
)
from controller.models.tenant import RevokedSession, Tenant, User, UserMFA
from controller.services import mfa
from controller.services.audit import record_audit, record_system_audit
from controller.services.enrollment import _loggable

logger = logging.getLogger(__name__)

router = APIRouter()

# Equalizes login timing when the user is missing, inactive or has no local password, so latency reveals none of those.
_DUMMY_PASSWORD_HASH = hash_password("timing-equalization-placeholder")


class LoginRequest(BaseModel):
    tenant_id: str
    user_email: str
    password: str


class TokenResponse(BaseModel):
    access_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: Optional[int] = None
    mfa_required: bool = False
    mfa_token: Optional[str] = None


class MFAVerifyRequest(BaseModel):
    mfa_token: str
    code: str


class MFAEnrollRequest(BaseModel):
    # Confirming a new authenticator ends every session, so starting one asks for the password again.
    password: str


class MFAConfirmRequest(BaseModel):
    code: str


class MFADisableRequest(BaseModel):
    password: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class DiscoverRequest(BaseModel):
    email: str


_TOO_MANY = "Too many attempts; try again later"


def _client_address(http_request: Optional[Request]) -> str:
    client = getattr(http_request, "client", None)
    return client.host if client and client.host else "unknown"


def _too_many(wait: int) -> HTTPException:
    return HTTPException(status_code=429, detail=_TOO_MANY, headers={"Retry-After": str(wait)})


def _refuse_if_locked(key: Hashable) -> None:
    wait = login_failures.blocked(key)
    if wait:
        raise _too_many(wait)


async def _refuse_login(key: Hashable, ip: str, email: str, tenant: Optional[Tenant] = None,
                        user: Optional[User] = None) -> NoReturn:
    """Record a failed sign-in and raise the generic 401, or a 429 when this failure starts a lock."""
    wait = login_failures.failed(key)
    if not login_address_failures.check(ip) and login_address_warned.check(ip):
        logger.warning("Sign-in failures from %s reached %d across all accounts within %ds", _loggable(ip),
                       login_failures.failures * 10, login_failures.window_seconds)
    if not wait:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    logger.warning("Sign-in for %s from %s locked for %ds", _loggable(email), _loggable(ip), wait)
    # Only a real account gets an audit row, so made-up emails cannot fill the audit log.
    if tenant is not None and user is not None and user.is_active and user.password_hash \
            and lockout_audit_limiter.check(str(user.id)):
        await record_system_audit(tenant, "user.login_locked", target_type="user", target_id=str(user.id),
                                  detail={"email": email, "ip": ip, "failures": login_failures.count(key),
                                          "lockout_seconds": wait})
    raise _too_many(wait)


@router.post("/api/v1/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest, http_request: Request):
    """Authenticate a local user (email + password) and return a session token.

    Tenants on an external provider (OIDC) do not use this endpoint; their clients present a provider token directly.
    """
    ip = _client_address(http_request)
    email = request.user_email.strip().lower()
    key = (ip, request.tenant_id, email)
    _refuse_if_locked(key)

    # Every refusal counts the same way, so an unknown email is locked exactly as a known one is.
    tenant = await Tenant.get_or_none(id=request.tenant_id)
    if not tenant or not tenant.is_active:
        await _refuse_login(key, ip, email)

    if tenant.auth_provider != "local":
        # Same generic refusal as a missing tenant, as naming the provider would reveal to an anonymous caller that the
        # tenant exists and which IdP it uses. /api/v1/auth/discover provides that for clients that need it.
        await _refuse_login(key, ip, email)

    user = await User.get_or_none(tenant=tenant, email=request.user_email)
    if user and user.is_active and user.password_hash:
        ok = verify_password(request.password, user.password_hash)
    else:
        # The bcrypt work always runs, so timing does not reveal whether a user exists.
        verify_password(request.password, _DUMMY_PASSWORD_HASH)
        ok = False
    if not ok:
        await _refuse_login(key, ip, email, tenant, user)

    # A pending second factor counts as a success here, since verify_mfa_login keeps its own key.
    login_failures.succeeded(key)
    if await mfa.is_enabled(user):
        return TokenResponse(
            access_token=None,
            expires_in=None,
            mfa_required=True,
            mfa_token=issue_mfa_pending_token(user_id=str(user.id), tenant_id=tenant.id)
        )

    token = issue_session_token(
        user_id=str(user.id), tenant_id=tenant.id, email=user.email, role=user.role
    )
    return TokenResponse(access_token=token, expires_in=JWT_TTL_SECONDS)


@router.post("/api/v1/auth/mfa/verify", response_model=TokenResponse)
async def verify_mfa_login(request: MFAVerifyRequest, http_request: Request):
    claims = decode_mfa_pending_token(request.mfa_token)
    invalid = HTTPException(status_code=401, detail="Invalid credentials")
    if not claims:
        raise invalid

    user_id = claims["sub"]
    # No client address in the key, since the pending token already proves the password and expires in minutes.
    key = ("mfa", user_id)
    _refuse_if_locked(key)

    user = await User.get_or_none(id=user_id)
    if not user or not user.is_active:
        raise invalid

    if not await mfa.verify_code(user, request.code) and not await mfa.verify_recovery_code(user, request.code):
        wait = login_failures.failed(key)
        raise _too_many(wait) if wait else invalid
    login_failures.succeeded(key)

    token = issue_session_token(
        user_id=str(user.id), tenant_id=user.tenant_id, email=user.email, role=user.role
    )
    return TokenResponse(access_token=token, expires_in=JWT_TTL_SECONDS)


def _password_key(principal: Principal) -> Hashable:
    """The throttle key for a signed-in user's password check; raises 429 while the key is locked."""
    key = ("password", principal.tenant.id, principal.user.id)
    _refuse_if_locked(key)
    return key


def _password_refused(key: Hashable, detail: str) -> HTTPException:
    """Record a wrong password and return the 401 with detail, or a 429 when this failure starts a lock."""
    wait = login_failures.failed(key)
    return _too_many(wait) if wait else HTTPException(status_code=401, detail=detail)


@router.post("/api/v1/auth/mfa/enroll")
async def enroll_mfa(request: MFAEnrollRequest, principal: Principal = Depends(get_current_principal)):
    if principal.tenant.auth_provider != "local":
        raise HTTPException(status_code=400, detail="Cannot enroll MFA for external provider")
    key = _password_key(principal)
    if not principal.user.password_hash or not verify_password(request.password, principal.user.password_hash):
        raise _password_refused(key, "Invalid password")
    login_failures.succeeded(key)
    try:
        secret, uri = await mfa.begin_enrollment(principal.user)
        return {"secret": secret, "provisioning_uri": uri}
    except ValueError:
        raise HTTPException(status_code=409, detail="MFA is already confirmed")


def _fresh_session(principal: Principal) -> str:
    """A session token issued after an MFA change, which ends every session issued before it."""
    user = principal.user
    return issue_session_token(user_id=str(user.id), tenant_id=principal.tenant.id, email=user.email, role=user.role)


@router.post("/api/v1/auth/mfa/confirm")
async def confirm_mfa(request: MFAConfirmRequest, principal: Principal = Depends(get_current_principal)):
    """Confirm two-factor enrollment. Returns the recovery codes, shown only this once, and a new session token."""
    codes = await mfa.confirm_enrollment(principal.user, request.code)
    if codes is None:
        raise HTTPException(status_code=400, detail="Invalid code")

    await record_audit(
        principal,
        "user.mfa_confirm",
        target_id=str(principal.user.id),
        detail={}
    )
    return {"recovery_codes": codes, "access_token": _fresh_session(principal), "token_type": "bearer",
            "expires_in": JWT_TTL_SECONDS}


@router.delete("/api/v1/auth/mfa", response_model=TokenResponse)
async def disable_mfa(request: MFADisableRequest, principal: Principal = Depends(get_current_principal)):
    """Turn two-factor off after checking the password. Returns a new session token."""
    if principal.tenant.auth_provider != "local":
        raise HTTPException(status_code=400, detail="Cannot disable MFA for external provider")
    key = _password_key(principal)
    if not principal.user.password_hash or not verify_password(request.password, principal.user.password_hash):
        raise _password_refused(key, "Invalid password")
    login_failures.succeeded(key)

    await mfa.disable(principal.user)

    await record_audit(
        principal,
        "user.mfa_disable",
        target_id=str(principal.user.id),
        detail={}
    )
    return TokenResponse(access_token=_fresh_session(principal), expires_in=JWT_TTL_SECONDS)


@router.get("/api/v1/auth/mfa")
async def get_mfa_status(principal: Principal = Depends(get_current_principal)):
    mfa_record = await UserMFA.filter(user_id=principal.user.id).first()
    if mfa_record and mfa_record.confirmed_at:
        return {
            "enabled": True,
            "confirmed_at": mfa_record.confirmed_at.isoformat(),
            "recovery_codes_remaining": len(mfa_record.recovery_codes or [])
        }
    return {
        "enabled": False,
        "confirmed_at": None,
        "recovery_codes_remaining": 0
    }


@router.get("/api/v1/auth/me")
async def whoami(principal: Principal = Depends(get_current_principal)):
    """The authenticated principal: tenant, email, role, and whether it holds the admin role."""
    return {
        "tenant_id": principal.tenant.id,
        "email": principal.email,
        "role": principal.role,
        "is_admin": principal.is_admin,
        "has_password": bool(getattr(principal.user, "password_hash", None)),
    }


@router.post("/api/v1/auth/logout", status_code=204)
async def logout(
    credentials: HTTPAuthorizationCredentials = Security(security),
    principal: Principal = Depends(get_current_principal),
):
    """Sign out, ending only the session that made this request."""
    user = principal.user
    now = datetime.now(timezone.utc)
    claims = decode_session_token(credentials.credentials) or {}
    if claims.get("jti") and claims.get("exp"):
        await RevokedSession.get_or_create(
            jti=str(claims["jti"]),
            defaults={"user": user, "expires_at": datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc)},
        )
    # A row refuses nothing once its token is past exp plus the verification leeway; each sign-out prunes rows a
    # minute beyond that.
    prune_before = now - timedelta(seconds=TOKEN_LEEWAY_SECONDS) - timedelta(minutes=1)
    await RevokedSession.filter(expires_at__lt=prune_before).delete()
    await record_audit(
        principal, "user.logout", target_type="user", target_id=str(user.id), detail={"email": user.email},
    )
    return Response(status_code=204)


@router.post("/api/v1/auth/password", response_model=TokenResponse)
async def change_own_password(
    request: PasswordChangeRequest,
    principal: Principal = Depends(get_current_principal),
):
    """Change the signed-in user's own password after verifying the current one, ending every other session for
    the account."""
    tenant = principal.tenant
    if tenant.auth_provider != "local":
        raise HTTPException(
            status_code=400,
            detail=f"Tenant uses '{tenant.auth_provider}' authentication; passwords are managed by that provider",
        )
    user = principal.user
    if user is None or not user.password_hash:
        raise HTTPException(status_code=400, detail="This account has no local password")
    key = _password_key(principal)
    if not verify_password(request.current_password, user.password_hash):
        raise _password_refused(key, "Current password is incorrect")
    login_failures.succeeded(key)
    problem = password_policy_error(request.new_password)
    if problem:
        raise HTTPException(status_code=400, detail=problem)
    if request.new_password == request.current_password:
        raise HTTPException(status_code=400, detail="New password must differ from the current one")

    user.password_hash = hash_password(request.new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    await user.save(update_fields=["password_hash", "password_changed_at"])
    await record_audit(
        principal, "user.password_change", target_type="user", target_id=str(user.id),
        detail={"email": user.email, "self": True},
    )
    token = issue_session_token(
        user_id=str(user.id), tenant_id=tenant.id, email=user.email, role=user.role
    )
    return TokenResponse(access_token=token, expires_in=JWT_TTL_SECONDS)


@router.post("/api/v1/auth/discover")
async def discover_login(request: DiscoverRequest, http_request: Request):
    """Look up which tenants an email address can sign in to and how, confirming to any caller that the address
    has access."""
    email = request.email.strip().lower()
    if not email or not discover_limiter.check(("discover", _client_address(http_request), email)):
        raise HTTPException(status_code=429, detail=_TOO_MANY)

    users = await User.filter(email__iexact=email, is_active=True).prefetch_related("tenant")
    tenants = []
    for u in users:
        t = u.tenant
        if not t.is_active:
            continue
        cfg = t.auth_config or {}
        entry = {"tenant_id": t.id, "name": t.name, "provider": t.auth_provider}
        # External IdP tenants may configure where a client goes to obtain a provider token.
        if t.auth_provider != "local" and cfg.get("login_url"):
            entry["login_url"] = cfg["login_url"]
        tenants.append(entry)

    return {"tenants": tenants}
