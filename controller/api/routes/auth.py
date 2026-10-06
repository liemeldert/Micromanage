"""Authentication, MFA, and password management endpoints."""
from datetime import datetime, timezone
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from controller.auth.dependencies import Principal, get_current_principal
from controller.auth.passwords import hash_password, password_policy_error, verify_password
from controller.auth.ratelimit import login_limiter
from controller.auth.tokens import (
    decode_mfa_pending_token,
    issue_mfa_pending_token,
    issue_session_token,
    JWT_TTL_SECONDS,
)
from controller.models.tenant import Tenant, User, UserMFA
from controller.services import mfa
from controller.services.audit import record_audit

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
    # Confirming a new authenticator ends every other session, so starting one asks for the password again. Optional
    # only for externally authenticated tenants, which hold no local password.
    password: Optional[str] = None


class MFAConfirmRequest(BaseModel):
    code: str


class MFADisableRequest(BaseModel):
    password: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class DiscoverRequest(BaseModel):
    email: str


@router.post("/api/v1/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest, http_request: Request):
    """Authenticate a local user (email + password) and return a session token.

    Tenants on an external provider (OIDC) do not use this endpoint; their clients present a provider token directly.
    """
    throttle_key = f"{request.tenant_id}:{request.user_email}"
    if not login_limiter.check(throttle_key):
        raise HTTPException(status_code=429, detail="Too many attempts; try again later")

    # Generic to avoid enumeration
    invalid = HTTPException(status_code=401, detail="Invalid credentials")

    tenant = await Tenant.get_or_none(id=request.tenant_id)
    if not tenant or not tenant.is_active:
        raise invalid

    if tenant.auth_provider != "local":
        # Same generic refusal as a missing tenant: naming the provider would tell an anonymous caller that the tenant
        # exists and which IdP it sits behind. /api/v1/auth/discover answers that question for clients that need it.
        raise invalid

    user = await User.get_or_none(tenant=tenant, email=request.user_email)
    if user and user.is_active and user.password_hash:
        ok = verify_password(request.password, user.password_hash)
    else:
        # Always do the bcrypt work so timing doesn't show if a user exists
        verify_password(request.password, _DUMMY_PASSWORD_HASH)
        ok = False
    if not ok:
        raise invalid

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
    # Throttle based on user_id from the verified token
    if not login_limiter.check(str(user_id)):
        raise HTTPException(status_code=429, detail="Too many attempts; try again later")

    user = await User.get_or_none(id=user_id)
    if not user or not user.is_active:
        raise invalid

    if await mfa.verify_code(user, request.code):
        pass
    elif await mfa.verify_recovery_code(user, request.code):
        pass
    else:
        raise invalid

    token = issue_session_token(
        user_id=str(user.id), tenant_id=user.tenant_id, email=user.email, role=user.role
    )
    return TokenResponse(access_token=token, expires_in=JWT_TTL_SECONDS)


@router.post("/api/v1/auth/mfa/enroll")
async def enroll_mfa(request: Optional[MFAEnrollRequest] = None,
                     principal: Principal = Depends(get_current_principal)):
    if principal.tenant.auth_provider == "local":
        password = (request.password if request else None) or ""
        if not principal.user.password_hash or not verify_password(password, principal.user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid password")
    try:
        secret, uri = await mfa.begin_enrollment(principal.user)
        return {"secret": secret, "provisioning_uri": uri}
    except ValueError:
        raise HTTPException(status_code=409, detail="MFA is already confirmed")


@router.post("/api/v1/auth/mfa/confirm")
async def confirm_mfa(request: MFAConfirmRequest, principal: Principal = Depends(get_current_principal)):
    codes = await mfa.confirm_enrollment(principal.user, request.code)
    if codes is None:
        raise HTTPException(status_code=400, detail="Invalid code")

    await record_audit(
        principal,
        "user.mfa_confirm",
        target_id=str(principal.user.id),
        detail={}
    )
    return {"recovery_codes": codes}


@router.delete("/api/v1/auth/mfa", status_code=204)
async def disable_mfa(request: MFADisableRequest, principal: Principal = Depends(get_current_principal)):
    if principal.tenant.auth_provider != "local":
        raise HTTPException(status_code=400, detail="Cannot disable MFA for external provider")

    if not principal.user.password_hash or not verify_password(request.password, principal.user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")

    await mfa.disable(principal.user)

    await record_audit(
        principal,
        "user.mfa_disable",
        target_id=str(principal.user.id),
        detail={}
    )
    return Response(status_code=204)


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
    # Same limiter as sign-in: this route also confirms whether a given password is the right one.
    throttle_key = f"{tenant.id}:{user.email}"
    if not login_limiter.check(throttle_key):
        raise HTTPException(status_code=429, detail="Too many attempts; try again later")
    if not verify_password(request.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
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
async def discover_login(request: DiscoverRequest):
    """Look up which tenants an email address can sign in to and how, confirming to any caller that the address
    has access."""
    email = request.email.strip().lower()
    if not email or not login_limiter.check(f"discover:{email}"):
        raise HTTPException(status_code=429, detail="Too many attempts; try again later")

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
