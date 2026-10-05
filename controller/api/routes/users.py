"""User management endpoints (admin only)."""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from controller.api.ids import require_uuid as _require_uuid
from controller.auth import ROLE_ADMIN, ROLE_MEMBER, ROLES
from controller.auth.dependencies import Principal, require_admin
from controller.auth.passwords import hash_password, password_policy_error
from controller.models.tenant import User
from controller.services.audit import record_audit

router = APIRouter()


class UserCreate(BaseModel):
    email: str
    password: Optional[str] = None
    role: str = ROLE_MEMBER
    external_id: Optional[str] = None


class UserUpdate(BaseModel):
    password: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


@router.get("/api/v1/users")
async def list_users(admin: Principal = Depends(require_admin)):
    users = await User.filter(tenant=admin.tenant).all()
    return {
        "users": [
            {
                "id": str(u.id),
                "email": u.email,
                "role": u.role,
                "is_active": u.is_active,
                "has_password": bool(u.password_hash),
                "external_id": u.external_id,
            }
            for u in users
        ]
    }


@router.post("/api/v1/users", status_code=201)
async def create_user(payload: UserCreate, admin: Principal = Depends(require_admin)):
    if payload.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {sorted(ROLES)}")
    if await User.get_or_none(tenant=admin.tenant, email=payload.email):
        raise HTTPException(status_code=409, detail="User already exists")
    if admin.tenant.auth_provider == "local" and not payload.password:
        raise HTTPException(status_code=400, detail="password required for local-auth tenants")
    if payload.password is not None:
        problem = password_policy_error(payload.password)
        if problem:
            raise HTTPException(status_code=400, detail=problem)

    user = await User.create(
        tenant=admin.tenant,
        email=payload.email,
        role=payload.role,
        external_id=payload.external_id,
        password_hash=hash_password(payload.password) if payload.password else None,
        # Stamped from the outset so the column means when the current password was set, not whether it has ever been
        # replaced. Nothing predates it, so no live session is cut off.
        password_changed_at=(datetime.now(timezone.utc) if payload.password else None),
    )
    await record_audit(
        admin,
        "user.create",
        target_type="user",
        target_id=str(user.id),
        # Non-secret facts only: never the password itself.
        detail={
            "email": user.email,
            "role": user.role,
            "password_set": bool(payload.password),
            "external_id_set": bool(payload.external_id),
        },
    )
    return {"id": str(user.id), "email": user.email, "role": user.role}


@router.put("/api/v1/users/{user_id}")
async def update_user(user_id: str, payload: UserUpdate, admin: Principal = Depends(require_admin)):
    _require_uuid(user_id, "User not found")
    user = await User.get_or_none(id=user_id, tenant=admin.tenant)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if payload.role is not None:
        if payload.role not in ROLES:
            raise HTTPException(status_code=400, detail=f"role must be one of {sorted(ROLES)}")
        # lol I accidentally did this on accident
        if user.role == ROLE_ADMIN and payload.role != ROLE_ADMIN:
            if str(user.id) == str(admin.user.id):
                raise HTTPException(
                    status_code=400, detail="Cannot change your own role",
                )
            remaining_admins = await User.filter(
                tenant=admin.tenant, role=ROLE_ADMIN, is_active=True,
            ).exclude(id=user.id).count()
            if remaining_admins == 0:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot demote the last active admin in this tenant",
                )
        user.role = payload.role
    if payload.password is not None:
        problem = password_policy_error(payload.password)
        if problem:
            raise HTTPException(status_code=400, detail=problem)
        user.password_hash = hash_password(payload.password)
        # Stored to invalidate all existing sessions
        user.password_changed_at = datetime.now(timezone.utc)
    if payload.is_active is not None:
        # Don't let an admin deactivate themselves
        if not payload.is_active and str(user.id) == str(admin.user.id):
            raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
        if not payload.is_active and user.role == ROLE_ADMIN:
            remaining_admins = await User.filter(
                tenant=admin.tenant, role=ROLE_ADMIN, is_active=True,
            ).exclude(id=user.id).count()
            if remaining_admins == 0:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot deactivate the last active admin in this tenant",
                )
        user.is_active = payload.is_active
    await user.save()
    # Record which fields changed, as booleans. Never the new password itself.
    changed = {
        "role": payload.role is not None,
        "password": payload.password is not None,
        "is_active": payload.is_active is not None,
    }
    await record_audit(
        admin,
        "user.update",
        target_type="user",
        target_id=str(user.id),
        detail={"email": user.email, "changed": changed},
    )
    return {"message": "User updated"}


@router.delete("/api/v1/users/{user_id}")
async def delete_user(user_id: str, admin: Principal = Depends(require_admin)):
    _require_uuid(user_id, "User not found")
    user = await User.get_or_none(id=user_id, tenant=admin.tenant)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if str(user.id) == str(admin.user.id):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    deleted_email = user.email  # captured before deletion for the audit log
    deleted_role = user.role
    await user.delete()
    await record_audit(
        admin,
        "user.delete",
        target_type="user",
        target_id=user_id,
        detail={"email": deleted_email, "role": deleted_role},
    )
    return {"message": "User deleted"}
