import asyncio
import logging
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional

import yaml
from controller.utils.yaml_validator import YAMLValidator
from fastapi import FastAPI, HTTPException, Depends, Request, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field
from tortoise.contrib.fastapi import register_tortoise

from controller.auth import ROLE_ADMIN, ROLE_MEMBER, ROLES, DESTRUCTIVE_COMMANDS
from controller.auth.dependencies import Principal, get_current_principal, require_admin
from controller.auth.passwords import hash_password, verify_password
from controller.auth.ratelimit import login_limiter
from controller.auth.tokens import issue_session_token, JWT_TTL_SECONDS
from controller.models.database import DATABASE_URL
from controller.models.tenant import (
    Tenant,
    User,
    Device,
    Task,
    AppDeployment,
    ProfileDeployment,
)
from controller.services.app_manager import AppManager
from controller.services.mdm_connector import MDMConnector
from controller.services.task_manager import TaskManager
from controller.services import enrollment as enrollment_svc

app = FastAPI(title="MDM IAC API", version="1.0.0")
logger = logging.getLogger(__name__)

# Shared task manager so cancellation/state is visible across requests within
# this process (a per-request instance made cancel a no-op).
task_manager = TaskManager()

# CORS: the browser talks to the controller only through the Next.js proxy
# (same-origin), so cross-origin access should be tightly scoped. Configure
# explicit origins via CORS_ALLOWED_ORIGINS (comma-separated); default to the
# local dev web UI. Never "*" on a control-plane API.
_cors_origins = [
    o.strip()
    for o in os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Tenant-Id"],
    expose_headers=["Content-Disposition"],
)

_SECRET_S3_KEYS = ("secret_access_key", "access_key_id", "session_token")

# Precomputed hash used to equalize login timing when the user is missing or has
# no local password, so response latency doesn't reveal account existence.
_DUMMY_PASSWORD_HASH = hash_password("timing-equalization-placeholder")


def _redact_s3_config(s3_config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Strip credential material from an S3 config before returning it."""
    cfg = dict(s3_config or {})
    for key in _SECRET_S3_KEYS:
        if key in cfg:
            cfg[key] = "***redacted***"
    return cfg


def _atomic_write_yaml(path: Path, data: Dict[str, Any]) -> None:
    """Write YAML to ``path`` atomically (write temp + os.replace)."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        yaml.safe_dump(data, f, default_flow_style=False)
    os.replace(tmp, path)


# Base models
class LoginRequest(BaseModel):
    tenant_id: str
    user_email: str
    password: str


class UserCreate(BaseModel):
    email: str
    password: Optional[str] = None
    role: str = ROLE_MEMBER
    external_id: Optional[str] = None


class UserUpdate(BaseModel):
    password: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TenantCreate(BaseModel):
    id: str = Field(..., regex="^[a-zA-Z0-9-_]+$")
    name: str
    allowed_users: List[str] = []
    s3_bucket: Optional[str] = None
    s3_region: str = "us-east-1"
    dep_enabled: bool = False


class TenantUpdate(BaseModel):
    name: Optional[str] = None
    allowed_users: Optional[List[str]] = None
    s3_config: Optional[Dict[str, Any]] = None
    dep_enabled: Optional[bool] = None
    is_active: Optional[bool] = None


class GroupConfig(BaseModel):
    groups: List[Dict[str, Any]]


class AppConfig(BaseModel):
    apps: List[Dict[str, Any]]


class ProfileConfig(BaseModel):
    profiles: List[Dict[str, Any]]


class CommandRequest(BaseModel):
    command_type: str
    parameters: Dict[str, Any] = {}


class DeviceFilter(BaseModel):
    group: Optional[str] = None
    model: Optional[str] = None
    os_version: Optional[str] = None
    last_seen_days: Optional[int] = None


# Authentication / authorization dependencies live in controller.auth
# (get_current_principal / require_admin are imported above).


# Auth endpoints
@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest, http_request: Request):
    """Authenticate a local user (email + password) and return a session token.

    Tenants configured for an external provider (Clerk/OIDC) do not use this
    endpoint; their clients present a provider-issued token directly.
    """
    throttle_key = f"{request.tenant_id}:{request.user_email}"
    if not login_limiter.check(throttle_key):
        raise HTTPException(status_code=429, detail="Too many attempts; try again later")

    # Generic error to avoid tenant/user enumeration.
    invalid = HTTPException(status_code=401, detail="Invalid credentials")

    tenant = await Tenant.get_or_none(id=request.tenant_id)
    if not tenant or not tenant.is_active:
        raise invalid

    if tenant.auth_provider != "local":
        raise HTTPException(
            status_code=400,
            detail=f"Tenant uses '{tenant.auth_provider}' authentication; "
                   f"present a provider-issued token in the Authorization header",
        )

    user = await User.get_or_none(tenant=tenant, email=request.user_email)
    if user and user.is_active and user.password_hash:
        ok = verify_password(request.password, user.password_hash)
    else:
        # Always do the bcrypt work so timing doesn't reveal user existence.
        verify_password(request.password, _DUMMY_PASSWORD_HASH)
        ok = False
    if not ok:
        raise invalid

    token = issue_session_token(
        user_id=str(user.id), tenant_id=tenant.id, email=user.email, role=user.role
    )
    return TokenResponse(access_token=token, expires_in=JWT_TTL_SECONDS)


@app.get("/api/v1/auth/me")
async def whoami(principal: Principal = Depends(get_current_principal)):
    """Return the authenticated principal (UI uses this to gate admin actions)."""
    return {
        "tenant_id": principal.tenant.id,
        "email": principal.email,
        "role": principal.role,
        "is_admin": principal.is_admin,
    }


# User management (admin only)
@app.get("/api/v1/users")
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


@app.post("/api/v1/users", status_code=201)
async def create_user(payload: UserCreate, admin: Principal = Depends(require_admin)):
    if payload.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {sorted(ROLES)}")
    if await User.get_or_none(tenant=admin.tenant, email=payload.email):
        raise HTTPException(status_code=409, detail="User already exists")
    if admin.tenant.auth_provider == "local" and not payload.password:
        raise HTTPException(status_code=400, detail="password required for local-auth tenants")

    user = await User.create(
        tenant=admin.tenant,
        email=payload.email,
        role=payload.role,
        external_id=payload.external_id,
        password_hash=hash_password(payload.password) if payload.password else None,
    )
    return {"id": str(user.id), "email": user.email, "role": user.role}


@app.put("/api/v1/users/{user_id}")
async def update_user(user_id: str, payload: UserUpdate, admin: Principal = Depends(require_admin)):
    user = await User.get_or_none(id=user_id, tenant=admin.tenant)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if payload.role is not None:
        if payload.role not in ROLES:
            raise HTTPException(status_code=400, detail=f"role must be one of {sorted(ROLES)}")
        user.role = payload.role
    if payload.password is not None:
        user.password_hash = hash_password(payload.password)
    if payload.is_active is not None:
        # Don't let an admin deactivate themselves and risk locking the tenant out.
        if not payload.is_active and str(user.id) == str(admin.user.id):
            raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
        user.is_active = payload.is_active
    await user.save()
    return {"message": "User updated"}


@app.delete("/api/v1/users/{user_id}")
async def delete_user(user_id: str, admin: Principal = Depends(require_admin)):
    user = await User.get_or_none(id=user_id, tenant=admin.tenant)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if str(user.id) == str(admin.user.id):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    await user.delete()
    return {"message": "User deleted"}


# Tenant management
@app.get("/api/v1/tenant", response_model=Dict[str, Any])
async def get_tenant_info(principal: Principal = Depends(get_current_principal)):
    """Get current tenant information"""
    tenant = principal.tenant
    return {
        "id": tenant.id,
        "name": tenant.name,
        "allowed_users": tenant.allowed_users,
        "s3_config": _redact_s3_config(tenant.s3_config),
        "auth_provider": tenant.auth_provider,
        "dep_enabled": tenant.dep_enabled,
        "created_at": tenant.created_at,
        "is_active": tenant.is_active,
    }


@app.put("/api/v1/tenant")
async def update_tenant(update: TenantUpdate, admin: Principal = Depends(require_admin)):
    """Update tenant settings (admin only)."""
    tenant = admin.tenant

    if update.name is not None:
        tenant.name = update.name
    if update.allowed_users is not None:
        tenant.allowed_users = update.allowed_users
    if update.s3_config is not None:
        tenant.s3_config = update.s3_config
    if update.dep_enabled is not None:
        tenant.dep_enabled = update.dep_enabled
    if update.is_active is not None:
        # Guard against an admin locking the whole tenant out irrecoverably.
        if not update.is_active:
            raise HTTPException(
                status_code=400,
                detail="Deactivating a tenant via this API is not allowed; use admin tooling",
            )
        tenant.is_active = update.is_active

    await tenant.save()

    # Mirror non-secret fields into the YAML config (atomic write).
    yaml_path = Path(f"./yaml-configs/tenants/{tenant.id}/config.yaml")
    if yaml_path.exists():
        with open(yaml_path, "r") as f:
            config = yaml.safe_load(f) or {}

        config.setdefault("tenant", {})
        config["tenant"]["name"] = tenant.name
        config["tenant"]["allowed_users"] = tenant.allowed_users
        if tenant.s3_config:
            config["tenant"]["s3"] = tenant.s3_config
        config["tenant"].setdefault("dep", {})
        config["tenant"]["dep"]["enabled"] = tenant.dep_enabled

        _atomic_write_yaml(yaml_path, config)

    return {"message": "Tenant updated successfully"}


# YAML Configuration Management
@app.get("/api/v1/config/{config_type}")
async def get_yaml_config(config_type: str, principal: Principal = Depends(get_current_principal)):
    """Get YAML configuration by type (groups, apps, profiles, config)"""
    if config_type not in ["groups", "apps", "profiles", "config"]:
        raise HTTPException(status_code=400, detail="Invalid config type")

    tenant = principal.tenant
    yaml_path = Path(f"./yaml-configs/tenants/{tenant.id}/{config_type}.yaml")

    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail="Configuration not found")

    with open(yaml_path, "r") as f:
        config = yaml.safe_load(f) or {}

    # config.yaml embeds tenant.s3 which may carry credentials — never return them.
    if config_type == "config" and isinstance(config.get("tenant"), dict):
        if "s3" in config["tenant"]:
            config["tenant"]["s3"] = _redact_s3_config(config["tenant"]["s3"])

    return config


@app.put("/api/v1/config/{config_type}")
async def update_yaml_config(
        config_type: str,
        config_data: Dict[str, Any],
        principal: Principal = Depends(get_current_principal),
):
    """Update YAML configuration.

    Validates the SUBMITTED data (not the existing on-disk files) by validating
    it in an isolated copy of the tenant config dir, and only commits — atomically
    — when validation passes.
    """
    if config_type not in ["groups", "apps", "profiles"]:
        raise HTTPException(status_code=400, detail="Invalid config type")

    tenant = principal.tenant
    tenant_dir = Path(f"./yaml-configs/tenants/{tenant.id}")
    yaml_path = tenant_dir / f"{config_type}.yaml"
    if not tenant_dir.exists():
        raise HTTPException(status_code=404, detail="Tenant configuration not found")

    # Validate the candidate config against a private copy of the tenant dir so
    # cross-file checks run, without ever touching live files until it's valid.
    # validate_all() requires all four files to exist, so stub any that are
    # absent on disk with a minimal valid document.
    stubs = {
        "config.yaml": {"tenant": {"id": tenant.id, "name": tenant.name, "allowed_users": []}},
        "groups.yaml": {"groups": []},
        "apps.yaml": {"apps": []},
        "profiles.yaml": {"profiles": []},
    }
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        for fn in ["config.yaml", "groups.yaml", "apps.yaml", "profiles.yaml"]:
            src = tenant_dir / fn
            if src.exists():
                shutil.copy(src, tdp / fn)
            else:
                with open(tdp / fn, "w") as f:
                    yaml.safe_dump(stubs[fn], f, default_flow_style=False)
        # Overwrite the file being updated with the submitted candidate data.
        with open(tdp / f"{config_type}.yaml", "w") as f:
            yaml.safe_dump(config_data, f, default_flow_style=False)

        valid, errors, warnings = YAMLValidator(tdp).validate_all()

    if not valid:
        raise HTTPException(
            status_code=400, detail={"errors": errors, "warnings": warnings}
        )

    _atomic_write_yaml(yaml_path, config_data)
    return {"message": f"{config_type} configuration updated", "warnings": warnings}


@app.post("/api/v1/config/validate")
async def validate_yaml_configs(principal: Principal = Depends(get_current_principal)):
    """Validate all YAML configurations"""
    tenant = principal.tenant
    validator = YAMLValidator(Path(f"./yaml-configs/tenants/{tenant.id}"))

    valid, errors, warnings = validator.validate_all()

    return {"valid": valid, "errors": errors, "warnings": warnings}


# Device Management
@app.get("/api/v1/devices")
async def list_devices(
        skip: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=500),
        group: Optional[str] = None,
        model: Optional[str] = None,
        principal: Principal = Depends(get_current_principal),
):
    """List all devices with optional filtering"""
    tenant = principal.tenant

    query = Device.filter(tenant=tenant)

    if group:
        query = query.filter(groups__contains=[group])
    if model:
        query = query.filter(device_model__icontains=model)

    total = await query.count()
    devices = await query.offset(skip).limit(limit).all()

    return {
        "total": total,
        "devices": [
            {
                "id": str(device.id),
                "udid": device.udid,
                "serial_number": device.serial_number,
                "device_model": device.device_model,
                "os_version": device.os_version,
                "hostname": device.hostname,
                "groups": device.groups,
                "enrollment_date": device.enrollment_date,
                "last_seen": device.last_seen,
            }
            for device in devices
        ],
    }


@app.get("/api/v1/devices/{device_id}")
async def get_device_details(device_id: str, principal: Principal = Depends(get_current_principal)):
    """Get detailed device information"""
    tenant = principal.tenant
    device = await Device.get_or_none(id=device_id, tenant=tenant)

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Get installed apps and profiles
    apps = await AppDeployment.filter(device=device).all()
    profiles = await ProfileDeployment.filter(device=device).all()
    tasks = await Task.filter(device=device).order_by("-created_at").limit(10).all()

    return {
        "device": {
            "id": str(device.id),
            "udid": device.udid,
            "serial_number": device.serial_number,
            "device_model": device.device_model,
            "os_version": device.os_version,
            "hostname": device.hostname,
            "groups": device.groups,
            "enrollment_date": device.enrollment_date,
            "last_seen": device.last_seen,
        },
        "installed_apps": [
            {
                "app_id": app.app_id,
                "version": app.app_version,
                "status": app.status,
                "install_date": app.install_date,
            }
            for app in apps
        ],
        "installed_profiles": [
            {
                "profile_id": profile.profile_id,
                "status": profile.status,
                "install_date": profile.install_date,
            }
            for profile in profiles
        ],
        "recent_tasks": [task.to_dict() for task in tasks],
    }


@app.post("/api/v1/devices/{device_id}/command")
async def send_device_command(
        device_id: str,
        command: CommandRequest,
        principal: Principal = Depends(get_current_principal),
):
    """Send a command to a device.

    Destructive commands (restart/shutdown/clear_passcode) require the admin
    role. Every command creates a Task row for auditability (who/when/what).
    """
    tenant = principal.tenant

    # Authorization: destructive commands are admin-only.
    if command.command_type in DESTRUCTIVE_COMMANDS and principal.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=403,
            detail=f"'{command.command_type}' requires the admin role",
        )

    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    mdm_connector = MDMConnector()

    try:
        # Map command types to handlers
        if command.command_type == "install_app":
            app_info = command.parameters.get("app_info")
            if not app_info:
                raise HTTPException(status_code=400, detail="app_info required")

            task = await task_manager.create_task(
                tenant=tenant,
                task_type="app_install",
                description=f"Install {app_info['name']}",
                device=device,
                user=principal.email,
                details={"app_info": app_info},
            )

            from controller.services.task_handlers import handle_app_install_task

            asyncio.create_task(
                task_manager.execute_task(task, handle_app_install_task)
            )

            return {"task_id": str(task.id), "message": "App installation started"}

        elif command.command_type == "remove_app":
            app_id = command.parameters.get("app_id")
            bundle_id = command.parameters.get("bundle_id")

            if not app_id or not bundle_id:
                raise HTTPException(
                    status_code=400, detail="app_id and bundle_id required"
                )

            task = await task_manager.create_task(
                tenant=tenant,
                task_type="app_remove",
                description=f"Remove app {app_id}",
                device=device,
                user=principal.email,
                details={"app_id": app_id, "bundle_id": bundle_id},
            )

            from controller.services.task_handlers import handle_app_remove_task

            asyncio.create_task(task_manager.execute_task(task, handle_app_remove_task))

            return {"task_id": str(task.id), "message": "App removal started"}

        # Direct, immediately-issued commands: record an audit Task, then send.
        direct_dispatch = {
            "refresh_info": mdm_connector.get_device_info,
            "restart": mdm_connector.restart_device,
            "shutdown": mdm_connector.shutdown_device,
            "clear_passcode": mdm_connector.clear_passcode,
        }
        handler = direct_dispatch.get(command.command_type)
        if handler is None:
            raise HTTPException(status_code=400, detail="Invalid command type")

        task = await task_manager.create_task(
            tenant=tenant,
            task_type=command.command_type,
            description=f"{command.command_type} on {device.serial_number}",
            device=device,
            user=principal.email,
            details={},
        )
        try:
            result = await handler(device.udid)
            task.details["command_uuid"] = result.get("command_uuid")
            task.status = "running"
            await task.save()
        except Exception as exc:
            task.status = "failed"
            task.error = str(exc)
            await task.save()
            logger.error(f"Command {command.command_type} failed for {device.udid}: {exc}")
            raise HTTPException(status_code=502, detail="Failed to send command to device")

        return {"task_id": str(task.id), "message": "Command sent", "result": result}

    finally:
        await mdm_connector.close()


# Task Management
@app.get("/api/v1/tasks")
async def list_tasks(
        skip: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=500),
        status: Optional[str] = None,
        device_id: Optional[str] = None,
        principal: Principal = Depends(get_current_principal),
):
    """List tasks with optional filtering"""
    tenant = principal.tenant

    query = Task.filter(tenant=tenant)

    if status:
        query = query.filter(status=status)
    if device_id:
        query = query.filter(device_id=device_id)

    total = await query.count()
    tasks = (
        await query.order_by("-created_at")
        .offset(skip)
        .limit(limit)
        .prefetch_related("device")
        .all()
    )

    return {"total": total, "tasks": [task.to_dict() for task in tasks]}


@app.get("/api/v1/tasks/{task_id}")
async def get_task_details(task_id: str, principal: Principal = Depends(get_current_principal)):
    """Get task details"""
    tenant = principal.tenant
    task = await Task.get_or_none(id=task_id, tenant=tenant).prefetch_related("device")

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return task.to_dict()


@app.post("/api/v1/tasks/{task_id}/cancel")
async def cancel_task(task_id: str, principal: Principal = Depends(get_current_principal)):
    """Cancel a running task"""
    tenant = principal.tenant
    task = await Task.get_or_none(id=task_id, tenant=tenant)

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task.status not in ["pending", "running"]:
        raise HTTPException(status_code=400, detail="Task cannot be cancelled")

    cancelled = await task_manager.cancel_task(str(task.id))

    if cancelled:
        task.status = "cancelled"
        task.completed_at = datetime.now(timezone.utc)
        await task.save()

    return {"message": "Task cancelled" if cancelled else "Task not running"}


# Reports and Statistics
@app.get("/api/v1/stats/overview")
async def get_overview_stats(principal: Principal = Depends(get_current_principal)):
    """Get overview statistics"""
    tenant = principal.tenant

    device_count = await Device.filter(tenant=tenant).count()
    active_devices = await Device.filter(
        tenant=tenant, last_seen__gte=datetime.now(timezone.utc) - timedelta(days=7)
    ).count()

    task_stats = await task_manager.get_task_stats(tenant)

    app_deployments = await AppDeployment.filter(
        tenant=tenant, status="installed"
    ).count()
    profile_deployments = await ProfileDeployment.filter(
        tenant=tenant, status="installed"
    ).count()

    return {
        "devices": {"total": device_count, "active_7d": active_devices},
        "tasks": task_stats,
        "deployments": {"apps": app_deployments, "profiles": profile_deployments},
    }


@app.get("/api/v1/stats/devices/by-model")
async def get_devices_by_model(principal: Principal = Depends(get_current_principal)):
    """Get device distribution by model"""
    tenant = principal.tenant

    from tortoise.functions import Count

    stats = (
        await Device.filter(tenant=tenant)
        .annotate(count=Count("id"))
        .group_by("device_model")
        .values("device_model", "count")
    )

    return stats


@app.get("/api/v1/stats/devices/by-os")
async def get_devices_by_os(principal: Principal = Depends(get_current_principal)):
    """Get device distribution by OS version"""
    tenant = principal.tenant

    from tortoise.functions import Count

    stats = (
        await Device.filter(tenant=tenant)
        .annotate(count=Count("id"))
        .group_by("os_version")
        .values("os_version", "count")
    )

    return stats


# File Management
_SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9._-]+$")


@app.post("/api/v1/apps/upload")
async def upload_app_package(
        file: UploadFile = File(...),
        app_id: str = Query(..., min_length=1),
        version: str = Query(..., min_length=1),
        principal: Principal = Depends(get_current_principal),
):
    """Upload an app package to S3"""
    tenant = principal.tenant

    if not (tenant.s3_config or {}).get("bucket"):
        raise HTTPException(status_code=400, detail="S3 not configured for tenant")

    # Reject anything that could escape the intended key namespace (path/object
    # injection or overwriting another app's package).
    if not _SAFE_KEY_RE.match(app_id) or not _SAFE_KEY_RE.match(version):
        raise HTTPException(
            status_code=400,
            detail="app_id and version may contain only letters, digits, '.', '_' and '-'",
        )

    file_extension = os.path.splitext(file.filename or "")[1]
    if file_extension and not _SAFE_KEY_RE.match(file_extension.lstrip(".")):
        raise HTTPException(status_code=400, detail="Unsupported file name")

    s3_key = f"{app_id}/{app_id}-{version}{file_extension}"

    app_manager = AppManager(tenant)
    s3_config = tenant.s3_config

    try:
        app_manager.s3_client.upload_fileobj(
            file.file, s3_config["bucket"], f"{s3_config.get('prefix', '')}{s3_key}"
        )

        return {"s3_key": s3_key, "message": "File uploaded successfully"}
    except Exception as e:
        logger.error(f"App upload failed for tenant {tenant.id}: {e}")
        raise HTTPException(status_code=500, detail="Upload failed")


# App Manifest Endpoints
@app.get("/api/manifests/{deployment_id}")
async def get_app_manifest(deployment_id: str):
    """Get app installation manifest for MDM"""
    # Note: This endpoint doesn't require authentication because devices need to access it
    # The deployment_id acts as a secure token

    # Get the deployment
    deployment = await AppDeployment.get_or_none(id=deployment_id).prefetch_related(
        "tenant", "device"
    )

    if not deployment:
        raise HTTPException(status_code=404, detail="Deployment not found")

    # Get app configuration
    tenant = deployment.tenant
    yaml_path = Path(f"./yaml-configs/tenants/{tenant.id}/apps.yaml")

    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail="App configuration not found")

    with open(yaml_path, "r") as f:
        apps_config = yaml.safe_load(f)

    # Find the app and version
    app_info = None
    for app in apps_config.get("apps", []):
        if app["id"] == deployment.app_id:
            for version in app.get("versions", []):
                if version["version"] == deployment.app_version:
                    app_info = {
                        "id": app["id"],
                        "name": app["name"],
                        "bundle_id": app["bundle_id"],
                        "version": version["version"],
                        "s3_key": version["s3_key"],
                        "sha256": version.get("sha256", ""),
                    }
                    break
            break

    if not app_info:
        raise HTTPException(status_code=404, detail="App version not found")

    # Integrity is mandatory: refuse to hand a device a download URL we cannot
    # bind to a known-good content hash.
    if not re.match(r"^[a-fA-F0-9]{64}$", app_info.get("sha256") or ""):
        logger.error(
            f"Refusing manifest for {deployment.app_id} {deployment.app_version}: missing sha256"
        )
        raise HTTPException(status_code=500, detail="App version is missing an integrity hash")

    # Generate presigned URL for the app package
    app_manager = AppManager(tenant)
    s3_config = tenant.s3_config

    try:
        download_url = app_manager.s3_client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": s3_config["bucket"],
                "Key": f"{s3_config.get('prefix', '')}{app_info['s3_key']}",
            },
            ExpiresIn=3600,  # 1 hour
        )
    except Exception as e:
        logger.error(f"Failed to generate presigned URL: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate download URL")

    # Build the manifest plist
    manifest = {
        "items": [
            {
                "assets": [{"kind": "software-package", "url": download_url}],
                "metadata": {
                    "bundle-identifier": app_info["bundle_id"],
                    "bundle-version": app_info["version"],
                    "kind": "software",
                    "title": app_info["name"],
                },
            }
        ]
    }

    # SHA256 is guaranteed present (enforced above).
    manifest["items"][0]["assets"][0]["sha256"] = app_info["sha256"]

    # Convert to plist format
    import plistlib

    plist_data = plistlib.dumps(manifest)

    # Return as plist with appropriate content type
    return Response(
        content=plist_data,
        media_type="application/x-plist",
        headers={
            "Content-Disposition": (
                f"attachment; filename={app_info['id']}-{app_info['version']}.plist"
            )
        },
    )


@app.get("/api/manifests/{deployment_id}/info")
async def get_app_manifest_info(
        deployment_id: str, principal: Principal = Depends(get_current_principal)
):
    """Get information about an app manifest (authenticated endpoint)"""
    # This endpoint requires authentication and provides info about the manifest

    deployment = await AppDeployment.get_or_none(
        id=deployment_id, tenant=principal.tenant
    ).prefetch_related("device")

    if not deployment:
        raise HTTPException(status_code=404, detail="Deployment not found")

    return {
        "deployment_id": str(deployment.id),
        "app_id": deployment.app_id,
        "app_version": deployment.app_version,
        "device_id": str(deployment.device.id),
        "device_serial": deployment.device.serial_number,
        "status": deployment.status,
        "created_at": deployment.created_at,
        "manifest_url": f"{os.getenv('PUBLIC_API_URL')}/api/manifests/{deployment_id}",
    }


# Enrollment
@app.get("/api/v1/enrollment")
async def get_enrollment(principal: Principal = Depends(get_current_principal)):
    """Enrollment details for the current tenant (server URLs, topic, enroll URL)."""
    return enrollment_svc.enrollment_details(principal.tenant)


@app.get("/api/v1/enroll/{tenant_id}/{token}")
async def download_enrollment_profile(tenant_id: str, token: str):
    """Serve the over-the-air enrollment .mobileconfig for a device to install.

    Unauthenticated (devices have no JWT) but gated by a per-tenant token.
    """
    tenant = await Tenant.get_or_none(id=tenant_id)
    if not tenant or not tenant.is_active:
        raise HTTPException(status_code=404, detail="Not found")
    if not enrollment_svc.verify_enrollment_token(tenant_id, token):
        raise HTTPException(status_code=403, detail="Forbidden")

    data = enrollment_svc.build_enrollment_mobileconfig(tenant)
    return Response(
        content=data,
        media_type="application/x-apple-aspen-config",
        headers={
            "Content-Disposition": f'attachment; filename="enroll-{tenant_id}.mobileconfig"'
        },
    )


# Health check
@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc)}


# Register Tortoise ORM
register_tortoise(
    app,
    db_url=DATABASE_URL,
    modules={"models": ["controller.models.tenant"]},
    generate_schemas=True,
    add_exception_handlers=True,
)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
