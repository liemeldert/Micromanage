import asyncio
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional

import jwt
import yaml
from controller.utils.yaml_validator import YAMLValidator
from fastapi import FastAPI, HTTPException, Depends, Security, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from tortoise.contrib.fastapi import register_tortoise

from controller.models.database import DATABASE_URL
from controller.models.tenant import (
    Tenant,
    Device,
    Task,
    AppDeployment,
    ProfileDeployment,
)
from controller.services.app_manager import AppManager
from controller.services.mdm_connector import MDMConnector
from controller.services.task_manager import TaskManager

app = FastAPI(title="MDM IAC API", version="1.0.0")
security = HTTPBearer()
logger = logging.getLogger(__name__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

# JWT settings
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24


# Base models
class LoginRequest(BaseModel):
    tenant_id: str
    user_email: str


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


# Authentication
async def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        tenant_id = payload.get("tenant_id")
        user_email = payload.get("user_email")

        if not tenant_id or not user_email:
            raise HTTPException(status_code=401, detail="Invalid token")

        tenant = await Tenant.get_or_none(id=tenant_id)
        if not tenant or not tenant.is_active:
            raise HTTPException(status_code=401, detail="Invalid tenant")

        if user_email not in tenant.allowed_users:
            raise HTTPException(status_code=403, detail="User not authorized")

        return {"tenant": tenant, "user_email": user_email}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Auth endpoints
@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """Authenticate user and get access token"""
    tenant = await Tenant.get_or_none(id=request.tenant_id)

    if not tenant or not tenant.is_active:
        raise HTTPException(status_code=401, detail="Invalid tenant")

    if request.user_email not in tenant.allowed_users:
        raise HTTPException(status_code=401, detail="User not authorized")

    # Create JWT token
    expiration = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {
        "tenant_id": request.tenant_id,
        "user_email": request.user_email,
        "exp": expiration,
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return TokenResponse(access_token=token, expires_in=JWT_EXPIRATION_HOURS * 3600)


# Tenant management
@app.get("/api/v1/tenant", response_model=Dict[str, Any])
async def get_tenant_info(auth=Depends(verify_token)):
    """Get current tenant information"""
    tenant = auth["tenant"]
    return {
        "id": tenant.id,
        "name": tenant.name,
        "allowed_users": tenant.allowed_users,
        "s3_config": tenant.s3_config,
        "dep_enabled": tenant.dep_enabled,
        "created_at": tenant.created_at,
        "is_active": tenant.is_active,
    }


@app.put("/api/v1/tenant")
async def update_tenant(update: TenantUpdate, auth=Depends(verify_token)):
    """Update tenant information"""
    tenant = auth["tenant"]

    if update.name is not None:
        tenant.name = update.name
    if update.allowed_users is not None:
        tenant.allowed_users = update.allowed_users
    if update.s3_config is not None:
        tenant.s3_config = update.s3_config
    if update.dep_enabled is not None:
        tenant.dep_enabled = update.dep_enabled
    if update.is_active is not None:
        tenant.is_active = update.is_active

    await tenant.save()

    # Update YAML config
    yaml_path = Path(f"./yaml-configs/tenants/{tenant.id}/config.yaml")
    if yaml_path.exists():
        with open(yaml_path, "r") as f:
            config = yaml.safe_load(f)

        config["tenant"]["name"] = tenant.name
        config["tenant"]["allowed_users"] = tenant.allowed_users
        if tenant.s3_config:
            config["tenant"]["s3"] = tenant.s3_config
        config["tenant"]["dep"]["enabled"] = tenant.dep_enabled

        with open(yaml_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False)

    return {"message": "Tenant updated successfully"}


# YAML Configuration Management
@app.get("/api/v1/config/{config_type}")
async def get_yaml_config(config_type: str, auth=Depends(verify_token)):
    """Get YAML configuration by type (groups, apps, profiles, config)"""
    if config_type not in ["groups", "apps", "profiles", "config"]:
        raise HTTPException(status_code=400, detail="Invalid config type")

    tenant = auth["tenant"]
    yaml_path = Path(f"./yaml-configs/tenants/{tenant.id}/{config_type}.yaml")

    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail="Configuration not found")

    with open(yaml_path, "r") as f:
        config = yaml.safe_load(f)

    return config


@app.put("/api/v1/config/{config_type}")
async def update_yaml_config(
        config_type: str, config_data: Dict[str, Any], auth=Depends(verify_token)
):
    """Update YAML configuration"""
    if config_type not in ["groups", "apps", "profiles"]:
        raise HTTPException(status_code=400, detail="Invalid config type")

    tenant = auth["tenant"]
    yaml_path = Path(f"./yaml-configs/tenants/{tenant.id}/{config_type}.yaml")

    # Validate configuration
    validator = YAMLValidator(Path(f"./yaml-configs/tenants/{tenant.id}"))

    # Write temporary file for validation
    temp_path = yaml_path.with_suffix(".tmp")
    with open(temp_path, "w") as f:
        yaml.dump(config_data, f, default_flow_style=False)

    # Validate
    valid, errors, warnings = validator.validate_all()

    # Remove temp file
    temp_path.unlink()

    if not valid:
        raise HTTPException(
            status_code=400, detail={"errors": errors, "warnings": warnings}
        )

    # Save configuration
    with open(yaml_path, "w") as f:
        yaml.dump(config_data, f, default_flow_style=False)

    return {"message": f"{config_type} configuration updated", "warnings": warnings}


@app.post("/api/v1/config/validate")
async def validate_yaml_configs(auth=Depends(verify_token)):
    """Validate all YAML configurations"""
    tenant = auth["tenant"]
    validator = YAMLValidator(Path(f"./yaml-configs/tenants/{tenant.id}"))

    valid, errors, warnings = validator.validate_all()

    return {"valid": valid, "errors": errors, "warnings": warnings}


# Device Management
@app.get("/api/v1/devices")
async def list_devices(
        skip: int = 0,
        limit: int = 100,
        group: Optional[str] = None,
        model: Optional[str] = None,
        auth=Depends(verify_token),
):
    """List all devices with optional filtering"""
    tenant = auth["tenant"]

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
async def get_device_details(device_id: str, auth=Depends(verify_token)):
    """Get detailed device information"""
    tenant = auth["tenant"]
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
        device_id: str, command: CommandRequest, auth=Depends(verify_token)
):
    """Send a command to a device"""
    tenant = auth["tenant"]
    device = await Device.get_or_none(id=device_id, tenant=tenant)

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Create task
    task_manager = TaskManager()
    mdm_connector = MDMConnector()

    try:
        # Map command types to handlers
        if command.command_type == "refresh_info":
            result = await mdm_connector.get_device_info(device.udid)
        elif command.command_type == "install_app":
            app_info = command.parameters.get("app_info")
            if not app_info:
                raise HTTPException(status_code=400, detail="app_info required")

            task = await task_manager.create_task(
                tenant=tenant,
                task_type="app_install",
                description=f"Install {app_info['name']}",
                device=device,
                user=auth["user_email"],
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
                user=auth["user_email"],
                details={"app_id": app_id, "bundle_id": bundle_id},
            )

            from controller.services.task_handlers import handle_app_remove_task

            asyncio.create_task(task_manager.execute_task(task, handle_app_remove_task))

            return {"task_id": str(task.id), "message": "App removal started"}

        elif command.command_type == "restart":
            result = await mdm_connector.restart_device(device.udid)
        elif command.command_type == "shutdown":
            result = await mdm_connector.shutdown_device(device.udid)
        elif command.command_type == "clear_passcode":
            result = await mdm_connector.clear_passcode(device.udid)
        else:
            raise HTTPException(status_code=400, detail="Invalid command type")

        return {"message": "Command sent", "result": result}

    finally:
        await mdm_connector.close()


# Task Management
@app.get("/api/v1/tasks")
async def list_tasks(
        skip: int = 0,
        limit: int = 100,
        status: Optional[str] = None,
        device_id: Optional[str] = None,
        auth=Depends(verify_token),
):
    """List tasks with optional filtering"""
    tenant = auth["tenant"]

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
async def get_task_details(task_id: str, auth=Depends(verify_token)):
    """Get task details"""
    tenant = auth["tenant"]
    task = await Task.get_or_none(id=task_id, tenant=tenant).prefetch_related("device")

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return task.to_dict()


@app.post("/api/v1/tasks/{task_id}/cancel")
async def cancel_task(task_id: str, auth=Depends(verify_token)):
    """Cancel a running task"""
    tenant = auth["tenant"]
    task = await Task.get_or_none(id=task_id, tenant=tenant)

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task.status not in ["pending", "running"]:
        raise HTTPException(status_code=400, detail="Task cannot be cancelled")

    task_manager = TaskManager()
    cancelled = await task_manager.cancel_task(str(task.id))

    if cancelled:
        task.status = "cancelled"
        task.completed_at = datetime.now(timezone.utc)
        await task.save()

    return {"message": "Task cancelled" if cancelled else "Task not running"}


# Reports and Statistics
@app.get("/api/v1/stats/overview")
async def get_overview_stats(auth=Depends(verify_token)):
    """Get overview statistics"""
    tenant = auth["tenant"]

    device_count = await Device.filter(tenant=tenant).count()
    active_devices = await Device.filter(
        tenant=tenant, last_seen__gte=datetime.now(timezone.utc) - timedelta(days=7)
    ).count()

    task_stats = await TaskManager().get_task_stats(tenant)

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
async def get_devices_by_model(auth=Depends(verify_token)):
    """Get device distribution by model"""
    tenant = auth["tenant"]

    from tortoise.functions import Count

    stats = (
        await Device.filter(tenant=tenant)
        .annotate(count=Count("id"))
        .group_by("device_model")
        .values("device_model", "count")
    )

    return stats


@app.get("/api/v1/stats/devices/by-os")
async def get_devices_by_os(auth=Depends(verify_token)):
    """Get device distribution by OS version"""
    tenant = auth["tenant"]

    from tortoise.functions import Count

    stats = (
        await Device.filter(tenant=tenant)
        .annotate(count=Count("id"))
        .group_by("os_version")
        .values("os_version", "count")
    )

    return stats


# File Management
@app.post("/api/v1/apps/upload")
async def upload_app_package(
        file: UploadFile = File(...),
        app_id: str = None,
        version: str = None,
        auth=Depends(verify_token),
):
    """Upload an app package to S3"""
    tenant = auth["tenant"]

    if not tenant.s3_config.get("bucket"):
        raise HTTPException(status_code=400, detail="S3 not configured for tenant")

    # Generate S3 key
    file_extension = os.path.splitext(file.filename)[1]
    s3_key = f"{app_id}/{app_id}-{version}{file_extension}"

    # Upload to S3
    app_manager = AppManager(tenant)
    s3_config = tenant.s3_config

    try:
        app_manager.s3_client.upload_fileobj(
            file.file, s3_config["bucket"], f"{s3_config.get('prefix', '')}{s3_key}"
        )

        return {"s3_key": s3_key, "message": "File uploaded successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


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

    # Add SHA256 if available
    if app_info.get("sha256"):
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
async def get_app_manifest_info(deployment_id: str, auth=Depends(verify_token)):
    """Get information about an app manifest (authenticated endpoint)"""
    # This endpoint requires authentication and provides info about the manifest

    deployment = await AppDeployment.get_or_none(
        id=deployment_id, tenant=auth["tenant"]
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
