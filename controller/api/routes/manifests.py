"""App manifest and download package endpoints for managed devices."""
import asyncio
import logging
import plistlib
import re

from fastapi import APIRouter, Depends, HTTPException, Request, Response
import yaml

from controller.api.ids import require_uuid as _require_uuid
from controller.auth.dependencies import Principal, get_current_principal
from controller.models.tenant import AppDeployment, Tenant
from controller.services import readiness
from controller.services.app_manager import AppManager, S3ConfigError
from controller.services.tenant_config import tenant_dir as _tenant_dir

logger = logging.getLogger(__name__)

router = APIRouter()


async def _resolve_package(deployment_id: str):
    """The deployment, its tenant and the authored app version behind a device-facing package URL.

    Shared by the manifest and package endpoints so a missing sha256 is refused once, not independently in each.
    """
    _require_uuid(deployment_id, "Deployment not found")
    deployment = await AppDeployment.get_or_none(id=deployment_id).prefetch_related(
        "tenant", "device"
    )

    if not deployment:
        raise HTTPException(status_code=404, detail="Deployment not found")

    tenant = deployment.tenant
    yaml_path = _tenant_dir(tenant.id) / "apps.yaml"

    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail="App configuration not found")

    with open(yaml_path, "r", encoding="utf-8") as f:
        apps_config = yaml.safe_load(f)

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

    # Integrity is mandatory: no device gets a download URL that cannot be bound to a known content hash.
    if not re.match(r"^[a-fA-F0-9]{64}$", app_info.get("sha256") or ""):
        logger.error(
            f"Refusing manifest for {deployment.app_id} {deployment.app_version}: missing sha256"
        )
        raise HTTPException(status_code=500, detail="App version is missing an integrity hash")

    return deployment, tenant, app_info


def _package_location(tenant: Tenant, s3_key: str):
    """(AppManager, bucket, full key) for an app package, or a 500.

    The S3 config error, which names the tenant and missing keys, is logged rather than returned to the caller.
    """
    app_manager = AppManager(tenant)
    try:
        return app_manager, app_manager._get_s3_bucket(), app_manager._build_s3_key(s3_key)
    except S3ConfigError as e:
        logger.error(f"Failed to locate package for tenant {tenant.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate download URL")
    except Exception as e:
        logger.error(f"Failed to locate package: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate download URL")


@router.api_route("/api/manifests/{deployment_id}/package", methods=["GET", "HEAD"])
async def get_app_package(deployment_id: str, request: Request):
    """Return the download address a manifest points a device at (unauthenticated, like the manifest)."""
    _deployment, tenant, app_info = await _resolve_package(deployment_id)
    app_manager, bucket, full_s3_key = _package_location(tenant, app_info["s3_key"])

    if request.method == "HEAD":
        try:
            head = await asyncio.to_thread(
                app_manager.s3_client.head_object, Bucket=bucket, Key=full_s3_key
            )
        except Exception as exc:
            code = str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))
            if code in ("404", "NoSuchKey", "NotFound"):
                logger.error(f"Package missing for deployment {deployment_id}: {full_s3_key}")
                raise HTTPException(status_code=404, detail="Package not found")
            logger.error(f"Could not read package metadata for {deployment_id}: {exc}")
            raise HTTPException(status_code=502, detail="Package metadata unavailable")
        # The number the device asked for, and the type it will store.
        return Response(
            status_code=200,
            headers={
                "Content-Length": str(head.get("ContentLength", 0)),
                "Content-Type": head.get("ContentType") or "application/octet-stream",
            },
        )

    try:
        download_url = app_manager.s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": full_s3_key},
            ExpiresIn=3600,  # 1 hour
        )
    except Exception as e:
        logger.error(f"Failed to generate presigned URL: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate download URL")
    # 302 and not 301: the presigned URL expires, so nothing about this redirect is permanent and nothing should cache
    # it as though it were.
    return Response(status_code=302, headers={"Location": download_url})


@router.get("/api/manifests/{deployment_id}")
async def get_app_manifest(deployment_id: str):
    """The InstallApplication manifest plist for one deployment, as a device fetches it. Unauthenticated, like the
    package endpoint above."""
    deployment, tenant, app_info = await _resolve_package(deployment_id)

    app_manager = AppManager(tenant)

    try:
        bucket = app_manager._get_s3_bucket()
        full_s3_key = app_manager._build_s3_key(app_info['s3_key'])
        download_url = app_manager.s3_client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": bucket,
                "Key": full_s3_key,
            },
            ExpiresIn=3600,  # 1 hour
        )
    except S3ConfigError as e:
        logger.error(f"Failed to generate presigned URL for tenant {tenant.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate download URL")
    except Exception as e:
        logger.error(f"Failed to generate presigned URL: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate download URL")

    # Points at this server's package endpoint, which answers HEAD and GET separately, instead of the presigned URL
    # directly. Falls back to the presigned URL when no public address is configured.
    public = readiness.public_api_url()
    asset_url = (f"{public}/api/manifests/{deployment_id}/package"
                 if public else download_url)

    manifest = {
        "items": [
            {
                "assets": [{"kind": "software-package", "url": asset_url}],
                "metadata": {
                    "bundle-identifier": app_info["bundle_id"],
                    "bundle-version": app_info["version"],
                    "kind": "software",
                    "title": app_info["name"],
                },
            }
        ]
    }

    # _resolve_package refuses a version without one, so this is always present.
    manifest["items"][0]["assets"][0]["sha256"] = app_info["sha256"]

    plist_data = plistlib.dumps(manifest)

    return Response(
        content=plist_data,
        media_type="application/x-plist",
        headers={
            "Content-Disposition": (
                f"attachment; filename={app_info['id']}-{app_info['version']}.plist"
            )
        },
    )


@router.get("/api/manifests/{deployment_id}/info")
async def get_app_manifest_info(
    deployment_id: str, principal: Principal = Depends(get_current_principal)
):
    """One deployment described: which app and version, which device, where it got to, and the manifest URL the device
    is given. Requires a session and is tenant-scoped, unlike the device-facing manifest above.
    """
    _require_uuid(deployment_id, "Deployment not found")
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
        "last_error": deployment.last_error,
        "last_task_id": str(deployment.last_task_id) if deployment.last_task_id else None,
        "created_at": deployment.created_at,
        # None when no public address is configured. A plain f-string would produce a URL beginning "None/" that a
        # client cannot tell apart from a real one.
        "manifest_url": (f"{readiness.public_api_url()}/api/manifests/{deployment_id}"
                         if readiness.public_api_url() else None),
    }
