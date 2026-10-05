"""App package file upload and storage management endpoints."""
import asyncio
import hashlib
import logging
import os
import re
from typing import List

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel

from controller.auth.dependencies import Principal, require_admin
from controller.services.app_manager import AppManager, S3ConfigError
from controller.services.audit import record_audit
from controller.utils.per_loop import KeyedLocks
from controller.utils.pkg_inspect import inspect_pkg

logger = logging.getLogger(__name__)

router = APIRouter()

_SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# Single upload per tenant: the quota read and write are not atomic.
_upload_locks = KeyedLocks()


def _upload_lock(tenant_id: str) -> asyncio.Lock:
    return _upload_locks.get(tenant_id)


@router.post("/api/v1/apps/upload")
async def upload_app_package(
    file: UploadFile = File(...),
    app_id: str = Query(..., min_length=1),
    version: str = Query(..., min_length=1),
    admin: Principal = Depends(require_admin),
):
    """Upload an app package to S3 (admin only); scoped devices install these bytes as root once apps.yaml points
    at the resulting key."""
    tenant = admin.tenant

    # Refuse anything that could escape the intended key namespace, by path or object injection or by overwriting
    # another app's package.
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

    # Last chance to warn: a component or unsigned package uploads and deploys fine, then fails on the device.
    warnings: List[str] = []
    if file_extension.lower() == ".pkg":
        try:
            warnings = inspect_pkg(file.file).get("warnings", [])
        except Exception:
            logger.exception("app upload: package inspection failed for %s", s3_key)
        finally:
            file.file.seek(0)

    # Bucket and key from the same resolver the reconciler uses to deploy this package: reading
    # tenant.s3_config["bucket"] directly would KeyError in ambient mode.
    try:
        bucket = app_manager._get_s3_bucket()
        full_s3_key = app_manager._build_s3_key(s3_key)
        # One upload at a time per tenant: usage is measured before the bytes go up, so two uploads that interleave
        # between the check and the put both see room only one of them has, and a 10 GB quota takes 20 GB.
        async with _upload_lock(tenant.id):
            # Checked against what is in the store now plus this file, less the object this upload replaces, so
            # re-uploading a version does not count twice. Objects other tools put in the bucket do count.
            quota = app_manager.storage_quota_bytes()
            replaced = 0
            if quota is not None:
                file.file.seek(0, os.SEEK_END)
                incoming = file.file.tell()
                file.file.seek(0)
                usage = await asyncio.to_thread(app_manager.storage_usage_bytes)
                replaced = await asyncio.to_thread(
                    _object_size_or_zero, app_manager, bucket, full_s3_key)
                if usage - replaced + incoming > quota:
                    raise HTTPException(
                        status_code=413,
                        detail=(f"This upload would put the tenant over its storage quota "
                                f"({_human_bytes(usage - replaced + incoming)} of {_human_bytes(quota)}). Delete "
                                f"unused packages first, or ask the operator to raise the quota."),
                    )
            # boto3 is synchronous, so this goes off the loop; otherwise a large .pkg stalls the whole API process.
            sha256 = await asyncio.to_thread(_sha256_fileobj, file.file)
            file.file.seek(0)
            await asyncio.to_thread(
                app_manager.s3_client.upload_fileobj, file.file, bucket, full_s3_key,
                {"Metadata": {AppManager.SHA256_METADATA_KEY: sha256}},
            )
            # Re-measure now the bytes are down, and take back only what this call created: an overwritten object
            # is a package devices install today.
            if quota is not None:
                settled = await asyncio.to_thread(app_manager.storage_usage_bytes)
                if settled > quota:
                    if not replaced:
                        try:
                            await asyncio.to_thread(
                                app_manager.s3_client.delete_object,
                                Bucket=bucket, Key=full_s3_key)
                        except Exception:
                            logger.exception(
                                "app upload: could not remove over-quota object %s", s3_key)
                    raise HTTPException(
                        status_code=413,
                        detail=(f"The store went over the tenant's quota while this upload was running "
                                f"({_human_bytes(settled)} of {_human_bytes(quota)}). Delete unused packages first, or "
                                f"ask the operator to raise the quota."),
                    )
    except S3ConfigError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"App upload failed for tenant {tenant.id}: {e}")
        raise HTTPException(status_code=500, detail="Upload failed")

    await record_audit(
        admin,
        "app.upload",
        target_type="app",
        target_id=app_id,
        # Location and identity of the package only; no credentials.
        detail={"app_id": app_id, "version": version, "s3_key": s3_key},
    )
    return {"s3_key": s3_key, "sha256": sha256, "message": "File uploaded successfully",
            "warnings": warnings}


def _sha256_fileobj(fileobj) -> str:
    """sha256 of a file object from its current position, in 1 MB reads."""
    digest = hashlib.sha256()
    for chunk in iter(lambda: fileobj.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _object_size_or_zero(app_manager: AppManager, bucket: str, full_key: str) -> int:
    """Size of an object that may not exist. Synchronous boto3; use to_thread."""
    try:
        head = app_manager.s3_client.head_object(Bucket=bucket, Key=full_key)
        return int(head.get("ContentLength") or 0)
    except Exception:
        return 0


def _human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{n} B"


@router.get("/api/v1/apps/packages")
async def list_app_packages(admin: Principal = Depends(require_admin)):
    """List the packages already in this tenant's object store (admin only), including ones uploaded some other
    way; a null sha256 means POST /api/v1/apps/packages/checksum can compute it."""
    app_manager = AppManager(admin.tenant)
    try:
        packages = await asyncio.to_thread(app_manager.list_packages)
    except S3ConfigError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Listing packages failed for tenant {admin.tenant.id}: {e}")
        raise HTTPException(status_code=502, detail="Could not list the object store")
    usage = sum(int(p.get("size") or 0) for p in packages)
    return {"packages": packages, "usage_bytes": usage,
            "quota_bytes": app_manager.storage_quota_bytes()}


class PackageChecksumRequest(BaseModel):
    s3_key: str


@router.post("/api/v1/apps/packages/checksum")
async def checksum_app_package(
    body: PackageChecksumRequest,
    admin: Principal = Depends(require_admin),
):
    """sha256 of one object already in the store (admin only).

    Streams the object through the controller once and records the digest on it, so the next listing already has it.
    """
    key = (body.s3_key or "").strip()
    if not key or key.startswith("/") or ".." in key.split("/"):
        raise HTTPException(status_code=400, detail="s3_key must be a key inside the bucket")
    app_manager = AppManager(admin.tenant)
    try:
        sha256 = await asyncio.to_thread(app_manager.checksum_package, key)
    except S3ConfigError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        code = getattr(getattr(e, "response", None), "get", lambda *_: None)("Error") or {}
        if isinstance(code, dict) and code.get("Code") in ("NoSuchKey", "404"):
            raise HTTPException(status_code=404, detail="No such package in the store")
        logger.error(f"Checksum failed for tenant {admin.tenant.id} key {key}: {e}")
        raise HTTPException(status_code=502, detail="Could not read the package")
    return {"s3_key": key, "sha256": sha256}
