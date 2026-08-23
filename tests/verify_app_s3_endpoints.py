"""E2E checks that the app-upload and app-manifest endpoints go through the S3 resolver instead of reading
tenant.s3_config by hand (sqlite in-memory).

Run: PYTHONPATH=. .venv/bin/python tests/verify_app_s3_endpoints.py

Building the bucket and key by hand, as s3_config["bucket"] and s3_config.get('prefix','') + key, raises KeyError for an
ambient-mode tenant, whose s3_config has no bucket at all, and joins a prefix without the separator
app_manager._build_s3_key inserts.

verify_s3_scoping.py covers resolve_s3_settings itself. What this file proves is that upload_app_package and
get_app_manifest go through AppManager._get_s3_bucket and _build_s3_key, behave for both an ambient-mode and a
tenant-mode tenant, and that a misconfigured tenant gets the S3ConfigError message rather than a bare failure.
"""
import io
import os
import plistlib
import tempfile
from pathlib import Path

import yaml
from fastapi import HTTPException, UploadFile
from tortoise import Tortoise

PASS, FAIL = [], []

AMBIENT = {
    "AWS_ACCESS_KEY_ID": "AKIA-OPERATOR",
    "AWS_SECRET_ACCESS_KEY": "OPERATOR-SECRET",
    "AWS_S3_BUCKET": "operator-packages",
    "AWS_DEFAULT_REGION": "us-east-1",
}


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


class FakeS3Client:
    """Stands in for boto3's client. Records the bucket and key of every upload so a test can check them with no
    outbound network call, and keeps an in-memory bucket so listing, HEAD, GET and copy behave for the storage picker
    and quota checks."""

    # Shared across instances: the store outlives any one client, the way a bucket outlives a boto3 session.
    objects = {}  # (bucket, key) -> {"body": bytes, "metadata": {...}}

    def __init__(self, kwargs):
        self.kwargs = kwargs
        self.uploads = []

    def upload_fileobj(self, fileobj, bucket, key, ExtraArgs=None):
        self.uploads.append((bucket, key))
        body = fileobj.read()
        self.objects[(bucket, key)] = {
            "body": body, "metadata": dict((ExtraArgs or {}).get("Metadata") or {})}

    def generate_presigned_url(self, operation, Params, ExpiresIn):
        return f"https://signed.example/{Params['Bucket']}/{Params['Key']}?exp={ExpiresIn}"

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        store = self.objects

        class _Paginator:
            def paginate(self, Bucket, Prefix=""):
                from datetime import datetime, timezone
                contents = [
                    {"Key": k, "Size": len(v["body"]),
                     "LastModified": datetime(2026, 1, 1, tzinfo=timezone.utc)}
                    for (b, k), v in store.items() if b == Bucket and k.startswith(Prefix)
                ]
                yield {"Contents": contents}

        return _Paginator()

    def head_object(self, Bucket, Key):
        obj = self.objects.get((Bucket, Key))
        if obj is None:
            raise KeyError(Key)
        return {"ContentLength": len(obj["body"]), "Metadata": dict(obj["metadata"])}

    def get_object(self, Bucket, Key):
        obj = self.objects.get((Bucket, Key))
        if obj is None:
            raise KeyError(Key)
        return {"Body": io.BytesIO(obj["body"]), "Metadata": dict(obj["metadata"]),
                "ContentType": "application/octet-stream"}

    def copy_object(self, Bucket, Key, CopySource, Metadata, MetadataDirective, ContentType):
        src = self.objects[(CopySource["Bucket"], CopySource["Key"])]
        self.objects[(Bucket, Key)] = {"body": src["body"], "metadata": dict(Metadata)}


def make_upload_file(content: bytes = b"pkg-bytes", filename: str = "app.pkg") -> UploadFile:
    return UploadFile(file=io.BytesIO(content), filename=filename)


async def main():
    for k, v in AMBIENT.items():
        os.environ[k] = v
    base = Path(tempfile.mkdtemp())
    os.environ["YAML_CONFIG_PATH"] = str(base)

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    import controller.services.app_manager as am
    from controller.auth.dependencies import Principal
    from controller.models.tenant import AppDeployment, Device, Tenant, User
    from controller.api.main import get_app_manifest, upload_app_package

    created_clients = []

    def fake_boto3_client(**kwargs):
        c = FakeS3Client(kwargs)
        created_clients.append(c)
        return c

    am.boto3.client = fake_boto3_client

    async def make_admin(tenant_id, s3_config=None):
        tenant = await Tenant.create(id=tenant_id, name=tenant_id, s3_config=s3_config or {})
        user = await User.create(tenant=tenant, email=f"a@{tenant_id}", role="admin")
        return Principal(tenant=tenant, user=user, email=f"a@{tenant_id}", role="admin"), tenant

    print("upload_app_package, ambient-mode tenant:")
    admin, tenant = await make_admin("amb-up")
    result = await upload_app_package(
        file=make_upload_file(), app_id="slack", version="1.0", admin=admin,
    )
    check("upload succeeds instead of KeyError('bucket')", result["s3_key"] == "slack/slack-1.0.pkg")
    check("bucket comes from the ambient environment",
          created_clients[-1].uploads[-1] == ("operator-packages", "slack/slack-1.0.pkg"))

    print("upload_app_package, tenant-mode tenant with an unslashed prefix:")
    admin, tenant = await make_admin("own-up", {
        "bucket": "acme-packages", "access_key_id": "AK", "secret_access_key": "SK",
        "prefix": "apps",  # no trailing slash: _build_s3_key must insert one
    })
    result = await upload_app_package(
        file=make_upload_file(), app_id="chrome", version="2.0", admin=admin,
    )
    check("upload succeeds for a tenant-owned bucket", result["s3_key"] == "chrome/chrome-2.0.pkg")
    check("bucket is the tenant's own",
          created_clients[-1].uploads[-1][0] == "acme-packages")
    check("prefix gets the separator _build_s3_key inserts",
          created_clients[-1].uploads[-1][1] == "apps/chrome/chrome-2.0.pkg")

    print("upload_app_package, incomplete tenant-mode config surfaces S3ConfigError:")
    admin, tenant = await make_admin("half-up", {"bucket": "acme-packages"})
    try:
        await upload_app_package(
            file=make_upload_file(), app_id="figma", version="1.0", admin=admin,
        )
        check("incomplete config rejected", False)
    except HTTPException as e:
        check("incomplete config -> 400", e.status_code == 400)
        check("message names the missing keys, not a bare 'Upload failed'",
              "access_key_id" in e.detail and "secret_access_key" in e.detail
              and e.detail != "Upload failed")

    def write_apps_yaml(tenant_id, app_id, version, s3_key, sha256="a" * 64):
        tdir = base / "tenants" / tenant_id
        tdir.mkdir(parents=True, exist_ok=True)
        (tdir / "apps.yaml").write_text(yaml.safe_dump({"apps": [
            {"id": app_id, "name": app_id.title(), "bundle_id": f"com.example.{app_id}",
             "versions": [{"version": version, "s3_key": s3_key, "sha256": sha256}]},
        ]}))

    async def make_deployment(tenant, app_id, version, s3_key):
        device = await Device.create(
            tenant=tenant, udid=f"U-{tenant.id}", serial_number=f"S-{tenant.id}",
            device_model="MacBookPro18,1", os_version="15.0", hostname=f"mac-{tenant.id}",
            enrollment_state="enrolled", management_type="apple_mdm",
        )
        deployment = await AppDeployment.create(
            tenant=tenant, device=device, app_id=app_id, app_version=version, status="pending",
        )
        write_apps_yaml(tenant.id, app_id, version, s3_key)
        return deployment

    print("get_app_manifest, ambient-mode tenant:")
    _, tenant = await make_admin("amb-mf")
    deployment = await make_deployment(tenant, "slack", "1.0", "slack/slack-1.0.pkg")
    resp = await get_app_manifest(str(deployment.id))
    manifest = plistlib.loads(resp.body)
    url = manifest["items"][0]["assets"][0]["url"]
    check("manifest built instead of KeyError('bucket')",
          url == "https://signed.example/operator-packages/slack/slack-1.0.pkg?exp=3600")

    print("get_app_manifest, tenant-mode tenant with an unslashed prefix:")
    _, tenant = await make_admin("own-mf", {
        "bucket": "acme-packages", "access_key_id": "AK", "secret_access_key": "SK",
        "prefix": "apps",
    })
    deployment = await make_deployment(tenant, "chrome", "2.0", "chrome/chrome-2.0.pkg")
    resp = await get_app_manifest(str(deployment.id))
    manifest = plistlib.loads(resp.body)
    url = manifest["items"][0]["assets"][0]["url"]
    check("bucket is the tenant's own and prefix gets a separator",
          url == "https://signed.example/acme-packages/apps/chrome/chrome-2.0.pkg?exp=3600")

    print("get_app_manifest, incomplete tenant-mode config tells the device nothing:")
    _, tenant = await make_admin("half-mf", {"bucket": "acme-packages"})
    deployment = await make_deployment(tenant, "figma", "1.0", "figma/figma-1.0.pkg")
    try:
        await get_app_manifest(str(deployment.id))
        check("incomplete config rejected", False)
    except HTTPException as e:
        # This endpoint is unauthenticated, so the deployment id is the only credential. The config error names the
        # tenant and its missing S3 keys, which belongs in the log rather than the response.
        check("incomplete config -> 500", e.status_code == 500)
        check("the tenant id does not reach the caller", tenant.id not in e.detail)
        check("the missing key names do not reach the caller",
              "access_key_id" not in e.detail and "secret_access_key" not in e.detail)

    print("the manifest carries no size, because Apple removed the key:")
    # A device HEADs the asset URL to size the download, and a presigned URL is signed for one verb, so a GET-signed URL
    # answers that HEAD with 403 and the device reports 0 B. The manifest cannot make up for it: sizeInBytes is removed.
    # https://raw.githubusercontent.com/apple/device-management/release/other/manifesturl.yaml
    _, tenant = await make_admin("size-mf")
    deployment = await make_deployment(tenant, "slack", "1.0", "slack/slack-1.0.pkg")
    resp = await get_app_manifest(str(deployment.id))
    manifest = plistlib.loads(resp.body)
    item = manifest["items"][0]
    check("no sizeInBytes on the metadata, which the device would ignore",
          "sizeInBytes" not in item["metadata"])
    check("...and none on the asset either, where the schema has no such key",
          "sizeInBytes" not in item["assets"][0] and "size" not in item["assets"][0])
    check("the integrity hash is still what binds the download",
          item["assets"][0].get("sha256"))

    print("the storage picker: listing, checksum, and what the upload records")
    from controller.api.main import (
        checksum_app_package, list_app_packages, PackageChecksumRequest,
    )
    import hashlib as _hashlib
    admin, tenant = await make_admin("pick", {
        "bucket": "pick-bucket", "access_key_id": "AK", "secret_access_key": "SK",
        "prefix": "t/",
    })
    payload = b"a package body of some length"
    result = await upload_app_package(
        file=make_upload_file(payload, "hello.pkg"), app_id="hello", version="1.0", admin=admin,
    )
    check("upload reports the sha256 of the bytes it stored",
          result["sha256"] == _hashlib.sha256(payload).hexdigest())
    stored = FakeS3Client.objects[("pick-bucket", "t/hello/hello-1.0.pkg")]
    check("and records it on the object", stored["metadata"].get("sha256") == result["sha256"])
    # Something that arrived outside the upload endpoint: no metadata.
    FakeS3Client.objects[("pick-bucket", "t/other/other-2.0.pkg")] = {"body": b"x" * 10, "metadata": {}}
    FakeS3Client.objects[("pick-bucket", "elsewhere/not-mine.pkg")] = {"body": b"y" * 5, "metadata": {}}
    listing = await list_app_packages(admin=admin)
    keys = {p["key"]: p for p in listing["packages"]}
    check("the listing shows keys in apps.yaml form, prefix stripped",
          set(keys) == {"hello/hello-1.0.pkg", "other/other-2.0.pkg"})
    check("an object outside the tenant prefix is not offered", "elsewhere/not-mine.pkg" not in keys
          and "../elsewhere/not-mine.pkg" not in keys)
    check("the uploaded one carries its checksum", keys["hello/hello-1.0.pkg"]["sha256"] == result["sha256"])
    check("the foreign one does not", keys["other/other-2.0.pkg"]["sha256"] is None)
    check("sizes and usage add up",
          keys["other/other-2.0.pkg"]["size"] == 10 and listing["usage_bytes"] == len(payload) + 10)
    check("no quota configured reads as unlimited", listing["quota_bytes"] is None)
    got = await checksum_app_package(PackageChecksumRequest(s3_key="other/other-2.0.pkg"), admin=admin)
    check("the checksum endpoint hashes the object", got["sha256"] == _hashlib.sha256(b"x" * 10).hexdigest())
    check("and writes it back so the next listing has it",
          FakeS3Client.objects[("pick-bucket", "t/other/other-2.0.pkg")]["metadata"].get("sha256") == got["sha256"])
    try:
        await checksum_app_package(PackageChecksumRequest(s3_key="../elsewhere/not-mine.pkg"), admin=admin)
        check("a key that climbs out of the prefix is refused", False)
    except HTTPException as e:
        check("a key that climbs out of the prefix is refused", e.status_code == 400)

    print("the storage quota")
    tenant.storage_quota_bytes = len(payload) + 10 + 4  # room for 4 more bytes
    await tenant.save()
    admin.tenant.storage_quota_bytes = tenant.storage_quota_bytes
    try:
        await upload_app_package(
            file=make_upload_file(b"12345", "big.pkg"), app_id="big", version="1.0", admin=admin,
        )
        check("an upload that would exceed the quota is refused", False)
    except HTTPException as e:
        check("an upload that would exceed the quota is refused with 413", e.status_code == 413)
        check("and the message says how far over", "quota" in e.detail)
    check("nothing was stored", ("pick-bucket", "t/big/big-1.0.pkg") not in FakeS3Client.objects)
    small = await upload_app_package(
        file=make_upload_file(b"1234", "ok.pkg"), app_id="ok", version="1.0", admin=admin,
    )
    check("one that fits is stored", small["s3_key"] == "ok/ok-1.0.pkg")
    # Replacing the same version does not count twice.
    same = await upload_app_package(
        file=make_upload_file(b"4321", "ok.pkg"), app_id="ok", version="1.0", admin=admin,
    )
    check("re-uploading the same version is not double counted", same["s3_key"] == "ok/ok-1.0.pkg")
    os.environ["MDM_DEFAULT_STORAGE_QUOTA_BYTES"] = "1"
    admin2, tenant2 = await make_admin("quota-default", {
        "bucket": "pick-bucket", "access_key_id": "AK", "secret_access_key": "SK",
        "prefix": "q/",
    })
    try:
        await upload_app_package(
            file=make_upload_file(b"12", "x.pkg"), app_id="x", version="1.0", admin=admin2,
        )
        check("the deployment default quota applies to a tenant with none of its own", False)
    except HTTPException as e:
        check("the deployment default quota applies to a tenant with none of its own",
              e.status_code == 413)
    tenant2.storage_quota_bytes = 0
    admin2.tenant.storage_quota_bytes = 0
    ok2 = await upload_app_package(
        file=make_upload_file(b"12", "x.pkg"), app_id="x", version="1.0", admin=admin2,
    )
    check("a tenant quota of 0 means unlimited and beats the default", ok2["s3_key"] == "x/x-1.0.pkg")
    os.environ.pop("MDM_DEFAULT_STORAGE_QUOTA_BYTES", None)

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run

run(main)
