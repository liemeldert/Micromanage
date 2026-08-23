"""E2E checks for per-tenant S3 credential scoping (sqlite in-memory).

Run: PYTHONPATH=. .venv/bin/python tests/verify_s3_scoping.py
"""
import os
import tempfile
from pathlib import Path

import yaml
from tortoise import Tortoise

import controller.services.app_manager as am
from controller.services.app_manager import (
    AppManager,
    S3ConfigError,
    resolve_s3_settings,
)
from controller.models.tenant import Device, Tenant
from controller.utils.yaml_validator import TenantConfig, YAMLValidator

PASS, FAIL = [], []

# What the deployment operator's environment holds. Every value is tagged so a leak into a tenant-scoped resolution is
# unmistakable.
AMBIENT = {
    "AWS_ACCESS_KEY_ID": "AKIA-OPERATOR",
    "AWS_SECRET_ACCESS_KEY": "OPERATOR-SECRET",
    "AWS_SESSION_TOKEN": "OPERATOR-TOKEN",
    "AWS_DEFAULT_REGION": "eu-west-3",
    "AWS_S3_BUCKET": "operator-packages",
    "AWS_S3_ENDPOINT_URL": "https://minio.operator.internal",
}


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def set_ambient_env():
    for k, v in AMBIENT.items():
        os.environ[k] = v


def resolve_with_no_env(tenant):
    """resolve_s3_settings(tenant) with any environment read made fatal."""
    real = am.os.getenv

    def fatal(*args, **kwargs):
        raise AssertionError("resolve_s3_settings read the environment")

    am.os.getenv = fatal
    try:
        return resolve_s3_settings(tenant)
    finally:
        am.os.getenv = real


async def test_ambient_tenant():
    print("tenant with no S3 configuration:")
    tenant = await Tenant.create(id="amb", name="Ambient")

    s = resolve_s3_settings(tenant)
    check("source is the environment", s.source == "environment")
    check("bucket from AWS_S3_BUCKET", s.bucket == "operator-packages")
    check("access key from AWS_ACCESS_KEY_ID", s.access_key_id == "AKIA-OPERATOR")
    check("secret from AWS_SECRET_ACCESS_KEY", s.secret_access_key == "OPERATOR-SECRET")
    check("session token from AWS_SESSION_TOKEN", s.session_token == "OPERATOR-TOKEN")
    check("region from AWS_DEFAULT_REGION", s.region == "eu-west-3")
    check("endpoint from AWS_S3_ENDPOINT_URL", s.endpoint_url == "https://minio.operator.internal")
    # These two have never been env vars, and the env templates say so.
    check("use_ssl defaults on", s.use_ssl is True)
    check("path_style defaults off", s.path_style is False)

    # The client really is built from those values.
    client = AppManager(tenant).s3_client
    check("client signs with the ambient key",
          client._request_signer._credentials.access_key == "AKIA-OPERATOR")
    check("client points at the ambient endpoint",
          client.meta.endpoint_url == "https://minio.operator.internal")

    # A prefix picks a path inside whichever bucket is already in force. It is not a trust decision, so it does not flip
    # the tenant into owning its S3.
    tenant.s3_config = {"prefix": "packages/"}
    s = resolve_s3_settings(tenant)
    check("prefix alone stays ambient", s.source == "environment" and s.bucket == "operator-packages")
    check("prefix is carried", s.prefix == "packages/")
    check("prefix reaches the key", AppManager(tenant)._build_s3_key("f.pkg") == "packages/f.pkg")


async def test_tenant_owned():
    print("tenant with a complete S3 configuration:")
    tenant = await Tenant.create(id="own", name="Owned", s3_config={
        "bucket": "acme-packages",
        "access_key_id": "AKIA-ACME",
        "secret_access_key": "ACME-SECRET",
        "region": "us-west-2",
        "endpoint_url": "https://s3.acme.example",
        "prefix": "apps/",
    })

    s = resolve_with_no_env(tenant)
    check("source is the tenant", s.source == "tenant")
    check("bucket is the tenant's", s.bucket == "acme-packages")
    check("access key is the tenant's", s.access_key_id == "AKIA-ACME")
    check("secret is the tenant's", s.secret_access_key == "ACME-SECRET")
    check("region is the tenant's", s.region == "us-west-2")
    check("endpoint is the tenant's", s.endpoint_url == "https://s3.acme.example")
    check("no ambient value survives anywhere",
          not set(AMBIENT.values()) & {s.bucket, s.access_key_id, s.secret_access_key,
                                       s.session_token, s.region, s.endpoint_url})

    client = AppManager(tenant).s3_client
    check("client signs with the tenant key",
          client._request_signer._credentials.access_key == "AKIA-ACME")
    check("client points at the tenant endpoint",
          client.meta.endpoint_url == "https://s3.acme.example")
    check("bucket accessor agrees", AppManager(tenant)._get_s3_bucket() == "acme-packages")

    # The reverse mix matters too: a tenant that brings its own keys but no endpoint must not have them sent to the
    # operator's MinIO.
    tenant.s3_config = {"bucket": "acme-packages", "access_key_id": "AKIA-ACME",
                        "secret_access_key": "ACME-SECRET"}
    s = resolve_with_no_env(tenant)
    check("no endpoint means real AWS, not the operator's", s.endpoint_url is None)
    check("region falls to the code default", s.region == "us-east-1")

    # An optional session token is passed through rather than dropped.
    tenant.s3_config = dict(tenant.s3_config, session_token="ACME-TOKEN")
    check("session token is the tenant's",
          resolve_with_no_env(tenant).session_token == "ACME-TOKEN")
    check("client carries the session token",
          AppManager(tenant).s3_client._request_signer._credentials.token == "ACME-TOKEN")


async def test_partial_configuration_fails():
    print("tenant with part of an S3 configuration:")
    tenant = await Tenant.create(id="half", name="Half")

    cases = [
        ("bucket alone", {"bucket": "acme-packages"},
         ("access_key_id", "secret_access_key")),
        ("bucket + access key, no secret",
         {"bucket": "b", "access_key_id": "AKIA-ACME"}, ("secret_access_key",)),
        ("credentials, no bucket",
         {"access_key_id": "AKIA-ACME", "secret_access_key": "S"}, ("bucket",)),
        ("endpoint alone", {"endpoint_url": "https://s3.acme.example"},
         ("bucket", "access_key_id", "secret_access_key")),
        ("region alone", {"region": "us-west-2"},
         ("bucket", "access_key_id", "secret_access_key")),
        ("transport toggle alone", {"use_ssl": False},
         ("bucket", "access_key_id", "secret_access_key")),
    ]

    for label, cfg, expect_missing in cases:
        tenant.s3_config = dict(cfg)
        try:
            s = resolve_s3_settings(tenant)
            check(f"{label} rejected", False)
            check(f"{label} did not borrow ambient keys",
                  s.access_key_id != AMBIENT["AWS_ACCESS_KEY_ID"])
        except S3ConfigError as e:
            msg = str(e)
            check(f"{label} raises S3ConfigError", True)
            check(f"{label} message names every missing key",
                  all(k in msg for k in expect_missing))
            check(f"{label} message says how to fix it",
                  "clear that configuration" in msg and "add the missing settings" in msg.lower())
            check(f"{label} message names the tenant", "'half'" in msg)
            check(f"{label} leaks no ambient credential",
                  AMBIENT["AWS_ACCESS_KEY_ID"] not in msg
                  and AMBIENT["AWS_SECRET_ACCESS_KEY"] not in msg)

    # And the accessors the deploy path actually calls fail the same way.
    tenant.s3_config = {"bucket": "acme-packages"}
    mgr = AppManager(tenant)
    for label, fn in [("s3_client", lambda: mgr.s3_client),
                      ("_get_s3_bucket", mgr._get_s3_bucket)]:
        try:
            fn()
            check(f"{label} raises on a half configuration", False)
        except S3ConfigError:
            check(f"{label} raises on a half configuration", True)

    # A whole missing configuration on a deployment with no AWS_S3_BUCKET is a different mistake and gets its own
    # message.
    tenant.s3_config = {}
    saved = os.environ.pop("AWS_S3_BUCKET")
    try:
        AppManager(tenant)._get_s3_bucket()
        check("empty env bucket is reported clearly", False)
    except S3ConfigError as e:
        check("empty env bucket is reported clearly", "AWS_S3_BUCKET" in str(e))
    finally:
        os.environ["AWS_S3_BUCKET"] = saved


async def test_use_ssl_false():
    print("use_ssl: false:")
    # As pydantic sees it coming out of config.yaml. A Dict[str, str] annotation used to coerce this to the string
    # "False", which is truthy.
    parsed = TenantConfig(**yaml.safe_load(
        "id: t\nname: T\nallowed_users: []\n"
        "s3:\n  bucket: b\n  access_key_id: A\n  secret_access_key: S\n"
        "  use_ssl: false\n  path_style: true\n"
    ))
    check("YAML false survives validation as a bool", parsed.s3["use_ssl"] is False)
    check("YAML true survives validation as a bool", parsed.s3["path_style"] is True)

    tenant = await Tenant.create(id="ssl", name="SSL", s3_config=dict(parsed.s3))
    s = resolve_with_no_env(tenant)
    check("resolved use_ssl is off", s.use_ssl is False)
    check("resolved path_style is on", s.path_style is True)
    client = AppManager(tenant).s3_client
    check("client speaks plain http", client.meta.endpoint_url.startswith("http://"))

    # JSON from PUT /api/v1/tenant, or a hand-edited string, means the same.
    tenant.s3_config = dict(parsed.s3, use_ssl="False", path_style="no")
    s = resolve_with_no_env(tenant)
    check("string 'False' is off", s.use_ssl is False)
    check("string 'no' is off", s.path_style is False)
    tenant.s3_config = dict(parsed.s3, use_ssl="true")
    check("string 'true' is on", resolve_with_no_env(tenant).use_ssl is True)


def test_validator():
    print("config.yaml validation:")

    def validate(s3_block):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            tenant = {"id": "t", "name": "T", "allowed_users": ["a@t"]}
            if s3_block is not None:
                tenant["s3"] = s3_block
            (tdp / "config.yaml").write_text(yaml.safe_dump({"tenant": tenant}))
            (tdp / "groups.yaml").write_text(yaml.safe_dump({"groups": []}))
            (tdp / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
            (tdp / "profiles.yaml").write_text(yaml.safe_dump({"profiles": []}))
            return YAMLValidator(tdp).validate_all()

    valid, errors, _ = validate({"bucket": "acme-packages"})
    check("bucket without credentials is an error", not valid)
    check("that error names both missing keys",
          any("access_key_id" in e and "secret_access_key" in e for e in errors))
    check("that error offers the escape route",
          any("remove the s3 block" in e for e in errors))

    valid, errors, _ = validate({
        "bucket": "b", "access_key_id": "A", "secret_access_key": "S"})
    check("a complete block validates", valid and not errors)

    valid, errors, _ = validate({})
    check("an empty block validates", valid and not errors)

    valid, errors, _ = validate(None)
    check("no block at all validates", valid and not errors)

    valid, errors, _ = validate({"prefix": "apps/"})
    check("a prefix-only block validates", valid and not errors)

    valid, errors, _ = validate({"endpoint_url": "https://s3.acme.example"})
    check("an endpoint without credentials is an error", not valid)


async def test_reconcile_is_not_collateral():
    print("a broken S3 config does not break reconciliation:")
    tenant = await Tenant.create(id="rec", name="Rec",
                                 s3_config={"bucket": "acme-packages"})
    await Device.create(
        tenant=tenant, udid="U-REC", serial_number="SREC",
        device_model="MacBookPro18,1", os_version="15.0",
        hostname="mac-rec", enrollment_state="enrolled",
        management_type="apple_mdm",
    )

    # Constructing the manager must not touch S3: the reconciler builds one per tenant at the top of every cycle, before
    # profiles and DDM are handled.
    mgr = AppManager(tenant)
    check("AppManager construction does not raise", mgr is not None)
    check("no client is built eagerly", mgr._s3_client is None)

    device = await Device.get(udid="U-REC")
    apps = await mgr.evaluate_device_apps(device, [], [])
    check("app scoping still works", apps == [])

    from controller.services.reconciler import reconcile_tenant

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td) / "tenants" / "rec"
        tdp.mkdir(parents=True)
        for name, doc in [("groups.yaml", {"groups": []}),
                          ("apps.yaml", {"apps": []}),
                          ("profiles.yaml", {"profiles": []})]:
            (tdp / name).write_text(yaml.safe_dump(doc))
        summary = await reconcile_tenant(tenant, Path(td))
    check("reconcile completes for the misconfigured tenant", summary["devices"] == 1)
    check("and queues nothing it cannot deliver", summary["apps_queued"] == 0)


async def test_package_precondition():
    print("a tenant that cannot serve packages is told once, not per device:")
    # Whether there is a bucket, and whose credentials address it, is a property of the tenant, so the sync loop asks
    # once per cycle before queueing rather than failing one task per device.
    from controller.services.reconciler import reconcile_tenant

    # Install needs bucket and public https address for ManifestURL.
    os.environ["PUBLIC_API_URL"] = "https://mdm.example.com"

    # 1. Resolvable: the ambient environment has a bucket and credentials.
    ok_tenant = await Tenant.create(id="pre-ok", name="Pre OK")
    check("a resolvable tenant reports no reason to hold",
          AppManager(ok_tenant).package_store_error() is None)

    # 2. Half a tenant configuration. resolve_s3_settings raises here rather than returning an empty
    # bucket, so a precondition that only tested for a missing bucket would let the exception out.
    half_tenant = await Tenant.create(
        id="pre-half", name="Pre Half", s3_config={"bucket": "acme-packages"})
    half_reason = AppManager(half_tenant).package_store_error()
    check("an incomplete tenant configuration is answered, not raised",
          isinstance(half_reason, str) and "incomplete S3 configuration" in half_reason)

    # 3. s3_config can be non-dict (JSONField stores anything); test invalid shapes.
    for shape in (["bucket", "acme"], "acme-packages", 7):
        odd_tenant = await Tenant.create(
            id=f"pre-odd-{type(shape).__name__}", name="Pre Odd")
        odd_tenant.s3_config = shape
        odd_reason = AppManager(odd_tenant).package_store_error()
        check(f"an s3_config that is a {type(shape).__name__} is answered, not raised",
              isinstance(odd_reason, str) and "not a set of settings" in odd_reason)

    # 4. The other thing no device can supply: a public address Apple accepts as a ManifestURL. The same
    # kind of mistake, so the same answer, rather than one failed task per scoped device.
    plain_tenant = await Tenant.create(id="pre-http", name="Pre HTTP")
    saved_url = os.environ.get("PUBLIC_API_URL")
    try:
        os.environ["PUBLIC_API_URL"] = "http://mdm.example.com"
        http_reason = AppManager(plain_tenant).package_store_error()
        os.environ.pop("PUBLIC_API_URL")
        unset_reason = AppManager(plain_tenant).package_store_error()
        os.environ["PUBLIC_API_URL"] = "https://mdm.example.com"
        https_reason = AppManager(plain_tenant).package_store_error()
    finally:
        if saved_url is None:
            os.environ.pop("PUBLIC_API_URL", None)
        else:
            os.environ["PUBLIC_API_URL"] = saved_url
    check("a non-https public address is a tenant-level hold",
          isinstance(http_reason, str) and "https ManifestURL" in http_reason)
    check("...and it names the setting to change",
          isinstance(http_reason, str) and "PUBLIC_API_URL" in http_reason)
    # An unset address is refused here too, once for the tenant and before any task row exists, with a message naming
    # the setting rather than quoting back a ManifestURL with no host on the front.
    check("an unset public address is refused too, not deferred to the device",
          isinstance(unset_reason, str) and "PUBLIC_API_URL" in unset_reason)
    check("an https one holds nothing", https_reason is None)

    # 5. No configuration anywhere.
    bare_tenant = await Tenant.create(id="pre-bare", name="Pre Bare")
    saved = os.environ.pop("AWS_S3_BUCKET")
    try:
        bare_reason = AppManager(bare_tenant).package_store_error()
    finally:
        os.environ["AWS_S3_BUCKET"] = saved
    check("a deployment with no bucket at all names the setting to fix",
          isinstance(bare_reason, str) and "AWS_S3_BUCKET" in bare_reason)

    # And the cycle itself, for the tenant whose settings raise: it has to complete, hold the install, and say how many
    # it held.
    await Device.create(
        tenant=half_tenant, udid="U-PRE-HALF", serial_number="SPREHALF",
        device_model="MacBookPro18,1", os_version="15.0", hostname="mac-pre-half",
        enrollment_state="enrolled", management_type="apple_mdm",
    )
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td) / "tenants" / "pre-half"
        tdp.mkdir(parents=True)
        (tdp / "groups.yaml").write_text(yaml.safe_dump({"groups": [
            {"name": "all-macs", "conditions": [
                {"type": "platform", "operator": "in", "value": ["Mac"]}]}]}))
        (tdp / "profiles.yaml").write_text(yaml.safe_dump({"profiles": []}))
        (tdp / "apps.yaml").write_text(yaml.safe_dump({"apps": [
            {"id": "slack", "name": "Slack", "bundle_id": "com.tinyspeck.slackmacgap",
             "versions": [{"version": "1.0", "s3_key": "apps/slack-1.0.pkg",
                           "groups": ["all-macs"]}]},
        ]}))
        summary = await reconcile_tenant(half_tenant, Path(td))
    check(f"the cycle completes rather than raising ({summary})",
          summary["devices"] == 1 and summary["errors"] == 0)
    check("nothing is queued and the hold is counted",
          summary["apps_queued"] == 0 and summary["apps_blocked"] == 1)


async def main():
    set_ambient_env()
    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()
    await test_ambient_tenant()
    await test_tenant_owned()
    await test_partial_configuration_fails()
    await test_use_ssl_false()
    test_validator()
    await test_reconcile_is_not_collateral()
    await test_package_precondition()
    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run

run(main)
