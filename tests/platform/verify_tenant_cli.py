"""tenant_cli tenant set-s3-prefix on in-memory sqlite: tenants can leave the shared bucket root one at a time, and a
prefix that overlaps another shared-bucket tenant is refused.

Run: PYTHONPATH=. python tests/platform/verify_tenant_cli.py
"""
import io
import os
import tempfile

os.environ["YAML_CONFIG_PATH"] = tempfile.mkdtemp(prefix="verify-tenant-cli-")
os.environ.pop("AWS_S3_BUCKET", None)

import typer  # noqa: E402
from rich.console import Console  # noqa: E402
from tortoise import Tortoise  # noqa: E402

from controller.models.tenant import Tenant  # noqa: E402
from controller.services.app_manager import resolve_s3_settings  # noqa: E402
from controller.tenant_cli import cli  # noqa: E402
from tests._verify_harness import make_check  # noqa: E402

PASS, FAIL = [], []
check = make_check(FAIL, PASS)

# The command body without with_db, which would open the deployment database.
_set_prefix = cli.tenant_set_s3_prefix.__wrapped__


async def set_prefix(tenant_id, prefix):
    """(exit code, console output) for one tenant set-s3-prefix run."""
    out = io.StringIO()
    cli.console = Console(file=out, width=400)
    try:
        await _set_prefix(tenant_id, prefix)
        code = 0
    except typer.Exit as e:
        code = e.exit_code
    return code, out.getvalue()


async def main():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()
    await Tenant.create(id="a", name="A")
    await Tenant.create(id="b", name="B")
    await Tenant.create(id="own", name="Own", s3_config={"bucket": "own", "access_key_id": "AK",
                                                         "secret_access_key": "SK", "prefix": "tenants/"})

    print("1) with two tenants at the bucket root, either can move into a sub-prefix")
    code, out = await set_prefix("a", "tenants/a")
    check("tenant a moves to tenants/a/", code == 0, out)
    check("the warning names tenant b, still at the root",
          "still at the shared bucket root" in out and "included: b" in out, out)
    a = await Tenant.get(id="a")
    check("it is stored as shared_prefix", a.s3_config == {"shared_prefix": "tenants/a/"}, a.s3_config)
    check("and resolves to that prefix", resolve_s3_settings(a).prefix == "tenants/a/")

    print("2) overlapping prefixes are refused")
    for value in ("tenants/a/", "tenants/a/sub/", "tenants/", ""):
        code, out = await set_prefix("b", value)
        check(f"tenant b refused {value!r}", code == 1, out)
    check("tenant b is unchanged", not (await Tenant.get(id="b")).s3_config)

    print("3) an own-bucket tenant never overlaps")
    code, out = await set_prefix("b", "tenants/b/")
    check("tenant b moves to tenants/b/ despite the own-bucket tenant's tenants/ prefix", code == 0, out)
    check("no warning once nobody is at the root", "still at the shared bucket root" not in out, out)

    print("4) a legacy shared-bucket prefix counts as that tenant's place")
    await Tenant.create(id="legacy", name="Legacy", s3_config={"prefix": "tenants/legacy/"})
    code, out = await set_prefix("a", "tenants/legacy/x/")
    check("nesting inside a legacy prefix is refused", code == 1, out)
    code, out = await set_prefix("legacy", "")
    check("returning to the root is refused while others share the bucket", code == 1, out)

    print("5) set-s3-prefix keeps an own-bucket tenant's own prefix")
    code, out = await set_prefix("own", "tenants/own/")
    own = await Tenant.get(id="own")
    check("the command succeeds", code == 0, out)
    check("its own-bucket prefix still applies", resolve_s3_settings(own).prefix == "tenants/", own.s3_config)
    check("the shared_prefix is stored for when the tenant returns to the shared bucket",
          own.s3_config.get("shared_prefix") == "tenants/own/")

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    return 1 if FAIL else 0


if __name__ == "__main__":
    from tests._verify_harness import run
    run(main)
