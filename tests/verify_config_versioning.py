"""Optimistic concurrency for YAML config saves, on in-memory sqlite.

Run: PYTHONPATH=. ./.venv/bin/python tests/verify_config_versioning.py

Every config editor reads a document, edits a local copy and PUTs the whole thing back, so two admins in one document
can lose each other's work. A read reports the document's version in X-Config-Version (the sha256 of the bytes on disk),
a save may send it back as If-Match, and a save whose base version is stale is refused with a 409 rather than
overwriting. Restore replaces the whole file too, so it follows the same rule.
"""
import hashlib
import os
import tempfile
from pathlib import Path

import yaml
from fastapi import HTTPException
from fastapi.responses import Response
from tortoise import Tortoise

# As in verify_config_authz.py, the YAML base goes into the environment before anything imports the app, so every reader
# sees the temp tree.
_BASE = Path(tempfile.mkdtemp())
os.environ["YAML_CONFIG_PATH"] = str(_BASE)

import controller.api.main as apimain  # noqa: E402
from controller.auth.dependencies import Principal  # noqa: E402
from controller.models.tenant import Tenant, User, AuditLog  # noqa: E402

PASS, FAIL = [], []

TENANT_ID = "t1"

MINIMAL = {
    "groups": {"groups": []},
    "apps": {"apps": []},
    "profiles": {"profiles": []},
    "tags": {"tags": []},
}


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


async def status_of(coro):
    """Run an endpoint coroutine, returning its HTTP status (200 on success)."""
    try:
        await coro
        return 200
    except HTTPException as exc:
        return exc.status_code


async def detail_of(coro):
    """The HTTPException detail an endpoint coroutine raised, or None."""
    try:
        await coro
        return None
    except HTTPException as exc:
        return exc.detail


def seed_config_dir():
    tdir = _BASE / "tenants" / TENANT_ID
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "config.yaml").write_text(yaml.safe_dump({
        "tenant": {"id": TENANT_ID, "name": "Tenant One", "allowed_users": ["admin@t1"]}
    }))
    for name, doc in MINIMAL.items():
        (tdir / f"{name}.yaml").write_text(yaml.safe_dump(doc))
    return tdir


def version_header(response):
    return response.headers.get(apimain._CONFIG_VERSION_HEADER)


def history_count(config_type):
    hdir = apimain._history_dir(TENANT_ID, config_type)
    return len(list(hdir.glob("*.json"))) if hdir.exists() else 0


async def main():
    tdir = seed_config_dir()
    groups_path = tdir / "groups.yaml"

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    tenant = await Tenant.create(id=TENANT_ID, name="Tenant One")
    admin_user = await User.create(tenant=tenant, email="admin@t1", role="admin")
    admin = Principal(tenant=tenant, user=admin_user, email="admin@t1", role="admin")

    # A save triggers a reactive reconcile. Stubbed out: this file is about versioning, and a real reconcile would queue
    # MDM work against a fake fleet.
    apimain._spawn_tenant_reconcile = lambda tenant_id: None

    #  1. A read reports the version of what it served.
    print("1) GET reports the document version in X-Config-Version")
    check("the header's wire name is exactly X-Config-Version",
          apimain._CONFIG_VERSION_HEADER == "X-Config-Version")

    resp = Response()
    await apimain.get_yaml_config("groups", False, admin, resp)
    version = version_header(resp)
    check("a structured GET carries a version", bool(version))
    check("the version is the sha256 of the bytes on disk",
          version == hashlib.sha256(groups_path.read_bytes()).hexdigest())

    raw = await apimain.get_yaml_config("groups", True, admin)
    check("a raw GET carries the same version", version_header(raw) == version)

    check("_config_version has no version for a file that does not exist",
          apimain._config_version(tdir / "nothing.yaml") is None)

    #  2. A save that agrees with disk writes, and reports the new version.
    print("2) a save carrying the current version writes")
    doc = {"groups": [{"name": "lab", "conditions": [
        {"type": "device_model", "operator": "contains", "value": "Mac"}]}]}
    resp = Response()
    await apimain.update_yaml_config("groups", dict(doc), admin,
                                     if_match=version, response=resp)
    saved = yaml.safe_load(groups_path.read_text())
    check("the document was written", saved == doc)
    new_version = version_header(resp)
    check("the save reports a version", bool(new_version))
    check("the reported version is the one now on disk",
          new_version == apimain._config_version(groups_path))
    check("writing the document changed its version", new_version != version)

    # The version a save hands back is usable as the base of the next save, so an editor can keep saving without
    # re-reading the file.
    doc2 = {"groups": [{"name": "lab", "conditions": [
        {"type": "device_model", "operator": "contains", "value": "MacBook"}]}]}
    resp = Response()
    code = await status_of(apimain.update_yaml_config(
        "groups", dict(doc2), admin, if_match=new_version, response=resp))
    check("a second save chained on that version succeeds", code == 200)
    check("and it too reports the version it produced",
          version_header(resp) == apimain._config_version(groups_path))
    new_version = version_header(resp)

    #  3. A stale version is refused, and nothing at all is written.
    print("3) a save carrying a stale version is a 409 that changes nothing")
    before_bytes = groups_path.read_bytes()
    before_history = history_count("groups")
    await AuditLog.all().delete()
    stale = version  # the version from before the two saves above

    detail = await detail_of(apimain.update_yaml_config(
        "groups", {"groups": []}, admin, if_match=stale))
    check("the refusal is an object detail naming the conflict",
          isinstance(detail, dict) and detail.get("error") == "conflict")
    check("it explains itself in one sentence an admin can act on",
          isinstance(detail, dict)
          and "changed by someone else" in (detail.get("message") or ""))
    check("it hands back the version that is actually on disk",
          isinstance(detail, dict) and detail.get("current_version") == new_version)

    code = await status_of(apimain.update_yaml_config(
        "groups", {"groups": []}, admin, if_match=stale))
    check("the status is 409", code == 409)
    check("the file on disk is untouched", groups_path.read_bytes() == before_bytes)
    check("no history snapshot was taken", history_count("groups") == before_history)
    check("no audit row was written", await AuditLog.all().count() == 0)

    # An If-Match that is present but empty is not a claim about any version.
    code = await status_of(apimain.update_yaml_config(
        "groups", dict(doc2), admin, if_match="  "))
    check("a blank If-Match is treated as no If-Match", code == 200)

    # A version may arrive quoted, the way an HTTP entity tag normally does.
    resp = Response()
    code = await status_of(apimain.update_yaml_config(
        "groups", dict(doc2), admin, if_match=f'"{apimain._config_version(groups_path)}"',
        response=resp))
    check("a quoted version is accepted", code == 200)

    #  4. Nothing external breaks: a client that sends no If-Match still saves.
    print("4) a save with no If-Match keeps working (last write wins)")
    code = await status_of(apimain.update_yaml_config("groups", dict(doc), admin))
    check("a save with no If-Match at all succeeds", code == 200)
    check("and it really did write", yaml.safe_load(groups_path.read_text()) == doc)

    #  5. A dry run writes nothing, so it cannot conflict.
    print("5) a dry run ignores If-Match")
    before_bytes = groups_path.read_bytes()
    result = await apimain.update_yaml_config(
        "groups", dict(doc2), admin, dry_run=True, if_match=stale)
    check("a dry run with a stale version still validates",
          isinstance(result, dict) and result.get("valid") is True)
    check("and it wrote nothing", groups_path.read_bytes() == before_bytes)

    #  6. Restore replaces the whole file too, so it follows the same rule.
    print("6) history restore honours If-Match against the live document")
    versions = (await apimain.list_config_history("groups", admin))["versions"]
    check("there are snapshots to restore from", bool(versions))
    version_id = versions[0]["id"]

    before_bytes = groups_path.read_bytes()
    before_history = history_count("groups")
    await AuditLog.all().delete()
    code = await status_of(apimain.restore_config_history_version(
        "groups", version_id, admin, if_match=stale))
    check("a restore carrying a stale version is a 409", code == 409)
    check("the file is untouched by the refused restore",
          groups_path.read_bytes() == before_bytes)
    check("the refused restore took no snapshot", history_count("groups") == before_history)
    check("and left no audit row", await AuditLog.all().count() == 0)

    resp = Response()
    live = apimain._config_version(groups_path)
    code = await status_of(apimain.restore_config_history_version(
        "groups", version_id, admin, if_match=live, response=resp))
    check("a restore carrying the live version succeeds", code == 200)
    check("the restore reports the version it produced",
          version_header(resp) == apimain._config_version(groups_path))
    code = await status_of(
        apimain.restore_config_history_version("groups", version_id, admin))
    check("a restore with no If-Match still works", code == 200)

    #  7. A document with no file yet has nothing to disagree with.
    print("7) the first save of a new document is never a conflict")
    declarations = tdir / "declarations.yaml"
    if declarations.exists():
        declarations.unlink()
    resp = Response()
    code = await status_of(apimain.update_yaml_config(
        "declarations", {"declarations": []}, admin,
        if_match="0" * 64, response=resp))
    check("a save against an absent file is allowed whatever it claims", code == 200)
    check("and the new file's version comes back",
          version_header(resp) == apimain._config_version(declarations))

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run  # noqa: E402

run(main)
