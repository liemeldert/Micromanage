"""Authorization checks for YAML config authoring, on in-memory sqlite.

Run: PYTHONPATH=. ./.venv/bin/python tests/verify_config_authz.py

Which documents a member may write is an allowlist, controller.auth.MEMBER_WRITABLE_CONFIG_TYPES, so a type nobody has
classified is refused. Under a blocklist, apps.yaml is member-writable: a member uploads a package, points an apps.yaml
version at it scoped to the whole fleet, and the reconcile that follows the save installs it as root on every device,
while the same member is refused a restart command.

PUT /api/v1/config/{type} allows a member only tags, and history restore is held to the same rule since it writes the
same files by another route. The structural checks pin the allowlist as a subset of the editable list and loop over the
live one, so adding a type without deciding its tier fails here. Also here: require_admin on the upload endpoint, audit
rows on writes and none on refusals, update_user refusing to demote the calling admin or the last active one,
TenantConfig declaring ddm and device_naming, and saves and restores that keep the author's comments.
"""
import inspect
import os
import tempfile
from pathlib import Path

import yaml
from fastapi import HTTPException
from tortoise import Tortoise

# The YAML base goes into the environment before any import, so every reader sees the temp tree from the first access,
# even though api.main resolves the base per call.
_BASE = Path(tempfile.mkdtemp())
os.environ["YAML_CONFIG_PATH"] = str(_BASE)

import controller.api.main as apimain  # noqa: E402
from controller.auth import MEMBER_WRITABLE_CONFIG_TYPES  # noqa: E402
from controller.auth.dependencies import Principal, require_admin  # noqa: E402
from controller.models.tenant import Tenant, User, AuditLog  # noqa: E402
from controller.utils.yaml_validator import TenantConfig  # noqa: E402

PASS, FAIL = [], []

TENANT_ID = "t1"

# Minimal valid documents, one per editable config type.
MINIMAL = {
    "groups": {"groups": []},
    "apps": {"apps": []},
    "profiles": {"profiles": []},
    "tags": {"tags": []},
    "flows": {},
    "dispatcher": {},
    "declarations": {"declarations": []},
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


def seed_config_dir():
    tdir = _BASE / "tenants" / TENANT_ID
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "config.yaml").write_text(yaml.safe_dump({
        "tenant": {"id": TENANT_ID, "name": "Tenant One", "allowed_users": ["admin@t1"]}
    }))
    for name, doc in MINIMAL.items():
        (tdir / f"{name}.yaml").write_text(yaml.safe_dump(doc))
    return tdir


async def main():
    tdir = seed_config_dir()

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    tenant = await Tenant.create(id=TENANT_ID, name="Tenant One")
    admin_user = await User.create(tenant=tenant, email="admin@t1", role="admin")
    member_user = await User.create(tenant=tenant, email="member@t1", role="member")
    admin = Principal(tenant=tenant, user=admin_user, email="admin@t1", role="admin")
    member = Principal(tenant=tenant, user=member_user, email="member@t1", role="member")

    # A config save triggers a reactive reconcile. Stubbed out: this file is about authorization, and a real reconcile
    # would queue MDM work against a fake fleet.
    apimain._spawn_tenant_reconcile = lambda tenant_id: None

    #  1. Per-type authorization on the save endpoint.
    print("1) PUT /api/v1/config/{type}: members may write only the allowlist")
    for ctype in ("groups", "apps", "profiles", "declarations", "flows", "dispatcher"):
        code = await status_of(apimain.update_yaml_config(ctype, dict(MINIMAL[ctype]), member))
        check(f"member is refused '{ctype}' (403)", code == 403)

    code = await status_of(apimain.update_yaml_config("tags", {"tags": []}, member))
    check("member may still write 'tags' (the advisory registry)", code == 200)

    # The escalation a blocklist allows, spelled out: an apps.yaml entry pointing at a member-supplied package, scoped
    # fleet-wide.
    poisoned = {"apps": [{
        "id": "evil", "name": "Evil", "bundle_id": "com.evil.pkg",
        "versions": [{
            "version": "1.0", "s3_key": "evil/evil-1.0.pkg",
            "sha256": "a" * 64, "target_groups": ["all"],
        }],
    }]}
    code = await status_of(apimain.update_yaml_config("apps", poisoned, member))
    check("member cannot publish an app version (the original escalation)", code == 403)

    #  2. Admins can still author everything.
    print("2) an admin can write every editable config type")
    for ctype in apimain._EDITABLE_CONFIG_TYPES:
        code = await status_of(apimain.update_yaml_config(ctype, dict(MINIMAL[ctype]), admin))
        check(f"admin may write '{ctype}'", code == 200)

    #  3. Invalid type is a 400, not a 403: the type check comes first.
    print("3) an unknown config type is still a 400, not a 403")
    code = await status_of(apimain.update_yaml_config("nonsense", {}, member))
    check("member gets 400 for an unknown config type", code == 400)
    code = await status_of(apimain.restore_config_history_version("nonsense", "x", member))
    check("member gets 400 for an unknown type on restore too", code == 400)

    #  4. Restore writes the same files, so it is held to the same rule.
    print("4) history restore follows the same rule as a save")
    # Two admin saves each leave a snapshot of the outgoing document behind.
    await apimain.update_yaml_config("apps", {"apps": []}, admin)
    await apimain.update_yaml_config("tags", {"tags": []}, admin)

    apps_versions = (await apimain.list_config_history("apps", admin))["versions"]
    tags_versions = (await apimain.list_config_history("tags", admin))["versions"]
    check("history snapshots exist to restore from",
          bool(apps_versions) and bool(tags_versions))

    if apps_versions:
        code = await status_of(
            apimain.restore_config_history_version("apps", apps_versions[0]["id"], member))
        check("member is refused restoring 'apps' (403)", code == 403)
    if tags_versions:
        code = await status_of(
            apimain.restore_config_history_version("tags", tags_versions[0]["id"], member))
        check("member may restore 'tags'", code == 200)

    #  5. Structural regressions: the default must be deny.
    print("5) structural: the allowlist is the whole story")
    check("MEMBER_WRITABLE_CONFIG_TYPES is a subset of _EDITABLE_CONFIG_TYPES",
          set(MEMBER_WRITABLE_CONFIG_TYPES) <= set(apimain._EDITABLE_CONFIG_TYPES))

    # Looped over the LIVE list on purpose: add a config type without deciding its tier and this fails, instead of
    # quietly shipping member-write.
    denied_all = True
    for ctype in apimain._EDITABLE_CONFIG_TYPES:
        if ctype in MEMBER_WRITABLE_CONFIG_TYPES:
            continue
        code = await status_of(apimain.update_yaml_config(ctype, dict(MINIMAL[ctype]), member))
        if code != 403:
            denied_all = False
            print(f"       -> '{ctype}' returned {code}, expected 403")
    check("every non-allowlisted editable type 403s for a member (live list)", denied_all)

    # And the direct assertion that the default is deny, not allow: a config type nobody has classified yet must be
    # refused.
    original = list(apimain._EDITABLE_CONFIG_TYPES)
    try:
        apimain._EDITABLE_CONFIG_TYPES.append("synthetic_future_type")
        code = await status_of(
            apimain.update_yaml_config("synthetic_future_type", {}, member))
        check("a brand-new config type is admin-only by default (403)", code == 403)
        code = await status_of(
            apimain.restore_config_history_version("synthetic_future_type", "x", member))
        check("a brand-new config type is admin-only on restore too (403)", code == 403)
    finally:
        apimain._EDITABLE_CONFIG_TYPES[:] = original
    check("the editable-type list was restored after the synthetic probe",
          apimain._EDITABLE_CONFIG_TYPES == original)

    #  6. Package upload is admin-only.
    # A FastAPI dependency does not run when the function is called directly, so this asserts the wiring rather than the
    # behaviour.
    print("6) POST /api/v1/apps/upload is wired to require_admin")
    params = inspect.signature(apimain.upload_app_package).parameters
    check("upload_app_package takes an 'admin' principal", "admin" in params)
    check("upload_app_package depends on require_admin",
          "admin" in params and getattr(params["admin"].default, "dependency", None) is require_admin)
    check("upload_app_package takes no bare principal", "principal" not in params)

    #  7. Config writes are audited.
    print("7) every config write leaves an audit row; a refused one leaves none")
    await AuditLog.all().delete()
    await apimain.update_yaml_config("tags", {"tags": []}, admin)
    rows = await AuditLog.filter(action="config.update")
    check("an admin save writes exactly one config.update row", len(rows) == 1)
    if rows:
        check("the row names the config document", rows[0].target_id == "tags")
        check("the row records target_type=config", rows[0].target_type == "config")
        check("the row stamps the acting admin",
              rows[0].actor_email == "admin@t1" and rows[0].actor_role == "admin")
        check("the row carries no document content (warning count only)",
              set(rows[0].detail or {}) == {"warnings"})

    await AuditLog.all().delete()
    await apimain.update_yaml_config("tags", {"tags": []}, member)
    rows = await AuditLog.filter(action="config.update")
    check("a member's allowed save is audited too, stamped member",
          len(rows) == 1 and rows[0].actor_role == "member")

    await AuditLog.all().delete()
    await status_of(apimain.update_yaml_config("apps", {"apps": []}, member))
    check("a refused (403) save writes no audit row",
          await AuditLog.all().count() == 0)

    await AuditLog.all().delete()
    tags_versions = (await apimain.list_config_history("tags", admin))["versions"]
    await apimain.restore_config_history_version("tags", tags_versions[0]["id"], admin)
    restores = await AuditLog.filter(action="config.restore")
    check("a restore writes a config.restore row naming the version",
          len(restores) == 1 and restores[0].detail.get("version_id") == tags_versions[0]["id"])
    check("a restore is also recorded as a config.update (it did write the file)",
          await AuditLog.filter(action="config.update").count() == 1)

    #  8. Last-admin / self-demotion guard on update_user.
    print("8) an admin cannot demote themselves or the last remaining admin")
    from controller.api.main import UserUpdate

    code = await status_of(
        apimain.update_user(str(admin_user.id), UserUpdate(role="member"), admin))
    check("an admin cannot demote themselves (400)", code == 400)
    await admin_user.refresh_from_db()
    check("the self-demotion attempt did not change the role", admin_user.role == "admin")

    code = await status_of(
        apimain.update_user(str(admin_user.id), UserUpdate(is_active=False), admin))
    check("an admin still cannot deactivate themselves (400)", code == 400)

    # Promoting a member is fine, and so is demoting an admin while another active admin remains.
    code = await status_of(
        apimain.update_user(str(member_user.id), UserUpdate(role="admin"), admin))
    await member_user.refresh_from_db()
    check("promoting a member to admin still works",
          code == 200 and member_user.role == "admin")
    code = await status_of(
        apimain.update_user(str(member_user.id), UserUpdate(role="member"), admin))
    await member_user.refresh_from_db()
    check("demoting an admin while another admin remains still works",
          code == 200 and member_user.role == "member")

    # The last-active-admin arm, reachable when the caller's own row stopped being an active admin after the token was
    # issued. Deactivate the caller's row, then try to demote the only other admin.
    second_admin = await User.create(tenant=tenant, email="admin2@t1", role="admin")
    admin_user.is_active = False
    await admin_user.save(update_fields=["is_active"])
    code = await status_of(
        apimain.update_user(str(second_admin.id), UserUpdate(role="member"), admin))
    check("demoting the last ACTIVE admin is refused (400)", code == 400)
    code = await status_of(
        apimain.update_user(str(second_admin.id), UserUpdate(is_active=False), admin))
    check("deactivating the last ACTIVE admin is refused (400)", code == 400)
    await second_admin.refresh_from_db()
    check("the last admin kept both their role and their access",
          second_admin.role == "admin" and second_admin.is_active)
    admin_user.is_active = True
    await admin_user.save(update_fields=["is_active"])

    #  9. TenantConfig declares the keys the sync loop reads back.
    print("9) config.yaml's tenant block validates ddm + device_naming")
    fields = TenantConfig.__fields__
    check("TenantConfig declares 'ddm'", "ddm" in fields)
    check("TenantConfig declares 'device_naming'", "device_naming" in fields)

    parsed = TenantConfig(id="t1", name="T", allowed_users=[], ddm={"enabled": True},
                          device_naming={"template": "{serial}-mac", "apply_on_enroll": True})
    check("a tenant naming template survives validation instead of being dropped",
          parsed.device_naming is not None
          and parsed.device_naming.template == "{serial}-mac")
    check("ddm.enabled survives validation", (parsed.ddm or {}).get("enabled") is True)

    # The mirror writes device_naming: {} to CLEAR the template, so empty must mean unset rather than "missing required
    # field".
    cleared = TenantConfig(id="t1", name="T", allowed_users=[], device_naming={})
    check("an empty device_naming clears the template instead of erroring",
          cleared.device_naming is None)

    bad = None
    try:
        TenantConfig(id="t1", name="T", allowed_users=[], device_naming={"template": "  "})
    except Exception as exc:
        bad = exc
    check("a blank tenant naming template is rejected", bad is not None)

    # A tenant-wide template with an unknown variable warns, the same way a per-group one does.
    (tdir / "config.yaml").write_text(yaml.safe_dump({"tenant": {
        "id": TENANT_ID, "name": "Tenant One", "allowed_users": ["admin@t1"],
        "device_naming": {"template": "{seriall}-mac"},
    }}))
    from controller.utils.yaml_validator import YAMLValidator
    valid, errors, warnings = YAMLValidator(tdir).validate_all()
    check("a bad tenant naming variable is warned about, not silently ignored",
          any("seriall" in w for w in warnings))
    check("the warning does not fail the document", valid)

    # 10. A save keeps the author's comments, and so does a restore.
    print("10) saving and restoring a config document does not delete its comments")
    tags_path = tdir / "tags.yaml"
    commented = (
        "# The advisory tag registry.\n"
        "#\n"
        "# A tag not listed here still works: this file only drives the picker\n"
        "# and the chip colours.\n"
        "tags:\n"
        "  # Anything on a bench rather than in a classroom.\n"
        "  - name: lab\n"
        # Padded on purpose: a re-render normalizes the spacing, so an identical file below shows the text was written
        # untouched rather than merely surviving a round trip.
        "    label:   Lab\n"
        "  - name: loaner\n"
        "    label: Loaner\n"
    )
    document = yaml.safe_load(commented)

    # A save that hands over the editor's own text writes that text. The key is spelled out rather than read from the
    # constant, since it is a wire name a client sends and renaming the constant has to fail here. A body with a
    # different spelling would lose its comments and save that key into the document.
    check("the reserved key's wire name is exactly __yaml_text__",
          apimain._RAW_YAML_KEY == "__yaml_text__")
    tags_path.write_text("tags: []\n")
    await apimain.update_yaml_config(
        "tags", {**document, "__yaml_text__": commented}, admin)
    on_disk = tags_path.read_text()
    check("the submitted text is written verbatim, comments and all",
          on_disk == commented)
    check("the reserved text key never reaches the file",
          "__yaml_text__" not in on_disk)
    check("the document itself is unchanged by the round trip",
          yaml.safe_load(on_disk) == document)

    # A form editor sends structure only. The comments then come from the file being replaced, which is the version of
    # them the author last saw.
    edited = yaml.safe_load(commented)
    edited["tags"][1]["label"] = "On loan"
    await apimain.update_yaml_config("tags", edited, admin)
    on_disk = tags_path.read_text()
    check("a structured save with no text still keeps the header comment",
          "# The advisory tag registry." in on_disk)
    check("it keeps a comment written against one entry",
          "# Anything on a bench rather than in a classroom." in on_disk)
    check("and it really did save the edit", yaml.safe_load(on_disk) == edited)

    # Text that disagrees with the validated structure is not written: the structure is what was validated, so the
    # structure is what reaches disk.
    honest = {"tags": [{"name": "lab", "label": "Lab"}]}
    await apimain.update_yaml_config(
        "tags", {**honest, "__yaml_text__": "tags:\n  - name: smuggled\n"}, admin)
    check("a text that does not match the document is ignored",
          yaml.safe_load(tags_path.read_text()) == honest)

    # Disagreeing about a value's type counts as disagreeing. Python reads True as 1 and 1 as 1.0, and readers of these
    # documents depend on the difference: a FileVault Enable is rewritten to Apple's "On" string only while it is still
    # a bool, and the validator's warning about it turns on the same check.
    probe = tdir / "probe.yaml"
    for label, data, text in (
            ("true as 1", {"enabled": True}, "# c\nenabled: 1\n"),
            ("false as 0", {"gate": False}, "# c\ngate: 0\n"),
            ("1 as 1.0", {"n": 1}, "# c\nn: 1.0\n"),
            ("a string as a number", {"s": "1"}, "# c\ns: 1\n"),
    ):
        probe.write_text("unrelated: true\n")
        written = apimain._config_document_text(probe, data, text)
        check(f"a text writing {label} is not accepted as the document",
              written != text)
        check(f"and what is written still parses to the validated types ({label})",
              written is None or apimain._same_document(yaml.safe_load(written), data))

    for label, data, text in (
            ("a bool", {"enabled": True}, "# c\nenabled: true\n"),
            ("a number", {"n": 1}, "# c\nn: 1\n"),
            ("a quoted string", {"s": "1"}, "# c\ns: '1'\n"),
            ("keys in another order", {"b": 2, "a": 1}, "# c\na: 1\nb: 2\n"),
    ):
        probe.write_text("unrelated: true\n")
        check(f"an honest text carrying {label} is still written verbatim",
              apimain._config_document_text(probe, data, text) == text)

    # Duplicate keys: pyyaml keeps the last one, so the text parses equal to the structure, but the browser's YAML 1.2
    # parser raises on it and the console could never save the file again.
    probe.write_text("unrelated: true\n")
    duplicated = "tags: [{name: evil}]\ntags: []\n"
    check("a text with a duplicated key is never written",
          apimain._config_document_text(probe, {"tags": []}, duplicated) != duplicated)

    # A verbatim write is the one path that puts unbounded bytes on disk, and every later save copies the whole file
    # into history.
    huge = "# padding\n" * 60000 + yaml.safe_dump(honest)
    check("the oversized text is larger than the cap it has to trip",
          len(huge) > apimain._RAW_YAML_MAX_CHARS)
    await apimain.update_yaml_config("tags", {**honest, "__yaml_text__": huge}, admin)
    saved = tags_path.read_text()
    check("an oversized text is dropped rather than written",
          len(saved) < apimain._RAW_YAML_MAX_CHARS)
    check("and the document still saves without it",
          yaml.safe_load(saved) == honest)

    # A restore brings the comments back: history keeps the raw file, and the restore writes it out rather than
    # reparsing it.
    versions = (await apimain.list_config_history("tags", admin))["versions"]
    commented_version = None
    for version in versions:
        stored = (await apimain.get_config_history_version("tags", version["id"], admin))
        if "# The advisory tag registry." in (stored["content"] or ""):
            commented_version = version
            break
    check("a snapshot of the commented document exists to restore from",
          commented_version is not None)
    if commented_version:
        tags_path.write_text("tags: []\n")
        await apimain.restore_config_history_version("tags", commented_version["id"], admin)
        restored = tags_path.read_text()
        check("restoring an old version restores its comments too",
              "# The advisory tag registry." in restored
              and "# Anything on a bench rather than in a classroom." in restored)
        stored = (await apimain.get_config_history_version(
            "tags", commented_version["id"], admin))["content"]
        check("the restored document is the one that was snapshotted",
              yaml.safe_load(restored) == yaml.safe_load(stored))

    # The helper's own contract, at two edges the endpoint cannot reach.
    probe.write_text("a: ***redacted***\n")
    sentinel_text = apimain._config_document_text(
        probe, {"a": "the real secret"}, "a: ***redacted***\n")
    check("a redacted sentinel is never written in place of the real value",
          sentinel_text is None
          or ("***redacted***" not in sentinel_text
              and yaml.safe_load(sentinel_text) == {"a": "the real secret"}))
    unparseable = apimain._config_document_text(probe, {"a": 1}, "a: [unclosed\n")
    check("a source that cannot be parsed is skipped, not written",
          unparseable is None or yaml.safe_load(unparseable) == {"a": 1})

    # Without ruamel.yaml the save still works; it just writes a plain dump.
    saved_round_trip = apimain.RoundTripYAML
    try:
        apimain.RoundTripYAML = None
        edited["tags"][0]["label"] = "Bench"
        await apimain.update_yaml_config("tags", edited, admin)
        check("a save without round-trip YAML still writes the document",
              yaml.safe_load(tags_path.read_text()) == edited)
    finally:
        apimain.RoundTripYAML = saved_round_trip

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run

run(main)
