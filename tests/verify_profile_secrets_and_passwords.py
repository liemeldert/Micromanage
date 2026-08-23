"""Profile secret redaction on the config API, and the password rules.

Run: PYTHONPATH=. python tests/verify_profile_secrets_and_passwords.py

profiles.yaml holds Wi-Fi PSKs, 802.1X passwords and SCEP challenges, and every member can read GET
/api/v1/config/{type}. Members get those values redacted in the structured view, the raw view and history snapshots,
while admins see the file as written. A save that echoes the sentinel back restores the value on disk, matched by
profile id and then by payload, so a reordered payload cannot inherit another payload's secret.

Passwords: a length floor on every path that sets one (API create and update, the CLI, and a warning at bootstrap), and
POST /api/v1/auth/password so a member can change their own without an admin. That route proves the current password
first, is throttled like sign-in, and returns a fresh token because the change ends every session minted before it.
"""
import os
import tempfile
from pathlib import Path

import yaml
from fastapi import HTTPException
from tortoise import Tortoise

_BASE = Path(tempfile.mkdtemp())
os.environ["YAML_CONFIG_PATH"] = str(_BASE)
# The password-change route hands back a session token, which needs a signing key.
os.environ.setdefault("JWT_SECRET", "verify-profile-secrets-suite-key-long-enough-for-hs256")

import controller.api.main as apimain  # noqa: E402
from controller.auth import passwords as pw  # noqa: E402
from controller.auth.dependencies import Principal  # noqa: E402
from controller.auth.tokens import decode_session_token  # noqa: E402
from controller.models.tenant import AuditLog, Tenant, User  # noqa: E402

PASS, FAIL = [], []
TENANT_ID = "t1"
REDACTED = "***redacted***"


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


async def status_of(coro):
    try:
        await coro
        return 200
    except HTTPException as exc:
        return exc.status_code


PROFILES = {
    "profiles": [
        {
            "id": "wifi",
            "name": "Campus Wi-Fi",
            "type": "configuration",
            "groups": ["all"],
            "payloads": [
                {
                    "PayloadType": "com.apple.wifi.managed",
                    "PayloadDisplayName": "Campus",
                    "SSID_STR": "CampusNet",
                    "Password": "hunter2hunter2",
                    "EAPClientConfiguration": {"UserName": "svc", "UserPassword": "eap-secret",
                                               "OneTimeUserPassword": False},
                },
                {
                    "PayloadType": "com.apple.security.scep",
                    "PayloadDisplayName": "SCEP",
                    "PayloadContent": {"URL": "https://ca/scep", "Challenge": "scep-secret",
                                       "Key Type": "RSA"},
                },
            ],
        },
        {
            "id": "passcode",
            "name": "Passcode",
            "type": "configuration",
            "groups": ["all"],
            "payload": {"PayloadType": "com.apple.mobiledevice.passwordpolicy",
                        "forcePIN": True, "minLength": 6},
        },
    ]
}


def seed_config_dir():
    tdir = _BASE / "tenants" / TENANT_ID
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "config.yaml").write_text(yaml.safe_dump({
        "tenant": {"id": TENANT_ID, "name": "Tenant One", "allowed_users": ["admin@t1"]}
    }))
    (tdir / "groups.yaml").write_text(yaml.safe_dump({"groups": [
        {"name": "all", "conditions": [{"type": "device_model", "operator": "regex",
                                        "value": ".*"}]}]}))
    (tdir / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
    (tdir / "profiles.yaml").write_text(
        "# Authored by hand\n" + yaml.safe_dump(PROFILES, sort_keys=False))
    return tdir


async def main():
    tdir = seed_config_dir()
    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    tenant = await Tenant.create(id=TENANT_ID, name="Tenant One")
    admin_user = await User.create(
        tenant=tenant, email="admin@t1", role="admin",
        password_hash=pw.hash_password("correct horse battery staple"))
    member_user = await User.create(
        tenant=tenant, email="member@t1", role="member",
        password_hash=pw.hash_password("member-password-12345"))
    admin = Principal(tenant=tenant, user=admin_user, email="admin@t1", role="admin")
    member = Principal(tenant=tenant, user=member_user, email="member@t1", role="member")
    apimain._spawn_tenant_reconcile = lambda tenant_id: None

    print("1) members read profiles.yaml with the secrets taken out")
    doc = await apimain.get_yaml_config("profiles", False, member)
    wifi = doc["profiles"][0]["payloads"][0]
    scep = doc["profiles"][0]["payloads"][1]
    check("the Wi-Fi password is redacted", wifi["Password"] == REDACTED)
    check("the nested EAP password is redacted",
          wifi["EAPClientConfiguration"]["UserPassword"] == REDACTED)
    check("the SCEP challenge inside PayloadContent is redacted",
          scep["PayloadContent"]["Challenge"] == REDACTED)
    check("the SSID, the EAP user name and the SCEP URL are still there",
          wifi["SSID_STR"] == "CampusNet"
          and wifi["EAPClientConfiguration"]["UserName"] == "svc"
          and scep["PayloadContent"]["URL"] == "https://ca/scep")
    check("a boolean under a secret-named key survives unredacted beside "
          "a redacted string sibling",
          wifi["EAPClientConfiguration"]["OneTimeUserPassword"] is False
          and wifi["EAPClientConfiguration"]["UserPassword"] == REDACTED)

    # The type rules directly: booleans pass through, strings and numbers do not, and hits records only what was
    # replaced.
    from controller.services.profile_manager import _redact_value
    redact_hits = []
    direct = _redact_value(
        {"Password": "s3cretvalue", "OneTimeUserPassword": True, "PIN": 123456},
        "", redact_hits)
    check("direct: strings and numbers redact, booleans pass through",
          direct["Password"] == REDACTED and direct["PIN"] == REDACTED
          and direct["OneTimeUserPassword"] is True)
    check("hits records only the replaced paths",
          sorted(redact_hits) == ["PIN", "Password"])
    check("a passcode policy with nothing secret in it is untouched",
          doc["profiles"][1]["payload"] == PROFILES["profiles"][1]["payload"])
    raw = await apimain.get_yaml_config("profiles", True, member)
    check("the raw view carries no secret either",
          "hunter2" not in raw.body.decode() and "scep-secret" not in raw.body.decode())

    print("2) admins read it as authored")
    doc = await apimain.get_yaml_config("profiles", False, admin)
    check("the Wi-Fi password is present for an admin",
          doc["profiles"][0]["payloads"][0]["Password"] == "hunter2hunter2")
    raw = await apimain.get_yaml_config("profiles", True, admin)
    check("and the raw view is the file itself, comment included",
          raw.body.decode().startswith("# Authored by hand"))

    print("3) a save that echoes the sentinel keeps the value on disk")
    edited = yaml.safe_load(yaml.safe_dump(doc))
    edited["profiles"][0]["payloads"][0]["Password"] = REDACTED
    edited["profiles"][0]["payloads"][0]["EAPClientConfiguration"]["UserPassword"] = REDACTED
    edited["profiles"][0]["payloads"][1]["PayloadContent"]["Challenge"] = REDACTED
    edited["profiles"][0]["payloads"][0]["SSID_STR"] = "CampusNet-5G"
    try:
        await apimain.update_yaml_config("profiles", edited, admin)
        code = 200
    except HTTPException as exc:
        code = exc.status_code
        print("   save refused:", exc.detail)
    check("the save is accepted", code == 200)
    on_disk = yaml.safe_load((tdir / "profiles.yaml").read_text())
    p0 = on_disk["profiles"][0]["payloads"]
    check("the Wi-Fi password on disk is the real one", p0[0]["Password"] == "hunter2hunter2")
    check("so is the nested EAP password",
          p0[0]["EAPClientConfiguration"]["UserPassword"] == "eap-secret")
    check("and the SCEP challenge", p0[1]["PayloadContent"]["Challenge"] == "scep-secret")
    check("the edit that was actually made landed", p0[0]["SSID_STR"] == "CampusNet-5G")
    check("no sentinel reached the file", REDACTED not in (tdir / "profiles.yaml").read_text())

    print("4) reordered payloads do not swap secrets")
    swapped = yaml.safe_load(yaml.safe_dump(on_disk))
    swapped["profiles"][0]["payloads"].reverse()
    swapped["profiles"][0]["payloads"][0]["PayloadContent"]["Challenge"] = REDACTED  # scep, now first
    swapped["profiles"][0]["payloads"][1]["Password"] = REDACTED  # wifi, now second
    apimain._restore_profile_secrets(TENANT_ID, swapped)
    check("the SCEP payload got its own challenge back",
          swapped["profiles"][0]["payloads"][0]["PayloadContent"]["Challenge"] == "scep-secret")
    check("the Wi-Fi payload got its own password back",
          swapped["profiles"][0]["payloads"][1]["Password"] == "hunter2hunter2")

    print("5) a sentinel with nothing behind it is dropped, not written")
    fresh = {"profiles": [{"id": "brand-new", "name": "New", "type": "configuration",
                           "groups": ["all"],
                           "payloads": [{"PayloadType": "com.apple.wifi.managed",
                                         "SSID_STR": "x", "Password": REDACTED}]}]}
    apimain._restore_profile_secrets(TENANT_ID, fresh)
    check("the key is gone rather than holding the sentinel",
          "Password" not in fresh["profiles"][0]["payloads"][0])

    print("6) history snapshots follow the same rule")
    versions = await apimain.list_config_history("profiles", admin)
    vid = versions["versions"][0]["id"]
    as_member = await apimain.get_config_history_version("profiles", vid, member)
    as_admin = await apimain.get_config_history_version("profiles", vid, admin)
    check("a member sees the snapshot redacted", "hunter2" not in as_member["content"]
          and REDACTED in as_member["content"])
    check("an admin sees the snapshot as saved", "hunter2hunter2" in as_admin["content"])

    print("7) the password policy")
    check("a short password is refused", pw.password_policy_error("short") is not None)
    check("an empty one is refused", pw.password_policy_error("") is not None)
    check("a known placeholder is refused even when long enough",
          pw.password_policy_error("change-me-now") is not None)
    check("twelve characters pass", pw.password_policy_error("abcdefghijkl") is None)
    check("a passphrase passes", pw.password_policy_error("correct horse battery staple") is None)

    print("8) the API applies it")
    code = await status_of(apimain.create_user(
        apimain.UserCreate(email="new@t1", password="short", role="member"), admin))
    check("create_user refuses a short password (400)", code == 400)
    check("and made no user", await User.get_or_none(tenant=tenant, email="new@t1") is None)
    code = await status_of(apimain.create_user(
        apimain.UserCreate(email="new@t1", password="a perfectly fine password", role="member"), admin))
    check("create_user accepts one that meets it", code == 200)
    new_user = await User.get_or_none(tenant=tenant, email="new@t1")
    code = await status_of(apimain.update_user(
        str(new_user.id), apimain.UserUpdate(password="short"), admin))
    check("update_user refuses a short password (400)", code == 400)

    print("9) POST /api/v1/auth/password: a member changes their own")
    code = await status_of(apimain.change_own_password(
        apimain.PasswordChangeRequest(current_password="wrong-password-123",
                                      new_password="a brand new passphrase"), member))
    check("the wrong current password is refused (401)", code == 401)
    code = await status_of(apimain.change_own_password(
        apimain.PasswordChangeRequest(current_password="member-password-12345",
                                      new_password="short"), member))
    check("a new password below the floor is refused (400)", code == 400)
    code = await status_of(apimain.change_own_password(
        apimain.PasswordChangeRequest(current_password="member-password-12345",
                                      new_password="member-password-12345"), member))
    check("the same password again is refused (400)", code == 400)
    before = await User.get(id=member_user.id)
    resp = await apimain.change_own_password(
        apimain.PasswordChangeRequest(current_password="member-password-12345",
                                      new_password="a brand new passphrase"), member)
    after = await User.get(id=member_user.id)
    check("the hash changed", after.password_hash != before.password_hash)
    check("the new password verifies",
          pw.verify_password("a brand new passphrase", after.password_hash))
    check("password_changed_at was stamped", after.password_changed_at is not None)
    claims = decode_session_token(resp.access_token)
    check("a fresh token for the same user comes back",
          claims.get("sub") == str(member_user.id) or claims.get("email") == "member@t1")
    check("the change is in the audit log",
          await AuditLog.filter(action="user.password_change", actor_email="member@t1").exists())

    print("10) an external-auth tenant has no local password to change")
    ext = await Tenant.create(id="ext", name="Ext", auth_config={"provider": "oidc"})
    ext_user = await User.create(tenant=ext, email="u@ext", role="member", external_id="sub")
    ext_p = Principal(tenant=ext, user=ext_user, email="u@ext", role="member")
    code = await status_of(apimain.change_own_password(
        apimain.PasswordChangeRequest(current_password="x", new_password="y" * 20), ext_p))
    check("the route answers 400 for an oidc tenant", code == 400)

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run  # noqa: E402

run(main)
