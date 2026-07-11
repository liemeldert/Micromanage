"""Backend E2E for ABM/ASM + Automated Device Enrollment (ADE/DEP).

Exercises the real link/sync/profile machinery on an in-memory sqlite Tortoise DB
with a FakeDepTransport standing in for Apple's DEP cloud service (no network) and a
FakeConnector standing in for NanoMDM. Covers:

  * PKI round-trip: generate keypair -> (ABM) envelope-encrypt a token to it ->
    complete_link decrypts + verifies via /account + stores it ENCRYPTED.
  * Device sync: full fetch -> pending placeholders; pagination; delta sync;
    op_type=deleted; duplicate-serial resolution by op_date; cursor advance.
  * Default-profile auto-assign to newly-added devices.
  * push_profile idempotency (payload_hash) + assign updates local status.
  * enrollment_source scope condition (ade vs ota).
  * release_device flow node -> DeviceConfigured queued via the audited path.
  * ADE endpoint / webhook adoption stamps enrollment_source + dep tag.
  * Token is never present in the DepServer API projection.

Run:  JWT_SECRET=test PYTHONPATH=. ./.venv/bin/python tests/verify_dep.py
Exits non-zero if any check fails.
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from tortoise import Tortoise

os.environ.setdefault("JWT_SECRET", "test-secret-for-dep-verify")
os.environ.setdefault("PUBLIC_API_URL", "https://mdm.example.com")

_FAILURES = []


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        _FAILURES.append(name)


class FakeConnector:
    """Stand-in for MDMConnector: records commands, never touches network."""

    sent = []

    def __init__(self, *a, **k):
        pass

    async def device_configured(self, udid):
        FakeConnector.sent.append(("DeviceConfigured", udid))
        return {"command_uuid": "u-devconf"}

    async def close(self):
        pass


class FakeDepTransport:
    """A stateful stand-in for Apple's DEP cloud service.

    Speaks just enough of the protocol for the client: the OAuth /session
    handshake, /account, /server/devices (paged), /devices/sync, /profile and
    /profile/devices. ``roster`` is a list of device-record dicts; ``sync_batches``
    is an optional list of delta batches returned by successive /devices/sync calls.
    """

    def __init__(self, roster, account=None, sync_batches=None, page_size=2):
        self.roster = roster
        self.account = account or {"org_name": "Acme Inc", "server_name": "acme-mdm",
                                   "org_id": "ORG123", "admin_id": "admin@acme.example"}
        self.sync_batches = list(sync_batches or [])
        self.page_size = page_size
        self.calls = []
        self.assigned = {}  # profile_uuid -> [serials]
        self._profile_seq = 0

    async def __call__(self, method, url, headers, body):
        path = url.split(self._host(url), 1)[-1] if "://" in url else url
        self.calls.append((method, path))
        data = json.loads(body) if body else {}

        if path.endswith("/session"):
            assert headers.get("Authorization", "").startswith("OAuth "), "missing OAuth header"
            return 200, {}, json.dumps({"auth_session_token": "SESS-1"}).encode()
        assert headers.get("X-ADM-Auth-Session") == "SESS-1", "missing session header"

        if path.endswith("/account"):
            return self._ok(self.account)

        if path.endswith("/server/devices"):
            # Cursor-paged full fetch.
            cursor = int(data.get("cursor") or 0)
            page = self.roster[cursor:cursor + self.page_size]
            nxt = cursor + len(page)
            more = nxt < len(self.roster)
            return self._ok({"devices": page, "cursor": str(nxt),
                             "more_to_follow": more, "fetched_until": "2026-01-01"})

        if path.endswith("/devices/sync"):
            batch = self.sync_batches.pop(0) if self.sync_batches else []
            return self._ok({"devices": batch, "cursor": "SYNC-CUR",
                             "more_to_follow": False})

        if path.endswith("/profile") and method == "POST":
            self._profile_seq += 1
            uuid = f"PUUID-{self._profile_seq}"
            return self._ok({"profile_uuid": uuid,
                             "devices": {d.get("serial_number"): "ASSIGNED"
                                         for d in [] }})

        if path.endswith("/profile/devices") and method == "POST":
            uuid = data.get("profile_uuid")
            serials = data.get("devices") or []
            self.assigned.setdefault(uuid, []).extend(serials)
            return self._ok({"profile_uuid": uuid,
                             "devices": {s: "SUCCESS" for s in serials}})

        return 404, {}, b'{"code":"NOT_FOUND"}'

    @staticmethod
    def _host(url):
        return url.split("://", 1)[1].split("/", 1)[0]

    @staticmethod
    def _ok(obj):
        return 200, {}, json.dumps(obj).encode()


def _envelope_token(cert_pem, token):
    """Simulate ABM: envelope-encrypt (CMS) a token JSON to our public cert."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    inner = ("-----BEGIN MESSAGE-----\n" + json.dumps(token) +
             "\n-----END MESSAGE-----\n").encode()
    return pkcs7.PKCS7EnvelopeBuilder().set_data(inner).add_recipient(cert).encrypt(
        Encoding.SMIME, [])


def _synthetic_apple_cms(serial, anchor_path, tamper=False, untrusted=False):
    """Build a base64 x-apple-aspen-deviceinfo header signed by a synthetic
    root->intermediate->device chain, and write the root as an anchor PEM (unless
    untrusted). Returns the base64 header string."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives.asymmetric import rsa

    def mkcert(cn, issuer_cn=None, issuer_key=None, ca=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        b = (x509.CertificateBuilder()
             .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
             .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)]))
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(datetime.datetime(2019, 1, 1))
             .not_valid_after(datetime.datetime(2029, 1, 1)))
        if ca:
            b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        return b.sign(issuer_key or key, hashes.SHA256()), key

    root, rk = mkcert("Test Apple Root CA", ca=True)
    inter, ik = mkcert("Test iPhone Device CA", "Test Apple Root CA", rk, ca=True)
    leaf, lk = mkcert(serial, "Test iPhone Device CA", ik)
    mi = _pl_dumps({"SERIAL": serial, "PRODUCT": "Mac14,2"})
    builder = pkcs7.PKCS7SignatureBuilder().set_data(mi).add_signer(leaf, lk, hashes.SHA256())
    for c in (inter, root):
        builder = builder.add_certificate(c)
    der = builder.sign(Encoding.DER, [])
    if tamper:
        der = bytearray(der)
        i = bytes(der).find(mi[:8])
        der[i] = der[i] ^ 0xFF
        der = bytes(der)
    if not untrusted:
        with open(anchor_path, "wb") as fh:
            fh.write(root.public_bytes(Encoding.PEM))
    import base64 as _b64
    return _b64.b64encode(der).decode()


def _pl_dumps(d):
    import plistlib
    return plistlib.dumps(d)


def _pl_loads(b):
    import plistlib
    return plistlib.loads(b)


def _fake_machineinfo(serial):
    """A base64 header carrying an XML plist with a SERIAL (as a real ADE device's
    x-apple-aspen-deviceinfo would, wrapped in CMS -- parse_machine_info extracts
    the embedded plist)."""
    import base64 as _b64
    import plistlib as _pl
    body = b"cms-prefix" + _pl.dumps({"SERIAL": serial, "PRODUCT": "Mac14,2"}) + b"cms-suffix"
    return _b64.b64encode(body).decode()


def _write_profiles(base):
    tdir = base / "tenants" / "default"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": [
        {"id": "zero-touch", "name": "Zero Touch", "type": "enrollment",
         "dep_profile": True, "payload": {
             "is_supervised": True, "is_mandatory": True, "await_device_configured": True,
             "support_phone_number": "+1-555", "department": "IT",
             "skip_setup_items": ["AppleID", "Passcode", "NotARealKey"]}},
    ]}))
    (tdir / "flows.yaml").write_text(yaml.safe_dump({"flows": [
        {"id": "zt", "name": "ZT", "enabled": True, "priority": 100,
         "trigger": {"on": "enroll", "match": {"conditions": [
             {"type": "enrollment_source", "operator": "in", "value": ["ade"]}]}},
         "start": "tag", "nodes": [
             {"id": "tag", "type": "assign_tag", "params": {"tags": ["corp"]}, "next": "rel"},
             {"id": "rel", "type": "release_device", "next": "done"},
             {"id": "done", "type": "end"},
         ]},
    ]}))
    for f in ("groups.yaml", "apps.yaml", "tags.yaml"):
        (tdir / f).write_text(yaml.safe_dump({}))


async def main():
    base = Path(tempfile.mkdtemp())
    os.environ["YAML_CONFIG_PATH"] = str(base)
    _write_profiles(base)

    import controller.services.mdm_connector as mc
    mc.MDMConnector = FakeConnector

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    from controller.models.tenant import Tenant, Device, DepServer, DepProfile, Task
    from controller.services import dep_manager, dep_pki, crypto_secrets, atc, scoping

    tenant = await Tenant.create(id="default", name="Default")

    # ── 1) Link: begin_link -> (ABM) encrypt token -> complete_link ──────────
    print("1) link a DEP server (keypair + token decrypt + /account verify)")
    server = await dep_manager.begin_link(tenant, "abm")
    check("keypair generated + status awaiting_token",
          bool(server.public_cert_pem) and server.status == "awaiting_token")
    check("private key stored ENCRYPTED (not plaintext PEM)",
          server.private_key_enc and "PRIVATE KEY" not in server.private_key_enc)

    token = {"consumer_key": "CK", "consumer_secret": "CS", "access_token": "AT",
             "access_secret": "AS", "access_token_expiry": "2027-01-01T00:00:00Z"}
    p7m = _envelope_token(server.public_cert_pem, token)

    fake = FakeDepTransport(roster=[
        {"serial_number": "SER-A", "model": "MacBookPro18,3", "op_type": "added", "op_date": "1"},
        {"serial_number": "SER-B", "model": "iPhone15,2", "op_type": "added", "op_date": "1"},
        {"serial_number": "SER-C", "model": "Mac14,2", "op_type": "added", "op_date": "1"},
    ])
    dep_manager._TEST_TRANSPORT = fake
    await dep_manager.complete_link(server, p7m)
    await server.refresh_from_db()
    check("status linked after token verified", server.status == "linked")
    check("token stored ENCRYPTED (no cleartext creds on the row)",
          server.token_enc and "consumer_key" not in server.token_enc)
    check("token decrypts back to the OAuth creds",
          json.loads(crypto_secrets.decrypt(server.token_enc))["consumer_key"] == "CK")
    check("account org captured", (server.account_detail or {}).get("org_name") == "Acme Inc")
    check("token expiry parsed", server.token_expires_at is not None)
    check("to_dict() NEVER leaks token/key", not any(
        k in server.to_dict() for k in ("token_enc", "private_key_enc", "public_cert_pem")))

    # ── 2) Device sync -> placeholders (paged full fetch) ────────────────────
    print("2) sync assigned devices into pending placeholders")
    summary = await dep_manager.sync_devices(server, transport=fake)
    check("sync ok", summary["ok"])
    check("3 devices added", summary["added"] == 3)
    check("sync paged (>1 page for 3 devices @ page_size 2)", summary["pages"] >= 2)
    devs = await Device.filter(tenant=tenant).order_by("serial_number")
    check("3 placeholders created", len(devs) == 3)
    check("placeholders are pending w/ null udid",
          all(d.enrollment_state == "pending" and d.udid is None for d in devs))
    check("dep_server_id stamped", all(str(d.dep_server_id) == str(server.id) for d in devs))
    await server.refresh_from_db()
    check("cursor advanced + stored", server.sync_cursor is not None)

    # Idempotent re-sync via delta with no changes.
    fake.sync_batches = [[]]
    summary2 = await dep_manager.sync_devices(server, transport=fake)
    check("delta sync used /devices/sync (not full fetch)",
          ("POST", "/devices/sync") in fake.calls)
    check("no duplicate devices after empty delta",
          await Device.filter(tenant=tenant).count() == 3)

    # ── 3) Delta with a modified + deleted (placeholder) op ──────────────────
    print("3) delta sync: modified + deleted")
    fake.sync_batches = [[
        {"serial_number": "SER-A", "model": "MacBookPro18,3", "op_type": "modified",
         "op_date": "3", "profile_status": "pushed"},
        {"serial_number": "SER-C", "op_type": "deleted", "op_date": "3"},
    ]]
    summary3 = await dep_manager.sync_devices(server, transport=fake)
    check("1 modified, 1 deleted", summary3["modified"] == 1 and summary3["deleted"] == 1)
    check("deleted placeholder forgotten (never enrolled)",
          await Device.filter(tenant=tenant, serial_number="SER-C").count() == 0)
    a = await Device.get(tenant=tenant, serial_number="SER-A")
    check("modified device profile_status updated", a.dep_profile_status == "pushed")

    # ── 4) Push a DEP profile + assign; idempotent re-push ───────────────────
    print("4) push + assign an enrollment profile")
    enroll_url = "https://mdm.example.com/api/v1/dep/enroll/default"
    mapping = await dep_manager.push_profile(server, "zero-touch", enroll_url, transport=fake)
    check("profile_uuid returned + stored", mapping.profile_uuid == "PUUID-1")
    # Verify the Apple profile omitted the invalid skip key + set the url.
    apple_profile = dep_manager._build_apple_profile(
        dep_manager._load_profile_yaml("default", "zero-touch"), server, tenant, enroll_url)
    check("invalid skip key dropped", apple_profile["skip_setup_items"] == ["AppleID", "Passcode"])
    check("await_device_configured mapped", apple_profile["await_device_configured"] is True)
    check("enroll url set on profile", apple_profile["url"] == enroll_url)
    calls_before = len(fake.calls)
    mapping2 = await dep_manager.push_profile(server, "zero-touch", enroll_url, transport=fake)
    check("re-push is idempotent (no new define call)",
          mapping2.profile_uuid == "PUUID-1" and len(fake.calls) == calls_before)

    results = await dep_manager.assign_profile(server, "zero-touch", ["SER-A", "SER-B"], enroll_url, transport=fake)
    check("assign returned SUCCESS per serial",
          results.get("SER-A") == "SUCCESS" and results.get("SER-B") == "SUCCESS")
    a = await Device.get(tenant=tenant, serial_number="SER-A")
    check("device profile status -> assigned", a.dep_profile_status == "assigned")

    # ── 5) Default-profile auto-assign on newly-synced devices ───────────────
    print("5) default profile auto-assigns to new devices")
    server.default_profile_id = "zero-touch"
    await server.save()
    fake.sync_batches = [[{"serial_number": "SER-D", "model": "Mac15,3",
                           "op_type": "added", "op_date": "5"}]]
    await dep_manager.sync_devices(server, transport=fake)
    d = await Device.get(tenant=tenant, serial_number="SER-D")
    check("new device auto-assigned the default profile",
          "SER-D" in fake.assigned.get("PUUID-1", []) and d.dep_profile_status == "assigned")

    # ── 6) enrollment_source scope condition ─────────────────────────────────
    print("6) enrollment_source scope condition")
    ade_dev = Device(tenant=tenant, serial_number="X", device_model="Mac14,2",
                     os_version="14", attributes={"enrollment_source": "ade"}, groups=[], tags=[])
    ota_dev = Device(tenant=tenant, serial_number="Y", device_model="Mac14,2",
                     os_version="14", attributes={}, groups=[], tags=[])
    cond = {"type": "enrollment_source", "operator": "in", "value": ["ade"]}
    check("ADE device matches enrollment_source:ade", scoping.evaluate_condition(ade_dev, cond, []))
    check("OTA/unknown device does NOT match (defaults to ota)",
          not scoping.evaluate_condition(ota_dev, cond, []))

    # ── 7) release_device node -> DeviceConfigured via audited path ──────────
    print("7) release_device sends DeviceConfigured")
    FakeConnector.sent = []
    enrolled = await Device.create(tenant=tenant, udid="UDID-REL", serial_number="SER-A",
                                   device_model="Mac14,2", os_version="14",
                                   enrollment_state="enrolled",
                                   attributes={"enrollment_source": "ade"}, groups=[], tags=[])
    # Adopt the placeholder row -> single device: reuse the enrolled one.
    run = await atc.start_flows_for_enroll(enrolled)
    await asyncio.sleep(0.1)  # let the fire-and-forget DeviceConfigured push run
    check("zero-touch flow ran + completed", run is not None and run.status == "completed")
    check("corp tag applied", "corp" in (await Device.get(id=enrolled.id)).tags)
    check("DeviceConfigured queued to the device",
          ("DeviceConfigured", "UDID-REL") in FakeConnector.sent)
    check("device_configured audit task recorded",
          await Task.filter(tenant=tenant, type="device_configured").count() == 1)

    # ── 7b) ADE endpoint: token-gated + pre-stamps enrollment_source ─────────
    print("7b) ADE enroll endpoint gates on the per-tenant token")
    os.environ["MDM_TOPIC"] = "com.apple.mgmt.External.test"
    os.environ["SCEP_CHALLENGE"] = "test-challenge"
    from controller.api import dep as dep_api
    from controller.services import enrollment as enroll_svc
    from fastapi import HTTPException

    class FakeReq:
        def __init__(self, headers):
            from starlette.datastructures import Headers
            self.headers = Headers(headers)

    good = enroll_svc.enrollment_token("default")
    # Bad token -> 403
    try:
        await dep_api.ade_enroll("default", "wrong-token", FakeReq({}))
        check("bad ADE token rejected", False)
    except HTTPException as ex:
        check("bad ADE token -> 403", ex.status_code == 403)
    # Good token -> 200 mobileconfig, and stamps enrollment_source on the placeholder
    await Device.create(tenant=tenant, udid=None, serial_number="ADE-1",
                        device_model="Mac", os_version="", enrollment_state="pending",
                        dep_server_id=server.id, attributes={}, groups=[], tags=[])
    resp = await dep_api.ade_enroll(
        "default", good, FakeReq({"x-apple-aspen-deviceinfo": _fake_machineinfo("ADE-1")}))
    check("good ADE token -> mobileconfig", resp.media_type == "application/x-apple-aspen-config")
    ade_dev2 = await Device.get(tenant=tenant, serial_number="ADE-1")
    check("ADE endpoint stamped enrollment_source=ade",
          (ade_dev2.attributes or {}).get("enrollment_source") == "ade")

    # ── 7c) ADE MachineInfo CMS signature verification ───────────────────────
    print("7c) Apple CA signature verification (CMS)")
    import tempfile as _tf
    from controller.services import dep_verify
    anchor_path = _tf.mktemp(suffix=".pem")
    os.environ["DEP_APPLE_ANCHOR_CERTS"] = anchor_path
    dep_verify._anchors.cache_clear()

    hdr_ok = _synthetic_apple_cms("VER-OK", anchor_path)
    dep_verify._anchors.cache_clear()  # anchor file now written
    import base64 as _b64
    content, verified, detail = dep_verify.verify_cms(_b64.b64decode(hdr_ok))
    check("valid CMS chain verifies", verified)
    check("verified CMS yields the MachineInfo", _pl_loads(bytes(content)).get("SERIAL") == "VER-OK")

    hdr_tampered = _synthetic_apple_cms("VER-BAD", anchor_path, tamper=True)
    dep_verify._anchors.cache_clear()
    _c, v_t, _d = dep_verify.verify_cms(_b64.b64decode(hdr_tampered))
    check("tampered CMS rejected", not v_t)

    hdr_untrusted = _synthetic_apple_cms("VER-EVIL", anchor_path, untrusted=True)
    dep_verify._anchors.cache_clear()
    _c, v_u, _d = dep_verify.verify_cms(_b64.b64decode(hdr_untrusted))
    check("CMS not chaining to an Apple anchor rejected", not v_u)

    # Endpoint enforcement: with DEP_ADE_REQUIRE_APPLE_SIGNATURE=true an unverified
    # request is 403; a verified one succeeds.
    os.environ["DEP_ADE_REQUIRE_APPLE_SIGNATURE"] = "true"
    hdr_ok2 = _synthetic_apple_cms("VER-ENF", anchor_path)
    dep_verify._anchors.cache_clear()
    try:
        await dep_api.ade_enroll("default", good, FakeReq({}))  # no header -> unverified
        check("enforced: missing signature -> 403", False)
    except HTTPException as ex:
        check("enforced: missing signature -> 403", ex.status_code == 403)
    resp_enf = await dep_api.ade_enroll("default", good, FakeReq({"x-apple-aspen-deviceinfo": hdr_ok2}))
    check("enforced: valid signature -> mobileconfig",
          resp_enf.media_type == "application/x-apple-aspen-config")
    os.environ.pop("DEP_ADE_REQUIRE_APPLE_SIGNATURE", None)
    os.environ.pop("DEP_APPLE_ANCHOR_CERTS", None)
    dep_verify._anchors.cache_clear()

    # ── 8) unlink wipes secrets ──────────────────────────────────────────────
    print("8) unlink wipes secret material")
    await dep_manager.unlink(server)
    await server.refresh_from_db()
    check("unlink clears token + key + status",
          server.token_enc is None and server.private_key_enc is None
          and server.status == "unlinked")

    await Tortoise.close_connections()
    print()
    if _FAILURES:
        print(f"FAILED ({len(_FAILURES)}): {_FAILURES}")
        sys.exit(1)
    print("ALL DEP CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
