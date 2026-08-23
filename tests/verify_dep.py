"""Backend E2E for ABM/ASM and Automated Device Enrollment (ADE/DEP).

Exercises the real link, sync and profile machinery on an in-memory sqlite with FakeDepTransport and FakeConnector.
Run:  JWT_SECRET=test PYTHONPATH=. ./.venv/bin/python tests/verify_dep.py
"""

import asyncio
import json
import os
import sys
import tempfile
import time
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


async def settle(predicate, timeout=5.0, interval=0.01):
    """Poll until a fire-and-forget effect lands or timeout expires."""
    deadline = time.monotonic() + timeout
    while True:
        if await predicate():
            return True
        if time.monotonic() >= deadline:
            return False
        await asyncio.sleep(interval)


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
    """Stateful mock of Apple's DEP cloud service."""

    def __init__(self, roster, account=None, sync_batches=None, page_size=2):
        self.roster = roster
        self.account = account or {"org_name": "Acme Inc", "server_name": "acme-mdm",
                                   "org_id": "ORG123", "admin_id": "admin@acme.example"}
        self.sync_batches = list(sync_batches or [])
        self.page_size = page_size
        self.calls = []
        self.assigned = {}  # profile_uuid -> [serials]
        self.cleared = []  # serials passed to DELETE /profile/devices
        self.disowned = []  # serials passed to /devices/disown
        self.batch_sizes = []  # devices-per-request, for the chunking checks
        self.request_bodies = []  # (path, decoded body) for every call
        self._profile_seq = 0
        # serial -> status overrides for assign/clear; anything unlisted is SUCCESS.
        self.assign_results = {}
        self.clear_results = {}
        # A scalar applies to every assign response; a list is consumed one entry per request, which is how a chunked
        # assignment gets a different value per batch.
        self.assign_retry_after = None
        # Canned failures: (path_suffix, status, body_bytes, skip), where skip is how many matching requests to let
        # through before failing the next one.
        self.error_queue = []

    async def __call__(self, method, url, headers, body):
        path = url.split(self._host(url), 1)[-1] if "://" in url else url
        self.calls.append((method, path))
        data = json.loads(body) if body else {}
        self.request_bodies.append((path, data))

        if path.endswith("/session"):
            assert headers.get("Authorization", "").startswith("OAuth "), "missing OAuth header"
            return 200, {}, json.dumps({"auth_session_token": "SESS-1"}).encode()
        assert headers.get("X-ADM-Auth-Session") == "SESS-1", "missing session header"

        if self.error_queue and path.endswith(self.error_queue[0][0]):
            suffix, status, err_body, skip = self.error_queue[0]
            if skip > 0:
                self.error_queue[0] = (suffix, status, err_body, skip - 1)
            else:
                self.error_queue.pop(0)
                return status, {}, err_body

        if isinstance(data.get("devices"), list):
            self.batch_sizes.append(len(data["devices"]))

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
            # One queued batch per call; more than one left means the delta is still paging, which is how a multi-page
            # sync is modelled.
            batch = self.sync_batches.pop(0) if self.sync_batches else []
            return self._ok({"devices": batch, "cursor": "SYNC-CUR",
                             "more_to_follow": bool(self.sync_batches)})

        if path.endswith("/profile") and method == "POST":
            self._profile_seq += 1
            uuid = f"PUUID-{self._profile_seq}"
            return self._ok({"profile_uuid": uuid,
                             "devices": {d.get("serial_number"): "ASSIGNED"
                                         for d in []}})

        if path.endswith("/profile/devices") and method == "POST":
            uuid = data.get("profile_uuid")
            serials = data.get("devices") or []
            self.assigned.setdefault(uuid, []).extend(serials)
            resp = {"profile_uuid": uuid,
                    "devices": {s: self.assign_results.get(s, "SUCCESS") for s in serials}}
            retry_after = self.assign_retry_after
            if isinstance(retry_after, list):
                retry_after = retry_after.pop(0) if retry_after else None
            if retry_after is not None:
                resp["retry_after_seconds"] = retry_after
            return self._ok(resp)

        if path.endswith("/profile/devices") and method == "DELETE":
            serials = data.get("devices") or []
            self.cleared.extend(serials)
            return self._ok({"devices": {s: self.clear_results.get(s, "SUCCESS")
                                         for s in serials}})

        if path.endswith("/devices/disown") and method == "POST":
            serials = data.get("devices") or []
            self.disowned.extend(serials)
            return self._ok({"devices": {s: "SUCCESS" for s in serials}})

        if path.endswith("/devices") and method == "POST":
            serials = data.get("devices") or []
            return self._ok({"devices": {s: {"serial_number": s} for s in serials}})

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


def _envelope_token_der(cert_pem, token):
    """The raw CMS EnvelopedData DER, before any MIME/PEM wrapping."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    inner = ("-----BEGIN MESSAGE-----\n" + json.dumps(token) +
             "\n-----END MESSAGE-----\n").encode()
    return pkcs7.PKCS7EnvelopeBuilder().set_data(inner).add_recipient(cert).encrypt(
        Encoding.DER, [])


def _apple_style_smime(der):
    """Wrap CMS DER the way ABM actually delivers it: MIME headers (name= before smime-type=, a Content-Description),
    CRLF line endings, 64-col base64 body."""
    import base64 as _b64
    body = _b64.encodebytes(der).decode().replace("\n", "\r\n")
    headers = (
        'Content-Type: application/pkcs7-mime; name="smime.p7m"; smime-type=enveloped-data\r\n'
        'Content-Transfer-Encoding: base64\r\n'
        'Content-Disposition: attachment; filename="smime.p7m"\r\n'
        'Content-Description: S/MIME Encrypted Message\r\n'
        '\r\n'
    )
    return (headers + body).encode()


def _synthetic_apple_cms_der(serial, anchor_path, tamper=False, untrusted=False):
    """The raw CMS SignedData DER a token-based ADE device POSTs as its request body: a MachineInfo plist signed by a
    synthetic root->intermediate->device chain, with the root written out as an anchor PEM (unless untrusted)."""
    import base64 as _b64
    return _b64.b64decode(
        _synthetic_apple_cms(serial, anchor_path, tamper=tamper, untrusted=untrusted))


def _synthetic_apple_cms(serial, anchor_path, tamper=False, untrusted=False):
    """Build a base64 x-apple-aspen-deviceinfo header signed by a synthetic root->intermediate->device chain, and write
    the root as an anchor PEM (unless untrusted). Returns the base64 header string."""
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


def _leaf_signed_cms(serial, anchor_path):
    """CMS signed by a forged cert chain: leaf is not a CA."""
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
    leaf, lk = mkcert("VER-REALDEVICE", "Test iPhone Device CA", ik)
    forged, fk = mkcert(serial, "VER-REALDEVICE", lk)
    mi = _pl_dumps({"SERIAL": serial, "PRODUCT": "Mac14,2"})
    builder = pkcs7.PKCS7SignatureBuilder().set_data(mi).add_signer(forged, fk, hashes.SHA256())
    for c in (leaf, inter, root):
        builder = builder.add_certificate(c)
    der = builder.sign(Encoding.DER, [])
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
    """A base64 header carrying an XML plist with a SERIAL (as a real ADE device's x-apple-aspen-deviceinfo would,
    wrapped in CMS. parse_machine_info extracts the embedded plist)."""
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
    (tdir / "flows.yaml").write_text(yaml.safe_dump({"flow": {
        "id": "zt", "name": "ZT", "enabled": True, "nodes": [
            {"id": "start", "type": "start",
             "params": {"kind": "enroll_dep", "match": {"conditions": [
                 {"type": "enrollment_source", "operator": "in", "value": ["ade"]}]}},
             "next": "tag"},
            {"id": "tag", "type": "assign_tag", "params": {"tags": ["corp"]}, "next": "rel"},
            {"id": "rel", "type": "release_device", "next": "done"},
            {"id": "done", "type": "end"},
        ]}}))
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
    from controller.services.dep_client import DepError

    tenant = await Tenant.create(id="default", name="Default")

    #  1) Link: begin_link -> (ABM) encrypt token -> complete_link
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
    # Bound to the tenant, so a database write cannot transplant one tenant's ABM credentials onto another tenant's row.
    # Both halves: the right binding opens it, a neighbour's does not.
    check("token ciphertext is bound to its own tenant",
          json.loads(crypto_secrets.decrypt(
              server.token_enc,
              aad=dep_manager._binding(server.tenant_id, "token")))["consumer_key"] == "CK")
    check("...and refuses to open under another tenant's binding",
          crypto_secrets.decrypt(
              server.token_enc, aad=dep_manager._binding("victim", "token")) is None)
    check("the private key is bound the same way",
          crypto_secrets.decrypt(
              server.private_key_enc,
              aad=dep_manager._binding("victim", "private_key")) is None)
    check("account org captured", (server.account_detail or {}).get("org_name") == "Acme Inc")
    check("token expiry parsed", server.token_expires_at is not None)

    # Token formats: S/MIME with MIME headers, raw DER, or base64 blob—all decrypt to same creds.
    _der = _envelope_token_der(server.public_cert_pem, token)
    import base64 as _b64
    for _label, _blob in (
            ("apple-style S/MIME", _apple_style_smime(_der)),
            ("raw DER", _der),
            ("bare base64", _b64.encodebytes(_der)),
    ):
        _got = dep_pki.decrypt_server_token(_blob, crypto_secrets.decrypt(server.private_key_enc),
                                            server.public_cert_pem)
        check(f"token decrypts from {_label}", _got.get("consumer_key") == "CK")
    check("to_dict() NEVER leaks token/key", not any(
        k in server.to_dict() for k in ("token_enc", "private_key_enc", "public_cert_pem")))

    # Legacy rows before binding: sync-time upgrade re-encrypts them under the binding.
    _legacy_enc = crypto_secrets.encrypt(json.dumps(token))
    server.token_enc = _legacy_enc
    await server.save()
    check("a token stored before the binding still builds a client",
          dep_manager.build_client(server, transport=fake) is not None)
    await dep_manager._upgrade_token_binding(server)
    await server.refresh_from_db()
    check("...and the next sync re-encrypts it under the binding",
          server.token_enc != _legacy_enc
          and json.loads(crypto_secrets.decrypt(
              server.token_enc,
              aad=dep_manager._binding(server.tenant_id, "token")))["consumer_key"] == "CK"
          and crypto_secrets.decrypt(
              server.token_enc, aad=dep_manager._binding("victim", "token")) is None)

    #  2) Device sync -> placeholders (paged full fetch)
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

    #  3) Delta with a modified + deleted (placeholder) op
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

    #  4) Push a DEP profile + assign; idempotent re-push
    print("4) push + assign an enrollment profile")
    enroll_url = "https://mdm.example.com/api/v1/dep/enroll/default"
    mapping = await dep_manager.push_profile(server, "zero-touch", enroll_url, transport=fake)
    check("profile_uuid returned + stored", mapping.profile_uuid == "PUUID-1")
    # The Apple profile drops the invalid skip key and carries the enrollment url.
    apple_profile = dep_manager._build_apple_profile(
        dep_manager._load_profile_yaml("default", "zero-touch"), server, tenant, enroll_url)
    check("invalid skip key dropped", apple_profile["skip_setup_items"] == ["AppleID", "Passcode"])
    check("await_device_configured mapped", apple_profile["await_device_configured"] is True)
    check("enroll url set on profile", apple_profile["url"] == enroll_url)
    calls_before = len(fake.calls)
    mapping2 = await dep_manager.push_profile(server, "zero-touch", enroll_url, transport=fake)
    check("re-push is idempotent (no new define call)",
          mapping2.profile_uuid == "PUUID-1" and len(fake.calls) == calls_before)

    outcome = await dep_manager.assign_profile(server, "zero-touch", ["SER-A", "SER-B"], enroll_url, transport=fake)
    results = outcome["results"]
    check("assign returned SUCCESS per serial",
          results.get("SER-A") == "SUCCESS" and results.get("SER-B") == "SUCCESS")
    a = await Device.get(tenant=tenant, serial_number="SER-A")
    check("device profile status -> assigned", a.dep_profile_status == "assigned")

    # Apple limits profile field lengths; over-long URLs break enrollment.
    long_yaml = {"id": "long", "name": "L" * 200, "payload": {
        "is_supervised": True,
        "department": "D" * 200,
        "support_phone_number": "5" * 90,
        "support_email_address": "e" * 300,
        "anchor_certs": ["QUJD", "  ", "REVG"]}}
    long_profile = dep_manager._build_apple_profile(long_yaml, server, tenant, enroll_url)
    check("over-long profile fields trimmed to Apple's documented maxima",
          len(long_profile["profile_name"]) == 125
          and len(long_profile["department"]) == 125
          and len(long_profile["support_phone_number"]) == 50
          and len(long_profile["support_email_address"]) == 250)
    check("anchor_certs passed through (blank entries dropped)",
          long_profile.get("anchor_certs") == ["QUJD", "REVG"])
    try:
        dep_manager._build_apple_profile(long_yaml, server, tenant,
                                         "https://x.example/" + "u" * 2100)
        check("an enrollment URL past Apple's 2000-character cap is refused", False)
    except DepError as ex:
        check("an enrollment URL past Apple's 2000-character cap is refused",
              ex.code == "CONFIG_URL_INVALID")

    # Validate is_mdm_removable constraint (Apple's FLAGS_INVALID rule) before sending.
    for _label, _payload, _want in (
            ("unsupervised + non-removable", {"is_supervised": False, "is_mdm_removable": False}, True),
            ("supervised omitted + non-removable", {"is_mdm_removable": False}, True),
            ("supervised + non-removable", {"is_supervised": True, "is_mdm_removable": False}, False),
    ):
        try:
            dep_manager._build_apple_profile(
                {"id": "flags", "name": "Flags", "payload": _payload}, server, tenant,
                enroll_url)
            refused = False
        except DepError as ex:
            refused = ex.code == "FLAGS_INVALID"
        check(f"FLAGS_INVALID guard: {_label} -> {'refused' if _want else 'accepted'}",
              refused is _want)

    #  5) Default-profile auto-assign on newly-synced devices
    print("5) default profile auto-assigns to new devices")
    server.default_profile_id = "zero-touch"
    await server.save()
    fake.sync_batches = [[{"serial_number": "SER-D", "model": "Mac15,3",
                           "op_type": "added", "op_date": "5"}]]
    await dep_manager.sync_devices(server, transport=fake)
    d = await Device.get(tenant=tenant, serial_number="SER-D")
    check("new device auto-assigned the default profile",
          "SER-D" in fake.assigned.get("PUUID-1", []) and d.dep_profile_status == "assigned")

    #  6) enrollment_source scope condition
    print("6) enrollment_source scope condition")
    ade_dev = Device(tenant=tenant, serial_number="X", device_model="Mac14,2",
                     os_version="14", attributes={"enrollment_source": "ade"}, groups=[], tags=[])
    ota_dev = Device(tenant=tenant, serial_number="Y", device_model="Mac14,2",
                     os_version="14", attributes={}, groups=[], tags=[])
    cond = {"type": "enrollment_source", "operator": "in", "value": ["ade"]}
    check("ADE device matches enrollment_source:ade", scoping.evaluate_condition(ade_dev, cond, []))
    check("OTA/unknown device does NOT match (defaults to ota)",
          not scoping.evaluate_condition(ota_dev, cond, []))

    #  7) release_device node -> DeviceConfigured via audited path
    print("7) release_device sends DeviceConfigured")
    FakeConnector.sent = []
    enrolled = await Device.create(tenant=tenant, udid="UDID-REL", serial_number="SER-A",
                                   device_model="Mac14,2", os_version="14",
                                   enrollment_state="enrolled",
                                   attributes={"enrollment_source": "ade"}, groups=[], tags=[])
    # Adopt the placeholder row -> single device: reuse the enrolled one.
    runs = await atc.start_flows_for_event(enrolled, "enroll_dep")
    run = runs[0] if runs else None

    async def release_landed():
        return (("DeviceConfigured", "UDID-REL") in FakeConnector.sent
                and await Task.filter(tenant=tenant, type="device_configured").count() == 1)

    await settle(release_landed)
    check("zero-touch flow ran + completed", run is not None and run.status == "completed")
    check("corp tag applied", "corp" in (await Device.get(id=enrolled.id)).tags)
    check("DeviceConfigured queued to the device",
          ("DeviceConfigured", "UDID-REL") in FakeConnector.sent)
    check("device_configured audit task recorded",
          await Task.filter(tenant=tenant, type="device_configured").count() == 1)

    #  7b) ADE endpoint: requires the per-tenant token, pre-stamps enrollment_source
    print("7b) ADE enroll endpoint requires the per-tenant token")
    os.environ["MDM_TOPIC"] = "com.apple.mgmt.External.test"
    os.environ["SCEP_CHALLENGE"] = "test-challenge"
    # The ServerURL and the SCEP URL are built from this when neither is set outright. Without it enrollment is refused
    # rather than issuing a profile with no host in it.
    os.environ["MDM_HOSTNAME"] = "mdm.example.test"
    from controller.api import dep as dep_api
    from controller.services import enrollment as enroll_svc
    from fastapi import HTTPException

    class FakeReq:
        """Starlette-shaped request with streamed body for ADE device enrollment."""

        CHUNK = 8 * 1024

        class _Peer:
            host = "203.0.113.7"

        def __init__(self, headers, body=b"", declare_length=True):
            from starlette.datastructures import Headers
            hdrs = dict(headers)
            if declare_length:
                hdrs.setdefault("content-length", str(len(body)))
            self.headers = Headers(hdrs)
            self._body = body
            self.streamed = 0
            self.client = self._Peer()

        async def stream(self):
            for start in range(0, len(self._body), self.CHUNK):
                chunk = self._body[start:start + self.CHUNK]
                self.streamed += len(chunk)
                yield chunk

    good = enroll_svc.enrollment_token("default")
    # A bad token and an unknown tenant answer the same 404, so an anonymous caller cannot ask this endpoint which
    # tenant ids exist, one guess at a time.
    try:
        await dep_api.ade_enroll("default", "wrong-token", FakeReq({}))
        check("bad ADE token rejected", False)
    except HTTPException as ex:
        check("bad ADE token -> 404, not 403", ex.status_code == 404)
    try:
        await dep_api.ade_enroll("no-such-tenant", good, FakeReq({}))
        check("unknown tenant rejected", False)
    except HTTPException as ex:
        check("unknown tenant -> the same 404", ex.status_code == 404)
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

    # ADE profile carries tenant signature just like OTA; webhook verifies it.
    from urllib.parse import parse_qs as _parse_qs, urlparse as _urlparse
    _mdm_payload = next(p for p in _pl_loads(resp.body)["PayloadContent"]
                        if p["PayloadType"] == "com.apple.mdm")
    _q = _parse_qs(_urlparse(_mdm_payload["ServerURL"]).query)
    check("ADE mobileconfig ServerURL claims the tenant",
          _q.get("tenant") == ["default"])
    check("ADE mobileconfig ServerURL carries a verifying tenant signature",
          len(_q.get("tsig", [])) == 1
          and enroll_svc.verify_tenant_url_token("default", _q["tsig"][0]))

    #  7c) ADE MachineInfo CMS signature verification
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

    # Every signature here verifies and the anchor is ours; the only fault is that the signer's issuer is a real device
    # certificate rather than a CA. Accepting it lets one device's identity forge MachineInfo for the whole fleet.
    hdr_forged = _leaf_signed_cms("VER-FORGED", anchor_path)
    dep_verify._anchors.cache_clear()
    _c, v_f, _d_f = dep_verify.verify_cms(_b64.b64decode(hdr_forged))
    check(f"CMS signed by a cert an Apple LEAF issued rejected ({_d_f})", not v_f)

    # Endpoint enforcement: DEP_ADE_REQUIRE_APPLE_SIGNATURE=true means verify CMS signature in the request body.
    os.environ["DEP_ADE_REQUIRE_APPLE_SIGNATURE"] = "true"
    body_ok = _synthetic_apple_cms_der("VER-BODY", anchor_path)
    dep_verify._anchors.cache_clear()
    await Device.create(tenant=tenant, udid=None, serial_number="VER-BODY",
                        device_model="Mac", os_version="", enrollment_state="pending",
                        dep_server_id=server.id, attributes={}, groups=[], tags=[])
    # Catch early endpoint exits: failed read is a check failure, not a traceback.
    resp_body, body_error = None, None
    try:
        resp_body = await dep_api.ade_enroll("default", good, FakeReq({}, body=body_ok))
    except HTTPException as ex:
        body_error = f"HTTP {ex.status_code}: {ex.detail}"
    check(f"enforced: signed MachineInfo in the POST body -> mobileconfig ({body_error})",
          resp_body is not None
          and resp_body.media_type == "application/x-apple-aspen-config")
    body_dev = await Device.get(tenant=tenant, serial_number="VER-BODY")
    check("...and the body's serial pre-stamped the placeholder as verified ADE",
          (body_dev.attributes or {}).get("enrollment_source") == "ade"
          and (body_dev.attributes or {}).get("ade_signature_verified") is True)

    body_bad = _synthetic_apple_cms_der("VER-BODYBAD", anchor_path, tamper=True)
    dep_verify._anchors.cache_clear()
    try:
        await dep_api.ade_enroll("default", good, FakeReq({}, body=body_bad))
        check("enforced: tampered POST body -> 403", False)
    except HTTPException as ex:
        check("enforced: tampered POST body -> 403", ex.status_code == 403)

    # Failed body verification is not retried against the header.
    hdr_ok2 = _synthetic_apple_cms("VER-ENF", anchor_path)
    dep_verify._anchors.cache_clear()
    try:
        await dep_api.ade_enroll(
            "default", good,
            FakeReq({"x-apple-aspen-deviceinfo": hdr_ok2}, body=body_bad))
        check("enforced: a bad body is not rescued by a good header -> 403", False)
    except HTTPException as ex:
        check("enforced: a bad body is not rescued by a good header -> 403",
              ex.status_code == 403)

    # Header fallback works when there is no body (web-view flow).
    resp_hdr = await dep_api.ade_enroll(
        "default", good, FakeReq({"x-apple-aspen-deviceinfo": hdr_ok2}))
    check("enforced: header fallback still verifies when there is no body",
          resp_hdr.media_type == "application/x-apple-aspen-config")

    try:
        await dep_api.ade_enroll("default", good, FakeReq({}))  # no body, no header
        check("enforced: no MachineInfo at all -> 403", False)
    except HTTPException as ex:
        check("enforced: no MachineInfo at all -> 403", ex.status_code == 403)

    # Buffer size capped: declared length > cap is refused before reading; chunked requests are cut off mid-stream.
    huge = b"A" * (dep_api._MACHINE_INFO_MAX_BYTES * 4)
    declared = FakeReq({}, body=huge)
    try:
        await dep_api.ade_enroll("default", good, declared)
        check("an oversized body is refused with 413", False)
    except HTTPException as ex:
        check("an oversized body is refused with 413", ex.status_code == 413)
    check("...before any of it is read", declared.streamed == 0)

    chunked = FakeReq({}, body=huge, declare_length=False)
    try:
        await dep_api.ade_enroll("default", good, chunked)
        check("an oversized chunked body is refused with 413", False)
    except HTTPException as ex:
        check("an oversized chunked body is refused with 413", ex.status_code == 413)
    check(f"...after reading no more than the cap ({chunked.streamed} bytes)",
          0 < chunked.streamed <= dep_api._MACHINE_INFO_MAX_BYTES + FakeReq.CHUNK
          and chunked.streamed < len(huge))
    os.environ.pop("DEP_ADE_REQUIRE_APPLE_SIGNATURE", None)
    os.environ.pop("DEP_APPLE_ANCHOR_CERTS", None)
    dep_verify._anchors.cache_clear()

    # Serial sanitization: reject control chars and oversized values.
    check("a serial with a control character is not usable",
          dep_api._clean_serial("ADE-1\nADE: forged line") == ""
          and dep_api._clean_serial("ADE-1\x00") == "")
    check("a serial longer than the column is not usable",
          dep_api._clean_serial("A" * (dep_api._SERIAL_MAX + 1)) == "")
    check("an ordinary serial still passes, trimmed",
          dep_api._clean_serial("  C02X1234ABCD  ") == "C02X1234ABCD")

    # Enforcement off: unverified request must not downgrade a prior verified signature.
    await Device.create(tenant=tenant, udid=None, serial_number="ADE-KEEP",
                        device_model="Mac", os_version="", enrollment_state="pending",
                        dep_server_id=server.id, groups=[], tags=[],
                        attributes={"enrollment_source": "ade",
                                    "ade_signature_verified": True})
    unsigned = (b"cms-prefix" + _pl_dumps({"SERIAL": "ADE-KEEP", "PRODUCT": "Mac14,2"})
                + b"cms-suffix")
    await dep_api.ade_enroll("default", good, FakeReq({}, body=unsigned))
    kept_ade = await Device.get(tenant=tenant, serial_number="ADE-KEEP")
    check("an unverified request cannot downgrade a recorded verification",
          (kept_ade.attributes or {}).get("ade_signature_verified") is True)

    #  7d) the sync device upsert is one query per SYNC, not per record
    print("7d) first-full-sync upsert reads devices once, not once per record")
    # sync_devices uses a prefetched serial->Device map instead of per-serial queries (optimization only).
    from tortoise import connections

    dep_conn = connections.get("default")
    seen_sql = []

    class _SqlSpy:
        def __enter__(self):
            self._q, self._qd = dep_conn.execute_query, dep_conn.execute_query_dict

            async def spy_q(sql, values=None):
                seen_sql.append(sql)
                return await self._q(sql, values)

            async def spy_qd(sql, values=None):
                seen_sql.append(sql)
                return await self._qd(sql, values)

            seen_sql.clear()
            dep_conn.execute_query, dep_conn.execute_query_dict = spy_q, spy_qd
            return self

        def __exit__(self, *exc):
            dep_conn.execute_query, dep_conn.execute_query_dict = self._q, self._qd
            return False

    def _device_selects():
        return [s for s in seen_sql
                if s.lstrip().upper().startswith("SELECT") and '"devices"' in s]

    # The default profile was set in section 5; an auto-assign pass would add its own device reads to the count below,
    # which section 7f measures separately.
    server.default_profile_id = None
    await server.save()

    def batch(prefix, n, op_date="7"):
        return [{"serial_number": f"{prefix}-{i}", "model": "Mac14,2",
                 "op_type": "added", "op_date": op_date} for i in range(n)]

    fake.sync_batches = [batch("M7A", 5)]
    with _SqlSpy():
        small = await dep_manager.sync_devices(server, transport=fake)
    small_selects = len(_device_selects())
    fake.sync_batches = [batch("M7B", 20)]
    with _SqlSpy():
        big = await dep_manager.sync_devices(server, transport=fake)
    big_selects = len(_device_selects())
    check(f"5 and 20 new serials cost the same number of device reads "
          f"({small_selects} and {big_selects})",
          small_selects == big_selects == 1)
    check("...and both syncs actually created their rows",
          small["added"] == 5 and big["added"] == 20)

    # The fallback: with the prefetch made to fail, the sync still completes and produces the same counts, at the old
    # one-query-per-record cost.
    real_prefetch = dep_manager._prefetch_devices_by_serial

    async def _boom(tenant_id):
        raise RuntimeError("prefetch unavailable")

    fake.sync_batches = [batch("M7C", 20)]
    degraded, degraded_error, degraded_selects = {}, None, 0
    try:
        dep_manager._prefetch_devices_by_serial = _boom
        with _SqlSpy():
            # Caught rather than left to escape: a prefetch the sync cannot do without has to read as a failed check,
            # not as a traceback that takes the rest of the suite with it.
            try:
                degraded = await dep_manager.sync_devices(server, transport=fake)
            except Exception as exc:
                degraded_error = exc
        degraded_selects = len(_device_selects())
    finally:
        dep_manager._prefetch_devices_by_serial = real_prefetch
    check(f"a failed prefetch still completes the sync with the same counts "
          f"({degraded_error})",
          degraded_error is None and degraded.get("ok")
          and degraded.get("added") == big["added"] == 20)
    check(f"...by falling back to one query per record ({degraded_selects})",
          degraded_selects == 20)

    # A serial reaching _upsert_device twice in one call finds the row the first occurrence created, instead of racing a
    # second insert against the unique index.
    dmap = await dep_manager._prefetch_devices_by_serial(tenant.id)
    first_created = await dep_manager._upsert_device(
        server, "M7-DUP", {"model": "Mac14,2", "profile_status": "assigned"}, dmap)
    second_created = await dep_manager._upsert_device(
        server, "M7-DUP", {"model": "Mac14,2", "profile_status": "pushed"}, dmap)
    dup_rows = await Device.filter(tenant=tenant, serial_number="M7-DUP")
    check("the second occurrence of a serial updates rather than creates",
          first_created is True and second_created is False and len(dup_rows) == 1)
    check("...and the update landed",
          bool(dup_rows) and dup_rows[0].dep_profile_status == "pushed")

    # Legacy duplicates: both prefetch and fallback paths must pick the same row.
    async def _seed_legacy_pair():
        await Device.filter(tenant=tenant, serial_number="M7-LEGACY").delete()
        rows = []
        for i in range(2):
            rows.append(await Device.create(
                tenant=tenant, udid=f"UDID-M7L{i}", serial_number="M7-LEGACY",
                device_model="Mac14,2", os_version="14",
                enrollment_state="enrolled", groups=[], tags=[]))
        return rows

    await _seed_legacy_pair()
    legacy_map = await dep_manager._prefetch_devices_by_serial(tenant.id)
    await dep_manager._upsert_device(
        server, "M7-LEGACY", {"model": "Mac14,2", "profile_status": "assigned"},
        legacy_map)
    mapped = [d for d in await Device.filter(tenant=tenant,
                                             serial_number="M7-LEGACY").order_by("udid")
              if d.dep_last_synced_at is not None]
    await _seed_legacy_pair()
    await dep_manager._upsert_device(
        server, "M7-LEGACY", {"model": "Mac14,2", "profile_status": "assigned"}, None)
    fallback = [d for d in await Device.filter(tenant=tenant,
                                               serial_number="M7-LEGACY").order_by("udid")
                if d.dep_last_synced_at is not None]
    check("a legacy duplicate pair leaves exactly one row stamped, either way",
          len(mapped) == 1 and len(fallback) == 1)
    check("...and the map path picks the same one the per-record query did",
          bool(mapped) and bool(fallback) and mapped[0].udid == fallback[0].udid)

    # DEP columns updated without touching enrollment lifecycle fields.
    kept = await Device.create(
        tenant=tenant, udid="UDID-M7KEEP", serial_number="M7-KEEP",
        device_model="MacBookPro18,3", os_version="15.1", name="Front Desk",
        enrollment_state="unenrolled", management_type="apple_mdm",
        groups=["macs"], tags=["front"], attributes={"enrollment_source": "ota"},
        installed_apps=[{"Identifier": "com.x"}])
    keep_map = await dep_manager._prefetch_devices_by_serial(tenant.id)
    await dep_manager._upsert_device(
        server, "M7-KEEP", {"model": "Mac14,2", "profile_uuid": "PU-KEEP",
                            "profile_status": "assigned"}, keep_map)
    kept = await Device.get(id=kept.id)
    check("an existing device keeps its lifecycle and non-DEP fields",
          kept.enrollment_state == "unenrolled" and kept.udid == "UDID-M7KEEP"
          and kept.name == "Front Desk" and kept.os_version == "15.1"
          and kept.device_model == "MacBookPro18,3"
          and kept.groups == ["macs"] and kept.tags == ["front"]
          and kept.attributes == {"enrollment_source": "ota"}
          and kept.installed_apps == [{"Identifier": "com.x"}])
    check("...while the DEP columns are stamped",
          kept.dep_profile_uuid == "PU-KEEP"
          and kept.dep_profile_status == "assigned"
          and str(kept.dep_server_id) == str(server.id)
          and kept.dep_last_synced_at is not None)

    # Serials stripped but not case-folded (unique index is case-sensitive).
    await Device.create(
        tenant=tenant, udid="UDID-M7CASE", serial_number="m7-case",
        device_model="Mac14,2", os_version="14", enrollment_state="pending",
        groups=[], tags=[])
    case_map = await dep_manager._prefetch_devices_by_serial(tenant.id)
    check("the map is keyed case-sensitively, like the column",
          "m7-case" in case_map and "M7-CASE" not in case_map)

    #  7e) every serial-list endpoint splits on Apple's 1000-device ceiling
    print("7e) serial lists are chunked at 1000 devices per request")
    # Apple requests are capped at 1000 devices; large syncs must chunk the list.
    from controller.services.dep_client import MAX_DEVICES_PER_REQUEST
    many = [f"CHUNK-{i}" for i in range(2500)]
    fake.batch_sizes = []
    chunk_out = await dep_manager.assign_profile(server, "zero-touch", many,
                                                 enroll_url, transport=fake)
    check(f"2500 serials assigned in batches of at most {MAX_DEVICES_PER_REQUEST} "
          f"({fake.batch_sizes})",
          fake.batch_sizes == [1000, 1000, 500])
    check("...and every serial's result survives the merge",
          len(chunk_out["results"]) == 2500
          and set(chunk_out["results"].values()) == {"SUCCESS"})

    fake.batch_sizes = []
    unassign_many = await dep_manager.unassign_profile(server, many, transport=fake)
    check(f"unassign chunks the same way ({fake.batch_sizes})",
          fake.batch_sizes == [1000, 1000, 500] and len(unassign_many) == 2500)

    fake.batch_sizes = []
    disown_many = await dep_manager.disown_devices(server, many, transport=fake)
    check(f"disown chunks the same way ({fake.batch_sizes})",
          fake.batch_sizes == [1000, 1000, 500] and len(disown_many) == 2500)

    chunk_client = dep_manager.build_client(server, transport=fake)
    fake.batch_sizes = []
    details = await chunk_client.device_details(many)
    check(f"device details chunk the same way ({fake.batch_sizes})",
          fake.batch_sizes == [1000, 1000, 500]
          and len(details.get("devices") or {}) == 2500)

    # retry_after_seconds merged across batches: take the max so caller waits for all throttled devices.
    fake.assign_retry_after = [10, 90, 30]
    spread = await dep_manager.assign_profile(server, "zero-touch", many, enroll_url,
                                              transport=fake)
    check("the longest retry_after_seconds across batches is the one returned",
          spread["retry_after_seconds"] == 90)
    fake.assign_retry_after = None

    # Failed batch raises; earlier batches already applied at Apple, rest not synthesized.
    fake.assigned["PUUID-1"] = []
    fake.error_queue = [("/profile/devices", 400, b'{"code":"DEVICE_NOT_ASSIGNED"}', 1)]
    mid_batch_error = None
    try:
        await dep_manager.assign_profile(server, "zero-touch", many, enroll_url,
                                         transport=fake)
    except DepError as ex:
        mid_batch_error = ex
    applied = fake.assigned.get("PUUID-1", [])
    check(f"a failing batch propagates the error ({mid_batch_error})",
          mid_batch_error is not None and mid_batch_error.code == "DEVICE_NOT_ASSIGNED")
    check(f"...with the batches before it already applied and none after "
          f"({len(applied)} serials)",
          applied == many[:1000])
    fake.error_queue = []

    #  7f) per-serial assignment results are recorded, not discarded
    print("7f) FAILED / NOT_ACCESSIBLE / THROTTLED results land on the device row")
    # Apple answers per serial, and with X-Server-Protocol-Version 9+ a throttled device reports THROTTLED; version 10+
    # adds retry_after_seconds. Only SUCCESS may stamp the profile onto the row.
    res_serials = ["RES-OK", "RES-FAIL", "RES-GONE", "RES-SLOW"]
    for s in res_serials:
        await Device.create(tenant=tenant, udid=None, serial_number=s,
                            device_model="Mac14,2", os_version="",
                            enrollment_state="pending", dep_server_id=server.id,
                            attributes={}, groups=[], tags=[])
    fake.assign_results = {"RES-FAIL": "FAILED", "RES-GONE": "NOT_ACCESSIBLE",
                           "RES-SLOW": "THROTTLED"}
    fake.assign_retry_after = 45
    res_client = dep_manager.build_client(server, transport=fake)
    res_out = await dep_manager._assign_and_record(
        server, "PUUID-1", res_serials, res_client)
    check("retry_after_seconds reaches the caller", res_out["retry_after_seconds"] == 45)
    rows = {d.serial_number: d for d in
            await Device.filter(tenant=tenant, serial_number__in=res_serials)}
    check("SUCCESS stamps the profile", rows["RES-OK"].dep_profile_status == "assigned"
          and rows["RES-OK"].dep_profile_uuid == "PUUID-1"
          and "dep_assign_result" not in (rows["RES-OK"].attributes or {}))
    check("a non-SUCCESS result is recorded on the row instead of a stale 'assigned'",
          all((rows[s].attributes or {}).get("dep_assign_result", {}).get("status") == want
              and rows[s].dep_profile_status != "assigned"
              for s, want in (("RES-FAIL", "FAILED"), ("RES-GONE", "NOT_ACCESSIBLE"),
                              ("RES-SLOW", "THROTTLED"))))
    check("...and a throttled row carries Apple's retry_after_seconds",
          (rows["RES-SLOW"].attributes or {})
          .get("dep_assign_result", {}).get("retry_after_seconds") == 45)

    # Batched device reads, with re-reads only for rows whose attributes change.
    bulk = [f"BULK-{i}" for i in range(20)]
    for s in bulk:
        await Device.create(tenant=tenant, udid=None, serial_number=s,
                            device_model="Mac14,2", os_version="",
                            enrollment_state="pending", dep_server_id=server.id,
                            attributes={}, groups=[], tags=[])
    fake.assign_results = {}
    fake.assign_retry_after = None
    with _SqlSpy():
        await dep_manager._assign_and_record(server, "PUUID-1", bulk, res_client)
    all_ok_selects = len(_device_selects())
    fake.assign_results = {s: "FAILED" for s in bulk[:3]}
    with _SqlSpy():
        await dep_manager._assign_and_record(server, "PUUID-1", bulk, res_client)
    three_bad_selects = len(_device_selects())
    check(f"20 serials cost one batched device read, not one per serial "
          f"({all_ok_selects})",
          all_ok_selects == 1)
    check(f"...and only a row whose record changes is re-read before its write "
          f"({three_bad_selects} for 3 failures)",
          three_bad_selects == 4)

    fake.assign_results = {}
    fake.assign_retry_after = None
    await dep_manager._assign_and_record(server, "PUUID-1", ["RES-FAIL"], res_client)
    retried = await Device.get(tenant=tenant, serial_number="RES-FAIL")
    check("a later SUCCESS clears the recorded failure",
          retried.dep_profile_status == "assigned"
          and "dep_assign_result" not in (retried.attributes or {}))

    #  7g) unassign only marks locally what Apple actually cleared
    print("7g) unassign writes the local 'removed' only where Apple cleared the profile")
    for s in ("UN-OK", "UN-NO"):
        await Device.create(tenant=tenant, udid=None, serial_number=s,
                            device_model="Mac14,2", os_version="",
                            enrollment_state="pending", dep_server_id=server.id,
                            dep_profile_uuid="PUUID-1", dep_profile_status="assigned",
                            attributes={}, groups=[], tags=[])
    fake.clear_results = {"UN-NO": "FAILED"}
    un_results = await dep_manager.unassign_profile(server, ["UN-OK", "UN-NO"],
                                                    transport=fake)
    un_rows = {d.serial_number: d for d in
               await Device.filter(tenant=tenant, serial_number__in=["UN-OK", "UN-NO"])}
    check("a cleared serial is marked removed",
          un_rows["UN-OK"].dep_profile_status == "removed")
    check("a serial Apple refused keeps its profile state",
          un_rows["UN-NO"].dep_profile_status == "assigned"
          and un_results["UN-NO"] == "FAILED")
    fake.clear_results = {}

    #  7h) cursor lifecycle: exhausted, aged out, and an unfinished pagination
    print("7h) cursor handling: EXHAUSTED_CURSOR, the 7-day age, paging backstop")
    from datetime import timedelta as _timedelta
    await server.refresh_from_db()
    server.sync_cursor = "KEEP-ME"
    stamped_at = dep_manager._now() - _timedelta(days=3)
    server.cursor_fetched_at = stamped_at
    await server.save()
    fake.error_queue = [("/devices/sync", 400, b"EXHAUSTED_CURSOR", 0)]
    calls_at = len(fake.calls)
    exh = await dep_manager.sync_devices(server, transport=fake)
    exh_calls = fake.calls[calls_at:]
    await server.refresh_from_db()
    check("EXHAUSTED_CURSOR is not an error", exh["ok"])
    check("...the cursor is kept, not discarded", server.sync_cursor == "KEEP-ME")
    check("...and no full refetch of the fleet is triggered",
          ("POST", "/server/devices") not in exh_calls)
    # cursor_fetched_at dates the cursor, not the sync tick (so 7-day age check can fire).
    check("...and a tick that got no new cursor does not restamp its age",
          abs((server.cursor_fetched_at - stamped_at).total_seconds()) < 1)

    # Expired cursor (>7 days) dropped before request; triggers full refetch.
    server.sync_cursor = "STALE-CUR"
    server.cursor_fetched_at = dep_manager._now() - _timedelta(days=8)
    await server.save()
    fake.roster = [{"serial_number": "AGED-1", "model": "Mac14,2",
                    "op_type": "added", "op_date": "2026-02-01T00:00:00Z"}]
    bodies_at = len(fake.request_bodies)
    aged = await dep_manager.sync_devices(server, transport=fake)
    aged_bodies = [(p, b) for p, b in fake.request_bodies[bodies_at:]
                   if p.endswith("/server/devices")]
    check("a cursor older than 7 days falls back to a full fetch",
          aged["ok"] and bool(aged_bodies))
    check("...and the aged cursor is not sent with it",
          bool(aged_bodies) and "cursor" not in aged_bodies[0][1])

    # Incomplete pagination: don't persist mid-fetch cursor (next tick would delta an incomplete fleet).
    await server.refresh_from_db()
    server.sync_cursor = None
    server.cursor_fetched_at = None
    await server.save()
    fake.roster = [{"serial_number": f"PAGE-{i}", "model": "Mac14,2",
                    "op_type": "added", "op_date": "2026-02-02T00:00:00Z"}
                   for i in range(10)]
    real_max_pages = dep_manager._MAX_SYNC_PAGES
    try:
        dep_manager._MAX_SYNC_PAGES = 2
        stopped = await dep_manager.sync_devices(server, transport=fake)
    finally:
        dep_manager._MAX_SYNC_PAGES = real_max_pages
    await server.refresh_from_db()
    check("an unfinished pagination is reported as a failed sync",
          not stopped["ok"] and stopped.get("error") == "SYNC_PAGING_INCOMPLETE")
    check("...no cursor is stored for it", server.sync_cursor is None)
    check("...and the devices it did read were still upserted",
          await Device.filter(tenant=tenant, serial_number__startswith="PAGE-").count() == 4)

    # Check row state before save: _collect_devices must not stage cursor from incomplete listing.
    probe = await DepServer.get(id=server.id)
    probe.sync_cursor = "MID-FETCH"
    probe.cursor_fetched_at = stamped_at
    probe_summary = {"pages": 0}
    probe_client = dep_manager.build_client(probe, transport=fake)
    fake.sync_batches = [[] for _ in range(5)]  # keeps more_to_follow set
    try:
        dep_manager._MAX_SYNC_PAGES = 2
        await dep_manager._collect_devices(probe_client, probe, probe_summary)
    finally:
        dep_manager._MAX_SYNC_PAGES = real_max_pages
        fake.sync_batches = []
    check("an abandoned listing stages no cursor on the row",
          probe_summary.get("incomplete") is True
          and probe.sync_cursor == "MID-FETCH"
          and probe.cursor_fetched_at == stamped_at)
    server.sync_cursor = None
    server.cursor_fetched_at = None
    await server.save()

    # Apple sets cursor size to 1000 hex chars max (https://developer.apple.com/documentation/devicemanagement/fetchdevicerequest).
    # Too-narrow column silently drops the cursor, breaking deltas on the next tick.
    long_cursor = "a1b2" * 250
    server.sync_cursor = long_cursor
    server.cursor_fetched_at = dep_manager._now()
    long_summary = await dep_manager._finish_sync(server, {"pages": 1, "ok": True}, None)
    long_reread = await DepServer.get(id=server.id)
    check("a cursor at Apple's 1000-character limit survives the save",
          len(long_cursor) == 1000 and long_reread.sync_cursor == long_cursor)
    check("...and the run that stored it still reports itself ok",
          long_summary.get("ok") is not False
          and long_reread.last_sync_status == "ok")
    server.sync_cursor = None
    server.cursor_fetched_at = None
    await server.save()

    #  7i) duplicate serials resolve by real timestamp, not string order
    print("7i) op_date duplicates resolve chronologically")
    # ISO 8601 with timezones doesn't sort lexicographically; Apple resolves by latest op_date.
    fake.sync_batches = [[
        {"serial_number": "OPD-1", "model": "Mac14,2", "op_type": "added",
         "op_date": "2026-01-03T01:00:00Z", "profile_status": "pushed"},
        {"serial_number": "OPD-1", "model": "Mac14,2", "op_type": "modified",
         "op_date": "2026-01-02T23:00:00-05:00", "profile_status": "assigned"},
    ]]
    server.sync_cursor = "OPD-CUR"
    server.cursor_fetched_at = dep_manager._now()
    await server.save()
    await dep_manager.sync_devices(server, transport=fake)
    opd = await Device.get(tenant=tenant, serial_number="OPD-1")
    check("the chronologically latest record wins across UTC offsets",
          opd.dep_profile_status == "assigned")
    check("a readable op_date beats an unreadable one",
          dep_manager._op_date_at_least("2026-01-01T00:00:00Z", "not-a-date")
          and not dep_manager._op_date_at_least("not-a-date", "2026-01-01T00:00:00Z"))
    check("...and with neither readable, the later record in the payload wins",
          dep_manager._op_date_at_least("3", "1")
          and dep_manager._op_date_at_least("1", "3"))

    #  7j) the undocumented 403 re-auth heuristic is matched exactly
    print("7j) 403 re-auth matches FORBIDDEN case-sensitively")
    # 403 re-auth: nanodep matches "FORBIDDEN" exactly to avoid false matches (proxy pages, etc).
    from controller.services.dep_client import DepAuthError, DepClient as _DepClient

    class _Forbidding:
        def __init__(self, body):
            self.body = body
            self.calls = []

        async def __call__(self, method, url, headers, body):
            path = "/" + url.split("://", 1)[1].split("/", 1)[1]
            self.calls.append((method, path))
            if path.endswith("/session"):
                return 200, {}, json.dumps({"auth_session_token": "S"}).encode()
            return 403, {}, self.body

    creds = {"consumer_key": "CK", "consumer_secret": "CS", "access_token": "AT",
             "access_secret": "AS"}
    for _label, _body, _want_sessions in (
            ("FORBIDDEN", b"FORBIDDEN", 2),
            ("an unrelated 403 page", b"<h1>Forbidden</h1> by the proxy", 1),
    ):
        t = _Forbidding(_body)
        try:
            await _DepClient(creds, base_url="https://dep.test", transport=t).account()
        except (DepAuthError, DepError):
            pass
        sessions = len([c for c in t.calls if c[1].endswith("/session")])
        check(f"403 body {_label}: {'re-authenticates' if _want_sessions == 2 else 'does not re-authenticate'}",
              sessions == _want_sessions)

    #  7k) an unrecognized skip key is dropped loudly, not silently
    print("7k) dropped skip_setup_items keys are logged with their names")
    import logging as _logging

    class _Capture(_logging.Handler):
        def __init__(self):
            super().__init__(level=_logging.WARNING)
            self.messages = []

        def emit(self, record):
            self.messages.append(record.getMessage())

    cap = _Capture()
    dep_log = _logging.getLogger("controller.services.dep_manager")
    dep_log.addHandler(cap)
    try:
        skipped = dep_manager._build_apple_profile(
            dep_manager._load_profile_yaml("default", "zero-touch"), server, tenant,
            enroll_url)
    finally:
        dep_log.removeHandler(cap)
    check("the unknown key is named in a WARNING",
          any("NotARealKey" in m for m in cap.messages))
    check("...and the recognized keys are still sent",
          skipped["skip_setup_items"] == ["AppleID", "Passcode"])

    #  8) unlink wipes secrets
    print("8) unlink wipes secret material")
    await dep_manager.unlink(server)
    await server.refresh_from_db()
    check("unlink clears token + key + status",
          server.token_enc is None and server.private_key_enc is None
          and server.status == "unlinked")

    #  9) remove fully deletes an unfinished connection
    print("9) remove deletes the row, its profiles, and clears device linkage")
    scratch = await dep_manager.begin_link(tenant, "scratch")
    await DepProfile.create(tenant=tenant, dep_server=scratch, profile_id="p1")
    orphan = await Device.create(
        tenant=tenant, udid="U-KEEP", serial_number="SER-KEEP",
        device_model="Mac14,2", os_version="",
        enrollment_state="enrolled", management_type="apple_mdm", groups=[],
        dep_server_id=scratch.id, dep_profile_status="assigned",
    )
    await dep_manager.remove(scratch)
    check("DepServer row deleted", await DepServer.get_or_none(id=scratch.id) is None)
    check("DepProfile mappings deleted",
          await DepProfile.filter(dep_server_id=scratch.id).count() == 0)
    await orphan.refresh_from_db()
    check("enrolled device kept, DEP linkage cleared",
          orphan.udid == "U-KEEP" and orphan.dep_server_id is None
          and orphan.dep_profile_status == "removed")

    await Tortoise.close_connections()
    print()
    if _FAILURES:
        print(f"FAILED ({len(_FAILURES)}): {_FAILURES}")
        sys.exit(1)
    print("ALL DEP CHECKS PASSED")


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
