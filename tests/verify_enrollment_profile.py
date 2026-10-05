"""What actually installs on a device: the enrollment .mobileconfig, checked over its serialized bytes.

Run: PYTHONPATH=. .venv/bin/python tests/verify_enrollment_profile.py
"""
import datetime
import os
import plistlib
import subprocess
import tempfile
from urllib.parse import parse_qs, urlparse

os.environ["JWT_SECRET"] = "test-secret-for-enrollment-profile"
os.environ["MDM_TOPIC"] = "com.apple.mgmt.External.11111111-2222-3333-4444-555555555555"
os.environ["MDM_SERVER_URL"] = "https://mdm.example.test/mdm"
os.environ["SCEP_URL"] = "https://mdm.example.test/scep/mdm_device_scep"
os.environ["SCEP_CHALLENGE"] = "challenge-that-must-not-leak"
os.environ["PUBLIC_API_URL"] = "https://mdm.example.test"
os.environ["MDM_HOSTNAME"] = "mdm.example.test"
os.environ.pop("MDM_EMBED_CA_CERT_PATH", None)

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from controller.services import enrollment as enroll, readiness  # noqa: E402
from tests._verify_harness import make_check

PASS, FAIL = [], []

TOPIC = os.environ["MDM_TOPIC"]
SCEP_URL = os.environ["SCEP_URL"]
CHALLENGE = os.environ["SCEP_CHALLENGE"]


check = make_check(FAIL, PASS)


class StubTenant:
    """build_enrollment_profile reads id and name, nothing else."""

    def __init__(self, tid, name=None):
        self.id = tid
        self.name = name or tid


def payload(profile, payload_type):
    """The one payload of this type, or None."""
    found = [p for p in profile["PayloadContent"] if p["PayloadType"] == payload_type]
    return found[0] if len(found) == 1 else None


def payload_types(profile):
    return [p["PayloadType"] for p in profile["PayloadContent"]]


def shipped(tenant):
    """The profile as a device receives it: serialized, then parsed back."""
    return plistlib.loads(enroll.build_enrollment_mobileconfig(tenant))


def self_signed_ca(path):
    """Write a real CA certificate to path as PEM and return its DER."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Micromanage Test Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Micromanage Tests"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with open(path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert.public_bytes(serialization.Encoding.DER)


def test_top_level():
    print("1) The .mobileconfig parses and the outer payload is a Configuration")
    tenant = StubTenant("acme", "Acme Inc")
    raw = enroll.build_enrollment_mobileconfig(tenant)
    check("build_enrollment_mobileconfig returns bytes", isinstance(raw, bytes))

    parsed = None
    try:
        parsed = plistlib.loads(raw)
    except Exception as exc:  # noqa: BLE001 - the point is that it parses
        print(f"    plistlib refused the profile: {exc}")
    check("plistlib parses the shipped bytes", isinstance(parsed, dict))
    if not isinstance(parsed, dict):
        return

    check("the outer payload is a Configuration", parsed.get("PayloadType") == "Configuration")
    # PayloadScope must stay absent: a System scope suppresses the user channel the MDM payload declares, and a Mac
    # cannot gain that channel after enrollment.
    check("it does not pin PayloadScope", "PayloadScope" not in parsed)
    check("its identifier is tenant-specific",
          parsed.get("PayloadIdentifier") == "com.micromanage.acme.enroll")
    check("it names the organization the tenant is called",
          parsed.get("PayloadOrganization") == "Acme Inc")
    check("PayloadVersion is 1", parsed.get("PayloadVersion") == 1)
    check("the SCEP and MDM payloads are both there, SCEP first",
          payload_types(parsed) == ["com.apple.security.scep", "com.apple.mdm"])

    # Every payload needs its own identity, and a device installs by UUID.
    uuids = [p.get("PayloadUUID") for p in parsed["PayloadContent"]] + [parsed.get("PayloadUUID")]
    check("every payload carries a distinct UUID",
          all(isinstance(u, str) and u for u in uuids) and len(set(uuids)) == len(uuids))


def test_scep_payload():
    print("2) The SCEP payload asks for the device identity certificate")
    scep = payload(shipped(StubTenant("acme", "Acme Inc")), "com.apple.security.scep")
    check("there is exactly one SCEP payload", scep is not None)
    if scep is None:
        return

    inner = scep.get("PayloadContent") or {}
    check("the SCEP URL is the configured one", inner.get("URL") == SCEP_URL)
    check("the SCEP name defaults to the bundled provisioner",
          inner.get("Name") == "mdm_device_scep")
    check("the challenge is the configured one", inner.get("Challenge") == CHALLENGE)
    subject = inner.get("Subject")
    check("the subject names the tenant's device",
          isinstance(subject, list) and subject[0][0][0] == "CN"
          and subject[0][0][1].startswith("acme MDM Device "))

    other_scep = payload(shipped(StubTenant("acme", "Acme Inc")), "com.apple.security.scep")
    other_subject = (other_scep.get("PayloadContent") or {}).get("Subject") if other_scep else None
    check("successive profiles get distinct subjects",
          other_subject is not None and other_subject != subject)
    check("the key is a 2048-bit RSA key",
          inner.get("Keysize") == 2048 and inner.get("Key Type") == "RSA")
    # 5 = digitalSignature | keyEncipherment. step-ca encrypts the issued certificate back to the device key, so a
    # signing-only 1 breaks SCEP.
    check("Key Usage is 5, so the issued certificate can be encrypted back",
          inner.get("Key Usage") == 5)
    check("retries are set, so a lost round trip does not fail enrollment",
          inner.get("Retries") == 3 and inner.get("RetryDelay") == 10)


def test_mdm_payload():
    print("3) The MDM payload binds the device to this controller and tenant")
    parsed = shipped(StubTenant("acme", "Acme Inc"))
    mdm = payload(parsed, "com.apple.mdm")
    scep = payload(parsed, "com.apple.security.scep")
    check("there is exactly one MDM payload", mdm is not None)
    if mdm is None or scep is None:
        return

    query = parse_qs(urlparse(mdm.get("ServerURL", "")).query)
    check("ServerURL points at the configured MDM server",
          (mdm.get("ServerURL") or "").startswith("https://mdm.example.test/mdm?"))
    check("ServerURL carries the tenant", query.get("tenant") == ["acme"])
    check("ServerURL carries a tsig that verifies for that tenant",
          len(query.get("tsig", [])) == 1
          and enroll.verify_tenant_url_token("acme", query["tsig"][0]))
    check("that tsig does not verify for another tenant",
          not enroll.verify_tenant_url_token("other", query["tsig"][0]))
    check("Topic is the configured APNs topic", mdm.get("Topic") == TOPIC)
    # macOS 26.6.1 refuses the install outright without this key.
    check("ServerCapabilities declares user-channel support",
          "com.apple.mdm.per-user-connections" in (mdm.get("ServerCapabilities") or []))
    check("ServerCapabilities declares bootstrap token support",
          "com.apple.mdm.bootstraptoken" in (mdm.get("ServerCapabilities") or []))
    check("the identity certificate is the SCEP payload's",
          mdm.get("IdentityCertificateUUID") == scep.get("PayloadUUID"))
    check("all access rights are requested", mdm.get("AccessRights") == 8191)
    check("the device checks out when the profile is removed",
          mdm.get("CheckOutWhenRemoved") is True)
    check("check-ins are signed", mdm.get("SignMessage") is True)


def test_embedded_ca(tmp):
    print("4) A configured CA certificate is shipped as DER inside the profile")
    pem_path = os.path.join(tmp, "root_ca.pem")
    der = self_signed_ca(pem_path)

    os.environ["MDM_EMBED_CA_CERT_PATH"] = pem_path
    try:
        parsed = shipped(StubTenant("acme", "Acme Inc"))
        root = payload(parsed, "com.apple.security.root")
        check("the root payload is appended after SCEP and MDM",
              payload_types(parsed) == ["com.apple.security.scep", "com.apple.mdm",
                                        "com.apple.security.root"])
        check("there is exactly one root payload", root is not None)
        if root is None:
            return
        # A str here would serialize as <string> and the device would install a certificate made of base64 text.
        check("its PayloadContent survives the plist as bytes, so <data>",
              isinstance(root.get("PayloadContent"), bytes))
        check("those bytes are the certificate's DER, not its PEM",
              root.get("PayloadContent") == der)
        check("it is named for the organization",
              root.get("PayloadDisplayName") == "Acme Inc Certificate Authority")
        check("readiness holds nothing against a CA path that reads cleanly",
              enroll.embedded_ca_error() is None)
    finally:
        os.environ.pop("MDM_EMBED_CA_CERT_PATH", None)


def test_challenge_is_not_repeated(tmp):
    print("5) The SCEP challenge appears in the SCEP payload and nowhere else")
    pem_path = os.path.join(tmp, "root_ca.pem")
    self_signed_ca(pem_path)
    os.environ["MDM_EMBED_CA_CERT_PATH"] = pem_path
    try:
        tenant = StubTenant("acme", "Acme Inc")
        raw = enroll.build_enrollment_mobileconfig(tenant)
        check("the challenge is in the shipped bytes exactly once",
              raw.count(CHALLENGE.encode()) == 1)

        parsed = plistlib.loads(raw)
        mdm = payload(parsed, "com.apple.mdm")
        root = payload(parsed, "com.apple.security.root")
        check("it is not in the MDM payload",
              CHALLENGE not in repr(mdm))
        check("it is not in the root payload",
              CHALLENGE not in repr(root))
        outer_only = {k: v for k, v in parsed.items() if k != "PayloadContent"}
        check("it is not in the outer Configuration payload",
              CHALLENGE not in repr(outer_only))

        # The download token belongs to the URL that fetches this file, not to the file itself.
        check("the enrollment download token is not in the profile either",
              enroll.enrollment_token("acme").encode() not in raw)
    finally:
        os.environ.pop("MDM_EMBED_CA_CERT_PATH", None)


def test_broken_ca_path(tmp):
    """A set path that cannot be read: the builder drops the payload and readiness refuses upstream."""
    print("6) A set-but-unusable CA path is refused upstream, not raised here")
    cases = [
        ("a path that names nothing", os.path.join(tmp, "absent.pem"), None),
        ("a file with no CERTIFICATE block",
         os.path.join(tmp, "not-a-cert.pem"),
         "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n"),
        ("a CERTIFICATE block with nothing in it",
         os.path.join(tmp, "empty-block.pem"),
         "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"),
    ]
    for label, path, content in cases:
        if content is not None:
            with open(path, "w") as fh:
                fh.write(content)
        os.environ["MDM_EMBED_CA_CERT_PATH"] = path
        try:
            raised, parsed = None, None
            try:
                parsed = shipped(StubTenant("acme", "Acme Inc"))
            except Exception as exc:  # noqa: BLE001 - the point is that none escapes
                raised = exc
            check(f"{label}: the builder raises nothing", raised is None)
            check(f"{label}: the profile is the SCEP + MDM pair",
                  parsed is not None
                  and payload_types(parsed) == ["com.apple.security.scep", "com.apple.mdm"])

            error = enroll.embedded_ca_error()
            check(f"{label}: embedded_ca_error says what is wrong",
                  isinstance(error, str) and path in error)

            status = readiness.check(readiness.ENROLL)
            check(f"{label}: enrollment is not ready, so the download refuses",
                  not status.ready)
            # Set and unusable is a different problem from never set, and readiness reports the two separately.
            check(f"{label}: the setting is reported broken, not missing",
                  "MDM_EMBED_CA_CERT_PATH" in status.broken
                  and "MDM_EMBED_CA_CERT_PATH" not in status.missing)
        finally:
            os.environ.pop("MDM_EMBED_CA_CERT_PATH", None)

    check("unset again: enrollment is ready and nothing is broken",
          readiness.check(readiness.ENROLL).ready)


def test_cms_signing():
    print("7) CMS PKCS#7 signing with mock cert, key and chain")
    from controller.services import crypto_secrets
    from cryptography.hazmat.primitives.serialization import pkcs7

    # 1. Unsigned fallback when unconfigured
    t_unsigned = StubTenant("t-unsigned", "Unsigned Tenant")
    unsigned_bytes = enroll.build_enrollment_mobileconfig(t_unsigned)
    check("unsigned profile starts with xml header", unsigned_bytes.startswith(b"<?xml"))
    parsed_unsigned = plistlib.loads(unsigned_bytes)
    check("unsigned profile parses as plist", isinstance(parsed_unsigned, dict))

    # 2. Build mock PKI: Root CA -> Intermediate CA -> Leaf signing cert
    root_key = rsa.generate_private_key(65537, 2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    inter_key = rsa.generate_private_key(65537, 2048)
    inter_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")])
    inter_cert = (
        x509.CertificateBuilder()
        .subject_name(inter_name)
        .issuer_name(root_name)
        .public_key(inter_key.public_key())
        .serial_number(2)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(65537, 2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Profile Signer")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(inter_name)
        .public_key(leaf_key.public_key())
        .serial_number(3)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(inter_key, hashes.SHA256())
    )

    leaf_key_pem = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    leaf_cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    chain_pem = (
        inter_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        + root_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    )

    from controller.services import profile_signing
    encrypted_key = crypto_secrets.encrypt(leaf_key_pem, aad=profile_signing._key_binding("t-signed"))

    t_signed = StubTenant("t-signed", "Signed Tenant")
    t_signed.profile_signing_cert_pem = leaf_cert_pem
    t_signed.profile_signing_key_enc = encrypted_key
    t_signed.profile_signing_chain_pem = chain_pem

    signed_bytes = enroll.build_enrollment_mobileconfig(t_signed)
    check("signed profile is not raw xml", not signed_bytes.startswith(b"<?xml"))
    check("signed profile starts with DER sequence byte", signed_bytes[0] == 0x30)

    # Verify embedded certificates in the PKCS#7 signedData
    embedded_certs = pkcs7.load_der_pkcs7_certificates(signed_bytes)
    embedded_cns = [
        c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        for c in embedded_certs
    ]
    check("leaf cert is embedded in PKCS#7", "Profile Signer" in embedded_cns)
    check("intermediate cert is embedded in PKCS#7", "Intermediate CA" in embedded_cns)
    check("root cert is embedded in PKCS#7", "Root CA" in embedded_cns)

    # Verify payload extraction from CMS bytes
    extracted_profile = enroll._extract_plist(signed_bytes)
    check("embedded plist can be extracted from CMS bytes", extracted_profile is not None)
    if extracted_profile:
        check(
            "extracted profile matches tenant",
            extracted_profile.get("PayloadIdentifier") == "com.micromanage.t-signed.enroll",
        )
        mdm = payload(extracted_profile, "com.apple.mdm")
        check("MDM payload is present in extracted profile", mdm is not None)
        if mdm:
            caps = mdm.get("ServerCapabilities", [])
            check("ServerCapabilities retains per-user-connections", "com.apple.mdm.per-user-connections" in caps)
            check("ServerCapabilities retains bootstraptoken", "com.apple.mdm.bootstraptoken" in caps)

    moved = StubTenant("t-other", "Other Tenant")
    moved.profile_signing_cert_pem = leaf_cert_pem
    moved.profile_signing_key_enc = encrypted_key
    check("a signing key copied to another tenant does not sign, and the profile is served unsigned",
          enroll.build_enrollment_mobileconfig(moved).startswith(b"<?xml"))

    print("8) Importing a signing certificate")
    import asyncio

    class SavingTenant(StubTenant):
        async def save(self, update_fields=None):
            self.saved = update_fields

    def cert_for(key, *, days=365, usage=None):
        builder = (
            x509.CertificateBuilder()
            .subject_name(leaf_name)
            .issuer_name(inter_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=2))
            .not_valid_after(now + datetime.timedelta(days=days))
        )
        if usage is not None:
            builder = builder.add_extension(usage, critical=True)
        return builder.sign(inter_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode("ascii")

    from cryptography.hazmat.primitives.serialization import pkcs12

    def p12_of(key, cert_pem, cas=(), password=b"secret", legacy=False):
        cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
        if legacy:
            # The 3DES/SHA1 flavour that Keychain Access has long produced.
            enc = (serialization.PrivateFormat.PKCS12.encryption_builder()
                   .kdf_rounds(2048).key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
                   .hmac_hash(hashes.SHA1()).build(password))
        else:
            enc = serialization.BestAvailableEncryption(password)
        return pkcs12.serialize_key_and_certificates(b"signer", key, cert, list(cas), enc)

    def refused(p12, needle, password="secret", intermediates=()):
        try:
            asyncio.run(profile_signing.import_p12(SavingTenant("t-imp"), p12, password, intermediates))
        except ValueError as exc:
            return needle in str(exc)
        return False

    no_sign = x509.KeyUsage(False, False, True, False, False, False, False, False, False)
    check("a wrong .p12 password is refused", refused(p12_of(leaf_key, leaf_cert_pem), "Check the password", "nope"))
    check("an expired certificate is refused",
          refused(p12_of(leaf_key, cert_for(leaf_key, days=-1)), "expired"))
    check("a certificate without digitalSignature is refused",
          refused(p12_of(leaf_key, cert_for(leaf_key, usage=no_sign)), "digital signatures"))
    check("a file that is not a .p12 is refused", refused(b"not a p12 file", "Could not open the .p12"))
    cert_only = pkcs12.serialize_key_and_certificates(
        b"c", None, leaf_cert, None, serialization.BestAvailableEncryption(b"secret"))
    check("a .p12 without a private key is refused", refused(cert_only, "both a certificate and its private key"))
    check("a PEM intermediate is refused, since only .cer files are accepted",
          refused(p12_of(leaf_key, leaf_cert_pem), "not a .cer",
                  intermediates=[inter_cert.public_bytes(serialization.Encoding.PEM)]))

    weak_key = rsa.generate_private_key(65537, 1024)
    check("a 1024-bit RSA key is refused", refused(p12_of(weak_key, cert_for(weak_key)), "at least 2048 bits"))
    future = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(inter_name)
              .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now + datetime.timedelta(days=3)).not_valid_after(now + datetime.timedelta(days=30))
              .sign(inter_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode("ascii"))
    check("a certificate that is not valid yet is refused", refused(p12_of(leaf_key, future), "not valid yet"))
    other_leaf = cert_for(rsa.generate_private_key(65537, 2048))
    check("a non-CA certificate uploaded as an intermediate is refused",
          refused(p12_of(leaf_key, leaf_cert_pem), "is not a CA certificate",
                  intermediates=[x509.load_pem_x509_certificate(other_leaf.encode()).public_bytes(
                      serialization.Encoding.DER)]))
    leaf_as_inter = SavingTenant("t-leafdup")
    asyncio.run(profile_signing.import_p12(leaf_as_inter, p12_of(leaf_key, leaf_cert_pem), "secret",
                                           [leaf_cert.public_bytes(serialization.Encoding.DER)]))
    check("the signing certificate uploaded again as an intermediate is dropped, not refused",
          profile_signing.info(leaf_as_inter)["chain_count"] == 0)
    unencrypted = pkcs12.serialize_key_and_certificates(b"s", leaf_key, leaf_cert, None, serialization.NoEncryption())
    blank = SavingTenant("t-blank")
    asyncio.run(profile_signing.import_p12(blank, unencrypted, ""))
    check("a .p12 exported with no password opens with the password left blank", profile_signing.is_configured(blank))
    with tempfile.TemporaryDirectory() as tmp:
        key_path, cert_path, out_path = (os.path.join(tmp, n) for n in ("k.pem", "c.pem", "e.p12"))
        with open(key_path, "w") as fh:
            fh.write(leaf_key_pem)
        with open(cert_path, "w") as fh:
            fh.write(leaf_cert_pem)
        made = subprocess.run(["openssl", "pkcs12", "-export", "-inkey", key_path, "-in", cert_path,
                               "-passout", "pass:", "-out", out_path], capture_output=True)
        if made.returncode == 0:
            empty = SavingTenant("t-empty")
            with open(out_path, "rb") as fh:
                asyncio.run(profile_signing.import_p12(empty, fh.read(), ""))
            check("a .p12 exported with an empty password opens with the password left blank",
                  profile_signing.is_configured(empty))
        else:
            print("  (openssl CLI unavailable, skipping the empty-password .p12 case)")

    legacy = SavingTenant("t-legacy")
    asyncio.run(profile_signing.import_p12(legacy, p12_of(leaf_key, leaf_cert_pem, legacy=True), "secret"))
    check("a legacy 3DES .p12 like Keychain exports imports", profile_signing.is_configured(legacy))

    imported = SavingTenant("t-imp")
    der = serialization.Encoding.DER
    asyncio.run(profile_signing.import_p12(
        imported, p12_of(leaf_key, leaf_cert_pem, cas=[inter_cert]), "secret",
        [inter_cert.public_bytes(der), root_cert.public_bytes(der)]))
    check("a valid import records the expiry", imported.profile_signing_cert_expires_at is not None)
    check("the stored key is encrypted, not PEM", "PRIVATE KEY" not in imported.profile_signing_key_enc)
    status = profile_signing.info(imported)
    check("status reports the subject, with a duplicate intermediate counted once",
          status["configured"] and "Profile Signer" in status["subject"] and status["chain_count"] == 2)
    check("status never includes key material",
          not any(k in status for k in ("key", "key_pem", "private_key", "password")))
    check("status reports the key decrypts, not expired, not self-signed",
          status["key_decrypts"] is True and status["expired"] is False and status["self_signed"] is False)
    moved_status = SavingTenant("t-elsewhere")
    moved_status.profile_signing_cert_pem = imported.profile_signing_cert_pem
    moved_status.profile_signing_key_enc = imported.profile_signing_key_enc
    moved_status.profile_signing_chain_pem = None
    check("status flags a key that no longer decrypts", profile_signing.info(moved_status)["key_decrypts"] is False)
    lapsed = SavingTenant("t-lapsed")
    lapsed.profile_signing_cert_pem = cert_for(leaf_key, days=-1)
    lapsed.profile_signing_chain_pem = None
    lapsed.profile_signing_key_enc = crypto_secrets.encrypt(leaf_key_pem, aad=profile_signing._key_binding("t-lapsed"))
    check("status flags an expired certificate", profile_signing.info(lapsed)["expired"] is True)
    check("an expired certificate is not used to sign, and the profile is served unsigned",
          enroll.build_enrollment_mobileconfig(lapsed).startswith(b"<?xml"))
    check("an imported certificate signs the profile",
          enroll.build_enrollment_mobileconfig(imported)[0] == 0x30)


def main():
    test_top_level()
    test_scep_payload()
    test_mdm_payload()
    with tempfile.TemporaryDirectory() as tmp:
        test_embedded_ca(tmp)
        test_challenge_is_not_repeated(tmp)
        test_broken_ca_path(tmp)
    test_cms_signing()

    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        return 1
    return 0


from tests._verify_harness import run  # noqa: E402

run(main)
