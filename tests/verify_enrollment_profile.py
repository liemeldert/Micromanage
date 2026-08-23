"""What actually installs on a device: the enrollment .mobileconfig.

Run: PYTHONPATH=. .venv/bin/python tests/verify_enrollment_profile.py

Every value in services.enrollment.build_enrollment_profile comes from an environment variable, and a typo in any of
them produces a profile that still builds, still parses, and fails on the device with nothing on the server to look at.
So these checks run over the serialized bytes rather than the dict: plistlib parses what a Mac would parse, and each
payload is checked for the keys Apple requires of it.

Covered: the outer Configuration payload, its tenant identifiers and absent PayloadScope; the SCEP payload's URL, Name,
Subject, Challenge and key parameters; the MDM payload's ServerURL tenant plus a tsig that verifies, Topic,
ServerCapabilities and the SCEP payload's UUID as the identity certificate; a root-CA payload whose PayloadContent is
the certificate's DER as bytes, so the plist gets <data>; and the SCEP challenge appearing nowhere else. Last, a
set-but-unusable MDM_EMBED_CA_CERT_PATH: the builder omits the payload without raising, while embedded_ca_error and
readiness.check('enroll') report it broken, so the enrollment download refuses.
"""
import datetime
import os
import plistlib
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

PASS, FAIL = [], []

TOPIC = os.environ["MDM_TOPIC"]
SCEP_URL = os.environ["SCEP_URL"]
CHALLENGE = os.environ["SCEP_CHALLENGE"]


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


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


def main():
    test_top_level()
    test_scep_payload()
    test_mdm_payload()
    with tempfile.TemporaryDirectory() as tmp:
        test_embedded_ca(tmp)
        test_challenge_is_not_repeated(tmp)
        test_broken_ca_path(tmp)

    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        return 1
    return 0


from tests._verify_harness import run  # noqa: E402

run(main)
