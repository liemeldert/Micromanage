"""E2E checks that a device cannot pick its own tenant, on in-memory sqlite.

Run: PYTHONPATH=. .venv/bin/python tests/verify_tenant_binding.py
"""
import base64
import os
import plistlib
import tempfile
from urllib.parse import parse_qs, urlparse

os.environ["JWT_SECRET"] = "test-secret-for-tenant-binding"
os.environ["MDM_SERVER_URL"] = "https://mdm.example.test/mdm"
os.environ["MDM_TOPIC"] = "com.apple.mgmt.External.test"
os.environ["SCEP_CHALLENGE"] = "test-challenge"
os.environ["PUBLIC_API_URL"] = "https://mdm.example.test"
os.environ.pop("MDM_ALLOW_UNSIGNED_TENANT_CLAIM", None)
os.environ.pop("MDM_ENROLL_REQUIRE_KNOWN_SERIAL", None)
os.environ.pop("MDM_REQUIRE_SIGNED_TENANT_CLAIM", None)
# Popped so a shell that already has this set does not turn the "unset" checks into no-ops.
os.environ.pop("MDM_EMBED_CA_CERT_PATH", None)

from tortoise import Tortoise  # noqa: E402

from controller.auth.tokens import AuthConfigError  # noqa: E402
from controller.models.tenant import (  # noqa: E402
    Tenant, Device, EnrollmentAttempt, AuditLog,
)
from controller.services import enrollment as enroll  # noqa: E402
from controller.services.webhook_handler import (  # noqa: E402
    WebhookHandler, _resolve_tenant, _first_param, _log_attempt,
)

PASS, FAIL = [], []
SECRET = os.environ["JWT_SECRET"]


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


class StubTenant:
    """build_enrollment_profile / enrollment_details only read id + name."""

    def __init__(self, tid, name=None):
        self.id = tid
        self.name = name or tid


def _mdm_payload(profile):
    return next(p for p in profile["PayloadContent"]
                if p["PayloadType"] == "com.apple.mdm")


def _payload_types(profile):
    return [p["PayloadType"] for p in profile["PayloadContent"]]


# What every deployment that sets no CA path must keep getting.
_BASE_PAYLOADS = ["com.apple.security.scep", "com.apple.mdm"]


def _raises(fn, exc):
    try:
        fn()
        return False
    except exc:
        return True


def test_tokens():
    print("1) HMAC helpers fail closed and are tenant-specific")
    a1 = enroll.tenant_url_token("alpha")
    a2 = enroll.tenant_url_token("alpha")
    b = enroll.tenant_url_token("beta")
    check("tenant_url_token is deterministic", a1 == a2 and len(a1) == 32)
    check("tenant_url_token differs per tenant", a1 != b)
    check("valid token verifies", enroll.verify_tenant_url_token("alpha", a1))
    check("token minted for another tenant is rejected",
          not enroll.verify_tenant_url_token("alpha", b))
    mutated = ("0" if a1[0] != "0" else "1") + a1[1:]
    check("one-character mutation is rejected",
          not enroll.verify_tenant_url_token("alpha", mutated))
    check("empty token is rejected", not enroll.verify_tenant_url_token("alpha", ""))
    check("None token is rejected", not enroll.verify_tenant_url_token("alpha", None))
    check("empty tenant id is rejected", not enroll.verify_tenant_url_token("", a1))

    # Two tokens use the same key; they must be kept separate.
    check("tenant signature is NOT the enrollment-download token",
          enroll.enrollment_token("alpha") != a1)
    check("enrollment-download token does not verify as a tenant signature",
          not enroll.verify_tenant_url_token("alpha", enroll.enrollment_token("alpha")))

    # Fail closed: empty key would expose every signature.
    for label, value in (("unset", None), ("the shipped placeholder",
                                           "your-secret-key-change-in-production")):
        if value is None:
            os.environ.pop("JWT_SECRET", None)
        else:
            os.environ["JWT_SECRET"] = value
        check(f"tenant_url_token raises when JWT_SECRET is {label}",
              _raises(lambda: enroll.tenant_url_token("alpha"), AuthConfigError))
        check(f"verify_tenant_url_token returns False when JWT_SECRET is {label}",
              not enroll.verify_tenant_url_token("alpha", a1))
        check(f"enrollment_token raises when JWT_SECRET is {label}",
              _raises(lambda: enroll.enrollment_token("alpha"), AuthConfigError))
        check(f"verify_enrollment_token returns False when JWT_SECRET is {label}",
              not enroll.verify_enrollment_token("alpha", "anything"))
        check(f"enrollment_details reports JWT_SECRET missing when it is {label}",
              "JWT_SECRET" in enroll.enrollment_details(StubTenant("alpha"))["missing"])
        os.environ["JWT_SECRET"] = SECRET
    check("JWT_SECRET restored for the rest of the run",
          enroll.verify_tenant_url_token("alpha", a1))


def test_profile_shape():
    print("2) The generated profile ships a signed, encoded tenant claim")
    profile = enroll.build_enrollment_profile(StubTenant("alpha", "Alpha Inc"))
    url = _mdm_payload(profile)["ServerURL"]
    q = parse_qs(urlparse(url).query)
    check("ServerURL carries a tenant", q.get("tenant") == ["alpha"])
    check("ServerURL carries a tsig", len(q.get("tsig", [])) == 1)
    check("the shipped tsig verifies for that tenant",
          enroll.verify_tenant_url_token("alpha", q["tsig"][0]))
    check("the shipped tsig does not verify for another tenant",
          not enroll.verify_tenant_url_token("beta", q["tsig"][0]))
    # macOS requires ServerCapabilities to declare user-channel support.
    check("the MDM payload declares user-channel support",
          "com.apple.mdm.per-user-connections"
          in _mdm_payload(profile).get("ServerCapabilities", []))

    # Tenant ids with query-string metacharacters must round-trip safely into the signature.
    weird = "we&ird=id#x"
    q2 = parse_qs(urlparse(enroll._server_url_for(weird)).query)
    check("a tenant id with &, = and # round-trips intact",
          q2.get("tenant") == [weird])
    check("its signature still verifies after encoding",
          enroll.verify_tenant_url_token(weird, q2["tsig"][0]))

    check("_first_param unwraps Go url.Values lists",
          _first_param({"tenant": ["a"]}, "tenant") == "a"
          and _first_param({"tenant": "a"}, "tenant") == "a"
          and _first_param({"tenant": []}, "tenant") is None
          and _first_param(None, "tenant") is None)

    test_embedded_ca_payload(profile)


def test_embedded_ca_payload(unset_profile):
    """MDM_EMBED_CA_CERT_PATH: the opt-in root-CA payload.

    Bad values degrade to the base profile rather than fail; unset leaves it alone.
    """
    print("2b) MDM_EMBED_CA_CERT_PATH adds a root-CA payload, and only when it works")
    check("unset: the profile is the SCEP + MDM pair it has always been",
          _payload_types(unset_profile) == _BASE_PAYLOADS)

    # Fake DER: the builder strips armour and base64-decodes without parsing, proving the round-trip.
    der = bytes(range(256)) * 3
    b64 = base64.b64encode(der).decode()
    pem = ("-----BEGIN CERTIFICATE-----\n"
           + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
           + "\n-----END CERTIFICATE-----\n")

    with tempfile.TemporaryDirectory() as tmp:
        pem_path = os.path.join(tmp, "root_ca.crt")
        with open(pem_path, "w") as fh:
            fh.write(pem)
        try:
            os.environ["MDM_EMBED_CA_CERT_PATH"] = pem_path
            p = enroll.build_enrollment_profile(StubTenant("alpha", "Alpha Inc"))
            roots = [x for x in p["PayloadContent"]
                     if x["PayloadType"] == "com.apple.security.root"]
            check("set: exactly one com.apple.security.root payload is added",
                  len(roots) == 1)
            check("...appended, with the SCEP and MDM payloads untouched",
                  _payload_types(p) == _BASE_PAYLOADS + ["com.apple.security.root"])
            check("...carrying the PEM's DER (armour stripped, base64-decoded)",
                  len(roots) == 1 and roots[0].get("PayloadContent") == der)
            check("...as bytes, so the .mobileconfig gets <data> and not a string",
                  len(roots) == 1 and isinstance(roots[0].get("PayloadContent"), bytes))
            # The dict is not what installs on a device; the plist bytes are.
            shipped = plistlib.loads(
                enroll.build_enrollment_mobileconfig(StubTenant("alpha", "Alpha Inc")))
            check("...and the DER survives into the shipped .mobileconfig",
                  [x["PayloadContent"] for x in shipped["PayloadContent"]
                   if x["PayloadType"] == "com.apple.security.root"] == [der])

            # A path that names nothing. Enrollment must not break when an optional knob is wrong, so this is a logged
            # error and the base profile, not an exception out of the builder.
            os.environ["MDM_EMBED_CA_CERT_PATH"] = os.path.join(tmp, "absent.crt")
            raised, p = None, None
            try:
                p = enroll.build_enrollment_profile(StubTenant("alpha", "Alpha Inc"))
            except Exception as exc:  # noqa: BLE001 - the point is that none escapes
                raised = exc
            check("a path that does not exist raises nothing", raised is None)
            check("...and yields the profile without a root payload",
                  p is not None and _payload_types(p) == _BASE_PAYLOADS)

            # Non-certificate files also degrade gracefully.
            junk_path = os.path.join(tmp, "not-a-cert.pem")
            with open(junk_path, "w") as fh:
                fh.write("-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n")
            os.environ["MDM_EMBED_CA_CERT_PATH"] = junk_path
            raised, p = None, None
            try:
                p = enroll.build_enrollment_profile(StubTenant("alpha", "Alpha Inc"))
            except Exception as exc:  # noqa: BLE001
                raised = exc
            check("a file with no certificate in it raises nothing", raised is None)
            check("...and also yields the profile without a root payload",
                  p is not None and _payload_types(p) == _BASE_PAYLOADS)
        finally:
            os.environ.pop("MDM_EMBED_CA_CERT_PATH", None)

    check("unset again: later profiles are back to the SCEP + MDM pair",
          _payload_types(enroll.build_enrollment_profile(StubTenant("alpha")))
          == _BASE_PAYLOADS)


async def test_resolve_multi_tenant():
    print("3) _resolve_tenant with several tenants: only a signed claim wins")
    await Tenant.create(id="a", name="Alpha")
    await Tenant.create(id="b", name="Beta")
    await Tenant.create(id="default", name="Default")
    sig_a = enroll.tenant_url_token("a")

    t, why = await _resolve_tenant({"tenant": "a", "tsig": sig_a})
    check("a validly signed claim resolves", t is not None and t.id == "a" and why == "signed")

    # Attack: editing tenant= in a held profile redirects to a different tenant.
    t, why = await _resolve_tenant({"tenant": "b", "tsig": sig_a})
    check("a claim for tenant b signed with a's token is refused",
          t is None and why == "bad_signature")
    t, why = await _resolve_tenant({"tenant": "b"})
    check("an unsigned claim for a real tenant is refused",
          t is None and why == "bad_signature")
    t, why = await _resolve_tenant({"tenant": "b", "tsig": "garbage"})
    check("a garbage signature is refused", t is None and why == "bad_signature")

    # No parameter means no claim, no fallback to "default".
    t, why = await _resolve_tenant({})
    check("no claim at all resolves to nothing, not to the 'default' tenant",
          t is None and why == "ambiguous")
    check("...and a tenant named 'default' really is present to have fallen into",
          await Tenant.get_or_none(id="default") is not None)

    t, why = await _resolve_tenant({"tenant": ["a"], "tsig": [sig_a]})
    check("Go-style list params resolve", t is not None and t.id == "a" and why == "signed")

    t, why = await _resolve_tenant({"tenant": "gone", "tsig": enroll.tenant_url_token("gone")})
    check("a valid signature for a deleted tenant resolves to nothing",
          t is None and why == "unknown_tenant")
    t, why = await _resolve_tenant({"tenant": "never-existed"})
    check("an unsigned claim for a tenant that never existed is not called an attack",
          t is None and why == "unknown_tenant")


async def test_migration_switch():
    print("4) MDM_ALLOW_UNSIGNED_TENANT_CLAIM reopens the old behaviour, bounded")
    os.environ["MDM_ALLOW_UNSIGNED_TENANT_CLAIM"] = "true"
    try:
        t, why = await _resolve_tenant({"tenant": "b"})
        check("legacy mode honours an unsigned claim",
              t is not None and t.id == "b" and why == "legacy_unsigned")
        t, why = await _resolve_tenant({})
        check("legacy mode restores the 'default' fallback",
              t is not None and t.id == "default" and why == "legacy_unsigned")
        t, why = await _resolve_tenant({"tenant": "a", "tsig": enroll.tenant_url_token("a")})
        check("legacy mode still prefers a valid signature",
              t is not None and t.id == "a" and why == "signed")
    finally:
        os.environ.pop("MDM_ALLOW_UNSIGNED_TENANT_CLAIM", None)
    t, why = await _resolve_tenant({"tenant": "b"})
    check("unsetting the switch re-closes the hole", t is None and why == "bad_signature")


async def test_resolve_sole_tenant():
    print("5) Single-tenant installs are unaffected, signed or not")
    await Device.all().delete()
    await EnrollmentAttempt.all().delete()
    await AuditLog.all().delete()
    await Tenant.all().delete()
    await Tenant.create(id="solo", name="Solo")

    t, why = await _resolve_tenant({})
    check("no claim resolves to the only tenant",
          t is not None and t.id == "solo" and why == "sole_tenant")
    t, why = await _resolve_tenant({"tenant": "solo"})
    check("an unsigned claim still resolves to the only tenant",
          t is not None and t.id == "solo" and why == "sole_tenant")
    t, why = await _resolve_tenant({"tenant": "someone-else", "tsig": "bogus"})
    check("even a forged claim resolves to the only tenant (no boundary to cross)",
          t is not None and t.id == "solo" and why == "sole_tenant")
    t, why = await _resolve_tenant({"tenant": "solo", "tsig": enroll.tenant_url_token("solo")})
    check("a signed claim resolves to the only tenant",
          t is not None and t.id == "solo" and why == "signed")

    await Tenant.all().delete()


async def test_upsert_end_to_end():
    print("6) _upsert_device: forged claims create nothing, valid ones enrol")
    handler = WebhookHandler()
    await Tenant.create(id="a", name="Alpha")
    await Tenant.create(id="b", name="Beta")
    await Tenant.create(id="default", name="Default")
    sig_a = enroll.tenant_url_token("a")

    dev = await handler._upsert_device(
        "UDID-FORGED", {"tenant": "b", "tsig": sig_a},
        {"SerialNumber": "SN-FORGED"}, topic="mdm.Authenticate",
    )
    check("forged claim enrols nothing", dev is None)
    check("forged claim creates no Device row",
          await Device.get_or_none(udid="UDID-FORGED") is None)
    attempts = await EnrollmentAttempt.filter(outcome="bad_tenant_claim").all()
    check("forged claim logs exactly one bad_tenant_claim", len(attempts) == 1)
    if attempts:
        a = attempts[0]
        check("bad_tenant_claim keeps the unverified id out of the FK", a.tenant_id is None)
        check("bad_tenant_claim records the requested id in detail only",
              a.detail.get("requested_tenant") == "b")
        check("bad_tenant_claim records the udid", a.udid == "UDID-FORGED")

    await handler._upsert_device(
        "UDID-FORGED", {"tenant": "b", "tsig": sig_a},
        {"SerialNumber": "SN-FORGED"}, topic="mdm.TokenUpdate",
    )
    attempts = await EnrollmentAttempt.filter(outcome="bad_tenant_claim").all()
    check("a repeating forged claim dedupes to one row (no table flood)",
          len(attempts) == 1 and attempts[0].detail.get("count") == 2)

    dev = await handler._upsert_device(
        "UDID-GOOD", {"tenant": "a", "tsig": sig_a},
        {"SerialNumber": "SN-GOOD", "ProductName": "Mac14,2", "OSVersion": "15.0"},
        topic="mdm.Authenticate",
    )
    check("a validly signed claim enrols", dev is not None)
    check("the device is created in the claimed tenant", dev is not None and dev.tenant_id == "a")


async def test_existing_fleet_untouched():
    """Fleet safety: old installs with unsigned URLs still work.

    This proves no security property (test 10 covers that); see docs for full context.
    """
    print("7) Already-enrolled devices are untouched (the load-bearing claim)")
    handler = WebhookHandler()
    tenant_a = await Tenant.get(id="a")
    await Device.create(tenant=tenant_a, udid="UDID-LIVE", serial_number="SN-LIVE",
                        device_model="Mac14,2", os_version="15.0",
                        enrollment_state="enrolled", attributes={}, groups=[], tags=[])
    before = await EnrollmentAttempt.all().count()

    # An enrolled device keeps checking in with whatever ServerURL it installed months ago: no tsig at all, or (hostile
    # case) another tenant's id.
    for label, params in (("with no tenant claim", {}),
                          ("with a forged claim for tenant b", {"tenant": "b"})):
        dev = await handler._upsert_device(
            "UDID-LIVE", params, {}, topic="mdm.Connect")
        row = await Device.get_or_none(udid="UDID-LIVE")
        check(f"an enrolled device still resolves {label}", dev is not None)
        check(f"it stays in its own tenant {label}",
              row is not None and row.tenant_id == "a")
        check(f"it stays enrolled {label}",
              row is not None and row.enrollment_state == "enrolled")
    check("no enrollment attempt was logged for the live device",
          await EnrollmentAttempt.all().count() == before)


async def test_rekey_audit():
    print("8) A serial re-key is audited")
    handler = WebhookHandler()
    tenant_a = await Tenant.get(id="a")
    sig_a = enroll.tenant_url_token("a")
    await AuditLog.all().delete()

    # ADE placeholder adoption is a first enrollment, writes no audit.
    await Device.create(tenant=tenant_a, udid=None, serial_number="SN-PLACEHOLDER",
                        device_model="Mac", os_version="", enrollment_state="pending",
                        attributes={}, groups=[], tags=[])
    await handler._upsert_device(
        "UDID-ADOPTED", {"tenant": "a", "tsig": sig_a},
        {"SerialNumber": "SN-PLACEHOLDER"}, topic="mdm.Authenticate")
    check("adopting a placeholder writes no re-key audit",
          await AuditLog.filter(action="device.rekey").count() == 0)

    # Real re-key: same serial, new udid on an already-enrolled row.
    await handler._upsert_device(
        "UDID-REKEYED", {"tenant": "a", "tsig": sig_a},
        {"SerialNumber": "SN-PLACEHOLDER"}, topic="mdm.Authenticate")
    logs = await AuditLog.filter(action="device.rekey").all()
    check("a re-key writes exactly one audit row", len(logs) == 1)
    if logs:
        log = logs[0]
        check("the re-key audit is scoped to the device's tenant", log.tenant_id == "a")
        check("the re-key audit is marked machine-originated",
              log.actor_email is None and log.actor_role is None)
        check("the re-key audit carries both udids",
              log.detail.get("old_udid") == "UDID-ADOPTED"
              and log.detail.get("new_udid") == "UDID-REKEYED")
        check("the re-key audit carries the serial",
              log.detail.get("serial") == "SN-PLACEHOLDER")


async def test_require_known_serial():
    print("9) MDM_ENROLL_REQUIRE_KNOWN_SERIAL gates creation on pre-provisioning")
    handler = WebhookHandler()
    tenant_a = await Tenant.get(id="a")
    sig_a = enroll.tenant_url_token("a")
    params = {"tenant": "a", "tsig": sig_a}

    os.environ["MDM_ENROLL_REQUIRE_KNOWN_SERIAL"] = "true"
    try:
        dev = await handler._upsert_device(
            "UDID-STRANGER", params, {"SerialNumber": "SN-STRANGER"},
            topic="mdm.Authenticate")
        check("an unprovisioned serial is refused", dev is None)
        check("an unprovisioned serial creates no Device row",
              await Device.get_or_none(udid="UDID-STRANGER") is None)
        rows = await EnrollmentAttempt.filter(outcome="unknown_serial").all()
        check("an unprovisioned serial logs unknown_serial", len(rows) == 1)
        if rows:
            check("unknown_serial is scoped to the resolved tenant FK",
                  rows[0].tenant_id == "a" and rows[0].serial_number == "SN-STRANGER")

        await Device.create(tenant=tenant_a, udid=None, serial_number="SN-KNOWN",
                            device_model="Mac", os_version="",
                            enrollment_state="pending", attributes={}, groups=[], tags=[])
        dev = await handler._upsert_device(
            "UDID-KNOWN", params, {"SerialNumber": "SN-KNOWN"}, topic="mdm.Authenticate")
        check("a pre-provisioned serial still enrols", dev is not None)
    finally:
        os.environ.pop("MDM_ENROLL_REQUIRE_KNOWN_SERIAL", None)

    dev = await handler._upsert_device(
        "UDID-STRANGER-2", params, {"SerialNumber": "SN-STRANGER-2"},
        topic="mdm.Authenticate")
    check("with the switch off, an unknown serial enrols as before", dev is not None)


async def _fresh_fleet():
    """Two tenants and one enrolled device in 'a'. Returns the device row."""
    await Device.all().delete()
    await EnrollmentAttempt.all().delete()
    await AuditLog.all().delete()
    await Tenant.all().delete()
    tenant_a = await Tenant.create(id="a", name="Alpha")
    await Tenant.create(id="b", name="Beta")
    return await Device.create(
        tenant=tenant_a, udid="UDID-TARGET", serial_number="SN-TARGET",
        device_model="Mac14,2", os_version="15.0", hostname="target-mac",
        enrollment_state="enrolled", attributes={}, groups=[], tags=[])


async def test_known_udid_conflicting_claim():
    print("10) A known udid does NOT skip the tenant check")
    handler = WebhookHandler()
    await _fresh_fleet()
    sig_b = enroll.tenant_url_token("b")

    # Attack: SCEP challenge is global (tenant-agnostic certs), udids are public; assert a victim's udid with your tsig.
    dev = await handler._upsert_device(
        "UDID-TARGET", {"tenant": "b", "tsig": sig_b},
        {"SerialNumber": "SN-ATTACKER", "DeviceName": "pwned",
         "ProductName": "MacAttack1,1", "OSVersion": "99.9"},
        topic="mdm.Authenticate")
    row = await Device.get_or_none(udid="UDID-TARGET")
    check("a verified claim that contradicts the row is refused", dev is None)
    check("the row stays in its own tenant", row.tenant_id == "a")
    # Refusal before any attacker-supplied field reaches the row.
    check("the row's serial is NOT overwritten", row.serial_number == "SN-TARGET")
    check("the row's hostname is NOT overwritten", row.hostname == "target-mac")
    check("the row's model is NOT overwritten", row.device_model == "Mac14,2")
    check("the row's os_version is NOT overwritten", row.os_version == "15.0")

    attempts = await EnrollmentAttempt.filter(outcome="bad_tenant_claim").all()
    check("the refusal is recorded", len(attempts) == 1)
    if attempts:
        a = attempts[0]
        # Scoped to the row's tenant (database fact), visible to the targeted tenant only.
        check("the attempt is scoped to the TARGETED tenant, so they can see it",
              a.tenant_id == "a")
        check("the attempt names the claimed tenant in detail only",
              a.detail.get("claimed_tenant") == "b"
              and a.detail.get("reason") == "tenant_conflict")
        check("the attempt records the serial the attacker asserted",
              a.detail.get("reported_serial") == "SN-ATTACKER")

    for _ in range(4):
        await handler._upsert_device(
            "UDID-TARGET", {"tenant": "b", "tsig": sig_b},
            {"SerialNumber": "SN-ATTACKER"}, topic="mdm.Connect")
    attempts = await EnrollmentAttempt.filter(outcome="bad_tenant_claim").all()
    check("repeats dedupe to one row with a count (no table flood)",
          len(attempts) == 1 and attempts[0].detail.get("count") == 5)
    check("and write no audit rows (AuditLog has no dedupe)",
          await AuditLog.all().count() == 0)

    # Unenrolled device (cheaper target, no serial change needed) is guarded the same way.
    row = await Device.get_or_none(udid="UDID-TARGET")
    row.enrollment_state = "unenrolled"
    await row.save()
    dev = await handler._upsert_device(
        "UDID-TARGET", {"tenant": "b", "tsig": sig_b}, {}, topic="mdm.TokenUpdate")
    row = await Device.get_or_none(udid="UDID-TARGET")
    check("an unenrolled row is not resurrected by a foreign signed claim",
          dev is None and row.enrollment_state == "unenrolled")

    # Correctly-enrolled device's ServerURL carries tenant+tsig; it always agrees, no cost.
    before = [(r.id, r.detail.get("count"))
              for r in await EnrollmentAttempt.all().order_by("id")]
    dev = await handler._upsert_device(
        "UDID-TARGET", {"tenant": "a", "tsig": enroll.tenant_url_token("a")},
        {"SerialNumber": "SN-TARGET", "OSVersion": "15.1"}, topic="mdm.Connect")
    row = await Device.get_or_none(udid="UDID-TARGET")
    check("the device's own signed check-in still works", dev is not None)
    check("...and still updates its facts", row.os_version == "15.1")
    after = [(r.id, r.detail.get("count"))
             for r in await EnrollmentAttempt.all().order_by("id")]
    check("...and neither adds nor bumps an enrollment-attempt row",
          after == before)

    # Pre-signature profile sends no tsig; unsigned proves nothing, falls through unchanged (residual gap).
    dev = await handler._upsert_device(
        "UDID-TARGET", {}, {"SerialNumber": "SN-TARGET", "OSVersion": "15.2"},
        topic="mdm.Connect")
    row = await Device.get_or_none(udid="UDID-TARGET")
    check("a pre-fix device with no tsig still checks in",
          dev is not None and row.os_version == "15.2")
    dev = await handler._upsert_device(
        "UDID-TARGET", {"tenant": "b"}, {"SerialNumber": "SN-TARGET"},
        topic="mdm.Connect")
    check("an UNSIGNED foreign claim also falls through (it proves nothing)",
          dev is not None)


async def test_udid_rekey_is_audited():
    print("11) A takeover on a known udid is audited, not just the serial path")
    handler = WebhookHandler()
    await _fresh_fleet()

    # Both identifiers hardware-derived; genuine device won't change serial on same udid. Stays permitted, is audited.
    dev = await handler._upsert_device(
        "UDID-TARGET", {}, {"SerialNumber": "SN-STOLEN"}, topic="mdm.Authenticate")
    logs = await AuditLog.filter(action="device.rekey").all()
    check("the check-in is still accepted (no behaviour change)", dev is not None)
    check("a udid-matched serial change writes exactly one audit row", len(logs) == 1)
    if logs:
        log = logs[0]
        check("the audit is scoped to the device's tenant", log.tenant_id == "a")
        check("the audit says which identifier matched", log.detail.get("matched_on") == "udid")
        check("the audit carries both serials",
              log.detail.get("old_serial") == "SN-TARGET"
              and log.detail.get("new_serial") == "SN-STOLEN")
        check("the audit keeps the udid pair (unchanged on this path)",
              log.detail.get("old_udid") == "UDID-TARGET"
              and log.detail.get("new_udid") == "UDID-TARGET")

    # Once persisted, the next check-in agrees with the row, so the signal is one-per-change rather than
    # one-per-check-in.
    await handler._upsert_device(
        "UDID-TARGET", {}, {"SerialNumber": "SN-STOLEN"}, topic="mdm.Connect")
    check("a repeat check-in on the settled serial is silent",
          await AuditLog.filter(action="device.rekey").count() == 1)
    # A check-in that reports no serial at all (a bare Connect/Idle) must not read as a change either.
    await handler._upsert_device("UDID-TARGET", {}, {}, topic="mdm.Connect")
    check("a serial-less check-in is silent",
          await AuditLog.filter(action="device.rekey").count() == 1)


async def test_malformed_tsig():
    print("12) Malformed and non-ASCII signatures fail closed AND leave a trace")
    handler = WebhookHandler()
    await _fresh_fleet()

    # hmac.compare_digest over two str raises TypeError on any non-ASCII input. Left to propagate it reaches the
    # webhook's blanket except, which fails closed but records nothing and abandons the rest of the check-in.
    hostile = {
        "non-ASCII": "abcdé",
        "emoji": "sig-\U0001f600",
        "lone surrogate": "sig-\ud800",
        "NUL byte": "sig-\x00",
        "very long": "a" * 10000,
        "empty": "",
    }
    for label, tsig in hostile.items():
        try:
            ok = enroll.verify_tenant_url_token("a", tsig)
            check(f"verify_tenant_url_token returns False for a {label} tsig", ok is False)
        except Exception as e:
            check(f"verify_tenant_url_token returns False for a {label} tsig",
                  f"raised {type(e).__name__}" == "")
        try:
            ok = enroll.verify_enrollment_token("a", tsig)
            check(f"verify_enrollment_token returns False for a {label} token", ok is False)
        except Exception as e:
            check(f"verify_enrollment_token returns False for a {label} token",
                  f"raised {type(e).__name__}" == "")
        try:
            t, why = await _resolve_tenant({"tenant": "a", "tsig": tsig})
            check(f"_resolve_tenant refuses a {label} tsig as bad_signature",
                  t is None and why == "bad_signature")
        except Exception as e:
            check(f"_resolve_tenant refuses a {label} tsig as bad_signature",
                  f"raised {type(e).__name__}" == "")

    # A probe for an unknown udid is recorded.
    dev = await handler._upsert_device(
        "UDID-PROBE", {"tenant": "a", "tsig": "abcdé"},
        {"SerialNumber": "SN-PROBE"}, topic="mdm.Authenticate")
    check("a non-ASCII probe enrols nothing", dev is None)
    rows = await EnrollmentAttempt.filter(udid="UDID-PROBE").all()
    check("a non-ASCII probe is recorded rather than silently swallowed",
          len(rows) == 1 and rows[0].outcome == "bad_tenant_claim")

    # The check-in handler must not abort on this input.
    raised = None
    try:
        await handler.handle_webhook({
            "topic": "mdm.Authenticate",
            "checkin_event": {"udid": "UDID-PROBE-2",
                              "url_params": {"tenant": "a", "tsig": "abcdé"},
                              "raw_payload": None},
        })
    except Exception as e:  # noqa: BLE001 - the point is that nothing escapes
        raised = e
    check("handle_webhook does not raise on a non-ASCII tsig", raised is None)

    # A non-ASCII claim against a KNOWN udid must not raise either. It is not a verified claim, so the row falls through
    # untouched.
    dev = await handler._upsert_device(
        "UDID-TARGET", {"tenant": "b", "tsig": "abcdé"},
        {"SerialNumber": "SN-TARGET"}, topic="mdm.Connect")
    check("a non-ASCII claim on a known udid falls through, no raise",
          dev is not None)


async def test_inactive_tenant():
    print("13) A deactivated tenant stops taking new enrollments")
    handler = WebhookHandler()
    await _fresh_fleet()
    # Three tenants so the sole-tenant fallback is not what we are measuring.
    await Tenant.create(id="c", name="Gamma")
    sig_b = enroll.tenant_url_token("b")
    beta = await Tenant.get(id="b")
    beta.is_active = False
    await beta.save()
    try:
        t, why = await _resolve_tenant({"tenant": "b", "tsig": sig_b})
        check("a properly signed claim for a deactivated tenant is refused",
              t is None and why == "inactive_tenant")
        check("it is NOT reported as an attack (it is an offboarded tenant)",
              why != "bad_signature")
        dev = await handler._upsert_device(
            "UDID-OFFBOARDED", {"tenant": "b", "tsig": sig_b},
            {"SerialNumber": "SN-OFFBOARDED"}, topic="mdm.Authenticate")
        check("no device is created in a deactivated tenant", dev is None)
        check("...and no Device row appears",
              await Device.get_or_none(udid="UDID-OFFBOARDED") is None)
        rows = await EnrollmentAttempt.filter(udid="UDID-OFFBOARDED").all()
        check("the drop is recorded as a misconfiguration, not an attack",
              len(rows) == 1 and rows[0].outcome == "no_tenant"
              and rows[0].detail.get("reason") == "inactive_tenant")
        # Every other enrollment surface checks is_active as well.
        t, why = await _resolve_tenant({"tenant": "a", "tsig": enroll.tenant_url_token("a")})
        check("an active tenant is unaffected", t is not None and t.id == "a")

        # A single-tenant install is exempt on purpose: sole_tenant counts inactive tenants, so deactivating the only
        # tenant does not stop enrollment.
        await Device.all().delete()
        await Tenant.filter(id__in=["b", "c"]).delete()
        await Tenant.all().update(is_active=False)
        t, why = await _resolve_tenant({})
        check("a single-tenant install still resolves even when deactivated",
              t is not None and why == "sole_tenant")
    finally:
        await Tenant.all().update(is_active=True)


async def test_attempt_log_is_tenant_scoped():
    print("14) One tenant cannot rewrite another's enrollment-attempt row")
    await _fresh_fleet()
    a = await Tenant.get(id="a")
    b = await Tenant.get(id="b")

    # Dedupe keyed on (tenant, udid, outcome); global lookup would let b overwrite a's records.
    await _log_attempt("no_serial", tenant=a, udid="UDID-SHARED",
                       serial_number="SN-A", topic="mdm.Authenticate",
                       detail={"owner": "a"})
    await _log_attempt("no_serial", tenant=b, udid="UDID-SHARED",
                       serial_number="SN-B", topic="mdm.TokenUpdate",
                       detail={"owner": "b"})
    rows = await EnrollmentAttempt.filter(udid="UDID-SHARED", outcome="no_serial").all()
    check("the same (udid, outcome) in two tenants keeps two rows", len(rows) == 2)
    row_a = await EnrollmentAttempt.filter(
        udid="UDID-SHARED", outcome="no_serial", tenant_id="a").first()
    row_b = await EnrollmentAttempt.filter(
        udid="UDID-SHARED", outcome="no_serial", tenant_id="b").first()
    check("tenant a's row is intact",
          row_a is not None and row_a.serial_number == "SN-A"
          and row_a.detail.get("owner") == "a" and row_a.topic == "mdm.Authenticate")
    check("tenant b's row is its own",
          row_b is not None and row_b.serial_number == "SN-B"
          and row_b.detail.get("owner") == "b")
    check("neither row absorbed the other's count",
          row_a.detail.get("count") == 1 and row_b.detail.get("count") == 1)

    # Dedupe still works within one tenant, which is what bounds the table.
    await _log_attempt("no_serial", tenant=a, udid="UDID-SHARED",
                       serial_number="SN-A", topic="mdm.Connect", detail={"owner": "a"})
    rows = await EnrollmentAttempt.filter(udid="UDID-SHARED", outcome="no_serial").all()
    row_a = await EnrollmentAttempt.filter(
        udid="UDID-SHARED", outcome="no_serial", tenant_id="a").first()
    check("a repeat within one tenant still dedupes",
          len(rows) == 2 and row_a.detail.get("count") == 2)

    # Tenant-less rows dedupe among themselves, never merge into a tenant's row.
    await _log_attempt("no_tenant", tenant=None, udid="UDID-SHARED", detail={"owner": None})
    await _log_attempt("no_tenant", tenant=None, udid="UDID-SHARED", detail={"owner": None})
    orphans = await EnrollmentAttempt.filter(
        udid="UDID-SHARED", outcome="no_tenant", tenant_id__isnull=True).all()
    check("unscoped rows dedupe among themselves",
          len(orphans) == 1 and orphans[0].detail.get("count") == 2)


async def test_tsig_is_a_bearer_token():
    """tsig binds to tenant, not device. See docs for the bearer model."""
    print("15) BY DESIGN: tsig is a bearer claim on a TENANT, not on a device")
    handler = WebhookHandler()
    await _fresh_fleet()
    sig_a = enroll.tenant_url_token("a")

    # Static HMAC over tenant id only: bearer token for the enrollment profile's tenant.
    check("the signature is a pure function of the tenant id (no nonce/expiry)",
          enroll.tenant_url_token("a") == sig_a == enroll.tenant_url_token("a"))
    for i in range(3):
        dev = await handler._upsert_device(
            f"UDID-BEARER-{i}", {"tenant": "a", "tsig": sig_a},
            {"SerialNumber": f"SN-BEARER-{i}"}, topic="mdm.Authenticate")
        check(f"the same tsig enrols an unrelated device #{i} into tenant a",
              dev is not None and dev.tenant_id == "a")
    check("it is not consumed by use", enroll.verify_tenant_url_token("a", sig_a))
    check("nothing about the device is bound into it",
          enroll.tenant_url_token("a") == sig_a)
    # What it binds is the tenant, and nothing else.
    check("the same tsig is worthless for another tenant",
          not enroll.verify_tenant_url_token("b", sig_a))


async def test_require_signed_tenant_claim():
    print("16) MDM_REQUIRE_SIGNED_TENANT_CLAIM: opt-in refusal of unsigned known-udid check-ins")
    handler = WebhookHandler()
    await _fresh_fleet()
    sig_a = enroll.tenant_url_token("a")

    # Flag off (default): unsigned known-udid check-ins work (backward compat).
    before = await EnrollmentAttempt.all().count()
    dev = await handler._upsert_device(
        "UDID-TARGET", {}, {"SerialNumber": "SN-TARGET", "OSVersion": "16.0"},
        topic="mdm.Connect")
    row = await Device.get_or_none(udid="UDID-TARGET")
    check("flag off: an unsigned known-udid check-in is still accepted", dev is not None)
    check("flag off: ...and its facts are updated as before", row.os_version == "16.0")
    check("flag off: no enrollment attempt is logged",
          await EnrollmentAttempt.all().count() == before)

    os.environ["MDM_REQUIRE_SIGNED_TENANT_CLAIM"] = "true"
    try:
        # Flag on, no claim: refused before any attacker-supplied field reaches the row.
        dev = await handler._upsert_device(
            "UDID-TARGET", {},
            {"SerialNumber": "SN-ATTACKER", "DeviceName": "renamed",
             "ProductName": "MacAttack1,1", "OSVersion": "1.0"},
            topic="mdm.Connect")
        row = await Device.get_or_none(udid="UDID-TARGET")
        check("flag on: an unsigned known-udid check-in is refused", dev is None)
        check("flag on: the row's serial is NOT mutated", row.serial_number == "SN-TARGET")
        check("flag on: the row's hostname is NOT mutated", row.hostname == "target-mac")
        check("flag on: the row's model is NOT mutated", row.device_model == "Mac14,2")
        check("flag on: the row's os_version is NOT mutated", row.os_version == "16.0")

        attempts = await EnrollmentAttempt.filter(outcome="unsigned_tenant_claim").all()
        check("flag on: exactly one unsigned_tenant_claim attempt is logged",
              len(attempts) == 1)
        if attempts:
            a = attempts[0]
            check("...scoped to the row's OWN tenant, a database fact", a.tenant_id == "a")
            check("...distinct outcome from the forged-signature case",
                  a.outcome == "unsigned_tenant_claim" != "bad_tenant_claim")
            check("...reason says 'no claim', not 'forged claim'",
                  a.detail.get("reason") == "no_verified_claim")
            check("...records the attacker-reported serial", a.detail.get("reported_serial") == "SN-ATTACKER")

        # Unsigned claim naming own tenant still refused; id in detail only, never in FK.
        dev = await handler._upsert_device(
            "UDID-TARGET", {"tenant": "a"}, {"SerialNumber": "SN-TARGET"},
            topic="mdm.Connect")
        check("flag on: unsigned claim naming the device's own tenant is still refused",
              dev is None)
        attempts = await EnrollmentAttempt.filter(outcome="unsigned_tenant_claim").all()
        check("...dedupes to the same row rather than flooding the table",
              len(attempts) == 1 and attempts[0].detail.get("count") == 2)
        check("...the unverified id goes into detail, never into the tenant FK",
              attempts[0].detail.get("requested_tenant") == "a" and attempts[0].tenant_id == "a")

        # Flag on, signed: correctly re-enrolled device unaffected.
        dev = await handler._upsert_device(
            "UDID-TARGET", {"tenant": "a", "tsig": sig_a},
            {"SerialNumber": "SN-TARGET", "OSVersion": "16.1"}, topic="mdm.Connect")
        row = await Device.get_or_none(udid="UDID-TARGET")
        check("flag on: a signed check-in is accepted", dev is not None)
        check("...and updates facts normally", row.os_version == "16.1")
        check("...without adding another attempt row",
              len(await EnrollmentAttempt.filter(outcome="unsigned_tenant_claim").all()) == 1)

        # Both flags set: contradiction, but ALLOW wins (see webhook_handler).
        os.environ["MDM_ALLOW_UNSIGNED_TENANT_CLAIM"] = "true"
        try:
            before_count = attempts[0].detail.get("count") if attempts else 0
            dev = await handler._upsert_device(
                "UDID-TARGET", {}, {"SerialNumber": "SN-TARGET", "OSVersion": "16.2"},
                topic="mdm.Connect")
            row = await Device.get_or_none(udid="UDID-TARGET")
            check("both flags set: MDM_ALLOW_UNSIGNED_TENANT_CLAIM wins, check-in accepted",
                  dev is not None)
            check("...and facts are updated normally", row.os_version == "16.2")
            after = await EnrollmentAttempt.filter(outcome="unsigned_tenant_claim").all()
            after_count = after[0].detail.get("count") if after else 0
            check("...no new unsigned_tenant_claim attempt is logged",
                  after_count == before_count)
        finally:
            os.environ.pop("MDM_ALLOW_UNSIGNED_TENANT_CLAIM", None)
    finally:
        os.environ.pop("MDM_REQUIRE_SIGNED_TENANT_CLAIM", None)

    # Flag restored off: unsigned check-ins resume working, unaffected by anything above.
    dev = await handler._upsert_device(
        "UDID-TARGET", {}, {"SerialNumber": "SN-TARGET", "OSVersion": "16.3"},
        topic="mdm.Connect")
    row = await Device.get_or_none(udid="UDID-TARGET")
    check("flag restored off: unsigned check-ins work again",
          dev is not None and row.os_version == "16.3")


async def main():
    test_tokens()
    test_profile_shape()

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    await test_resolve_multi_tenant()
    await test_migration_switch()
    await test_resolve_sole_tenant()
    await test_upsert_end_to_end()
    await test_existing_fleet_untouched()
    await test_rekey_audit()
    await test_require_known_serial()
    await test_known_udid_conflicting_claim()
    await test_udid_rekey_is_audited()
    await test_malformed_tsig()
    await test_inactive_tenant()
    await test_attempt_log_is_tenant_scoped()
    await test_tsig_is_a_bearer_token()
    await test_require_signed_tenant_claim()

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run

run(main)
