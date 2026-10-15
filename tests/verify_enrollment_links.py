"""Enrollment links and per-enrollment SCEP challenges (services.enrollment_links), on in-memory sqlite.

Run: PYTHONPATH=. .venv/bin/python tests/verify_enrollment_links.py
"""
import hashlib
import os
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet

os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["PUBLIC_API_URL"] = "https://mdm.example.test/"
os.environ.pop("SCEP_NAME", None)

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402
from tortoise import Tortoise  # noqa: E402
from tortoise.exceptions import IntegrityError  # noqa: E402

from controller.auth.dependencies import Principal  # noqa: E402
from controller.models import database  # noqa: E402
from controller.models.tenant import (  # noqa: E402
    AuditLog, Device, EnrollmentAttempt, EnrollmentLink, ScepChallenge, Task, Tenant, User,
)
from controller.services import enrollment_links as el  # noqa: E402
from controller.utils.timeutil import as_utc  # noqa: E402
from tests._verify_harness import make_check, spki_sha256  # noqa: E402

PASS, FAIL = [], []
check = make_check(FAIL, PASS)

NOW = datetime.now(timezone.utc)
SCEP = "mdm_device_scep"


def make_csr(cn, *, key_usage=True, san=False, eku=False, key=None, extra_names=()):
    """(DER, key) for a CSR with Subject CN cn, any extra subject attributes, and the requested extensions."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)] + list(extra_names)))
    if key_usage:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True)
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("evil.example.test")]),
                                        critical=False)
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    csr = builder.sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.DER), key



async def refusals(reason):
    rows = await EnrollmentAttempt.filter(outcome="challenge_refused").all()
    return [r for r in rows if (r.detail or {}).get("reason") == reason]


async def test_links(tenant, admin):
    print("\n1) create, url, find and revoke")
    expires = NOW + timedelta(days=7)
    link, token = await el.create_link(tenant, "admin@t1", "Front desk", expires, 2, principal=admin)
    check("the token is base64url of 32 bytes", len(token) == 43 and "=" not in token)
    check("only the hash of the token is stored in clear",
          link.token_hash == hashlib.sha256(token.encode()).hexdigest() and token not in link.token_enc)
    check("the sealed token opens to the same value", el.link_token(link) == token)
    url = el.link_url(link)
    check("the url is the public address plus the token", url == f"https://mdm.example.test/api/v1/enroll/{token}",
          url)
    found = await el.find_link(token)
    check("find_link returns the link for its token", found is not None and found.id == link.id)
    check("find_link returns None for another token", await el.find_link(token + "x") is None)
    check("to_dict carries no token", not any("token" in k for k in link.to_dict()))
    check("creation is audited",
          await AuditLog.filter(action="enrollment_link.create", target_id=str(link.id),
                                actor_email="admin@t1").exists())

    print("\n2) take_download counts against the limit, expiry and revocation")
    check("first download counts", await el.take_download(link))
    check("second download counts", await el.take_download(link))
    check("a third is refused at max_downloads 2", not await el.take_download(link))
    await link.refresh_from_db()
    check("downloads stops at the limit", link.downloads == 2, str(link.downloads))

    unlimited, _ = await el.create_link(tenant, "admin@t1", None, expires, None, principal=admin)
    check("a link without a limit keeps counting",
          all([await el.take_download(unlimited) for _ in range(5)]))

    expired, _ = await el.create_link(tenant, "admin@t1", None, NOW - timedelta(minutes=1), None, principal=admin)
    check("an expired link is refused", not await el.take_download(expired))

    revoked, _ = await el.create_link(tenant, "admin@t1", None, expires, None, principal=admin)
    await el.revoke_link(revoked, admin)
    check("revoke sets revoked_at", revoked.revoked_at is not None)
    check("revocation is audited",
          await AuditLog.filter(action="enrollment_link.revoke", target_id=str(revoked.id)).exists())
    first_revoked_at = revoked.revoked_at
    await el.revoke_link(revoked, admin)
    check("revoking again keeps the first time and writes no second audit entry",
          revoked.revoked_at == first_revoked_at
          and await AuditLog.filter(action="enrollment_link.revoke", target_id=str(revoked.id)).count() == 1)
    check("a revoked link is refused", not await el.take_download(revoked))

    system_link, _ = await el.create_link(tenant, "api-token", None, expires, None)
    check("without a principal the audit row is a system row naming the creator",
          await AuditLog.filter(action="enrollment_link.create", target_id=str(system_link.id),
                                actor_email=None).exists())
    return unlimited


async def test_mint(tenant, link, device, task):
    print("\n3) mint for each origin")
    row, challenge, cn = await el.mint_challenge(tenant, link=link, lifetime=el.MANUAL_LIFETIME)
    check("manual origin", row.origin == "manual")
    check("subject_cn is mm <id>", cn == f"mm {row.id}" and row.subject_cn == cn)
    check("only the hash of the challenge is stored",
          row.challenge_hash == hashlib.sha256(challenge.encode()).hexdigest() and challenge != row.challenge_hash)
    check("manual lifetime is 15 minutes",
          timedelta(minutes=14) < row.expires_at - NOW <= timedelta(minutes=16))

    ade, _, _ = await el.mint_challenge(tenant, serial="ADE-1", expected_udid="UDID-ADE-1",
                                        lifetime=el.ADE_LIFETIME)
    check("ADE origin", ade.origin == "ade")
    renewal, _, _ = await el.mint_challenge(tenant, device=device, task=task, lifetime=el.RENEWAL_LIFETIME)
    check("renewal origin", renewal.origin == "renewal")
    far = NOW + timedelta(days=3650)
    rts, rts_challenge, rts_cn = await el.mint_challenge(tenant, serial=device.serial_number,
                                                        expected_udid=device.udid, task=task, origin="rts",
                                                        lifetime=el.RTS_LIFETIME, usable_from=far)
    check("Return to Service origin", rts.origin == "rts")
    check("a Return to Service row is not usable until activated",
          (await el.validate_and_consume(rts_challenge, SCEP, "t-rts", rts_cn, make_csr(rts_cn)[0]))[1]
          == "not_yet_usable")
    await el.activate_challenge(rts, el.RTS_LIFETIME)
    der, _ = make_csr(rts_cn)
    check("after activation it is usable", (await el.validate_and_consume(rts_challenge, SCEP, "t-rts", rts_cn,
                                                                          der))[0])
    pending, _, _ = await el.mint_challenge(tenant, serial="RTS-LATE", expected_udid="UDID-LATE", origin="rts",
                                            lifetime=el.RTS_LIFETIME, usable_from=far)
    await el.activate_challenge(pending, el.RTS_LIFETIME)
    await pending.refresh_from_db()
    check("activation of a row minted before its task makes it usable for the lifetime",
          pending.origin == "rts" and as_utc(pending.usable_from) <= datetime.now(timezone.utc)
          and timedelta(hours=23) < as_utc(pending.expires_at) - datetime.now(timezone.utc) <= timedelta(hours=24))
    explicit, _, _ = await el.mint_challenge(tenant, serial="RTS-X", lifetime=el.RTS_LIFETIME, origin="rts")
    check("an explicit origin is stored", explicit.origin == "rts")
    await el.link_task(explicit, task.id)
    await explicit.refresh_from_db()
    check("link_task stores the task id", explicit.task_id == task.id)

    print("\n4) one open renewal per device")
    try:
        await el.mint_challenge(tenant, device=device, lifetime=el.RENEWAL_LIFETIME)
        check("a second open renewal is refused", False)
    except el.OpenRenewalExists:
        check("a second open renewal is refused", True)
    try:
        await ScepChallenge.create(tenant=tenant, device=device, origin="renewal", challenge_hash="f" * 64,
                                   subject_cn="mm x", expires_at=NOW + timedelta(days=1))
        check("the partial unique index refuses a second open row written directly", False)
    except IntegrityError:
        check("the partial unique index refuses a second open row written directly", True)
    await ScepChallenge.filter(id=renewal.id).update(consumed_at=NOW)
    again, _, _ = await el.mint_challenge(tenant, device=device, lifetime=el.RENEWAL_LIFETIME)
    check("once the open one is consumed another can be minted", again.origin == "renewal")
    await ScepChallenge.filter(id=again.id).update(expires_at=NOW - timedelta(seconds=1))
    fresh, _, _ = await el.mint_challenge(tenant, device=device, lifetime=el.RENEWAL_LIFETIME)
    check("an expired unconsumed renewal does not block the next one",
          fresh.origin == "renewal" and not await ScepChallenge.filter(id=again.id).exists())

    print("\n5) a new ADE mint supersedes the serial's earlier one")
    first, first_challenge, first_cn = await el.mint_challenge(tenant, serial="ADE-2", lifetime=el.ADE_LIFETIME)
    second, _, _ = await el.mint_challenge(tenant, serial="ADE-2", lifetime=el.ADE_LIFETIME)
    await first.refresh_from_db()
    check("the earlier challenge is expired", as_utc(first.expires_at) <= datetime.now(timezone.utc))
    check("and refused as expired",
          (await el.validate_and_consume(first_challenge, SCEP, "t1", first_cn, make_csr(first_cn)[0]))[1]
          == "expired")
    await second.refresh_from_db()
    check("the new one is still live", as_utc(second.expires_at) > datetime.now(timezone.utc))
    await el.mint_challenge(tenant, serial="ADE-3", lifetime=el.ADE_LIFETIME)
    await second.refresh_from_db()
    check("another serial's mint leaves it alone", as_utc(second.expires_at) > datetime.now(timezone.utc))

    print("\n5b) a mint without a verified udid leaves the serial's verified rows alone")
    verified, _, _ = await el.mint_challenge(tenant, serial="ADE-2", expected_udid="UDID-ADE-2",
                                             lifetime=el.ADE_LIFETIME)
    await second.refresh_from_db()
    check("a verified mint expires the serial's unverified row",
          as_utc(second.expires_at) <= datetime.now(timezone.utc))
    unverified, _, _ = await el.mint_challenge(tenant, serial="ADE-2", lifetime=el.ADE_LIFETIME)
    await verified.refresh_from_db()
    check("an unverified mint leaves the verified row live", as_utc(verified.expires_at) > datetime.now(timezone.utc))
    again, _, _ = await el.mint_challenge(tenant, serial="ADE-2", expected_udid="UDID-ADE-2",
                                          lifetime=el.ADE_LIFETIME)
    await verified.refresh_from_db()
    await unverified.refresh_from_db()
    check("a later verified mint expires both",
          as_utc(verified.expires_at) <= datetime.now(timezone.utc)
          and as_utc(unverified.expires_at) <= datetime.now(timezone.utc))


async def test_validate(tenant, link):
    print("\n6) validate_and_consume")
    row, challenge, cn = await el.mint_challenge(tenant, link=link, lifetime=el.MANUAL_LIFETIME)

    check("a wrong provisioner is refused",
          (await el.validate_and_consume(challenge, "acme", "t", cn, make_csr(cn)[0]))[:2] == (False, "provisioner"))
    before = await EnrollmentAttempt.filter(outcome="challenge_refused").count()
    check("an unknown challenge is refused with no row",
          await el.validate_and_consume("nope", SCEP, "t", cn, make_csr(cn)[0]) == (False, "unknown", None))
    check("...and writes no attempt", await EnrollmentAttempt.filter(outcome="challenge_refused").count() == before)

    ok, reason, _ = await el.validate_and_consume(challenge, SCEP, "t", "mm someone-else", make_csr(cn)[0])
    check("a body CN that differs is refused", (ok, reason) == (False, "cn_mismatch"))
    ok, reason, _ = await el.validate_and_consume(challenge, SCEP, "t", cn, make_csr("mm other")[0])
    check("a CSR CN that differs is refused", (ok, reason) == (False, "cn_mismatch"))
    ok, reason, _ = await el.validate_and_consume(challenge, SCEP, "t", cn, b"not a csr")
    check("an unparseable CSR is refused", (ok, reason) == (False, "csr_invalid"))
    ok, reason, _ = await el.validate_and_consume(challenge, SCEP, "t", cn, make_csr(cn, san=True)[0])
    check("a CSR with a subjectAltName is refused", (ok, reason) == (False, "csr_extensions"))
    ok, reason, _ = await el.validate_and_consume(challenge, SCEP, "t", cn, make_csr(cn, eku=True)[0])
    check("a CSR with an extendedKeyUsage is refused", (ok, reason) == (False, "csr_extensions"))
    check("a refusal with a matched row is an attempt naming the challenge",
          any((r.detail or {}).get("challenge_id") == str(row.id) and r.tenant_id == tenant.id
              for r in await refusals("csr_extensions")))
    mine = [r for r in await EnrollmentAttempt.filter(outcome="challenge_refused").all()
            if (r.detail or {}).get("challenge_id") == str(row.id)]
    check("repeated refusals of one challenge share one attempt row with a count",
          len(mine) == 1 and mine[0].detail.get("count") == 5, str([r.detail for r in mine]))
    later_row, later_challenge, later_cn = await el.mint_challenge(tenant, link=link, lifetime=el.MANUAL_LIFETIME)
    decoy = await EnrollmentAttempt.create(tenant=tenant, udid=None, outcome="challenge_refused",
                                           detail={"reason": "csr_invalid", "challenge_id": str(later_row.id),
                                                   "count": 1})
    await EnrollmentAttempt.filter(id=decoy.id).update(created_at=as_utc(later_row.created_at) - timedelta(days=1))
    await el.validate_and_consume(later_challenge, SCEP, "t", later_cn, b"not a csr")
    await decoy.refresh_from_db()
    named = [r for r in await EnrollmentAttempt.filter(outcome="challenge_refused").all()
             if (r.detail or {}).get("challenge_id") == str(later_row.id)]
    check("an attempt naming the challenge from before its row is not the one a refusal counts on",
          decoy.detail.get("count") == 1 and len(named) == 2
          and any(r.id != decoy.id and (r.detail or {}).get("count") == 1 for r in named),
          str([r.detail for r in named]))
    ok, reason, _ = await el.validate_and_consume(
        challenge, SCEP, "t", cn, make_csr(cn, extra_names=[x509.NameAttribute(NameOID.ORGANIZATION_NAME, "x")])[0])
    check("a subject with more than the CN is refused", (ok, reason) == (False, "cn_mismatch"))
    ok, reason, _ = await el.validate_and_consume(
        challenge, SCEP, "t", cn, make_csr(cn, extra_names=[x509.NameAttribute(NameOID.COMMON_NAME, cn)])[0])
    check("a subject with two CNs is refused", (ok, reason) == (False, "cn_mismatch"))
    await row.refresh_from_db()
    check("refusals leave the challenge unconsumed", row.consumed_at is None)

    der, key = make_csr(cn)
    ok, reason, consumed = await el.validate_and_consume(challenge, SCEP, "txn-1", cn, der)
    check("a CN-only CSR with keyUsage is allowed", ok and reason is None)
    check("consumption stores the transaction, CSR and key hashes",
          consumed.consumed_at is not None and consumed.transaction_id == "txn-1"
          and consumed.csr_hash == hashlib.sha256(der).hexdigest() and consumed.spki_hash == spki_sha256(key))
    check("a key-usage-free CSR also passes the extension rule",
          el._inspect_csr(make_csr("x", key_usage=False)[0])[0] is None)

    check("step-ca's retry with the same transaction and CSR is allowed again",
          (await el.validate_and_consume(challenge, SCEP, "txn-1", cn, der))[:2] == (True, None))
    check("another transaction is refused as reused",
          (await el.validate_and_consume(challenge, SCEP, "txn-2", cn, der))[:2] == (False, "reused"))
    other_der, _ = make_csr(cn)
    check("the same transaction with a CSR for another key is refused as reused",
          (await el.validate_and_consume(challenge, SCEP, "txn-1", cn, other_der))[:2] == (False, "reused"))

    print("\n7) expiry, revocation and the tenant")
    expired_row, expired_challenge, expired_cn = await el.mint_challenge(tenant, link=link,
                                                                         lifetime=el.MANUAL_LIFETIME)
    await ScepChallenge.filter(id=expired_row.id).update(expires_at=NOW - timedelta(seconds=1))
    check("an expired challenge is refused",
          (await el.validate_and_consume(expired_challenge, SCEP, "t", expired_cn, make_csr(expired_cn)[0]))[1]
          == "expired")

    _, later_challenge, later_cn = await el.mint_challenge(
        tenant, link=link, lifetime=el.MANUAL_LIFETIME, usable_from=NOW + timedelta(hours=1))
    check("a challenge before usable_from is refused",
          (await el.validate_and_consume(later_challenge, SCEP, "t", later_cn, make_csr(later_cn)[0]))[1]
          == "not_yet_usable")

    revoked_link, _ = await el.create_link(tenant, "admin@t1", None, NOW + timedelta(days=1), None)
    _, rchallenge, rcn = await el.mint_challenge(tenant, link=revoked_link, lifetime=el.MANUAL_LIFETIME)
    await EnrollmentLink.filter(id=revoked_link.id).update(revoked_at=NOW)
    check("a challenge from a revoked link is refused",
          (await el.validate_and_consume(rchallenge, SCEP, "t", rcn, make_csr(rcn)[0]))[1] == "link_revoked")

    asleep = await Tenant.create(id="t-off", name="Inactive", is_active=False)
    _, achallenge, acn = await el.mint_challenge(asleep, serial="OFF-1", lifetime=el.ADE_LIFETIME)
    check("a challenge for an inactive tenant is refused",
          (await el.validate_and_consume(achallenge, SCEP, "t", acn, make_csr(acn)[0]))[1] == "tenant_inactive")
    check("...and its attempt row is in that tenant",
          any(r.tenant_id == "t-off" and r.serial_number == "OFF-1" for r in await refusals("tenant_inactive")))

    os.environ["SCEP_NAME"] = "custom_scep"
    try:
        _, cchallenge, ccn = await el.mint_challenge(tenant, link=link, lifetime=el.MANUAL_LIFETIME)
        check("SCEP_NAME names the provisioner accepted",
              (await el.validate_and_consume(cchallenge, "custom_scep", "t", ccn, make_csr(ccn)[0]))[0]
              and (await el.validate_and_consume(cchallenge, SCEP, "t", ccn, make_csr(ccn)[0]))[1]
              == "provisioner")
    finally:
        os.environ.pop("SCEP_NAME", None)


async def test_sweep(tenant, task):
    print("\n8) sweep_expired")
    await ScepChallenge.all().delete()
    await EnrollmentLink.all().delete()
    long_ago = NOW - timedelta(days=40)
    old_expired, _ = await el.create_link(tenant, "a", "old", long_ago, None)
    old_revoked, _ = await el.create_link(tenant, "a", "revoked", NOW + timedelta(days=90), None)
    await EnrollmentLink.filter(id=old_revoked.id).update(revoked_at=long_ago)
    live, _ = await el.create_link(tenant, "a", "live", NOW + timedelta(days=1), None)
    recently_expired, _ = await el.create_link(tenant, "a", "recent", NOW - timedelta(days=2), None)

    async def challenge(expires_at, **extra):
        row, _, _ = await el.mint_challenge(tenant, serial=None, lifetime=timedelta(minutes=15))
        await ScepChallenge.filter(id=row.id).update(expires_at=expires_at, **extra)
        return row

    unconsumed_old = await challenge(NOW - timedelta(days=10))
    unconsumed_recent = await challenge(NOW - timedelta(days=2))
    unbound_old = await challenge(long_ago, consumed_at=long_ago)
    unbound_recent = await challenge(NOW - timedelta(days=10), consumed_at=NOW - timedelta(days=10))
    bound_old = await challenge(long_ago, consumed_at=long_ago, bound_at=long_ago, bound_udid="U1",
                                cert_sha256="a" * 64)

    async def pending_rts(created_at, origin="rts", task_id=None):
        row, _, _ = await el.mint_challenge(tenant, serial="RTS-P", lifetime=el.RTS_LIFETIME, origin=origin,
                                            usable_from=el.RTS_PENDING_FROM)
        await ScepChallenge.filter(id=row.id).update(created_at=created_at, task_id=task_id)
        return row

    two_hours_ago = NOW - timedelta(hours=2)
    orphan_rts = await pending_rts(two_hours_ago)
    orphan_ade = await pending_rts(two_hours_ago, origin="ade")
    pending_recent = await pending_rts(NOW - timedelta(minutes=5))
    pending_linked = await pending_rts(two_hours_ago, task_id=task.id)

    deleted = await el.sweep_expired()
    check("it reports two links and three challenges", deleted == 5, str(deleted))
    remaining_links = set(await EnrollmentLink.all().values_list("id", flat=True))
    check("old expired and old revoked links are gone",
          old_expired.id not in remaining_links and old_revoked.id not in remaining_links)
    check("live and recently expired links stay", {live.id, recently_expired.id} <= remaining_links)
    remaining = set(await ScepChallenge.all().values_list("id", flat=True))
    check("challenges unconsumed past 7 days are gone", unconsumed_old.id not in remaining)
    check("consumed challenges that never bound are gone after 30 days", unbound_old.id not in remaining)
    check("recent ones and bound ones stay",
          {unconsumed_recent.id, unbound_recent.id, bound_old.id} <= remaining)
    check("a pending Return to Service row left unlinked for an hour is gone", orphan_rts.id not in remaining)
    check("a recent pending row, a linked one and an ADE row stay",
          {pending_recent.id, pending_linked.id, orphan_ade.id} <= remaining)

    from controller.services.task_manager import run_retention
    result = await run_retention()
    check("run_retention reports the sweep under enrollment_links", result.get("enrollment_links") == 0,
          str(result))


async def main():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()
    # The partial index is Postgres DDL that sqlite also accepts; the suites never run _AUX_DDL otherwise.
    index_ddl = next(d for d in database._AUX_DDL if "idx_scep_challenges_open_renewal" in d)
    await Tortoise.get_connection("default").execute_script(index_ddl)

    tenant = await Tenant.create(id="t1", name="Tenant One")
    user = await User.create(tenant=tenant, email="admin@t1", role="admin")
    admin = Principal(tenant=tenant, user=user, email="admin@t1", role="admin")
    device = await Device.create(tenant=tenant, udid="UDID-1", serial_number="SER-1", device_model="Mac",
                                 os_version="15.0")
    task = await Task.create(tenant=tenant, device=device, type="enrollment_renew", status="pending",
                             description="renew")

    link = await test_links(tenant, admin)
    await test_mint(tenant, link, device, task)
    await test_validate(tenant, link)
    await test_sweep(tenant, task)

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run  # noqa: E402

run(main)
