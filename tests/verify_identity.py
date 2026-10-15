"""Identity enforcement (services.identity) against the harness's NanoMDM stub, on in-memory sqlite.

Run: PYTHONPATH=. .venv/bin/python tests/verify_identity.py
"""
import hashlib
import os
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet

os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.pop("SCEP_NAME", None)

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from tortoise import Tortoise  # noqa: E402

from controller.models.tenant import (  # noqa: E402
    Alert, Device, EnrollmentAttempt, IdentityCutover, LegacyIdentity, ScepChallenge, Task, Tenant,
)
from controller.services import alerts, identity  # noqa: E402
from controller.services import enrollment_links as el  # noqa: E402
from controller.services.nanomdm_store import Identity  # noqa: E402
from controller.utils.timeutil import as_utc  # noqa: E402
from tests._verify_harness import install_identity_stub, make_check, spki_sha256  # noqa: E402

PASS, FAIL = [], []
check = make_check(FAIL, PASS)

NOW = datetime.now(timezone.utc)
SCEP = "mdm_device_scep"


def h(char):
    return char * 64



async def consumed_challenge(tenant, **mint):
    """A challenge row consumed through the webhook path, with the key its CSR used."""
    row, challenge, cn = await el.mint_challenge(tenant, lifetime=mint.pop("lifetime", el.MANUAL_LIFETIME), **mint)
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])).sign(key, hashes.SHA256())
    ok, reason, row = await el.validate_and_consume(challenge, SCEP, f"txn-{row.id}", cn,
                                                    csr.public_bytes(serialization.Encoding.DER))
    assert ok, reason
    return row, key


def issued(row, key, cert_char):
    """The Identity NanoMDM would hold for a certificate issued to row's CSR."""
    return Identity(cert_sha256=h(cert_char), spki_sha256=spki_sha256(key), subject_cn=row.subject_cn,
                    not_after=NOW + timedelta(days=365))


async def device(tenant, udid, serial, state="enrolled", **extra):
    return await Device.create(tenant=tenant, udid=udid, serial_number=serial, device_model="Mac",
                               os_version="15.0", enrollment_state=state, **extra)


async def attempts(outcome, udid):
    return await EnrollmentAttempt.filter(outcome=outcome, udid=udid).all()


async def test_allowed(tenant, stub):
    print("\n1) allowed_hashes")
    dev = await device(tenant, "U-ALLOW", "S-ALLOW", identity_sha256=h("a"))
    await LegacyIdentity.create(udid="U-ALLOW", cert_sha256=h("b"))
    check("identity plus legacy rows", await identity.allowed_hashes(dev) == {h("a"), h("b")})

    earlier = NOW - timedelta(days=200)
    await ScepChallenge.create(tenant=tenant, origin="manual", challenge_hash=h("1"), subject_cn="mm old",
                               expires_at=earlier, consumed_at=earlier, bound_at=earlier, bound_udid="U-ALLOW",
                               cert_sha256=h("c"))
    task = await Task.create(tenant=tenant, device=dev, type="enrollment_renew", status="pending",
                             description="renew")
    await ScepChallenge.create(tenant=tenant, device=dev, task=task, origin="renewal", challenge_hash=h("2"),
                               subject_cn="mm new", expires_at=NOW + timedelta(days=7), consumed_at=NOW,
                               bound_at=NOW, bound_udid="U-ALLOW", cert_sha256=h("a"))
    check("an unacknowledged renewal keeps the previous bound hash",
          await identity.allowed_hashes(dev) == {h("a"), h("b"), h("c")})
    await Task.filter(id=task.id).update(status="failed")
    check("a failed renewal task still keeps it", await identity.allowed_hashes(dev) == {h("a"), h("b"), h("c")})
    await Task.filter(id=task.id).update(status="completed")
    check("once the renewal task completes it is gone", await identity.allowed_hashes(dev) == {h("a"), h("b")})


async def test_judge(tenant, stub):
    print("\n2) Judge accepts a challenge certificate whose key matches")
    row, key = await consumed_challenge(tenant, link=await make_link(tenant))
    stub.set_identity("U-NEW", issued(row, key, "d"))
    decision = await identity.judge("U-NEW", device=None)
    check("accepted as a manual enrollment",
          decision.accepted and decision.origin == "manual" and not decision.is_takeover and decision.applied)
    check("the decision names the row's tenant and the ota source",
          decision.tenant is not None and decision.tenant.id == tenant.id and decision.enrollment_source == "ota")
    await row.refresh_from_db()
    check("the row is bound to the udid and certificate",
          row.bound_udid == "U-NEW" and row.cert_sha256 == h("d") and row.bound_at is not None)
    check("associations are pruned to the certificate", ("prune", "U-NEW", {h("d")}) in stub.calls)
    check("nothing is parked", not stub.parks)

    again = await identity.judge("U-NEW", device=None)
    check("judging the same certificate again accepts it", again.accepted)

    stub.set_identity("U-OTHER", issued(row, key, "x"))
    refused = await identity.judge("U-OTHER", device=None)
    check("the same challenge on another udid is refused", refused.reason == "bound_elsewhere")
    check("...and that certificate is parked", ("park", "U-OTHER", h("x")) in stub.calls)

    print("\n3) refusals")
    row2, _ = await consumed_challenge(tenant, link=await make_link(tenant))
    stub.set_identity("U-SPKI", Identity(cert_sha256=h("e"), spki_sha256=h("0"), subject_cn=row2.subject_cn,
                                         not_after=NOW))
    decision = await identity.judge("U-SPKI", device=None)
    check("a key that differs from the CSR's is refused", decision.reason == "spki_mismatch")
    check("its certificate is parked", ("park", "U-SPKI", h("e")) in stub.calls)
    check("...and a bad_identity attempt names the challenge",
          any((a.detail or {}).get("challenge_id") == str(row2.id) for a in await attempts("bad_identity",
                                                                                          "U-SPKI")))

    _, _, ucn = await el.mint_challenge(tenant, link=await make_link(tenant), lifetime=el.MANUAL_LIFETIME)
    stub.set_identity("U-UNCONSUMED", Identity(h("f"), h("0"), ucn, NOW))
    check("an unconsumed challenge row is refused",
          (await identity.judge("U-UNCONSUMED", device=None)).reason == "not_consumed")

    stub.set_identity("U-LEGACY-X", Identity(h("7"), h("8"), "t1 MDM Device " + "ab" * 16, NOW))
    decision = await identity.judge("U-LEGACY-X", device=None)
    check("a legacy subject outside the snapshot is refused", decision.reason == "legacy_not_in_snapshot")
    check("...and parked", ("park", "U-LEGACY-X", h("7")) in stub.calls)

    stub.set_identity("U-ODD", Identity(h("9"), h("8"), "someone else", NOW))
    check("any other subject is refused", (await identity.judge("U-ODD", device=None)).reason == "unknown_cn")

    stub.set_identity("U-GONE", None)
    calls_before = len(stub.calls)
    decision = await identity.judge("U-GONE", device=None)
    check("an unreadable identity is refused as unreadable", decision.reason == "identity_unreadable")
    check("...with no NanoMDM write", len(stub.calls) == calls_before)
    check("...and an identity_unreadable attempt", bool(await attempts("identity_unreadable", "U-GONE")))

    print("\n4) the stub's default is a legacy certificate in the snapshot")
    known = await device(tenant, "U-KNOWN", "S-KNOWN")
    decision = await identity.judge("U-KNOWN", device=known)
    check("a known udid with the default identity is accepted as legacy",
          decision.accepted and decision.origin == "legacy" and decision.tenant.id == tenant.id)
    await known.refresh_from_db()
    check("a legacy acceptance sets identity_sha256",
          known.identity_sha256 == stub.legacy_identity("U-KNOWN", tenant.id).cert_sha256)
    check("the cutover reads as done", await identity.cutover_done())

    print("\n5) a refusal on an enrolled device restores its push token")
    victim = await device(tenant, "U-VICTIM", "S-VICTIM", identity_sha256=h("a"))
    victim.push_token_enc = identity.seal_push_token(victim, "deadbeef", "magic-1")
    await victim.save()
    stub.associations["U-VICTIM"] = {h("a")}
    stub.set_identity("U-VICTIM", Identity(h("b"), h("0"), "mm " + "0" * 8 + "-0000-0000-0000-" + "0" * 12, NOW))
    stub.associations["U-VICTIM"] = {h("a"), h("b")}
    decision = await identity.judge("U-VICTIM", device=victim)
    check("an unknown challenge id is refused", decision.reason == "unknown_challenge")
    check("the refused certificate is parked and the bound one kept",
          ("park", "U-VICTIM", h("b")) in stub.calls and stub.associations["U-VICTIM"] == {h("a")})
    check("the push token is written back",
          ("restore_push", "U-VICTIM", ("deadbeef", "magic-1", True)) in stub.calls)
    alert = await Alert.get_or_none(device_id=victim.id, rule_id=identity.ALERT_RULE_REFUSED, status="open")
    check("an identity_refused alert is open and records the push write, and no identity write without a PEM",
          alert is not None and alert.detail.get("push_restored") is True
          and alert.detail.get("identity_restored") is None, str(alert and alert.detail))
    await victim.refresh_from_db()
    check("the device row keeps its identity", victim.identity_sha256 == h("a"))

    print("\n5b) Judge does not check whether the tenant is active")
    other = await Tenant.create(id="t-later-off", name="Later inactive")
    row3, key3 = await consumed_challenge(other, link=await make_link(other))
    stub.set_identity("U-OFF", issued(row3, key3, "6"))
    check("bound while the tenant is active", (await identity.judge("U-OFF", device=None)).accepted)
    await Tenant.filter(id=other.id).update(is_active=False)
    parks = len(stub.parks)
    decision = await identity.judge("U-OFF", device=None)
    check("an inactive tenant's bound certificate is still accepted", decision.accepted and decision.reason is None)
    check("...and nothing is parked", len(stub.parks) == parks)


async def test_cross_tenant(tenant, stub):
    print("\n5c) a challenge from another tenant never binds onto this tenant's device row")
    other = await Tenant.create(id="t2", name="Tenant Two")
    for state in ("unenrolled", "pending", "enrolled"):
        udid = f"U-CROSS-{state}"
        target = await device(tenant, udid, f"S-CROSS-{state}", state=state, identity_sha256=h("a"))
        row, key = await consumed_challenge(other, link=await make_link(other))
        stub.set_identity(udid, issued(row, key, "7"))
        decision = await identity.judge(udid, device=target)
        check(f"refused as tenant_mismatch onto a {state} row", decision.reason == "tenant_mismatch", decision.reason)
        check("...and the certificate is parked", ("park", udid, h("7")) in stub.calls)
        await row.refresh_from_db()
        await target.refresh_from_db()
        check("...the row stays unbound and the device keeps its identity",
              row.bound_udid is None and target.identity_sha256 == h("a"))
        check("...and takeover_allowed refuses across tenants", await identity.takeover_allowed(target, row) is None)


async def make_link(tenant):
    link, _ = await el.create_link(tenant, "admin@t1", None, NOW + timedelta(days=1), None)
    return link


async def test_takeover(tenant, stub):
    print("\n6) a fresh challenge onto an enrolled row is left to the caller")
    held = await device(tenant, "U-HELD", "S-HELD", identity_sha256=h("a"))
    row, key = await consumed_challenge(tenant, link=await make_link(tenant))
    stub.set_identity("U-HELD", issued(row, key, "c"))
    calls_before = len(stub.calls)
    decision = await identity.judge("U-HELD", device=held)
    check("Judge reports a takeover and writes nothing",
          decision.accepted and decision.is_takeover and not decision.applied and len(stub.calls) == calls_before)
    await row.refresh_from_db()
    check("...the row is not bound yet", row.bound_udid is None)
    check("takeover_allowed refuses without a condition", await identity.takeover_allowed(held, row) is None)
    held.reenrollment_allowed_until = NOW + timedelta(hours=1)
    check("an allowance permits it", await identity.takeover_allowed(held, row) == "allowance")
    held.reenrollment_allowed_until = NOW - timedelta(hours=1)
    check("an expired allowance does not", await identity.takeover_allowed(held, row) is None)
    held.erase_acked_at = NOW
    check("an erase acknowledgement permits it", await identity.takeover_allowed(held, row) == "erase_acked")
    bound = await ScepChallenge.create(tenant=tenant, origin="manual", challenge_hash=h("3"), subject_cn="mm held",
                                       expires_at=NOW, consumed_at=NOW, bound_at=NOW + timedelta(minutes=1),
                                       bound_udid="U-HELD", cert_sha256=h("a"))
    check("...but not one older than the current bind", await identity.takeover_allowed(held, row) is None)
    await ScepChallenge.filter(id=bound.id).update(bound_at=NOW - timedelta(minutes=1))
    check("...and one newer than the current bind permits it",
          await identity.takeover_allowed(held, row) == "erase_acked")
    held.erase_acked_at = None
    held.enrollment_state = "unenrolled"
    check("an unenrolled row permits it", await identity.takeover_allowed(held, row) == "unenrolled")
    held.enrollment_state = "enrolled"
    ade = ScepChallenge(tenant_id=tenant.id, origin="ade", serial="S-HELD", expected_udid="U-HELD")
    check("a verified ADE challenge for this udid and serial permits it",
          await identity.takeover_allowed(held, ade) == "ade_verified")
    check("...but not for another serial",
          await identity.takeover_allowed(held, ScepChallenge(tenant_id=tenant.id, origin="ade", serial="S-X",
                                                              expected_udid="U-HELD")) is None)
    serial_ade = ScepChallenge(tenant_id=tenant.id, origin="ade", serial="S-HELD", expected_udid="U-ELSEWHERE")
    check("an ADE challenge for this serial from another udid is refused on the udid path",
          await identity.takeover_allowed(held, serial_ade) is None)
    check("...and allowed on the serial path while the current bind is manual",
          await identity.takeover_allowed(held, serial_ade, serial_path=True) == "ade_serial")
    await ScepChallenge.filter(id=bound.id).update(origin="ade")
    check("...but not when the current bind is ADE",
          await identity.takeover_allowed(held, serial_ade, serial_path=True) is None)
    await bound.delete()

    held.reenrollment_allowed_until = NOW + timedelta(hours=1)
    await held.save()
    await LegacyIdentity.create(udid="U-HELD", cert_sha256=h("9"))
    decision = await identity.apply_acceptance(decision, "U-HELD", held)
    await held.refresh_from_db()
    check("applying it binds the new certificate and clears the allowance",
          held.identity_sha256 == h("c") and held.reenrollment_allowed_until is None)
    check("...deletes the udid's legacy rows", not await LegacyIdentity.filter(udid="U-HELD").exists())
    check("...sets the enrollment source", (held.attributes or {}).get("enrollment_source") == "ota")
    check("...and opens a takeover alert",
          await Alert.filter(device_id=held.id, rule_id=identity.ALERT_RULE_TAKEOVER).exists())

    print("\n7) renewal keeps the previous certificate until it is acknowledged")
    renewing = await device(tenant, "U-RENEW", "S-RENEW", identity_sha256=h("1"))
    await LegacyIdentity.create(udid="U-RENEW", cert_sha256=h("1"))
    task = await Task.create(tenant=tenant, device=renewing, type="enrollment_renew", status="pending",
                             description="renew")
    row, key = await consumed_challenge(tenant, device=renewing, task=task, lifetime=el.RENEWAL_LIFETIME)
    stub.set_identity("U-RENEW", issued(row, key, "2"))
    stub.associations["U-RENEW"] = {h("1"), h("2")}
    decision = await identity.judge("U-RENEW", device=renewing)
    check("the renewal is accepted", decision.accepted and decision.is_renewal and not decision.is_takeover)
    check("both hashes survive the prune", stub.associations["U-RENEW"] == {h("1"), h("2")})
    check("the reconciler leaves it alone", "U-RENEW" not in await identity.reconciler_candidates())
    await Task.filter(id=task.id).update(status="completed")
    await identity.finish_renewal(await Device.get(udid="U-RENEW"), task_id=task.id)
    check("finishing the renewal prunes to the new certificate", stub.associations["U-RENEW"] == {h("2")})

    stub.set_identity("U-THIEF", issued(row, key, "3"))
    check("a bound renewal certificate on another udid is refused",
          (await identity.judge("U-THIEF", device=None)).reason == "bound_elsewhere")

    print("\n7b) the previous hash from an earlier bound row, with no legacy row")
    second = await device(tenant, "U-RENEW2", "S-RENEW2", identity_sha256=h("4"))
    earlier = NOW - timedelta(days=300)
    await ScepChallenge.create(tenant=tenant, origin="manual", challenge_hash=h("4"), subject_cn="mm first",
                               expires_at=earlier, consumed_at=earlier, bound_at=earlier, bound_udid="U-RENEW2",
                               cert_sha256=h("4"))
    task = await Task.create(tenant=tenant, device=second, type="enrollment_renew", status="pending",
                             description="renew")
    row, key = await consumed_challenge(tenant, device=second, task=task, lifetime=el.RENEWAL_LIFETIME)
    stub.set_identity("U-RENEW2", issued(row, key, "6"))
    stub.associations["U-RENEW2"] = {h("4"), h("6")}
    decision = await identity.judge("U-RENEW2", device=second)
    check("the renewal is accepted", decision.accepted and decision.is_renewal)
    check("both hashes survive the prune", stub.associations["U-RENEW2"] == {h("4"), h("6")})
    await Task.filter(id=task.id).update(status="failed")
    check("a failed task leaves both allowed", "U-RENEW2" not in await identity.reconciler_candidates())
    second = await Device.get(udid="U-RENEW2")
    check("fail_renewal without force rolls nothing back",
          await identity.fail_renewal(second, task_id=task.id) is False)
    await row.refresh_from_db()
    kept = await Device.get(udid="U-RENEW2")
    check("...keeps identity_sha256, both associations and the row's hash, and expires the row",
          kept.identity_sha256 == h("6") and stub.associations["U-RENEW2"] == {h("4"), h("6")}
          and row.cert_sha256 == h("6") and as_utc(row.expires_at) <= datetime.now(timezone.utc))
    check("fail_renewal with force rolls back",
          await identity.fail_renewal(second, task_id=task.id, force=True) is True)
    await second.refresh_from_db()
    await row.refresh_from_db()
    check("...identity_sha256 is the previous certificate again", second.identity_sha256 == h("4"))
    check("...the new certificate is pruned", stub.associations["U-RENEW2"] == {h("4")})
    check("...and the renewal row is expired", as_utc(row.expires_at) <= datetime.now(timezone.utc))

    task = await Task.create(tenant=tenant, device=second, type="enrollment_renew", status="pending",
                             description="renew again")
    row, key = await consumed_challenge(tenant, device=second, task=task, lifetime=el.RENEWAL_LIFETIME)
    stub.set_identity("U-RENEW2", issued(row, key, "8"))
    stub.associations["U-RENEW2"] = {h("4"), h("8")}
    check("a second renewal is accepted", (await identity.judge("U-RENEW2", device=second)).accepted)
    second = await Device.get(udid="U-RENEW2")
    check("...and its previous hash is the rolled-back certificate, not the failed one",
          await identity.allowed_hashes(second) == {h("8"), h("4")})

    print("\n7c) wrong_device on unbound rows")
    owner = await device(tenant, "U-OWNER", "S-OWNER")
    task = await Task.create(tenant=tenant, device=owner, type="enrollment_renew", status="pending",
                             description="renew")
    row, key = await consumed_challenge(tenant, device=owner, task=task, lifetime=el.RENEWAL_LIFETIME)
    stub.set_identity("U-NOT-OWNER", issued(row, key, "1"))
    check("a renewal row used by another udid", (await identity.judge("U-NOT-OWNER", device=None)).reason
          == "wrong_device")
    erase = await Task.create(tenant=tenant, device=owner, type="erase_device", status="pending",
                              description="erase")
    row, key = await consumed_challenge(tenant, serial="S-OWNER", expected_udid="U-OWNER", task=erase,
                                        origin="rts", lifetime=el.RTS_LIFETIME)
    stub.set_identity("U-RTS-OTHER", issued(row, key, "2"))
    check("a Return to Service row used by another udid",
          row.origin == "rts" and (await identity.judge("U-RTS-OTHER", device=None)).reason == "wrong_device")
    row, key = await consumed_challenge(tenant, task=erase, origin="rts", lifetime=el.RTS_LIFETIME)
    stub.set_identity("U-RTS-ANY", issued(row, key, "3"))
    check("a Return to Service row with no expected udid",
          (await identity.judge("U-RTS-ANY", device=None)).reason == "wrong_device")
    row, key = await consumed_challenge(tenant, serial="S-ADE-W", expected_udid="U-ADE-OK", lifetime=el.ADE_LIFETIME)
    stub.set_identity("U-ADE-OTHER", issued(row, key, "5"))
    check("an ADE row used by a udid other than the expected one",
          row.origin == "ade" and (await identity.judge("U-ADE-OTHER", device=None)).reason == "wrong_device")


async def test_failed_renewal_rebind(tenant, stub):
    print("\n7d) a failed renewal stops widening the allowed set")
    dev = await device(tenant, "U-REBIND", "S-REBIND", identity_sha256=h("a"))
    earlier = NOW - timedelta(days=100)
    await ScepChallenge.create(tenant=tenant, origin="manual", challenge_hash=h("5"), subject_cn="mm rebind",
                               expires_at=earlier, consumed_at=earlier, bound_at=earlier, bound_udid="U-REBIND",
                               cert_sha256=h("a"))
    older = await Task.create(tenant=tenant, device=dev, type="enrollment_renew", status="completed",
                              description="renew done")
    done = await ScepChallenge.create(tenant=tenant, device=dev, task=older, origin="renewal", challenge_hash=h("6"),
                                      subject_cn="mm done", expires_at=NOW + timedelta(days=7),
                                      consumed_at=earlier, bound_at=earlier, bound_udid="U-OLD-DONE",
                                      cert_sha256=h("9"))
    orphan = await Task.create(tenant=tenant, device=dev, type="enrollment_renew", status="failed",
                               description="mint failed")
    check("a renew task with no row of its own rolls nothing back",
          await identity.fail_renewal_tasks([orphan.id]) == 0)
    await done.refresh_from_db()
    check("...and leaves the device's other renewal row alone",
          done.cert_sha256 == h("9") and as_utc(done.expires_at) > datetime.now(timezone.utc))

    task = await Task.create(tenant=tenant, device=dev, type="enrollment_renew", status="pending",
                             description="renew")
    row, key = await consumed_challenge(tenant, device=dev, task=task, lifetime=el.RENEWAL_LIFETIME)
    stub.set_identity("U-REBIND", issued(row, key, "b"))
    stub.associations["U-REBIND"].add(h("a"))
    check("the renewal is accepted", (await identity.judge("U-REBIND", device=dev)).accepted)
    dev = await Device.get(udid="U-REBIND")
    check("...and the pre-renewal hash is allowed while it is open", h("a") in await identity.allowed_hashes(dev))

    other = await Task.create(tenant=tenant, device=dev, type="refresh_info", status="failed", description="x")
    check("other task types are ignored", await identity.fail_renewal_tasks([other.id]) == 0)
    await Task.filter(id=task.id).update(status="failed")
    check("fail_renewal_tasks with force rolls the renewal back",
          await identity.fail_renewal_tasks([task.id], force=True) == 1)
    dev = await Device.get(udid="U-REBIND")
    check("...identity_sha256 is the pre-renewal hash", dev.identity_sha256 == h("a"))
    check("...and a second call changes nothing", await identity.fail_renewal_tasks([task.id], force=True) == 0)

    dev.reenrollment_allowed_until = NOW + timedelta(hours=1)
    await dev.save()
    fresh, fresh_key = await consumed_challenge(tenant, link=await make_link(tenant))
    stub.set_identity("U-REBIND", issued(fresh, fresh_key, "c"))
    decision = await identity.judge("U-REBIND", device=dev)
    check("a fresh manual enrollment is a takeover", decision.accepted and decision.is_takeover)
    await identity.apply_acceptance(decision, "U-REBIND", dev)
    dev = await Device.get(udid="U-REBIND")
    check("after the re-bind only the new hash is allowed", await identity.allowed_hashes(dev) == {h("c")},
          str(await identity.allowed_hashes(dev)))
    stub.associations["U-REBIND"] = {h("a"), h("c")}
    check("...and the reconciler picks up the pre-renewal hash", "U-REBIND" in await identity.reconciler_candidates())

    print("\n7e) an expired renewal row stops widening the allowed set")
    exp = await device(tenant, "U-EXPIRED", "S-EXPIRED", identity_sha256=h("e"))
    await ScepChallenge.create(tenant=tenant, origin="manual", challenge_hash=h("7"), subject_cn="mm exp",
                               expires_at=earlier, consumed_at=earlier, bound_at=earlier, bound_udid="U-EXPIRED",
                               cert_sha256=h("d"))
    task = await Task.create(tenant=tenant, device=exp, type="enrollment_renew", status="pending",
                             description="renew")
    renewal = await ScepChallenge.create(tenant=tenant, device=exp, task=task, origin="renewal",
                                         challenge_hash=h("8"), subject_cn="mm exp new",
                                         expires_at=NOW + timedelta(days=7), consumed_at=NOW, bound_at=NOW,
                                         bound_udid="U-EXPIRED", cert_sha256=h("e"))
    check("an open renewal keeps the previous hash", await identity.allowed_hashes(exp) == {h("d"), h("e")})
    await ScepChallenge.filter(id=renewal.id).update(expires_at=NOW - timedelta(minutes=1))
    check("an expired one does not", await identity.allowed_hashes(exp) == {h("e")})


async def test_attempt_dedupe(tenant, stub):
    print("\n7f) repeated judgements of one udid update one attempt row")
    stub.set_identity("U-UNREADABLE", None)
    for _ in range(3):
        await identity.judge("U-UNREADABLE", device=None)
    rows = await attempts("identity_unreadable", "U-UNREADABLE")
    check("one identity_unreadable row with a count of 3",
          len(rows) == 1 and rows[0].detail.get("count") == 3, str([r.detail for r in rows]))

    held = await device(tenant, "U-REPEAT", "S-REPEAT", identity_sha256=h("a"))
    stub.set_identity("U-REPEAT", Identity(h("4"), h("0"), "someone else", NOW))
    for _ in range(2):
        await identity.judge("U-REPEAT", device=held)
    rows = await attempts("bad_identity", "U-REPEAT")
    check("one bad_identity row per tenant, udid and outcome with a count of 2",
          len(rows) == 1 and rows[0].detail.get("count") == 2 and rows[0].tenant_id == tenant.id,
          str([r.detail for r in rows]))
    stub.set_identity("U-REPEAT", Identity(h("5"), h("0"), "mm " + "1" * 8 + "-0000-0000-0000-" + "1" * 12, NOW))
    await identity.judge("U-REPEAT", device=held)
    rows = await attempts("bad_identity", "U-REPEAT")
    check("...which keeps every reason it merged",
          len(rows) == 1 and rows[0].detail.get("reason") == "unknown_challenge"
          and rows[0].detail.get("reasons") == ["unknown_cn", "unknown_cn", "unknown_challenge"],
          str([r.detail for r in rows]))


async def test_udid_lock():
    print("\n7g) udid_lock on sqlite, and the lock cap follows the pool")
    async with identity.udid_lock("U-LOCK"):
        async with identity.udid_lock("U-LOCK-2"):
            inside = await Device.filter(udid="U-LOCK").count()
    check("udid_lock is a no-op that still runs its block", inside == 0)
    from controller.models import database
    check("the pool maximum is read from the DSN's maxsize",
          identity._pool_max_size("postgres://u:p@db:5432/x?maxsize=6") == 6)
    check("...raised to the floor _pooled_url applies",
          identity._pool_max_size("postgres://u:p@db:5432/x?maxsize=1") == 2)
    check("...and DB_POOL_MAX without one",
          identity._pool_max_size("postgres://u:p@db:5432/x") == database.DB_POOL_MAX)


async def test_cutover_pending(tenant, stub):
    print("\n7h) before the cutover Judge changes nothing")
    row, key = await consumed_challenge(tenant, link=await make_link(tenant))
    stub.set_identity("U-EARLY", issued(row, key, "e"))
    calls_before = len(stub.calls)
    identity.reset_cutover_cache()
    try:
        decision = await identity.judge("U-EARLY", device=None)
    finally:
        identity.set_cutover_cache(True)
    await row.refresh_from_db()
    check("an unapplied no-op decision",
          not decision.accepted and decision.reason == "cutover_pending" and not decision.applied)
    check("...with nothing written", len(stub.calls) == calls_before and row.bound_udid is None
          and not await EnrollmentAttempt.filter(udid="U-EARLY").exists())


async def test_stale_identity(tenant, stub):
    print("\n7i) a refused Authenticate's certificate left in NanoMDM's devices row")
    row, key = await consumed_challenge(tenant, link=await make_link(tenant))
    legit = issued(row, key, "1")
    stub.set_identity("U-STALE", legit)
    check("the first enrollment is accepted", (await identity.judge("U-STALE", device=None)).accepted)
    dev = await device(tenant, "U-STALE", "S-STALE", identity_sha256=legit.cert_sha256,
                       bootstrap_token_escrowed=True)
    dev.push_token_enc = identity.seal_push_token(dev, "beef", "magic-s")
    await dev.save()
    accepted = await identity.judge("U-STALE", device=dev, topic="mdm.TokenUpdate")
    dev = await Device.get(udid="U-STALE")
    check("an accepted judgement keeps the certificate's PEM",
          accepted.accepted and dev.identity_pem == stub.pem_for(legit))

    bad = Identity(h("2"), h("0"), "someone else", NOW)
    stub.set_identity("U-STALE", bad)
    stub.associations["U-STALE"] = {legit.cert_sha256, bad.cert_sha256}
    calls = len(stub.calls)
    refused = await identity.judge("U-STALE", device=dev)
    dev = await Device.get(udid="U-STALE")
    new_calls = stub.calls[calls:]
    check("a refusal parks the certificate",
          refused.reason == "unknown_cn" and ("park", "U-STALE", h("2")) in new_calls)
    check("...writes the accepted certificate back to the devices row",
          ("restore_identity", "U-STALE", (stub.pem_for(legit), "S-STALE", stub.pem_for(bad))) in new_calls
          and stub.overrides["U-STALE"].cert_sha256 == legit.cert_sha256)
    check("...restores the push token", ("restore_push", "U-STALE", ("beef", "magic-s", True)) in new_calls)
    alert = await Alert.filter(device_id=dev.id, rule_id=identity.ALERT_RULE_REFUSED).first()
    check("...and clears bootstrap_token_escrowed and says so in the alert",
          dev.bootstrap_token_escrowed is False and alert is not None
          and "escrowed bootstrap token was cleared" in alert.summary)

    # Without a PEM to write back the parked certificate stays in the devices row.
    await Device.filter(id=dev.id).update(identity_pem=None)
    dev = await Device.get(udid="U-STALE")
    stub.overrides["U-STALE"] = bad
    calls = len(stub.calls)
    for topic in ("mdm.TokenUpdate", "mdm.Connect"):
        decision = await identity.judge("U-STALE", device=dev, topic=topic)
        check(f"a {topic} with a parked certificate in the devices row is an unapplied no-op",
              decision.reason == "stale_identity" and not decision.applied)
    check("...that writes nothing", len(stub.calls) == calls)
    refused = await identity.judge("U-STALE", device=dev)
    check("a judgement without a topic still refuses it, but never restores the push token",
          not refused.accepted and not [c for c in stub.calls[calls:] if c[0] == "restore_push"])


async def test_bootstrap_token(tenant, stub):
    print("\n7j) the sealed bootstrap token copy")
    dev = await device(tenant, "U-BT-SEAL", "S-BT-SEAL")
    dev.bootstrap_token_enc = identity.seal_bootstrap_token(dev, "dG9rZW4=")
    dev.push_token_enc = identity.seal_push_token(dev, "beef", "magic-bt")
    await dev.save()
    check("a sealed bootstrap token opens with the device's binding",
          identity.open_bootstrap_token(await Device.get(id=dev.id)) == "dG9rZW4=")
    moved = await device(tenant, "U-BT-MOVED", "S-BT-MOVED", bootstrap_token_enc=dev.bootstrap_token_enc)
    check("...and not on another device", identity.open_bootstrap_token(moved) is None)
    dev.bootstrap_token_enc = dev.push_token_enc
    check("a push token ciphertext does not open as a bootstrap token", identity.open_bootstrap_token(dev) is None)

    async def refused_device(udid, char, **extra):
        """An enrolled device bound to a challenge certificate, then judged with an unknown certificate in NanoMDM."""
        row, key = await consumed_challenge(tenant, link=await make_link(tenant))
        legit = issued(row, key, char)
        stub.set_identity(udid, legit)
        check(f"{udid}: the first enrollment is accepted", (await identity.judge(udid, device=None)).accepted)
        dev = await device(tenant, udid, f"S-{udid}", identity_sha256=legit.cert_sha256,
                           identity_pem=stub.pem_for(legit), bootstrap_token_escrowed=True, **extra)
        return dev, legit

    async def refuse(dev, legit, char):
        bad = Identity(h(char), h("0"), "someone else", NOW)
        stub.set_identity(dev.udid, bad)
        stub.associations[dev.udid] = {legit.cert_sha256, bad.cert_sha256}
        stub.bootstrap[dev.udid] = ("aG9zdGlsZQ==", True)
        await identity.judge(dev.udid, device=dev)
        alert = await Alert.filter(device_id=dev.id, rule_id=identity.ALERT_RULE_REFUSED).first()
        return await Device.get(id=dev.id), alert

    dev, legit = await refused_device("U-BT-REFUSE", "3")
    dev.bootstrap_token_enc = identity.seal_bootstrap_token(dev, "dG9rZW4=")
    await dev.save(update_fields=["bootstrap_token_enc"])
    dev, alert = await refuse(dev, legit, "4")
    check("a refusal writes the sealed copy back over what the refused certificate left",
          ("restore_bootstrap_token", "U-BT-REFUSE", ("dG9rZW4=", False)) in stub.calls
          and stub.bootstrap["U-BT-REFUSE"] == ("dG9rZW4=", True))
    check("...keeps the escrow flag and says so in the alert",
          dev.bootstrap_token_escrowed is True and alert is not None
          and alert.detail.get("bootstrap_token_restored") is True
          and alert.detail.get("bootstrap_token_cleared") is False)

    dev, legit = await refused_device("U-BT-NOCOPY", "5")
    dev, alert = await refuse(dev, legit, "6")
    check("a refusal without a sealed copy clears the flag",
          dev.bootstrap_token_escrowed is False and alert is not None
          and alert.detail.get("bootstrap_token_cleared") is True
          and not [c for c in stub.bootstrap_restores if c[1] == "U-BT-NOCOPY"])
    check("...and clears the token the refused certificate left in NanoMDM",
          ("clear_bootstrap_token", "U-BT-NOCOPY", False) in stub.calls
          and stub.bootstrap["U-BT-NOCOPY"] == (None, False))

    dev, legit = await refused_device("U-BT-FAIL", "7")
    dev.bootstrap_token_enc = identity.seal_bootstrap_token(dev, "dG9rZW4=")
    await dev.save(update_fields=["bootstrap_token_enc"])
    stub.fail_bootstrap = {"restore"}
    try:
        dev, alert = await refuse(dev, legit, "8")
    finally:
        stub.fail_bootstrap = set()
    check("a refusal whose write fails clears the flag and keeps the copy",
          dev.bootstrap_token_escrowed is False and identity.open_bootstrap_token(dev) == "dG9rZW4="
          and alert is not None and alert.detail.get("bootstrap_token_cleared") is True)
    check("...and clears the token the refused certificate left in NanoMDM",
          stub.bootstrap["U-BT-FAIL"] == (None, False))

    print("\n7l) a fresh bind the reconciler applies drops the old install's bootstrap token")
    row, key = await consumed_challenge(tenant, link=await make_link(tenant))
    gone = await device(tenant, "U-BT-FRESH", "S-BT-FRESH", state="unenrolled", bootstrap_token_escrowed=True)
    gone.bootstrap_token_enc = identity.seal_bootstrap_token(gone, "b2xk")
    await gone.save(update_fields=["bootstrap_token_enc"])
    stub.set_identity("U-BT-FRESH", issued(row, key, "9"))
    decision = await identity.judge("U-BT-FRESH", device=gone)
    gone = await Device.get(id=gone.id)
    check("the sealed copy and the flag are cleared",
          decision.accepted and decision.applied and gone.bootstrap_token_enc is None
          and gone.bootstrap_token_escrowed is False
          and not [c for c in stub.bootstrap_restores if c[1] == "U-BT-FRESH"])

    print("\n7k) an accepted Authenticate on the same install writes the sealed copy back")
    legacy = await device(tenant, "U-BT-LEGACY", "S-BT-LEGACY", bootstrap_token_escrowed=False)
    legacy.bootstrap_token_enc = identity.seal_bootstrap_token(legacy, "dG9rZW4=")
    await legacy.save(update_fields=["bootstrap_token_enc"])
    decision = await identity.judge("U-BT-LEGACY", device=legacy, topic="mdm.Authenticate")
    legacy = await Device.get(id=legacy.id)
    check("a legacy Authenticate on an enrolled row writes it back while NanoMDM's is unset",
          decision.accepted and decision.bootstrap_token_restored is True
          and ("restore_bootstrap_token", "U-BT-LEGACY", ("dG9rZW4=", True)) in stub.calls
          and legacy.bootstrap_token_escrowed is True)
    decision = await identity.judge("U-BT-LEGACY", device=legacy, topic="mdm.TokenUpdate")
    check("a TokenUpdate writes nothing", decision.accepted and decision.bootstrap_token_restored is None)
    stub.bootstrap["U-BT-LEGACY"] = ("bmV3ZXI=", True)
    decision = await identity.judge("U-BT-LEGACY", device=legacy)
    legacy = await Device.get(id=legacy.id)
    check("the reconciler's judgement leaves a token the device escrowed since, and the flag",
          decision.bootstrap_token_restored is False and stub.bootstrap["U-BT-LEGACY"] == ("bmV3ZXI=", True)
          and legacy.bootstrap_token_escrowed is True)
    stub.bootstrap["U-BT-LEGACY"] = (None, False)
    stub.fail_bootstrap = {"restore"}
    try:
        decision = await identity.judge("U-BT-LEGACY", device=legacy, topic="mdm.Authenticate")
    finally:
        stub.fail_bootstrap = set()
    legacy = await Device.get(id=legacy.id)
    alert = await Alert.filter(device_id=legacy.id, rule_id=identity.ALERT_RULE_BOOTSTRAP).first()
    check("a failed write clears the flag, keeps the copy and raises an alert",
          decision.accepted and legacy.bootstrap_token_escrowed is False
          and identity.open_bootstrap_token(legacy) == "dG9rZW4=" and alert is not None
          and alert.detail.get("bootstrap_token_restored") is False and alert.detail.get("udid") == "U-BT-LEGACY")


async def renewal_bound(tenant, stub, udid, prev_char, new_char, minted_pem=None):
    """An enrolled device holding prev_char's certificate (PEM included) whose renewal to new_char is bound while its
    task is still pending. Returns (device, task, renewal row, previous identity, renewal identity)."""
    old = Identity(h(prev_char), h("0"), "mm first", NOW + timedelta(days=30))
    dev = await device(tenant, udid, f"S-{udid}", identity_sha256=old.cert_sha256, identity_pem=stub.pem_for(old))
    earlier = NOW - timedelta(days=300)
    await ScepChallenge.create(tenant=tenant, origin="manual", challenge_hash=hashlib.sha256(udid.encode()).hexdigest(),
                               subject_cn="mm first", expires_at=earlier, consumed_at=earlier, bound_at=earlier,
                               bound_udid=udid, cert_sha256=old.cert_sha256)
    task = await Task.create(tenant=tenant, device=dev, type="enrollment_renew", status="pending",
                             description="renew")
    row, key = await consumed_challenge(tenant, device=dev, task=task, lifetime=el.RENEWAL_LIFETIME)
    if minted_pem:
        await ScepChallenge.filter(id=row.id).update(previous_pem=minted_pem)
    new = issued(row, key, new_char)
    stub.set_identity(udid, new)
    stub.associations[udid] = {old.cert_sha256, new.cert_sha256}
    check(f"{udid}: the renewal is accepted", (await identity.judge(udid, device=dev)).accepted)
    await row.refresh_from_db()
    return await Device.get(id=dev.id), task, row, old, new


async def test_renewal_rollback(tenant, stub):
    print("\n7m) a forced rollback restores the previous certificate's PEM, in the row and in NanoMDM")
    dev, task, row, old, new = await renewal_bound(tenant, stub, "U-RB-OK", "p", "q")
    check("the renewal bind keeps the device's previous PEM on the row", row.previous_pem == stub.pem_for(old))
    check("fail_renewal with force rolls back", await identity.fail_renewal(dev, task_id=task.id, force=True) is True)
    dev = await Device.get(id=dev.id)
    await row.refresh_from_db()
    check("...identity_sha256 and identity_pem are the previous certificate's",
          dev.identity_sha256 == old.cert_sha256 and dev.identity_pem == stub.pem_for(old))
    check("...NanoMDM's identity certificate is written back while it still names the renewal certificate",
          [c[2] for c in stub.identity_restores if c[1] == "U-RB-OK"]
          == [(stub.pem_for(old), "S-U-RB-OK", stub.pem_for(new))])
    check("...so NanoMDM reads the previous certificate again",
          (await stub.list_identities(["U-RB-OK"]))["U-RB-OK"].cert_sha256 == old.cert_sha256)
    check("...the renewal certificate is pruned", stub.associations["U-RB-OK"] == {old.cert_sha256})
    check("...and the row loses its certificate and previous PEM",
          row.cert_sha256 is None and row.previous_pem is None and as_utc(row.expires_at) <= datetime.now(timezone.utc))

    dev, task, row, old, new = await renewal_bound(tenant, stub, "U-RB-NOPEM", "p", "q")
    await ScepChallenge.filter(id=row.id).update(previous_pem=None)
    check("without a previous PEM the rollback still runs",
          await identity.fail_renewal(dev, task_id=task.id, force=True) is True)
    dev = await Device.get(id=dev.id)
    check("...identity_pem is left empty and NanoMDM is not written",
          dev.identity_sha256 == old.cert_sha256 and dev.identity_pem is None
          and not [c for c in stub.identity_restores if c[1] == "U-RB-NOPEM"])

    dev, task, row, old, new = await renewal_bound(tenant, stub, "U-RB-WRONG", "p", "q")
    await ScepChallenge.filter(id=row.id).update(previous_pem=stub.pem_for(new))
    await identity.fail_renewal(dev, task_id=task.id, force=True)
    dev = await Device.get(id=dev.id)
    check("a previous PEM that is not the previous certificate is not used",
          dev.identity_sha256 == old.cert_sha256 and dev.identity_pem is None
          and not [c for c in stub.identity_restores if c[1] == "U-RB-WRONG"])

    dev, task, row, old, new = await renewal_bound(tenant, stub, "U-RB-THIRD", "p", "q")
    third = Identity(h("r"), h("0"), "mm third", NOW)
    stub.overrides["U-RB-THIRD"] = third
    await identity.fail_renewal(dev, task_id=task.id, force=True)
    check("a NanoMDM row that names a third certificate is not overwritten",
          len([c for c in stub.identity_restores if c[1] == "U-RB-THIRD"]) == 1
          and stub.overrides["U-RB-THIRD"] is third)

    dev, task, row, old, new = await renewal_bound(tenant, stub, "U-RB-PRUNED", "p", "q")
    stub.associations["U-RB-PRUNED"] = {new.cert_sha256}
    prunes = len(stub.prunes)
    check("a forced Error after the previous certificate was pruned rolls nothing back",
          await identity.fail_renewal(dev, task_id=task.id, force=True) is False)
    dev = await Device.get(id=dev.id)
    await row.refresh_from_db()
    check("...the device keeps the renewal certificate",
          dev.identity_sha256 == new.cert_sha256 and dev.identity_pem == stub.pem_for(new))
    check("...NanoMDM is neither pruned nor written",
          stub.associations["U-RB-PRUNED"] == {new.cert_sha256} and len(stub.prunes) == prunes
          and not [c for c in stub.identity_restores if c[1] == "U-RB-PRUNED"])
    check("...the row is expired and keeps its certificate",
          row.cert_sha256 == new.cert_sha256 and as_utc(row.expires_at) <= datetime.now(timezone.utc))
    check("...and a renewal alert is open",
          await Alert.filter(device_id=dev.id, rule_id=identity.ALERT_RULE_RENEWAL, status="open").exists())

    dev, task, row, old, new = await renewal_bound(tenant, stub, "U-RB-UNREAD", "p", "q")
    import controller.services.nanomdm_store as store
    reader = store.list_associations

    async def unreadable(udid):
        raise RuntimeError("NanoMDM database: unreachable")

    prunes = len(stub.prunes)
    store.list_associations = unreadable
    try:
        rolled = await identity.fail_renewal(dev, task_id=task.id, force=True)
    finally:
        store.list_associations = reader
    dev = await Device.get(id=dev.id)
    await row.refresh_from_db()
    check("unreadable associations still roll the device row back",
          rolled is True and dev.identity_sha256 == old.cert_sha256 and dev.identity_pem == stub.pem_for(old)
          and row.cert_sha256 is None)
    check("...without pruning", len(stub.prunes) == prunes)
    check("...and writes NanoMDM's identity certificate back only while it names the renewal certificate",
          [c[2] for c in stub.identity_restores if c[1] == "U-RB-UNREAD"]
          == [(stub.pem_for(old), "S-U-RB-UNREAD", stub.pem_for(new))]
          and stub.overrides["U-RB-UNREAD"].cert_sha256 == old.cert_sha256)

    # The write back failed and the associations read again: NanoMDM still names the renewal certificate.
    stub.overrides["U-RB-UNREAD"] = new
    stub.associations["U-RB-UNREAD"] = {old.cert_sha256, new.cert_sha256}
    decision = await identity.judge("U-RB-UNREAD", device=dev)
    dev = await Device.get(id=dev.id)
    await row.refresh_from_db()
    check("Judge refuses the certificate of a rolled-back renewal row",
          not decision.accepted and decision.reason == "renewal_rolled_back", str(decision.reason))
    check("...the row does not bind again and the previous certificate stays the identity",
          row.cert_sha256 is None and dev.identity_sha256 == old.cert_sha256
          and dev.identity_pem == stub.pem_for(old))
    check("...and the renewal certificate is parked",
          ("park", "U-RB-UNREAD", new.cert_sha256) in stub.calls
          and stub.associations["U-RB-UNREAD"] == {old.cert_sha256})

    minted = stub.pem_for(Identity(h("m"), h("0"), "mm parked", NOW))
    dev, task, row, old, new = await renewal_bound(tenant, stub, "U-RB-MINTED", "p", "q", minted_pem=minted)
    check("a minted previous PEM naming another certificate is replaced by the device's at the bind",
          row.previous_pem == stub.pem_for(old))
    dev, task, row, old, new = await renewal_bound(tenant, stub, "U-RB-KEEPMINT", "p", "q",
                                                   minted_pem=stub.pem_for(Identity(h("p"), h("0"), "mm first", NOW)))
    check("...and one naming the previous certificate is kept", row.previous_pem == stub.pem_for(old))

    dev, task, row, old, new = await renewal_bound(tenant, stub, "U-RB-MOVED", "p", "q")
    await Device.filter(id=dev.id).update(identity_sha256=h("x"), identity_pem=None)
    stub.associations["U-RB-MOVED"] = {old.cert_sha256, new.cert_sha256, h("x")}
    await identity.fail_renewal(await Device.get(id=dev.id), task_id=task.id, force=True)
    dev = await Device.get(id=dev.id)
    check("a rollback after the identity moved past the renewal keeps only the current identity",
          dev.identity_sha256 == h("x") and stub.associations["U-RB-MOVED"] == {h("x")},
          str(stub.associations["U-RB-MOVED"]))

    print("\n7r) finish_renewal prunes only while the renewal is the device's identity")
    dev, task, row, old, new = await renewal_bound(tenant, stub, "U-FIN-STALE", "p", "q")
    stale = await Device.get(id=dev.id)
    stale.identity_sha256 = old.cert_sha256  # what a row loaded before the bind holds
    await Task.filter(id=task.id).update(status="completed")
    await identity.finish_renewal(stale, task_id=task.id)
    check("a device object loaded before the bind is refreshed and the renewed certificate kept",
          stub.associations["U-FIN-STALE"] == {new.cert_sha256}, str(stub.associations["U-FIN-STALE"]))
    dev, task, row, old, new = await renewal_bound(tenant, stub, "U-FIN-OTHER", "p", "q")
    await Device.filter(id=dev.id).update(identity_sha256=h("x"))
    prunes = len(stub.prunes)
    removed = await identity.finish_renewal(await Device.get(id=dev.id), task_id=task.id)
    check("a renewal row whose certificate is not the device's identity prunes nothing",
          removed == 0 and len(stub.prunes) == prunes
          and stub.associations["U-FIN-OTHER"] == {old.cert_sha256, new.cert_sha256})

    dev, task, row, old, new = await renewal_bound(tenant, stub, "U-RB-FIN", "p", "q")
    await Task.filter(id=task.id).update(status="completed")
    check("the renewal row keeps the previous PEM until finish_renewal", row.previous_pem == stub.pem_for(old))
    await identity.finish_renewal(dev, task_id=task.id)
    await row.refresh_from_db()
    check("...and finish_renewal with the renewal's task id clears it", row.previous_pem is None)


async def test_refusal_compare_and_set(tenant, stub):
    print("\n7n) a refusal writes the accepted certificate back only over the refused one")
    row, key = await consumed_challenge(tenant, link=await make_link(tenant))
    legit = issued(row, key, "s")
    stub.set_identity("U-CAS", legit)
    check("the first enrollment is accepted", (await identity.judge("U-CAS", device=None)).accepted)
    dev = await device(tenant, "U-CAS", "S-CAS", identity_sha256=legit.cert_sha256, identity_pem=stub.pem_for(legit))
    bad = Identity(h("t"), h("0"), "someone else", NOW)
    stub.set_identity("U-CAS", bad)
    stub.associations["U-CAS"] = {legit.cert_sha256, bad.cert_sha256}
    decision = await identity.judge("U-CAS", device=dev, apply=False)
    newer = Identity(h("u"), h("0"), "mm newer", NOW)
    stub.overrides["U-CAS"] = newer
    await identity.apply_refusal(decision, "U-CAS", dev)
    check("a newer identity certificate stored since the refused one is left in place",
          [c[2] for c in stub.identity_restores if c[1] == "U-CAS"]
          == [(stub.pem_for(legit), "S-CAS", stub.pem_for(bad))] and stub.overrides["U-CAS"] is newer)

    print("\n7n2) a refusal records the writes it could not make on its alert")
    import controller.services.nanomdm_store as store

    row, key = await consumed_challenge(tenant, link=await make_link(tenant))
    legit = issued(row, key, "k")
    stub.set_identity("U-CAS-DOWN", legit)
    check("the first enrollment is accepted", (await identity.judge("U-CAS-DOWN", device=None)).accepted)
    dev = await device(tenant, "U-CAS-DOWN", "S-CAS-DOWN", identity_sha256=legit.cert_sha256,
                       identity_pem=stub.pem_for(legit))
    dev.push_token_enc = identity.seal_push_token(dev, "beef", "magic-down")
    await dev.save(update_fields=["push_token_enc"])
    bad = Identity(h("l"), h("0"), "someone else", NOW)
    stub.set_identity("U-CAS-DOWN", bad)
    stub.associations["U-CAS-DOWN"] = {legit.cert_sha256, bad.cert_sha256}

    async def raising(*_args, **_kwargs):
        raise RuntimeError("NanoMDM database: down")

    store.restore_identity, store.restore_push = raising, raising
    try:
        decision = await identity.judge("U-CAS-DOWN", device=dev)
    finally:
        store.restore_identity, store.restore_push = stub.restore_identity, stub.restore_push
    alert = await Alert.get_or_none(device_id=dev.id, rule_id=identity.ALERT_RULE_REFUSED)
    check("the refusal is applied, with both writes recorded as failed",
          decision.applied and alert is not None and alert.detail.get("identity_restored") is False
          and alert.detail.get("push_restored") is False, str(alert and alert.detail))
    check("...and NanoMDM still names the refused certificate", stub.overrides["U-CAS-DOWN"] is bad)


async def test_capture(tenant, stub):
    print("\n7o) capture_bootstrap_token seals NanoMDM's token for a settled identity")

    async def fresh(udid, **extra):
        dev = await device(tenant, udid, f"S-{udid}", **extra)
        await stub.get_identity(udid)
        return dev

    async def gets(udid):
        return len([c for c in stub.calls if c[0] == "get_bootstrap_token" and c[1] == udid])

    dev = await fresh("U-CAP")
    await Alert.create(tenant=tenant, device=dev, rule_id=identity.ALERT_RULE_BOOTSTRAP, severity="red",
                       status="open", summary="lost", opened_at=NOW, detail={})
    check("nothing while NanoMDM holds no token", await identity.capture_bootstrap_token(dev, "U-CAP") is False)
    stub.bootstrap["U-CAP"] = ("Y2FwdHVyZQ==", True)
    check("a token with no sealed copy is captured", await identity.capture_bootstrap_token(dev, "U-CAP") is True)
    dev = await Device.get(id=dev.id)
    check("...sealed, with the flag set and the bootstrap token alert resolved",
          identity.open_bootstrap_token(dev) == "Y2FwdHVyZQ==" and dev.bootstrap_token_escrowed is True
          and not await Alert.filter(device_id=dev.id, rule_id=identity.ALERT_RULE_BOOTSTRAP).exclude(
              status="resolved").exists())
    reads = await gets("U-CAP")
    check("a copy that opens with the flag set reads nothing",
          await identity.capture_bootstrap_token(dev, "U-CAP") is False and await gets("U-CAP") == reads)

    kept = await fresh("U-CAP-KEEP")
    kept.bootstrap_token_enc = identity.seal_bootstrap_token(kept, "b2xk")
    await kept.save(update_fields=["bootstrap_token_enc"])
    stub.bootstrap["U-CAP-KEEP"] = ("bmV3", True)
    check("a copy that differs is kept", await identity.capture_bootstrap_token(kept, "U-CAP-KEEP") is False
          and identity.open_bootstrap_token(await Device.get(id=kept.id)) == "b2xk")
    check("...unless replace is given", await identity.capture_bootstrap_token(kept, "U-CAP-KEEP", replace=True)
          and identity.open_bootstrap_token(await Device.get(id=kept.id)) == "bmV3")

    same = await fresh("U-CAP-SAME")
    same.bootstrap_token_enc = identity.seal_bootstrap_token(same, "c2FtZQ==")
    await same.save(update_fields=["bootstrap_token_enc"])
    stub.bootstrap["U-CAP-SAME"] = ("c2FtZQ==", True)
    check("a copy equal to NanoMDM's token only sets the flag",
          await identity.capture_bootstrap_token(same, "U-CAP-SAME") is True
          and (await Device.get(id=same.id)).bootstrap_token_escrowed is True)

    stray = await fresh("U-CAP-STRAY")
    stub.bootstrap["U-CAP-STRAY"] = ("c3RyYXk=", True)
    stub.associations["U-CAP-STRAY"].add(h("z"))
    check("an unsettled identity is not read", await identity.capture_bootstrap_token(stray, "U-CAP-STRAY") is False
          and await gets("U-CAP-STRAY") == 0)

    gone = await fresh("U-CAP-GONE", state="unenrolled")
    stub.bootstrap["U-CAP-GONE"] = ("Z29uZQ==", True)
    check("an unenrolled row is skipped", await identity.capture_bootstrap_token(gone, "U-CAP-GONE") is False)

    failing = await fresh("U-CAP-FAIL")
    stub.bootstrap["U-CAP-FAIL"] = ("ZmFpbA==", True)
    stub.fail_bootstrap = {"get"}
    try:
        captured = await identity.capture_bootstrap_token(failing, "U-CAP-FAIL")
    finally:
        stub.fail_bootstrap = set()
    failing = await Device.get(id=failing.id)
    check("a read failure writes nothing",
          captured is False and failing.bootstrap_token_enc is None and failing.bootstrap_token_escrowed is False)

    refused = await fresh("U-CAP-REFUSED")
    stub.bootstrap["U-CAP-REFUSED"] = ("cmVmdXNlZA==", True)
    alert = await Alert.create(tenant=tenant, device=refused, rule_id=identity.ALERT_RULE_REFUSED, severity="red",
                               status="open", summary="refused", opened_at=datetime.now(timezone.utc),
                               detail={"last_seen_at": datetime.now(timezone.utc).isoformat()})
    check("nothing within five minutes of a refusal",
          await identity.capture_bootstrap_token(refused, "U-CAP-REFUSED") is False)
    alert.detail = {"last_seen_at": (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat()}
    await alert.save()
    check("...and the token is captured once the window has passed",
          await identity.capture_bootstrap_token(refused, "U-CAP-REFUSED") is True)

    print("\n7p) a renewal Authenticate replaces the copy with a token NanoMDM kept over the write back")
    for udid, stray_char in (("U-CAP-RENEW", None), ("U-CAP-RENEW-STRAY", "y")):
        old = Identity(h("v"), h("0"), "mm first", NOW + timedelta(days=30))
        dev = await device(tenant, udid, f"S-{udid}", identity_sha256=old.cert_sha256, bootstrap_token_escrowed=True)
        dev.bootstrap_token_enc = identity.seal_bootstrap_token(dev, "b2xk")
        await dev.save(update_fields=["bootstrap_token_enc"])
        earlier = NOW - timedelta(days=300)
        await ScepChallenge.create(tenant=tenant, origin="manual",
                                   challenge_hash=hashlib.sha256(udid.encode()).hexdigest(), subject_cn="mm first",
                                   expires_at=earlier, consumed_at=earlier, bound_at=earlier, bound_udid=udid,
                                   cert_sha256=old.cert_sha256)
        task = await Task.create(tenant=tenant, device=dev, type="enrollment_renew", status="pending",
                                 description="renew")
        row, key = await consumed_challenge(tenant, device=dev, task=task, lifetime=el.RENEWAL_LIFETIME)
        stub.set_identity(udid, issued(row, key, "w"))
        stub.associations[udid].add(old.cert_sha256)
        if stray_char:
            stub.associations[udid].add(h(stray_char))
        stub.bootstrap[udid] = ("bmV3", True)
        decision = await identity.judge(udid, device=dev, topic="mdm.Authenticate")
        dev = await Device.get(id=dev.id)
        if stray_char is None:
            check("the newer token is sealed over the old copy",
                  decision.accepted and decision.bootstrap_token_restored is False
                  and identity.open_bootstrap_token(dev) == "bmV3" and dev.bootstrap_token_escrowed is True)
        else:
            check("...but not when the same acceptance pruned another certificate",
                  decision.accepted and identity.open_bootstrap_token(dev) == "b2xk")


async def test_checkout(tenant, stub):
    print("\n7q) checkout_allowed after a refusal and with an unreadable identity")
    dev = await device(tenant, "U-CO", "S-CO")
    await stub.get_identity("U-CO")
    check("a CheckOut on the device's own identity is allowed", await identity.checkout_allowed(dev, "U-CO"))
    await alerts.raise_or_bump(dev, identity.ALERT_RULE_REFUSED, "identity_refused", "refused", {})
    alert = await Alert.get(device_id=dev.id, rule_id=identity.ALERT_RULE_REFUSED)
    seen = alert.detail["last_seen_at"]
    check("recently_refused holds right after a refusal", await identity.recently_refused(dev))
    check("...and not once the window has passed",
          not await identity.recently_refused(dev, now=datetime.now(timezone.utc) + timedelta(minutes=6)))
    check("a CheckOut within five minutes of a refusal is ignored",
          await identity.checkout_allowed(dev, "U-CO") is False)
    rows = await attempts("bad_identity", "U-CO")
    check("...recorded as checkout_refused with the cause",
          len(rows) == 1 and rows[0].detail.get("reason") == "checkout_refused"
          and rows[0].detail.get("cause") == "recent_refusal", str([r.detail for r in rows]))
    alert = await Alert.get(id=alert.id)
    check("...and counted on the refusal alert without moving its last refusal",
          alert.detail.get("ignored", {}).get("checkout", {}).get("count") == 1
          and alert.detail["last_seen_at"] == seen)
    alert.detail = {**alert.detail, "last_seen_at": (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat()}
    await alert.save()
    check("a CheckOut after the window is allowed again", await identity.checkout_allowed(dev, "U-CO"))

    unread = await device(tenant, "U-CO-UNREAD", "S-CO-UNREAD")
    await stub.get_identity("U-CO-UNREAD")
    import controller.services.nanomdm_store as store
    reader, failures = store.get_identity, []

    async def flaky(udid):
        if len(failures) < limit:
            failures.append(udid)
            raise RuntimeError("NanoMDM database: unreachable")
        return await reader(udid)

    store.get_identity = flaky
    try:
        limit = 1
        once = await identity.checkout_allowed(unread, "U-CO-UNREAD")
        failures.clear()
        limit = 2
        twice = await identity.checkout_allowed(unread, "U-CO-UNREAD")
    finally:
        store.get_identity = reader
    check("one failed identity read is retried", once is True)
    rows = await attempts("bad_identity", "U-CO-UNREAD")
    check("two failed reads refuse the CheckOut with the cause identity_unreadable",
          twice is False and len(rows) == 1 and rows[0].detail.get("cause") == "identity_unreadable")
    check("...and raise a checkout alert rather than a refusal alert",
          await Alert.filter(device_id=unread.id, rule_id=identity.ALERT_RULE_CHECKOUT, status="open").exists()
          and not await Alert.filter(device_id=unread.id, rule_id=identity.ALERT_RULE_REFUSED).exists())


async def test_reconciler(stub):
    print("\n8) reconciler_candidates")
    stub.associations["U-STRAY"] = {h("5")}
    candidates = await identity.reconciler_candidates()
    check("a udid holding a hash outside its allowed set is a candidate", "U-STRAY" in candidates)
    check("a device whose associations match its identity is not a candidate", "U-HELD" not in candidates)


async def test_cutover(stub):
    print("\n9) cutover")
    await IdentityCutover.all().delete()
    await LegacyIdentity.all().delete()
    identity.reset_cutover_cache()
    stub.uninstall()
    fresh = install_identity_stub()
    identity.reset_cutover_cache()

    async def unreachable(udids=None):
        raise RuntimeError("NanoMDM database: unreachable")

    reader = fresh.list_identities
    import controller.services.nanomdm_store as store
    store.list_identities = unreachable
    check("an unreachable NanoMDM skips the cutover", await identity.run_cutover() is False)
    check("...and writes nothing", not await IdentityCutover.exists() and not await LegacyIdentity.exists())
    store.list_identities = reader
    check("no stamp exists before the cutover runs", not await IdentityCutover.exists())

    one = Identity(h("a"), h("b"), "t1 MDM Device " + "cd" * 16, NOW)
    fresh.overrides["U-C1"] = one
    fresh.associations["U-C1"] = {h("a"), h("d")}
    fresh.overrides["U-C2"] = None
    fresh.associations["U-C2"] = {h("e"), h("f")}
    # U-C3 re-enrolls during the cutover, so NanoMDM records its new certificate between the reads and the prune.
    old_c3 = Identity(h("1"), h("2"), "t1 MDM Device " + "ab" * 16, NOW)
    new_c3 = Identity(h("3"), h("4"), "t1 MDM Device " + "ef" * 16, NOW)
    fresh.overrides["U-C3"] = old_c3
    fresh.associations["U-C3"] = {h("1")}
    pruner = fresh.prune_associations_bulk

    async def reenrolling_prune(keep):
        fresh.overrides["U-C3"] = new_c3
        return await pruner(keep)

    store.prune_associations_bulk = reenrolling_prune
    try:
        check("the cutover runs", await identity.run_cutover() is True)
    finally:
        store.prune_associations_bulk = pruner
    check("a udid with an identity collapses to it", fresh.associations["U-C1"] == {h("a")})
    check("a udid without one keeps every association", fresh.associations["U-C2"] == {h("e"), h("f")})
    snapshot = set(await LegacyIdentity.all().values_list("udid", "cert_sha256"))
    check("the snapshot holds what remains, plus the certificate of a udid that re-enrolled during the cutover",
          snapshot == {("U-C1", h("a")), ("U-C2", h("e")), ("U-C2", h("f")), ("U-C3", h("1")), ("U-C3", h("3"))},
          str(snapshot))
    check("...and that certificate is associated again",
          ("add_association", "U-C3", h("3")) in fresh.calls and fresh.associations["U-C3"] == {h("1"), h("3")})
    check("the stamp is written", await IdentityCutover.filter(id=1, snapshot_done=True).exists())
    reenrolled = await Device.create(tenant=await Tenant.get(id="t1"), udid="U-C3", serial_number="S-C3",
                                     device_model="Mac", os_version="15.0", enrollment_state="enrolled")
    check("...so Judge accepts that certificate once the device re-associates it",
          (await identity.judge("U-C3", device=reenrolled)).accepted)
    prunes = len(fresh.prunes)
    check("a second run does nothing", await identity.run_cutover() is True and len(fresh.prunes) == prunes)

    # The same race when the association cannot be written back: the snapshot alone carries the certificate.
    await IdentityCutover.all().delete()
    await LegacyIdentity.all().delete()
    identity.reset_cutover_cache()
    fresh.overrides["U-C3"] = old_c3
    fresh.associations["U-C3"] = {h("1")}

    async def refusing_add(udid, sha256):
        raise RuntimeError("NanoMDM database: adding a certificate association failed")

    store.prune_associations_bulk, store.add_association = reenrolling_prune, refusing_add
    try:
        check("the cutover still runs when the association cannot be added", await identity.run_cutover() is True)
    finally:
        store.prune_associations_bulk, store.add_association = pruner, fresh.add_association
    check("...and the snapshot alone carries the new certificate",
          ("U-C3", h("3")) in set(await LegacyIdentity.all().values_list("udid", "cert_sha256"))
          and fresh.associations["U-C3"] == {h("1")})


async def main():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()
    tenant = await Tenant.create(id="t1", name="Tenant One")
    stub = install_identity_stub()

    await test_allowed(tenant, stub)
    await test_judge(tenant, stub)
    await test_cross_tenant(tenant, stub)
    await test_takeover(tenant, stub)
    await test_failed_renewal_rebind(tenant, stub)
    await test_attempt_dedupe(tenant, stub)
    await test_udid_lock()
    await test_cutover_pending(tenant, stub)
    await test_stale_identity(tenant, stub)
    await test_bootstrap_token(tenant, stub)
    await test_renewal_rollback(tenant, stub)
    await test_refusal_compare_and_set(tenant, stub)
    await test_capture(tenant, stub)
    await test_checkout(tenant, stub)
    await test_reconciler(stub)
    await test_cutover(stub)

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run  # noqa: E402

run(main)
