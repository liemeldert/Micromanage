"""Identity certificate renewal (services.identity_renewal) and the reconciler pass, against the harness's NanoMDM stub
on in-memory sqlite.

Run: PYTHONPATH=. python tests/enrollment/verify_identity_renewal.py
"""
import hashlib
import logging
import os
import tempfile
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.fernet import Fernet

_TMP = Path(tempfile.mkdtemp(prefix="verify-identity-renewal-"))
os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["JWT_SECRET"] = "test-secret-for-identity-renewal"
os.environ["PUBLIC_API_URL"] = "https://mdm.example.test"
os.environ["MDM_HOSTNAME"] = "mdm.example.test"
os.environ["MDM_TOPIC"] = "com.apple.mgmt.External.test"
os.environ["YAML_CONFIG_PATH"] = str(_TMP)
os.environ.pop("SCEP_WEBHOOK_SECRET_FILE", None)
os.environ.pop("IDENTITY_RENEW_DAYS", None)

from tortoise import Tortoise  # noqa: E402

from controller.models.tenant import (  # noqa: E402
    Alert, Device, EnrollmentAttempt, LegacyIdentity, ScepChallenge, Task, Tenant, User,
)
from controller.auth.dependencies import Principal  # noqa: E402
from controller.services import identity, identity_renewal, reconciler  # noqa: E402
from controller.services.nanomdm_store import Identity  # noqa: E402
from controller.utils.timeutil import as_utc, utcnow  # noqa: E402
from tests._verify_harness import install_identity_stub, make_check  # noqa: E402

PASS, FAIL = [], []
check = make_check(FAIL, PASS)


class FakeConnector:
    def __init__(self, fail=False):
        self.fail = fail
        self.sent = []
        self.closed = False

    async def install_profile_bytes(self, udid, profile):
        self.sent.append((udid, profile))
        if self.fail:
            raise RuntimeError("nanomdm unreachable")
        return {"command_uuid": str(uuid.uuid4()), "push_failed": False, "push_errors": {}}

    async def close(self):
        self.closed = True


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def challenge_identity(udid, days_left):
    return Identity(cert_sha256=sha(f"cert:{udid}"), spki_sha256=sha(f"spki:{udid}"), subject_cn=f"mm {uuid.uuid4()}",
                    not_after=datetime.now(timezone.utc) + timedelta(days=days_left))


async def device(tenant, stub, udid, days_left=None, **extra):
    """An enrolled device; days_left gives it a challenge certificate, None leaves the stub's legacy one."""
    dev = await Device.create(tenant=tenant, udid=udid, serial_number=udid[-12:], device_model="Mac",
                              os_version="15.0", enrollment_state="enrolled", **extra)
    if days_left is not None:
        ident = challenge_identity(udid, days_left)
        stub.set_identity(udid, ident)
        dev.identity_sha256 = ident.cert_sha256
        await dev.save(update_fields=["identity_sha256"])
    return dev


async def renew_tasks(dev):
    return await Task.filter(device_id=dev.id, type="enrollment_renew").all()


async def test_not_ready(tenant, stub):
    print("\n1) nothing is sent while enrollment is not ready")
    await device(tenant, stub, "U-NOTREADY", days_left=3)
    connector = FakeConnector()
    counts = await identity_renewal.scan_and_renew(connector=connector)
    check("no push without the webhook secret file", counts["pushed"] == 0 and not connector.sent, str(counts))
    check("no challenge row minted", not await ScepChallenge.filter(origin="renewal").exists())
    await Device.filter(udid="U-NOTREADY").delete()


async def test_scan(tenant, stub):
    print("\n2) due devices get a task and a renewal row")
    near = await device(tenant, stub, "U-NEAR", days_left=10)
    legacy = await device(tenant, stub, "U-LEGACY")
    fresh = await device(tenant, stub, "U-FRESH", days_left=300)
    extra = await device(tenant, stub, "U-EXTRA", days_left=5)
    stub.associations["U-EXTRA"].add(sha("other"))
    stale = await device(tenant, stub, "U-STALE", days_left=5)
    await Device.filter(id=stale.id).update(last_seen=utcnow() - timedelta(days=45))
    gone = await device(tenant, stub, "U-GONE", days_left=5)
    await Device.filter(id=gone.id).update(enrollment_state="unenrolled")

    connector = FakeConnector()
    counts = await identity_renewal.scan_and_renew(connector=connector)
    check("near expiry and legacy are pushed", counts["pushed"] == 2, str(counts))
    check("the sent udids", sorted(u for u, _ in connector.sent) == ["U-LEGACY", "U-NEAR"], str(connector.sent))
    check("the profile bytes are a plist", all(p.startswith(b"<?xml") for _, p in connector.sent))
    check("a device with extra associations is skipped", counts["blocked"] == 1)
    check("the caller's connector is not closed", connector.closed is False)
    for dev in (near, legacy):
        tasks = await renew_tasks(dev)
        task = tasks[0] if len(tasks) == 1 else None
        check(f"{dev.udid}: one enrollment_renew task", task is not None, str(tasks))
        if task is None:
            continue
        check(f"{dev.udid}: task running with a command uuid", task.status == "running" and bool(task.command_uuid))
        check(f"{dev.udid}: task description", task.description == "Enrollment profile renewal")
        check(f"{dev.udid}: no profile_info in details", "profile_info" not in (task.details or {}))
        row = await ScepChallenge.get_or_none(device_id=dev.id)
        check(f"{dev.udid}: renewal row linked to the task",
              row is not None and row.origin == "renewal" and row.task_id == task.id, str(row and row.origin))
        check(f"{dev.udid}: renewal row lives 7 days",
              row is not None and timedelta(days=6, hours=23) < as_utc(row.expires_at) - utcnow() <= timedelta(days=7))
        check(f"{dev.udid}: renewal row keeps the PEM of the certificate NanoMDM holds",
              row is not None and row.previous_pem == stub.pem_for(await stub.get_identity(dev.udid)))
    for dev in (fresh, extra, stale, gone):
        check(f"{dev.udid}: no task and no row",
              not await renew_tasks(dev) and not await ScepChallenge.filter(device_id=dev.id).exists())

    print("\n3) a second run does not duplicate")
    again = FakeConnector()
    counts = await identity_renewal.scan_and_renew(connector=again)
    check("nothing sent", counts["pushed"] == 0 and not again.sent, str(counts))
    check("both open renewals counted", counts["open"] == 2, str(counts))
    check("still one task each", all([len(await renew_tasks(d)) == 1 for d in (near, legacy)]))
    check("still one row each", await ScepChallenge.filter(origin="renewal").count() == 2)

    print("\n4) a consumed renewal whose task is still running is not renewed again")
    await ScepChallenge.filter(device_id=near.id).update(consumed_at=utcnow())
    counts = await identity_renewal.scan_and_renew(connector=FakeConnector())
    check("the running task keeps it open", counts["pushed"] == 0 and counts["open"] == 2, str(counts))


async def test_limit(tenant, stub):
    print("\n5) the limit holds, most urgent first")
    for i, days in enumerate((20, 2, 9)):
        await device(tenant, stub, f"U-LIMIT-{i}", days_left=days)
    connector = FakeConnector()
    counts = await identity_renewal.scan_and_renew(limit=1, connector=connector)
    check("one push", counts["pushed"] == 1 and len(connector.sent) == 1, str(counts))
    check("the soonest expiry goes first", connector.sent and connector.sent[0][0] == "U-LIMIT-1", str(connector.sent))
    counts = await identity_renewal.scan_and_renew(limit=10, connector=FakeConnector())
    check("the next run sends the rest", counts["pushed"] == 2, str(counts))


async def test_dispatch_failure(tenant, stub):
    print("\n6) a failed send expires the row and fails the task")
    dev = await device(tenant, stub, "U-FAIL", days_left=4)
    counts = await identity_renewal.scan_and_renew(connector=FakeConnector(fail=True))
    check("counted as failed", counts["failed"] == 1 and counts["pushed"] == 0, str(counts))
    tasks = await renew_tasks(dev)
    check("one task, failed with an error", len(tasks) == 1 and tasks[0].status == "failed" and bool(tasks[0].error),
          str([(t.status, t.error) for t in tasks]))
    check("the task has completed_at", len(tasks) == 1 and tasks[0].completed_at is not None)
    row = await ScepChallenge.get_or_none(device_id=dev.id)
    check("the row is expired", row is not None and as_utc(row.expires_at) <= utcnow())

    print("\n7) the next run retries")
    connector = FakeConnector()
    counts = await identity_renewal.scan_and_renew(connector=connector)
    check("sent again", counts["pushed"] == 1 and [u for u, _ in connector.sent] == ["U-FAIL"], str(counts))
    rows = await ScepChallenge.filter(device_id=dev.id).all()
    check("the expired row was replaced", len(rows) == 1 and as_utc(rows[0].expires_at) > utcnow())


async def test_reconcile(stub):
    print("\n8) the reconcile pass judges each candidate once")
    calls = []
    original_candidates, original_judge = identity.reconciler_candidates, identity.judge

    async def candidates():
        return ["U-NEAR"]

    async def judge(udid, *, device=None, apply=True, **_):
        calls.append((udid, device.udid if device is not None else None, apply))
        return identity.Decision(True, applied=True)

    identity.reconciler_candidates, identity.judge = candidates, judge
    try:
        counts = await identity_renewal.reconcile_once()
    finally:
        identity.reconciler_candidates, identity.judge = original_candidates, original_judge
    check("judge called once with the device and apply", calls == [("U-NEAR", "U-NEAR", True)], str(calls))
    check("counted as accepted", counts["judged"] == 1 and counts["accepted"] == 1, str(counts))

    print("\n9) no judging before the cutover")
    calls.clear()

    async def no_cutover():
        return False

    original_run = identity.run_cutover
    identity.reset_cutover_cache()
    identity.run_cutover, identity.reconciler_candidates, identity.judge = no_cutover, candidates, judge
    try:
        counts = await identity_renewal.reconcile_once()
    finally:
        identity.run_cutover, identity.reconciler_candidates, identity.judge = (
            original_run, original_candidates, original_judge)
        identity.set_cutover_cache(True)
    check("nothing judged", not calls and not any(counts.values()), str(counts))


async def test_reconcile_lock_and_log(tenant, stub):
    print("\n10) each judge runs under udid_lock; a takeover without a condition is refused, an allowed one left")
    taken, records = [], []
    original_candidates, original_judge, original_lock = (
        identity.reconciler_candidates, identity.judge, identity.udid_lock)
    now = utcnow()
    rows = {}
    for udid in ("U-NEAR", "U-LEGACY"):
        rows[udid] = await ScepChallenge.create(tenant=tenant, origin="manual", challenge_hash=sha(f"take:{udid}"),
                                                subject_cn=f"mm take {udid}", expires_at=now + timedelta(days=1),
                                                consumed_at=now)
    await Device.filter(udid="U-LEGACY").update(reenrollment_allowed_until=now + timedelta(hours=1))
    intruder = challenge_identity("U-INTRUDER", 365)
    stub.associations["U-NEAR"].add(intruder.cert_sha256)

    async def candidates():
        return ["U-NEAR", "U-LEGACY"]

    async def judge(udid, **_):
        return identity.Decision(True, row=rows[udid], is_takeover=True, origin="manual", identity=intruder,
                                 cert_sha256=intruder.cert_sha256)

    @asynccontextmanager
    async def recording_lock(udid):
        taken.append(udid)
        yield

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record)

    log = logging.getLogger(identity_renewal.__name__)
    handler, level = Capture(level=logging.DEBUG), log.level
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)
    identity.reconciler_candidates, identity.judge, identity.udid_lock = candidates, judge, recording_lock
    try:
        counts = await identity_renewal.reconcile_once()
    finally:
        identity.reconciler_candidates, identity.judge, identity.udid_lock = (
            original_candidates, original_judge, original_lock)
        log.removeHandler(handler)
        log.setLevel(level)
    check("the lock is taken once per udid", taken == ["U-NEAR", "U-LEGACY"], str(taken))
    check("one refused and one left unapplied",
          counts["refused"] == 1 and counts["unapplied"] == 1 and counts["judged"] == 2, str(counts))
    check("the refused takeover's certificate is parked", ("park", "U-NEAR", intruder.cert_sha256) in stub.calls)
    check("...and recorded as takeover_refused",
          any((a.detail or {}).get("reason") == "takeover_refused"
              for a in await EnrollmentAttempt.filter(udid="U-NEAR", outcome="bad_identity")))
    check("the allowed takeover is logged at debug and nothing louder",
          len(records) == 1 and records[0].levelno == logging.DEBUG,
          str([(r.levelname, r.getMessage()) for r in records]))
    check("...and nothing is parked for it", not [c for c in stub.parks if c[1] == "U-LEGACY"])


async def bound_renewal(tenant, stub, udid):
    """An enrolled device whose renewal certificate is bound while its enrollment_renew task is still running."""
    dev = await device(tenant, stub, udid, days_left=200)
    before = dev.identity_sha256
    earlier = utcnow() - timedelta(days=100)
    await ScepChallenge.create(tenant=tenant, origin="manual", challenge_hash=sha(f"{udid}-1"), subject_cn="mm t1",
                               expires_at=earlier, consumed_at=earlier, bound_at=earlier, bound_udid=udid,
                               cert_sha256=before)
    task = await Task.create(tenant=tenant, device=dev, type="enrollment_renew", status="running",
                             description="renew")
    renewed = sha(f"cert:{udid}:renewed")
    row = await ScepChallenge.create(tenant=tenant, device=dev, task=task, origin="renewal",
                                     challenge_hash=sha(f"{udid}-2"), subject_cn="mm t2",
                                     expires_at=utcnow() + timedelta(days=7), consumed_at=utcnow(),
                                     bound_at=utcnow(), bound_udid=udid, cert_sha256=renewed)
    await Device.filter(id=dev.id).update(identity_sha256=renewed)
    stub.associations[udid] = {before, renewed}
    return dev, task, row, before, renewed


async def test_timeout_keeps_both(tenant, stub):
    print("\n11) a timeout of a bound renewal expires its row and keeps both certificates")
    dev, task, row, before, renewed = await bound_renewal(tenant, stub, "U-TIMEOUT")
    await reconciler.fail_tasks([{"id": task.id, "type": task.type, "tenant_id": task.tenant_id}], "timed out")
    await dev.refresh_from_db()
    await row.refresh_from_db()
    await task.refresh_from_db()
    check("the task is failed", task.status == "failed")
    check("identity_sha256 stays the renewed certificate", dev.identity_sha256 == renewed)
    check("the renewal row is expired and keeps its hash",
          row.cert_sha256 == renewed and as_utc(row.expires_at) <= utcnow())
    check("both certificates stay associated", stub.associations["U-TIMEOUT"] == {before, renewed},
          str(stub.associations["U-TIMEOUT"]))

    print("\n11b) a late Error after the timeout and the reconciler's prune keeps the renewed certificate")
    dev, task, row, before, renewed = await bound_renewal(tenant, stub, "U-LATE-ERROR")
    await reconciler.fail_tasks([{"id": task.id, "type": task.type, "tenant_id": task.tenant_id}], "timed out")
    await dev.refresh_from_db()
    check("once the timeout expires the row the previous certificate is no longer allowed",
          before not in await identity.allowed_hashes(dev))
    # What the reconciler's next pass leaves, as asserted for an accepted judgement in verify_identity.
    stub.associations["U-LATE-ERROR"] = {renewed}
    rolled = await identity.fail_renewal(dev, task_id=task.id, force=True)
    await dev.refresh_from_db()
    await row.refresh_from_db()
    check("the late Error rolls nothing back and the device keeps the renewed certificate",
          rolled is False and dev.identity_sha256 == renewed and stub.associations["U-LATE-ERROR"] == {renewed}
          and row.cert_sha256 == renewed)
    check("...and raises the renewal alert",
          await Alert.filter(device_id=dev.id, rule_id=identity.ALERT_RULE_RENEWAL, status="open").exists())

    print("\n12) the cancel route expires a bound renewal the same way")
    from controller.api.routes import tasks as task_routes

    dev, task, row, before, renewed = await bound_renewal(tenant, stub, "U-CANCEL")
    cancel_user = await User.create(tenant=tenant, email="admin@renewal", role="admin")
    cancel_admin = Principal(tenant=tenant, user=cancel_user, email=cancel_user.email, role="admin")
    seen = []
    original = identity.fail_renewal_tasks

    async def recording(task_ids, **kwargs):
        task_ids = list(task_ids)
        seen.append(([str(t) for t in task_ids], kwargs))
        return await original(task_ids, **kwargs)

    identity.fail_renewal_tasks = recording
    try:
        await task_routes.cancel_task(str(task.id), cancel_admin)
    finally:
        identity.fail_renewal_tasks = original
    await dev.refresh_from_db()
    await row.refresh_from_db()
    await task.refresh_from_db()
    check("the route calls fail_renewal_tasks for the task without force",
          seen == [([str(task.id)], {})], str(seen))
    check("the task is cancelled", task.status == "cancelled")
    check("...the row is expired, and the identity and associations are kept",
          as_utc(row.expires_at) <= utcnow() and row.cert_sha256 == renewed and dev.identity_sha256 == renewed
          and stub.associations["U-CANCEL"] == {before, renewed})


async def test_bootstrap_token(tenant, stub):
    print("\n13) before a renewal the escrowed bootstrap token gets a sealed copy")
    blocked = await device(tenant, stub, "U-BT-BLOCK", days_left=3, bootstrap_token_escrowed=True)
    stub.bootstrap["U-BT-BLOCK"] = ("dG9rZW4=", True)
    stub.fail_bootstrap = {"get"}
    try:
        counts = await identity_renewal.scan_and_renew(connector=FakeConnector())
    finally:
        stub.fail_bootstrap = set()
    check("a device whose token cannot be read is held back as blocked",
          counts["blocked"] >= 1 and not await renew_tasks(blocked), str(counts))

    copied = await device(tenant, stub, "U-BT-COPY", days_left=3, bootstrap_token_escrowed=True)
    stub.bootstrap["U-BT-COPY"] = ("Y29weQ==", True)
    missing = await device(tenant, stub, "U-BT-NONE", days_left=3, bootstrap_token_escrowed=True)
    connector = FakeConnector()
    await identity_renewal.scan_and_renew(connector=connector)
    sent = {u for u, _ in connector.sent}
    copied, missing, blocked = [await Device.get(id=d.id) for d in (copied, missing, blocked)]
    check("NanoMDM's token is sealed before the renewal is sent",
          "U-BT-COPY" in sent and identity.open_bootstrap_token(copied) == "Y29weQ==")
    check("...and the device held back before is sent once it can be read",
          "U-BT-BLOCK" in sent and identity.open_bootstrap_token(blocked) == "dG9rZW4=")
    check("a flag with no token in NanoMDM is cleared and the renewal sent",
          "U-BT-NONE" in sent and missing.bootstrap_token_escrowed is False and missing.bootstrap_token_enc is None)

    unsettled = await device(tenant, stub, "U-BT-UNSETTLED", bootstrap_token_escrowed=True)
    stub.bootstrap["U-BT-UNSETTLED"] = ("dW5zZXR0bGVk", True)
    await stub.get_identity("U-BT-UNSETTLED")
    await LegacyIdentity.filter(udid="U-BT-UNSETTLED").delete()
    connector = FakeConnector()
    await identity_renewal.scan_and_renew(connector=connector)
    unsettled = await Device.get(id=unsettled.id)
    check("a legacy device whose identity is not in its snapshot is held back and nothing is sealed",
          "U-BT-UNSETTLED" not in {u for u, _ in connector.sent} and unsettled.bootstrap_token_enc is None
          and not [c for c in stub.calls if c[0] == "get_bootstrap_token" and c[1] == "U-BT-UNSETTLED"])

    print("\n14) the reconciler retries a bootstrap token write that did not happen")
    retry = await device(tenant, stub, "U-BT-RETRY", days_left=200)
    retry.bootstrap_token_enc = identity.seal_bootstrap_token(retry, "cmV0cnk=")
    await retry.save(update_fields=["bootstrap_token_enc"])
    spoken = await device(tenant, stub, "U-BT-SPOKEN", days_left=200)
    spoken.bootstrap_token_enc = identity.seal_bootstrap_token(spoken, "b2xk")
    await spoken.save(update_fields=["bootstrap_token_enc"])
    stub.bootstrap["U-BT-SPOKEN"] = ("bmV3", True)
    foreign = await device(tenant, stub, "U-BT-FOREIGN", days_left=200)
    foreign.bootstrap_token_enc = identity.seal_bootstrap_token(foreign, "Zm9yZWlnbg==")
    await foreign.save(update_fields=["bootstrap_token_enc"])
    stub.associations["U-BT-FOREIGN"].add(sha("pending takeover"))
    alert = await Alert.create(tenant=tenant, device=retry, rule_id=identity.ALERT_RULE_BOOTSTRAP, severity="red",
                               status="open", summary="lost", opened_at=utcnow(), detail={})
    restored = await identity_renewal.retry_bootstrap_restores()
    retry, spoken, foreign = [await Device.get(id=d.id) for d in (retry, spoken, foreign)]
    check("a device whose NanoMDM token is unset gets the sealed copy back",
          restored == 1 and retry.bootstrap_token_escrowed is True
          and stub.bootstrap["U-BT-RETRY"] == ("cmV0cnk=", True))
    check("...and its bootstrap token alert is resolved",
          (await Alert.get(id=alert.id)).status == "resolved")
    check("...one that escrowed a token since is left alone",
          spoken.bootstrap_token_escrowed is False and stub.bootstrap["U-BT-SPOKEN"] == ("bmV3", True))
    check("...and one holding a certificate outside its allowed set is not written",
          foreign.bootstrap_token_escrowed is False
          and not [c for c in stub.bootstrap_restores if c[1] == "U-BT-FOREIGN"])

    print("\n15) the reconcile pass seals a token NanoMDM holds for a device with no copy")
    first = await device(tenant, stub, "U-BT-CAP-1", days_left=200)
    second = await device(tenant, stub, "U-BT-CAP-2", days_left=200)
    stub.bootstrap["U-BT-CAP-1"] = ("Zmlyc3Q=", True)
    stub.bootstrap["U-BT-CAP-2"] = ("c2Vjb25k", True)
    stub.bootstrap["U-BT-FOREIGN"] = ("Zm9yZWlnbg==", True)
    original_candidates = identity.reconciler_candidates

    async def no_candidates():
        return []

    passes = [await identity_renewal.capture_bootstrap_tokens(limit=1) for _ in range(6)]
    check("passes of one device each move past a device they cannot seal and reach both",
          sum(passes) == 2 and max(passes) == 1, str(passes))
    stub.bootstrap["U-BT-CAP-3"] = ("dGhpcmQ=", True)
    third = await device(tenant, stub, "U-BT-CAP-3", days_left=200)
    identity.reconciler_candidates = no_candidates
    # The passes above leave the capture cursor somewhere in the id order, which could be past the third device.
    identity_renewal._capture_after = None
    try:
        counts = await identity_renewal.reconcile_once()
    finally:
        identity.reconciler_candidates = original_candidates
    first, second, third, spoken, foreign = [await Device.get(id=d.id) for d in (first, second, third, spoken,
                                                                                foreign)]
    check("reconcile_once runs the capture", counts["bootstrap_captured"] == 1
          and identity.open_bootstrap_token(third) == "dGhpcmQ=", str(counts))
    check("...both devices end up sealed with the flag set",
          identity.open_bootstrap_token(first) == "Zmlyc3Q=" and identity.open_bootstrap_token(second) == "c2Vjb25k"
          and first.bootstrap_token_escrowed and second.bootstrap_token_escrowed)
    check("a device whose copy differs from NanoMDM's token keeps its copy and its clear flag",
          identity.open_bootstrap_token(spoken) == "b2xk" and spoken.bootstrap_token_escrowed is False)
    check("a device holding a certificate outside its allowed set is not sealed",
          identity.open_bootstrap_token(foreign) == "Zm9yZWlnbg==" and foreign.bootstrap_token_escrowed is False)
    fourth = await device(tenant, stub, "U-BT-CAP-4", days_left=200)
    stub.bootstrap["U-BT-CAP-4"] = ("Zm91cnRo", True)
    unset = await device(tenant, stub, "U-BT-CAP-UNSET", days_left=200)
    unset.bootstrap_token_enc = identity.seal_bootstrap_token(unset, "dW5zZXQ=")
    await unset.save(update_fields=["bootstrap_token_enc"])
    identity_renewal._capture_after = None
    stub.fail_bootstrap = {"list"}
    try:
        identity.reconciler_candidates = no_candidates
        counts = await identity_renewal.reconcile_once()
    finally:
        identity.reconciler_candidates = original_candidates
        stub.fail_bootstrap = set()
    fourth = await Device.get(id=fourth.id)
    check("an unreadable NanoMDM seals nothing and leaves the pass's other counts intact",
          counts["bootstrap_captured"] == 0 and counts["bootstrap_restored"] == 1 and counts["judged"] == 0
          and fourth.bootstrap_token_enc is None, str(counts))
    identity.reconciler_candidates = no_candidates
    try:
        counts = await identity_renewal.reconcile_once()
    finally:
        identity.reconciler_candidates = original_candidates
    fourth = await Device.get(id=fourth.id)
    check("...and the next pass seals the candidate it could not read",
          counts["bootstrap_captured"] == 1 and identity.open_bootstrap_token(fourth) == "Zm91cnRo"
          and fourth.bootstrap_token_escrowed is True, str(counts))


async def test_refusal_retry(tenant, stub):
    print("\n16) the reconcile pass retries the writes a refusal could not make")
    import controller.services.nanomdm_store as store

    async def refused_with_nanomdm_down(udid, push=True):
        dev = await device(tenant, stub, udid, days_left=200)
        legit = await stub.get_identity(udid)
        dev.identity_pem = legit.pem
        if push:
            dev.push_token_enc = identity.seal_push_token(dev, "beef", f"magic-{udid}")
        await dev.save(update_fields=["identity_pem", "push_token_enc"])
        bad = Identity(cert_sha256=sha(f"bad:{udid}"), spki_sha256="0" * 64, subject_cn="someone else",
                       not_after=utcnow())
        stub.set_identity(udid, bad)
        stub.associations[udid] = {legit.cert_sha256, bad.cert_sha256}

        async def raising(*_args, **_kwargs):
            raise RuntimeError("NanoMDM database: down")

        store.restore_identity, store.restore_push = raising, raising
        try:
            await identity.judge(udid, device=dev)
        finally:
            store.restore_identity, store.restore_push = stub.restore_identity, stub.restore_push
        alert = await Alert.get(device_id=dev.id, rule_id=identity.ALERT_RULE_REFUSED)
        return dev, legit, bad, alert

    retry, legit, bad, alert = await refused_with_nanomdm_down("U-RF-RETRY")
    check("a refusal whose writes raise records both as failed and leaves the refused certificate in NanoMDM",
          alert.detail.get("identity_restored") is False and alert.detail.get("push_restored") is False
          and stub.overrides["U-RF-RETRY"] is bad, str(alert.detail))
    moved, _, _, moved_alert = await refused_with_nanomdm_down("U-RF-MOVED", push=False)
    newer = Identity(cert_sha256=sha("newer"), spki_sha256="0" * 64, subject_cn="mm newer", not_after=utcnow())
    stub.overrides["U-RF-MOVED"] = newer
    seen_before = (alert.detail["last_seen_at"], moved_alert.detail["last_seen_at"])
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    log = logging.getLogger(identity.__name__)
    handler, level = Capture(level=logging.INFO), log.level
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    restores_before = len(stub.identity_restores)
    try:
        written = await identity_renewal.retry_refusal_restores()
    finally:
        log.removeHandler(handler)
        log.setLevel(level)
    alert, moved_alert = await Alert.get(id=alert.id), await Alert.get(id=moved_alert.id)
    check("the pass writes the identity certificate and push token back for the device NanoMDM still misnames",
          written == 2 and stub.overrides["U-RF-RETRY"].cert_sha256 == legit.cert_sha256
          and ("restore_push", "U-RF-RETRY", ("beef", "magic-U-RF-RETRY", True)) in stub.calls, str(written))
    check("...with the compare-and-set on the refused certificate",
          [c[2][2] for c in stub.identity_restores if c[1] == "U-RF-RETRY"] == [stub.pem_for(bad)])
    check("...and clears the flags on its alert",
          alert.detail.get("identity_restored") is True and alert.detail.get("push_restored") is True,
          str(alert.detail))
    check("a device whose identity moved on is dropped with a log line and no write",
          moved_alert.detail.get("identity_restored") is None
          and not [c for c in stub.identity_restores[restores_before:] if c[1] == "U-RF-MOVED"]
          and any("U-RF-MOVED moved on" in m for m in records), str(records))
    check("neither alert reopens the refusal window or counts another refusal",
          (alert.detail["last_seen_at"], moved_alert.detail["last_seen_at"]) == seen_before
          and alert.detail.get("count") == 1 and moved_alert.detail.get("count") == 1)
    restores_before = len(stub.identity_restores)
    original_candidates = identity.reconciler_candidates

    async def no_candidates():
        return []

    identity.reconciler_candidates = no_candidates
    try:
        counts = await identity_renewal.reconcile_once()
    finally:
        identity.reconciler_candidates = original_candidates
    check("the next reconcile pass has nothing left to retry",
          counts["refusal_writes"] == 0 and len(stub.identity_restores) == restores_before, str(counts))


async def test_scan_guard(tenant, stub):
    print("\n17) one device whose task cannot be created does not stop the devices behind it")
    boom = await device(tenant, stub, "U-BOOM", days_left=1)
    after = await device(tenant, stub, "U-AFTER", days_left=2)
    had_own = "create" in Task.__dict__
    saved = Task.__dict__.get("create")
    original_create = Task.create

    async def failing_create(**kwargs):
        if getattr(kwargs.get("device"), "udid", None) == "U-BOOM":
            raise RuntimeError("database down")
        return await original_create(**kwargs)

    Task.create = failing_create
    connector = FakeConnector()
    try:
        counts = await identity_renewal.scan_and_renew(connector=connector)
    finally:
        if had_own:
            Task.create = saved
        else:
            del Task.create
    sent = [u for u, _ in connector.sent]
    check("the failing device is counted and the next one is still sent",
          counts["failed"] >= 1 and "U-BOOM" not in sent and "U-AFTER" in sent, str((counts, sent)))
    check("the failing device has no task", not await renew_tasks(boom))
    check("...and the one behind it has", len(await renew_tasks(after)) == 1)


async def main():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()
    stub = install_identity_stub()
    tenant = await Tenant.create(id="t1", name="Renewal Tenant")

    await test_not_ready(tenant, stub)
    secret = _TMP / "scep_webhook_secret"
    secret.write_text("dmVyaWZ5LXJlbmV3YWw=")
    os.environ["SCEP_WEBHOOK_SECRET_FILE"] = str(secret)
    await test_scan(tenant, stub)
    await test_limit(tenant, stub)
    await test_dispatch_failure(tenant, stub)
    await test_reconcile(stub)
    await test_reconcile_lock_and_log(tenant, stub)
    await test_timeout_keeps_both(tenant, stub)
    await test_bootstrap_token(tenant, stub)
    await test_refusal_retry(tenant, stub)
    await test_scan_guard(tenant, stub)

    stub.uninstall()
    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    return 1 if FAIL else 0


from tests._verify_harness import run  # noqa: E402

run(main)
