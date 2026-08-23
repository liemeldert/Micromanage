"""E2E checks for the fleet-wide flow run list, on in-memory sqlite.

Run: PYTHONPATH=. ./.venv/bin/python tests/verify_flow_runs.py

Covers GET /api/v1/flow-runs in controller/api/main.py. Tenant scoping first, then the filters and how they compose:
status (single and as a comma set), flow, event_kind, device_id, waiting_signal, the started_at window, parked_before
(silent since, not started before) and released_unverified. That last one reads the release guard's verdict out of the
run's context, where no WHERE clause can see it, and still totals and paginates exactly.

The counts follow the population filters and ignore the selection filters. The row projection carries device identity,
the guard verdict and a gap summary, and drops the timeline, the visited list and the gap ledger.
"""
from datetime import datetime, timedelta, timezone

from tortoise import Tortoise

from controller.auth.dependencies import Principal
from controller.models.tenant import Tenant, User, Device, FlowRun
from controller.api.main import list_flow_runs

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


NOW = datetime.now(timezone.utc)


def ago(**kw):
    return NOW - timedelta(**kw)


async def call(principal, **kw):
    """The endpoint with its defaults filled in, so a check only names what it varies."""
    params = dict(
        skip=0, limit=100, status=None, flow=None, event_kind=None, device_id=None,
        waiting_signal=None, released_unverified=False, since=None, until=None,
        parked_before=None,
    )
    params.update(kw)
    return await list_flow_runs(principal=principal, **params)


def ids(res):
    return [r["id"] for r in res["flow_runs"]]


async def main():
    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    tenant = await Tenant.create(id="t1", name="Tenant One")
    member_user = await User.create(tenant=tenant, email="member@t1", role="member")
    member = Principal(tenant=tenant, user=member_user, email="member@t1", role="member")

    other = await Tenant.create(id="t2", name="Tenant Two")
    other_user = await User.create(tenant=other, email="member@t2", role="member")
    other_member = Principal(tenant=other, user=other_user, email="member@t2",
                             role="member")

    async def device(t, serial, host):
        return await Device.create(
            tenant=t, udid=f"UDID-{serial}", serial_number=serial,
            device_model="iPad13,1", os_version="17.5", hostname=host,
            enrollment_state="enrolled", groups=[], tags=[])

    cart = [await device(tenant, f"IPAD-{i}", f"ipad-{i}") for i in range(4)]
    mac = await device(tenant, "MAC-1", "mac-1")
    other_device = await device(other, "OTHER-1", "other-1")

    async def run(dev, *, flow="onboarding", status="completed", event="enroll_dep",
                  started=None, updated=None, tnt=None, **kw):
        r = await FlowRun.create(
            tenant=tnt or tenant, device=dev, flow_id=flow, flow_hash="h" * 8,
            status=status, event_kind=event, start_node="s-dep",
            started_at=started or ago(minutes=30), **kw)
        if updated is not None:
            # auto_now would restamp this on any save, and the parked filters are read against updated_at.
            await FlowRun.filter(id=r.id).update(updated_at=updated)
            await r.refresh_from_db()
        return r

    # Four iPads and a Mac, in the states the list has to tell apart.
    r_ok = await run(cart[0], started=ago(minutes=40),
                     context={"timeline": [{"at": "x", "node": "n", "message": "m"}] * 12,
                              "visited": ["a", "b", "c"]},
                     completed_at=ago(minutes=39))
    # Failed outright: a profile the device rejected.
    r_failed = await run(cart[1], status="failed", started=ago(minutes=35),
                         error="node 'install-wifi' (install_profiles) failed: rejected",
                         completed_at=ago(minutes=34))
    # Failed on the release guard: released before the configuration the flow promised was confirmed.
    r_unverified = await run(
        cart[2], status="failed", started=ago(minutes=20),
        error=("released the device from Setup Assistant before its configuration "
               "was confirmed: it did not get wifi-corp (missing from profiles.yaml)"),
        completed_at=ago(minutes=19),
        context={"unverified": {"node": "release", "severity": "red",
                                "body": "it did not get wifi-corp"},
                 "gaps": [{"kind": "not_queued", "grade": "broken", "node": "install-wifi",
                           "signal": "profile_installed",
                           "items": [{"id": "wifi-corp", "why": "missing from profiles.yaml"}]},
                          {"kind": "barrier_empty", "grade": "broken", "node": "await-wifi",
                           "signal": "profile_installed"}]})
    # Parked on a barrier for hours.
    r_stuck = await run(cart[3], status="waiting", started=ago(hours=4),
                        updated=ago(hours=4), current_node="await-info",
                        waiting_signal="device_info",
                        wait_deadline=NOW + timedelta(minutes=10),
                        context={"gaps": [{"kind": "never_arrived", "grade": "policy",
                                           "node": "await-apps", "signal": "app_installed"}]})
    # Parked on a manual gate: only a person resumes it, but the escalation ladder still gives it a deadline.
    r_gate = await run(mac, flow="mac-onboarding", status="waiting", event="enroll_profile",
                       started=ago(minutes=6), updated=ago(minutes=6),
                       current_node="approve", waiting_signal="manual",
                       waiting_ref="alert-1",
                       wait_deadline=NOW + timedelta(hours=4))
    # Same device, a check-in run that started a minute ago and is still moving.
    r_running = await run(mac, flow="mac-onboarding", status="running", event="checkin",
                          started=ago(minutes=1), updated=ago(minutes=1),
                          current_node="tag-corp")
    # The other tenant's run, which must never appear.
    r_other = await run(other_device, tnt=other, status="failed", error="not yours")

    print("1) tenant scoping")
    res = await call(member)
    check("the caller sees only their own tenant's runs (6)", res["total"] == 6)
    check("the other tenant's run is not in the list", str(r_other.id) not in ids(res))
    check("newest-first ordering", ids(res)[0] == str(r_running.id))
    res_other = await call(other_member)
    check("a member of the other tenant sees only their own row",
          res_other["total"] == 1 and ids(res_other) == [str(r_other.id)])
    check("...and their counts are their own, not this tenant's",
          res_other["counts"]["all"] == 1 and res_other["counts"]["failed"] == 1)
    res_cross = await call(other_member, device_id=str(cart[1].id))
    check("filtering by a device in another tenant returns nothing, not that device",
          res_cross["total"] == 0)

    print("2) status, single and as a set")
    res_failed = await call(member, status="failed")
    check("status=failed narrows to the two failed runs",
          res_failed["total"] == 2
          and set(ids(res_failed)) == {str(r_failed.id), str(r_unverified.id)})
    res_attn = await call(member, status="failed,waiting")
    check("status=failed,waiting is the attention view (4)",
          res_attn["total"] == 4
          and set(ids(res_attn)) == {str(r_failed.id), str(r_unverified.id),
                                     str(r_stuck.id), str(r_gate.id)})
    res_spaced = await call(member, status=" failed , waiting ")
    check("whitespace in the set is tolerated", res_spaced["total"] == 4)
    res_junk = await call(member, status="nonsense")
    check("an unknown status matches nothing rather than everything",
          res_junk["total"] == 0)

    print("3) flow, event kind and device")
    res_flow = await call(member, flow="mac-onboarding")
    check("flow narrows to that flow's runs (2)", res_flow["total"] == 2)
    res_kind = await call(member, event_kind="enroll_dep")
    check("event_kind narrows to the DEP enrollments (4)", res_kind["total"] == 4)
    res_dev = await call(member, device_id=str(mac.id))
    check("device_id narrows to one device's runs (2)", res_dev["total"] == 2)
    res_both = await call(member, flow="mac-onboarding", event_kind="checkin")
    check("filters compose (one check-in run of the mac flow)",
          res_both["total"] == 1 and ids(res_both) == [str(r_running.id)])
    check("flow_ids lists what actually ran, for the filter's options",
          res["flow_ids"] == ["mac-onboarding", "onboarding"])

    print("4) the stuck filters")
    res_gate = await call(member, waiting_signal="manual")
    check("waiting_signal=manual isolates the run waiting on a person",
          res_gate["total"] == 1 and ids(res_gate) == [str(r_gate.id)])
    res_parked = await call(member, parked_before=NOW - timedelta(hours=1))
    check("parked_before finds the run silent since this morning, not the fresh one",
          res_parked["total"] == 1 and ids(res_parked) == [str(r_stuck.id)])
    res_parked_all = await call(member, parked_before=NOW)
    check("a wider parked_before takes in the gate too", res_parked_all["total"] == 2)
    # The failed runs started long before this cutoff and are not parked at all.
    check("parked_before never returns a terminal run",
          all(r["status"] == "waiting" for r in res_parked_all["flow_runs"]))

    print("5) the started_at window")
    res_since = await call(member, since=NOW - timedelta(minutes=10))
    check("since bounds started_at (the gate and the running run)",
          res_since["total"] == 2
          and set(ids(res_since)) == {str(r_gate.id), str(r_running.id)})
    res_until = await call(member, until=NOW - timedelta(minutes=30))
    check("until bounds the other end (everything older than half an hour)",
          res_until["total"] == 3
          and set(ids(res_until)) == {str(r_ok.id), str(r_failed.id), str(r_stuck.id)})
    res_window = await call(member, since=NOW - timedelta(minutes=36),
                            until=NOW - timedelta(minutes=15))
    check("a window is both ends at once",
          res_window["total"] == 2
          and set(ids(res_window)) == {str(r_failed.id), str(r_unverified.id)})
    res_empty = await call(member, since=NOW - timedelta(days=40),
                           until=NOW - timedelta(days=35))
    check("an empty window is empty, and says how far back rows go at all",
          res_empty["total"] == 0 and res_empty["retention_days"] >= 1)

    print("6) released unverified: the verdict lives in context, not a column")
    res_unv = await call(member, released_unverified=True)
    check("the switch isolates the guard-tripped run",
          res_unv["total"] == 1 and ids(res_unv) == [str(r_unverified.id)])
    check("an ordinary failure is not swept in with it",
          str(r_failed.id) not in ids(res_unv))
    check("the count agrees with the filter",
          res["counts"]["released_unverified"] == 1)
    check("the row says so on its own, so the table needs no second call",
          res_unv["flow_runs"][0]["released_unverified"] is True)
    check("the scan was not capped at this size", res["scan_capped"] is False)
    # This flow has no failed runs, so the guard scan produces an empty id set: that path has to return an empty list
    # rather than break on an empty IN.
    res_unv_flow = await call(member, released_unverified=True, flow="mac-onboarding")
    check("it composes with the other filters, including down to nothing",
          res_unv_flow["total"] == 0 and res_unv_flow["flow_runs"] == [])
    res_unv_off = await call(member, released_unverified=False)
    check("off is the whole list, not the negative set", res_unv_off["total"] == 6)
    res_unv_contra = await call(member, released_unverified=True, status="completed")
    check("a contradictory status yields nothing rather than ignoring one filter",
          res_unv_contra["total"] == 0)

    print("7) counts follow the population, not the selection")
    check("counts cover every state in the tenant",
          res["counts"] == {"all": 6, "running": 1, "waiting": 2, "completed": 1,
                            "failed": 2, "cancelled": 0, "on_gate": 1,
                            "released_unverified": 1})
    check("selecting one status does not zero the others",
          res_failed["counts"] == res["counts"])
    check("...nor does the stuck filter", res_parked["counts"] == res["counts"])
    check("on_gate counts only the run waiting on a person",
          res["counts"]["on_gate"] == 1)
    check("a population filter does move the counts",
          res_flow["counts"]["all"] == 2 and res_flow["counts"]["waiting"] == 1
          and res_flow["counts"]["failed"] == 0)
    check("a window moves them the same way", res_since["counts"]["all"] == 2)

    print("8) the row projection")
    row = next(r for r in res["flow_runs"] if r["id"] == str(r_unverified.id))
    check("no timeline in a list row", "timeline" not in row)
    check("no visited in a list row", "visited" not in row)
    check("no raw context in a list row", "context" not in row)
    check("no gap ledger in a list row", "gaps" not in row)
    check("the gap ledger is summarised to a count", row["gap_count"] == 2)
    check("...and to the worst grade in it", row["gap_grade"] == "broken")
    check("the error is carried, since it is what the row is read for",
          "wifi-corp" in (row["error"] or ""))
    check("device identity travels with the row, so no per-row lookup",
          row["device"]["serial_number"] == "IPAD-2"
          and row["device"]["device_model"] == "iPad13,1")
    check("the device id comes back for linking", row["device_id"] == str(cart[2].id))
    ok_row = next(r for r in res["flow_runs"] if r["id"] == str(r_ok.id))
    check("a clean run reports no gaps and no guard verdict",
          ok_row["gap_count"] == 0 and ok_row["gap_grade"] is None
          and ok_row["released_unverified"] is False)
    check("a completed run carries the timestamps a duration is read from",
          ok_row["started_at"] and ok_row["completed_at"] and ok_row["updated_at"])
    gate_row = next(r for r in res["flow_runs"] if r["id"] == str(r_gate.id))
    check("a gate row says it waits on a person, with the ladder's next deadline",
          gate_row["waiting_signal"] == "manual"
          and gate_row["wait_deadline"] is not None)
    check("...and points at the alert holding the decision",
          gate_row["waiting_ref"] == "alert-1")
    stuck_row = next(r for r in res["flow_runs"] if r["id"] == str(r_stuck.id))
    check("a barrier row carries the deadline it will time out on",
          stuck_row["wait_deadline"] is not None
          and stuck_row["current_node"] == "await-info")

    print("9) pagination")
    page1 = await call(member, limit=2)
    page2 = await call(member, skip=2, limit=2)
    check("a page reports the full total, not the page size",
          page1["total"] == 6 and len(page1["flow_runs"]) == 2)
    check("the second page continues the first",
          len(page2["flow_runs"]) == 2 and not set(ids(page1)) & set(ids(page2)))
    check("paging the guard set is exact too",
          (await call(member, released_unverified=True, limit=1))["total"] == 1)
    tail = await call(member, skip=6, limit=2)
    check("past the end is empty and still reports the total",
          tail["flow_runs"] == [] and tail["total"] == 6)

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run

run(main)
