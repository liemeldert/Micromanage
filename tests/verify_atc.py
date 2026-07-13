"""Backend E2E for the ATC flow engine (single-flow model), on in-memory sqlite.

Exercises the real state machine end to end (no docker, no MDM network):
start-node dispatch by event (DEP vs OTA enroll, check-in, schedule), match
scoping, checkin/schedule dedup, the wait_for -> timeout -> manual_gate human
gate + resume, the green "held in Setup Assistant" alert lifecycle, ref-based
waits, flow_hash pinning across a live edit, legacy-doc migration, and the
flows.yaml validator.

Run:  PYTHONPATH=. ./.venv/bin/python tests/verify_atc.py
Exits non-zero if any check fails.
"""

import asyncio
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from tortoise import Tortoise

_FAILURES = []


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        _FAILURES.append(name)


class FakeConnector:
    """Stand-in for MDMConnector: returns command_uuids, never touches network."""

    def __init__(self, *a, **k):
        pass

    async def set_device_name(self, udid, name):
        return {"command_uuid": "u-name"}

    async def install_profile(self, udid, payload):
        return {"command_uuid": "u-prof"}

    async def remove_profile(self, udid, identifier):
        return {"command_uuid": "u-prof-rm"}

    async def install_app(self, udid, manifest_url, management_flags=1):
        return {"command_uuid": "u-app"}

    async def remove_app(self, udid, bundle_id):
        return {"command_uuid": "u-app-rm"}

    async def get_device_info(self, udid):
        return {"command_uuid": "u-info"}

    async def get_security_info(self, udid):
        return {"command_uuid": "u-sec"}

    async def device_configured(self, udid):
        return {"command_uuid": "u-configured"}

    async def send_raw_command(self, udid, request_type, fields):
        return {"command_uuid": "u-raw"}

    async def close(self):
        pass


# A single flow with several start nodes. Starts scoped to "NOSUCH" never fire on
# a real event -- they are driven manually via start_run_from_start in the tests.
BASE_FLOW = {
    "id": "main",
    "name": "Main flow",
    "enabled": True,
    "nodes": [
        # ── DEP/ADE enrollment onboarding (Mac) ──────────────────────────────
        {"id": "s-dep", "type": "start",
         "params": {"kind": "enroll_dep", "match": {
             "conditions": [{"type": "platform", "operator": "in", "value": ["Mac"]}]}},
         "next": "dep-assign"},
        {"id": "dep-assign", "type": "assign_tag",
         "params": {"tags": ["corp", "onboarding"]}, "next": "dep-name"},
        {"id": "dep-name", "type": "set_name",
         "params": {"template": "IT-{serial}"}, "next": "dep-branch"},
        {"id": "dep-branch", "type": "branch",
         "params": {"condition": {"type": "hostname", "operator": "contains",
                                  "value": ["-eu-"]}},
         "on_true": "dep-eu", "on_false": "dep-us"},
        {"id": "dep-eu", "type": "install_profiles",
         "params": {"profile_ids": ["eu-wifi"]}, "next": "dep-wait"},
        {"id": "dep-us", "type": "install_profiles",
         "params": {"profile_ids": ["us-wifi"]}, "next": "dep-wait"},
        {"id": "dep-wait", "type": "wait_for",
         "params": {"signal": "device_info", "timeout_minutes": 60},
         "on_timeout": "dep-degraded", "next": "dep-release"},
        {"id": "dep-degraded", "type": "assign_tag",
         "params": {"tags": ["onboarding-timeout"]}, "next": "dep-release"},
        {"id": "dep-release", "type": "release_device", "next": "dep-end"},
        {"id": "dep-end", "type": "end"},

        # ── OTA / manual enrollment ──────────────────────────────────────────
        {"id": "s-profile", "type": "start",
         "params": {"kind": "enroll_profile", "match": {}}, "next": "p-tag"},
        {"id": "p-tag", "type": "assign_tag", "params": {"tags": ["ota"]}, "next": "p-end"},
        {"id": "p-end", "type": "end"},

        # ── Check-in trigger (parks so dedup is observable) ──────────────────
        {"id": "s-checkin", "type": "start",
         "params": {"kind": "checkin", "match": {}}, "next": "c-wait"},
        {"id": "c-wait", "type": "wait_for",
         "params": {"signal": "device_info", "timeout_minutes": 5}, "next": "c-end"},
        {"id": "c-end", "type": "end"},

        # ── Scheduled interval (scoped to SCHED serials) ─────────────────────
        {"id": "s-schedule", "type": "start",
         "params": {"kind": "schedule", "interval_minutes": 60, "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["SCHED-1"]}]}},
         "next": "sch-tag"},
        {"id": "sch-tag", "type": "assign_tag", "params": {"tags": ["swept"]}, "next": "sch-end"},
        {"id": "sch-end", "type": "end"},

        # ── Human gate (manual-only) ─────────────────────────────────────────
        {"id": "s-gate", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "g-wait"},
        {"id": "g-wait", "type": "wait_for",
         "params": {"signal": "device_info", "timeout_minutes": 1},
         "on_timeout": "g-gate", "next": "g-end"},
        {"id": "g-gate", "type": "manual_gate",
         "params": {"summary": "Device stuck in setup", "severity": "yellow",
                    "options": [
                        {"label": "Release device from setup", "edge": "on_release"},
                        {"label": "Cancel flow", "edge": "on_cancel"},
                        {"label": "Keep waiting", "edge": "on_wait"}]},
         "on_release": "g-release", "on_cancel": "g-cancel-end", "on_wait": "g-end"},
        {"id": "g-release", "type": "release_device", "next": "g-end"},
        {"id": "g-cancel-end", "type": "end"},
        {"id": "g-end", "type": "end"},

        # ── Ref-based wait (manual-only) ─────────────────────────────────────
        {"id": "s-ref", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "r-tag"},
        {"id": "r-tag", "type": "assign_tag", "params": {"tags": ["corp"]}, "next": "r-inst"},
        {"id": "r-inst", "type": "install_profiles",
         "params": {"profile_ids": ["eu-wifi"]}, "next": "r-wait"},
        {"id": "r-wait", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30}, "next": "r-end"},
        {"id": "r-end", "type": "end"},

        # ── Two sequential ref waits (regression, manual-only) ───────────────
        {"id": "s-double", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "d-inst1"},
        {"id": "d-inst1", "type": "install_profiles",
         "params": {"profile_ids": ["P1"]}, "next": "d-wait1"},
        {"id": "d-wait1", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30}, "next": "d-inst2"},
        {"id": "d-inst2", "type": "install_profiles",
         "params": {"profile_ids": ["P2"]}, "next": "d-wait2"},
        {"id": "d-wait2", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30}, "next": "d-done"},
        {"id": "d-done", "type": "end"},

        # ── Empty-expectation wait skip (manual-only) ────────────────────────
        {"id": "s-standalone", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "sw"},
        {"id": "sw", "type": "wait_for",
         "params": {"signal": "app_installed", "timeout_minutes": 5}, "next": "sw-end"},
        {"id": "sw-end", "type": "end"},
    ],
}


def _write_configs(base: Path):
    tdir = base / "tenants" / "default"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "config.yaml").write_text(yaml.safe_dump(
        {"tenant": {"id": "default", "name": "Default", "allowed_users": []}}))
    (tdir / "groups.yaml").write_text(yaml.safe_dump({"groups": [
        {"name": "all-macs", "conditions": [
            {"type": "platform", "operator": "in", "value": ["Mac"]}]}]}))
    (tdir / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
    (tdir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": [
        {"id": "eu-wifi", "name": "EU WiFi", "payload": {"PayloadType": "com.apple.wifi"}},
        {"id": "us-wifi", "name": "US WiFi", "payload": {"PayloadType": "com.apple.wifi"}},
        {"id": "P1", "name": "Profile 1", "payload": {"PayloadType": "com.apple.test1"}},
        {"id": "P2", "name": "Profile 2", "payload": {"PayloadType": "com.apple.test2"}},
    ]}))
    (tdir / "flows.yaml").write_text(yaml.safe_dump({"flow": BASE_FLOW}))


async def main():
    base = Path(tempfile.mkdtemp())
    os.environ["YAML_CONFIG_PATH"] = str(base)
    _write_configs(base)
    tdir = base / "tenants" / "default"

    # Patch the connector before atc's lazy imports resolve it.
    import controller.services.mdm_connector as mc
    mc.MDMConnector = FakeConnector

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    from controller.models.tenant import Tenant, Device, FlowRun, Alert, ProfileDeployment
    from controller.services import atc
    from controller.services.flow_step_catalog import normalize_flow_document
    from controller.utils.yaml_validator import YAMLValidator

    tenant = await Tenant.create(id="default", name="Default")

    async def new_device(serial, host, dep=False, model="MacBookPro18,3"):
        return await Device.create(
            tenant=tenant, udid=f"UDID-{serial}", serial_number=serial,
            device_model=model, os_version="14.5", hostname=host,
            enrollment_state="enrolled", groups=[], tags=[],
            dep_profile_uuid=(f"DEPUUID-{serial}" if dep else None))

    async def active_in_setup(device):
        return await Alert.filter(
            device_id=device.id, rule_id="atc:in-setup").exclude(status="resolved").first()

    # ── 1) DEP enroll runs s-dep, applies tags/name/branch/install, parks; a
    #      green in-setup alert opens ────────────────────────────────────────
    print("1) enroll_dep on a Mac runs s-dep and parks; green in-setup alert opens")
    dev = await new_device("MAC-EU", "host-eu-1", dep=True)
    runs = await atc.start_flows_for_event(dev, "enroll_dep")
    await dev.refresh_from_db()
    check("exactly one run started", len(runs) == 1)
    run = runs[0]
    check("entered from start node s-dep", run.start_node == "s-dep")
    check("event_kind recorded", run.event_kind == "enroll_dep")
    check("tags corp+onboarding applied", {"corp", "onboarding"} <= set(dev.tags))
    check("name set from template", dev.name == "IT-MAC-EU")
    await run.refresh_from_db()
    check("parked waiting at dep-wait", run.status == "waiting" and run.current_node == "dep-wait")
    check("EU branch taken", "dep-eu" in (run.context or {}).get("visited", []))
    check("US branch not taken", "dep-us" not in (run.context or {}).get("visited", []))
    a = await active_in_setup(dev)
    check("green in-setup alert opened", a is not None and a.severity == "green" and a.status == "open")
    check("in-setup alert carries kind + release action",
          bool(a) and (a.detail or {}).get("kind") == "atc_in_setup"
          and (a.detail or {}).get("actions"))

    # ── 2) device_info resumes -> release_device -> completes; alert resolves ──
    print("2) device_info resumes the run through release_device to completion")
    await atc.advance_on_signal(str(dev.id), "device_info")
    await run.refresh_from_db()
    check("run completed", run.status == "completed")
    check("release_device visited", "dep-release" in (run.context or {}).get("visited", []))
    check("in-setup alert resolved after release", await active_in_setup(dev) is None)

    # ── 3) wait_for timeout follows on_timeout (degraded) ─────────────────────
    print("3) wait_for timeout follows on_timeout")
    dev2 = await new_device("MAC-US", "host-us-1", dep=True)
    run2 = (await atc.start_flows_for_event(dev2, "enroll_dep"))[0]
    await run2.refresh_from_db()
    check("US branch taken", "dep-us" in (run2.context or {}).get("visited", []))
    await FlowRun.filter(id=run2.id).update(
        wait_deadline=datetime.now(timezone.utc) - timedelta(minutes=1))
    swept = await atc.sweep_timeouts(tenant)
    await run2.refresh_from_db()
    await dev2.refresh_from_db()
    check("sweep processed the run", swept >= 1)
    check("timeout tag applied", "onboarding-timeout" in dev2.tags)
    check("completed after timeout path", run2.status == "completed")

    # ── 4) DEP vs OTA dispatch: enroll_profile runs s-profile only ────────────
    print("4) enroll_profile runs the profile start (kind routing)")
    ota = await new_device("OTA-1", "host-ota")
    pruns = await atc.start_flows_for_event(ota, "enroll_profile")
    await ota.refresh_from_db()
    check("one profile run started", len(pruns) == 1 and pruns[0].start_node == "s-profile")
    check("ota tag applied + completed", "ota" in ota.tags and pruns[0].status == "completed")

    # ── 5) match scoping: a non-Mac device does not fire the Mac-scoped start ──
    print("5) start match scope excludes out-of-scope devices")
    ipad = await new_device("IPAD-1", "host-ipad", dep=True, model="iPad13,8")
    ipad_runs = await atc.start_flows_for_event(ipad, "enroll_dep")
    check("Mac-scoped s-dep did not fire for an iPad", ipad_runs == [])

    # ── 6) check-in dedup: a second check-in does not pile up a run ────────────
    print("6) checkin start dedups while a run is active")
    cdev = await new_device("CHK-1", "host-chk")
    r1 = await atc.start_flows_for_event(cdev, "checkin")
    r2 = await atc.start_flows_for_event(cdev, "checkin")
    check("first checkin started a run", len(r1) == 1)
    check("second checkin deduped (no new run)", r2 == [])
    active = await FlowRun.filter(
        device_id=cdev.id, start_node="s-checkin", status__in=["running", "waiting"]).count()
    check("exactly one active checkin run", active == 1)

    # ── 7) scheduled interval: launch, then skip until the interval elapses ────
    print("7) scheduled start launches on interval, dedups within it")
    sdev = await new_device("SCHED-1", "host-sched")
    n1 = await atc.sweep_scheduled_starts(tenant, [sdev])
    await sdev.refresh_from_db()
    check("schedule launched one run", n1 == 1)
    check("schedule tag applied", "swept" in sdev.tags)
    n2 = await atc.sweep_scheduled_starts(tenant, [sdev])
    check("re-sweep within interval launches nothing", n2 == 0)
    await FlowRun.filter(device_id=sdev.id, start_node="s-schedule").update(
        started_at=datetime.now(timezone.utc) - timedelta(hours=2))
    n3 = await atc.sweep_scheduled_starts(tenant, [sdev])
    check("re-sweep after interval relaunches", n3 == 1)
    total_sched = await FlowRun.filter(device_id=sdev.id, start_node="s-schedule").count()
    check("two schedule runs recorded", total_sched == 2)

    # ── 8) human gate: timeout -> manual_gate -> resume down chosen edge ───────
    print("8) wait_for timeout escalates to a manual_gate; admin decision resumes")
    gdev = await new_device("GATE-1", "host-gate")
    grun = await atc.start_run_from_start(gdev, "s-gate")
    await grun.refresh_from_db()
    check("gate flow parked at g-wait", grun.status == "waiting" and grun.current_node == "g-wait")
    await FlowRun.filter(id=grun.id).update(
        wait_deadline=datetime.now(timezone.utc) - timedelta(minutes=1))
    await atc.sweep_timeouts(tenant)
    await grun.refresh_from_db()
    check("parked on manual gate", grun.status == "waiting" and grun.current_node == "g-gate")
    check("waiting_signal is manual with no deadline",
          grun.waiting_signal == "manual" and grun.wait_deadline is None)
    gate_alert = await Alert.filter(
        rule_id=f"atc:gate:{grun.id}").exclude(status="resolved").first()
    check("gate alert opened", gate_alert is not None and gate_alert.status == "open"
          and (gate_alert.detail or {}).get("kind") == "atc_gate")

    # sweep must NOT auto-advance a manual gate
    await atc.sweep_timeouts(tenant)
    await grun.refresh_from_db()
    check("manual gate not swept by timeout", grun.status == "waiting" and grun.current_node == "g-gate")

    resumed = await atc.resume_manual_gate(grun.id, "on_release", "admin@x")
    await grun.refresh_from_db()
    check("gate resumed to completion via on_release", grun.status == "completed")
    check("release_device visited from gate", "g-release" in (grun.context or {}).get("visited", []))
    gate_after = await Alert.filter(
        rule_id=f"atc:gate:{grun.id}").exclude(status="resolved").first()
    check("gate alert resolved on decision", gate_after is None)

    # double-click: resuming again is a benign no-op
    again = await atc.resume_manual_gate(grun.id, "on_release", "admin@x")
    await grun.refresh_from_db()
    check("double resume is idempotent (still completed)",
          grun.status == "completed" and again is not None)

    # plain-resolve of a gate alert fails the run (dismissed without decision)
    print("8b) plain-resolving a gate alert fails the parked run")
    gdev2 = await new_device("GATE-2", "host-gate2")
    grun2 = await atc.start_run_from_start(gdev2, "s-gate")
    await FlowRun.filter(id=grun2.id).update(
        wait_deadline=datetime.now(timezone.utc) - timedelta(minutes=1))
    await atc.sweep_timeouts(tenant)
    await grun2.refresh_from_db()
    check("gdev2 parked on manual gate", grun2.current_node == "g-gate")
    ga2 = await Alert.filter(rule_id=f"atc:gate:{grun2.id}").exclude(status="resolved").first()
    await atc.fail_gate_run(str(grun2.id), "gate dismissed by admin@x")
    await grun2.refresh_from_db()
    check("run failed on gate dismissal", grun2.status == "failed")
    _ = ga2

    # ── 9) ref-based wait matches only the queued profile ref ─────────────────
    print("9) profile_installed wait matches only the queued profile ref")
    dev3 = await new_device("REF-1", "host-ref")
    run3 = await atc.start_run_from_start(dev3, "s-ref")
    await run3.refresh_from_db()
    check("parked on profile_installed", run3.waiting_signal == "profile_installed")
    await atc.advance_on_signal(str(dev3.id), "profile_installed", ref="other")
    await run3.refresh_from_db()
    check("unrelated profile ref does not resume", run3.status == "waiting")
    await atc.advance_on_signal(str(dev3.id), "profile_installed", ref="eu-wifi")
    await run3.refresh_from_db()
    check("matching profile ref resumes to completion", run3.status == "completed")

    # ── 10) empty-expectation ref wait is skipped, not hung ───────────────────
    print("10) a ref-based wait with nothing queued is skipped")
    dev6 = await new_device("STANDALONE-1", "host-sa")
    run6 = await atc.start_run_from_start(dev6, "s-standalone")
    await run6.refresh_from_db()
    check("standalone wait_for(app_installed) skipped -> completed", run6.status == "completed")

    # ── 11) two sequential ref waits: stale ref must not satisfy the second ────
    print("11) REGRESSION: second wait_for is not satisfied by a stale ref")
    dev7 = await new_device("DOUBLE-1", "host-dw")
    run7 = await atc.start_run_from_start(dev7, "s-double")
    await run7.refresh_from_db()
    check("parked at d-wait1", run7.status == "waiting" and run7.current_node == "d-wait1")

    async def mark_installed(device, profile_id):
        await ProfileDeployment.update_or_create(
            tenant=tenant, device=device, profile_id=profile_id,
            defaults={"status": "installed"})

    await mark_installed(dev7, "P1")
    await atc.advance_on_signal(str(dev7.id), "profile_installed", ref="P1")
    await run7.refresh_from_db()
    check("advanced to d-wait2", run7.status == "waiting" and run7.current_node == "d-wait2")
    await atc.advance_on_signal(str(dev7.id), "profile_installed", ref="P1")
    await run7.refresh_from_db()
    check("redelivered P1 does not resume d-wait2", run7.current_node == "d-wait2")
    await mark_installed(dev7, "P2")
    await atc.advance_on_signal(str(dev7.id), "profile_installed", ref="P2")
    await run7.refresh_from_db()
    check("matching P2 resumes to completion", run7.status == "completed")

    # ── 12) flow_hash pinning: a breaking edit can't corrupt an in-flight run ──
    print("12) editing flows.yaml mid-run does not affect the pinned run")
    dev4 = await new_device("PIN-1", "host-eu-4", dep=True)
    run4 = (await atc.start_flows_for_event(dev4, "enroll_dep"))[0]
    await run4.refresh_from_db()
    original_hash = run4.flow_hash
    broken = {"flow": {**BASE_FLOW,
                       "nodes": [n for n in BASE_FLOW["nodes"] if n["id"] != "dep-end"]}}
    (tdir / "flows.yaml").write_text(yaml.safe_dump(broken))
    await atc.advance_on_signal(str(dev4.id), "device_info")
    await run4.refresh_from_db()
    check("pinned run still completed after breaking edit", run4.status == "completed")
    check("flow_hash unchanged", run4.flow_hash == original_hash)
    (tdir / "flows.yaml").write_text(yaml.safe_dump({"flow": BASE_FLOW}))

    # ── 13) enroll supersede is scoped to the same start ──────────────────────
    print("13) re-enroll supersedes the prior run from the same start")
    dev5 = await new_device("RE-1", "host-eu-5", dep=True)
    ra = (await atc.start_flows_for_event(dev5, "enroll_dep"))[0]
    await ra.refresh_from_db()
    check("first run waiting", ra.status == "waiting")
    rb = (await atc.start_flows_for_event(dev5, "enroll_dep"))[0]
    await ra.refresh_from_db()
    await rb.refresh_from_db()
    check("prior run cancelled", ra.status == "cancelled")
    check("new run active + distinct", rb.id != ra.id and rb.status in ("waiting", "running", "completed"))

    # ── 14) legacy multi-flow migration ───────────────────────────────────────
    print("14) legacy multi-flow flows.yaml migrates to a single flow")
    legacy = {"flows": [
        {"id": "legacy-a", "name": "A", "enabled": True, "priority": 10,
         "trigger": {"on": "enroll", "match": {
             "conditions": [{"type": "platform", "operator": "in", "value": ["Mac"]}]}},
         "start": "n1",
         "nodes": [{"id": "n1", "type": "assign_tag", "params": {"tags": ["x"]}, "next": "n2"},
                   {"id": "n2", "type": "end"}]},
        {"id": "legacy-b", "name": "B", "enabled": False, "priority": 5,
         "trigger": {"on": "enroll", "match": {}}, "start": "m1",
         "nodes": [{"id": "m1", "type": "end"}]},
    ]}
    mflow, mwarns = normalize_flow_document(legacy)
    check("legacy migrated to a flow", mflow is not None)
    starts = [n for n in (mflow or {}).get("nodes", []) if n.get("type") == "start"]
    check("a start node was synthesized", len(starts) == 1
          and starts[0]["params"]["kind"] == "enroll_dep"
          and starts[0]["next"] == "n1")
    check("kept the first enabled flow (legacy-a)", (mflow or {}).get("id") == "legacy-a")
    check("migration emitted a warning", len(mwarns) >= 1)
    passthrough, _ = normalize_flow_document({"flow": BASE_FLOW})
    check("new-shape doc passes through unchanged", passthrough is BASE_FLOW)

    # ── 15) flows.yaml validator ──────────────────────────────────────────────
    print("15) validator accepts the model flow and rejects malformed starts/gates")

    def validate_flow(doc):
        (tdir / "flows.yaml").write_text(yaml.safe_dump(doc))
        valid, errors, warnings = YAMLValidator(tdir).validate_all()
        (tdir / "flows.yaml").write_text(yaml.safe_dump({"flow": BASE_FLOW}))
        return valid, errors, warnings

    ok, errs, _ = validate_flow({"flow": BASE_FLOW})
    check("BASE_FLOW validates", ok, )
    if not ok:
        print("      errors:", errs)

    def _err(doc):
        return validate_flow(doc)[1]

    no_start = {"flow": {"id": "x", "name": "X",
                         "nodes": [{"id": "a", "type": "end"}]}}
    check("no-start flow rejected",
          any("no 'start'" in e for e in _err(no_start)))

    bad_kind = {"flow": {"id": "x", "name": "X", "nodes": [
        {"id": "s", "type": "start", "params": {"kind": "bogus"}, "next": "e"},
        {"id": "e", "type": "end"}]}}
    check("bad start kind rejected",
          any("unknown trigger kind" in e for e in _err(bad_kind)))

    sched_no_iv = {"flow": {"id": "x", "name": "X", "nodes": [
        {"id": "s", "type": "start", "params": {"kind": "schedule"}, "next": "e"},
        {"id": "e", "type": "end"}]}}
    check("schedule without interval rejected",
          any("interval_minutes" in e for e in _err(sched_no_iv)))

    bad_gate = {"flow": {"id": "x", "name": "X", "nodes": [
        {"id": "s", "type": "start", "params": {"kind": "enroll_dep"}, "next": "g"},
        {"id": "g", "type": "manual_gate", "params": {
            "summary": "s", "severity": "yellow",
            "options": [{"label": "Go", "edge": "on_bogus"}]},
         "on_release": "e"},
        {"id": "e", "type": "end"}]}}
    check("manual_gate with an invalid option edge rejected",
          any("invalid edge" in e for e in _err(bad_gate)))

    # Let any spawned background tasks settle, then close.
    await asyncio.sleep(0.2)
    await Tortoise.close_connections()

    print()
    if _FAILURES:
        print(f"FAILED ({len(_FAILURES)}): {_FAILURES}")
        return 1
    print("ALL ATC E2E CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
