"""Backend E2E for the ATC flow engine, on an in-memory sqlite Tortoise DB.

Exercises the real state machine end to end (no docker, no MDM network): enroll
-> flow runs forward -> parks at wait_for -> resumes on a device signal ->
completes; plus timeout sweep, ref-based waits, flow_hash pinning across a live
edit, and re-enroll supersede.

Run:  PYTHONPATH=. ./.venv/bin/python tests/verify_atc.py
Exits non-zero if any check fails.
"""

import asyncio
import os
import sys
import tempfile
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

    async def send_raw_command(self, udid, request_type, fields):
        return {"command_uuid": "u-raw"}

    async def close(self):
        pass


BASE_FLOWS = {
    "flows": [
        {
            "id": "standard-mac-onboarding",
            "name": "Standard Mac Onboarding",
            "enabled": True,
            "priority": 100,
            "trigger": {"on": "enroll", "match": {
                "conditions": [{"type": "platform", "operator": "in", "value": ["Mac"]}]}},
            "start": "assign-tags",
            "nodes": [
                {"id": "assign-tags", "type": "assign_tag",
                 "params": {"tags": ["corp", "onboarding"]}, "next": "name-device"},
                {"id": "name-device", "type": "set_name",
                 "params": {"template": "IT-{serial}"}, "next": "region-branch"},
                {"id": "region-branch", "type": "branch",
                 "params": {"condition": {"type": "hostname", "operator": "contains",
                                          "value": ["-eu-"]}},
                 "on_true": "eu-wifi", "on_false": "us-wifi"},
                {"id": "eu-wifi", "type": "install_profiles",
                 "params": {"profile_ids": ["eu-wifi"]}, "next": "await-checkin"},
                {"id": "us-wifi", "type": "install_profiles",
                 "params": {"profile_ids": ["us-wifi"]}, "next": "await-checkin"},
                {"id": "await-checkin", "type": "wait_for",
                 "params": {"signal": "device_info", "timeout_minutes": 60},
                 "on_timeout": "mark-degraded", "next": "finish"},
                {"id": "mark-degraded", "type": "assign_tag",
                 "params": {"tags": ["onboarding-timeout"]}, "next": "finish"},
                {"id": "finish", "type": "end"},
            ],
        },
        {
            "id": "standalone-wait-flow",
            "name": "Standalone wait",
            "enabled": True,
            "priority": 1,
            "trigger": {"on": "enroll", "match": {}},
            "start": "w",
            "nodes": [
                {"id": "w", "type": "wait_for",
                 "params": {"signal": "app_installed", "timeout_minutes": 5}, "next": "d"},
                {"id": "d", "type": "end"},
            ],
        },
        {
            "id": "ref-wait-flow",
            "name": "Ref wait",
            "enabled": True,
            "priority": 1,
            "trigger": {"on": "enroll", "match": {}},
            "start": "t",
            "nodes": [
                {"id": "t", "type": "assign_tag", "params": {"tags": ["corp"]}, "next": "inst"},
                {"id": "inst", "type": "install_profiles",
                 "params": {"profile_ids": ["eu-wifi"]}, "next": "wait"},
                {"id": "wait", "type": "wait_for",
                 "params": {"signal": "profile_installed", "timeout_minutes": 30},
                 "next": "done"},
                {"id": "done", "type": "end"},
            ],
        },
        {
            # Regression: two sequential wait_for(profile_installed) barriers.
            # W2 must not be satisfied by a stale ref left over from W1.
            "id": "double-wait-flow",
            "name": "Double wait",
            "enabled": True,
            "priority": 1,
            "trigger": {"on": "enroll", "match": {}},
            "start": "inst1",
            "nodes": [
                {"id": "inst1", "type": "install_profiles",
                 "params": {"profile_ids": ["P1"]}, "next": "wait1"},
                {"id": "wait1", "type": "wait_for",
                 "params": {"signal": "profile_installed", "timeout_minutes": 30},
                 "next": "inst2"},
                {"id": "inst2", "type": "install_profiles",
                 "params": {"profile_ids": ["P2"]}, "next": "wait2"},
                {"id": "wait2", "type": "wait_for",
                 "params": {"signal": "profile_installed", "timeout_minutes": 30},
                 "next": "done2"},
                {"id": "done2", "type": "end"},
            ],
        },
        {
            # Regression: re-enroll must cancel ALL active runs for the device,
            # not just a prior run of the same flow id. Scoped to a specific
            # serial prefix (via an additional AND'd condition) so it can never
            # win against another test's device elsewhere in this suite.
            "id": "re-enroll-a",
            "name": "Re-enroll A (tag absent)",
            "enabled": True,
            "priority": 200,
            "trigger": {"on": "enroll", "match": {"conditions": [
                {"type": "serial_number", "operator": "contains", "value": "SWITCH"},
                {"type": "tag", "operator": "in", "value": ["switch-flow"], "negate": True}]}},
            "start": "await-a",
            "nodes": [
                {"id": "await-a", "type": "wait_for",
                 "params": {"signal": "device_info", "timeout_minutes": 60}, "next": "end-a"},
                {"id": "end-a", "type": "end"},
            ],
        },
        {
            "id": "re-enroll-b",
            "name": "Re-enroll B (tag present)",
            "enabled": True,
            "priority": 150,
            "trigger": {"on": "enroll", "match": {"conditions": [
                {"type": "serial_number", "operator": "contains", "value": "SWITCH"},
                {"type": "tag", "operator": "in", "value": ["switch-flow"]}]}},
            "start": "await-b",
            "nodes": [
                {"id": "await-b", "type": "wait_for",
                 "params": {"signal": "device_info", "timeout_minutes": 60}, "next": "end-b"},
                {"id": "end-b", "type": "end"},
            ],
        },
    ]
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
    (tdir / "flows.yaml").write_text(yaml.safe_dump(BASE_FLOWS))


async def main():
    base = Path(tempfile.mkdtemp())
    os.environ["YAML_CONFIG_PATH"] = str(base)
    _write_configs(base)

    # Patch the connector before atc's lazy imports resolve it.
    import controller.services.mdm_connector as mc
    mc.MDMConnector = FakeConnector

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    from controller.models.tenant import Tenant, Device, FlowRun
    from controller.services import atc

    tenant = await Tenant.create(id="default", name="Default")

    async def new_device(serial, host):
        return await Device.create(
            tenant=tenant, udid=f"UDID-{serial}", serial_number=serial,
            device_model="MacBookPro18,3", os_version="14.5", hostname=host,
            enrollment_state="enrolled", groups=[], tags=[])

    # ── 1) Enroll -> flow runs, applies tags/name/branch/install, parks ───────
    print("1) enroll runs the flow and parks at wait_for")
    dev = await new_device("MAC-EU", "host-eu-1")
    run = await atc.start_flows_for_enroll(dev)
    await dev.refresh_from_db()
    check("a run was created", run is not None)
    check("picked highest-priority flow", run.flow_id == "standard-mac-onboarding")
    check("tags corp+onboarding applied", set(["corp", "onboarding"]) <= set(dev.tags))
    check("name set from template", dev.name == "IT-MAC-EU")
    await run.refresh_from_db()
    check("parked waiting", run.status == "waiting")
    check("parked at await-checkin", run.current_node == "await-checkin")
    check("waiting on device_info", run.waiting_signal == "device_info")
    check("EU branch taken (visited eu-wifi)", "eu-wifi" in (run.context or {}).get("visited", []))
    check("US branch not taken", "us-wifi" not in (run.context or {}).get("visited", []))

    # ── 2) device_info signal resumes -> completes ────────────────────────────
    print("2) device_info signal resumes the run to completion")
    await atc.advance_on_signal(str(dev.id), "device_info")
    await run.refresh_from_db()
    check("run completed", run.status == "completed")
    check("ended at finish (visited)", "finish" in (run.context or {}).get("visited", []))

    # ── 3) timeout follows on_timeout ─────────────────────────────────────────
    print("3) wait_for timeout follows on_timeout")
    dev2 = await new_device("MAC-US", "host-us-1")
    run2 = await atc.start_flows_for_enroll(dev2)
    await run2.refresh_from_db()
    check("US device took us-wifi branch", "us-wifi" in (run2.context or {}).get("visited", []))
    # Force the deadline into the past and sweep.
    from datetime import datetime, timedelta, timezone
    run2.wait_deadline = datetime.now(timezone.utc) - timedelta(minutes=1)
    await run2.save()
    swept = await atc.sweep_timeouts(tenant)
    await run2.refresh_from_db()
    await dev2.refresh_from_db()
    check("sweep processed the run", swept >= 1)
    check("timeout followed on_timeout (onboarding-timeout tag)", "onboarding-timeout" in dev2.tags)
    check("run completed after timeout path", run2.status == "completed")

    # ── 4) ref-based wait: profile_installed matches only the queued ref ───────
    print("4) profile_installed wait matches only the queued profile ref")
    dev3 = await new_device("MAC-REF", "host-3")
    run3 = await atc.start_flow_by_id(dev3, "ref-wait-flow")
    await run3.refresh_from_db()
    check("parked on profile_installed", run3.waiting_signal == "profile_installed")
    check("expected ref recorded", "eu-wifi" in (run3.context or {}).get("expected", {}).get("profile_installed", []))
    await atc.advance_on_signal(str(dev3.id), "profile_installed", ref="other-profile")
    await run3.refresh_from_db()
    check("unrelated profile ref does NOT resume", run3.status == "waiting")
    await atc.advance_on_signal(str(dev3.id), "profile_installed", ref="eu-wifi")
    await run3.refresh_from_db()
    check("matching profile ref resumes to completion", run3.status == "completed")

    # ── 5) flow_hash pinning: a live edit that breaks the flow can't corrupt an
    #      in-flight run (it finishes on its snapshot) ─────────────────────────
    print("5) editing flows.yaml mid-run does not affect the pinned run")
    dev4 = await new_device("MAC-PIN", "host-eu-4")
    run4 = await atc.start_flows_for_enroll(dev4)
    await run4.refresh_from_db()
    original_hash = run4.flow_hash
    # Break the on-disk flow: drop the 'finish' node entirely. A run reading the
    # live definition would fail; the pinned snapshot still has it.
    broken = yaml.safe_load((base / "tenants" / "default" / "flows.yaml").read_text())
    broken["flows"][0]["nodes"] = [n for n in broken["flows"][0]["nodes"] if n["id"] != "finish"]
    (base / "tenants" / "default" / "flows.yaml").write_text(yaml.safe_dump(broken))
    await atc.advance_on_signal(str(dev4.id), "device_info")
    await run4.refresh_from_db()
    check("pinned run still completed after breaking edit", run4.status == "completed")
    check("flow_hash unchanged", run4.flow_hash == original_hash)
    # restore
    (base / "tenants" / "default" / "flows.yaml").write_text(yaml.safe_dump(BASE_FLOWS))

    # ── 6) re-enroll supersedes an active run of the same flow ────────────────
    print("6) re-enroll supersedes the prior active run of the same flow")
    dev5 = await new_device("MAC-RE", "host-eu-5")
    run_a = await atc.start_flows_for_enroll(dev5)
    await run_a.refresh_from_db()
    check("first run is waiting", run_a.status == "waiting")
    run_b = await atc.start_flows_for_enroll(dev5)
    await run_a.refresh_from_db()
    await run_b.refresh_from_db()
    check("prior run cancelled", run_a.status == "cancelled")
    check("new run active", run_b.status in ("waiting", "running", "completed"))
    check("distinct run ids", run_a.id != run_b.id)

    # ── 7) a wait_for with nothing queued to wait on is skipped, not hung ─────
    print("7) a ref-based wait with an empty expectation is skipped (no stall)")
    dev6 = await new_device("MAC-SW", "host-6")
    run6 = await atc.start_flow_by_id(dev6, "standalone-wait-flow")
    await run6.refresh_from_db()
    check("standalone wait_for(app_installed) skipped -> completed",
          run6.status == "completed")

    # ── 8) REGRESSION: two sequential wait_for(profile_installed) barriers ────
    # Before the fix, W2's expected refs still carried P1's ref from W1 (never
    # cleared on resume), so W2 would resolve immediately on P1's signal instead
    # of genuinely waiting for P2. _consume_expected must reset the bucket when
    # the run leaves W1.
    print("8) REGRESSION: a second wait_for(profile_installed) is not satisfied "
          "by a stale ref from the first")
    dev7 = await new_device("MAC-DW", "host-7")
    run7 = await atc.start_flow_by_id(dev7, "double-wait-flow")
    await run7.refresh_from_db()
    check("parked at wait1", run7.status == "waiting" and run7.current_node == "wait1")
    check("wait1 expects P1", "P1" in (run7.context or {}).get("expected", {}).get("profile_installed", []))

    # Simulate P1 installed (deployment row, matching how the reconciler would
    # record it) and deliver the matching signal. install_profiles spawns a
    # background task that get_or_creates its own (pending) deployment row, so
    # use update_or_create (same idiom as ProfileManager.deploy_profile) rather
    # than a blind create that would race it.
    from controller.models.tenant import ProfileDeployment as _PD

    async def _mark_installed(device, profile_id):
        await _PD.update_or_create(
            tenant=tenant, device=device, profile_id=profile_id,
            defaults={"status": "installed"},
        )

    await _mark_installed(dev7, "P1")
    await atc.advance_on_signal(str(dev7.id), "profile_installed", ref="P1")
    await run7.refresh_from_db()
    check("advanced past wait1 to wait2 (not completed)",
          run7.status == "waiting" and run7.current_node == "wait2")
    check("wait2 expects P2, not P1 (stale ref cleared)",
          "P2" in (run7.context or {}).get("expected", {}).get("profile_installed", [])
          and "P1" not in (run7.context or {}).get("expected", {}).get("profile_installed", []))

    # A redelivered P1 signal must NOT resume wait2 (that's the bug: the old ref
    # satisfying the new barrier).
    await atc.advance_on_signal(str(dev7.id), "profile_installed", ref="P1")
    await run7.refresh_from_db()
    check("redelivered P1 ref does NOT resume wait2",
          run7.status == "waiting" and run7.current_node == "wait2")

    # Now genuinely satisfy wait2 with P2 and confirm completion.
    await _mark_installed(dev7, "P2")
    await atc.advance_on_signal(str(dev7.id), "profile_installed", ref="P2")
    await run7.refresh_from_db()
    check("matching P2 ref resumes wait2 to completion", run7.status == "completed")

    # ── 9) REGRESSION: re-enroll supersedes ALL active runs, not just the same
    #      flow id ─────────────────────────────────────────────────────────────
    # Set up two enroll flows: A (higher priority) wins while a 'switch-flow' tag
    # is absent and parks at a wait_for. Then flip device state so A's trigger no
    # longer matches and B's does, and re-enroll. The prior A run must be
    # cancelled (not left dangling in 'waiting') and only B's run active.
    print("9) REGRESSION: re-enroll cancels a prior run even when a DIFFERENT "
          "flow wins the second time")
    dev8 = await new_device("MAC-SWITCH", "host-8")
    dev8.tags = []
    await dev8.save(update_fields=["tags"])
    run_first = await atc.start_flows_for_enroll(dev8)
    await run_first.refresh_from_db()
    check("first enroll picked flow A (tag absent)", run_first.flow_id == "re-enroll-a")
    check("flow A run parked waiting", run_first.status == "waiting")

    # Flip device state: flow A's trigger (negated tag) no longer matches, flow
    # B's (tag present) now does.
    await dev8.refresh_from_db()
    dev8.tags = ["switch-flow"]
    await dev8.save(update_fields=["tags"])
    run_second = await atc.start_flows_for_enroll(dev8)
    await run_first.refresh_from_db()
    await run_second.refresh_from_db()
    check("second enroll picked the NEW winning flow B", run_second.flow_id == "re-enroll-b")
    check("distinct flow ids across the two runs", run_first.flow_id != run_second.flow_id)
    check("prior flow-A run cancelled (superseded across flow ids)",
          run_first.status == "cancelled")
    active_count = await FlowRun.filter(
        device_id=dev8.id, status__in=["running", "waiting"]
    ).count()
    check("at most one active run remains for the device", active_count <= 1)
    check("the one active run is flow B's", run_second.status in ("waiting", "running", "completed"))

    # Let any spawned install/reconcile background tasks settle, then close.
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
