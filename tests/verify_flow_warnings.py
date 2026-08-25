"""Coverage for the server-side flow warning channel in controller/utils/yaml_validator.py.

Run: PYTHONPATH=. ./.venv/bin/python tests/verify_flow_warnings.py
"""
import asyncio
import json
import os
import tempfile
from pathlib import Path

import yaml

from controller.utils import payload_types
from controller.utils.yaml_validator import Profile, YAMLValidator

PASS, FAIL = [], []

SEEDED_TENANT = Path(__file__).resolve().parents[1] / "deploy" / "tenant-template" / "default"


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


WIFI = {
    "id": "wifi",
    "name": "Corporate Wi-Fi",
    "type": "configuration",
    "groups": ["lab"],
    "payload": {"PayloadType": "com.apple.wifi.managed", "SSID_STR": "CorpNet"},
}
APP = {
    "id": "pages",
    "name": "Pages",
    "bundle_id": "com.apple.Pages",
    "versions": [{"version": "1.0", "groups": ["lab"],
                  "s3_key": "apps/pages-1.0.pkg", "sha256": "0" * 64}],
}
DEP_PAYLOAD = {
    "id": "ade-ipads",
    "name": "Classroom iPads",
    "dep_profile": True,
    "payload": {"await_device_configured": True},
}
DEP_ALIAS = {
    "id": "ade-alias",
    "name": "Classroom iPads (alias key)",
    "type": "enrollment",
    "enrollment": {"await_device_configured": True},
}
DEP_NO_AWAIT = {
    "id": "ade-relaxed",
    "name": "Relaxed iPads",
    "dep_profile": True,
    "payload": {"await_device_configured": False},
}


def run(flow, profiles=None, dispatcher=None, declarations=None, apps=None):
    """Validate a synthetic tenant whose flows.yaml holds the given flow.

    dispatcher, declarations and apps, when given, are written as their own files, so the rule-scope, legacy-bridge and
    app-schema checks run from the same harness.
    """
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        (tdir / "config.yaml").write_text(yaml.safe_dump(
            {"tenant": {"id": "t1", "name": "T1", "allowed_users": ["a@t1"]}}))
        (tdir / "groups.yaml").write_text(yaml.safe_dump({"groups": [
            {"name": "lab",
             "conditions": [{"type": "tag", "operator": "in", "value": ["lab"]}]}]}))
        (tdir / "apps.yaml").write_text(yaml.safe_dump(
            {"apps": apps if apps is not None else [APP]}))
        (tdir / "profiles.yaml").write_text(yaml.safe_dump(
            {"profiles": profiles if profiles is not None else [WIFI]}))
        if flow is not None:
            (tdir / "flows.yaml").write_text(yaml.safe_dump({"flow": flow}))
        if dispatcher is not None:
            (tdir / "dispatcher.yaml").write_text(yaml.safe_dump(dispatcher))
        if declarations is not None:
            (tdir / "declarations.yaml").write_text(yaml.safe_dump(declarations))
        v = YAMLValidator(tdir)
        valid, errors, warnings = v.validate_all()
        return valid, errors, warnings, v.flow_warnings


def codes(fw):
    return [w["code"] for w in fw]


def by_code(fw, code):
    return [w for w in fw if w["code"] == code]


def flow_doc(nodes):
    return {"id": "f", "name": "F", "enabled": True, "nodes": nodes}


START = {"id": "start-1", "type": "start",
         "params": {"kind": "enroll_dep",
                    "match": {"conditions": [
                        {"type": "platform", "operator": "in", "value": ["Mac"]}]}},
         "next": "install-wifi"}


def main():
    print("1) gated install -> release with no barrier -> release-ordering fires")
    flow = flow_doc([
        dict(START),
        {"id": "install-wifi", "type": "install_profiles",
         "params": {"profile_ids": ["wifi"]}, "next": "release-1"},
        {"id": "release-1", "type": "release_device", "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, warnings, fw = run(flow)
    hits = by_code(fw, "release-ordering")
    check("save stays valid", valid and not errors)
    check("one release-ordering warning", len(hits) == 1)
    check("badge sits on the release node",
          hits and hits[0]["node_id"] == "release-1")
    check("message names both nodes",
          hits and '"release-1"' in hits[0]["message"]
          and '"install-wifi"' in hits[0]["message"])
    check("structured entries mirror into plain warnings",
          all(w["message"] in warnings for w in fw))

    print("2) matching wait_for barrier between install and release -> silent")
    flow = flow_doc([
        dict(START),
        {"id": "install-wifi", "type": "install_profiles",
         "params": {"profile_ids": ["wifi"]}, "next": "wait-1"},
        {"id": "wait-1", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "next": "release-1"},
        {"id": "release-1", "type": "release_device", "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, _, _, fw = run(flow)
    check("barriered flow gets no release-ordering warning",
          valid and not by_code(fw, "release-ordering"))

    print("3) gate: false install before release -> silent (opted out)")
    flow = flow_doc([
        dict(START),
        {"id": "install-wifi", "type": "install_profiles",
         "params": {"profile_ids": ["wifi"], "gate": False}, "next": "release-1"},
        {"id": "release-1", "type": "release_device", "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, _, _, fw = run(flow)
    check("ungated install gets no release-ordering warning",
          valid and not by_code(fw, "release-ordering"))

    print("4) a barrier for the WRONG signal does not count")
    flow = flow_doc([
        dict(START, next="install-apps-1"),
        {"id": "install-apps-1", "type": "install_apps",
         "params": {"app_ids": ["pages"]}, "next": "wait-1"},
        {"id": "wait-1", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "next": "release-1"},
        {"id": "release-1", "type": "release_device", "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, _, _, fw = run(flow)
    hits = by_code(fw, "release-ordering")
    check("app install behind a profile barrier still warns",
          valid and len(hits) == 1 and "apps" in hits[0]["message"])

    print("5) kiosk flow: no release node, no await profile -> fully silent")
    flow = flow_doc([
        dict(START),
        {"id": "install-wifi", "type": "install_profiles",
         "params": {"profile_ids": ["wifi"]}, "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, _, _, fw = run(flow)
    check("kiosk flow gets no release-ordering warning",
          valid and not by_code(fw, "release-ordering"))
    check("kiosk flow gets no dep-await warning",
          not by_code(fw, "dep-await-no-release"))

    print("6) await_device_configured DEP profile, enroll_dep start, no release -> dep-await-no-release fires")
    flow = flow_doc([
        dict(START, next="tag-1"),
        {"id": "tag-1", "type": "assign_tag", "params": {"tags": ["x"]},
         "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, _, fw = run(flow, profiles=[WIFI, DEP_PAYLOAD])
    hits = by_code(fw, "dep-await-no-release")
    check("save stays valid", valid and not errors)
    check("dep-await-no-release fires once, on the start node",
          len(hits) == 1 and hits[0]["node_id"] == "start-1")
    check("message names the DEP profile and the consequence",
          hits and '"ade-ipads"' in hits[0]["message"]
          and "Setup Assistant" in hits[0]["message"])

    print("7) release reachable from the enroll_dep start -> dep-await-no-release silent")
    flow = flow_doc([
        dict(START, next="release-1"),
        {"id": "release-1", "type": "release_device", "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, _, _, fw = run(flow, profiles=[WIFI, DEP_PAYLOAD])
    check("flow that releases gets no dep-await-no-release warning",
          valid and not by_code(fw, "dep-await-no-release"))

    print("8) enrollment: alias key is visible to dep-await-no-release (the Profile model keeps it)")
    check("Profile model retains the enrollment key",
          (Profile(**DEP_ALIAS).enrollment or {}).get("await_device_configured") is True)
    flow = flow_doc([
        dict(START, next="end-1"),
        {"id": "end-1", "type": "end"},
    ])
    valid, _, warnings, fw = run(flow, profiles=[WIFI, DEP_ALIAS])
    hits = by_code(fw, "dep-await-no-release")
    check("enrollment:-authored profile fires dep-await-no-release",
          valid and len(hits) == 1 and '"ade-alias"' in hits[0]["message"])
    check("no spurious empty-payload warning for the alias profile",
          not any("ade-alias" in w and "empty payload" in w for w in warnings))

    # Upgrade path: a document with a non-dict enrollment: was saveable before the field was declared and has to stay
    # saveable, or declaring it write-locks the tenant at upgrade.
    print("8b) a non-mapping enrollment: value coerces to None, warns, and saves")
    for shape in (True, "server", [1, 2]):
        legacy = dict(WIFI, id="legacy", name="Legacy", enrollment=shape)
        valid, errors, warnings, fw = run(flow, profiles=[legacy])
        check(f"enrollment: {shape!r} still saves", valid and not errors)
        check(f"enrollment: {shape!r} draws the ignored-key warning",
              any("'legacy'" in w and "enrollment" in w for w in warnings))
    check("model coerces a non-dict enrollment to None",
          Profile(**dict(WIFI, enrollment=True)).enrollment is None)

    print("9) await profile but no enroll_dep start anywhere -> dep-await-no-release fires with no node")
    flow = flow_doc([
        {"id": "start-1", "type": "start",
         "params": {"kind": "checkin", "match": {"groups": ["lab"]}},
         "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, _, _, fw = run(flow, profiles=[WIFI, DEP_PAYLOAD])
    hits = by_code(fw, "dep-await-no-release")
    check("dep-await-no-release fires without a node id",
          valid and len(hits) == 1 and hits[0]["node_id"] is None)
    check("message says the flow has no Automated Enrollment start",
          hits and "no Automated Enrollment start" in hits[0]["message"])

    print("10) DEP profile without await_device_configured -> dep-await-no-release silent")
    flow = flow_doc([
        dict(START, next="end-1"),
        {"id": "end-1", "type": "end"},
    ])
    valid, _, _, fw = run(flow, profiles=[WIFI, DEP_NO_AWAIT])
    check("await_device_configured: false raises nothing",
          valid and not by_code(fw, "dep-await-no-release"))

    print("11) exclude-only start scope -> warns it matches nobody")
    flow = flow_doc([
        dict(START, params={"kind": "enroll_dep",
                            "match": {"exclude_devices": ["SER1"]}},
             next="end-1"),
        {"id": "end-1", "type": "end"},
    ])
    valid, _, _, fw = run(flow)
    hits = by_code(fw, "exclude-only-scope")
    check("exclude-only scope warns on the start node",
          valid and len(hits) == 1 and hits[0]["node_id"] == "start-1")
    check("message says it matches no devices",
          hits and "matches no devices" in hits[0]["message"])

    print("12) exclude alongside groups -> silent (a real scope)")
    flow = flow_doc([
        dict(START, params={"kind": "enroll_dep",
                            "match": {"groups": ["lab"],
                                      "exclude_devices": ["SER1"]}},
             next="end-1"),
        {"id": "end-1", "type": "end"},
    ])
    valid, _, _, fw = run(flow)
    check("exclude with groups gets no warning",
          valid and not by_code(fw, "exclude-only-scope"))

    print("13) unknown scope keys -> warned, with the nearest valid key")
    flow = flow_doc([
        dict(START, params={"kind": "enroll_dep",
                            "match": {"group": ["lab"], "platforms": ["Mac"]}},
             next="end-1"),
        {"id": "end-1", "type": "end"},
    ])
    valid, _, _, fw = run(flow)
    hits = by_code(fw, "unknown-scope-key")
    check("both unknown keys warned", valid and len(hits) == 2)
    near = [w for w in hits if '"group"' in w["message"]]
    far = [w for w in hits if '"platforms"' in w["message"]]
    check("typo suggests the nearest key",
          near and 'Did you mean "groups"?' in near[0]["message"])
    check("no near match lists the valid keys",
          far and "Valid keys: groups, conditions" in far[0]["message"])

    print("14) clean scoped flow -> no scope warnings at all")
    flow = flow_doc([
        dict(START, next="end-1"),
        {"id": "end-1", "type": "end"},
    ])
    valid, _, _, fw = run(flow)
    check("well-formed scope raises nothing",
          valid and not by_code(fw, "exclude-only-scope")
          and not by_code(fw, "unknown-scope-key"))

    print("15) every rule at once -> the save still succeeds")
    flow = flow_doc([
        {"id": "start-1", "type": "start",
         "params": {"kind": "enroll_dep",
                    "match": {"group": ["lab"], "exclude_devices": ["SER1"]}},
         "next": "install-wifi"},
        {"id": "install-wifi", "type": "install_profiles",
         "params": {"profile_ids": ["wifi"]}, "next": "release-1"},
        {"id": "release-1", "type": "release_device", "next": "end-1"},
        {"id": "end-1", "type": "end"},
        # A second enrollment entry point that never releases: this one draws dep-await-no-release while start-1, which
        # does release, stays clean.
        {"id": "start-2", "type": "start",
         "params": {"kind": "enroll_dep", "match": {"groups": ["lab"]}},
         "next": "end-2"},
        {"id": "end-2", "type": "end"},
    ])
    valid, errors, _, fw = run(flow, profiles=[WIFI, DEP_PAYLOAD])
    got = set(codes(fw))
    check("warnings never fail a save", valid and not errors)
    check("all four codes present",
          {"release-ordering", "dep-await-no-release", "exclude-only-scope",
           "unknown-scope-key"} <= got)
    check("dep-await-no-release fires only for the start with no release path",
          [w["node_id"] for w in by_code(fw, "dep-await-no-release")] == ["start-2"])
    check("every entry is structured",
          all(set(w) == {"flow_id", "node_id", "code", "message"} for w in fw))
    # Node ids are only unique inside a flow, so a finding that does not name its flow points at every flow with a node
    # by that name.
    check("and every entry names the flow it belongs to",
          all(w["flow_id"] for w in fw))

    scope_asymmetry_checks()

    asyncio.run(endpoint_checks())

    barrier_checks()
    accounts_after_release_checks()
    release_without_await_checks()
    bundle_quiet_checks()
    parked_check_warning_checks()
    payload_type_warning_checks()

    print()
    print(f"{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        for f in FAIL:
            print(f"  FAILED: {f}")
        raise SystemExit(1)


SCOPED_START = {"id": "start-1", "type": "start",
                "params": {"kind": "enroll_dep", "match": {"groups": ["lab"]}},
                "next": "end-1"}
BARE_START = {"id": "start-1", "type": "start",
              "params": {"kind": "enroll_dep"}, "next": "end-1"}
END = {"id": "end-1", "type": "end"}


def rule(**over):
    """A minimal valid dispatcher rule; override any field."""
    base = {"id": "r1", "name": "R1", "severity": "yellow",
            "check": {"type": "filevault_disabled"}}
    base.update(over)
    return {"rules": [base]}


def start_warns(warnings):
    return [w for w in warnings if "fires for every device" in w]


def rule_warns(warnings):
    return [w for w in warnings if "watches every device" in w]


def scope_asymmetry_checks():
    """An empty scope means "everyone" to flow starts and dispatcher rules, and "no one" to profiles and app versions.
    These cover the monitoring half."""

    print("16) unscoped flow start -> warns it fires fleet-wide")
    valid, _, warnings, fw = run(flow_doc([BARE_START, END]))
    hits = start_warns(warnings)
    check("bare start warns", valid and len(hits) == 1)
    check("names the start", hits and '"start-1"' in hits[0])
    check("says fleet-wide is normal, not broken",
          hits and "normal choice for a fleet-wide flow" in hits[0])
    check("stays off the badge channel",
          not [w for w in fw if "fires for every device" in w["message"]])

    print("17) empty and scoped starts -> the predicate matches the engine")
    valid, _, warnings, _ = run(flow_doc([
        dict(BARE_START, params={"kind": "enroll_dep", "match": {}}), END]))
    check("match: {} warns", valid and len(start_warns(warnings)) == 1)
    valid, _, warnings, _ = run(flow_doc([
        dict(BARE_START, params={"kind": "enroll_dep",
                                 "match": {"groups": []}}), END]))
    check("match with only empty lists warns",
          valid and len(start_warns(warnings)) == 1)
    valid, _, warnings, _ = run(flow_doc([SCOPED_START, END]))
    check("a real scope stays silent", valid and not start_warns(warnings))

    print("18) exclude-only start -> the other warning, not this one")
    valid, _, warnings, fw = run(flow_doc([
        dict(BARE_START, params={"kind": "enroll_dep",
                                 "match": {"exclude_devices": ["SER1"]}}), END]))
    check("exclude-only is not treated as empty",
          valid and not start_warns(warnings))
    check("exclude-only still raises its own code",
          len(by_code(fw, "exclude-only-scope")) == 1)

    print("19) unscoped dispatcher rule -> warns it watches everyone")
    flow = flow_doc([SCOPED_START, END])
    valid, _, warnings, _ = run(flow, dispatcher=rule())
    hits = rule_warns(warnings)
    check("unscoped rule warns", valid and len(hits) == 1)
    check("names the rule", hits and "'r1'" in hits[0])
    check("says fleet-wide is normal, not broken",
          hits and "normal choice for a fleet-wide rule" in hits[0])
    valid, _, warnings, _ = run(flow, dispatcher=rule(scope={"groups": ["lab"]}))
    check("a scoped rule stays silent", valid and not rule_warns(warnings))
    valid, _, warnings, _ = run(flow, dispatcher=rule(enabled=False))
    check("a disabled rule stays silent", valid and not rule_warns(warnings))
    # An empty enabled: parses as None. The engine reads enabled off the raw document with a True default and skips the
    # rule, so the warning skips it too; the pydantic field keeps None, which is not False.
    valid, _, warnings, _ = run(flow, dispatcher=rule(enabled=None))
    check("a rule with an empty enabled: stays silent, like the engine",
          valid and not rule_warns(warnings))
    # The other half of the same read. safe_dump writes this as enabled: 'no', a truthy string the engine runs, while
    # the pydantic field coerces it to False, so reading the model would stay quiet about a live rule.
    valid, _, warnings, _ = run(flow, dispatcher=rule(enabled="no"))
    check("a rule with a quoted enabled: 'no' still warns, because it runs",
          valid and len(rule_warns(warnings)) == 1)
    valid, _, warnings, _ = run(
        flow, dispatcher=rule(scope={"exclude_devices": ["SER1"]}))
    check("exclude-only rule is not treated as empty",
          valid and not rule_warns(warnings))

    print("20) the validator's empty test still agrees with both engines")
    # The predicate lives in three files. Rather than hoist it into scoping.py, this asserts the copies agree and fails
    # loudly when they drift. Both engines return True for "matches everyone", which the validator calls empty.
    from controller.utils.yaml_validator import _scope_is_empty
    from controller.services.atc import _scope_matches as atc_matches
    from controller.services.dispatcher import _scope_matches as disp_matches

    class FakeDevice:
        # Every field the scope engine can read has to be present, or a later sample would evaluate False for a missing
        # attribute rather than for a scope that did not match, and the guard would pass for the wrong reason.
        serial_number = "SER-GUARD"
        device_model = "Macmini9,1"
        os_version = "14.0"
        hostname = "guard"
        groups = []
        tags = []
        attributes = {}
        enrollment_date = None
        enrollment_state = "enrolled"
        management_type = "apple_mdm"
        udid = "UDID-GUARD"
        name = "guard"

    # Every non-empty sample below is built not to match this device on its own merits, which is what makes strict
    # equality the right assertion: a True from an engine can then only be its empty-scope shortcut, so drift is caught
    # in both directions.
    samples = [
        None, {}, {"groups": []}, {"conditions": []},
        {"groups": [], "conditions": [], "include_devices": [],
         "exclude_devices": []},
        {"groups": ["nope"]},
        {"exclude_devices": ["SER-GUARD"]},
        {"include_devices": ["SOME-OTHER-SERIAL"]},
        {"conditions": [{"type": "serial_number", "operator": "in",
                         "value": ["SOME-OTHER-SERIAL"]}]},
        {"conditions": [{"type": "tag", "operator": "in",
                         "value": ["not-a-tag-this-device-has"]}]},
    ]
    dev = FakeDevice()
    disagreed = []
    for s in samples:
        empty = _scope_is_empty(s)
        for name, fn in (("atc", atc_matches), ("dispatcher", disp_matches)):
            if fn(dev, [], s) != empty:
                disagreed.append((name, s, f"engine={fn(dev, [], s)} empty={empty}"))
    check("validator emptiness matches atc and dispatcher", not disagreed)
    if disagreed:
        for d in disagreed:
            print(f"     disagreement: {d}")


async def endpoint_checks():
    """The channel to the editor: a dry-run PUT of a config type validates the candidate and returns flow_warnings with
    no write, no history snapshot and no audit row. The real save carries the same flow_warnings."""
    print("21) PUT ?dry_run=true returns warnings and commits nothing")

    base = Path(tempfile.mkdtemp())
    os.environ["YAML_CONFIG_PATH"] = str(base)
    from tortoise import Tortoise
    import controller.api.main as apimain
    from controller.auth.dependencies import Principal
    from controller.models.tenant import AuditLog, Tenant, User

    tdir = base / "tenants" / "t1"
    tdir.mkdir(parents=True)
    (tdir / "config.yaml").write_text(yaml.safe_dump(
        {"tenant": {"id": "t1", "name": "T1", "allowed_users": ["admin@t1"]}}))
    (tdir / "groups.yaml").write_text(yaml.safe_dump({"groups": [
        {"name": "lab",
         "conditions": [{"type": "tag", "operator": "in", "value": ["lab"]}]}]}))
    (tdir / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
    (tdir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": [WIFI]}))

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()
    tenant = await Tenant.create(id="t1", name="T1")
    admin_user = await User.create(tenant=tenant, email="admin@t1", role="admin")
    admin = Principal(tenant=tenant, user=admin_user, email="admin@t1", role="admin")
    # A spy rather than a no-op: dry runs must leave no reconcile behind, and the real save must spawn one.
    reconciles = []
    apimain._spawn_tenant_reconcile = lambda tenant_id: reconciles.append(str(tenant_id))

    doc = {"flow": flow_doc([
        dict(START, params={"kind": "enroll_dep", "match": {}}),
        {"id": "install-wifi", "type": "install_profiles",
         "params": {"profile_ids": ["wifi"]}, "next": "release-1"},
        {"id": "release-1", "type": "release_device", "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])}

    # Always close the sqlite connection: an aiosqlite connection is a non-daemon thread, and one left behind by a stray
    # exception hangs the interpreter at exit instead of failing the suite.
    try:
        res = await apimain.update_yaml_config("flows", dict(doc), admin, dry_run=True)
        check("dry run reports valid with structured flow_warnings",
              res.get("valid") is True
              and any(w["code"] == "release-ordering"
                      for w in res.get("flow_warnings", [])))
        check("dry run writes no flows.yaml", not (tdir / "flows.yaml").exists())
        check("dry run leaves no history snapshot",
              not (tdir / "_history" / "flows").exists())
        check("dry run leaves no audit row", await AuditLog.all().count() == 0)

        bad = {"flow": flow_doc([{"id": "e", "type": "end"}])}
        res = await apimain.update_yaml_config("flows", dict(bad), admin, dry_run=True)
        check("dry run reports errors instead of raising",
              res.get("valid") is False and res.get("errors"))

        # A tenant with no config dir yet: a save scaffolds the dir plus a config.yaml, a dry run touches no disk.
        tenant2 = await Tenant.create(id="t2", name="T2")
        admin2_user = await User.create(tenant=tenant2, email="admin@t2", role="admin")
        admin2 = Principal(tenant=tenant2, user=admin2_user,
                           email="admin@t2", role="admin")
        plain = {"flow": flow_doc([
            dict(START, params={"kind": "enroll_dep", "match": {}}, next="end-1"),
            {"id": "end-1", "type": "end"},
        ])}
        res = await apimain.update_yaml_config("flows", dict(plain), admin2,
                                               dry_run=True)
        check("dry run against a dir-less tenant validates",
              res.get("valid") is True)
        check("dry run scaffolds no tenant dir",
              not (base / "tenants" / "t2").exists())
        check("dry runs spawn no reconcile", reconciles == [])

        res = await apimain.update_yaml_config("flows", dict(doc), admin)
        check("real save succeeds and carries the same flow_warnings",
              "updated" in res.get("message", "")
              and any(w["code"] == "release-ordering"
                      for w in res.get("flow_warnings", [])))
        check("real save writes flows.yaml", (tdir / "flows.yaml").exists())
        check("real save leaves an audit row", await AuditLog.all().count() == 1)
        check("real save spawns exactly one reconcile", reconciles == ["t1"])
    finally:
        await Tortoise.close_connections()


def barrier_checks():
    """code barrier-empty: a live wait_for on a ref-based signal with no producer queuing to it.
    See the doc for details on ref-based signals and gate: false.
    """
    print("22) wait_for with no producer above it -> barrier-empty fires")
    flow = flow_doc([
        dict(START, next="wait-1"),
        {"id": "wait-1", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, warnings, fw = run(flow)
    hits = by_code(fw, "barrier-empty")
    check("save stays valid", valid and not errors)
    check("one barrier-empty, badged on the wait node",
          [w["node_id"] for w in hits] == ["wait-1"])
    check("message says nothing above it installs anything",
          hits and "no step above it installs any" in hits[0]["message"])
    check("message names the step that would fix it",
          hits and "Put an Install profiles step above it" in hits[0]["message"])
    check("the finding mirrors into the plain warnings list",
          all(w["message"] in warnings for w in hits))

    print("23) near miss: install_profiles directly above the wait -> silent")
    flow = flow_doc([
        dict(START),
        {"id": "install-wifi", "type": "install_profiles",
         "params": {"profile_ids": ["wifi"]}, "next": "wait-1"},
        {"id": "wait-1", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, _, fw = run(flow)
    check("the canonical install-then-wait flow raises nothing",
          valid and not errors and not by_code(fw, "barrier-empty"))

    # The three refless signals wait for the next thing the device does and never needed anything queued, so they are
    # absent from _WAIT_PRODUCERS, and the rule stays off the seeded onboarding flow that waits on device_info.
    print("24) near miss: the refless signals with no producer -> silent")
    for signal in ("device_info", "checkin", "ddm_status"):
        flow = flow_doc([
            dict(START, next="wait-1"),
            {"id": "wait-1", "type": "wait_for",
             "params": {"signal": signal, "timeout_minutes": 30},
             "next": "end-1"},
            {"id": "end-1", "type": "end"},
        ])
        valid, errors, _, fw = run(flow)
        check(f"wait on {signal} raises nothing",
              valid and not errors and not by_code(fw, "barrier-empty"))

    # The catalog help for the wait's own gate param offers it as the way to allow a wait that finds nothing waiting, so
    # the rule honours it as the sanctioned opt-out.
    print("25) near miss: the wait carries gate: false -> silent (opted out)")
    flow = flow_doc([
        dict(START, next="wait-1"),
        {"id": "wait-1", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30,
                    "gate": False},
         "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, _, fw = run(flow)
    check("an opted-out wait raises nothing",
          valid and not errors and not by_code(fw, "barrier-empty"))

    print("26) producer above the wait but with its gate off -> barrier-empty fires")
    flow = flow_doc([
        dict(START),
        {"id": "install-wifi", "type": "install_profiles",
         "params": {"profile_ids": ["wifi"], "gate": False}, "next": "wait-1"},
        {"id": "wait-1", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, _, fw = run(flow)
    hits = by_code(fw, "barrier-empty")
    check("save stays valid", valid and not errors)
    check("one barrier-empty, badged on the wait node",
          [w["node_id"] for w in hits] == ["wait-1"])
    check("message names the ungated producer and the param",
          hits and '"install-wifi"' in hits[0]["message"]
          and "gate: false" in hits[0]["message"])

    print("27) a second wait on the same signal -> barrier-empty fires on the second one")
    flow = flow_doc([
        dict(START),
        {"id": "install-wifi", "type": "install_profiles",
         "params": {"profile_ids": ["wifi"]}, "next": "wait-1"},
        {"id": "wait-1", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "next": "wait-2"},
        {"id": "wait-2", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, _, fw = run(flow)
    hits = by_code(fw, "barrier-empty")
    check("save stays valid", valid and not errors)
    check("only the second wait warns", [w["node_id"] for w in hits] == ["wait-2"])
    check("message names the earlier wait that took the list",
          hits and '"wait-1"' in hits[0]["message"]
          and "already waited for the same thing" in hits[0]["message"])

    print("27b) near miss: a producer between the two waits -> silent")
    flow = flow_doc([
        dict(START),
        {"id": "install-wifi", "type": "install_profiles",
         "params": {"profile_ids": ["wifi"]}, "next": "wait-1"},
        {"id": "wait-1", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "next": "install-2"},
        {"id": "install-2", "type": "install_profiles",
         "params": {"profile_ids": ["wifi"]}, "next": "wait-2"},
        {"id": "wait-2", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, _, fw = run(flow)
    check("a refilled list between two waits raises nothing",
          valid and not errors and not by_code(fw, "barrier-empty"))

    # Deliberately unsound but quiet: a run taking on_false really does reach an empty barrier, but catching that needs
    # a producer on every path, which is dominator analysis this validator does not attempt. The runtime guard covers
    # the half that ends in a release. Do not turn this into a warning.
    print("28) near miss: producer on one branch only -> silent by design")
    flow = flow_doc([
        dict(START, next="br"),
        {"id": "br", "type": "branch",
         "params": {"condition": {"type": "platform", "operator": "in",
                                  "value": ["Mac"]}},
         "on_true": "install-wifi", "on_false": "wait-1"},
        {"id": "install-wifi", "type": "install_profiles",
         "params": {"profile_ids": ["wifi"]}, "next": "wait-1"},
        {"id": "wait-1", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, _, fw = run(flow)
    check("a producer on one branch of a join raises nothing",
          valid and not errors and not by_code(fw, "barrier-empty"))

    print("29) the producer has to match the signal")
    flow = flow_doc([
        dict(START, next="install-apps-1"),
        {"id": "install-apps-1", "type": "install_apps",
         "params": {"app_ids": ["pages"]}, "next": "wait-1"},
        {"id": "wait-1", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, _, fw = run(flow)
    hits = by_code(fw, "barrier-empty")
    check("an app install does not feed a profile barrier",
          valid and not errors and [w["node_id"] for w in hits] == ["wait-1"])
    # refresh_info is a real non-destructive catalog command with no required params; DeviceInformation is not a catalog
    # type and would hard-error.
    print("29b) near miss: send_command above a command_ack wait -> silent")
    flow = flow_doc([
        dict(START, next="cmd-1"),
        {"id": "cmd-1", "type": "send_command",
         "params": {"command": "refresh_info"}, "next": "wait-1"},
        {"id": "wait-1", "type": "wait_for",
         "params": {"signal": "command_ack", "timeout_minutes": 30},
         "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, _, fw = run(flow)
    check("a command above its acknowledgement wait raises nothing",
          valid and not errors and not by_code(fw, "barrier-empty"))

    print("29c) declaration_applied with no sync_declarations above it -> barrier-empty fires")
    flow = flow_doc([
        dict(START, next="wait-1"),
        {"id": "wait-1", "type": "wait_for",
         "params": {"signal": "declaration_applied", "timeout_minutes": 30},
         "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, _, fw = run(flow)
    hits = by_code(fw, "barrier-empty")
    check("the fourth signal warns too",
          valid and not errors and [w["node_id"] for w in hits] == ["wait-1"])
    check("the message uses that signal's wording",
          hits and "declarations to be applied" in hits[0]["message"]
          and "no step above it syncs any" in hits[0]["message"])

    # A timeout edge is a real edge: a run that times out at wait-0 arrives at wait-1 with the profile list intact, so
    # the barrier is not empty on every run and the rule stays quiet.
    print("30) near miss: the producer reaches the wait along on_timeout -> silent")
    flow = flow_doc([
        dict(START),
        {"id": "install-wifi", "type": "install_profiles",
         "params": {"profile_ids": ["wifi"]}, "next": "wait-0"},
        {"id": "wait-0", "type": "wait_for",
         "params": {"signal": "device_info", "timeout_minutes": 30},
         "next": "end-1", "on_timeout": "wait-1"},
        {"id": "wait-1", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, _, fw = run(flow)
    check("a producer reaching the wait by the timeout edge raises nothing",
          valid and not errors and not by_code(fw, "barrier-empty"))


def accounts_after_release_checks():
    """code accounts-after-release: configure_accounts steps after release_device are ineffective.
    """
    print("31) configure_accounts below a release -> accounts-after-release fires")
    flow = flow_doc([
        dict(START, next="rel"),
        {"id": "rel", "type": "release_device", "next": "acc"},
        {"id": "acc", "type": "configure_accounts",
         "params": {"primary_account": "prompt_admin"}, "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, _, fw = run(flow)
    hits = by_code(fw, "accounts-after-release")
    check("save stays valid", valid and not errors)
    check("badge sits on the accounts node, which is the node to move",
          [w["node_id"] for w in hits] == ["acc"])
    check("message names both nodes",
          hits and '"acc"' in hits[0]["message"] and '"rel"' in hits[0]["message"])
    # This tenant's profiles are the default [WIFI], so no DEP profile exists and release-without-await stays out of the
    # way of the accounts-after-release assertion above.
    check("no DEP profile means no release-without-await here",
          not by_code(fw, "release-without-await"))

    print("32a) near miss: accounts above the release -> silent")
    flow = flow_doc([
        dict(START, next="acc"),
        {"id": "acc", "type": "configure_accounts",
         "params": {"primary_account": "prompt_admin"}, "next": "rel"},
        {"id": "rel", "type": "release_device", "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, _, fw = run(flow)
    check("the canonical Mac onboarding order raises nothing",
          valid and not errors and not by_code(fw, "accounts-after-release"))

    print("32b) near miss: accounts on a sibling branch of the release -> silent")
    flow = flow_doc([
        dict(START, next="br"),
        {"id": "br", "type": "branch",
         "params": {"condition": {"type": "platform", "operator": "in",
                                  "value": ["Mac"]}},
         "on_true": "acc", "on_false": "rel"},
        {"id": "acc", "type": "configure_accounts",
         "params": {"primary_account": "prompt_admin"}, "next": "end-1"},
        {"id": "rel", "type": "release_device", "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, _, fw = run(flow)
    check("a sibling branch is not below the release",
          valid and not errors and not by_code(fw, "accounts-after-release"))

    # An unreachable subgraph already draws the plain unreachable warning; a second finding for the same dead nodes is
    # noise on the badge channel.
    print("32c) near miss: accounts under a release no start reaches -> silent")
    flow = flow_doc([
        dict(START, next="end-1"),
        {"id": "end-1", "type": "end"},
        {"id": "rel", "type": "release_device", "next": "acc"},
        {"id": "acc", "type": "configure_accounts",
         "params": {"primary_account": "prompt_admin"}, "next": "end-1"},
    ])
    valid, errors, warnings, fw = run(flow)
    check("a dead release subgraph raises nothing on the badge channel",
          valid and not errors and not by_code(fw, "accounts-after-release"))
    check("the dead nodes still draw the plain unreachable warning",
          any("'rel' is unreachable" in w for w in warnings))


def release_without_await_checks():
    """code release-without-await: a release node when no DEP profile awaits configuration.
    """
    rel_flow = flow_doc([
        dict(START, next="rel"),
        {"id": "rel", "type": "release_device", "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])

    print("33) release step, no DEP profile awaits -> release-without-await fires")
    valid, errors, warnings, fw = run(rel_flow, profiles=[WIFI, DEP_NO_AWAIT])
    hits = by_code(fw, "release-without-await")
    check("save stays valid", valid and not errors)
    check("one release-without-await, badged on the release node",
          [w["node_id"] for w in hits] == ["rel"])
    check("message names the setting an admin has to turn on",
          hits and "await_device_configured" in hits[0]["message"]
          and "Await final configuration" in hits[0]["message"])
    check("dep-await-no-release and release-without-await never both fire on one document",
          not by_code(fw, "dep-await-no-release"))
    check("the finding mirrors into the plain warnings list",
          all(w["message"] in warnings for w in hits))

    print("34a) near miss: a DEP profile awaiting under payload: -> silent")
    valid, errors, _, fw = run(rel_flow, profiles=[WIFI, DEP_PAYLOAD])
    check("an awaiting payload: profile raises nothing",
          valid and not errors and not by_code(fw, "release-without-await"))

    # The one case in this bundle that must never regress. dep_manager._build_apple_profile reads payload or enrollment,
    # so a profile authored with enrollment: really does set await_device_configured at Apple, and a validator reading
    # only payload would warn on the tenant whose configuration is correct.
    print("34b) near miss: a DEP profile awaiting under the enrollment: alias -> silent")
    valid, errors, _, fw = run(rel_flow, profiles=[WIFI, DEP_ALIAS])
    check("an awaiting enrollment: profile raises nothing",
          valid and not errors and not by_code(fw, "release-without-await"))
    # The alias tenant is correct end to end here: it awaits and it releases, so dep-await-no-release has nothing to say
    # either and the whole channel should be empty.
    check("the alias tenant's correct flow raises nothing at all", fw == [])

    # Deliberate silence: enrollment profiles may live outside Micromanage, in which case devices really are held and
    # the release step is needed. The validator cannot tell that from a decorative release step.
    print("34c) near miss: no DEP profile at all -> silent")
    valid, errors, _, fw = run(rel_flow, profiles=[WIFI])
    check("a tenant with no enrollment profile raises nothing",
          valid and not errors and not by_code(fw, "release-without-await"))

    print("34d) near miss: no release node -> silent")
    flow = flow_doc([
        dict(START, next="end-1"),
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, _, fw = run(flow, profiles=[WIFI, DEP_NO_AWAIT])
    check("a flow that never releases raises nothing",
          valid and not errors and not by_code(fw, "release-without-await"))

    print("34e) near miss: a release node no start reaches -> silent")
    flow = flow_doc([
        dict(START, next="end-1"),
        {"id": "end-1", "type": "end"},
        {"id": "rel", "type": "release_device", "next": "end-1"},
    ])
    valid, errors, warnings, fw = run(flow, profiles=[WIFI, DEP_NO_AWAIT])
    check("a dead release node raises nothing on the badge channel",
          valid and not errors and not by_code(fw, "release-without-await"))
    check("the dead node still draws the plain unreachable warning",
          any("'rel' is unreachable" in w for w in warnings))

    print("34f) a bare type: enrollment profile with no settings -> release-without-await fires")
    bare = {"id": "ade-bare", "name": "Bare enrollment", "type": "enrollment"}
    valid, errors, _, fw = run(rel_flow, profiles=[WIFI, bare])
    hits = by_code(fw, "release-without-await")
    check("an enrollment profile that sets nothing does not await",
          valid and not errors and [w["node_id"] for w in hits] == ["rel"])


def bundle_quiet_checks():
    """The flow the product documents, and the one real tenant on disk. A rule that warns on either is wrong."""
    print("35) the documented onboarding flow -> the whole channel is silent")
    flow = flow_doc([
        dict(START),
        {"id": "install-wifi", "type": "install_profiles",
         "params": {"profile_ids": ["wifi"]}, "next": "wait-1"},
        {"id": "wait-1", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "next": "acc"},
        {"id": "acc", "type": "configure_accounts",
         "params": {"primary_account": "prompt_admin"}, "next": "rel"},
        {"id": "rel", "type": "release_device", "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    valid, errors, _, fw = run(flow, profiles=[WIFI, DEP_PAYLOAD])
    check("save stays valid", valid and not errors)
    check("a correct install, wait, accounts, release flow raises nothing", fw == [])
    for w in fw:
        print(f"     unexpected: [{w['code']}] on {w['node_id']}: {w['message']}")

    print("36) the seeded default tenant still validates with no flow warnings")
    seeded = SEEDED_TENANT
    v = YAMLValidator(seeded)
    valid, errors, warnings = v.validate_all()
    check("the seeded tenant is on disk and validates",
          seeded.is_dir() and valid and not errors)
    check("the seeded tenant raises no flow warnings at all", v.flow_warnings == [])
    for w in v.flow_warnings:
        print(f"     unexpected: [{w['code']}] on {w['node_id']}: {w['message']}")


def parked_warns(warnings):
    return [w for w in warnings if "flow_parked_for" in w]


def parked_check_warning_checks():
    """The flow_parked_for check needs an hours threshold and does nothing at all without one, so a rule saved without
    one is told so. A warning rather than an error, like everything else here."""
    flow = flow_doc([SCOPED_START, END])

    print("37) flow_parked_for with no threshold -> warns that it never fires")
    valid, errors, warnings, _ = run(
        flow, dispatcher=rule(check={"type": "flow_parked_for"}))
    hits = parked_warns(warnings)
    check("a check with no hours warns", len(hits) == 1)
    check("the save still succeeds, so no tenant is locked out",
          valid and not errors)
    check("the warning names the rule", hits and "'r1'" in hits[0])
    check("the warning says what to do about it",
          hits and "Set 'hours'" in hits[0])

    print("37b) a threshold the engine accepts -> silent")
    valid, errors, warnings, _ = run(
        flow, dispatcher=rule(check={"type": "flow_parked_for", "hours": 4}))
    check("hours: 4 saves clean and silent",
          valid and not errors and not parked_warns(warnings))
    # The evaluator parses with float(), so a quoted number really does work and warning about it would be wrong. The
    # validator uses the same expression, which keeps the two from drifting.
    valid, _, warnings, _ = run(
        flow, dispatcher=rule(check={"type": "flow_parked_for", "hours": "4"}))
    check("a quoted number stays silent, because the engine accepts it",
          valid and not parked_warns(warnings))
    # Inputs may sit under params: or flat beside type:, and evaluate_check resolves both the same way.
    valid, _, warnings, _ = run(flow, dispatcher=rule(
        check={"type": "flow_parked_for", "params": {"hours": 4}}))
    check("the params: wrapper style stays silent too",
          valid and not parked_warns(warnings))

    print("37c) near miss: unreadable threshold, and other checks are left alone")
    valid, _, warnings, _ = run(
        flow, dispatcher=rule(check={"type": "flow_parked_for", "hours": "soon"}))
    check("hours that cannot be read as a number warns",
          valid and len(parked_warns(warnings)) == 1)
    valid, _, warnings, _ = run(
        flow, dispatcher=rule(check={"type": "filevault_disabled"}))
    check("a check of another type never draws this warning",
          valid and not parked_warns(warnings))

    print("37d) a disabled rule stays silent, read the way the engine reads it")
    # Same three cases as section 19: what a rule that never runs would have done is not news, and enabled has to be
    # read off the raw document rather than off the pydantic model, because the two disagree in both directions.
    broken = {"type": "flow_parked_for"}
    valid, _, warnings, _ = run(
        flow, dispatcher=rule(check=broken, enabled=False))
    check("a disabled rule draws no warning", valid and not parked_warns(warnings))
    # An empty enabled: parses as None. The model keeps None, the engine treats it as off, so the warning skips it.
    valid, _, warnings, _ = run(
        flow, dispatcher=rule(check=broken, enabled=None))
    check("an empty enabled: stays silent, like the engine",
          valid and not parked_warns(warnings))
    # The other half of the same read. safe_dump writes enabled: 'no', a truthy string the engine runs, while the
    # pydantic field coerces it to False.
    valid, _, warnings, _ = run(
        flow, dispatcher=rule(check=broken, enabled="no"))
    check("a quoted enabled: 'no' still warns, because the rule runs",
          valid and len(parked_warns(warnings)) == 1)


def payload_warns(warnings):
    return [w for w in warnings if "is not a payload type" in w]


def profile_with(payload_type, **over):
    """A configuration profile carrying one payload of the given type."""
    doc = {"id": "p1", "name": "P1", "type": "configuration", "groups": ["lab"],
           "payload": {"PayloadType": payload_type, "PayloadDisplayName": "P1"}}
    doc.update(over)
    return doc


def payload_type_warning_checks():
    """A PayloadType Apple does not document is a warning, not an error.
    See the doc for why typos look like working deployments.
    """
    flow = flow_doc([SCOPED_START, END])

    print("38) a com.apple.* PayloadType Apple does not document -> warns")
    valid, errors, warnings, _ = run(
        flow, profiles=[profile_with("com.apple.dok")])
    hits = payload_warns(warnings)
    check("an undocumented Apple payload type warns", len(hits) == 1)
    check("the save still succeeds, so no tenant is locked out", valid and not errors)
    check("the warning names the profile and the type it read",
          hits and "'p1'" in hits[0] and "'com.apple.dok'" in hits[0])
    check("the warning explains why the deployment will look successful",
          hits and "report the profile installed" in hits[0])
    check("the warning claims no platform and no outcome it cannot know",
          hits and "macOS" not in hits[0] and "does nothing" not in hits[0])
    for typo in ("com.apple.dcok", "com.apple.wifi.manged", "com.apple.Dock"):
        _, _, warnings, _ = run(flow, profiles=[profile_with(typo)])
        check(f"{typo} still warns", len(payload_warns(warnings)) == 1)

    print("38a) near miss: payload types the product ships a manifest for -> silent")
    # com.apple.SubmitDiagInfo is the one the editor has a form for that Apple's profile schemas never described.
    for known in ("com.apple.wifi.managed", "com.apple.mobiledevice.passwordpolicy",
                  "com.apple.dock", "com.apple.MCX.FileVault2",
                  "com.apple.security.FDERecoveryKeyEscrow",
                  "com.apple.SubmitDiagInfo"):
        _, _, warnings, _ = run(flow, profiles=[profile_with(known)])
        check(f"{known} draws no warning", not payload_warns(warnings))

    print("38b) near miss: Apple types with no generated manifest -> silent")
    # Apple documents all of these and admins author them, but the manifest generator produces no editor form for any of
    # them, so the Apple schema set is the only thing between them and a false warning.
    for extra in ("com.apple.ManagedClient.preferences", "com.apple.vpn.managed",
                  "com.apple.homescreenlayout", "com.apple.vpn.managed.applayer",
                  "com.apple.vpn.managed.appmapping", "com.apple.apn.managed",
                  "com.apple.security.certificaterevocation",
                  "com.apple.security.identitypreference",
                  "com.apple.systempolicy.rule", "com.apple.preference.users",
                  "com.apple.mcxMenuExtras"):
        _, _, warnings, _ = run(flow, profiles=[profile_with(extra)])
        check(f"{extra} draws no warning", not payload_warns(warnings))

    print("38c) near miss: a third-party payload type -> silent")
    for vendor in ("com.microsoft.office", "io.zoom.config", "net.tunnelblick.vpn"):
        _, _, warnings, _ = run(flow, profiles=[profile_with(vendor)])
        check(f"{vendor} draws no warning", not payload_warns(warnings))

    print("38d) a missing PayloadType is still the error it always was")
    valid, errors, warnings, _ = run(
        flow, profiles=[{"id": "p1", "name": "P1", "type": "configuration",
                         "groups": ["lab"], "payload": {"PayloadDisplayName": "P1"}}])
    check("no type at all is an error, not a warning",
          not valid and any("missing 'PayloadType'" in e for e in errors))
    check("and it is not also warned about, which would say it twice",
          not payload_warns(warnings))

    print("38e) each payload in a multi-payload profile is judged on its own")
    valid, _, warnings, _ = run(flow, profiles=[
        {"id": "p1", "name": "P1", "type": "configuration", "groups": ["lab"],
         "payloads": [{"PayloadType": "com.apple.wifi.managed", "SSID_STR": "CorpNet"},
                      {"PayloadType": "com.apple.dok"},
                      {"PayloadType": "com.apple.dcok"}]}])
    hits = payload_warns(warnings)
    check("two bad types among three payloads -> two warnings", valid and len(hits) == 2)
    check("each warning points at the payload it came from",
          len(hits) == 2 and "payload 2" in hits[0] and "payload 3" in hits[1])

    print("38f) DEP / enrollment profiles carry a different document -> silent")
    # payload here is a DEP profile document, not a mobileconfig payload, so it has no PayloadType and must not be
    # judged as though it should.
    _, _, warnings, _ = run(flow, profiles=[
        {"id": "ade", "name": "ADE", "dep_profile": True,
         "payload": {"await_device_configured": True}}])
    check("a DEP profile draws no payload-type warning", not payload_warns(warnings))

    print("38g) the seeded default tenant draws no payload-type warning")
    seeded = SEEDED_TENANT
    valid, errors, warnings = YAMLValidator(seeded).validate_all()
    check("the tenant shipped with the product stays quiet",
          seeded.is_dir() and valid and not payload_warns(warnings))

    print("38h) the server's copies of the payload domains and data keys still match")
    # The server must not read anything out of webui at runtime, so controller/utils/payload_types.py holds a copy of
    # the domains in webui/lib/manifests.generated.json. Reading the JSON here keeps the copy honest: rebuild the
    # manifests without regenerating the set and the validator starts warning about types the editor offers.
    manifests = (Path(__file__).resolve().parents[1] / "webui" / "lib"
                 / "manifests.generated.json")
    check("the generated manifests are on disk", manifests.is_file())
    if manifests.is_file():
        domains = {entry["domain"] for entry in json.loads(manifests.read_text())}
        check("every domain the editor offers is a type the validator accepts",
              domains == payload_types._MANIFEST_PAYLOAD_TYPES)
        missing = sorted(domains - payload_types._MANIFEST_PAYLOAD_TYPES)
        extra = sorted(payload_types._MANIFEST_PAYLOAD_TYPES - domains)
        for d in missing:
            print(f"     missing from controller/utils/payload_types.py: {d}")
        for d in extra:
            print(f"     no longer in the manifests: {d}")

    # The data keys are copied the same way and matter more: a missing entry means a certificate payload reaches the
    # device as <string> and fails to install with ConfigProfilePluginDomain -50. They live in their own artifact
    # because the scan behind them reads sources the editor's form catalog does not.
    keys_json = (Path(__file__).resolve().parents[1] / "webui" / "lib"
                 / "data-keys.generated.json")
    check("the generated data keys are on disk", keys_json.is_file())
    if keys_json.is_file():
        generated = json.loads(keys_json.read_text())
        gen_keys = {d: set(v["keys"]) for d, v in generated.items()}
        server_keys = {k: set(v) for k, v in payload_types.DATA_PAYLOAD_KEYS.items()}
        check("every generated data key is one profile_manager decodes to bytes",
              gen_keys == server_keys)
        for d in sorted(set(gen_keys) ^ set(server_keys)):
            print(f"     data key drift for {d}: generated {sorted(gen_keys.get(d, []))} "
                  f"vs server {sorted(server_keys.get(d, []))}")

        gen_containers = {d: set(v["containers"]) for d, v in generated.items()
                          if v["containers"]}
        server_containers = {k: set(v)
                             for k, v in payload_types.DATA_PAYLOAD_CONTAINERS.items()}
        check("the container half of the copy matches too",
              gen_containers == server_containers)
        for d in sorted(set(gen_containers) ^ set(server_containers)):
            print(f"     container drift for {d}: "
                  f"generated {sorted(gen_containers.get(d, []))} "
                  f"vs server {sorted(server_containers.get(d, []))}")

        # A fixed list of Apple payload types could not describe a third-party payload at all.
        check("the table reaches past Apple's own payload types",
              any(not d.startswith("com.apple.") for d in server_keys))
        check("a data key authored inside a container is in the table",
              "CAFingerprint" in server_keys.get("com.apple.security.scep", set()))
        # A <data> value whose content is text must never be decoded as base64.
        check("a key whose manifest calls the content text stays out",
              "SharedSecret" not in server_keys.get("com.apple.vpn.managed", set())
              and "filedata" not in server_keys.get("com.apple.mcxloginscripts", set()))

    print("38i) the two sets are what the check reads, and neither is redundant")
    # The manifest set alone false-warns on the eleven types in 38b, and the Apple set alone drops the types the editor
    # has a form for that Apple's schema directory never described.
    apple = payload_types._APPLE_DOCUMENTED_PAYLOAD_TYPES
    manifest = payload_types._MANIFEST_PAYLOAD_TYPES
    check("the Apple set covers types the manifests do not", bool(apple - manifest))
    check("the manifests cover types Apple's profile schemas do not",
          bool({m for m in manifest if m.startswith("com.apple.")} - apple))
    check("the check reads the union of both",
          payload_types.KNOWN_PAYLOAD_TYPES == apple | manifest)
    check("every Apple entry is in Apple's own namespace",
          all(a.startswith("com.apple.") for a in apple))

    # ==39. Legacy-bridge declarations and the payload types Apple forbids==
    #
    # A com.apple.configuration.legacy declaration hands the device a URL for an existing profile. Apple forbids
    # com.apple.mdm and com.apple.declarations inside one:
    # https://raw.githubusercontent.com/apple/device-management/release/declarative/declarations/configurations/legacy.yaml
    # An error rather than a warning: the device refuses the download, and retrying at the device end cannot help.
    def bridge(profile_id):
        return {"declarations": [{"id": "bridged", "type": "com.apple.configuration.legacy",
                                  "groups": ["lab"], "profile": profile_id}]}

    def forbidden_profile(profile_id, ptype):
        return {"id": profile_id, "name": profile_id, "type": "configuration",
                "groups": ["lab"],
                "payloads": [{"PayloadType": ptype, "PayloadDisplayName": "X"}]}

    print("\n39) bridging a profile carrying com.apple.mdm -> hard error")
    valid, errors, warnings, fw = run(
        None, profiles=[forbidden_profile("mdm-profile", "com.apple.mdm")],
        declarations=bridge("mdm-profile"))
    check("config rejected", not valid)
    check("the error names the declaration, the profile and the payload type",
          any("bridged" in e and "mdm-profile" in e and "com.apple.mdm" in e
              for e in errors))

    print("39a) com.apple.declarations is forbidden the same way")
    valid, errors, warnings, fw = run(
        None, profiles=[forbidden_profile("decl-profile", "com.apple.declarations")],
        declarations=bridge("decl-profile"))
    check("config rejected", not valid)
    check("the error names com.apple.declarations",
          any("com.apple.declarations" in e for e in errors))

    print("39b) one forbidden payload among several is still caught")
    mixed = {"id": "mixed", "name": "mixed", "type": "configuration", "groups": ["lab"],
             "payloads": [WIFI["payload"],
                          {"PayloadType": "com.apple.mdm", "PayloadDisplayName": "X"}]}
    valid, errors, warnings, fw = run(None, profiles=[mixed],
                                      declarations=bridge("mixed"))
    check("config rejected", not valid)
    check("the error names the forbidden type, not the Wi-Fi payload beside it",
          any("com.apple.mdm" in e and "com.apple.wifi.managed" not in e
              for e in errors))

    print("39c) near miss: an ordinary profile bridges fine")
    valid, errors, warnings, fw = run(None, profiles=[WIFI], declarations=bridge("wifi"))
    check("config accepted", valid)
    check("nothing said about payload types in the bridge",
          not any("legacy" in e or "bridges profile" in e for e in errors))

    print("39d) near miss: a forbidden payload on a profile nobody bridges is left alone")
    valid, errors, warnings, fw = run(
        None, profiles=[WIFI, forbidden_profile("mdm-profile", "com.apple.mdm")],
        declarations=bridge("wifi"))
    check("config accepted", valid)
    check("no bridge error", not any("bridges profile" in e for e in errors))

    print("39e) the payload check follows the type that consumes the profile")
    # ddm_manager reads profile under com.apple.configuration.legacy and nowhere else, so the same key on another
    # declaration type never reaches a device. The model refuses it there first, rather than reporting a bridged payload
    # the device was never going to see.
    inert = {"declarations": [{"id": "inert", "type": "com.apple.configuration.passcode.settings",
                               "groups": ["lab"], "profile": "mdm-profile",
                               "payload": {"RequirePasscode": True}}]}
    valid, errors, warnings, fw = run(
        None, profiles=[WIFI, forbidden_profile("mdm-profile", "com.apple.mdm")],
        declarations=inert)
    check("the key is refused where it does nothing",
          not valid and any("only valid with type com.apple.configuration.legacy" in e
                            for e in errors))
    check("and the forbidden payload type is not what it is blamed on",
          not any("com.apple.mdm" in e for e in errors))

    # ==39f. Software update enforcement declaration sanity checks==
    #
    # com.apple.configuration.softwareupdate.enforcement.specific enforces one OS version by a deadline. Apple marks
    # TargetOSVersion and TargetLocalDateTime required, and TargetLocalDateTime is a local time with no timezone suffix:
    # https://raw.githubusercontent.com/apple/device-management/release/declarative/declarations/configurations/softwareupdate.enforcement.specific.yaml
    # Warnings rather than errors, because Apple's declaration schemas move and a per-type check that hard-failed a save
    # would age badly.
    def enforce(payload):
        return {"declarations": [{
            "id": "os-enforce", "type":
                "com.apple.configuration.softwareupdate.enforcement.specific",
            "groups": ["lab"], "payload": payload}]}

    print("\n39f) a complete enforcement declaration saves clean")
    valid, errors, warnings, fw = run(None, declarations=enforce(
        {"TargetOSVersion": "15.6.1", "TargetLocalDateTime": "2026-09-01T09:00:00"}))
    check("config accepted", valid and not errors)
    check("nothing warned about the enforcement declaration",
          not any("os-enforce" in w for w in warnings))

    print("39f-i) a missing required key warns, still saves")
    valid, errors, warnings, fw = run(None, declarations=enforce(
        {"TargetOSVersion": "15.6.1"}))
    check("config still saves (a warning, not a block)", valid and not errors)
    check("the warning names the missing TargetLocalDateTime",
          any("os-enforce" in w and "TargetLocalDateTime" in w for w in warnings))

    print("39f-ii) a TargetLocalDateTime carrying a timezone suffix warns")
    valid, errors, warnings, fw = run(None, declarations=enforce(
        {"TargetOSVersion": "15.6.1", "TargetLocalDateTime": "2026-09-01T09:00:00Z"}))
    check("config still saves", valid and not errors)
    check("the warning says the value must be local time with no timezone",
          any("os-enforce" in w and "local time" in w for w in warnings))

    print("39f-iii) an UNQUOTED TargetLocalDateTime is named as a quoting mistake")
    # YAML resolves an unquoted 2026-09-01T10:00:00 to a datetime, which json.dumps cannot serialize, so the declaration
    # GET 500s on every sync and the device loops. The serve path normalizes it anyway, so this stays a warning. Written
    # through yaml.safe_dump from a real datetime so the round trip is the author's.
    from datetime import datetime as _dt

    valid, errors, warnings, fw = run(None, declarations=enforce(
        {"TargetOSVersion": "15.6.1",
         "TargetLocalDateTime": _dt(2026, 9, 1, 10, 0, 0)}))
    check("config still saves", valid and not errors)
    check("the warning names the key and says to quote it",
          any("os-enforce" in w and "TargetLocalDateTime" in w and "uote" in w
              for w in warnings))
    check("the old timezone-suffix warning is not also fired at it",
          not any("os-enforce" in w and "local time" in w for w in warnings))

    print("39f-iv) a nested unquoted timestamp is found too, quoted ones are left alone")
    valid, errors, warnings, fw = run(None, declarations={"declarations": [{
        "id": "nested", "type": "com.apple.configuration.passcode.settings",
        "groups": ["lab"],
        "payload": {"Window": {"Deadlines": [{"At": _dt(2026, 9, 1, 10, 0, 0)}]}}}]})
    check("config still saves", valid and not errors)
    check("the warning names the path to the leaf",
          any("nested" in w and "Window.Deadlines[0].At" in w for w in warnings))

    valid, errors, warnings, fw = run(None, declarations=enforce(
        {"TargetOSVersion": "15.6.1", "TargetLocalDateTime": "2026-09-01T10:00:00"}))
    check("a properly quoted timestamp warns about nothing",
          valid and not any("os-enforce" in w for w in warnings))

    # ==39g. The declaration ids the server serves on its own==
    #
    # ddm_manager emits mm.cfg.status-subscriptions and mm.act.status-subscriptions itself, off the top-level
    # status_subscriptions list. An authored item with that id becomes a second Identifier of the same name carrying a
    # different ServerToken, and the device cannot tell which one it is being asked for.
    print("\n39g) the reserved status-subscriptions declaration id is refused")
    valid, errors, warnings, fw = run(None, declarations={"declarations": [{
        "id": "status-subscriptions",
        "type": "com.apple.configuration.passcode.settings",
        "groups": ["lab"], "payload": {"RequirePasscode": True}}]})
    check("config rejected", not valid)
    check("the error names the collision and the list to use instead",
          any("status-subscriptions" in e and "mm.cfg.status-subscriptions" in e
              and "status_subscriptions" in e for e in errors))

    print("39g-i) near miss: an id that merely contains it is fine")
    valid, errors, warnings, fw = run(None, declarations={"declarations": [{
        "id": "my-status-subscriptions",
        "type": "com.apple.configuration.passcode.settings",
        "groups": ["lab"], "payload": {"RequirePasscode": True}}]})
    check("config accepted", valid and not errors)

    print("39g-ii) the type-level refusal still stands on its own")
    valid, errors, warnings, fw = run(None, declarations={"declarations": [{
        "id": "subs", "type": "com.apple.configuration.management.status-subscriptions",
        "groups": ["lab"], "payload": {"StatusItems": []}}]})
    check("config rejected", not valid)
    check("the error points at the top-level list",
          any("auto-managed" in e and "status_subscriptions" in e for e in errors))

    # ==39h. A scope carrying an absurd number of conditions==
    #
    # Every condition is evaluated synchronously for every device on every pass, and a regex one can spend
    # GROUP_REGEX_TIMEOUT before giving up. Nothing caps the count at evaluate time, since a scope that silently stopped
    # matching would pull profiles back off devices, so the author is told at save time.
    print("\n39h) a scope with more conditions than scoping is sized for warns")
    from controller.services.scoping import MAX_SCOPE_CONDITIONS

    many = [{"type": "hostname", "operator": "regex", "value": f"^host-{i}"}
            for i in range(MAX_SCOPE_CONDITIONS + 1)]
    valid, errors, warnings, fw = run(None, declarations={"declarations": [{
        "id": "wide", "type": "com.apple.configuration.passcode.settings",
        "conditions": many, "payload": {"RequirePasscode": True}}]})
    check("config still saves (a warning, not a block)", valid and not errors)
    check("the warning names the declaration and the count",
          any("wide" in w and str(len(many)) in w for w in warnings))

    print("39h-i) near miss: a scope at the ceiling says nothing")
    valid, errors, warnings, fw = run(None, declarations={"declarations": [{
        "id": "atmax", "type": "com.apple.configuration.passcode.settings",
        "conditions": many[:MAX_SCOPE_CONDITIONS],
        "payload": {"RequirePasscode": True}}]})
    check("config accepted with no condition-count warning",
          valid and not any("conditions, over the" in w for w in warnings))

    # ==39i. iOS platform lists after the watchOS/visionOS split==
    #
    # 'iOS' is no longer the fallback platform for every non-Mac, non-TV model, so platforms: ['iOS'] no longer reaches
    # watches or Vision Pro. The validator says so once per document rather than once per item.
    print("\n39i) platforms: ['iOS'] without watchOS/visionOS warns once per document")
    ios_a = dict(WIFI, id="wifi-ios", platforms=["iOS"])
    ios_b = dict(WIFI, id="vpn-ios", name="VPN", platforms=["iOS", "macOS"])
    valid, errors, warnings, fw = run(None, profiles=[ios_a, ios_b])
    hits = [w for w in warnings if "profiles.yaml" in w and "watchOS" in w]
    check("config still saves (a warning, not a block)", valid and not errors)
    check("exactly one warning for the whole document", len(hits) == 1)
    check("it names both flagged profiles",
          hits and "wifi-ios" in hits[0] and "vpn-ios" in hits[0])

    print("39i-i) near miss: a list that already includes watchOS says nothing")
    covered = dict(WIFI, id="wifi-watch", platforms=["iOS", "watchOS"])
    valid, errors, warnings, fw = run(None, profiles=[covered])
    check("no split warning",
          valid and not any("without watchOS or visionOS" in w for w in warnings))

    print("39i-ii) declarations get the same warning, and the new values validate")
    valid, errors, warnings, fw = run(None, declarations={"declarations": [
        {"id": "pass-ios", "type": "com.apple.configuration.passcode.settings",
         "groups": ["lab"], "platforms": ["iOS"],
         "payload": {"RequirePasscode": True}},
        {"id": "pass-watch", "type": "com.apple.configuration.passcode.settings",
         "groups": ["lab"], "platforms": ["watchOS", "visionOS"],
         "payload": {"RequirePasscode": True}}]})
    check("watchOS and visionOS pass the platform enum", valid and not errors)
    check("the declarations document warns once, naming the iOS-only item",
          len([w for w in warnings if "declarations.yaml" in w and "watchOS" in w]) == 1
          and any("pass-ios" in w and "pass-watch" not in w
                  for w in warnings if "declarations.yaml" in w))

    # ==40. configure_accounts and Apple's managed-admin rule==
    #
    # SkipPrimarySetupAccountCreation and SetPrimarySetupAccountAsRegularUser both require AutoSetupAdminAccounts when
    # true, and the managed admin is what fills that key:
    # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/account.configuration.yaml A
    # warning rather than an error: the step itself refuses to send like this, so a save loses that step, not the
    # config.
    def accounts_flow(params):
        return flow_doc([
            {"id": "start-1", "type": "start",
             "params": {"kind": "enroll_dep", "match": {"conditions": [
                 {"type": "platform", "operator": "in", "value": ["Mac"]}]}},
             "next": "acct-1"},
            {"id": "acct-1", "type": "configure_accounts", "params": params,
             "next": "end-1"},
            {"id": "end-1", "type": "end"},
        ])

    def admin_warn(ws):
        return [w for w in ws if "AutoSetupAdminAccounts" in w]

    print("\n40) Standard primary account with no managed admin -> warns, saves")
    valid, errors, warnings, fw = run(accounts_flow({"primary_account": "prompt_standard"}))
    check("save stays valid: this is a warning, never an error", valid and not errors)
    check("one warning, naming Apple's key and the mode",
          len(admin_warn(warnings)) == 1 and "prompt_standard" in admin_warn(warnings)[0])

    print("40a) skip with no managed admin warns the same way")
    valid, errors, warnings, fw = run(accounts_flow({"primary_account": "skip"}))
    check("save stays valid", valid and not errors)
    check("one warning, naming the mode", len(admin_warn(warnings)) == 1
          and "skip" in admin_warn(warnings)[0])

    print("40b) near miss: either mode with a managed admin -> silent")
    for mode in ("prompt_standard", "skip"):
        valid, errors, warnings, fw = run(accounts_flow({
            "primary_account": mode, "managed_admin": True,
            "managed_admin_shortname": "mmadmin",
            "managed_admin_password_source": "generate"}))
        check(f"{mode} with a managed admin saves clean",
              valid and not errors and not admin_warn(warnings))

    print("40c) near miss: the Admin mode needs no managed admin -> silent")
    valid, errors, warnings, fw = run(accounts_flow({"primary_account": "prompt_admin"}))
    check("save stays valid", valid and not errors)
    check("nothing said about AutoSetupAdminAccounts", not admin_warn(warnings))

    retired_command_checks()
    bridge_url_warning_checks()
    remediation_hold_warning_checks()
    model_error_wording_checks()
    checkin_cadence_warning_checks()
    checkin_param_type_checks()
    app_managed_key_checks()
    webhook_target_warning_checks()
    data_keys_declaration_checks()


def data_key_warns(warnings):
    return [w for w in warnings if "declares data key" in w]


def data_keys_declaration_checks():
    """A profile's data_keys declaration is checked against what it provides.
    """
    flow = flow_doc([SCOPED_START, END])
    import base64 as _b64
    cert = _b64.b64encode(b"vendor cert bytes").decode()

    def vendor(data_keys=None, payload_over=None):
        payload = {"PayloadType": "com.acme.sensor", "DeviceCert": cert}
        payload.update(payload_over or {})
        doc = {"id": "p1", "name": "P1", "type": "configuration",
               "groups": ["lab"], "payload": payload}
        if data_keys is not None:
            doc["data_keys"] = data_keys
        return doc

    print("\n49) the model keeps data_keys, so the declaration survives a save")
    # pydantic drops undeclared keys, and a dropped declaration would ship every listed value as <string>.
    p = Profile(**vendor(data_keys=["DeviceCert"]))
    check("data_keys survives model validation", p.data_keys == ["DeviceCert"])

    print("49a) a declared name no payload carries -> warns, saves")
    valid, errors, warnings, _ = run(flow, profiles=[vendor(data_keys=["DeviceCret"])])
    hits = data_key_warns(warnings)
    check("save stays valid: this is a warning, never an error", valid and not errors)
    check("one warning, naming the profile and the unmatched name",
          len(hits) == 1 and "'p1'" in hits[0] and "'DeviceCret'" in hits[0])
    check("the warning says the declaration does nothing",
          hits and "does nothing" in hits[0])

    print("49b) a declared key whose value is not base64 -> warns, saves")
    valid, errors, warnings, _ = run(flow, profiles=[vendor(
        data_keys=["DeviceCert"], payload_over={"DeviceCert": "not base64 at all!"})])
    hits = data_key_warns(warnings)
    check("save stays valid", valid and not errors)
    check("one warning, naming the key",
          len(hits) == 1 and "'DeviceCert'" in hits[0])
    check("the warning says what ships instead", hits and "string" in hits[0])

    print("49c) near miss: a correct declaration is silent")
    valid, errors, warnings, _ = run(flow, profiles=[vendor(data_keys=["DeviceCert"])])
    check("a declared key holding base64 draws no warning",
          valid and not errors and not data_key_warns(warnings))

    print("49d) near miss: a declared name inside a container counts as matched")
    valid, _, warnings, _ = run(flow, profiles=[vendor(
        data_keys=["SigningKey"],
        payload_over={"Settings": {"SigningKey": cert}})])
    check("a nested occurrence satisfies the declaration",
          not data_key_warns(warnings))

    print("49e) near miss: no declaration, no judgment")
    valid, _, warnings, _ = run(flow, profiles=[vendor(
        payload_over={"DeviceCert": "not base64 at all!"})])
    check("an undeclared value is never judged for base64",
          not data_key_warns(warnings))

    print("49f) near miss: a declared name over a free-form dict is matched, not judged")
    # The decode skips containers under a matching name, and so does the base64 judgment; only the unmatched-name check
    # should stay quiet here.
    valid, _, warnings, _ = run(flow, profiles=[vendor(
        data_keys=["Settings"],
        payload_over={"Settings": {"anything": "goes here"}})])
    check("a dict under a declared name draws no warning",
          not data_key_warns(warnings))


def param_warns(warnings, key):
    return [w for w in warnings if f"{key} is" in w]


def checkin_param_type_checks():
    """A check-in start with tag and condition knobs; see the doc for ATC semantics.
    """
    from controller.services.atc import (
        CHECKIN_COOLDOWN_DEFAULT_MINUTES, _checkin_cooldown_minutes, _truthy_param,
    )

    print("\n48) a cooldown the engine cannot read as a number warns")
    for value in (True, False, "soon", [30], {"minutes": 30}):
        valid, errors, warnings, _ = run(checkin_flow(cooldown=value))
        hits = param_warns(warnings, "cooldown_minutes")
        check(f"cooldown_minutes: {value!r} warns, and still saves",
              valid and not errors and len(hits) == 1)
        check(f"...and the engine really does fall back for {value!r}",
              _checkin_cooldown_minutes({"cooldown_minutes": value})
              == CHECKIN_COOLDOWN_DEFAULT_MINUTES)
    hits = param_warns(run(checkin_flow(cooldown=True))[2], "cooldown_minutes")
    check("the warning names the default the engine will use instead",
          hits and str(CHECKIN_COOLDOWN_DEFAULT_MINUTES) in hits[0])
    check("and says how to ask for a run on every check-in",
          hits and "0 to run on every" in hits[0])

    print("48a) near miss: a value the engine reads as the number written")
    # A quoted number is sloppy typing the engine honours exactly, so warning about it would say nothing.
    for value in (0, 5, 60, -5, "30"):
        _, _, warnings, _ = run(checkin_flow(cooldown=value))
        check(f"cooldown_minutes: {value!r} draws no type warning",
              not param_warns(warnings, "cooldown_minutes"))
    check("an unset cooldown says nothing either",
          not param_warns(run(checkin_flow())[2], "cooldown_minutes"))

    print("48b) a once: that is not a boolean warns, and says which way it reads")
    for value, reading in (("yes please", "false"), ("true", "true"), (1, "true"),
                           (0, "false"), ("no", "false")):
        valid, errors, warnings, _ = run(checkin_flow(once=value))
        hits = param_warns(warnings, "once")
        check(f"once: {value!r} warns, and still saves",
              valid and not errors and len(hits) == 1)
        check(f"...and says the engine reads it as {reading}",
              hits and f"reads it as {reading}" in hits[0])
        check(f"...which is what the engine does read for {value!r}",
              _truthy_param(value) is (reading == "true"))

    print("48c) near miss: a boolean once, and an absent one")
    for value in (True, False):
        _, _, warnings, _ = run(checkin_flow(once=value))
        check(f"once: {value} draws no warning", not param_warns(warnings, "once"))
    check("an unset once says nothing", not param_warns(run(checkin_flow())[2], "once"))

    print("48d) near miss: neither knob is judged on another trigger kind")
    schedule = flow_doc([
        {"id": "start-1", "type": "start",
         "params": {"kind": "schedule", "interval_minutes": 30, "once": "yes please",
                    "cooldown_minutes": "soon", "match": {"groups": ["lab"]}},
         "next": "end-1"},
        {"id": "end-1", "type": "end"}])
    valid, errors, warnings, _ = run(schedule)
    check("a scheduled start carrying both keys draws neither warning",
          valid and not errors
          and not param_warns(warnings, "once")
          and not param_warns(warnings, "cooldown_minutes"))

    print("48e) an unreadable cooldown is not also read as the fast cadence")
    # The two warnings answer different questions and must not both appear: a value the engine ignores is the default
    # wait, not a run on every check-in.
    _, _, warnings, fw = run(checkin_flow(cooldown=True))
    check("the cadence warning stays quiet for a value that takes the default",
          not by_code(fw, "checkin-every-event"))
    _, _, _, fw = run(checkin_flow(cooldown=0, once="yes please"))
    check("a once: the engine reads as false leaves the cadence warning free to fire",
          len(by_code(fw, "checkin-every-event")) == 1)


def checkin_flow(*, cooldown=None, once=None, tail=None):
    """A check-in-triggered flow whose one step is tail, a send_command by default. cooldown=None leaves the key unset,
    which the engine reads as its own default."""
    params = {"kind": "checkin", "match": {"groups": ["lab"]}}
    if cooldown is not None:
        params["cooldown_minutes"] = cooldown
    if once is not None:
        params["once"] = once
    step = tail or {"id": "cmd-1", "type": "send_command",
                    "params": {"command": "security_info"}}
    step = dict(step, next="end-1")
    return flow_doc([{"id": "start-1", "type": "start", "params": params,
                      "next": step["id"]},
                     step,
                     {"id": "end-1", "type": "end"}])


def checkin_cadence_warning_checks():
    """A check-in start with an unset cooldown should have one set.
    See the doc for why infinite cooldown is problematic.
    """
    print("\n45) cooldown_minutes: 0 above a step that queues work -> warns")
    valid, errors, warnings, fw = run(checkin_flow(cooldown=0))
    hits = by_code(fw, "checkin-every-event")
    check("the save still succeeds, so no tenant is locked out", valid and not errors)
    check("one warning, badged on the start node",
          len(hits) == 1 and hits[0]["node_id"] == "start-1")
    check("it names the step that queues the work",
          hits and "'cmd-1'" in hits[0]["message"])
    check("it says the run can restart itself",
          hits and "restarting itself" in hits[0]["message"])
    check("it says what to do instead",
          hits and "Leave cooldown_minutes unset" in hits[0]["message"])
    check("and it rides the plain warnings channel too, like every flow warning",
          any("cooldown_minutes" in w for w in warnings))

    print("45a) near miss: an unset cooldown takes the engine's default -> silent")
    valid, _, _, fw = run(checkin_flow())
    check("nothing is said about a flow that never asked for the fast cadence",
          valid and not by_code(fw, "checkin-every-event"))

    print("45b) near miss: a cooldown the engine will honour -> silent")
    for cooldown in (1, 30, 1440):
        _, _, _, fw = run(checkin_flow(cooldown=cooldown))
        check(f"cooldown_minutes: {cooldown} draws no warning",
              not by_code(fw, "checkin-every-event"))

    print("45c) a negative cooldown is no longer a wait, so it warns like zero")
    # atc._checkin_cooldown_minutes clamps at zero, so this is the same cadence written a different way.
    _, _, _, fw = run(checkin_flow(cooldown=-5))
    check("cooldown_minutes: -5 warns", len(by_code(fw, "checkin-every-event")) == 1)

    print("45d) near miss: once: caps the flow at one run per device -> silent")
    _, _, _, fw = run(checkin_flow(cooldown=0, once=True))
    check("a start that can only fire once draws no warning",
          not by_code(fw, "checkin-every-event"))

    print("45e) near miss: a flow that only tags is the case zero was meant for")
    tagging = {"id": "tag-1", "type": "assign_tag", "params": {"tags": ["seen"]}}
    _, _, _, fw = run(checkin_flow(cooldown=0, tail=tagging))
    check("a tagging flow draws no warning", not by_code(fw, "checkin-every-event"))

    print("45f) near miss: another trigger kind is not this cadence at all")
    enroll = flow_doc([SCOPED_START, END])
    _, _, _, fw = run(enroll)
    check("an enrollment start draws no warning",
          not by_code(fw, "checkin-every-event"))

    print("45g) every device-touching step type is treated the same way")
    for step in ({"id": "p-1", "type": "install_profiles",
                  "params": {"profile_ids": ["wifi"]}},
                 {"id": "a-1", "type": "install_apps", "params": {"app_ids": ["pages"]}},
                 {"id": "d-1", "type": "sync_declarations"},
                 {"id": "r-1", "type": "release_device"}):
        _, _, _, fw = run(checkin_flow(cooldown=0, tail=step))
        check(f"a {step['type']} step draws the warning",
              len(by_code(fw, "checkin-every-event")) == 1)


def app_managed_key_checks():
    # See the doc for why install_as_managed type checking is needed.
    flow = flow_doc([SCOPED_START, END])

    def app(**over):
        doc = {"id": "pages", "name": "Pages", "bundle_id": "com.apple.Pages",
               "versions": [{"version": "1.0", "groups": ["lab"],
                             "s3_key": "apps/pages-1.0.pkg", "sha256": "0" * 64}]}
        doc.update(over)
        return doc

    print("\n46) install_as_managed is accepted on an app")
    for value in (True, False):
        valid, errors, _, _ = run(flow, apps=[app(install_as_managed=value)])
        check(f"install_as_managed: {value} saves clean", valid and not errors)

    print("46a) leaving it out is still valid, and stays the common case")
    valid, errors, _, _ = run(flow, apps=[app()])
    check("an app without the key saves clean", valid and not errors)

    print("46b) a value that is not a boolean is refused, readably")
    valid, errors, _, _ = run(flow, apps=[app(install_as_managed="yes please")])
    said = [e for e in errors if e.startswith("Invalid app at index 0")]
    check("the app is refused", not valid and len(said) == 1)
    check("the error names the key and no pydantic code",
          said and "install_as_managed" in said[0] and "type=" not in said[0])

    print("46c) the key is read off the app, not off one of its versions")
    # Where it lives decides which half of a multi-version app it governs, so it is pinned here.
    from controller.utils.yaml_validator import App, AppVersion
    check("App carries the field", "install_as_managed" in App.__fields__)
    check("and AppVersion does not", "install_as_managed" not in AppVersion.__fields__)
    # getattr rather than an attribute read: a model that lost the field should fail this check by name, not take the
    # suite down on the way past.
    check("an app that omits it parses as None, not False",
          getattr(App(**app()), "install_as_managed", "missing") is None)


def webhook_warns(warnings, needle):
    return [w for w in warnings if needle in w]


def webhook_target_warning_checks():
    # See the doc for webhook delivery details and private allowlist.
    flow = flow_doc([SCOPED_START, END])
    before = os.environ.get("DISPATCHER_WEBHOOK_ALLOW_PRIVATE")

    def with_targets(*targets, allow_private=None):
        if allow_private is None:
            os.environ.pop("DISPATCHER_WEBHOOK_ALLOW_PRIVATE", None)
        else:
            os.environ["DISPATCHER_WEBHOOK_ALLOW_PRIVATE"] = allow_private
        return run(flow, dispatcher={
            "webhooks": list(targets),
            "rules": [{"id": "r1", "name": "R1", "severity": "yellow",
                       "check": {"type": "filevault_disabled"},
                       "actions": [{"type": "webhook",
                                    "params": {"target": targets[0]["name"]}}]}]})

    public = {"name": "collector", "url": "https://8.8.8.8/hook", "secret": "s"}
    lan = {"name": "lan-collector", "url": "http://10.0.0.5/hook", "secret": "s"}
    loopback = {"name": "demo", "url": "http://localhost:9099/hook", "secret": "s"}

    try:
        print("\n47) a LAN webhook target warns that deliveries are dropped")
        valid, errors, warnings, _ = with_targets(lan)
        hits = webhook_warns(warnings, "deliveries are refused")
        check("the save still succeeds, so no tenant is locked out",
              valid and not errors)
        check("one warning, naming the target", len(hits) == 1 and "'lan-collector'" in hits[0])
        check("it says the alert is dropped before it is sent",
              hits and "dropped before it is sent" in hits[0])
        check("and it names the allowlist that admits an internal collector",
              hits and "DISPATCHER_WEBHOOK_PRIVATE_ALLOWLIST" in hits[0])
        # Not a substring of the allowlist name, so this asks for the deprecated boolean by itself.
        check("with the deprecated boolean named second, not instead",
              hits and "DISPATCHER_WEBHOOK_ALLOW_PRIVATE" in hits[0]
              and hits[0].index("DISPATCHER_WEBHOOK_PRIVATE_ALLOWLIST")
              < hits[0].index("DISPATCHER_WEBHOOK_ALLOW_PRIVATE"))

        print("47a) a loopback target is refused the same way")
        _, _, warnings, _ = with_targets(loopback)
        check("localhost warns", len(webhook_warns(warnings, "deliveries are refused")) == 1)

        print("47b) near miss: a public target is silent")
        _, _, warnings, _ = with_targets(public)
        check("a public address draws no delivery warning",
              not webhook_warns(warnings, "deliveries are refused"))

        print("47c) near miss: the allow-private setting is honoured, from the "
              "delivery path's own predicate")
        for value in ("true", "1", "yes"):
            _, _, warnings, _ = with_targets(lan, allow_private=value)
            check(f"DISPATCHER_WEBHOOK_ALLOW_PRIVATE={value} silences it",
                  not webhook_warns(warnings, "deliveries are refused"))
        _, _, warnings, _ = with_targets(lan, allow_private="false")
        check("and an explicit false does not",
              len(webhook_warns(warnings, "deliveries are refused")) == 1)

        print("47d) a target with no secret warns that alerts arrive unsigned")
        valid, errors, warnings, _ = with_targets(
            {"name": "collector", "url": "https://8.8.8.8/hook"})
        hits = webhook_warns(warnings, "delivered unsigned")
        check("the save still succeeds", valid and not errors)
        check("one warning, naming the target", len(hits) == 1 and "'collector'" in hits[0])
        check("it says what the receiver cannot do",
              hits and "cannot tell an alert from this server apart" in hits[0])
        check("a target with a secret draws no such warning",
              not webhook_warns(with_targets(public)[2], "delivered unsigned"))

        print("47e) the two warnings are independent")
        _, _, warnings, _ = with_targets({"name": "both", "url": "http://10.0.0.5/hook"})
        check("a private target with no secret draws both",
              len(webhook_warns(warnings, "deliveries are refused")) == 1
              and len(webhook_warns(warnings, "delivered unsigned")) == 1)

        print("47g) a predicate that will not answer does not hold up the save")
        # The one case no URL can produce here: a resolver that hangs. The deadline bounds the wait and not just the
        # answer, so a save never sits behind name resolution and a slow resolver never invents a warning. Patched on
        # the module the validator imports from, which also proves it imports rather than carrying its own copy.
        import time
        from controller.services import dispatcher as dispatcher_mod
        original = dispatcher_mod._webhook_target_blocked

        async def never_answers(url):
            await asyncio.sleep(30)
            return True

        dispatcher_mod._webhook_target_blocked = never_answers
        try:
            started = time.monotonic()
            _, _, warnings, _ = with_targets(lan)
            elapsed = time.monotonic() - started
        finally:
            dispatcher_mod._webhook_target_blocked = original
        check("the save returns on the deadline, not on the resolver", elapsed < 10)
        check("and says nothing, because a slow answer is not a blocked target",
              not webhook_warns(warnings, "deliveries are refused"))
        check("the real predicate is back, and still answers",
              len(webhook_warns(with_targets(lan)[2], "deliveries are refused")) == 1)

        print("47f) said once per target, not once per rule that names it")
        _, _, warnings, _ = run(flow, dispatcher={
            "webhooks": [lan],
            "rules": [{"id": f"r{n}", "name": f"R{n}", "severity": "yellow",
                       "check": {"type": "filevault_disabled"},
                       "actions": [{"type": "webhook",
                                    "params": {"target": "lan-collector"}}]}
                      for n in (1, 2, 3)]})
        check("three rules pointing at one target still say it once",
              len(webhook_warns(warnings, "deliveries are refused")) == 1)
    finally:
        if before is None:
            os.environ.pop("DISPATCHER_WEBHOOK_ALLOW_PRIVATE", None)
        else:
            os.environ["DISPATCHER_WEBHOOK_ALLOW_PRIVATE"] = before


def model_error_wording_checks():
    """A rejected document says what is wrong in the reader's vocabulary.

    Stringifying a pydantic failure hands the console a header counting the errors, the field on its own line, and a
    machine code after the message. The code names an internal class and cannot help anyone fix a document.
    """
    from controller.utils.yaml_validator import _model_error

    print("\n44) a missing required field reads as a plain sentence")
    _, errors, _, _ = run(flow_doc([SCOPED_START, END]),
                          profiles=[{"id": "p1", "type": "configuration"}])
    said = [e for e in errors if e.startswith("Invalid profile at index 0")]
    check("the profile is refused", len(said) == 1)
    check("the field and its message, and nothing between them",
          said and "name: field required" in said[0])
    check("no pydantic error code",
          said and "type=" not in said[0] and "value_error" not in said[0])
    check("no error-counting header and no line breaks",
          said and "validation error" not in said[0] and "\n" not in said[0])

    print("44a) a nested field keeps the path to the key that is wrong")
    _, errors, _, _ = run(flow_doc([SCOPED_START, END]), profiles=[
        {"id": "p1", "name": "P1", "type": "configuration", "groups": ["lab"],
         "payload": {"PayloadType": "com.apple.dock"},
         "conditions": [{"type": "nope", "operator": "in", "value": ["x"]}]}])
    said = [e for e in errors if e.startswith("Invalid profile at index 0")]
    check("the path names the condition and the key inside it",
          said and "conditions.0.type" in said[0])
    check("and carries the message the model raised",
          said and "Invalid condition type: nope" in said[0]
          and "type=" not in said[0])

    print("44b) several failures in one document are joined, not stacked")
    _, errors, _, _ = run(flow_doc([SCOPED_START, END]),
                          profiles=[{"id": "p1", "type": "configuration"}])
    said = [e for e in errors if e.startswith("Invalid profile at index 0")]
    check("one error string carrying both failures",
          said and said[0].count(": ") >= 2 and "; " in said[0])

    print("44c) near miss: anything that is not a model failure is left alone")
    # The same handlers catch YAML syntax errors and unreadable files, and those already read as sentences. A
    # whole-model validator has no field to name.
    check("a plain exception passes through unchanged",
          _model_error(ValueError("mapping values are not allowed here"))
          == "mapping values are not allowed here")

    class RootOnly:
        def errors(self):
            return [{"loc": ("__root__",), "msg": "a rule needs a check", "type": "value_error"}]

    check("a whole-model message is shown without a field name in front",
          _model_error(RootOnly()) == "a rule needs a check")

    class Unhelpful:
        def errors(self):
            raise RuntimeError("no")

        def __str__(self):
            return "something went wrong"

    check("an entry list that cannot be read falls back to the exception itself",
          _model_error(Unhelpful()) == "something went wrong")


def remediation_warns(warnings):
    return [w for w in warnings if "as a remediation" in w]


def remediation_hold_warning_checks():
    """A remediation install is held on the device until the rule is deleted.
    See the doc for why removal pass cannot remove it.
    """
    flow = flow_doc([SCOPED_START, END])
    # lab-remedy is a remediation profile with no scope of its own, so the rule is what puts it on a device. WIFI is
    # scoped to a group and stands for the other half of the fork.
    lab_remedy = {"id": "lab-remedy", "name": "Lab Remediation", "type": "configuration",
                  "groups": [], "payload": {"PayloadType": "com.apple.dock", "tilesize": 48}}

    def remediating(profile_ids, profiles=None):
        return run(flow, profiles=profiles if profiles is not None else [WIFI, lab_remedy],
                   dispatcher=rule(actions=[{"type": "install_profiles",
                                             "params": {"profile_ids": profile_ids}}]))

    print("\n43) an install_profiles remediation says the profile is held")
    valid, errors, warnings, _ = remediating(["wifi"])
    hits = remediation_warns(warnings)
    check("the save still succeeds: this is how the feature works, not a mistake",
          valid and not errors)
    check("one warning, naming the rule and the profile",
          len(hits) == 1 and "'r1'" in hits[0] and "'wifi'" in hits[0])
    check("it says resolving the alert does not take the profile off",
          hits and "resolving the alert does not take it off" in hits[0])
    check("and that disabling the rule does not either",
          hits and "disabling the rule" in hits[0])

    print("43a) a profile with no scope of its own is said so plainly")
    valid, _, warnings, _ = remediating(["lab-remedy"])
    hits = remediation_warns(warnings)
    check("the extra clause names profiles.yaml and the profile",
          valid and len(hits) == 1
          and "nothing in profiles.yaml scopes 'lab-remedy'" in hits[0])
    check("and it still carries the hold, which is the part that surprises",
          hits and "while this rule exists" in hits[0])

    print("43b) every profile the action names is judged on its own")
    valid, _, warnings, _ = remediating(["wifi", "lab-remedy"])
    hits = remediation_warns(warnings)
    check("two profiles -> two warnings, one per profile",
          valid and len(hits) == 2 and "'wifi'" in hits[0] and "'lab-remedy'" in hits[1])
    check("only the unscoped one carries the extra clause",
          len(hits) == 2 and "profiles.yaml scopes" not in hits[0]
          and "profiles.yaml scopes" in hits[1])

    print("43c) near miss: an unknown profile is still the error it always was")
    valid, errors, warnings, _ = remediating(["no-such-profile"])
    check("the reference is refused",
          not valid and any("references unknown profile" in e for e in errors))
    check("and it is not also described as held, which it never will be",
          not remediation_warns(warnings))

    print("43d) near miss: the other action types are left alone")
    for action in ({"type": "assign_tag", "params": {"tags": ["quarantine"]}},
                   {"type": "install_apps", "params": {"app_ids": ["pages"]}},
                   {"type": "send_command", "params": {"command": "security_info"}}):
        _, _, warnings, _ = run(flow, profiles=[WIFI, lab_remedy],
                                dispatcher=rule(actions=[action]))
        check(f"a {action['type']} action draws no hold warning",
              not remediation_warns(warnings))

    print("43e) near miss: a profile installed by a flow step is not a remediation")
    # install_profiles is a flow node type too, and there the profile arrives through the flow rather than through a
    # rule, so no hold is involved.
    step = flow_doc([
        {"id": "start-1", "type": "start",
         "params": {"kind": "enroll_dep", "match": {"groups": ["lab"]}},
         "next": "install-1"},
        {"id": "install-1", "type": "install_profiles",
         "params": {"profile_ids": ["lab-remedy"]}, "next": "end-1"},
        {"id": "end-1", "type": "end"},
    ])
    _, _, warnings, _ = run(step, profiles=[WIFI, lab_remedy])
    check("a flow node installing the same profile draws no hold warning",
          not remediation_warns(warnings))


def bridge_warns(warnings):
    return [w for w in warnings if "PUBLIC_API_URL" in w]


def bridge_url_warning_checks():
    """A legacy bridge with no PUBLIC_API_URL will be dropped from the declaration set.
    See the doc for why this matters at save time.
    """
    flow = flow_doc([SCOPED_START, END])
    legacy = {"declarations": [{"id": "bridged", "type": "com.apple.configuration.legacy",
                                "groups": ["lab"], "profile": "wifi"}]}
    native = {"declarations": [{"id": "passcode",
                                "type": "com.apple.configuration.passcode.settings",
                                "groups": ["lab"], "payload": {"RequirePasscode": True}}]}
    before = os.environ.get("PUBLIC_API_URL")

    def with_public_url(value, declarations):
        if value is None:
            os.environ.pop("PUBLIC_API_URL", None)
        else:
            os.environ["PUBLIC_API_URL"] = value
        return run(flow, declarations=declarations)

    try:
        print("\n42) a legacy bridge with no PUBLIC_API_URL -> warns, saves")
        valid, errors, warnings, _ = with_public_url(None, legacy)
        hits = bridge_warns(warnings)
        check("the save still succeeds, so no tenant is locked out", valid and not errors)
        check("one warning, naming the declaration", len(hits) == 1 and "'bridged'" in hits[0])
        check("it says the declaration reaches no device", hits and "no device" in hits[0])
        check("and it answers the console's own count", hits and "scoped" in hits[0])

        print("42a) an http PUBLIC_API_URL warns and quotes the value")
        valid, errors, warnings, _ = with_public_url("http://localhost:8001", legacy)
        hits = bridge_warns(warnings)
        check("the save still succeeds", valid and not errors)
        check("one warning, carrying the value that cannot serve it",
              len(hits) == 1 and "http://localhost:8001" in hits[0])

        print("42b) near miss: an https PUBLIC_API_URL is silent")
        for url in ("https://mdm.example.edu", "https://mdm.example.edu/"):
            _, _, warnings, _ = with_public_url(url, legacy)
            check(f"{url} draws no warning", not bridge_warns(warnings))

        print("42c) near miss: a declaration carrying its own payload is silent")
        # Only the bridge sends the device somewhere to download from, so only the bridge reads the public URL.
        for url in (None, "http://localhost:8001"):
            _, _, warnings, _ = with_public_url(url, native)
            check(f"a native declaration is left alone with PUBLIC_API_URL={url}",
                  not bridge_warns(warnings))

        print("42d) every bridge in the file is judged, not just the first")
        two = {"declarations": [legacy["declarations"][0],
                                dict(legacy["declarations"][0], id="bridged-2")]}
        valid, _, warnings, _ = with_public_url(None, two)
        hits = bridge_warns(warnings)
        check("two bridges -> two warnings, one per declaration",
              valid and len(hits) == 2
              and "'bridged'" in hits[0] and "'bridged-2'" in hits[1])
    finally:
        if before is None:
            os.environ.pop("PUBLIC_API_URL", None)
        else:
            os.environ["PUBLIC_API_URL"] = before


def retired_warns(warnings):
    return [w for w in warnings if "retired" in w]


def retired_command_checks():
    """A command the catalog has retired is a warning in both branches.
    See the doc for why this matters for dispatcher rules.
    """
    from controller.services import command_catalog as _cc
    from controller.services.command_catalog import VALID_COMMAND_TYPES

    # Nothing is retired today, so the warning path runs against a synthetic entry mutated into RETIRED_COMMANDS for the
    # length of this function. The validator reads that dict by reference, so the mutation looks like a real retirement
    # to it. The reason wording matters because the assertions below check it reaches the warning.
    _saved_retired = dict(_cc.RETIRED_COMMANDS)
    retired = "clear_passcode_legacy"
    _cc.RETIRED_COMMANDS[retired] = ("Apple requires a key for it that nothing "
                                     "in this deployment can supply")
    check("this suite injected a retired command to exercise the path",
          retired in _cc.RETIRED_COMMANDS)

    def command_flow(cmd):
        return flow_doc([
            {"id": "start-1", "type": "start",
             "params": {"kind": "enroll_dep", "match": {"groups": ["lab"]}},
             "next": "cmd-1"},
            {"id": "cmd-1", "type": "send_command", "params": {"command": cmd},
             "next": "end-1"},
            {"id": "end-1", "type": "end"},
        ])

    print(f"\n41) a dispatcher rule naming the retired '{retired}' -> warns, saves")
    flow = flow_doc([SCOPED_START, END])
    valid, errors, warnings, _ = run(flow, dispatcher=rule(actions=[
        {"type": "send_command", "params": {"command": retired}}]))
    hits = retired_warns(warnings)
    check("the save still succeeds, so the whole tenant is not locked out",
          valid and not errors)
    check("one warning, naming the rule and the command",
          len(hits) == 1 and "'r1'" in hits[0] and f"'{retired}'" in hits[0])
    check("the warning gives the reason and names the file to fix",
          hits and "Apple requires a key" in hits[0] and "dispatcher.yaml" in hits[0])
    check("and it is not also called unknown, which is what it is not",
          not any("unknown command" in e for e in errors))

    print("41a) the same command as an automated flow step -> warns, saves")
    valid, errors, warnings, _ = run(command_flow(retired))
    hits = retired_warns(warnings)
    check("the save still succeeds", valid and not errors)
    check("one warning, naming the node and the file",
          len(hits) == 1 and "cmd-1" in hits[0] and "flows.yaml" in hits[0])
    # The retired command is also destructive, and the flow branch forbids destructive steps. Retirement is read first,
    # because a command that can never be dispatched cannot do what that rule protects against.
    check("the destructive-step error is not raised as well",
          not any("destructive" in e for e in errors))

    print("41b) near miss: an outright unknown command is still a hard error")
    for owner, kwargs in (("dispatcher", {"dispatcher": rule(actions=[
        {"type": "send_command",
         "params": {"command": "clear_pascode"}}])}),
                          ("flow", {})):
        target = command_flow("clear_pascode") if owner == "flow" else flow
        valid, errors, warnings, _ = run(target, **kwargs)
        check(f"{owner}: a misspelling is refused",
              not valid and any("unknown command" in e for e in errors))
        check(f"{owner}: and is not called retired", not retired_warns(warnings))

    print("41c) near miss: a live command draws neither")
    check("the catalog still offers the command this case uses",
          "security_info" in VALID_COMMAND_TYPES)
    valid, errors, warnings, _ = run(command_flow("security_info"))
    check("a live non-destructive flow step saves clean",
          valid and not errors and not retired_warns(warnings))
    valid, errors, warnings, _ = run(flow, dispatcher=rule(actions=[
        {"type": "send_command", "params": {"command": "security_info"}}]))
    check("and so does the same action on a rule",
          valid and not errors and not retired_warns(warnings))

    # Restore the catalog for anything else in this process.
    _cc.RETIRED_COMMANDS.clear()
    _cc.RETIRED_COMMANDS.update(_saved_retired)


if __name__ == "__main__":
    # aliased: this file has its own module-level run() helper
    from tests._verify_harness import run as _run_verify_suite

    _run_verify_suite(main)
