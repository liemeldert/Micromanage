"""Coverage for ATC multi-flow: the document schema, run isolation between flows, and the save gate
(controller/services/flow_gate.py).

Run: PYTHONPATH=. ./.venv/bin/python tests/verify_atc_multiflow.py
"""

import copy
import os
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from controller.services import flow_gate
from controller.services.flow_step_catalog import (
    default_enrollment_flow,
    is_draft,
    node_scope,
    normalize_flow_document,
    start_kind_scope,
)
from controller.utils.yaml_validator import YAMLValidator
from tests._verify_harness import run

FAILED = []


def check(label, ok):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        FAILED.append(label)


def flow(fid, nodes=None, **extra):
    doc = {"id": fid, "name": fid.title(), "nodes": nodes if nodes is not None
    else [{"id": "s", "type": "start", "params": {"kind": "checkin"},
           "next": "e"},
          {"id": "e", "type": "end"}]}
    doc.update(extra)
    return doc


def doc(*flows):
    return {"version": 2, "flows": list(flows)}


# The default flow() above starts on check-in, which is what a compliance flow looks like. An enrollment flow has to
# start on an enrollment or the gate says so, so the permanent-flow fixtures come through here.
def eflow(fid="enrollment", nodes=None, **extra):
    extra.setdefault("permanent", True)
    return flow(fid, nodes if nodes is not None else
    [{"id": "es", "type": "start", "params": {"kind": "enroll_dep"},
      "next": "ee"},
     {"id": "ee", "type": "end"}], **extra)


def codes(findings):
    return sorted(f.code for f in findings)


PROTECTION_CODES = {"permanent-flow-deleted", "permanent-flow-renamed",
                    "permanent-flow-missing", "permanent-flag-moved",
                    "permanent-flow-disabled"}


def pcodes(findings):
    """Just the protection findings. The flag-move fixtures below hand the enrollment role to a flow that was never
    built for it, so they draw integrity findings too, and each assertion should stay about one rule."""
    return sorted(f.code for f in findings if f.code in PROTECTION_CODES)


# == 1. document schema ==

def schema_checks():
    print("1) flows.yaml v0 / v1 / v2 all read, and nothing is invented")

    empty, warns = normalize_flow_document({})
    check("an empty document has no flows and no complaint",
          empty == [] and warns == [])
    # The engine reads this on every enroll, check-in and poll tick. Inventing a flow here would run one on every tenant
    # that never authored one, release_device included, which sends DeviceConfigured to real hardware.
    check("a document with nothing in it does not get a default flow",
          normalize_flow_document({"flows": []})[0] == [])

    v1 = {"flow": flow("onboarding")}
    before = copy.deepcopy(v1)
    flows, warns = normalize_flow_document(v1)
    check("v1 reads as one flow and keeps its id",
          len(flows) == 1 and flows[0]["id"] == "onboarding")
    check("v1's flow becomes the permanent one", flows[0]["permanent"] is True)
    check("v1 upgrades silently", warns == [])
    check("v1 input is not written into", v1 == before)
    check("and the nodes are shared, not copied",
          flows[0]["nodes"] is v1["flow"]["nodes"])

    v0 = {"flows": [
        {"id": "old-a", "name": "A", "priority": 10, "start": "n1",
         "trigger": {"match": {"groups": ["lab"]}},
         "nodes": [{"id": "n1", "type": "assign_tag", "params": {"tags": ["x"]},
                    "next": "n2"},
                   {"id": "n2", "type": "end"}]},
        {"id": "old-b", "name": "B", "enabled": False, "start": "m1",
         "trigger": {}, "nodes": [{"id": "m1", "type": "end"}]},
    ]}
    flows, warns = normalize_flow_document(v0)
    check("v0 collapses to the first enabled flow",
          len(flows) == 1 and flows[0]["id"] == "old-a")
    check("v0 gets a synthesized start carrying the old trigger match",
          flows[0]["nodes"][0]["type"] == "start"
          and flows[0]["nodes"][0]["params"]["match"] == {"groups": ["lab"]})
    check("v0 says so", any("pre-start-node" in w for w in warns))

    v2 = doc(flow("enrollment", permanent=True), flow("triage"))
    flows, warns = normalize_flow_document(v2)
    check("v2 keeps every flow, in document order",
          [f["id"] for f in flows] == ["enrollment", "triage"] and warns == [])

    # v0 and v2 share the flows key. An unversioned document is read entry by entry, so a half-migrated file does not
    # take the modern flows down with it.
    mixed = {"flows": [
        {"id": "legacy", "name": "L", "start": "a",
         "nodes": [{"id": "a", "type": "end"}]},
        flow("modern"),
    ]}
    flows, _ = normalize_flow_document(mixed)
    check("a mixed unversioned document classifies per entry",
          [f["id"] for f in flows] == ["legacy", "modern"]
          and flows[0]["nodes"][0]["id"] == "migrated-start"
          and flows[1]["nodes"][0]["id"] == "s")

    print("1b) normalization repairs what it can rather than failing")
    flows, warns = normalize_flow_document(doc(flow("a"), flow("b")))
    check("a document with no flag adopts its first live flow",
          flows[0]["permanent"] is True and "permanent" not in flows[1])
    check("and says so when there was a choice to make",
          any("adopted" in w for w in warns))
    # Silence matters here: this is every v1 tenant's read, on every check-in, until they next save.
    _, warns = normalize_flow_document(doc(flow("only")))
    check("but says nothing when there was only one candidate", warns == [])

    junk = {"version": 2, "flows": ["nope", {"name": "no id"},
                                    flow("a"), flow("a", name="dup")]}
    flows, warns = normalize_flow_document(junk)
    check("junk entries are dropped and a duplicate id keeps the first",
          [f["id"] for f in flows] == ["a"] and len(warns) == 3)

    drafts = doc(
        flow("enrollment", permanent=True),
        flow("enrollment--draft", draft_of="enrollment"),
        flow("orphan--draft", draft_of="gone"),
        flow("nested--draft", draft_of="enrollment--draft"),
        flow("flagged--draft", draft_of="enrollment", permanent=True),
    )
    flows, warns = normalize_flow_document(drafts)
    kept = [f["id"] for f in flows]
    check("a draft of a live flow is kept", "enrollment--draft" in kept)
    check("a draft of nothing is dropped", "orphan--draft" not in kept)
    check("a draft of a draft is dropped", "nested--draft" not in kept)
    check("a draft cannot carry the permanent flag",
          all(not is_draft(f) or "permanent" not in f for f in flows))
    check("and the live flow still has it",
          [f for f in flows if f["id"] == "enrollment"][0]["permanent"] is True)

    for bad in (None, [], "x", 7, {"flow": {}}, {"version": 2}):
        flows, _ = normalize_flow_document(bad)
        if flows != []:
            check(f"a malformed document ({bad!r}) reads as no flows", False)
            break
    else:
        check("a malformed document reads as no flows and never raises", True)


# == 2. catalog scope ==

def scope_checks():
    print("2) the catalog says which flows a node and a trigger belong to")
    check("configure_accounts is enrollment-only",
          node_scope("configure_accounts") == "enrollment")
    check("release_device is enrollment-only",
          node_scope("release_device") == "enrollment")
    for universal in ("assign_tag", "remove_tag", "set_name", "install_profiles",
                      "install_apps", "sync_declarations", "send_command",
                      "set_firmware_lock", "branch", "wait_for", "manual_gate",
                      "end", "start"):
        if node_scope(universal) != "universal":
            check(f"{universal} is universal", False)
            break
    else:
        check("every other node type, set_firmware_lock included, is universal", True)
    check("an unknown node type reads as universal, not enrollment",
          node_scope("no-such-node") == "universal")
    check("both enrollment triggers are enrollment-only",
          start_kind_scope("enroll_dep") == "enrollment"
          and start_kind_scope("enroll_profile") == "enrollment")
    check("check-in and schedule are universal",
          start_kind_scope("checkin") == "universal"
          and start_kind_scope("schedule") == "universal")


# == 3. the default enrollment flow ==

def default_flow_checks():
    print("3) the flow a newly provisioned tenant starts with")
    df = default_enrollment_flow()
    check("it is a fresh object every call, with the same content",
          df is not default_enrollment_flow() and df == default_enrollment_flow())
    check("it is the permanent flow and it is on",
          df["permanent"] is True and df["enabled"] is True)
    kinds = {(n.get("params") or {}).get("kind") for n in df["nodes"]
             if n["type"] == "start"}
    check("it covers both ways a device can enrol",
          kinds == {"enroll_dep", "enroll_profile"})
    wait = [n for n in df["nodes"] if n["type"] == "wait_for"][0]
    # device_info is refless (atc._REFLESS_SIGNALS), so the run always parks and the empty-barrier path is unreachable.
    # A gate key here would be dead configuration.
    check("its wait carries no gate key", "gate" not in wait["params"])
    gate = [n for n in df["nodes"] if n["type"] == "manual_gate"][0]
    edges = {o["edge"] for o in gate["params"]["options"]}
    # A flow is a DAG and the engine follows a gate edge rather than re-parking, so there is no edge a keep-waiting
    # option could point at. The escalation ladder covers the run left alone.
    check("its gate offers no option it cannot honour",
          edges == {"on_release", "on_cancel"}
          and all(gate.get(e) for e in edges))

    with tempfile.TemporaryDirectory() as tmp:
        tdir = Path(tmp)
        (tdir / "config.yaml").write_text(yaml.safe_dump(
            {"tenant": {"id": "t", "name": "T", "allowed_users": ["a@b.c"]}}))
        for name in ("groups.yaml", "apps.yaml", "profiles.yaml"):
            (tdir / name).write_text(yaml.safe_dump({name.split(".")[0]: []}))
        (tdir / "flows.yaml").write_text(yaml.safe_dump(doc(df)))
        v = YAMLValidator(tdir)
        valid, errors, _ = v.validate_all()
        check("it validates clean out of the box", valid, )
        if not valid:
            print("       errors:", errors)
        check("and raises no node-level flow warnings", v.flow_warnings == [])
        check("the gate passes it too",
              flow_gate.blocking(flow_gate.check_flows_document(
                  doc(df), profiles=[], prior=None)) == [])


# == 4. the validator over many flows ==

def validator_checks():
    print("4) the validator reads every flow, and names the flow it is talking about")
    with tempfile.TemporaryDirectory() as tmp:
        tdir = Path(tmp)
        (tdir / "config.yaml").write_text(yaml.safe_dump(
            {"tenant": {"id": "t", "name": "T", "allowed_users": ["a@b.c"]}}))
        for name in ("groups.yaml", "apps.yaml", "profiles.yaml"):
            (tdir / name).write_text(yaml.safe_dump({name.split(".")[0]: []}))

        def validate(document):
            (tdir / "flows.yaml").write_text(yaml.safe_dump(document))
            v = YAMLValidator(tdir)
            valid, errors, warnings = v.validate_all()
            return valid, errors, v.flow_warnings

        good = doc(default_enrollment_flow(), flow("triage"))
        valid, errors, fw = validate(good)
        check("two well-formed flows validate", valid)
        if not valid:
            print("       errors:", errors)

        broken = doc(default_enrollment_flow(),
                     flow("triage", nodes=[{"id": "s", "type": "start",
                                            "params": {"kind": "checkin"},
                                            "next": "nowhere"}]))
        valid, errors, _ = validate(broken)
        check("a dangling edge in the second flow is still an error",
              not valid and any("triage" in e for e in errors))

        # Normalization adopts a permanent flow when none is flagged, so the one shape it refuses to resolve is the only
        # document-level error left.
        two = doc(flow("a", permanent=True), flow("b", permanent=True))
        valid, errors, _ = validate(two)
        check("two permanent flows is a document error",
              not valid and any("more than one permanent flow" in e for e in errors))

        # A warning has to name its flow: node ids repeat across flows, so one carrying only a node id would point at
        # every flow that has one.
        noisy = doc(
            flow("enrollment", permanent=True,
                 nodes=[{"id": "start-1", "type": "start",
                         "params": {"kind": "enroll_dep",
                                    "match": {"exclude_devices": ["x"]}},
                         "next": "end-1"},
                        {"id": "end-1", "type": "end"}]),
            flow("triage",
                 nodes=[{"id": "start-1", "type": "start",
                         "params": {"kind": "checkin",
                                    "match": {"exclude_devices": ["x"]}},
                         "next": "end-1"},
                        {"id": "end-1", "type": "end"}]))
        valid, errors, fw = validate(noisy)
        hits = [w for w in fw if w["code"] == "exclude-only-scope"]
        check("the same node id in two flows produces two distinct findings",
              len(hits) == 2
              and {w["flow_id"] for w in hits} == {"enrollment", "triage"})
        check("every structured finding carries its flow",
              all(set(w) == {"flow_id", "node_id", "code", "message"} for w in fw))

        # release_device is enrollment-scoped, so a release step outside the enrollment flow is a scope violation the
        # gate reports. Repeating it here as a DEP warning would put two complaints on one node.
        (tdir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": [
            {"id": "dep", "name": "DEP", "type": "enrollment",
             "payload": {"await_device_configured": False}}]}))
        rel = [{"id": "s", "type": "start", "params": {"kind": "checkin"},
                "next": "r"},
               {"id": "r", "type": "release_device", "next": "e"},
               {"id": "e", "type": "end"}]
        _, _, fw = validate(doc(flow("enrollment", permanent=True, nodes=rel),
                                flow("triage", nodes=rel)))
        owners = {w["flow_id"] for w in fw if w["code"] == "release-without-await"}
        check("the DEP cross-checks speak only for the enrollment flow",
              owners == {"enrollment"})


# == 5. the save gate ==

def gate_checks():
    print("5) the gate protects the enrollment flow")
    live = doc(eflow(), flow("triage"))

    def check_doc(candidate, prior=live, profiles=None):
        return flow_gate.check_flows_document(candidate, profiles=profiles,
                                              prior=prior)

    check("a document that changes nothing is clean",
          codes(check_doc(live)) == [])
    check("a first save has nothing to protect",
          codes(check_doc(live, prior=None)) == [])

    gone = doc(flow("triage"))
    check("deleting the enrollment flow is refused",
          pcodes(check_doc(gone)) == ["permanent-flow-deleted"])
    renamed = doc(eflow("onboarding"), flow("triage"))
    check("renaming it is refused, and named as a rename",
          pcodes(check_doc(renamed)) == ["permanent-flow-renamed"])
    check("neither can be acknowledged away",
          not any(f.acknowledgeable for f in check_doc(gone) + check_doc(renamed)))

    moved = doc(eflow(permanent=False), flow("triage", permanent=True))
    check("moving the flag to another flow is refused",
          pcodes(check_doc(moved)) == ["permanent-flag-moved"])
    unflagged = doc(flow("triage"), eflow(permanent=False))
    check("dropping the flag where another flow would inherit it is refused",
          pcodes(check_doc(unflagged)) == ["permanent-flow-missing"])
    # Every v1 tenant's next save looks like this: no flag written yet, and the flow that normalization adopts is the
    # one that already had it.
    readopt = doc(eflow(permanent=False), flow("triage"))
    check("but dropping it where the same flow is re-adopted is fine",
          pcodes(check_doc(readopt)) == [])

    off = doc(eflow(enabled=False), flow("triage"))
    check("switching the enrollment flow off is refused",
          pcodes(check_doc(off)) == ["permanent-flow-disabled"])
    check("switching another flow off is not",
          pcodes(check_doc(doc(eflow(),
                               flow("triage", enabled=False)))) == [])

    print("5b) Setup Assistant steps stay in the enrollment flow")
    setup_nodes = [{"id": "s", "type": "start", "params": {"kind": "enroll_dep"},
                    "next": "r"},
                   {"id": "r", "type": "release_device", "next": "e"},
                   {"id": "e", "type": "end"}]
    check("a release step in a compliance flow is refused",
          "enrollment-node-outside-enrollment-flow" in
          codes(check_doc(doc(eflow(),
                              flow("triage", nodes=setup_nodes)))))
    check("the same step in the enrollment flow is fine",
          codes(check_doc(doc(flow("enrollment", permanent=True,
                                   nodes=setup_nodes)))) == [])
    enroll_start = [{"id": "s", "type": "start",
                     "params": {"kind": "enroll_dep"}, "next": "e"},
                    {"id": "e", "type": "end"}]
    check("an enrollment trigger in a compliance flow is refused",
          "enrollment-trigger-outside-enrollment-flow" in
          codes(check_doc(doc(eflow(),
                              flow("triage", nodes=enroll_start)))))
    check("a draft of the enrollment flow may hold both",
          [f.code for f in check_doc(doc(
              eflow(nodes=setup_nodes),
              flow("enrollment--draft", draft_of="enrollment",
                   nodes=setup_nodes)))
           if f.code.startswith("enrollment-node")] == [])
    check("a draft of a compliance flow may not",
          "enrollment-node-outside-enrollment-flow" in
          codes(check_doc(doc(eflow(),
                              flow("triage"),
                              flow("triage--draft", draft_of="triage",
                                   nodes=setup_nodes)))))

    print("5c) the ways an enrollment flow breaks quietly")
    no_start = doc(flow("enrollment", permanent=True))  # a check-in start only
    check("an enrollment flow with no enrollment trigger is refused",
          "enrollment-no-start" in codes(check_doc(no_start)))

    dep_profiles = [{"id": "dep", "type": "enrollment",
                     "payload": {"await_device_configured": True}}]
    held = doc(eflow(nodes=enroll_start))
    check("await_device_configured with no release on the path is refused",
          "enrollment-dep-await-no-release" in
          codes(check_doc(held, profiles=dep_profiles)))
    released = doc(eflow(nodes=[
        {"id": "s", "type": "start", "params": {"kind": "enroll_dep"}, "next": "r"},
        {"id": "r", "type": "release_device", "next": "e"},
        {"id": "e", "type": "end"}]))
    check("and with one, it is not",
          "enrollment-dep-await-no-release" not in
          codes(check_doc(released, profiles=dep_profiles)))
    check("a tenant whose profiles we cannot read is not guessed at",
          "enrollment-dep-await-no-release" not in
          codes(check_doc(held, profiles=None)))
    check("nor is one whose profiles hold nobody",
          "enrollment-dep-await-no-release" not in
          codes(check_doc(held, profiles=[{"id": "dep", "type": "enrollment",
                                           "payload": {}}])))

    after = doc(eflow(nodes=[
        {"id": "s", "type": "start", "params": {"kind": "enroll_dep"}, "next": "r"},
        {"id": "r", "type": "release_device", "next": "a"},
        {"id": "a", "type": "configure_accounts",
         "params": {"primary_account": "prompt_admin"}, "next": "e"},
        {"id": "e", "type": "end"}]))
    check("account setup below the release step is refused",
          "enrollment-accounts-after-release" in codes(check_doc(after)))
    before_release = doc(eflow(nodes=[
        {"id": "s", "type": "start", "params": {"kind": "enroll_dep"}, "next": "a"},
        {"id": "a", "type": "configure_accounts",
         "params": {"primary_account": "prompt_admin"}, "next": "r"},
        {"id": "r", "type": "release_device", "next": "e"},
        {"id": "e", "type": "end"}]))
    check("and above it, it is not",
          codes(check_doc(before_release)) == [])

    no_admin = doc(eflow(nodes=[
        {"id": "s", "type": "start", "params": {"kind": "enroll_dep"}, "next": "a"},
        {"id": "a", "type": "configure_accounts",
         "params": {"primary_account": "skip"}, "next": "e"},
        {"id": "e", "type": "end"}]))
    check("skipping the user account with no managed admin is refused",
          "enrollment-accounts-no-admin" in codes(check_doc(no_admin)))
    with_admin = copy.deepcopy(no_admin)
    with_admin["flows"][0]["nodes"][1]["params"]["managed_admin"] = True
    check("with a managed admin, it is not",
          "enrollment-accounts-no-admin" not in codes(check_doc(with_admin)))
    check("and prompting for an admin account needs no managed admin",
          codes(check_doc(before_release)) == [])

    print("5d) drafts are advice on save and refusals on promote")
    draft_doc = doc(eflow(nodes=enroll_start),
                    flow("enrollment--draft", draft_of="enrollment",
                         nodes=enroll_start))
    found = check_doc(draft_doc, profiles=dep_profiles)
    on_draft = [f for f in found if f.flow_id == "enrollment--draft"]
    check("a half-finished draft still reports its problems",
          any(f.code == "enrollment-dep-await-no-release" for f in on_draft))
    check("but none of them blocks the save",
          all(f.advisory for f in on_draft)
          and not any(f.flow_id == "enrollment--draft"
                      for f in flow_gate.blocking(found)))
    check("while the live flow's identical problem does block it",
          any(f.flow_id == "enrollment" for f in flow_gate.blocking(found)))

    print("5e) draft shape rules")
    orphan = doc(eflow(), flow("x--draft", draft_of="gone"))
    check("a draft of nothing is refused",
          codes(check_doc(orphan)) == ["draft-target-missing"])
    deep = doc(eflow(),
               flow("enrollment--draft", draft_of="enrollment"),
               flow("deep--draft", draft_of="enrollment--draft"))
    check("a draft of a draft is refused",
          "draft-of-draft" in codes(check_doc(deep)))
    twice = doc(eflow(),
                flow("enrollment--draft", draft_of="enrollment"),
                flow("enrollment--draft-2", draft_of="enrollment"))
    check("a second draft of one flow is refused",
          "draft-duplicate" in codes(check_doc(twice)))

    # These three are the only findings on a draft that survive the advisory demotion. They are about where the draft
    # sits, which finishing it does not change, and the write that raises one loses the draft on the next read.
    check("and all three actually block the save",
          [codes(flow_gate.blocking(check_doc(d)))
           for d in (orphan, deep, twice)] ==
          [["draft-target-missing"], ["draft-of-draft"], ["draft-duplicate"]])
    check("no acknowledgement waives one",
          codes(flow_gate.blocking(check_doc(orphan),
                                   {"draft-target-missing"})) ==
          ["draft-target-missing"])
    # Deleting a flow that had a draft. Accepted, the orphan is dropped by the next normalize with its unmerged work.
    deleted_target = doc(eflow(), flow("triage--draft", draft_of="triage"))
    check("deleting a flow out from under its draft is refused",
          codes(flow_gate.blocking(check_doc(deleted_target))) ==
          ["draft-target-missing"])
    # The exemption is per code, not per flow: everything else on the same draft is still a work in progress and still
    # only advice.
    mixed = check_doc(doc(eflow(nodes=enroll_start),
                          flow("enrollment--draft", draft_of="enrollment",
                               nodes=enroll_start),
                          flow("enrollment--draft-2", draft_of="enrollment",
                               nodes=enroll_start)),
                      profiles=dep_profiles)
    on_second = [f for f in mixed if f.flow_id == "enrollment--draft-2"]
    check("a shape finding does not drag the draft's own problems with it",
          codes(f for f in on_second if not f.advisory) == ["draft-duplicate"]
          and any(f.advisory for f in on_second))

    check("a duplicate flow id is refused and cannot be acknowledged",
          codes(check_doc(doc(eflow(),
                              flow("t"), flow("t", name="again")))) ==
          ["flow-duplicate-id"]
          and not check_doc(doc(eflow(),
                                flow("t"), flow("t")))[0].acknowledgeable)

    print("5f) deployment limits")
    original = (flow_gate.MAX_FLOWS_PER_TENANT, flow_gate.MAX_NODES_PER_FLOW,
                flow_gate.MAX_SCHEDULE_STARTS_PER_TENANT,
                flow_gate.MIN_SCHEDULE_INTERVAL_MINUTES,
                flow_gate.MIN_CHECKIN_COOLDOWN_MINUTES,
                flow_gate.MAX_DRAFTS_PER_TENANT)
    try:
        flow_gate.MAX_FLOWS_PER_TENANT = 2
        check("more flows than the deployment allows is refused",
              "limit-flows" in codes(check_doc(doc(
                  eflow(), flow("b"), flow("c")))))
        check("exactly the limit is not",
              "limit-flows" not in codes(check_doc(doc(
                  eflow(), flow("b")))))
        flow_gate.MAX_DRAFTS_PER_TENANT = 0
        check("a draft does not count against the flow limit",
              "limit-flows" not in codes(check_doc(doc(
                  eflow(), flow("b"),
                  flow("b--draft", draft_of="b")))))
        flow_gate.MAX_DRAFTS_PER_TENANT = original[5]

        flow_gate.MAX_NODES_PER_FLOW = 1
        check("a flow bigger than the node cap is refused",
              "limit-nodes-per-flow" in codes(check_doc(live)))
        flow_gate.MAX_NODES_PER_FLOW = original[1]

        sched = [{"id": "s", "type": "start",
                  "params": {"kind": "schedule", "interval_minutes": 5},
                  "next": "e"}, {"id": "e", "type": "end"}]
        flow_gate.MIN_SCHEDULE_INTERVAL_MINUTES = 15
        check("a schedule faster than the floor is refused",
              "limit-schedule-interval" in codes(check_doc(doc(
                  eflow(), flow("s", nodes=sched)))))
        sched[0]["params"]["interval_minutes"] = 15
        check("one at the floor is not",
              "limit-schedule-interval" not in codes(check_doc(doc(
                  eflow(), flow("s", nodes=sched)))))
        flow_gate.MAX_SCHEDULE_STARTS_PER_TENANT = 0
        check("too many scheduled starts is refused",
              "limit-schedule-starts" in codes(check_doc(doc(
                  eflow(), flow("s", nodes=sched)))))
        check("a draft's scheduled start does not count, since it never fires",
              "limit-schedule-starts" not in codes(check_doc(doc(
                  eflow(), flow("s"),
                  flow("s--draft", draft_of="s", nodes=sched)))))

        # The code default stays 0, which every tenant running an explicit cooldown of 0 relies on.
        flow_gate.MIN_CHECKIN_COOLDOWN_MINUTES = original[4]
        zero = [{"id": "s", "type": "start",
                 "params": {"kind": "checkin", "cooldown_minutes": 0},
                 "next": "e"}, {"id": "e", "type": "end"}]
        check("a zero cooldown passes on a deployment with no floor",
              "limit-checkin-cooldown" not in codes(check_doc(doc(
                  eflow(), flow("c", nodes=zero)))))
        flow_gate.MIN_CHECKIN_COOLDOWN_MINUTES = 5
        check("and is refused on one that sets a floor",
              "limit-checkin-cooldown" in codes(check_doc(doc(
                  eflow(), flow("c", nodes=zero)))))
    finally:
        (flow_gate.MAX_FLOWS_PER_TENANT, flow_gate.MAX_NODES_PER_FLOW,
         flow_gate.MAX_SCHEDULE_STARTS_PER_TENANT,
         flow_gate.MIN_SCHEDULE_INTERVAL_MINUTES,
         flow_gate.MIN_CHECKIN_COOLDOWN_MINUTES,
         flow_gate.MAX_DRAFTS_PER_TENANT) = original

    print("5g) acknowledging a finding")
    dep_break = doc(eflow(nodes=enroll_start))
    found = check_doc(dep_break, profiles=dep_profiles)
    check("a policy finding blocks by default", flow_gate.blocking(found))
    check("and lets the save through once it is acknowledged",
          flow_gate.blocking(found, {"enrollment-dep-await-no-release"}) == [])
    check("a shape finding ignores the acknowledgement",
          flow_gate.blocking(check_doc(gone), {"permanent-flow-deleted"}))


def main():
    schema_checks()
    scope_checks()
    default_flow_checks()
    validator_checks()
    gate_checks()
    print()
    if FAILED:
        print(f"FAILED ({len(FAILED)}): {FAILED}")
        return 1
    print("ALL ATC MULTI-FLOW CHECKS PASSED")
    return 0


if __name__ == "__main__":
    run(main)
