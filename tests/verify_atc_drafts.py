"""Verify the ATC flow drafts lifecycle: document surgery, secret handling and the invariants a draft has to satisfy
while it sits beside the flow it copies.

Run: PYTHONPATH=. ./.venv/bin/python tests/verify_atc_drafts.py

The first sections are pure document work over services.flow_drafts. The last one needs a database, because a draft
carries the same enrollment starts as the flow it copies, so services.atc executing one would provision every device
twice. services.atc._load_flows is the only place that filter lives.

Two things here are easy to get subtly wrong and are pinned deliberately. A draft's static passwords live on disk under
the draft's own flow id, because _restore_flow_secrets keys on (flow_id, node_id) and would otherwise drop the sentinel
the editor echoes back. And the diff compares authored values while reporting redacted ones:
redacting first would make a rotated password compare equal to itself.
"""

import copy
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests._verify_harness import run

FAILED = []


def check(desc: str, condition: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if condition else 'FAIL'}] {desc}" + (f": {detail}" if detail and not condition else ""))
    if not condition:
        FAILED.append(desc)


def document_checks():
    print("1) draft document surgery and invariants (flow_drafts.py)")

    from controller.services import flow_drafts, flow_gate, flow_step_catalog, atc
    from controller.api.main import (
        _iter_flow_nodes,
        _redact_flows_config,
        _redact_flows_history,
        _restore_flow_secrets,
    )

    v2_base: Dict[str, Any] = {
        "version": 2,
        "flows": [
            {
                "id": "enrollment",
                "name": "Enrollment Flow",
                "enabled": True,
                "permanent": True,
                "nodes": [
                    {
                        "id": "start-1",
                        "type": "start",
                        "params": {"kind": "enroll_dep"},
                        "next": "fw-1",
                    },
                    {
                        "id": "fw-1",
                        "type": "set_firmware_lock",
                        "params": {"password": "super-secret-password-123"},
                        "next": "rel-1",
                    },
                    {
                        "id": "rel-1",
                        "type": "release_device",
                        "next": "end-1",
                    },
                    {
                        "id": "end-1",
                        "type": "end",
                    },
                ],
            },
            {
                "id": "compliance",
                "name": "Daily Compliance",
                "enabled": True,
                "nodes": [
                    {
                        "id": "start-1",
                        "type": "start",
                        "params": {"kind": "schedule", "interval_minutes": 60},
                        "next": "end-1",
                    },
                    {
                        "id": "end-1",
                        "type": "end",
                    },
                ],
            },
        ],
    }

    # 1. Draft creation
    d1 = flow_drafts.create(v2_base, "enrollment", note="Updating firmware step", actor="admin@example.com",
                            at="2026-08-21T12:00:00Z")
    flows1 = d1["flows"]
    check("draft creation appends <target>--draft", any(f["id"] == "enrollment--draft" for f in flows1))

    draft_flow = next(f for f in flows1 if f["id"] == "enrollment--draft")
    check("draft carries draft_of pointing to target", draft_flow.get("draft_of") == "enrollment")
    check("draft carries draft_base_hash", bool(draft_flow.get("draft_base_hash")))
    check("draft carries draft_note and actor",
          draft_flow.get("draft_note") == "Updating firmware step" and draft_flow.get(
              "draft_created_by") == "admin@example.com")
    check("draft does not carry permanent flag", draft_flow.get("permanent") is None)
    check("target flow is untouched", any(f["id"] == "enrollment" and f["permanent"] is True for f in flows1))

    # Secret survival in draft (B1)
    fw_node = next(n for n in draft_flow["nodes"] if n["id"] == "fw-1")
    check("draft creation preserves plaintext secrets on disk",
          fw_node.get("params", {}).get("password") == "super-secret-password-123")

    # Draft creation errors
    try:
        flow_drafts.create(d1, "enrollment")
        check("duplicate draft creation raises 409", False)
    except flow_drafts.DraftError as e:
        check("duplicate draft creation raises 409", e.status == 409 and e.code == "draft-duplicate")

    try:
        flow_drafts.create(d1, "nonexistent")
        check("draft of nonexistent flow raises 404", False)
    except flow_drafts.DraftError as e:
        check("draft of nonexistent flow raises 404", e.status == 404)

    try:
        flow_drafts.create(d1, "enrollment--draft")
        check("draft of a draft raises 404", False)
    except flow_drafts.DraftError as e:
        check("draft of a draft raises 404", e.status == 404)

    print("\n2) secret redaction covers drafts (A8.11)")
    from controller.api.main import _REDACTED
    redacted = _redact_flows_config(d1)
    draft_r = next(f for f in redacted["flows"] if f["id"] == "enrollment--draft")
    fw_r = next(n for n in draft_r["nodes"] if n["id"] == "fw-1")
    check("redaction replaces draft password with sentinel", fw_r["params"]["password"] == _REDACTED)

    target_r = next(f for f in redacted["flows"] if f["id"] == "enrollment")
    fw_tr = next(n for n in target_r["nodes"] if n["id"] == "fw-1")
    check("redaction replaces target password with sentinel", fw_tr["params"]["password"] == _REDACTED)

    print("\n3) semantic diff (flow_drafts.diff)")
    # Add an account step to the draft and move one node's coordinates.
    draft_mod = copy.deepcopy(draft_flow)
    draft_mod["nodes"].append({
        "id": "acct-1",
        "type": "configure_accounts",
        "params": {"managed_admin_password": "new-admin-password"},
        "next": "end-1",
    })
    draft_mod["nodes"][0]["ui"] = {"x": 100, "y": 200}  # coordinate-only change

    diff_res = flow_drafts.diff(v2_base["flows"][0], draft_mod)
    check("diff identifies added node", diff_res["summary"]["added"] == 1)
    check("diff summary excludes coordinate moves", diff_res["summary"]["changed"] == 0)
    check("diff flags base_drifted as false initially", diff_res["base_drifted"] is False)

    print("\n4) base drift detection and force waiving (A8.14)")
    # Mutate live target in doc
    doc_with_drift = copy.deepcopy(d1)
    target_in_doc = next(f for f in doc_with_drift["flows"] if f["id"] == "enrollment")
    target_in_doc["name"] = "Renamed Live Enrollment"

    # Check diff sees drift
    diff_drift = flow_drafts.diff(target_in_doc, draft_flow)
    check("diff detects base drift when live target changes", diff_drift["base_drifted"] is True)

    # Promote without force fails
    try:
        flow_drafts.promote(doc_with_drift, "enrollment", force=False)
        check("promote on drifted base raises 409", False)
    except flow_drafts.DraftError as e:
        check("promote on drifted base raises 409", e.status == 409 and e.code == "draft-base-drift")

    # Promote with force succeeds in document surgery
    promoted_doc, summary = flow_drafts.promote(doc_with_drift, "enrollment", force=True)
    check("promote with force=True succeeds", any(f["id"] == "enrollment" for f in promoted_doc["flows"]))
    check("promoted document has draft removed", not any(f["id"] == "enrollment--draft" for f in promoted_doc["flows"]))
    # Promotion makes the two hashes agree again, so nothing downstream can tell afterwards whether force overrode a
    # real drift. The summary is where the audit row gets its answer.
    check("the summary says force overrode a real drift", summary["base_drifted"] is True)
    _, undrifted = flow_drafts.promote(d1, "enrollment", force=True)
    check("and says so honestly when there was nothing to override",
          undrifted["base_drifted"] is False)
    check("the node counts are still there beside it",
          set(undrifted) == {"added", "removed", "changed", "unchanged", "base_drifted"},
          str(sorted(undrifted)))

    print("\n5) gate finding split: advisory on draft vs blocking on promote (A8.14)")
    # Put an illegal node in draft (e.g. release_device inside compliance draft)
    d_comp = flow_drafts.create(v2_base, "compliance")
    comp_draft = next(f for f in d_comp["flows"] if f["id"] == "compliance--draft")
    comp_draft["nodes"].insert(1, {
        "id": "bad-rel",
        "type": "release_device",
        "next": "end-1",
    })
    findings = flow_gate.check_flows_document(d_comp, prior=v2_base)
    comp_findings = [f for f in findings if f.flow_id == "compliance--draft"]
    check("scoping violation on draft is marked advisory", all(f.advisory for f in comp_findings))
    check("advisory finding does not block draft save", len(flow_gate.blocking(findings)) == 0)

    # Promote candidate turns draft into target, where it becomes non-advisory and blocks
    cand_doc, _ = flow_drafts.promote(d_comp, "compliance")
    cand_findings = flow_gate.check_flows_document(cand_doc, prior=v2_base)
    check("same violation on promoted target blocks save", len(flow_gate.blocking(cand_findings)) > 0)

    print("\n6) scope borrowing for drafts")
    # Draft of enrollment flow borrows enrollment scope
    d_enr = flow_drafts.create(v2_base, "enrollment")
    enr_findings = flow_gate.check_flows_document(d_enr, prior=v2_base)
    check("release_device inside draft of enrollment flow is valid",
          not any(f.code == "enrollment-node-outside-enrollment-flow" for f in enr_findings))

    print("\n7) draft discard")
    discarded_doc = flow_drafts.discard(d1, "enrollment")
    check("discard removes draft", not any(f["id"] == "enrollment--draft" for f in discarded_doc["flows"]))
    check("target flow is retained", any(f["id"] == "enrollment" for f in discarded_doc["flows"]))

    try:
        flow_drafts.discard(discarded_doc, "enrollment")
        check("discarding nonexistent draft raises 404", False)
    except flow_drafts.DraftError as e:
        check("discarding nonexistent draft raises 404", e.status == 404)

    print("\n8) provisioning (atc_provision.py)")
    from controller.services import atc_provision

    check("ATC_PROVISION_EXISTING_TENANTS defaults to False", atc_provision.ATC_PROVISION_EXISTING_TENANTS is False)


def secret_round_trip_checks():
    """The sentinel the editor echoes back has to find the draft's own stored value. _restore_flow_secrets keys on
    (flow_id, node_id), and a draft's node ids are the target's, so dropping the flow id from that key would collide
    them."""
    print("\n9) a draft's secrets survive a save that never revealed them")
    from controller.api.main import _REDACTED, _restore_flow_secrets
    from controller.services import flow_drafts

    check("flow_drafts uses the same sentinel as the config API",
          flow_drafts.REDACTED == _REDACTED)

    base = Path(tempfile.mkdtemp())
    os.environ["YAML_CONFIG_PATH"] = str(base)
    tdir = base / "tenants" / "t-secrets"
    tdir.mkdir(parents=True)

    def node(pw):
        return {"id": "fw-1", "type": "set_firmware_lock",
                "params": {"password_source": "static", "password": pw}}

    on_disk = {"version": 2, "flows": [
        {"id": "enrollment", "name": "E", "permanent": True, "nodes": [node("LIVE-PW")]},
        {"id": "enrollment--draft", "name": "E", "draft_of": "enrollment",
         "nodes": [node("DRAFT-PW")]},
    ]}
    (tdir / "flows.yaml").write_text(yaml.safe_dump(on_disk))

    incoming = copy.deepcopy(on_disk)
    for flow in incoming["flows"]:
        flow["nodes"][0]["params"]["password"] = _REDACTED
    _restore_flow_secrets("t-secrets", incoming)
    live_pw = incoming["flows"][0]["nodes"][0]["params"]["password"]
    draft_pw = incoming["flows"][1]["nodes"][0]["params"]["password"]
    check("the live flow gets its own password back", live_pw == "LIVE-PW")
    check("the draft gets its own, not the flow it was copied from",
          draft_pw == "DRAFT-PW")

    # A draft created without its own copy on disk has nothing under (draft_id, node_id), so the sentinel is dropped
    # rather than resolved.
    orphan = {"version": 2, "flows": [
        {"id": "enrollment", "name": "E", "permanent": True, "nodes": [node("LIVE-PW")]},
    ]}
    (tdir / "flows.yaml").write_text(yaml.safe_dump(orphan))
    incoming = {"version": 2, "flows": [
        {"id": "enrollment--draft", "name": "E", "draft_of": "enrollment",
         "nodes": [node(_REDACTED)]},
    ]}
    _restore_flow_secrets("t-secrets", incoming)
    check("a draft with nothing stored under its own id loses the sentinel "
          "rather than inheriting somebody else's password",
          "password" not in incoming["flows"][0]["nodes"][0]["params"])

    from controller.api.main import _redact_flows_history
    snapshot = _redact_flows_history(yaml.safe_dump(on_disk))
    check("a history snapshot redacts the draft too",
          "DRAFT-PW" not in snapshot and "LIVE-PW" not in snapshot)


def diff_secret_checks():
    print("\n10) the diff reports a rotated secret without revealing it")
    from controller.services import flow_drafts

    def flow(fid, pw, **extra):
        doc = {"id": fid, "name": "F", "nodes": [
            {"id": "fw-1", "type": "set_firmware_lock",
             "params": {"password_source": "static", "password": pw}}]}
        doc.update(extra)
        return doc

    target = flow("f", "OLD-PW")
    draft = flow("f--draft", "NEW-PW", draft_of="f")
    d = flow_drafts.diff(target, draft)
    check("a rotated password counts as a change", d["summary"]["changed"] == 1)
    entry = next((n for n in d["nodes"] if n["id"] == "fw-1"), None)
    params_diff = (entry or {}).get("params_diff") or {}
    check("and is reported as sentinel to sentinel",
          params_diff.get("password") == {"from": flow_drafts.REDACTED,
                                          "to": flow_drafts.REDACTED})
    check("neither value appears anywhere in the payload",
          "OLD-PW" not in repr(d) and "NEW-PW" not in repr(d))

    same = flow_drafts.diff(target, flow("f--draft", "OLD-PW", draft_of="f"))
    check("an unchanged password is not reported as a change",
          same["summary"]["changed"] == 0)

    added = flow_drafts.diff(
        {"id": "f", "name": "F", "nodes": []},
        flow("f--draft", "NEW-PW", draft_of="f"))
    node_entry = added["nodes"][0]
    check("an added node's secret is redacted too",
          node_entry["params"]["password"] == flow_drafts.REDACTED
          and "NEW-PW" not in repr(added))


def legacy_document_checks():
    """A tenant that has not saved through the multi-flow editor still has the single-flow document on disk. The draft
    endpoints read the flow list, so without normalization on the way in they hand those tenants an empty list and 404
    every draft operation."""
    print("\n11) drafts work on a document that predates the v2 shape")
    from controller.api.main import _flows_document
    from controller.services import flow_drafts, tenant_config

    base = Path(tempfile.mkdtemp())
    os.environ["YAML_CONFIG_PATH"] = str(base)
    tdir = base / "tenants" / "t-legacy"
    tdir.mkdir(parents=True)

    v1 = {"flow": {"id": "onboarding", "name": "Onboarding", "enabled": True,
                   "nodes": [{"id": "s", "type": "start",
                              "params": {"kind": "enroll_dep"}, "next": "e"},
                             {"id": "e", "type": "end"}]}}
    (tdir / "flows.yaml").write_text(yaml.safe_dump(v1))
    tenant_config.invalidate("t-legacy")

    doc = _flows_document("t-legacy")
    check("a single-flow document reads as a v2 document",
          doc.get("version") == 2 and [f["id"] for f in doc["flows"]] == ["onboarding"])
    check("and its flow is the permanent one",
          doc["flows"][0].get("permanent") is True)

    created = flow_drafts.create(doc, "onboarding", note="n", actor="a", at="t")
    check("a draft can be created against it",
          "onboarding--draft" in [f["id"] for f in created["flows"]])
    promoted, _summary = flow_drafts.promote(created, "onboarding")
    check("and promoted back",
          [f["id"] for f in promoted["flows"]] == ["onboarding"]
          and promoted["flows"][0].get("permanent") is True)
    check("the stale single-flow key is not carried into the write",
          "flow" not in promoted)

    v0 = {"flows": [{"id": "old", "name": "Old", "start": "a", "trigger": {},
                     "nodes": [{"id": "a", "type": "end"}]}]}
    (tdir / "flows.yaml").write_text(yaml.safe_dump(v0))
    tenant_config.invalidate("t-legacy")
    doc = _flows_document("t-legacy")
    check("the original list shape reads as v2 as well",
          [f["id"] for f in doc["flows"]] == ["old"])


def setup_script_checks():
    """setup.sh scaffolds flows.yaml with a literal heredoc, because it runs before there is a controller to ask. That
    makes it a second source of truth for the default enrollment flow, and it has drifted before: one copy carried a
    dead gate key and offered a "Keep waiting" option wired to the release step, which would have released the device.
    """
    print("\n12) setup.sh scaffolds exactly the generated default flow")
    import re

    from controller.services.flow_step_catalog import default_enrollment_flow

    src = (Path(__file__).resolve().parent.parent / "setup.sh").read_text()
    blocks = re.findall(
        r"cat > \"\$\{?\w+\}?/flows\.yaml\"\s*<< 'EOF'\n(.*?)\nEOF", src, re.S)
    check("setup.sh scaffolds flows.yaml in both tenant paths", len(blocks) == 2)
    expected = {"version": 2, "flows": [default_enrollment_flow()]}
    for i, block in enumerate(blocks):
        try:
            parsed = yaml.safe_load(block)
        except yaml.YAMLError as exc:
            check(f"setup.sh heredoc {i} parses", False, str(exc))
            continue
        check(f"setup.sh heredoc {i} is the generated default flow",
              parsed == expected)


async def engine_checks():
    """The property no document test can reach: services.atc never runs a draft."""
    print("\n13) a draft never runs, on any trigger")
    from tortoise import Tortoise

    base = Path(tempfile.mkdtemp())
    os.environ["YAML_CONFIG_PATH"] = str(base)
    tdir = base / "tenants" / "default"
    tdir.mkdir(parents=True)
    (tdir / "config.yaml").write_text(yaml.safe_dump(
        {"tenant": {"id": "default", "name": "D", "allowed_users": ["a@b.c"]}}))
    for name in ("groups", "apps", "profiles"):
        (tdir / f"{name}.yaml").write_text(yaml.safe_dump({name: []}))

    def flow(fid, kind, **extra):
        params = {"kind": kind}
        if kind == "schedule":
            params["interval_minutes"] = 60
        doc = {"id": fid, "name": fid, "nodes": [
            {"id": "start-1", "type": "start", "params": params, "next": "tag-1"},
            {"id": "tag-1", "type": "assign_tag", "params": {"tags": [fid]},
             "next": "end-1"},
            {"id": "end-1", "type": "end"}]}
        doc.update(extra)
        return doc

    # Every flow below carries the same start node id, which is what the editor mints, and the draft carries the same
    # enrollment trigger as the flow it copies. Those are the two collisions the composite run identity and the draft
    # filter have to survive.
    (tdir / "flows.yaml").write_text(yaml.safe_dump({"version": 2, "flows": [
        flow("enrollment", "enroll_dep", permanent=True),
        flow("enrollment--draft", "enroll_dep", draft_of="enrollment"),
        flow("sweeper", "schedule"),
        flow("sweeper--draft", "schedule", draft_of="sweeper"),
        flow("off", "enroll_dep", enabled=False),
    ]}))

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()
    from controller.models.tenant import Device, FlowRun, Tenant
    from controller.services import atc
    import controller.services.reconciler as rec
    rec.request_reconcile = lambda tenant_id: None

    tenant = await Tenant.create(id="default", name="Default")
    dev = await Device.create(
        tenant=tenant, udid="UDID-DRAFT-1", serial_number="DRAFT-1",
        device_model="MacBookPro18,3", os_version="14.5", hostname="h",
        enrollment_state="enrolled", groups=[], tags=[])

    loaded = [f["id"] for f in atc._load_flows("default")]
    check("_load_flows hides every draft and shows the rest",
          loaded == ["enrollment", "sweeper", "off"], str(loaded))
    check("permanent flow first", loaded and loaded[0] == "enrollment")
    check("_load_flow can still fetch a draft by id",
          (atc._load_flow("default", "enrollment--draft") or {}).get("draft_of")
          == "enrollment")

    runs = await atc.start_flows_for_event(dev, "enroll_dep")
    check("one enroll starts exactly one run", len(runs) == 1, str(len(runs)))
    check("and it is the live flow, not the draft",
          all(r.flow_id == "enrollment" for r in runs))
    await dev.refresh_from_db()
    check("the draft's steps never touched the device",
          "enrollment--draft" not in (dev.tags or []))
    check("a disabled flow did not run either",
          "off" not in (dev.tags or []))

    launched = await atc.sweep_scheduled_starts(tenant, [dev])
    check("the schedule sweep launches the live flow once", launched == 1)
    sweeper_runs = await FlowRun.filter(device_id=dev.id,
                                        flow_id__startswith="sweeper").all()
    check("and records nothing against the draft",
          {r.flow_id for r in sweeper_runs} == {"sweeper"})

    # A draft that somebody hand-edited to enabled: true is still inert. The filter is on draft_of, deliberately ahead
    # of the enabled check.
    doc = yaml.safe_load((tdir / "flows.yaml").read_text())
    for f in doc["flows"]:
        if f["id"] == "enrollment--draft":
            f["enabled"] = True
    (tdir / "flows.yaml").write_text(yaml.safe_dump(doc))
    from controller.services import tenant_config
    tenant_config.invalidate("default")
    dev2 = await Device.create(
        tenant=tenant, udid="UDID-DRAFT-2", serial_number="DRAFT-2",
        device_model="MacBookPro18,3", os_version="14.5", hostname="h2",
        enrollment_state="enrolled", groups=[], tags=[])
    runs2 = await atc.start_flows_for_event(dev2, "enroll_dep")
    check("a draft marked enabled by hand is still inert",
          len(runs2) == 1 and runs2[0].flow_id == "enrollment")

    print("\n14) promotion leaves runs alone")
    from controller.services import flow_drafts
    before = await FlowRun.filter(device_id=dev.id, flow_id="enrollment").count()
    promoted, summary = flow_drafts.promote(
        yaml.safe_load((tdir / "flows.yaml").read_text()), "enrollment")
    (tdir / "flows.yaml").write_text(yaml.safe_dump(promoted))
    tenant_config.invalidate("default")
    after = await FlowRun.filter(device_id=dev.id, flow_id="enrollment").count()
    check("a promotion keeps the target's id, so its run history survives",
          after == before and before > 0)
    check("the draft is gone from the document",
          "enrollment--draft" not in [f["id"] for f in promoted["flows"]])
    check("the target keeps permanent and enabled",
          next(f for f in promoted["flows"] if f["id"] == "enrollment")
          .get("permanent") is True)

    pinned = (runs[0].context or {}).get("flow") or {}
    check("an already-started run still holds its own pinned definition",
          pinned.get("id") == "enrollment" or runs[0].status in
          ("completed", "failed", "cancelled"))

    print("\n15) the flow summary the switcher is built on")
    # Nothing else calls this endpoint, so nothing else would catch a bad query in it.
    from controller.api.main import get_flows_summary
    from controller.auth.dependencies import Principal
    from controller.models.tenant import User

    user = await User.create(tenant=tenant, email="member@default", role="member")
    member = Principal(tenant=tenant, user=user, email="member@default", role="member")
    summary = await get_flows_summary(member)
    by_id = {f["id"]: f for f in summary["flows"]}
    # Drafts are in the summary on purpose, along with the note, author and age a caller needs to flag a stale one.
    check("it answers for every flow, drafts included",
          set(by_id) == {"enrollment", "sweeper", "off", "sweeper--draft"},
          str(sorted(by_id)))
    check("and marks which of them are drafts",
          by_id["sweeper--draft"]["draft_of"] == "sweeper"
          and by_id["sweeper"]["draft_of"] is None)
    check("it reports the triggers a flow actually starts on",
          by_id["enrollment"]["start_kinds"] == ["enroll_dep"],
          str(by_id["enrollment"]["start_kinds"]))
    check("it counts the runs in the window",
          by_id["enrollment"]["runs_in_window"] >= 1)
    check("it names the permanent flow", by_id["enrollment"]["permanent"] is True)
    check("it reports the retention horizon, so an empty window can be explained",
          isinstance(summary.get("retention_days"), int))
    check("and the deployment limits the switcher shows usage against",
          summary["limits"]["max_flows_per_tenant"] > 0)
    check("a flow that has never run reports zero rather than nothing",
          by_id["off"]["runs_in_window"] == 0
          and by_id["off"]["last_run_at"] is None)

    print("\n17) a promotion records what it overrode")
    # The audit row is the only trace an override leaves, so it has to record what was actually overridden. A client may
    # send force on every promotion and acknowledge whatever it had on screen, so neither is evidence that a refusal was
    # walked past.
    from fastapi import HTTPException
    from controller.api.main import PromoteDraftRequest, promote_flow_draft
    from controller.models.tenant import AuditLog

    admin_user = await User.create(tenant=tenant, email="admin@default", role="admin")
    admin = Principal(tenant=tenant, user=admin_user, email="admin@default",
                      role="admin")

    async def promotion_detail(target):
        row = await AuditLog.filter(action="flow.promote_draft",
                                    target_id=target).first()
        return dict(row.detail or {}) if row else {}

    # 'off' starts on enrollment without being the enrollment flow, which every promotion below would otherwise have to
    # acknowledge past.
    (tdir / "flows.yaml").write_text(yaml.safe_dump({"version": 2, "flows": [
        flow("enrollment", "enroll_dep", permanent=True),
        flow("sweeper", "schedule"),
        flow("sweeper--draft", "schedule", draft_of="sweeper"),
    ]}))
    tenant_config.invalidate("default")

    # sweeper--draft was written by hand and carries no base hash, so force has nothing to waive here.
    await promote_flow_draft("sweeper", PromoteDraftRequest(force=True), admin)
    detail = await promotion_detail("sweeper")
    check("force with nothing to override is recorded as exactly that",
          detail.get("force") is True and detail.get("base_drifted") is False
          and detail.get("acknowledged") == [], str(detail))

    # Now one that has to get past both refusals: the live flow moved after the draft was taken, and the content coming
    # in trips a policy finding.
    drifted = flow_drafts.create(
        yaml.safe_load((tdir / "flows.yaml").read_text()), "enrollment",
        note="", actor="admin@default", at="")
    next(f for f in drifted["flows"]
         if f["id"] == "enrollment--draft")["nodes"][0]["params"] = {"kind": "checkin"}
    next(f for f in drifted["flows"]
         if f["id"] == "enrollment")["description"] = "edited after the draft"
    (tdir / "flows.yaml").write_text(yaml.safe_dump(drifted))
    tenant_config.invalidate("default")

    try:
        await promote_flow_draft("enrollment", PromoteDraftRequest(), admin)
        check("a drifted base stops the promotion", False)
    except HTTPException as exc:
        check("a drifted base stops the promotion", exc.status_code == 409)
    try:
        await promote_flow_draft("enrollment", PromoteDraftRequest(force=True), admin)
        check("and force does not carry the gate finding through with it", False)
    except HTTPException as exc:
        check("and force does not carry the gate finding through with it",
              exc.status_code == 400)

    await promote_flow_draft(
        "enrollment",
        PromoteDraftRequest(force=True,
                            acknowledge=["enrollment-no-start", "nothing-raised-this"]),
        admin)
    detail = await promotion_detail("enrollment")
    check("the row names the finding the acknowledgement actually waived",
          detail.get("acknowledged") == ["enrollment-no-start"], str(detail))
    check("and that force overrode a real drift",
          detail.get("force") is True and detail.get("base_drifted") is True,
          str(detail))
    check("the draft note and the change summary are still there",
          "draft_note" in detail and "summary" in detail, str(detail))

    print("\n18) a pre-existing finding does not block an unrelated promotion")
    # 'rogue' starts on enrollment without being the enrollment flow, a blocking finding already in the document before
    # the promotion touched anything. Only what the promotion introduces may refuse it.
    (tdir / "flows.yaml").write_text(yaml.safe_dump({"version": 2, "flows": [
        flow("enrollment", "enroll_dep", permanent=True),
        flow("rogue", "enroll_dep"),
        flow("sweeper", "schedule"),
        flow("sweeper--draft", "schedule", draft_of="sweeper"),
    ]}))
    tenant_config.invalidate("default")
    res = await promote_flow_draft("sweeper", PromoteDraftRequest(), admin)
    check("the promotion goes through past the stranger's finding",
          res.get("promoted") is True, str(res))
    codes = {f.get("code") for f in res.get("gate_findings", [])}
    check("and that finding is still reported, so nothing is hidden",
          "enrollment-trigger-outside-enrollment-flow" in codes, str(codes))

    await Tortoise.close_connections()


def unfinished_draft_checks():
    print()
    print("16) an unfinished draft saves, and only a draft does")

    from controller.utils.yaml_validator import YAMLValidator

    # Half-wired: a start with nowhere to go and no end anywhere. On a live flow that is several errors from
    # _flow_edges and _check_flow_graph.
    unfinished = [
        {"id": "start-1", "type": "start", "params": {"kind": "checkin"}},
    ]

    def validate(flows):
        with tempfile.TemporaryDirectory() as td:
            tdir = Path(td)
            (tdir / "config.yaml").write_text(yaml.safe_dump(
                {"tenant": {"id": "t1", "name": "T1", "allowed_users": ["a@t1"]}}))
            (tdir / "groups.yaml").write_text(yaml.safe_dump({"groups": []}))
            (tdir / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
            (tdir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": []}))
            (tdir / "flows.yaml").write_text(yaml.safe_dump({"version": 2, "flows": flows}))
            return YAMLValidator(tdir).validate_all()

    live = {"id": "sweeper", "name": "Sweeper", "permanent": True,
            "nodes": [{"id": "s", "type": "start", "params": {"kind": "checkin"}, "next": "e"},
                      {"id": "e", "type": "end"}]}

    valid, errors, warnings = validate([live, {
        "id": "sweeper--draft", "name": "Sweeper", "draft_of": "sweeper", "nodes": unfinished}])
    check("an unfinished draft does not block the save", valid, str(errors))
    check("and its problems are still reported, as warnings",
          any("sweeper--draft" in w and "does not block" in w for w in warnings),
          str(warnings))
    check("with nothing said against the live flow",
          not any("'sweeper'" in e for e in errors), str(errors))

    valid, errors, _ = validate([{**live, "nodes": unfinished}])
    check("the same shape on a live flow is still an error", not valid)
    check("because that one is what devices run",
          any("sweeper" in e for e in errors), str(errors))


async def main():
    document_checks()
    secret_round_trip_checks()
    diff_secret_checks()
    legacy_document_checks()
    setup_script_checks()
    unfinished_draft_checks()
    await engine_checks()
    print()
    if FAILED:
        print(f"FAILED ({len(FAILED)}): {FAILED}")
        return 1
    print("ALL ATC DRAFTS CHECKS PASSED")
    return 0


if __name__ == "__main__":
    run(main)
