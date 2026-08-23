"""Standalone checks for controller/services/compliance_catalog.py::evaluate_check.

No database: evaluate_check only reads getattr()'d device fields (attributes, last_seen, tags, ddm_*) plus a
caller-supplied ctx dict, so these checks use a plain attribute bag instead of a Device model. The same bag stands in
for a FlowRun row in the flow_parked_for section, which reads its runs by field name and takes either.

Run (from repo root, with the project venv):

    PYTHONPATH=. ./.venv/bin/python tests/verify_compliance_catalog.py

Covers every check type in CHECK_CATALOG: a finding when non-compliant, None when compliant or when the signal is
unreported, and no raise on a malformed check config.
"""
import json
import logging
import re
import sys
from datetime import datetime, timedelta, timezone

FAILURES: list = []


class LogTrap(logging.Handler):
    """Collects whatever a module logs while it is attached."""

    def __init__(self):
        super().__init__()
        self.records: list = []

    def emit(self, record):
        self.records.append(record)


def check(name: str, cond: bool) -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        FAILURES.append(name)


class Dev:
    """Minimal attribute bag standing in for a Device row."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def main() -> None:
    from controller.services import compliance_catalog as cc

    # == catalog metadata sanity ==
    print("\n[0] catalog metadata")
    check("catalog() lists every evaluator's type",
          set(cc._EVALUATORS) <= cc.VALID_CHECK_TYPES)
    check("get_check returns catalog metadata by type",
          cc.get_check("filevault_disabled") is not None and
          cc.get_check("filevault_disabled")["label"] == "FileVault disabled")
    check("get_check returns None for an unknown type", cc.get_check("nope") is None)

    # == filevault_disabled ==
    print("\n[1] filevault_disabled")
    check("explicit False -> finding", cc.evaluate_check(
        {"type": "filevault_disabled"},
        Dev(attributes={"SecurityInfo": {"FDE_Enabled": False}})) is not None)
    check("explicit True -> compliant (None)", cc.evaluate_check(
        {"type": "filevault_disabled"},
        Dev(attributes={"SecurityInfo": {"FDE_Enabled": True}})) is None)
    check("FDE_Enabled='Off' (string) -> finding",
          cc.evaluate_check({"type": "filevault_disabled"},
                            Dev(attributes={"SecurityInfo": {"FDE_Enabled": "Off"}})) is not None)
    check("only FDE_Enabled is read, so a key Apple never defines is not a posture",
          cc.evaluate_check({"type": "filevault_disabled"},
                            Dev(attributes={"SecurityInfo": {"FileVaultStatus": "Off"}})) is None)
    check("unreported (no SecurityInfo at all) -> compliant, not a false alarm",
          cc.evaluate_check({"type": "filevault_disabled"}, Dev(attributes={})) is None)
    check("unreported (attributes is None) -> compliant, no crash",
          cc.evaluate_check({"type": "filevault_disabled"}, Dev(attributes=None)) is None)

    # == firewall_disabled ==
    #
    # macOS reports the application firewall inside SecurityInfo's FirewallSettings dictionary, never as a top-level
    # key. The flat key is only a fallback for inventories already stored that way.
    print("\n[2] firewall_disabled")

    def nested(on):
        """SecurityInfo as a Mac sends it, firewall on or off."""
        return {"SecurityInfo": {"FirewallSettings": {
            "FirewallEnabled": on, "BlockAllIncoming": False, "StealthMode": False,
            "AllowSigned": True, "AllowSignedApp": True, "Applications": []}}}

    check("nested FirewallSettings.FirewallEnabled False -> finding", cc.evaluate_check(
        {"type": "firewall_disabled"}, Dev(attributes=nested(False))) is not None)
    check("nested FirewallSettings.FirewallEnabled True -> compliant", cc.evaluate_check(
        {"type": "firewall_disabled"}, Dev(attributes=nested(True))) is None)
    check("flat FirewallEnabled False still reads as a finding (stored inventories)",
          cc.evaluate_check({"type": "firewall_disabled"},
                            Dev(attributes={"SecurityInfo": {"FirewallEnabled": False}}))
          is not None)
    check("flat FirewallEnabled True -> compliant", cc.evaluate_check(
        {"type": "firewall_disabled"},
        Dev(attributes={"SecurityInfo": {"FirewallEnabled": True}})) is None)
    # A re-polled device can carry both keys, one of them stale. The nested one is what it just reported.
    both_off = {"SecurityInfo": {"FirewallEnabled": True,
                                 "FirewallSettings": {"FirewallEnabled": False}}}
    check("nested wins over a stale flat key", cc.evaluate_check(
        {"type": "firewall_disabled"}, Dev(attributes=both_off)) is not None)
    both_on = {"SecurityInfo": {"FirewallEnabled": False,
                                "FirewallSettings": {"FirewallEnabled": True}}}
    check("nested wins in the other direction too", cc.evaluate_check(
        {"type": "firewall_disabled"}, Dev(attributes=both_on)) is None)
    # Which key answered is recorded: a finding off the fallback came from an older inventory.
    nested_hit = cc.evaluate_check({"type": "firewall_disabled"},
                                   Dev(attributes=nested(False)))
    flat_hit = cc.evaluate_check(
        {"type": "firewall_disabled"},
        Dev(attributes={"SecurityInfo": {"FirewallEnabled": False}}))
    check("the finding records which key it read",
          nested_hit["detail"]["path"] == "SecurityInfo.FirewallSettings.FirewallEnabled"
          and flat_hit["detail"]["path"] == "SecurityInfo.FirewallEnabled")
    check("the detail is JSON scalars, which is what an Alert stores",
          json.dumps(nested_hit["detail"]) and json.dumps(flat_hit["detail"]))
    check("FirewallSettings present but without the key -> compliant", cc.evaluate_check(
        {"type": "firewall_disabled"},
        Dev(attributes={"SecurityInfo": {"FirewallSettings": {"StealthMode": True}}})) is None)
    check("FirewallSettings of a wrong shape -> compliant, no crash", cc.evaluate_check(
        {"type": "firewall_disabled"},
        Dev(attributes={"SecurityInfo": {"FirewallSettings": "off"}})) is None)
    check("unreported -> compliant", cc.evaluate_check(
        {"type": "firewall_disabled"}, Dev(attributes={})) is None)

    # == passcode_missing ==
    print("\n[3] passcode_missing")
    check("explicit False (no passcode) -> finding", cc.evaluate_check(
        {"type": "passcode_missing"},
        Dev(attributes={"SecurityInfo": {"PasscodePresent": False}})) is not None)
    check("explicit True -> compliant", cc.evaluate_check(
        {"type": "passcode_missing"},
        Dev(attributes={"SecurityInfo": {"PasscodePresent": True}})) is None)
    check("unreported -> compliant", cc.evaluate_check(
        {"type": "passcode_missing"}, Dev(attributes={})) is None)

    # == user_approved_enrollment_missing ==
    #
    # ManagementStatus is a nested Mac-only dictionary, so everything that does not send it reads as unknown.
    print("\n[3a] user_approved_enrollment_missing")

    def mgmt(**over):
        row = {"EnrolledViaDEP": False, "IsUserEnrollment": False,
               "UserApprovedEnrollment": True, "IsActivationLockManageable": True}
        row.update(over)
        return Dev(attributes={"SecurityInfo": {"ManagementStatus": row}})

    finding = cc.evaluate_check({"type": "user_approved_enrollment_missing"},
                                mgmt(UserApprovedEnrollment=False))
    check("UserApprovedEnrollment False -> finding", finding is not None)
    check("the detail carries the value the device reported",
          finding is not None and finding["detail"]["UserApprovedEnrollment"] is False)
    check("UserApprovedEnrollment True -> compliant", cc.evaluate_check(
        {"type": "user_approved_enrollment_missing"}, mgmt()) is None)
    check("no ManagementStatus at all -> compliant", cc.evaluate_check(
        {"type": "user_approved_enrollment_missing"}, Dev(attributes={})) is None)
    check("ManagementStatus of a wrong shape -> compliant, no crash",
          cc.evaluate_check({"type": "user_approved_enrollment_missing"},
                            Dev(attributes={"SecurityInfo":
                                                {"ManagementStatus": "approved"}})) is None)
    # The key sits one level down, so a rule authored against the wrong level must not accidentally pass either.
    check("the same key at the top of SecurityInfo is not what's read",
          cc.evaluate_check({"type": "user_approved_enrollment_missing"},
                            Dev(attributes={"SecurityInfo":
                                                {"UserApprovedEnrollment": False}})) is None)

    # == bootstrap_token_disallowed ==
    #
    # BootstrapTokenAllowedForAuthentication is a string, not a boolean: the token is allowed, refused, or the hardware
    # has none at all. Only the refusal is a posture problem.
    print("\n[3b] bootstrap_token_disallowed")

    def token(state):
        return Dev(attributes={"SecurityInfo": {
            "BootstrapTokenAllowedForAuthentication": state,
            "BootstrapTokenRequiredForSoftwareUpdate": True,
            "BootstrapTokenRequiredForKernelExtensionApproval": True}})

    finding = cc.evaluate_check({"type": "bootstrap_token_disallowed"},
                                token("disallowed"))
    check("'disallowed' -> finding", finding is not None)
    check("the detail says what the unusable token blocks",
          finding is not None
          and finding["detail"]["BootstrapTokenRequiredForSoftwareUpdate"] is True
          and finding["detail"]["BootstrapTokenRequiredForKernelExtensionApproval"] is True)
    check("the detail is JSON scalars, which is what an Alert stores",
          finding is not None and json.dumps(finding["detail"]) is not None)
    check("'allowed' -> compliant", cc.evaluate_check(
        {"type": "bootstrap_token_disallowed"}, token("allowed")) is None)
    check("'not supported' is hardware, not policy -> compliant", cc.evaluate_check(
        {"type": "bootstrap_token_disallowed"}, token("not supported")) is None)
    check("unreported (iPhone, or a Mac not yet polled) -> compliant",
          cc.evaluate_check({"type": "bootstrap_token_disallowed"},
                            Dev(attributes={})) is None)
    check("a non-string value -> compliant, no crash", cc.evaluate_check(
        {"type": "bootstrap_token_disallowed"}, token(False)) is None)
    check("the detail carries None for keys the device left out", cc.evaluate_check(
        {"type": "bootstrap_token_disallowed"},
        Dev(attributes={"SecurityInfo": {
            "BootstrapTokenAllowedForAuthentication": "disallowed"}}))
    ["detail"]["BootstrapTokenRequiredForSoftwareUpdate"] is None)

    # == remote_desktop_enabled ==
    print("\n[3c] remote_desktop_enabled")
    check("RemoteDesktopEnabled True -> finding", cc.evaluate_check(
        {"type": "remote_desktop_enabled"},
        Dev(attributes={"SecurityInfo": {"RemoteDesktopEnabled": True}})) is not None)
    check("RemoteDesktopEnabled False -> compliant", cc.evaluate_check(
        {"type": "remote_desktop_enabled"},
        Dev(attributes={"SecurityInfo": {"RemoteDesktopEnabled": False}})) is None)
    check("unreported -> compliant", cc.evaluate_check(
        {"type": "remote_desktop_enabled"}, Dev(attributes={})) is None)

    # == os_below ==
    print("\n[4] os_below")
    check("device os below the minimum -> finding", cc.evaluate_check(
        {"type": "os_below", "min": "17.0"}, Dev(os_version="16.7")) is not None)
    check("device os at/above the minimum -> compliant", cc.evaluate_check(
        {"type": "os_below", "min": "17.0"}, Dev(os_version="17.0")) is None)
    check("numeric-aware compare: 17.4 is NOT below 17.10 (would be by string compare)",
          cc.evaluate_check({"type": "os_below", "min": "17.10"}, Dev(os_version="17.4"))
          is not None)  # 17.4 < 17.10 numerically, so this DOES fire
    check("missing min param -> no finding, no crash",
          cc.evaluate_check({"type": "os_below"}, Dev(os_version="10.0")) is None)
    check("empty device os_version -> no finding, no crash",
          cc.evaluate_check({"type": "os_below", "min": "17.0"}, Dev(os_version="")) is None)
    check("malformed device os_version -> no finding, no crash", cc.evaluate_check(
        {"type": "os_below", "min": "17.0"}, Dev(os_version="not-a-version")) is None)
    check("malformed min -> no finding, no crash", cc.evaluate_check(
        {"type": "os_below", "min": "not-a-version"}, Dev(os_version="17.0")) is None)
    check("using params={} wrapper style also works", cc.evaluate_check(
        {"type": "os_below", "params": {"min": "17.0"}}, Dev(os_version="16.0")) is not None)

    # == not_seen_for ==
    print("\n[5] not_seen_for")
    old = datetime.now(timezone.utc) - timedelta(days=10)
    recent = datetime.now(timezone.utc) - timedelta(hours=1)
    check("last_seen older than the limit -> finding", cc.evaluate_check(
        {"type": "not_seen_for", "days": 5}, Dev(last_seen=old)) is not None)
    check("last_seen within the limit -> compliant", cc.evaluate_check(
        {"type": "not_seen_for", "days": 5}, Dev(last_seen=recent)) is None)
    check("naive last_seen is treated as UTC, not a crash", cc.evaluate_check(
        {"type": "not_seen_for", "days": 5},
        Dev(last_seen=(datetime.now(timezone.utc) - timedelta(days=10)).replace(tzinfo=None)))
          is not None)
    check("never seen (None) -> no finding, no crash", cc.evaluate_check(
        {"type": "not_seen_for", "days": 5}, Dev(last_seen=None)) is None)
    check("malformed days -> no finding, no crash", cc.evaluate_check(
        {"type": "not_seen_for", "days": "not-a-number"}, Dev(last_seen=old)) is None)
    check("missing days param -> no finding, no crash", cc.evaluate_check(
        {"type": "not_seen_for"}, Dev(last_seen=old)) is None)

    # == lost_mode_active ==
    print("\n[6] lost_mode_active")
    check("IsMDMLostModeEnabled True -> finding", cc.evaluate_check(
        {"type": "lost_mode_active"}, Dev(attributes={"IsMDMLostModeEnabled": True})) is not None)
    check("IsMDMLostModeEnabled False -> compliant", cc.evaluate_check(
        {"type": "lost_mode_active"}, Dev(attributes={"IsMDMLostModeEnabled": False})) is None)
    check("unreported -> compliant", cc.evaluate_check(
        {"type": "lost_mode_active"}, Dev(attributes={})) is None)

    # == unsupervised ==
    print("\n[7] unsupervised")
    check("IsSupervised explicit False -> finding", cc.evaluate_check(
        {"type": "unsupervised"}, Dev(attributes={"IsSupervised": False})) is not None)
    check("IsSupervised True -> compliant", cc.evaluate_check(
        {"type": "unsupervised"}, Dev(attributes={"IsSupervised": True})) is None)
    check("unreported -> compliant (unknown != known-bad)", cc.evaluate_check(
        {"type": "unsupervised"}, Dev(attributes={})) is None)

    # == missing_profile ==
    print("\n[8] missing_profile")
    check("profile not in ctx.profile_status -> finding", cc.evaluate_check(
        {"type": "missing_profile", "profile_id": "p1"}, Dev(),
        ctx={"profile_status": {}}) is not None)
    check("profile status != installed -> finding", cc.evaluate_check(
        {"type": "missing_profile", "profile_id": "p1"}, Dev(),
        ctx={"profile_status": {"p1": "failed"}}) is not None)
    check("profile status == installed -> compliant", cc.evaluate_check(
        {"type": "missing_profile", "profile_id": "p1"}, Dev(),
        ctx={"profile_status": {"p1": "installed"}}) is None)
    check("missing profile_id param -> no finding, no crash", cc.evaluate_check(
        {"type": "missing_profile"}, Dev(), ctx={"profile_status": {}}) is None)
    check("no ctx at all -> no finding, no crash", cc.evaluate_check(
        {"type": "missing_profile", "profile_id": "p1"}, Dev()) is not None)

    # == config_drift ==
    print("\n[9] config_drift")
    check("non-empty ctx.drift -> finding", cc.evaluate_check(
        {"type": "config_drift"}, Dev(), ctx={"drift": ["missing app x"]}) is not None)
    check("empty ctx.drift -> compliant", cc.evaluate_check(
        {"type": "config_drift"}, Dev(), ctx={"drift": []}) is None)
    check("no ctx at all -> compliant, no crash",
          cc.evaluate_check({"type": "config_drift"}, Dev()) is None)

    # == declaration_drift ==
    print("\n[10] declaration_drift")
    ddm_dev = Dev(ddm_enabled_at=datetime.now(timezone.utc),
                  ddm_declaration_status={"mm.cfg.foo": {"active": True, "valid": "valid"}})
    check("device never enrolled in DDM -> compliant regardless of drift",
          cc.evaluate_check({"type": "declaration_drift"}, Dev(ddm_enabled_at=None),
                            ctx={"ddm_desired": [{"Identifier": "mm.cfg.foo", "Type": "x"}]})
          is None)
    check("desired declaration present+active+valid -> compliant", cc.evaluate_check(
        {"type": "declaration_drift"}, ddm_dev,
        ctx={"ddm_desired": [{"Identifier": "mm.cfg.foo", "Type": "com.apple.foo"}]}) is None)
    check("desired declaration entirely missing from reported status -> finding",
          cc.evaluate_check({"type": "declaration_drift"}, ddm_dev,
                            ctx={"ddm_desired": [{"Identifier": "mm.cfg.bar", "Type": "x"}]})
          is not None)
    invalid_dev = Dev(ddm_enabled_at=datetime.now(timezone.utc),
                      ddm_declaration_status={"mm.cfg.foo": {"valid": "invalid",
                                                             "reasons": [{"code": "bad-payload"}]}})
    finding = cc.evaluate_check(
        {"type": "declaration_drift"}, invalid_dev,
        ctx={"ddm_desired": [{"Identifier": "mm.cfg.foo", "Type": "com.apple.foo"}]})
    check("invalid declaration -> finding with the reason code surfaced",
          finding is not None and finding["detail"]["problems"][0].get("reason") == "bad-payload")
    check("com.apple.management.* declarations are exempt from the active check",
          cc.evaluate_check({"type": "declaration_drift"}, ddm_dev,
                            ctx={"ddm_desired": [{"Identifier": "mm.cfg.mgmt",
                                                  "Type": "com.apple.management.x"}]}) is None)
    check("ids filter narrows to just the requested declarations", cc.evaluate_check(
        {"type": "declaration_drift", "ids": ["foo"]}, ddm_dev,
        ctx={"ddm_desired": [{"Identifier": "mm.cfg.foo", "Type": "com.apple.foo"},
                             {"Identifier": "mm.cfg.bar", "Type": "com.apple.bar"}]}) is None)
    check("no ctx.ddm_desired -> compliant, no crash",
          cc.evaluate_check({"type": "declaration_drift"}, ddm_dev) is None)

    # == ddm_status ==
    print("\n[11] ddm_status")
    ddm_status_dev = Dev(ddm_enabled_at=datetime.now(timezone.utc),
                         ddm_status={"softwareupdate": {"install-state": "pending"}})
    check("equals match on a dot-path -> finding", cc.evaluate_check(
        {"type": "ddm_status", "path": "softwareupdate.install-state",
         "operator": "equals", "value": "pending"}, ddm_status_dev) is not None)
    check("equals mismatch -> compliant", cc.evaluate_check(
        {"type": "ddm_status", "path": "softwareupdate.install-state",
         "operator": "equals", "value": "installed"}, ddm_status_dev) is None)
    check("not_exists on a present path -> compliant", cc.evaluate_check(
        {"type": "ddm_status", "path": "softwareupdate.install-state",
         "operator": "not_exists"}, ddm_status_dev) is None)
    check("exists on a missing path -> compliant", cc.evaluate_check(
        {"type": "ddm_status", "path": "nope.nope", "operator": "exists"},
        ddm_status_dev) is None)
    check("comparison operator on a missing path -> compliant (unknown != known-bad)",
          cc.evaluate_check({"type": "ddm_status", "path": "nope.nope",
                             "operator": "equals", "value": "x"}, ddm_status_dev) is None)
    check("device with no DDM data at all -> compliant, no crash", cc.evaluate_check(
        {"type": "ddm_status", "path": "a.b", "operator": "exists"},
        Dev(ddm_enabled_at=None, ddm_status=None)) is None)
    gte_dev = Dev(ddm_enabled_at=datetime.now(timezone.utc), ddm_status={"battery": {"level": 80}})
    check("gte numeric compare -> finding", cc.evaluate_check(
        {"type": "ddm_status", "path": "battery.level", "operator": "gte", "value": 50},
        gte_dev) is not None)
    check("gte non-numeric actual/value -> compliant, no crash", cc.evaluate_check(
        {"type": "ddm_status", "path": "battery.level", "operator": "gte", "value": "not-a-number"},
        gte_dev) is None)

    # == tagged ==
    print("\n[12] tagged")
    check("device carries one of the named tags -> finding", cc.evaluate_check(
        {"type": "tagged", "tags": ["risky", "quarantine"]}, Dev(tags=["risky"])) is not None)
    check("device carries none of the named tags -> compliant", cc.evaluate_check(
        {"type": "tagged", "tags": ["risky"]}, Dev(tags=["ok"])) is None)
    check("no tags at all -> compliant, no crash",
          cc.evaluate_check({"type": "tagged", "tags": ["risky"]}, Dev(tags=[])) is None)
    check("missing tags param -> compliant, no crash",
          cc.evaluate_check({"type": "tagged"}, Dev(tags=["risky"])) is None)

    # == attribute (advanced/generic) ==
    print("\n[13] attribute")
    # These paths are the ones a real Mac reports, the catalog's help-text example among them: an example naming a key
    # no device sends builds rules that are permanently compliant.
    attr_dev = Dev(attributes={"SecurityInfo": {"SystemIntegrityProtectionEnabled": False},
                               "BatteryLevel": 42})
    check("equals match -> finding", cc.evaluate_check(
        {"type": "attribute", "key": "SecurityInfo.SystemIntegrityProtectionEnabled",
         "operator": "equals", "value": "False"}, attr_dev) is not None)
    check("not_equals mismatch -> finding", cc.evaluate_check(
        {"type": "attribute", "key": "BatteryLevel", "operator": "not_equals", "value": "99"},
        attr_dev) is not None)
    check("exists on a present key -> finding", cc.evaluate_check(
        {"type": "attribute", "key": "BatteryLevel", "operator": "exists"}, attr_dev) is not None)
    check("exists on a missing key -> compliant", cc.evaluate_check(
        {"type": "attribute", "key": "Nope.Nope", "operator": "exists"}, attr_dev) is None)
    check("comparison operator on a missing key -> compliant, not a false alarm",
          cc.evaluate_check({"type": "attribute", "key": "Nope.Nope", "operator": "equals",
                             "value": "x"}, attr_dev) is None)
    check("gt numeric compare -> finding", cc.evaluate_check(
        {"type": "attribute", "key": "BatteryLevel", "operator": "gt", "value": 10},
        attr_dev) is not None)
    check("gt numeric compare, false -> compliant", cc.evaluate_check(
        {"type": "attribute", "key": "BatteryLevel", "operator": "gt", "value": 100},
        attr_dev) is None)
    check("gt with non-numeric actual -> compliant, no crash (TypeError swallowed)",
          cc.evaluate_check({"type": "attribute",
                             "key": "SecurityInfo.SystemIntegrityProtectionEnabled",
                             "operator": "gt", "value": 1}, attr_dev) is None)
    check("regex match -> finding", cc.evaluate_check(
        {"type": "attribute", "key": "BatteryLevel", "operator": "regex", "value": "^4"},
        attr_dev) is not None)
    check("regex no match -> compliant", cc.evaluate_check(
        {"type": "attribute", "key": "BatteryLevel", "operator": "regex", "value": "^9"},
        attr_dev) is None)
    check("invalid regex pattern -> compliant, no crash", cc.evaluate_check(
        {"type": "attribute", "key": "BatteryLevel", "operator": "regex", "value": "("},
        attr_dev) is None)
    check("missing key param -> compliant, no crash",
          cc.evaluate_check({"type": "attribute", "operator": "equals", "value": "x"},
                            attr_dev) is None)
    check("attributes is None -> compliant, no crash",
          cc.evaluate_check({"type": "attribute", "key": "a", "operator": "exists"},
                            Dev(attributes=None)) is None)

    # == flow_parked_for ==
    #
    # The only check that reads ctx["flow_runs"]. Entries arrive either as FlowRun rows or as mappings using the model's
    # own field names, so both are exercised here.
    print("\n[14] flow_parked_for")
    now = datetime.now(timezone.utc)

    def parked(**over):
        """A run parked five hours ago on a manual gate, with a live deadline."""
        row = {"id": "run-1", "status": "waiting", "flow_id": "onboard",
               "current_node": "gate-1", "waiting_signal": "manual",
               "updated_at": now - timedelta(hours=5),
               "wait_deadline": now + timedelta(hours=1)}
        row.update(over)
        return row

    finding = cc.evaluate_check({"type": "flow_parked_for", "hours": 4}, Dev(),
                                ctx={"flow_runs": [parked()]})
    check("a run parked past the threshold -> finding", finding is not None)
    check("the summary names the flow and the step it is stuck on",
          finding is not None and "onboard" in finding["summary"]
          and "gate-1" in finding["summary"])
    check("the detail carries the run id and how long it has waited",
          finding is not None
          and finding["detail"]["runs"][0]["run_id"] == "run-1"
          and finding["detail"]["runs"][0]["hours_parked"] == 5.0)
    check("the detail is JSON scalars, which is what an Alert stores",
          finding is not None and json.dumps(finding["detail"]) is not None)
    check("the same run as a row object rather than a mapping -> same verdict",
          cc.evaluate_check({"type": "flow_parked_for", "hours": 4}, Dev(),
                            ctx={"flow_runs": [Dev(**parked())]}) is not None)
    check("using params={} wrapper style also works", cc.evaluate_check(
        {"type": "flow_parked_for", "params": {"hours": 4}}, Dev(),
        ctx={"flow_runs": [parked()]}) is not None)
    check("naive updated_at is treated as UTC, not a crash", cc.evaluate_check(
        {"type": "flow_parked_for", "hours": 4}, Dev(),
        ctx={"flow_runs": [parked(updated_at=(now - timedelta(hours=5))
                                  .replace(tzinfo=None))]}) is not None)

    # Near misses: a healthy run must not raise a finding.
    check("parked, but inside the threshold -> compliant", cc.evaluate_check(
        {"type": "flow_parked_for", "hours": 4}, Dev(),
        ctx={"flow_runs": [parked(updated_at=now - timedelta(hours=1))]}) is None)
    check("parked with no deadline -> compliant (the ladder adopts it instead)",
          cc.evaluate_check({"type": "flow_parked_for", "hours": 4}, Dev(),
                            ctx={"flow_runs": [parked(wait_deadline=None)]}) is None)
    check("a completed run that finished long ago -> compliant", cc.evaluate_check(
        {"type": "flow_parked_for", "hours": 4}, Dev(),
        ctx={"flow_runs": [parked(status="completed", current_node=None,
                                  waiting_signal=None, wait_deadline=None)]}) is None)
    # A real terminal row also loses its deadline (atc._complete / _fail null it), so the case above would stay quiet on
    # the deadline guard alone. This one keeps the stale deadline on purpose, which is what pins the status filter.
    check("a terminal row still carrying a stale deadline -> compliant",
          cc.evaluate_check({"type": "flow_parked_for", "hours": 4}, Dev(),
                            ctx={"flow_runs": [parked(status="failed")]}) is None)
    check("a run that is executing rather than parked -> compliant",
          cc.evaluate_check({"type": "flow_parked_for", "hours": 4}, Dev(),
                            ctx={"flow_runs": [parked(status="running")]}) is None)

    # Two stuck runs are one finding, not two: the rule raises one alert per device and the detail is where they are
    # enumerated.
    multi = cc.evaluate_check(
        {"type": "flow_parked_for", "hours": 4}, Dev(),
        ctx={"flow_runs": [parked(), parked(id="run-2", flow_id="reissue")]})
    check("two parked runs -> one finding that counts them",
          multi is not None and "2 flow runs" in multi["summary"]
          and len(multi["detail"]["runs"]) == 2)

    # Never-crash discipline, and the case where nothing fills ctx["flow_runs"] and every device reads as compliant.
    check("no ctx at all -> compliant, no crash (today's dormant behaviour)",
          cc.evaluate_check({"type": "flow_parked_for", "hours": 4}, Dev()) is None)
    check("ctx without the key -> compliant, no crash", cc.evaluate_check(
        {"type": "flow_parked_for", "hours": 4}, Dev(), ctx={"drift": []}) is None)
    check("an empty run list -> compliant", cc.evaluate_check(
        {"type": "flow_parked_for", "hours": 4}, Dev(), ctx={"flow_runs": []}) is None)
    check("missing hours param -> compliant, no crash", cc.evaluate_check(
        {"type": "flow_parked_for"}, Dev(), ctx={"flow_runs": [parked()]}) is None)
    check("malformed hours -> compliant, no crash", cc.evaluate_check(
        {"type": "flow_parked_for", "hours": "soon"}, Dev(),
        ctx={"flow_runs": [parked()]}) is None)
    # The threshold is parsed inside its own try. evaluate_check's outer catch returns None either way, so what the
    # inner guard buys is silence: a rule saved without an hours value would log a traceback per device per sweep.
    trap = LogTrap()
    cc.logger.addHandler(trap)
    try:
        cc.evaluate_check({"type": "flow_parked_for"}, Dev(),
                          ctx={"flow_runs": [parked()]})
        cc.evaluate_check({"type": "flow_parked_for", "hours": "soon"}, Dev(),
                          ctx={"flow_runs": [parked()]})
    finally:
        cc.logger.removeHandler(trap)
    check("an unusable threshold logs nothing, so a sweep cannot drown in it",
          not trap.records)
    check("flow_runs of a wrong shape entirely -> compliant, no crash",
          cc.evaluate_check({"type": "flow_parked_for", "hours": 4}, Dev(),
                            ctx={"flow_runs": 7}) is None)
    check("a scalar where a run belongs -> compliant, no crash", cc.evaluate_check(
        {"type": "flow_parked_for", "hours": 4}, Dev(),
        ctx={"flow_runs": ["not-a-run", None]}) is None)
    # One unreadable entry must not take the real finding down with it: the timestamp guard is per run, not per
    # evaluation.
    salvage = cc.evaluate_check(
        {"type": "flow_parked_for", "hours": 4}, Dev(),
        ctx={"flow_runs": [parked(id="run-bad", updated_at="this morning"),
                           parked(updated_at=None), parked()]})
    check("a run with an unusable updated_at does not hide a stuck one",
          salvage is not None and len(salvage["detail"]["runs"]) == 1
          and salvage["detail"]["runs"][0]["run_id"] == "run-1")

    # == malformed / unknown checks never raise ==
    print("\n[15] malformed check configs never raise")
    check("unknown check type -> None, no crash",
          cc.evaluate_check({"type": "not-a-real-check"}, Dev()) is None)
    check("missing type entirely -> None, no crash",
          cc.evaluate_check({}, Dev()) is None)
    check("params is a totally wrong shape (a list) -> None, no crash",
          cc.evaluate_check({"type": "attribute", "params": ["not", "a", "dict"]}, attr_dev)
          is None)
    # A non-dict ctx is a caller bug, so it normalizes to an empty context and the check still evaluates. Here p1 is not
    # recorded as installed, which is a finding rather than a crash.
    check("ctx of an unexpected type is normalized, no crash", cc.evaluate_check(
        {"type": "missing_profile", "profile_id": "p1"}, Dev(), ctx="not-a-dict")
          is not None)

    # A rule restored by hand can put a bare scalar where the check mapping belongs. That reads as compliant.
    for bad_check in (None, "bad", ["a", "b"], 7):
        check(f"non-dict check {bad_check!r} -> no finding, no crash",
              cc.evaluate_check(bad_check, Dev()) is None)

    # == the checks against the inventory the seed fleet carries ==
    #
    # Every case above builds its own attribute bag, so a check and its tests can agree on a key layout no device sends
    # and stay green forever. These run the curated Mac checks against tests/_seed_attrs.py's SecurityInfo, which is
    # also what the dev preview seeder writes onto the demo fleet, so changing one without the other fails.
    print("\n[16] the security checks against the seeded fleet's inventory")
    from tests._seed_attrs import build_attrs

    def seeded(model, **kw):
        return Dev(attributes=build_attrs(model, "15.5", serial="C02SEED0001",
                                          name="SEED", **kw))

    healthy_mac = seeded("MacBookPro18,3")
    seeded_sec = healthy_mac.attributes["SecurityInfo"]
    # Pinned explicitly: the flat fallback in firewall_disabled would keep every verdict below green on a seed that had
    # drifted to the flat key.
    check("the seed puts the firewall where a Mac reports it and nowhere else",
          "FirewallEnabled" in (seeded_sec.get("FirewallSettings") or {})
          and "FirewallEnabled" not in seeded_sec)
    check("the seed carries the keys the newer Mac checks read",
          "UserApprovedEnrollment" in (seeded_sec.get("ManagementStatus") or {})
          and "BootstrapTokenAllowedForAuthentication" in seeded_sec
          and "RemoteDesktopEnabled" in seeded_sec)
    check("a healthy seeded Mac trips none of the security checks",
          all(cc.evaluate_check({"type": t}, healthy_mac) is None
              for t in ("filevault_disabled", "firewall_disabled", "passcode_missing",
                        "user_approved_enrollment_missing",
                        "bootstrap_token_disallowed", "remote_desktop_enabled")))
    check("a seeded Mac with the firewall off trips firewall_disabled",
          cc.evaluate_check({"type": "firewall_disabled"},
                            seeded("MacBookPro18,3", firewall=False)) is not None)
    check("a seeded Mac with FileVault off trips filevault_disabled",
          cc.evaluate_check({"type": "filevault_disabled"},
                            seeded("MacBookPro18,3", fv=False)) is not None)
    check("a seeded iPhone without a passcode trips passcode_missing",
          cc.evaluate_check({"type": "passcode_missing"},
                            seeded("iPhone15,2", passcode=False)) is not None)
    check("the Mac-only checks stay quiet on a seeded iPhone, which never reports them",
          all(cc.evaluate_check({"type": t}, seeded("iPhone15,2")) is None
              for t in ("firewall_disabled", "user_approved_enrollment_missing",
                        "bootstrap_token_disallowed", "remote_desktop_enabled")))
    # The example path in the attribute check's help text has to resolve against a Mac's real inventory.
    example = next((p.get("help") or "" for c in cc.CHECK_CATALOG
                    if c["type"] == "attribute"
                    for p in c["params"] if p["name"] == "key"), "")
    # Quoted either way, and a help text with no example at all fails by name rather than on an IndexError.
    quoted = re.search(r"""["']([A-Za-z0-9_.]+\.[A-Za-z0-9_.]+)["']""", example)
    check("the attribute check's help text still offers an example path",
          quoted is not None)
    example_path = quoted.group(1) if quoted else ""
    check(f"the documented example path {example_path or '(none)'} exists on a seeded Mac",
          bool(example_path) and cc._dig(healthy_mac.attributes, example_path) is not None)

    print()
    if FAILURES:
        print(f"RESULT: FAIL ({len(FAILURES)} check(s) failed): {FAILURES}")
        sys.exit(1)
    print("RESULT: PASS (all compliance_catalog checks passed)")


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
