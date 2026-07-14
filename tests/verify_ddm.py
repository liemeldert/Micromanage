"""Backend E2E for Declarative Device Management (DDM), on in-memory sqlite.

Exercises the DDM core with no docker and no MDM network: OS support gates,
per-device declaration composition (scoping, platform filter, predicates, the
auto status-subscriptions/org-info/properties declarations), ServerToken /
DeclarationsToken stability and sensitivity, manifest grouping, StatusReport
ingestion (incremental merge, _removed, FullReport, capability filtering, ATC
signals), the sync command lifecycle, the declaration_drift / ddm_status
compliance checks, the legacy profile bridge, and the NanoMDM HMAC gate.

Run:  PYTHONPATH=. ./.venv/bin/python tests/verify_ddm.py
Exits non-zero if any check fails.
"""

import asyncio
import base64
import hashlib
import hmac as hmac_mod
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
    """Stand-in for MDMConnector: records DeclarativeManagement enqueues."""

    calls = []

    def __init__(self, *a, **k):
        pass

    async def declarative_management(self, udid, tokens_json=None):
        FakeConnector.calls.append({"udid": udid, "data": tokens_json})
        return {"command_uuid": f"u-ddm-{len(FakeConnector.calls)}"}

    async def close(self):
        pass


DECLARATIONS_DOC = {
    "organization_info": {"email": "it@example.com"},
    "status_subscriptions": ["app.managed.list"],
    "declarations": [
        {"id": "passcode", "name": "Passcode policy",
         "type": "com.apple.configuration.passcode.settings",
         "groups": ["all-macs"],
         "payload": {"RequirePasscode": True, "MinimumLength": 6}},
        {"id": "excluded", "name": "Never on SN-1",
         "type": "com.apple.configuration.passcode.settings",
         "groups": ["all-macs"], "exclude_devices": ["SN-1"],
         "payload": {"RequirePasscode": True}},
        {"id": "ios-only", "name": "iOS only",
         "type": "com.apple.configuration.softwareupdate.settings",
         "platforms": ["iOS"], "payload": {"Notifications": True}},
        {"id": "gated", "name": "Predicate gated",
         "type": "com.apple.configuration.passcode.settings",
         "groups": ["all-macs"],
         "predicate": '"kiosk" IN @property(tags)',
         "payload": {"RequirePasscode": False}},
        {"id": "bridged", "name": "Bridged WiFi",
         "type": "com.apple.configuration.legacy",
         "groups": ["all-macs"], "profile": "wifi"},
    ],
}


def _write_configs(base: Path, declarations=None, wifi_ssid="CorpNet"):
    tdir = base / "tenants" / "default"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "config.yaml").write_text(yaml.safe_dump(
        {"tenant": {"id": "default", "name": "Default", "allowed_users": []}}))
    (tdir / "groups.yaml").write_text(yaml.safe_dump({"groups": [
        {"name": "all-macs", "conditions": [
            {"type": "platform", "operator": "in", "value": ["Mac"]}]}]}))
    (tdir / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
    (tdir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": [
        {"id": "wifi", "name": "WiFi", "payload": {
            "PayloadType": "com.apple.wifi", "SSID_STR": wifi_ssid}},
    ]}))
    (tdir / "declarations.yaml").write_text(
        yaml.safe_dump(declarations or DECLARATIONS_DOC))
    return tdir


def _ident_map(declarations):
    return {d["Identifier"]: d for d in declarations}


async def main():
    base = Path(tempfile.mkdtemp())
    os.environ["YAML_CONFIG_PATH"] = str(base)
    os.environ["WEBHOOK_SECRET"] = "verify-secret"
    os.environ.pop("DDM_HMAC_SECRET", None)
    os.environ["PUBLIC_API_URL"] = "https://mdm.example.com"
    _write_configs(base)

    import controller.services.mdm_connector as mc
    mc.MDMConnector = FakeConnector

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    from controller.models.tenant import Tenant, Device, Task
    from controller.services import atc, ddm_manager, dispatcher
    from controller.services.compliance_catalog import _EVALUATORS
    from controller.services.profile_manager import ProfileManager
    from controller.services.tenant_config import load_declarations, load_groups

    # Record ATC signals / dispatcher evals instead of running them.
    signals = []

    async def fake_advance(device_id, signal, ref=None):
        signals.append((signal, ref))

    atc.advance_on_signal = fake_advance
    dispatcher_evals = []

    async def fake_evaluate(device, reason="event"):
        dispatcher_evals.append(reason)

    dispatcher.evaluate_device = fake_evaluate

    tenant = await Tenant.create(id="default", name="Default", ddm_enabled=True)

    async def new_device(serial, model="MacBookPro18,3", os_version="14.5", tags=None):
        return await Device.create(
            tenant=tenant, udid=f"UDID-{serial}", serial_number=serial,
            device_model=model, os_version=os_version, hostname=serial.lower(),
            enrollment_state="enrolled", groups=[], tags=tags or [])

    mac = await new_device("SN-0", tags=["corp"])

    print("== 1. OS support gates ==")
    check("macOS 14 supported", ddm_manager.device_supports_ddm(mac))
    check("macOS 12 unsupported",
          not ddm_manager.device_supports_ddm(await new_device("SN-OLD", os_version="12.7")))
    check("iOS 17 supported", ddm_manager.device_supports_ddm(
        await new_device("SN-IOS", model="iPhone14,2", os_version="17.5")))
    check("iOS 15 unsupported (user-enrollment only)",
          not ddm_manager.device_supports_ddm(
              await new_device("SN-IOS15", model="iPhone12,1", os_version="15.7")))
    check("unknown model unsupported",
          not ddm_manager.device_supports_ddm(
              await new_device("SN-UNK", model="Frobnitz9000")))

    print("== 2. Declaration composition ==")
    manager = ddm_manager.DDMManager(tenant)
    decls = await manager.build_device_declarations(
        mac, load_declarations(tenant.id), load_groups(tenant.id))
    idents = _ident_map(decls)
    check("scoped item produces cfg+act pair",
          "mm.cfg.passcode" in idents and "mm.act.passcode" in idents)
    check("platform-filtered item absent on Mac", "mm.cfg.ios-only" not in idents)
    check("auto status-subscriptions present", "mm.cfg.status-subscriptions" in idents)
    check("auto org-info present", "mm.mgmt.org-info" in idents)
    check("org-info name falls back to tenant name",
          idents.get("mm.mgmt.org-info", {}).get("Payload", {}).get("Name") == "Default")
    check("auto properties reflect tags",
          idents.get("mm.mgmt.properties", {}).get("Payload", {}).get("tags") == ["corp"])
    check("properties reflect freshly-computed groups",
          "all-macs" in idents.get("mm.mgmt.properties", {}).get("Payload", {}).get("groups", []))
    subs = [s["Name"] for s in
            idents.get("mm.cfg.status-subscriptions", {}).get("Payload", {}).get("StatusItems", [])]
    check("subscriptions = defaults + yaml extras",
          "device.operating-system.version" in subs and "app.managed.list" in subs)
    check("predicate passes through to the activation",
          idents.get("mm.act.gated", {}).get("Payload", {}).get("Predicate")
          == '"kiosk" IN @property(tags)')

    excluded = await new_device("SN-1")
    decls_excl = await manager.build_device_declarations(
        excluded, load_declarations(tenant.id), load_groups(tenant.id))
    check("exclude_devices wins", "mm.cfg.excluded" not in _ident_map(decls_excl))
    check("non-excluded device gets the same item", "mm.cfg.excluded" in idents)

    print("== 3. Token stability & sensitivity ==")
    token_a = ddm_manager.declarations_token(decls)
    decls_again = await manager.build_device_declarations(
        mac, load_declarations(tenant.id), load_groups(tenant.id))
    check("unchanged inputs -> identical DeclarationsToken",
          ddm_manager.declarations_token(decls_again) == token_a)

    edited = yaml.safe_load(yaml.safe_dump(DECLARATIONS_DOC))
    edited["declarations"][0]["payload"]["MinimumLength"] = 8
    _write_configs(base, declarations=edited)
    decls_edit = await manager.build_device_declarations(
        mac, load_declarations(tenant.id), load_groups(tenant.id))
    check("payload edit changes cfg ServerToken",
          _ident_map(decls_edit)["mm.cfg.passcode"]["ServerToken"]
          != idents["mm.cfg.passcode"]["ServerToken"])
    check("payload edit changes DeclarationsToken",
          ddm_manager.declarations_token(decls_edit) != token_a)
    _write_configs(base)  # restore

    mac.tags = ["corp", "kiosk"]
    await mac.save()
    decls_tagged = await manager.build_device_declarations(
        mac, load_declarations(tenant.id), load_groups(tenant.id))
    check("tag change re-tokens the properties declaration",
          _ident_map(decls_tagged)["mm.mgmt.properties"]["ServerToken"]
          != idents["mm.mgmt.properties"]["ServerToken"])
    mac.tags = ["corp"]
    await mac.save()

    print("== 4. Manifest grouping ==")
    manifest = ddm_manager.build_manifest(decls, token_a)
    groups = manifest["Declarations"]
    check("all four arrays present",
          all(k in groups for k in ("Activations", "Configurations", "Assets", "Management")))
    check("activation grouped under Activations",
          any(i["Identifier"] == "mm.act.passcode" for i in groups["Activations"]))
    check("management grouped under Management",
          any(i["Identifier"] == "mm.mgmt.properties" for i in groups["Management"]))
    check("assets empty list (not missing)", groups["Assets"] == [])
    check("manifest carries the token", manifest["DeclarationsToken"] == token_a)

    print("== 5. Status report ingestion ==")
    signals.clear()
    dispatcher_evals.clear()
    await ddm_manager.ingest_status_report(mac, {
        "StatusItems": {
            "device": {"operating-system": {"version": "14.6"}},
            "security": {"certificate": {"list": [
                {"identifier": "cert-1", "subject-summary": "A"},
                {"identifier": "cert-2", "subject-summary": "B"},
            ]}},
            "management": {"declarations": {
                "activations": [{"identifier": "mm.act.passcode", "active": True,
                                 "valid": "valid", "server-token": "t"}],
                "configurations": [{"identifier": "mm.cfg.passcode", "active": True,
                                    "valid": "valid", "server-token": "t"}],
                "assets": [], "management": [],
            }},
        },
        "Errors": [],
    })
    await mac.refresh_from_db()
    check("os_version mirrored from status", mac.os_version == "14.6")
    check("declaration status extracted",
          mac.ddm_declaration_status.get("mm.cfg.passcode", {}).get("active") is True)
    check("ddm_last_sync_at stamped", mac.ddm_last_sync_at is not None)
    check("ddm_status signal fired (refless)", ("ddm_status", None) in signals)
    check("declaration_applied fired with bare yaml id",
          ("declaration_applied", "passcode") in signals)
    check("dispatcher re-evaluated", "ddm" in dispatcher_evals)

    # Incremental delta: update one cert, remove the other.
    await ddm_manager.ingest_status_report(mac, {
        "StatusItems": {"security": {"certificate": {"list": [
            {"identifier": "cert-1", "subject-summary": "A2"},
            {"identifier": "cert-2", "_removed": True},
        ]}}},
        "Errors": [],
    })
    await mac.refresh_from_db()
    certs = mac.ddm_status["security"]["certificate"]["list"]
    check("incremental merge updates by identifier",
          any(c.get("subject-summary") == "A2" for c in certs))
    check("_removed entries dropped",
          not any(c.get("identifier") == "cert-2" for c in certs))
    check("unrelated subtree preserved on merge",
          mac.ddm_status.get("device", {}).get("operating-system", {}).get("version") == "14.6")

    # FullReport replaces everything.
    await ddm_manager.ingest_status_report(mac, {
        "StatusItems": {"device": {"operating-system": {"version": "14.6"}}},
        "Errors": [], "FullReport": True,
    })
    await mac.refresh_from_db()
    check("FullReport replaces stored state", "security" not in mac.ddm_status)

    # Client capabilities constrain what we serve.
    await ddm_manager.ingest_status_report(mac, {
        "StatusItems": {"management": {"client-capabilities": {"supported-payloads": {
            "declarations": {
                "activations": ["com.apple.activation.simple"],
                "configurations": ["com.apple.configuration.management.status-subscriptions"],
                "assets": [],
                "management": ["com.apple.management.organization-info",
                               "com.apple.management.properties"],
            },
            "status-items": ["device.operating-system.version"],
        }}}},
        "Errors": [],
    })
    await mac.refresh_from_db()
    check("client capabilities persisted",
          bool(mac.ddm_client_capabilities.get("supported-payloads")))
    decls_cap = await manager.build_device_declarations(
        mac, load_declarations(tenant.id), load_groups(tenant.id))
    cap_idents = _ident_map(decls_cap)
    check("unadvertised type dropped", "mm.cfg.passcode" not in cap_idents)
    check("orphaned activation dropped with its configuration",
          "mm.act.passcode" not in cap_idents)
    check("advertised types kept", "mm.cfg.status-subscriptions" in cap_idents)
    check("subscriptions filtered to advertised status items",
          [s["Name"] for s in cap_idents["mm.cfg.status-subscriptions"]["Payload"]["StatusItems"]]
          == ["device.operating-system.version"])
    mac.ddm_client_capabilities = {}
    await mac.save()

    print("== 6. Sync command lifecycle ==")
    FakeConnector.calls.clear()
    queued = await ddm_manager.sync_device(mac, reason="verify")
    await mac.refresh_from_db()
    check("first sync enqueues a command", queued and len(FakeConnector.calls) == 1)
    check("tokens front-loaded in Data",
          (mac.ddm_last_published_token or "").encode() in (FakeConnector.calls[0]["data"] or b""))
    check("ddm_enabled_at stamped", mac.ddm_enabled_at is not None)
    task = await Task.filter(tenant=tenant, type="ddm_sync").order_by("-created_at").first()
    check("ddm_sync task created with command_uuid",
          task is not None and task.details.get("command_uuid"))
    check("unchanged config no-ops",
          not await ddm_manager.sync_device(mac, reason="verify"))
    edited = yaml.safe_load(yaml.safe_dump(DECLARATIONS_DOC))
    edited["declarations"][0]["payload"]["MinimumLength"] = 10
    _write_configs(base, declarations=edited)
    check("config edit re-syncs", await ddm_manager.sync_device(mac, reason="verify"))
    _write_configs(base)
    tenant.ddm_enabled = False
    await tenant.save()
    check("disabled tenant no-ops",
          not await ddm_manager.sync_device(mac, reason="verify"))
    check("disabled tenant computes an empty desired set",
          await ddm_manager.compute_device_declarations(mac) == [])
    tenant.ddm_enabled = True
    await tenant.save()

    print("== 7. Compliance checks ==")
    # Re-sync mac's declaration status to a healthy state for the drift check.
    fresh = await ddm_manager.compute_device_declarations(mac, tenant)
    mac.ddm_declaration_status = {
        d["Identifier"]: {
            # The predicate-gated pair is reported inactive (predicate false on
            # this device) -- present-but-inactive must not count as drift.
            "active": d["Identifier"] not in ("mm.cfg.gated", "mm.act.gated"),
            "valid": "valid", "reasons": [],
        }
        for d in fresh if not d["Type"].startswith("com.apple.management.")
    }
    await mac.save()
    ctx = {"ddm_desired": fresh}
    drift = _EVALUATORS["declaration_drift"]
    check("healthy device compliant (mgmt always-inactive + predicate-gated exempt)",
          drift(mac, {}, ctx) is None)
    mac.ddm_declaration_status = dict(mac.ddm_declaration_status)
    mac.ddm_declaration_status["mm.cfg.passcode"] = {
        "active": False, "valid": "invalid",
        "reasons": [{"code": "Error.ConfigurationCannotBeApplied"}]}
    fired = drift(mac, {}, ctx)
    check("invalid declaration fires with reason code",
          fired and "Error.ConfigurationCannotBeApplied" in fired["summary"])
    check("ids param limits the check",
          drift(mac, {"ids": ["excluded"]}, ctx) is None
          and drift(mac, {"ids": ["passcode"]}, ctx) is not None)
    no_ddm = await new_device("SN-NODDM")
    check("device without DDM data is compliant", drift(no_ddm, {}, ctx) is None)

    mac.ddm_status = {"softwareupdate": {"install-state": "failed"}}
    ddm_status = _EVALUATORS["ddm_status"]
    check("ddm_status equals fires",
          ddm_status(mac, {"path": "softwareupdate.install-state",
                           "operator": "equals", "value": "failed"}, {}) is not None)
    check("ddm_status not_equals compliant",
          ddm_status(mac, {"path": "softwareupdate.install-state",
                           "operator": "not_equals", "value": "failed"}, {}) is None)
    check("unreported path only fires on existence operators",
          ddm_status(mac, {"path": "nope.nope", "operator": "equals", "value": "x"}, {}) is None
          and ddm_status(mac, {"path": "nope.nope", "operator": "not_exists"}, {}) is not None)
    check("no DDM data is compliant",
          ddm_status(no_ddm, {"path": "a.b", "operator": "exists"}, {}) is None)

    print("== 8. Legacy profile bridge ==")
    bridged = _ident_map(decls).get("mm.cfg.bridged", {})
    url = bridged.get("Payload", {}).get("ProfileURL", "")
    check("bridge declaration carries a public ProfileURL",
          url.startswith("https://mdm.example.com/public/ddm/profile/default/wifi?sig="))
    sig = url.rsplit("sig=", 1)[-1]
    check("bridge signature verifies",
          ddm_manager.verify_profile_bridge_sig("default", "wifi", sig))
    check("bridge signature rejects tampering",
          not ddm_manager.verify_profile_bridge_sig("default", "other", sig))
    _write_configs(base, wifi_ssid="NewNet")
    decls_wifi = await manager.build_device_declarations(
        mac, load_declarations(tenant.id), load_groups(tenant.id))
    check("profile edit re-tokens the bridged declaration",
          _ident_map(decls_wifi)["mm.cfg.bridged"]["ServerToken"]
          != bridged.get("ServerToken"))
    _write_configs(base)

    print("== 9. NanoMDM HMAC gate ==")
    good = base64.b64encode(hmac_mod.new(
        b"verify-secret", b"body", hashlib.sha256).digest()).decode()
    check("correct signature passes", ddm_manager.verify_hmac_signature(b"body", good))
    check("wrong signature fails", not ddm_manager.verify_hmac_signature(b"body", "nope"))
    empty_sig = base64.b64encode(hmac_mod.new(
        b"verify-secret", b"", hashlib.sha256).digest()).decode()
    check("empty body (GET) verifiable", ddm_manager.verify_hmac_signature(b"", empty_sig))
    saved = os.environ.pop("WEBHOOK_SECRET")
    check("unset secret fails closed", not ddm_manager.verify_hmac_signature(b"body", good))
    os.environ["WEBHOOK_SECRET"] = saved

    print("== 10. Webhook ddm_sync error path ==")
    from controller.services.webhook_handler import WebhookHandler
    mac.ddm_last_published_token = "stale-token"
    await mac.save()
    err_task = await Task.create(
        tenant=tenant, type="ddm_sync", status="running",
        description="Declarative sync (verify)", device=mac, user="system",
        details={"command_uuid": "u-err"})
    handler = WebhookHandler()
    await handler._handle_ddm_sync_response(
        mac, err_task, {"Status": "Error",
                        "ErrorChain": [{"USEnglishDescription": "boom"}]}, "Error")
    await mac.refresh_from_db()
    await err_task.refresh_from_db()
    check("error response fails the task", err_task.status == "failed")
    check("error response clears the published token (reconciler retries)",
          mac.ddm_last_published_token is None)
    ok_task = await Task.create(
        tenant=tenant, type="ddm_sync", status="running",
        description="Declarative sync (verify)", device=mac, user="system",
        details={"command_uuid": "u-ok"})
    await handler._handle_ddm_sync_response(mac, ok_task, {}, "Acknowledged")
    await ok_task.refresh_from_db()
    check("acknowledged response completes the task", ok_task.status == "completed")

    await Tortoise.close_connections()

    print()
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s):")
        for f in _FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("All DDM checks passed.")


if __name__ == "__main__":
    asyncio.run(main())
