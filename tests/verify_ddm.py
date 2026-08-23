"""Backend E2E for Declarative Device Management (DDM), on in-memory sqlite.

See docs/tests/verify_ddm.md for the full tour of every checked behavior.
Exits non-zero if any check fails.
"""

import base64
import hashlib
import hmac as hmac_mod
import json
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
    from controller.services.tenant_config import load_declarations, load_groups

    # Record ATC signals / dispatcher evals instead of running them.
    signals = []

    async def fake_advance(device_id, signal, ref=None):
        signals.append((signal, ref))

    atc.advance_on_signal = fake_advance
    dispatcher_evals = []

    async def fake_evaluate(device, reason="event"):
        dispatcher_evals.append(reason)

    # Kept so section 14 can measure a cache hit through the real entry point;
    # everything else in this suite wants the recording stub.
    real_evaluate_device = dispatcher.evaluate_device
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

    print("== 2b. watchOS / visionOS are platforms of their own ==")
    wearable_serials = ["SN-WATCH", "SN-VISION", "SN-IPH"]
    split = yaml.safe_load(yaml.safe_dump(DECLARATIONS_DOC))
    split["declarations"] += [
        {"id": "ios-scoped", "name": "iPhone passcode",
         "type": "com.apple.configuration.passcode.settings",
         "platforms": ["iOS"], "include_devices": wearable_serials,
         "payload": {"RequirePasscode": True}},
        {"id": "watch-only", "name": "Watch passcode",
         "type": "com.apple.configuration.passcode.settings",
         "platforms": ["watchOS"], "include_devices": wearable_serials,
         "payload": {"RequirePasscode": True}},
    ]
    _write_configs(base, declarations=split)
    watch = await new_device("SN-WATCH", model="Watch7,1", os_version="11.0")
    idents_watch = _ident_map(await manager.build_device_declarations(
        watch, load_declarations(tenant.id), load_groups(tenant.id)))
    check("a watch no longer receives an iOS-only declaration",
          "mm.cfg.ios-scoped" not in idents_watch)
    check("a watch receives a watchOS-scoped declaration",
          "mm.cfg.watch-only" in idents_watch)
    vision = await new_device("SN-VISION", model="RealityDevice14,1", os_version="2.0")
    idents_vision = _ident_map(await manager.build_device_declarations(
        vision, load_declarations(tenant.id), load_groups(tenant.id)))
    check("Vision Pro no longer receives an iOS-only declaration",
          "mm.cfg.ios-scoped" not in idents_vision)
    check("nor the watchOS one", "mm.cfg.watch-only" not in idents_vision)
    iphone = await new_device("SN-IPH", model="iPhone14,2", os_version="17.5")
    idents_iph = _ident_map(await manager.build_device_declarations(
        iphone, load_declarations(tenant.id), load_groups(tenant.id)))
    check("an iPhone still receives the iOS declaration",
          "mm.cfg.ios-scoped" in idents_iph)
    check("but not the watchOS one", "mm.cfg.watch-only" not in idents_iph)
    _write_configs(base)  # restore

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
    # Status ingest defers ATC and dispatcher fan-out, so the DDM response is not blocked.
    from controller.services import webhook_handler

    deferred = []
    real_spawn_deferred = webhook_handler._spawn_deferred
    webhook_handler._spawn_deferred = deferred.append
    try:
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
        check("no fan-out ran on the check-in path",
              signals == [] and dispatcher_evals == [])
        check("signals and rule eval were deferred", len(deferred) == 2)
        for coro in deferred:
            await coro
    finally:
        webhook_handler._spawn_deferred = real_spawn_deferred
        deferred.clear()
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
            # this device), so present-but-inactive shouldn't count as drift.
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

    # Both signatures arrive on unauthenticated requests: one as a header, one as a query parameter.
    # hmac.compare_digest over two str raises TypeError on non-ASCII, so check for False, not raise.
    def _refuses(fn, *args):
        try:
            return fn(*args) is False
        except Exception:
            return False

    for label, value in (("non-ASCII", "signatureé"),
                         ("a lone surrogate", "sig\ud800"),
                         ("a line separator", "sig ")):
        check(f"an HMAC signature carrying {label} is refused, not raised",
              _refuses(ddm_manager.verify_hmac_signature, b"body", value))
        check(f"a bridge signature carrying {label} is refused, not raised",
              _refuses(ddm_manager.verify_profile_bridge_sig,
                       "default", "wifi", value))

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

    print("== 11. Saving declarations.yaml stamps rollout starts ==")
    # A rollout with no start makes scoping.rollout_coverage fail open at 100%,
    # so a gradual declaration would ship to the whole fleet at once.
    from controller.api.main import _autofill_rollout_starts
    doc = {"declarations": [
        {"id": "gradual", "type": "com.apple.configuration.passcode.settings",
         "payload": {}, "rollout": {"percent": 10, "interval_hours": 24}},
        {"id": "kept", "type": "com.apple.configuration.passcode.settings",
         "payload": {}, "rollout": {"percent": 10, "start": "2020-01-01T00:00:00+00:00"}},
        {"id": "plain", "type": "com.apple.configuration.passcode.settings",
         "payload": {}},
    ]}
    _autofill_rollout_starts("declarations", doc)
    items = {d["id"]: d for d in doc["declarations"]}
    check("a new declaration rollout gets a start", bool(items["gradual"]["rollout"].get("start")))
    check("an existing start is left alone",
          items["kept"]["rollout"]["start"] == "2020-01-01T00:00:00+00:00")
    check("a declaration without a rollout is untouched", "rollout" not in items["plain"])

    print("== 12. Device-facing declaration cache ==")
    from fastapi import Request as FastAPIRequest
    from controller.api import ddm as ddm_api

    await mac.refresh_from_db()
    ddm_manager.invalidate_declaration_cache()
    build_counts = {"n": 0}
    orig_build = ddm_manager.DDMManager.build_device_declarations

    async def counting_build(self, *args, **kwargs):
        build_counts["n"] += 1
        return await orig_build(self, *args, **kwargs)

    ddm_manager.DDMManager.build_device_declarations = counting_build

    def ddm_request(enrollment_id):
        sig = base64.b64encode(hmac_mod.new(
            b"verify-secret", b"", hashlib.sha256).digest()).decode()

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        return FastAPIRequest({
            "type": "http", "method": "GET", "path": "/ddm/tokens",
            "query_string": b"", "headers": [
                (b"x-enrollment-id", enrollment_id.encode()),
                (b"x-hmac-signature", sig.encode()),
            ],
        }, receive)

    async def simulated_sync(device):
        """The N+2 requests NanoMDM proxies for one device sync: tokens,
        declaration-items, then one GET per declaration."""
        tokens_resp = await ddm_api.ddm_tokens(ddm_request(device.udid))
        token = json.loads(tokens_resp.body)["SyncTokens"]["DeclarationsToken"]
        items_resp = await ddm_api.ddm_declaration_items(ddm_request(device.udid))
        manifest = json.loads(items_resp.body)
        served = []
        path_groups = {"Activations": "activation", "Configurations": "configuration",
                       "Assets": "asset", "Management": "management"}
        for array, group in path_groups.items():
            for entry in manifest["Declarations"][array]:
                resp = await ddm_api.ddm_declaration(
                    group, entry["Identifier"], ddm_request(device.udid))
                served.append(json.loads(resp.body))
        return token, served

    token_s1, served_s1 = await simulated_sync(mac)
    n_requests = 2 + len(served_s1)
    check("sync fetches every declaration", len(served_s1) > 2)
    check(f"one build serves the whole {n_requests}-request burst",
          build_counts["n"] == 1)
    fresh_now = await orig_build(
        ddm_manager.DDMManager(tenant), mac,
        load_declarations(tenant.id), load_groups(tenant.id))
    check("served declarations byte-identical to a fresh build",
          ddm_manager._canonical_json(_ident_map(served_s1))
          == ddm_manager._canonical_json(_ident_map(fresh_now)))
    check("served token matches a fresh build",
          ddm_manager.declarations_token(fresh_now) == token_s1)

    # An edit landing between two syncs must show the new token on the very
    # next tokens request; a stale token would make the device skip the update.
    edited = yaml.safe_load(yaml.safe_dump(DECLARATIONS_DOC))
    edited["declarations"][0]["payload"]["MinimumLength"] = 12
    _write_configs(base, declarations=edited)
    builds_before = build_counts["n"]
    token_s2, served_s2 = await simulated_sync(mac)
    check("config edit between syncs yields a new token", token_s2 != token_s1)
    check("edited payload actually served",
          _ident_map(served_s2)["mm.cfg.passcode"]["Payload"]["MinimumLength"] == 12)
    check("the post-edit sync also costs exactly one build",
          build_counts["n"] == builds_before + 1)
    _write_configs(base)

    mac.tags = ["corp", "recache"]
    await mac.save()
    builds_before = build_counts["n"]
    resp = await ddm_api.ddm_tokens(ddm_request(mac.udid))
    token_s3 = json.loads(resp.body)["SyncTokens"]["DeclarationsToken"]
    check("device tag change invalidates (properties re-tokened)",
          token_s3 != token_s1)
    check("tag-change rebuild happens once", build_counts["n"] == builds_before + 1)
    resp = await ddm_api.ddm_tokens(ddm_request(mac.udid))
    check("identical follow-up request hits the cache",
          build_counts["n"] == builds_before + 1
          and json.loads(resp.body)["SyncTokens"]["DeclarationsToken"] == token_s3)
    mac.tags = ["corp"]
    await mac.save()

    os.environ["DDM_DECL_CACHE_TTL_SECONDS"] = "0"
    builds_before = build_counts["n"]
    await simulated_sync(mac)
    check(f"TTL 0 restores the pre-cache cost ({n_requests} builds per sync)",
          build_counts["n"] == builds_before + n_requests)
    os.environ.pop("DDM_DECL_CACHE_TTL_SECONDS")

    os.environ["DDM_DECL_CACHE_MAX_DEVICES"] = "3"
    ddm_manager.invalidate_declaration_cache()
    fleet = [mac]
    for i in range(4):
        fleet.append(await new_device(f"SN-CACHE-{i}"))
    for d in fleet:
        await ddm_manager.compute_device_declarations_cached(d)
    check("entry count bounded at the configured cap",
          len(ddm_manager._DECL_CACHE) == 3)
    check("least recently used device evicted first",
          str(mac.id) not in ddm_manager._DECL_CACHE
          and str(fleet[-1].id) in ddm_manager._DECL_CACHE)
    # Cap counts devices (one per slot). Test both call forms and key presence.
    for d in (mac, fleet[-1], mac):
        await ddm_manager.compute_device_declarations_cached(d)
        await ddm_manager.compute_device_declarations_cached(d, tenant)
    check("the cap bounds devices: one entry per device, whatever the caller "
          "shape",
          sorted(ddm_manager._DECL_CACHE)
          == sorted({str(mac.id), str(fleet[3].id), str(fleet[4].id)}))
    os.environ.pop("DDM_DECL_CACHE_MAX_DEVICES")
    ddm_manager.invalidate_declaration_cache()

    # One slot per device, whoever asks. Wrapper takes no caller-supplied device_groups (see doc).
    builds_before = build_counts["n"]
    first_call = await ddm_manager.compute_device_declarations_cached(mac, tenant)
    second_call = await ddm_manager.compute_device_declarations_cached(mac)
    check("one cache slot per device, whoever asks",
          list(ddm_manager._DECL_CACHE) == [str(mac.id)])
    check("the second caller is served the first one's object, at no build cost",
          build_counts["n"] == builds_before + 1 and second_call is first_call)

    # Uncached build keeps device_groups param (fleet iteration, sync path use it).
    supplied_a = ["all-macs"]
    supplied_b = ["all-macs", "handed-in"]  # only a caller could produce this
    fresh_a = await ddm_manager.compute_device_declarations(
        mac, tenant, device_groups=supplied_a)
    fresh_b = await ddm_manager.compute_device_declarations(
        mac, tenant, device_groups=supplied_b)
    check("the uncached build still honors a caller-supplied membership list",
          fresh_a != fresh_b)
    check("and asking it through the cache ignores membership entirely",
          await ddm_manager.compute_device_declarations_cached(mac, tenant)
          is first_call and build_counts["n"] == builds_before + 3)

    # The entry is stored only when the inputs held still. A config file replaced while the build was
    # running leaves it unstored, or the old fingerprint would vouch for content built from the new file.
    ddm_manager.invalidate_declaration_cache()
    raced = yaml.safe_load(yaml.safe_dump(DECLARATIONS_DOC))
    raced["declarations"].append(
        {"id": "landed-mid-build", "type": "com.apple.configuration.passcode.settings",
         "groups": ["all-macs"], "payload": {"RequirePasscode": True}})

    async def racing_build(self, *args, **kwargs):
        result = await counting_build(self, *args, **kwargs)
        _write_configs(base, declarations=raced)  # lands before the store check
        return result

    ddm_manager.DDMManager.build_device_declarations = racing_build
    await ddm_manager.compute_device_declarations_cached(mac, tenant)
    ddm_manager.DDMManager.build_device_declarations = counting_build
    check("a config edit during the build leaves the entry unstored",
          str(mac.id) not in ddm_manager._DECL_CACHE)
    _write_configs(base)
    ddm_manager.DDMManager.build_device_declarations = orig_build
    ddm_manager.invalidate_declaration_cache()

    print("== 13. Fingerprint coverage guard ==")
    # Fingerprint must cover every device field the build can read (see doc for AST and read-set checks).
    import ast as ast_mod
    import inspect
    import textwrap
    from datetime import datetime, timedelta, timezone
    from controller.services import scoping

    vocab_tree = ast_mod.parse(textwrap.dedent(inspect.getsource(scoping._evaluate_base)))
    ctypes = set()
    for node in ast_mod.walk(vocab_tree):
        if (isinstance(node, ast_mod.Compare)
            and isinstance(node.left, ast_mod.Name) and node.left.id == "ctype"):
            for comp in node.comparators:
                if isinstance(comp, ast_mod.Constant) and isinstance(comp.value, str):
                    ctypes.add(comp.value)
    check("condition vocabulary discovered from scoping source",
          {"group", "platform", "tag", "enrollment_source"} <= ctypes)

    field_reads = set()
    attr_key_reads = set()

    class RecordingDict(dict):
        def get(self, key, default=None):
            attr_key_reads.add(key)
            return super().get(key, default)

        def __getitem__(self, key):
            attr_key_reads.add(key)
            return super().__getitem__(key)

    class RecordingDevice:
        """Wraps a real device; records every field and attributes key read."""

        def __init__(self, wrapped):
            self.__dict__["_wrapped"] = wrapped

        def __getattr__(self, name):
            field_reads.add(name)
            value = getattr(self.__dict__["_wrapped"], name)
            if name == "attributes":
                # Non-empty, so "attributes or {}" callers keep the recorder.
                return RecordingDict(value or {"enrollment_source": "ota"})
            return value

    # One single-condition group per discovered type: every group is evaluated
    # for membership, and a lone condition cannot be short-circuited past.
    guard_groups = [
        {"name": f"guard-{t}",
         "conditions": [{"type": t, "operator": "equals", "value": "x"}]}
        for t in sorted(ctypes)
    ]
    # A rollout already under way (include_devices makes the scope pass), so the wave-bucket path reads
    # its device key too.
    recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    guard_doc = {"declarations": [
        {"id": "guard-rollout", "type": "com.apple.configuration.passcode.settings",
         "include_devices": [mac.serial_number],
         "rollout": {"percent": 10, "interval_hours": 24, "start": recent},
         "payload": {"Note": "{serial_number} {udid} {device_name} {hostname}"}},
    ]}
    spy = RecordingDevice(mac)
    check("support gate exercised on the proxy",
          isinstance(ddm_manager.device_supports_ddm(spy), bool))
    await manager.build_device_declarations(spy, guard_doc, guard_groups)
    check("proxy recorded a meaningful read set",
          {"serial_number", "device_model", "tags"} <= field_reads
          and "enrollment_source" in attr_key_reads)
    uncovered = sorted(field_reads - set(ddm_manager._FINGERPRINT_DEVICE_FIELDS))
    check(f"every device field the build reads is fingerprinted (uncovered: {uncovered})",
          not uncovered)
    unkeyed = sorted(attr_key_reads - set(ddm_manager._FINGERPRINT_ATTRIBUTE_KEYS))
    check(f"every attributes key the build reads is fingerprinted (unkeyed: {unkeyed})",
          not unkeyed)

    # Proxy sees only device reads, not caller inputs (see doc). Check signature against fingerprinted set.
    supplied_params = set(
        inspect.signature(ddm_manager.compute_device_declarations_cached).parameters
    ) - {"device", "tenant"}
    check(f"the wrapper takes no unfingerprinted caller input "
          f"(signature: {sorted(supplied_params)})",
          supplied_params == set(ddm_manager._FINGERPRINT_SUPPLIED_INPUTS))

    fp = ddm_manager._declaration_fingerprint

    # Dispatcher's .only() row must carry every fingerprinted field.
    missing_from_sweep = sorted(set(ddm_manager._FINGERPRINT_DEVICE_FIELDS)
                                - set(dispatcher._SWEEP_DEVICE_FIELDS))
    check(f"the sweep's .only() row carries every fingerprinted field "
          f"(missing: {missing_from_sweep})",
          not missing_from_sweep)
    await mac.refresh_from_db()
    partial = await Device.filter(id=mac.id).only(*dispatcher._SWEEP_DEVICE_FIELDS).first()
    check("a sweep partial row fingerprints identically to the full row",
          partial is not None and fp(tenant, partial) == fp(tenant, mac))

    print("== 14. Dispatcher path: the declaration_drift build hits the cache ==")
    # Restore real evaluate_device (was stubbed in section 5) to measure through the real entry point.
    dispatcher.evaluate_device = real_evaluate_device
    try:
        (base / "tenants" / "default" / "dispatcher.yaml").write_text(yaml.safe_dump({
            "rules": [{"id": "decl-drift", "name": "Declaration drift",
                       "severity": "yellow", "grace_minutes": 0,
                       "check": {"type": "declaration_drift"},
                       "actions": [], "auto_resolve": True}],
        }))
        check("fixture device is on the DDM path", mac.ddm_enabled_at is not None)
        snapshot = list(mac.groups or [])
        ddm_manager.invalidate_declaration_cache()
        ddm_manager.DDMManager.build_device_declarations = counting_build
        before = build_counts["n"]
        await dispatcher.evaluate_device(mac, reason="verify", tenant=tenant)
        first = build_counts["n"] - before
        await dispatcher.evaluate_device(mac, reason="verify", tenant=tenant)
        second = build_counts["n"] - before - first
        # Both halves matter: without the first, a skipped _build_ctx branch
        # would be indistinguishable from a cache hit.
        check("the dispatcher's desired-set build actually ran", first == 1)
        check("a second evaluation inside the TTL costs no build", second == 0)
        # Drift check shares the device-facing slot (see doc). Assert all cache keys.
        check("the dispatcher's build landed in the one slot this device has",
              list(ddm_manager._DECL_CACHE) == [str(mac.id)])
        # The snapshot is still handed to _build_ctx, whose signature takes one, though production
        # passes None and rule scoping reads the column separately. The DDM desired set ignores it.
        ctx_hit = await dispatcher._build_ctx(
            mac, tenant, [{"check": {"type": "declaration_drift"}}], snapshot)
        third = build_counts["n"] - before - first - second
        check("a third pass through _build_ctx costs no build either", third == 0)
        # api/ddm.py calls compute_device_declarations_cached(device), so this is the device-facing
        # serve path asking for its own set and being handed the object the drift check just read.
        served = await ddm_manager.compute_device_declarations_cached(mac)
        fourth = build_counts["n"] - before - first - second - third
        check("the device-facing serve path shares the dispatcher's entry",
              fourth == 0 and ctx_hit.get("ddm_desired") is served)
        # The comparison build below is deliberate and uncached, so it is taken
        # after the arithmetic above rather than inside it.
        check("the served set is what the check reads, and matches a fresh build",
              bool(ctx_hit.get("ddm_desired"))
              and ctx_hit["ddm_desired"] == await ddm_manager.compute_device_declarations(
                  mac, tenant))
    finally:
        dispatcher.evaluate_device = fake_evaluate
        ddm_manager.DDMManager.build_device_declarations = orig_build
        ddm_manager.invalidate_declaration_cache()

    print("== 15. A refused enqueue is handled, recorded and backed off ==")
    # A NanoMDM refusal of a DeclarativeManagement enqueue is an outcome, not an exception out of
    # sync_device into whichever loop is iterating the fleet.
    import logging
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz

    import httpx

    from controller.services import reconciler

    class RefusingConnector:
        """MDMConnector stand-in whose enqueue is refused."""

        def __init__(self, exc=None):
            self.calls = 0
            self._exc = exc

        async def declarative_management(self, udid, tokens_json=None):
            self.calls += 1
            if self._exc is not None:
                raise self._exc
            request = httpx.Request("PUT", f"http://nanomdm:9000/v1/enqueue/{udid}")
            raise httpx.HTTPStatusError(
                "Server error '500 Internal Server Error'",
                request=request, response=httpx.Response(500, request=request))

        async def close(self):
            pass

    class _LogCapture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []

        def emit(self, record):
            self.records.append(record)

    ddm_log = logging.getLogger("controller.services.ddm_manager")

    async def sync_capturing(device, connector, reason="verify", **kwargs):
        """One sync attempt, with everything ddm_manager logged during it."""
        cap = _LogCapture()
        ddm_log.addHandler(cap)
        try:
            outcome = await ddm_manager.sync_device(
                device, reason=reason, mdm_connector=connector, **kwargs)
        finally:
            ddm_log.removeHandler(cap)
        return outcome, cap.records

    async def rewind_failure(device, minutes):
        """Age the recorded failure so its backoff window has passed."""
        await device.refresh_from_db()
        attrs = dict(device.attributes or {})
        state = dict(attrs.get(ddm_manager.SYNC_FAILURE_KEY) or {})
        state["at"] = (_dt.now(_tz.utc) - _td(minutes=minutes)).isoformat()
        attrs[ddm_manager.SYNC_FAILURE_KEY] = state
        await Device.filter(id=device.id).update(attributes=attrs)
        await device.refresh_from_db()

    ddm_manager.invalidate_declaration_cache()
    refused = await new_device("SN-REFUSE")
    first_connector = RefusingConnector()
    outcome, records = await sync_capturing(refused, first_connector)
    check("a refused enqueue does not escape sync_device", first_connector.calls == 1)
    check("a refusal is falsy, so the reconciler's queued counter does not move",
          bool(outcome) is False)
    check("and is an EnqueueFailed, so a refusal is tellable from a no-op",
          isinstance(outcome, ddm_manager.EnqueueFailed))
    check("a rejected enqueue costs exactly one log line",
          len(records) == 1 and "not queued" in records[0].getMessage())
    check("that line names the device and the status, with no traceback",
          records[0].levelno == logging.WARNING
          and records[0].exc_info is None
          and "SN-REFUSE" in records[0].getMessage()
          and "HTTP 500" in records[0].getMessage())

    await refused.refresh_from_db()
    recorded = (refused.attributes or {}).get(ddm_manager.SYNC_FAILURE_KEY) or {}
    stale_token = recorded.get("declarations_token")
    check("the failure is recorded on the device's DDM state",
          recorded.get("attempts") == 1 and "HTTP 500" in (recorded.get("reason") or "")
          and bool(stale_token))
    check("a refused enqueue does not stamp the published token "
          "(so nothing later reads it as sent)",
          refused.ddm_last_published_token is None)
    failed_task = await Task.filter(tenant=tenant, device=refused, type="ddm_sync",
                                    status="failed").order_by("-created_at").first()
    check("a failed ddm_sync task shows the refusal on the device's commands",
          failed_task is not None and "HTTP 500" in (failed_task.error or ""))
    # Born terminal, so nothing else ever stamps this, and task retention keys
    # on it: a NULL leaves one row per refusal per device forever.
    check("and it is stamped completed, so retention can reclaim it",
          failed_task is not None and failed_task.completed_at is not None)

    # The record must make the next cycle not try again.
    held_connector = RefusingConnector()
    outcome_held, records_held = await sync_capturing(refused, held_connector)
    check("the next cycle inside the backoff does not attempt the same set again",
          held_connector.calls == 0)
    check("and says nothing at all while it is holding off", records_held == [])
    # A held-off device was sent nothing, so it must not read as the quiet already-in-sync no-op. A
    # refusal never stamps the published token, so the no-op branch can never explain the silence.
    check("holding off is falsy, so no fleet loop counts it as a sync",
          bool(outcome_held) is False)
    check("but it is a SyncHeldOff, tellable from both a no-op and a refusal",
          isinstance(outcome_held, ddm_manager.SyncHeldOff)
          and not isinstance(outcome_held, ddm_manager.EnqueueFailed))
    check("and it carries why, and when the next attempt is due",
          "HTTP 500" in outcome_held.reason
          and outcome_held.retry_at is not None
          and outcome_held.retry_at > _dt.now(_tz.utc))
    # Somebody asking for this explicitly gets an attempt, and asking does not
    # discard the record, so the automatic retries stay on the curve.
    bypass_connector = RefusingConnector()
    bypass_outcome, _bypass_records = await sync_capturing(
        refused, bypass_connector, ignore_backoff=True)
    check("ignore_backoff attempts anyway", bypass_connector.calls == 1)
    check("and gets a real refusal instead of the held-off answer",
          isinstance(bypass_outcome, ddm_manager.EnqueueFailed))
    await refused.refresh_from_db()
    check("and the consecutive count grew instead of restarting",
          ((refused.attributes or {}).get(ddm_manager.SYNC_FAILURE_KEY) or {})
          .get("attempts") == 2)

    # A new set gets attempted now, not held back (same rule as reconciler deployments).
    edited = yaml.safe_load(yaml.safe_dump(DECLARATIONS_DOC))
    edited["declarations"][0]["payload"]["MinimumLength"] = 14
    _write_configs(base, declarations=edited)
    moved_connector = RefusingConnector()
    await sync_capturing(refused, moved_connector)
    check("a declaration set that has changed since the refusal is attempted now",
          moved_connector.calls == 1)
    await refused.refresh_from_db()
    moved_state = (refused.attributes or {}).get(ddm_manager.SYNC_FAILURE_KEY) or {}
    check("a different set restarts the count rather than continuing it",
          moved_state.get("attempts") == 1
          and moved_state.get("declarations_token") != stale_token)

    # Consecutive refusals of the same set back off further each time.
    await rewind_failure(refused, reconciler.RETRY_MINUTES + 1)
    again_connector = RefusingConnector()
    await sync_capturing(refused, again_connector)
    await refused.refresh_from_db()
    repeat_state = (refused.attributes or {}).get(ddm_manager.SYNC_FAILURE_KEY) or {}
    check("an expired backoff attempts the same set again", again_connector.calls == 1)
    check("consecutive refusals of one set accumulate", repeat_state.get("attempts") == 2)
    check("the backoff curve is the reconciler's, imported rather than restated",
          ddm_manager.DDMManager._retry_wait_minutes(1) == reconciler.RETRY_MINUTES
          and ddm_manager.DDMManager._retry_wait_minutes(2) == 2 * reconciler.RETRY_MINUTES
          and ddm_manager.DDMManager._retry_wait_minutes(99) == reconciler.RETRY_MAX_MINUTES)

    # An unexpected failure is still handled, but keeps its traceback: the quiet one-liner is for the
    # two operational failures, not for everything.
    odd = await new_device("SN-ODD")
    odd_outcome, odd_records = await sync_capturing(
        odd, RefusingConnector(exc=RuntimeError("something unmodelled")))
    check("an unexpected failure is handled too, not raised",
          isinstance(odd_outcome, ddm_manager.EnqueueFailed))
    check("but keeps its traceback, since nothing here understands it",
          len(odd_records) == 1
          and odd_records[0].levelno == logging.ERROR
          and odd_records[0].exc_info is not None)

    # NanoMDM's reason must pass through the classifier (see doc).
    from controller.services.mdm_connector import EnqueueError

    nano_request = httpx.Request("PUT", "http://nanomdm:9000/v1/enqueue/UDID-SN-DETAIL")

    def enqueue_error(text):
        return EnqueueError(text, request=nano_request,
                            response=httpx.Response(500, request=nano_request))

    nano_text = ("NanoMDM did not queue the command for UDID-SN-DETAIL: "
                 "pq: insert or update on table \"enrollment_queue\" violates "
                 "foreign key constraint")
    detailed = await new_device("SN-DETAIL")
    detail_outcome, detail_records = await sync_capturing(
        detailed, RefusingConnector(exc=enqueue_error(nano_text)))
    check("an enqueue error carries NanoMDM's own reason, not just the status",
          "foreign key constraint" in detail_outcome.reason
          and "foreign key constraint" in detail_records[0].getMessage())
    check("and says it once, with no status prefix restating what it already says",
          detail_outcome.reason == nano_text)
    check("and still counts as operational, so it stays a one-line warning",
          len(detail_records) == 1
          and detail_records[0].levelno == logging.WARNING
          and detail_records[0].exc_info is None)
    detail_task = await Task.filter(tenant=tenant, device=detailed, type="ddm_sync",
                                    status="failed").first()
    check("and reaches the failed task an admin actually reads",
          detail_task is not None
          and "foreign key constraint" in (detail_task.error or ""))

    plain = await new_device("SN-PLAIN")
    plain_outcome, _plain_records = await sync_capturing(plain, RefusingConnector())
    check("a bare status error keeps the status in front and appends its message",
          plain_outcome.reason.startswith(
              "NanoMDM rejected the enqueue with HTTP 500")
          and "Server error" in plain_outcome.reason)

    long_outcome, _long_records = await sync_capturing(
        await new_device("SN-LONG"), RefusingConnector(exc=enqueue_error("x" * 5000)))
    check("and the reason is bounded, since it lands in a log line, a task "
          "column and a JSON attribute",
          len(long_outcome.reason) <= 300)
    long_plain, _long_plain_records = await sync_capturing(
        await new_device("SN-LONGPLAIN"),
        RefusingConnector(exc=httpx.HTTPStatusError(
            "y" * 5000, request=nano_request,
            response=httpx.Response(500, request=nano_request))))
    check("and the bound covers the whole composed phrase, not just the part "
          "appended to it",
          len(long_plain.reason) <= 300)

    # And a sync that goes through clears the record, so an old failure cannot
    # delay a later genuine one.
    await rewind_failure(refused, reconciler.RETRY_MAX_MINUTES + 1)
    FakeConnector.calls.clear()
    recovered = await ddm_manager.sync_device(
        refused, reason="verify", mdm_connector=FakeConnector())
    await refused.refresh_from_db()
    check("a sync that goes through queues normally again",
          recovered is True and len(FakeConnector.calls) == 1)
    check("and clears the failure record off the device",
          ddm_manager.SYNC_FAILURE_KEY not in (refused.attributes or {}))

    # Command-catalog path clears record too. Clear published token so next refusal is real.
    refused.ddm_last_published_token = None
    await refused.save()
    await ddm_manager.sync_device(
        refused, reason="verify", mdm_connector=RefusingConnector())
    await refused.refresh_from_db()
    check("a refusal is recorded again, so the next check means something",
          ddm_manager.SYNC_FAILURE_KEY in (refused.attributes or {}))
    await ddm_manager.enqueue_sync_command(refused, FakeConnector())
    await refused.refresh_from_db()
    check("a manual catalog sync clears the record on its way through",
          ddm_manager.SYNC_FAILURE_KEY not in (refused.attributes or {}))
    _write_configs(base)

    print("== 16. Removed declarations drop out of the reported status ==")
    # Device stops mentioning a declaration with no removal marker. Server prunes (see doc).
    ddm_manager.invalidate_declaration_cache()
    ghost = await new_device("SN-GHOST")

    def decl_entry(identifier, token="t1", active=True, valid="valid"):
        return {"identifier": identifier, "server-token": token,
                "active": active, "valid": valid}

    async def send_report(device, groups=None, full=False, extra=None):
        """Ingest a status report carrying the given declaration arrays."""
        items = dict(extra or {})
        if groups is not None:
            items["management"] = {"declarations": groups}
        payload = {"StatusItems": items, "Errors": []}
        if full:
            payload["FullReport"] = True
        await ddm_manager.ingest_status_report(device, payload)
        await device.refresh_from_db()

    def reported_group(device, group):
        return [e.get("identifier") for e in
                (((device.ddm_status.get("management") or {})
                  .get("declarations") or {}).get(group) or [])]

    # Author one extra declaration, so there is something that can stop being
    # served without touching the auto-managed ones.
    with_extra = yaml.safe_load(yaml.safe_dump(DECLARATIONS_DOC))
    with_extra["declarations"].append(
        {"id": "leaving", "name": "Goes away later",
         "type": "com.apple.configuration.passcode.settings",
         "groups": ["all-macs"], "payload": {"RequirePasscode": True}})
    _write_configs(base, declarations=with_extra)

    await send_report(ghost, {
        "configurations": [decl_entry("mm.cfg.passcode"), decl_entry("mm.cfg.leaving")],
        "activations": [decl_entry("mm.act.passcode")],
        "assets": [],
        "management": [decl_entry("mm.mgmt.org-info")],
    })
    check("a first report is stored as sent",
          set(reported_group(ghost, "configurations"))
          == {"mm.cfg.passcode", "mm.cfg.leaving"}
          and ghost.ddm_declaration_status.get("mm.mgmt.org-info") is not None)

    # Incremental reports keep unmentioned entries (see doc).
    await send_report(ghost, {
        "configurations": [decl_entry("mm.cfg.passcode", token="t2")],
        "activations": [],
        "assets": [],
        "management": [],
    })
    check("an incremental report keeps served entries it did not mention",
          set(reported_group(ghost, "configurations"))
          == {"mm.cfg.passcode", "mm.cfg.leaving"})
    check("and the entry it did mention is updated",
          ghost.ddm_declaration_status["mm.cfg.passcode"]["server-token"] == "t2")
    check("a required-but-empty array is no changes, not an emptied array",
          reported_group(ghost, "management") == ["mm.mgmt.org-info"]
          and reported_group(ghost, "activations") == ["mm.act.passcode"])

    # Now stop serving it. The device says nothing about the removal, so the
    # next report it makes for any reason is when the entry drops.
    _write_configs(base, declarations=DECLARATIONS_DOC)
    await send_report(ghost, {
        "configurations": [decl_entry("mm.cfg.passcode", token="t3")],
        "activations": [],
        "assets": [],
        "management": [],
    })
    check("a declaration that is no longer served drops out of the status tree",
          reported_group(ghost, "configurations") == ["mm.cfg.passcode"])
    check("and out of the flat reported map the UI and rules read",
          "mm.cfg.leaving" not in ghost.ddm_declaration_status)
    check("while everything still served is untouched",
          "mm.cfg.passcode" in ghost.ddm_declaration_status
          and "mm.mgmt.org-info" in ghost.ddm_declaration_status)

    # A device that says it still holds something no longer served is reporting
    # a removal that did not take. That is information, so it is kept.
    await send_report(ghost, {
        "configurations": [decl_entry("mm.cfg.passcode", token="t4"),
                           decl_entry("mm.cfg.leaving", valid="invalid")],
        "activations": [], "assets": [], "management": [],
    })
    check("an unserved declaration the device still asserts is kept",
          "mm.cfg.leaving" in ghost.ddm_declaration_status
          and ghost.ddm_declaration_status["mm.cfg.leaving"]["valid"] == "invalid")

    # A full report is authoritative by construction: it mentions everything it
    # wants kept, so nothing in it can be pruned.
    await send_report(ghost, {
        "configurations": [decl_entry("mm.cfg.passcode", token="t5"),
                           decl_entry("mm.cfg.leaving", valid="invalid")],
        "activations": [], "assets": [], "management": [],
    }, full=True)
    check("a full report's unserved entry survives the prune",
          "mm.cfg.leaving" in ghost.ddm_declaration_status)
    check("and a full report still replaces the tree wholesale",
          reported_group(ghost, "management") == [])

    # No served set is no evidence. With DDM off for the tenant nothing is
    # published, and that must not read as "the device holds nothing".
    tenant.ddm_enabled = False
    await tenant.save()
    ddm_manager.invalidate_declaration_cache()
    await send_report(ghost, {
        "configurations": [], "activations": [], "assets": [], "management": [],
    })
    check("an empty served set prunes nothing",
          "mm.cfg.passcode" in ghost.ddm_declaration_status
          and "mm.cfg.leaving" in ghost.ddm_declaration_status)
    tenant.ddm_enabled = True
    await tenant.save()
    ddm_manager.invalidate_declaration_cache()

    print("== 17. The server-capabilities declaration ==")
    # Server's half of capability handshake. Both payload keys required; see docs for details.
    # https://developer.apple.com/documentation/devicemanagement/managementservercapabilities
    # https://raw.githubusercontent.com/apple/device-management/release/declarative/declarations/management/server-capabilities.yaml
    ddm_manager.invalidate_declaration_cache()
    caps_device = await new_device("SN-CAPS")
    caps_set = await manager.build_device_declarations(
        caps_device, load_declarations(tenant.id), load_groups(tenant.id))
    caps_decl = _ident_map(caps_set).get("mm.mgmt.server-capabilities")
    check("every DDM device is served a server-capabilities declaration",
          caps_decl is not None)
    check("under Apple's declaration type",
          (caps_decl or {}).get("Type") == "com.apple.management.server-capabilities")
    caps_payload = (caps_decl or {}).get("Payload") or {}
    check("with exactly the two required payload keys and nothing else",
          caps_payload == {"Version": ddm_manager.DDM_PROTOCOL_VERSION,
                           "SupportedFeatures": {}})
    check("Version is a string, and the protocol version devices accept",
          isinstance(caps_payload.get("Version"), str)
          and caps_payload.get("Version") == "1.0.0")
    check("SupportedFeatures is a dictionary, present and empty",
          isinstance(caps_payload.get("SupportedFeatures"), dict)
          and caps_payload.get("SupportedFeatures") == {})
    check("it is grouped as a management declaration, so the device fetches it "
          "from /declaration/management/...",
          ddm_manager.manifest_group(caps_decl["Type"]) == "management")
    caps_manifest = ddm_manager.build_manifest(
        caps_set, ddm_manager.declarations_token(caps_set))
    check("and the manifest lists it in the Management array",
          any(i["Identifier"] == "mm.mgmt.server-capabilities"
              for i in caps_manifest["Declarations"]["Management"]))
    served_caps = _ident_map(await ddm_manager.compute_device_declarations_cached(
        caps_device, tenant))
    check("the device-facing serve path behind the cache hands out an identical declaration",
          served_caps.get("mm.mgmt.server-capabilities") == caps_decl)

    # It is capability-filtered like everything else, in both directions.
    def caps_with(management_types):
        return {"supported-payloads": {"declarations": {
            "activations": ["com.apple.activation.simple"],
            "configurations": [],
            "assets": [],
            "management": management_types,
        }}}

    caps_device.ddm_client_capabilities = caps_with(
        ["com.apple.management.organization-info"])
    await caps_device.save()
    ddm_manager.invalidate_declaration_cache()
    unadvertised = _ident_map(await manager.build_device_declarations(
        caps_device, load_declarations(tenant.id), load_groups(tenant.id)))
    check("a device that does not advertise the type is not sent it",
          "mm.mgmt.server-capabilities" not in unadvertised
          and "mm.mgmt.org-info" in unadvertised)
    caps_device.ddm_client_capabilities = caps_with(
        ["com.apple.management.organization-info",
         "com.apple.management.server-capabilities"])
    await caps_device.save()
    ddm_manager.invalidate_declaration_cache()
    advertised = _ident_map(await manager.build_device_declarations(
        caps_device, load_declarations(tenant.id), load_groups(tenant.id)))
    check("and a device that does advertise it survives the filter",
          "mm.mgmt.server-capabilities" in advertised)
    ddm_manager.invalidate_declaration_cache()

    print("== 18. A declaration that can reach nobody says so, once ==")
    # Legacy bridge needs servable https URL and a profile. Drop is logged once (see doc).
    ddm_manager.invalidate_declaration_cache()
    ddm_manager._warn_undeliverable.cache_clear()
    bridge_item = next(d for d in DECLARATIONS_DOC["declarations"]
                       if d["id"] == "bridged")
    check("a servable bridge has no reason against it",
          ddm_manager.undeliverable_reason(bridge_item, tenant.id) is None)
    check("and a declaration that is not a bridge never has one",
          ddm_manager.undeliverable_reason(
              next(d for d in DECLARATIONS_DOC["declarations"]
                   if d["id"] == "passcode"), tenant.id) is None)

    os.environ["PUBLIC_API_URL"] = "http://mdm.example.com"
    ddm_manager.invalidate_declaration_cache()
    reason = ddm_manager.undeliverable_reason(bridge_item, tenant.id)
    check("a non-https PUBLIC_API_URL is a reason, and the reason names it",
          reason is not None and "PUBLIC_API_URL" in reason and "https" in reason)

    bridge_cap = _LogCapture()
    ddm_log.addHandler(bridge_cap)
    try:
        blocked_device = await new_device("SN-BRIDGE")
        blocked_set = _ident_map(await manager.build_device_declarations(
            blocked_device, load_declarations(tenant.id), load_groups(tenant.id)))
        # Drop is logged once fleet-wide (not per device, see doc).
        for i in range(3):
            await manager.build_device_declarations(
                await new_device(f"SN-BRIDGE-{i}"),
                load_declarations(tenant.id), load_groups(tenant.id))
    finally:
        ddm_log.removeHandler(bridge_cap)
    check("the unservable bridge really is dropped from the built set",
          "mm.cfg.bridged" not in blocked_set and "mm.act.bridged" not in blocked_set)
    check("while everything else is still built", "mm.cfg.passcode" in blocked_set)
    check("the drop is said exactly once across four device builds",
          len(bridge_cap.records) == 1)
    check("and the one line names the declaration and the cause",
          "bridged" in bridge_cap.records[0].getMessage()
          and "PUBLIC_API_URL" in bridge_cap.records[0].getMessage()
          and bridge_cap.records[0].levelno == logging.WARNING)

    os.environ["PUBLIC_API_URL"] = "https://mdm.example.com"
    ddm_manager.invalidate_declaration_cache()
    ddm_manager._warn_undeliverable.cache_clear()
    check("fixing PUBLIC_API_URL clears the reason",
          ddm_manager.undeliverable_reason(bridge_item, tenant.id) is None)
    restored = _ident_map(await manager.build_device_declarations(
        blocked_device, load_declarations(tenant.id), load_groups(tenant.id)))
    check("and the declaration is served again with no other intervention",
          "mm.cfg.bridged" in restored
          and restored["mm.cfg.bridged"]["Payload"]["ProfileURL"].startswith("https://"))

    # The other way a bridge cannot be built: the profile it names is gone.
    missing_reason = ddm_manager.undeliverable_reason(
        dict(bridge_item, profile="not-in-profiles-yaml"), tenant.id)
    check("a bridge naming a profile that does not exist is a reason too",
          missing_reason is not None
          and "not-in-profiles-yaml" in missing_reason
          and "profiles.yaml" in missing_reason)
    ddm_manager._warn_undeliverable.cache_clear()

    print("== 19. A malformed status report cannot wedge a device ==")
    # StatusReport is device-supplied; ingest must guard every field (see doc for details).
    ddm_manager.invalidate_declaration_cache()
    poison = await new_device("SN-POISON")

    async def survives(report):
        """Ingest one report; False if it raised instead of coping."""
        try:
            await ddm_manager.ingest_status_report(poison, report)
        except Exception as exc:
            print(f"      (raised {type(exc).__name__}: {exc})")
            return False
        await poison.refresh_from_db()
        return True

    check("a non-object StatusItems is dropped, not raised",
          await survives({"StatusItems": ["not", "an", "object"], "Errors": []}))
    check("and nothing of it is stored", not poison.ddm_status)

    check("a non-object supported-payloads is ingested without raising",
          await survives({"StatusItems": {"management": {"client-capabilities": {
              "supported-versions": ["1.0.0"],
              "supported-payloads": "com.apple.configuration.passcode.settings",
          }}}, "Errors": []}))
    stored_caps = poison.ddm_client_capabilities or {}
    check("the poisonous key is dropped",
          not isinstance(stored_caps.get("supported-payloads"), str))
    check("while the rest of what the device advertised is kept",
          stored_caps.get("supported-versions") == ["1.0.0"])
    ddm_manager.invalidate_declaration_cache()
    check("and the device is still served a full declaration set",
          "mm.cfg.status-subscriptions" in _ident_map(
              await ddm_manager.compute_device_declarations_cached(poison, tenant)))

    # The other half: a row poisoned before the ingest guard existed has to
    # degrade to unknown-serve-everything rather than raise out of the build.
    poison.ddm_client_capabilities = {"supported-payloads": ["passcode"]}
    await poison.save()
    ddm_manager.invalidate_declaration_cache()
    check("a pre-existing poisoned row reads as unknown capabilities",
          ddm_manager.DDMManager._capability_declaration_types(poison) is None
          and ddm_manager.DDMManager._capability_status_items(poison) is None)
    poisoned_set = _ident_map(await manager.build_device_declarations(
        poison, load_declarations(tenant.id), load_groups(tenant.id)))
    check("so its build serves everything instead of failing",
          "mm.cfg.passcode" in poisoned_set
          and "mm.cfg.status-subscriptions" in poisoned_set)
    poison.ddm_client_capabilities = {}
    await poison.save()
    ddm_manager.invalidate_declaration_cache()

    check("an unhashable declaration identifier is ingested without raising",
          await survives({"StatusItems": {"management": {"declarations": {
              "activations": [{"identifier": ["not", "a", "string"],
                               "active": True, "valid": "valid"}],
              "configurations": [{"identifier": "mm.cfg.passcode", "active": True,
                                  "valid": "valid", "server-token": "t"}],
              "assets": [], "management": [],
          }}}, "Errors": []}))
    check("the well-formed entry beside it is still recorded",
          (poison.ddm_declaration_status or {}).get("mm.cfg.passcode", {})
          .get("active") is True)

    check("non-object management/device subtrees are ingested without raising",
          await survives({"StatusItems": {"management": "unavailable",
                                          "device": ["operating-system"]},
                          "Errors": 7}))
    check("the report still stamps the sync clock",
          poison.ddm_last_sync_at is not None)

    check("and after all of it the device still syncs end to end",
          "mm.cfg.status-subscriptions" in _ident_map((await simulated_sync(poison))[1]))
    ddm_manager.invalidate_declaration_cache()

    print("== 20. An unquoted YAML timestamp is served as an ISO string ==")
    # Unquoted YAML timestamps parse to datetime; serve path normalizes (see doc).
    tdir = base / "tenants" / "default"
    (tdir / "declarations.yaml").write_text(
        "declarations:\n"
        "  - id: enforce-update\n"
        "    name: Enforce update\n"
        "    type: com.apple.configuration.softwareupdate.enforcement.specific\n"
        "    groups: [all-macs]\n"
        "    payload:\n"
        "      TargetOSVersion: '15.6'\n"
        "      TargetLocalDateTime: 2026-09-01T10:00:00\n"
    )
    authored = yaml.safe_load((tdir / "declarations.yaml").read_text())
    raw_stamp = authored["declarations"][0]["payload"]["TargetLocalDateTime"]
    check("the authored value really does parse to a datetime",
          isinstance(raw_stamp, datetime))
    ddm_manager.invalidate_declaration_cache()
    stamp_device = await new_device("SN-STAMP")
    stamped = _ident_map(await manager.build_device_declarations(
        stamp_device, load_declarations(tenant.id), load_groups(tenant.id)))
    stamp_payload = stamped.get("mm.cfg.enforce-update", {}).get("Payload", {})
    check("the build normalizes it to the string the schema asks for",
          stamp_payload.get("TargetLocalDateTime") == "2026-09-01T10:00:00")
    check("and leaves the rest of the payload alone",
          stamp_payload.get("TargetOSVersion") == "15.6")

    def _serializable(obj):
        try:
            json.dumps(obj)
            return True
        except TypeError:
            return False

    check("so the built set is json-serializable", _serializable(stamped))
    served_stamp = _ident_map((await simulated_sync(stamp_device))[1])
    check("and the device-facing declaration GET serves it rather than 500ing",
          served_stamp.get("mm.cfg.enforce-update", {}).get("Payload", {})
          .get("TargetLocalDateTime") == "2026-09-01T10:00:00")
    check("the response encoder is the second half of the guard",
          b'"2026-09-01T10:00:00"'
          in ddm_api._DeclarationResponse({"When": raw_stamp}).body)
    check("an aware datetime normalizes to UTC with a Z",
          ddm_manager.json_safe(datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc))
          == "2026-09-01T10:00:00Z")
    check("and a value json already takes is passed through untouched",
          ddm_manager.json_safe("15.6") == "15.6" and ddm_manager.json_safe(6) == 6)
    _write_configs(base)
    ddm_manager.invalidate_declaration_cache()

    # Later ingest calls queued fan-out with the real spawn machinery; settle
    # it so the loop closes with no pending tasks.
    await webhook_handler.drain_deferred()
    await Tortoise.close_connections()

    print()
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s):")
        for f in _FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("All DDM checks passed.")


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
