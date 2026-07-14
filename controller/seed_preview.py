"""One-off PREVIEW seed: an example fleet + deployments + tasks + Dispatcher
alerts + ATC flow runs, for reviewing the UI locally. DEV ONLY.

Run inside the controller container (repo is bind-mounted):
    docker exec micromanage_2-controller-1 python -m controller.seed_preview

Idempotent: clears prior seeded rows for the 'default' tenant first. Config
(groups/apps/profiles/flows/dispatcher/tags .yaml) is authored on disk; this
only seeds the database and drives the real Dispatcher engine to raise alerts.
"""
import asyncio
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from controller.models.database import init_db, close_db
from controller.models.tenant import (
    Tenant, Device, Task, Alert, FlowRun, AppDeployment, ProfileDeployment,
)
from controller.services.group_manager import GroupManager
from controller.services.app_manager import AppManager
from controller.services.profile_manager import ProfileManager
from controller.services import dispatcher as dispatcher_svc

TENANT_ID = "default"
CFG = Path(os.getenv("YAML_CONFIG_PATH", "/app/yaml-configs")) / "tenants" / TENANT_ID
NOW = datetime.now(timezone.utc)


def ago(days=0, hours=0, minutes=0):
    return NOW - timedelta(days=days, hours=hours, minutes=minutes)


def load(name):
    with open(CFG / name) as f:
        return yaml.safe_load(f) or {}


MODEL_NAMES = {
    "MacBookPro18,3": "MacBook Pro (14-inch, 2021)",
    "MacBookAir15,2": "MacBook Air (15-inch, M2)",
    "MacBookPro17,1": "MacBook Pro (13-inch, M1)",
    "iPhone15,2": "iPhone 14 Pro",
    "iPhone14,5": "iPhone 13",
    "iPad13,8": "iPad Pro (12.9-inch, 5th gen)",
    "iPad11,3": "iPad Air (3rd gen)",
}
BUILDS = {
    "15.5": "24F74", "15.4": "24E248", "14.2": "23C64",
    "17.5": "21F79", "17.4": "21E236", "16.5": "20F66", "16.1": "20B82",
}


def build_attrs(model, osv, *, serial, name, supervised=True, fv=True, firewall=True,
                passcode=True, lost=False, battery=0.85, cap=256.0, avail=120.0,
                wifi="A4:83:E7:2C:1D:99"):
    a = {
        "ProductName": model,
        "ModelName": MODEL_NAMES.get(model, model),
        "OSVersion": osv,
        "BuildVersion": BUILDS.get(osv, ""),
        "SerialNumber": serial,
        "DeviceName": name or serial,
        "IsSupervised": supervised,
        "IsMDMLostModeEnabled": lost,
        "IsActivationLockEnabled": False,
        "IsDeviceLocatorServiceEnabled": True,
        "BatteryLevel": battery,
        "DeviceCapacity": cap,
        "AvailableDeviceCapacity": avail,
        "WiFiMAC": wifi,
        "BluetoothMAC": wifi.replace("99", "9A"),
        "AwaitingConfiguration": False,
        "SecurityInfo": {
            "FDE_Enabled": fv,
            "FirewallEnabled": firewall,
            "PasscodePresent": passcode,
            "PasscodeCompliant": passcode,
            "SIPEnabled": True,
            "SystemIntegrityProtectionEnabled": True,
            "FirmwarePasswordStatus": "off",
        },
    }
    return a


# serial, udid, model, os, name, state, tags, enroll_days_ago, seen_min_ago, compliance/attrs kwargs
FLEET = [
    dict(serial="C02FL1ABML85", udid="00008103-0011AABBCCDD0011", model="MacBookPro18,3",
         osv="15.5", name="IT-C02FL1ABML85", state="enrolled", tags=["corp", "executive"],
         enroll_days=52, seen_min=3,
         kw=dict(battery=0.92, cap=1024.0, avail=642.0)),
    dict(serial="C02GK2CDML86", udid="00008103-0022BBCCDDEE0022", model="MacBookAir15,2",
         osv="14.2", name="IT-C02GK2CDML86", state="enrolled", tags=["corp", "legacy-os"],
         enroll_days=40, seen_min=12,
         kw=dict(fv=False, battery=0.55, cap=512.0, avail=301.0)),
    dict(serial="C02HN3EFML87", udid="00008103-0033CCDDEEFF0033", model="MacBookPro18,3",
         osv="15.5", name="IT-C02HN3EFML87", state="enrolled", tags=["engineering"],
         enroll_days=21, seen_min=63,
         kw=dict(firewall=False, battery=0.78, cap=1024.0, avail=214.0)),
    dict(serial="DX3JK4GHIJ10", udid="00008120-0044DDEEFF001044", model="iPhone15,2",
         osv="17.5", name="iPhone — Exec", state="enrolled", tags=["corp", "executive"],
         enroll_days=33, seen_min=8,
         kw=dict(cap=256.0, avail=88.0, battery=0.64, wifi="B8:53:AC:1F:22:70")),
    dict(serial="DX3LM5KLMN11", udid="00008120-0055EEFF00112055", model="iPhone14,5",
         osv="16.1", name="iPhone — BYOD", state="enrolled", tags=["byod"],
         enroll_days=18, seen_min=41,
         kw=dict(supervised=False, passcode=False, cap=128.0, avail=19.0, battery=0.40,
                 wifi="C0:9F:42:8E:33:11")),
    dict(serial="DMPK6OPQR120", udid="00008112-0066FF0011223066", model="iPad13,8",
         osv="17.4", name="KIOSK-lobby-1", state="enrolled", tags=["kiosk"],
         enroll_days=60, seen_min=5,
         kw=dict(lost=True, cap=256.0, avail=181.0, battery=0.30, wifi="D4:61:9D:55:44:22")),
    dict(serial="DMPL7STUV131", udid="00008112-007700112233407", model="iPad11,3",
         osv="16.5", name="KIOSK-lobby-2", state="enrolled", tags=["kiosk"],
         enroll_days=59, seen_min=22,
         kw=dict(cap=64.0, avail=31.0, battery=0.88, wifi="D4:61:9D:66:55:33")),
    dict(serial="C02JX8WXML88", udid="00008103-0088223344550088", model="MacBookPro17,1",
         osv="15.4", name="IT-C02JX8WXML88", state="unenrolled", tags=["corp"],
         enroll_days=95, seen_min=4320,
         kw=dict(battery=0.71, cap=256.0, avail=140.0)),
    # DEP pre-provisioned placeholder (known by serial only, not yet enrolled).
    dict(serial="C02PENDING001", udid=None, model="MacBookAir15,2",
         osv="", name=None, state="pending", tags=["corp"],
         enroll_days=2, seen_min=None, kw=dict()),
]


async def clear():
    tenant = await Tenant.get_or_none(id=TENANT_ID)
    if not tenant:
        return
    for M in (Alert, FlowRun, Task, AppDeployment, ProfileDeployment):
        await M.filter(tenant=tenant).delete()
    await Device.filter(tenant=tenant).delete()


async def main():
    await init_db()
    tenant, _ = await Tenant.get_or_create(
        id=TENANT_ID, defaults={"name": "Default (dev)"})
    await clear()

    groups_cfg = load("groups.yaml").get("groups", [])
    apps_cfg = load("apps.yaml").get("apps", [])
    profiles_cfg = load("profiles.yaml").get("profiles", [])

    gm = GroupManager(TENANT_ID)
    am = AppManager(tenant)
    pm = ProfileManager(tenant)

    by_serial = {}
    ts_updates = {}  # device id -> (last_seen, last_polled_at, enrollment_date)

    for spec in FLEET:
        enrolled = spec["state"] == "enrolled"
        attrs = build_attrs(spec["model"], spec["osv"], serial=spec["serial"],
                            name=spec["name"], **spec["kw"]) if spec["osv"] else {}
        dev = await Device.create(
            tenant=tenant,
            udid=spec["udid"],
            serial_number=spec["serial"],
            device_model=spec["model"],
            os_version=spec["osv"],
            hostname=(spec["name"] or spec["serial"]),
            name=spec["name"],
            enrollment_state=spec["state"],
            management_type="apple_mdm",
            tags=list(spec["tags"]),
            attributes=attrs,
            poll_interval_minutes=720,  # suppress live polling during the preview
            unenrolled_at=(ago(days=3) if spec["state"] == "unenrolled" else None),
        )
        # Compute group membership from state (device_model/platform/tag conditions).
        dev.groups = gm.evaluate_device_groups(dev, groups_cfg)
        await dev.save(update_fields=["groups"])
        by_serial[spec["serial"]] = dev

        seen = ago(minutes=spec["seen_min"]) if spec["seen_min"] is not None else None
        ts_updates[dev.id] = (seen, NOW, ago(days=spec["enroll_days"]))

        if not enrolled:
            continue

        # Pre-seed "installed" deployments for everything the device is scoped
        # into, so the reconciler sees steady state (no install storm) and the
        # device's Apps/Profiles tabs are populated.
        apps = await am.evaluate_device_apps(dev, apps_cfg, groups_cfg)
        for a in apps:
            await AppDeployment.create(
                tenant=tenant, device=dev, app_id=a["app_id"],
                app_version=a["version"], status="installed", install_date=ago(days=7))
        desired, _held = await pm.evaluate_device_profiles(dev, profiles_cfg, groups_cfg)
        for p in desired:
            await ProfileDeployment.create(
                tenant=tenant, device=dev, profile_id=p["id"], status="installed",
                payload_hash=ProfileManager.desired_hash(p), install_date=ago(days=7))
        dev.installed_apps = {a["app_id"]: a["version"] for a in apps}
        dev.installed_profiles = [p["id"] for p in desired]
        await dev.save(update_fields=["installed_apps", "installed_profiles"])

    #  Dispatcher: raise real alerts by running the engine 
    for serial, dev in by_serial.items():
        if dev.enrollment_state == "enrolled":
            await dispatcher_svc.evaluate_device(dev, reason="seed")
    await dispatcher_svc.sweep(tenant)

    # Acknowledge one alert to show that lifecycle state on the board.
    fw = await Alert.filter(tenant=tenant, rule_id="firewall-required",
                            status="open").first()
    if fw:
        fw.status = "acknowledged"
        fw.acknowledged_at = ago(minutes=15)
        fw.acknowledged_by = "admin@localhost.dev"
        await fw.save(update_fields=["status", "acknowledged_at", "acknowledged_by"])

    #  Tasks: a realistic mix for the Tasks page 
    d1 = by_serial["C02FL1ABML85"]
    d4 = by_serial["DX3JK4GHIJ10"]
    d5 = by_serial["DX3LM5KLMN11"]
    d6 = by_serial["DMPK6OPQR120"]
    tasks = [
        dict(type="app_install", status="completed", device=d1, user="system",
             description="Install Slack v4.38.125", progress=100,
             started=ago(hours=2, minutes=6), completed=ago(hours=2)),
        dict(type="profile_install", status="completed", device=d1, user="system",
             description="Install profile: Corporate Wi-Fi", progress=100,
             started=ago(hours=2, minutes=5), completed=ago(hours=2, minutes=4)),
        dict(type="refresh_info", status="completed", device=d4, user="system",
             description="Refresh device information", progress=100,
             started=ago(minutes=11), completed=ago(minutes=10)),
        dict(type="lock", status="completed", device=d6, user="admin@localhost.dev",
             description="Lock device", progress=100,
             started=ago(minutes=31), completed=ago(minutes=30)),
        dict(type="app_install", status="failed", device=d5, user="system",
             description="Install Company Portal v2.5.0", progress=0,
             error="Timed out: no device response within 24h. The device may be offline.",
             started=ago(hours=25), completed=ago(hours=1)),
        dict(type="profile_install", status="running", device=d5, user="system",
             description="Install profile: Passcode Policy", progress=40,
             started=ago(minutes=5), completed=None),
    ]
    for t in tasks:
        task = await Task.create(
            tenant=tenant, type=t["type"], status=t["status"], device=t["device"],
            user=t["user"], description=t["description"], progress=t["progress"],
            error=t.get("error"), details={})
        await Task.filter(id=task.id).update(
            created_at=t["started"], started_at=t["started"], completed_at=t["completed"])

    #  ATC flow runs (for the run viewer) 
    flows = {f["id"]: f for f in load("flows.yaml").get("flows", [])}
    flow = flows.get("standard-onboarding")
    if flow:
        fhash = hashlib.sha256(
            json.dumps(flow, default=str).encode()).hexdigest()

        def tl(entries):
            return [{"at": at.isoformat(), "node": node, "message": msg}
                    for (at, node, msg) in entries]

        # Completed run (true branch: OS >= 15) on device 1.
        base = ago(days=52)
        await FlowRun.create(
            tenant=tenant, device=d1, flow_id="standard-onboarding", flow_hash=fhash,
            status="completed", current_node=None,
            completed_at=base + timedelta(minutes=4),
            context={"flow": flow, "expected": {}, "manual": False,
                     "visited": ["tag-corp", "name-device", "install-wifi", "await-info",
                                 "branch-os", "done"],
                     "timeline": tl([
                         (base, "tag-corp", "tags added=['corp'] removed=[]"),
                         (base + timedelta(seconds=1), "name-device", "set_name -> 'IT-C02FL1ABML85'"),
                         (base + timedelta(seconds=2), "install-wifi", "install_profiles queued=['wifi-corp']"),
                         (base + timedelta(seconds=3), "await-info", "waiting for device_info (timeout 60m)"),
                         (base + timedelta(minutes=3), "await-info", "resumed on device_info"),
                         (base + timedelta(minutes=3, seconds=1), "branch-os", "branch -> true"),
                         (base + timedelta(minutes=4), None, "completed"),
                     ])})

        # Completed run (false branch: legacy OS < 15) on device 2.
        d2 = by_serial["C02GK2CDML86"]
        base2 = ago(days=40)
        await FlowRun.create(
            tenant=tenant, device=d2, flow_id="standard-onboarding", flow_hash=fhash,
            status="completed", current_node=None,
            completed_at=base2 + timedelta(minutes=5),
            context={"flow": flow, "expected": {}, "manual": False,
                     "visited": ["tag-corp", "name-device", "install-wifi", "await-info",
                                 "branch-os", "tag-legacy", "done"],
                     "timeline": tl([
                         (base2, "tag-corp", "tags added=['corp'] removed=[]"),
                         (base2 + timedelta(seconds=1), "name-device", "set_name -> 'IT-C02GK2CDML86'"),
                         (base2 + timedelta(seconds=2), "install-wifi", "install_profiles queued=['wifi-corp']"),
                         (base2 + timedelta(seconds=3), "await-info", "waiting for device_info (timeout 60m)"),
                         (base2 + timedelta(minutes=4), "await-info", "resumed on device_info"),
                         (base2 + timedelta(minutes=4, seconds=1), "branch-os", "branch -> false"),
                         (base2 + timedelta(minutes=4, seconds=2), "tag-legacy", "tags added=['legacy-os'] removed=[]"),
                         (base2 + timedelta(minutes=5), None, "completed"),
                     ])})

        # Waiting run (parked on the wait_for barrier) on device 3.
        d3 = by_serial["C02HN3EFML87"]
        base3 = ago(minutes=8)
        await FlowRun.create(
            tenant=tenant, device=d3, flow_id="standard-onboarding", flow_hash=fhash,
            status="waiting", current_node="await-info",
            waiting_signal="device_info", waiting_ref=None,
            wait_deadline=NOW + timedelta(minutes=52),
            context={"flow": flow, "expected": {}, "manual": False,
                     "visited": ["tag-corp", "name-device", "install-wifi", "await-info"],
                     "timeline": tl([
                         (base3, "tag-corp", "tags added=['corp'] removed=[]"),
                         (base3 + timedelta(seconds=1), "name-device", "set_name -> 'IT-C02HN3EFML87'"),
                         (base3 + timedelta(seconds=2), "install-wifi", "install_profiles queued=['wifi-corp']"),
                         (base3 + timedelta(seconds=3), "await-info", "waiting for device_info (timeout 60m)"),
                     ])})

    #  Final timestamp pass (bypass auto_now so 'last seen' looks realistic) 
    for dev_id, (seen, polled, enrolled_at) in ts_updates.items():
        fields = {"last_polled_at": polled, "enrollment_date": enrolled_at}
        if seen is not None:
            fields["last_seen"] = seen
        await Device.filter(id=dev_id).update(**fields)

    # Let the fire-and-forget (SSRF-blocked) lost-mode webhook settle, then report.
    await asyncio.sleep(0.3)
    print(" seed complete ")
    for M in (Device, AppDeployment, ProfileDeployment, Task, Alert, FlowRun):
        print(f"  {M.__name__:18} {await M.filter(tenant=tenant).count()}")
    print("  alerts by severity:")
    for sev in ("black", "red", "yellow", "green"):
        n = await Alert.filter(tenant=tenant, severity=sev).count()
        if n:
            print(f"    {sev:7} {n}")
    await close_db()


if __name__ == "__main__":
    asyncio.run(main())
