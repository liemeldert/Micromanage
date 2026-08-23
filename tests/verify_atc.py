"""End-to-end test of the ATC flow engine: start dispatch, state machine, alerts.

Run:  PYTHONPATH=. ./.venv/bin/python tests/verify_atc.py Exits non-zero if any check fails.
"""

import copy
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Encryption-at-rest has to be configured before crypto_secrets is first used: the managed-admin escrow refuses to store
# plaintext. It is read lazily, so setting it at import time is enough.
from cryptography.fernet import Fernet

os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import yaml
from tortoise import Tortoise

_FAILURES = []

# Captured AccountConfiguration sends, and the switch that makes the next one raise inside the connector, which is the
# case where the command never left the server.
ACCOUNT_CMDS = []
ACCOUNT_SEND_FAILS = {"on": False}

# Tenant ids handed to the reconcile coalescer.
RECONCILE_CALLS = []

# The password on the Wi-Fi profile the DEP flow installs. Distinctive, so a search of the stored task row can only
# match the real thing.
WIFI_PROFILE_PASSWORD = "corpnet-psk-9a3e"


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        _FAILURES.append(name)


def _returns(value):
    """A stand-in for a coroutine function that always answers with value."""

    async def _fn(*args, **kwargs):
        return value

    return _fn


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

    async def account_configuration(self, udid, **kwargs):
        ACCOUNT_CMDS.append({"udid": udid, **kwargs})
        if ACCOUNT_SEND_FAILS["on"]:
            raise RuntimeError("MDM refused AccountConfiguration")
        return {"command_uuid": "u-acct"}

    async def close(self):
        pass


# A single flow with several start nodes. Starts scoped to "NOSUCH" never match a real event; the tests drive them
# manually via start_run_from_start.
BASE_FLOW = {
    "id": "main",
    "name": "Main flow",
    "enabled": True,
    "nodes": [
        # ==DEP/ADE enrollment onboarding (Mac)==
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

        # ==OTA / manual enrollment==
        {"id": "s-profile", "type": "start",
         "params": {"kind": "enroll_profile", "match": {}}, "next": "p-tag"},
        {"id": "p-tag", "type": "assign_tag", "params": {"tags": ["ota"]}, "next": "p-end"},
        {"id": "p-end", "type": "end"},

        # ==Check-in trigger (parks so dedup is observable)==
        {"id": "s-checkin", "type": "start",
         "params": {"kind": "checkin", "match": {}}, "next": "c-wait"},
        {"id": "c-wait", "type": "wait_for",
         "params": {"signal": "device_info", "timeout_minutes": 5}, "next": "c-end"},
        {"id": "c-end", "type": "end"},

        # ==Check-in triggers with no barrier, leaving the active-run guard nothing to hold, so only the cooldown
        #    stands between them and one run per check-in. Each is scoped to its own serial.==
        {"id": "s-loop", "type": "start",
         "params": {"kind": "checkin", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["LOOP-1"]}]}},
         "next": "loop-tag"},
        {"id": "loop-tag", "type": "assign_tag", "params": {"tags": ["looped"]},
         "next": "loop-end"},
        {"id": "loop-end", "type": "end"},

        {"id": "s-short", "type": "start",
         "params": {"kind": "checkin", "cooldown_minutes": 5, "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["SHORT-1"]}]}},
         "next": "loop-tag"},

        {"id": "s-nocool", "type": "start",
         "params": {"kind": "checkin", "cooldown_minutes": 0, "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["NOCOOL-1"]}]}},
         "next": "loop-tag"},

        {"id": "s-once", "type": "start",
         "params": {"kind": "checkin", "once": True, "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["ONCE-1"]}]}},
         "next": "loop-tag"},

        # ==Scheduled interval (scoped to SCHED serials)==
        {"id": "s-schedule", "type": "start",
         "params": {"kind": "schedule", "interval_minutes": 60, "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["SCHED-1", "SCHED-2", "SCHED-3", "SCHED-4"]}]}},
         "next": "sch-tag"},
        {"id": "sch-tag", "type": "assign_tag", "params": {"tags": ["swept"]}, "next": "sch-end"},
        {"id": "sch-end", "type": "end"},

        # ==Human gate (manual-only)==
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

        # ==Gate with an authored total timeout under the first ladder rung: the run fails at 30 minutes with no
        #    escalation (manual-only).==
        {"id": "s-gate-short", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "gs-gate"},
        {"id": "gs-gate", "type": "manual_gate",
         "params": {"summary": "Approve this device", "severity": "yellow",
                    "timeout_minutes": 30,
                    "options": [{"label": "Approve", "edge": "on_release"}]},
         "on_release": "gs-end"},
        {"id": "gs-end", "type": "end"},

        # ==Gate with an authored timeout past the first rung but inside the second: the 4 hour escalation still
        #    runs, then the run fails at the authored 5 hours (manual-only).==
        {"id": "s-gate-long", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "gl-gate"},
        {"id": "gl-gate", "type": "manual_gate",
         "params": {"summary": "Approve this device", "severity": "yellow",
                    "timeout_minutes": 300,
                    "options": [{"label": "Approve", "edge": "on_release"}]},
         "on_release": "gl-end"},
        {"id": "gl-end", "type": "end"},

        # ==Ref-based wait (manual-only)==
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

        # ==Two sequential ref waits (regression, manual-only)==
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

        # ==Empty-expectation wait skip (manual-only)==
        {"id": "s-standalone", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "sw"},
        {"id": "sw", "type": "wait_for",
         "params": {"signal": "app_installed", "timeout_minutes": 5}, "next": "sw-end"},
        {"id": "sw-end", "type": "end"},

        # ==Three-profile barrier, then a second barrier on the same signal. Must not release a half-provisioned
        #    device (manual-only).==
        {"id": "s-all", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "all-inst"},
        {"id": "all-inst", "type": "install_profiles",
         "params": {"profile_ids": ["P1", "P2", "P3"]}, "next": "all-wait"},
        {"id": "all-wait", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "on_timeout": "all-degraded", "next": "all-inst2"},
        {"id": "all-degraded", "type": "assign_tag",
         "params": {"tags": ["provisioning-incomplete"]}, "next": "all-end"},
        {"id": "all-inst2", "type": "install_profiles",
         "params": {"profile_ids": ["P4"]}, "next": "all-wait2"},
        {"id": "all-wait2", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "next": "all-end"},
        {"id": "all-end", "type": "end"},

        # ==An install that is entitled to nothing, then a barrier on it, as gradual rollout produces on 90% of a
        #    fleet (manual-only).==
        {"id": "s-noop", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "noop-inst"},
        {"id": "noop-inst", "type": "install_apps",
         "params": {"app_ids": ["held-back"]}, "next": "noop-wait"},
        {"id": "noop-wait", "type": "wait_for",
         "params": {"signal": "app_installed", "timeout_minutes": 5},
         "next": "noop-end"},
        {"id": "noop-end", "type": "end"},

        # ==A wait with no on_timeout edge: the timeout fails the run, and on an ADE device it dies holding the Mac
        #    at Remote Management (manual-only).==
        {"id": "s-held", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "held-wait"},
        {"id": "held-wait", "type": "wait_for",
         "params": {"signal": "device_info", "timeout_minutes": 5},
         "next": "held-release"},
        {"id": "held-release", "type": "release_device", "next": "held-end"},
        {"id": "held-end", "type": "end"},

        # ==An app whose rollout wave has not opened, then a barrier on it, then a release: two shipped features
        #    composing into a device that gets nothing installed (manual-only).==
        {"id": "s-rollout", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "ro-inst"},
        {"id": "ro-inst", "type": "install_apps",
         "params": {"app_ids": ["waved"]}, "next": "ro-wait"},
        {"id": "ro-wait", "type": "wait_for",
         "params": {"signal": "app_installed", "timeout_minutes": 5}, "next": "ro-release"},
        {"id": "ro-release", "type": "release_device", "next": "ro-end"},
        {"id": "ro-end", "type": "end"},

        # ==The same flow with the gate switched off, so this app cannot hold a device up (manual-only).==
        {"id": "s-optout", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "oo-inst"},
        {"id": "oo-inst", "type": "install_apps",
         "params": {"app_ids": ["waved"], "gate": False}, "next": "oo-wait"},
        {"id": "oo-wait", "type": "wait_for",
         "params": {"signal": "app_installed", "timeout_minutes": 5}, "next": "oo-release"},
        {"id": "oo-release", "type": "release_device", "next": "oo-end"},
        {"id": "oo-end", "type": "end"},

        # ==A bare barrier nothing feeds, then a release. No install step above it to explain the empty
        #    expectation, so the flow itself is wrong (manual-only).==
        {"id": "s-orphan", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "or-wait"},
        {"id": "or-wait", "type": "wait_for",
         "params": {"signal": "app_installed", "timeout_minutes": 5},
         "next": "or-release"},
        {"id": "or-release", "type": "release_device", "next": "or-end"},
        {"id": "or-end", "type": "end"},

        # ==A bare barrier nothing feeds, excused on the wait step itself: the opt-out for a flow with no producer
        #    node to put it on (manual-only).==
        {"id": "s-barewait", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "bw-wait"},
        {"id": "bw-wait", "type": "wait_for",
         "params": {"signal": "app_installed", "timeout_minutes": 5, "gate": False},
         "next": "bw-release"},
        {"id": "bw-release", "type": "release_device", "next": "bw-end"},
        {"id": "bw-end", "type": "end"},

        # ==A barrier that really holds, then a release: the flow everything else is measured against (manual-only).==
        {"id": "s-verified", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "v-inst"},
        {"id": "v-inst", "type": "install_profiles",
         "params": {"profile_ids": ["P1"]}, "next": "v-wait"},
        {"id": "v-wait", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "next": "v-release"},
        {"id": "v-release", "type": "release_device", "next": "v-end"},
        {"id": "v-end", "type": "end"},

        # ==A queued profile that never reports: the timeout edge runs on to a release, letting the device go
        #    (manual-only).==
        {"id": "s-late", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "late-inst"},
        {"id": "late-inst", "type": "install_profiles",
         "params": {"profile_ids": ["P3"]}, "next": "late-wait"},
        {"id": "late-wait", "type": "wait_for",
         "params": {"signal": "profile_installed", "timeout_minutes": 30},
         "on_timeout": "late-release", "next": "late-release"},
        {"id": "late-release", "type": "release_device", "next": "late-end"},
        {"id": "late-end", "type": "end"},

        # ==Managed-admin escrow (manual-only)==
        {"id": "s-acct", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "acct-cfg"},
        {"id": "acct-cfg", "type": "configure_accounts", "next": "acct-end",
         "params": {"primary_account": "prompt_standard", "managed_admin": True,
                    "managed_admin_shortname": "mmadmin",
                    "managed_admin_password_source": "generate"}},
        {"id": "acct-end", "type": "end"},

        # ==The two primary modes Apple ties to AutoSetupAdminAccounts, authored with no managed admin, plus the
        #    mode that needs none (manual-only).==
        {"id": "s-acct-std", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "acct-cfg-std"},
        {"id": "acct-cfg-std", "type": "configure_accounts", "next": "acct-end",
         "params": {"primary_account": "prompt_standard"}},

        {"id": "s-acct-skip", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "acct-cfg-skip"},
        {"id": "acct-cfg-skip", "type": "configure_accounts", "next": "acct-end",
         "params": {"primary_account": "skip"}},

        {"id": "s-acct-admin", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "acct-cfg-admin"},
        {"id": "acct-cfg-admin", "type": "configure_accounts", "next": "acct-end",
         "params": {"primary_account": "prompt_admin"}},

        # ==A declarative sync, with a barrier under it (manual-only)==
        {"id": "s-ddm", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "ddm-sync"},
        {"id": "ddm-sync", "type": "sync_declarations", "next": "ddm-wait"},
        {"id": "ddm-wait", "type": "wait_for",
         "params": {"signal": "declaration_applied", "timeout_minutes": 30},
         "next": "ddm-end"},
        {"id": "ddm-end", "type": "end"},

        # ==An app install that really resolves, so there is a task to read the install-source mark off. Every other
        #    install_apps node here names an app no device can get (manual-only).==
        {"id": "s-appmark", "type": "start",
         "params": {"kind": "enroll_profile", "match": {
             "conditions": [{"type": "serial_number", "operator": "in",
                             "value": ["__never__"]}]}},
         "next": "appmark-inst"},
        {"id": "appmark-inst", "type": "install_apps",
         "params": {"app_ids": ["ready"], "gate": False}, "next": "loop-end"},
    ],
}


def _write_configs(base: Path):
    tdir = base / "tenants" / "default"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "config.yaml").write_text(yaml.safe_dump(
        {"tenant": {"id": "default", "name": "Default", "allowed_users": []}}))
    (tdir / "groups.yaml").write_text(yaml.safe_dump({"groups": [
        {"name": "all-macs", "conditions": [
            {"type": "platform", "operator": "in", "value": ["Mac"]}]},
        # Matches nothing, which is how an install node that resolves nothing is reproduced: the app below is entitled
        # to no device.
        {"name": "nobody", "conditions": [
            {"type": "serial_number", "operator": "in", "value": ["__never__"]}]}]}))
    (tdir / "apps.yaml").write_text(yaml.safe_dump({"apps": [
        {"id": "held-back", "name": "Held Back", "bundle_id": "com.example.heldback",
         "versions": [{"version": "1.0", "s3_key": "apps/held-back-1.0.pkg",
                       "sha256": "b" * 64, "groups": ["nobody"]}]},
        # Scoped to every Mac, but its first wave opens in 2099, so no device is in the rollout yet. This is the
        # ordinary 10%-a-day rollout on day one, where the empty barrier is scheduled rather than accidental.
        {"id": "waved", "name": "Waved App", "bundle_id": "com.example.waved",
         "versions": [{"version": "1.0", "s3_key": "apps/waved-1.0.pkg",
                       "sha256": "c" * 64, "groups": ["all-macs"],
                       "rollout": {"percent": 10, "interval_hours": 24,
                                   "start": "2099-01-01T00:00:00+00:00"}}]},
        # Scoped to every Mac with no wave in the way, so an install_apps node naming it really queues a task.
        {"id": "ready", "name": "Ready App", "bundle_id": "com.example.ready",
         "versions": [{"version": "1.0", "s3_key": "apps/ready-1.0.pkg",
                       "sha256": "d" * 64, "groups": ["all-macs"]}]},
    ]}))
    (tdir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": [
        # Carries a password on purpose: the DEP flow installs this profile, which is what proves the tasks table never
        # holds the value.
        {"id": "eu-wifi", "name": "EU WiFi",
         "payload": {"PayloadType": "com.apple.wifi", "SSID_STR": "CorpNet",
                     "Password": WIFI_PROFILE_PASSWORD}},
        {"id": "us-wifi", "name": "US WiFi", "payload": {"PayloadType": "com.apple.wifi"}},
        {"id": "P1", "name": "Profile 1", "payload": {"PayloadType": "com.apple.test1"}},
        {"id": "P2", "name": "Profile 2", "payload": {"PayloadType": "com.apple.test2"}},
        {"id": "P3", "name": "Profile 3", "payload": {"PayloadType": "com.apple.test3"}},
        {"id": "P4", "name": "Profile 4", "payload": {"PayloadType": "com.apple.test4"}},
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

    from controller.models.tenant import (
        Alert, AuditLog, Device, DeviceSecret, FlowRun, ProfileDeployment, Task, Tenant,
    )
    from controller.services import atc, crypto_secrets
    from controller.services.flow_step_catalog import normalize_flow_document
    from controller.utils.yaml_validator import YAMLValidator

    # Record reconcile requests instead of running fleet-wide reconciles. _maybe_reconcile resolves this by module
    # attribute at call time, so the patch takes.
    import controller.services.reconciler as rec
    rec.request_reconcile = lambda tenant_id: RECONCILE_CALLS.append(str(tenant_id))

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

    def deadline_in(r, minutes):
        # Timeout precision is the poll tick, so a window, never an exact time.
        if r.wait_deadline is None:
            return False
        dl = r.wait_deadline
        if dl.tzinfo is None:
            dl = dl.replace(tzinfo=timezone.utc)
        delta = dl - datetime.now(timezone.utc)
        return timedelta(minutes=minutes - 5) < delta <= timedelta(minutes=minutes + 5)

    #  1) DEP enroll runs s-dep, applies tags/name/branch/install, parks; a
    #      green in-setup alert opens
    print("1) enroll_dep on a Mac runs s-dep and parks; green in-setup alert opens")
    dev = await new_device("MAC-EU", "host-eu-1", dep=True)
    runs = await atc.start_flows_for_event(dev, "enroll_dep")
    await dev.refresh_from_db()
    check("exactly one run started", len(runs) == 1)
    run = runs[0]
    check("entered from start node s-dep", run.start_node == "s-dep")
    check("event_kind recorded", run.event_kind == "enroll_dep")
    check("tags corp+onboarding applied", {"corp", "onboarding"} <= set(dev.tags))
    # The dep-assign node wrote through record_tag_change: one audit row naming the exact flow and node, not just "ATC".
    tag_rows = await AuditLog.filter(action="device.tags", target_id=str(dev.id)).all()
    check("assign_tag node wrote exactly one audit row", len(tag_rows) == 1)
    if tag_rows:
        d = tag_rows[0].detail or {}
        check("audit row names the flow and node",
              d.get("source") == "atc" and d.get("source_ref") == "main:dep-assign")
        check("audit row records both tags as added",
              sorted(d.get("added") or []) == ["corp", "onboarding"])
    check("name set from template", dev.name == "IT-MAC-EU")
    await run.refresh_from_db()
    check("parked waiting at dep-wait", run.status == "waiting" and run.current_node == "dep-wait")
    check("EU branch taken", "dep-eu" in (run.context or {}).get("visited", []))
    check("US branch not taken", "dep-us" not in (run.context or {}).get("visited", []))
    # The row an install leaves behind is readable by anyone who can list tasks and kept for TASK_RETENTION_DAYS. It
    # records which profile went out, not the passwords inside it.
    inst_task = await Task.filter(device=dev, type="profile_install").first()
    stored = json.dumps(inst_task.details or {}, default=str) if inst_task else ""
    check("the queued profile reaches the tasks table redacted",
          bool(inst_task) and WIFI_PROFILE_PASSWORD not in stored)
    digest = (inst_task.details or {}).get("payload_digest") or {} if inst_task else {}
    check("the row carries a digest of the real definition instead",
          bool(digest.get("sha256")) and digest.get("bytes"))
    check("and names the value it replaced",
          any("Password" in path for path in (digest.get("redacted") or [])))
    check("what is still readable is which profile went out",
          ((inst_task.details or {}).get("profile_info") or {}).get("id") == "eu-wifi"
          if inst_task else False)
    a = await active_in_setup(dev)
    check("green in-setup alert opened", a is not None and a.severity == "green" and a.status == "open")
    check("in-setup alert carries kind + release action",
          bool(a) and (a.detail or {}).get("kind") == "atc_in_setup"
          and (a.detail or {}).get("actions"))

    #  2) device_info resumes -> release_device -> completes; alert resolves
    print("2) device_info resumes the run through release_device to completion")
    await atc.advance_on_signal(str(dev.id), "device_info")
    await run.refresh_from_db()
    check("run completed", run.status == "completed")
    check("release_device visited", "dep-release" in (run.context or {}).get("visited", []))
    check("in-setup alert resolved after release", await active_in_setup(dev) is None)

    #  3) wait_for timeout follows on_timeout (degraded)
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

    #  4) DEP vs OTA dispatch: enroll_profile runs s-profile only
    print("4) enroll_profile runs the profile start (kind routing)")
    ota = await new_device("OTA-1", "host-ota")
    pruns = await atc.start_flows_for_event(ota, "enroll_profile")
    await ota.refresh_from_db()
    check("one profile run started", len(pruns) == 1 and pruns[0].start_node == "s-profile")
    check("ota tag applied + completed", "ota" in ota.tags and pruns[0].status == "completed")

    #  5) match scoping: a non-Mac device does not trigger the Mac-scoped start
    print("5) start match scope excludes out-of-scope devices")
    ipad = await new_device("IPAD-1", "host-ipad", dep=True, model="iPad13,8")
    ipad_runs = await atc.start_flows_for_event(ipad, "enroll_dep")
    check("Mac-scoped s-dep did not trigger for an iPad", ipad_runs == [])

    #  6) check-in dedup: a second check-in does not pile up a run
    print("6) checkin start dedups while a run is active")
    cdev = await new_device("CHK-1", "host-chk")
    r1 = await atc.start_flows_for_event(cdev, "checkin")
    r2 = await atc.start_flows_for_event(cdev, "checkin")
    check("first checkin started a run", len(r1) == 1)
    check("second checkin deduped (no new run)", r2 == [])
    active = await FlowRun.filter(
        device_id=cdev.id, start_node="s-checkin", status__in=["running", "waiting"]).count()
    check("exactly one active checkin run", active == 1)

    #  7) scheduled interval: launch, then skip until the interval elapses
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
    # sch-tag ran twice, once per launch, but "swept" was already on the device the second time, so _apply_tags'
    # before/after guard must keep this at one audit row.
    swept_rows = await AuditLog.filter(action="device.tags", target_id=str(sdev.id)).count()
    check("second (no-change) run wrote no additional audit row", swept_rows == 1)

    #  7b) the sweep decides a whole fleet from two queries, not two per device
    print("7b) scheduled sweep decides the fleet from prefetched sets")
    sdev2 = await new_device("SCHED-2", "host-sched2")
    sdev3 = await new_device("SCHED-3", "host-sched3")
    offscope = await new_device("NOSCHED-1", "host-nosched")
    # SCHED-2 is mid-run: write the row the dedup is meant to see, keyed by (device, flow, start).
    await FlowRun.create(
        tenant_id=tenant.id, device_id=sdev2.id, flow_id=BASE_FLOW["id"],
        start_node="s-schedule", event_kind="schedule", status="running",
        current_node="sch-tag", flow_hash="test-hash", context={},
    )
    fleet = [sdev, sdev2, sdev3, offscope]

    # Stub both per-device queries to catch regressions: fast path must not fall back.
    # Raise BaseException subclass so sweep's Exception handler won't swallow the guard failure.
    class FastPathViolation(BaseException):
        pass

    async def _no_active_run_query(device_id, start_id):
        raise FastPathViolation("sweep fell back to a per-device active-run query")

    async def _no_last_run_query(device_id, start_id):
        raise FastPathViolation("sweep fell back to a per-device last-run query")

    original_has_active_run = atc._has_active_run
    original_last_scheduled = atc._last_scheduled_for_device
    atc._has_active_run = _no_active_run_query
    atc._last_scheduled_for_device = _no_last_run_query
    n4 = -1
    try:
        n4 = await atc.sweep_scheduled_starts(tenant, fleet)
        check("fast path issued no per-device queries", True)
    except FastPathViolation as exc:
        # Caught here rather than left to escape, so a tripped guard reports as one named failure.
        check(f"fast path issued no per-device queries ({exc})", False)
    finally:
        atc._has_active_run = original_has_active_run
        atc._last_scheduled_for_device = original_last_scheduled
    check("only the never-run in-scope device launched", n4 == 1)
    check("never-run device got its run",
          await FlowRun.filter(device_id=sdev3.id, start_node="s-schedule").count() == 1)
    check("device with a run already going was skipped",
          await FlowRun.filter(device_id=sdev2.id, start_node="s-schedule").count() == 1)
    check("out-of-scope device was never considered",
          await FlowRun.filter(device_id=offscope.id, start_node="s-schedule").count() == 0)
    # SCHED-1 carries two runs by now, one aged past the interval and one from the relaunch above. The sweep has to read
    # the newest of the pair, so this catches a grouped query reaching for the wrong end of the range.
    check("device whose newest run is inside the interval did not relaunch",
          await FlowRun.filter(device_id=sdev.id, start_node="s-schedule").count() == 2)

    #  7c) a run from a DIFFERENT flow does not dedup this one: dedup keys on (device, flow, start).
    print("7c) a run from another flow with the same start id does not dedup")
    sdev4 = await new_device("SCHED-4", "host-sched4")
    await FlowRun.create(
        tenant_id=tenant.id, device_id=sdev4.id, flow_id="some-other-flow",
        start_node="s-schedule", event_kind="schedule", status="running",
        current_node="sch-tag", flow_hash="other-hash", context={},
    )
    n5 = await atc.sweep_scheduled_starts(tenant, [sdev4])
    check("the other flow's run did not block this one", n5 == 1)
    check("and the new run is recorded against this flow",
          await FlowRun.filter(device_id=sdev4.id, start_node="s-schedule",
                               flow_id=BASE_FLOW["id"]).count() == 1)

    #  8) human gate: timeout -> manual_gate -> resume down chosen edge
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
    check("waiting_signal is manual", grun.waiting_signal == "manual")
    check("parked with the ladder's first-rung deadline (4h)",
          deadline_in(grun, 240))
    gladder = (grun.context or {}).get("gate_ladder") or {}
    check("the ladder schedule is pinned on the run",
          gladder.get("schedule") == [240, 1680, 11760] and gladder.get("step") == 0)
    gate_alert = await Alert.filter(
        rule_id=f"atc:gate:{grun.id}").exclude(status="resolved").first()
    check("gate alert opened", gate_alert is not None and gate_alert.status == "open"
          and (gate_alert.detail or {}).get("kind") == "atc_gate")

    # a sweep before the rung expires must leave the gate alone
    await atc.sweep_timeouts(tenant)
    await grun.refresh_from_db()
    check("manual gate not swept before its rung expires",
          grun.status == "waiting" and grun.current_node == "g-gate")

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

    #  9) ref-based wait matches only the queued profile ref
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

    #  10) empty-expectation ref wait is skipped, not hung
    print("10) a ref-based wait with nothing queued is skipped")
    dev6 = await new_device("STANDALONE-1", "host-sa")
    run6 = await atc.start_run_from_start(dev6, "s-standalone")
    await run6.refresh_from_db()
    check("standalone wait_for(app_installed) skipped -> completed", run6.status == "completed")

    #  11) two sequential ref waits: stale ref must not satisfy the second
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

    #  12) flow_hash pinning: a breaking edit can't corrupt an in-flight run
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

    #  13) enroll supersede is scoped to the same start
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

    #  14) legacy multi-flow migration
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
    mflows, mwarns = normalize_flow_document(legacy)
    check("legacy migrated to one flow", len(mflows) == 1)
    mflow = mflows[0] if mflows else {}
    starts = [n for n in mflow.get("nodes", []) if n.get("type") == "start"]
    check("a start node was synthesized", len(starts) == 1
          and starts[0]["params"]["kind"] == "enroll_dep"
          and starts[0]["next"] == "n1")
    check("kept the first enabled flow (legacy-a)", mflow.get("id") == "legacy-a")
    check("migration emitted a warning", len(mwarns) >= 1)
    check("the migrated flow is the permanent one", mflow.get("permanent") is True)

    # The single-flow document is the previous format and upgrades silently, since a warning here would log on every
    # hot-path read until the next save.
    single, swarns = normalize_flow_document({"flow": BASE_FLOW})
    check("single-flow doc reads as one flow",
          len(single) == 1 and single[0]["id"] == BASE_FLOW["id"])
    check("single-flow upgrade is silent", swarns == [])
    check("single-flow doc is left untouched", "permanent" not in BASE_FLOW)
    check("single-flow nodes are shared, not copied",
          single[0]["nodes"] is BASE_FLOW["nodes"])

    v2doc = {"version": 2, "flows": [
        {"id": "enrollment", "name": "E", "permanent": True, "nodes": BASE_FLOW["nodes"]},
        {"id": "triage", "name": "T", "nodes": BASE_FLOW["nodes"]},
    ]}
    v2flows, v2warns = normalize_flow_document(v2doc)
    check("v2 doc keeps every flow in order",
          [f["id"] for f in v2flows] == ["enrollment", "triage"])
    check("v2 doc is silent", v2warns == [])

    #  15) flows.yaml validator
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

    # A gate timeout is optional; a malformed one is the same hard error as on wait_for. Absent must save, since the
    # escalation ladder covers it.
    def gate_doc(tmo):
        params = {"summary": "s", "severity": "yellow",
                  "options": [{"label": "Go", "edge": "on_release"}]}
        if tmo is not None:
            params["timeout_minutes"] = tmo
        return {"flow": {"id": "x", "name": "X", "nodes": [
            {"id": "s", "type": "start", "params": {"kind": "enroll_dep"}, "next": "g"},
            {"id": "g", "type": "manual_gate", "params": params, "on_release": "e"},
            {"id": "e", "type": "end"}]}}

    ok_no_tmo, errs_no_tmo, _ = validate_flow(gate_doc(None))
    check("manual_gate without timeout_minutes saves", ok_no_tmo)
    if not ok_no_tmo:
        print("      errors:", errs_no_tmo)
    check("manual_gate with a positive timeout_minutes saves",
          validate_flow(gate_doc(45))[0])
    check("a zero gate timeout is a hard error",
          any("manual_gate" in e and "timeout_minutes" in e
              for e in _err(gate_doc(0))))
    check("a negative gate timeout is a hard error",
          any("manual_gate" in e and "timeout_minutes" in e
              for e in _err(gate_doc(-5))))
    check("a boolean gate timeout is a hard error",
          any("manual_gate" in e and "timeout_minutes" in e
              for e in _err(gate_doc(True))))

    # The engine honours only a literal false, so a quoted one still holds the flow up. Warn, but do not block the save
    # over it: a flow error locks every config write for the tenant.
    quoted_gate = {"flow": {"id": "x", "name": "X", "nodes": [
        {"id": "s", "type": "start", "params": {"kind": "enroll_dep"}, "next": "i"},
        {"id": "i", "type": "install_profiles",
         "params": {"profile_ids": ["P1"], "gate": "false"}, "next": "e"},
        {"id": "e", "type": "end"}]}}
    qok, _qerrs, qwarns = validate_flow(quoted_gate)
    check("a gate that is neither true nor false warns and still saves",
          qok and any("neither true nor false" in w for w in qwarns))

    #  16) a wait_for waits for EVERY ref the run queued, not the first one
    print("16) a three-profile barrier holds until all three land")
    dev8 = await new_device("ALL-1", "host-all")
    run8 = await atc.start_run_from_start(dev8, "s-all")
    await run8.refresh_from_db()
    check("parked at all-wait", run8.status == "waiting" and run8.current_node == "all-wait")
    check("waiting_ref lists all three queued profiles",
          set((run8.waiting_ref or "").split(",")) == {"P1", "P2", "P3"})

    def satisfied_of(r, signal="profile_installed"):
        return list(((r.context or {}).get("satisfied") or {}).get(signal) or [])

    await atc.advance_on_signal(str(dev8.id), "profile_installed", ref="P1")
    await run8.refresh_from_db()
    check("one of three does NOT resume the run",
          run8.status == "waiting" and run8.current_node == "all-wait")
    # Re-read the row the way a restarted process would, to prove the partial barrier is on disk and not just on the
    # in-memory run.
    stored = await FlowRun.get(id=run8.id)
    check("the arrival is recorded durably on the run", satisfied_of(stored) == ["P1"])
    check("partial progress shows up in the timeline",
          any("1 of 3" in (t.get("message") or "")
              for t in (stored.context or {}).get("timeline", [])))

    await atc.advance_on_signal(str(dev8.id), "profile_installed", ref="P1")
    await run8.refresh_from_db()
    check("a redelivered ref is not counted twice", satisfied_of(run8) == ["P1"])

    await atc.advance_on_signal(str(dev8.id), "profile_installed", ref="P2")
    await run8.refresh_from_db()
    check("two of three still does NOT resume the run",
          run8.status == "waiting" and run8.current_node == "all-wait")
    check("both arrivals recorded", set(satisfied_of(run8)) == {"P1", "P2"})

    await atc.advance_on_signal(str(dev8.id), "profile_installed", ref="P3")
    await run8.refresh_from_db()
    check("the third arrival resumes the run",
          run8.current_node == "all-wait2" and run8.status == "waiting")
    check("the next barrier starts from a clean slate",
          satisfied_of(run8) == []
          and ((run8.context or {}).get("expected") or {}).get("profile_installed") == ["P4"])
    await atc.advance_on_signal(str(dev8.id), "profile_installed", ref="P1")
    await run8.refresh_from_db()
    check("a ref from the previous barrier does not lift this one",
          run8.current_node == "all-wait2")
    await atc.advance_on_signal(str(dev8.id), "profile_installed", ref="P4")
    await run8.refresh_from_db()
    check("the second barrier's own ref completes the run", run8.status == "completed")

    #  17) a partly-satisfied barrier that times out escalates
    print("17) a barrier stuck at 1 of 3 takes the on_timeout edge")
    dev9 = await new_device("ALL-2", "host-all2")
    run9 = await atc.start_run_from_start(dev9, "s-all")
    await atc.advance_on_signal(str(dev9.id), "profile_installed", ref="P1")
    await run9.refresh_from_db()
    check("still parked with one of three in", run9.current_node == "all-wait")
    await FlowRun.filter(id=run9.id).update(
        wait_deadline=datetime.now(timezone.utc) - timedelta(minutes=1))
    await atc.sweep_timeouts(tenant)
    await run9.refresh_from_db()
    await dev9.refresh_from_db()
    check("timeout edge taken instead of the happy path",
          "all-degraded" in (run9.context or {}).get("visited", []))
    check("all-inst2 never ran", "all-inst2" not in (run9.context or {}).get("visited", []))
    check("the device is tagged as incomplete", "provisioning-incomplete" in dev9.tags)
    check("run finished down the degraded path", run9.status == "completed")

    #  18) the pre-park check needs every ref too, not just one
    print("18) the pre-park check requires all refs to be installed already")
    dev10 = await new_device("PRE-1", "host-pre1")
    for pid in ("P1", "P2"):
        await mark_installed(dev10, pid)
    run10 = await atc.start_run_from_start(dev10, "s-all")
    await run10.refresh_from_db()
    check("two of three installed at park time still parks the run",
          run10.status == "waiting" and run10.current_node == "all-wait")

    dev11 = await new_device("PRE-2", "host-pre2")
    for pid in ("P1", "P2", "P3"):
        await mark_installed(dev11, pid)
    run11 = await atc.start_run_from_start(dev11, "s-all")
    await run11.refresh_from_db()
    check("all three installed at park time skips the barrier",
          run11.current_node == "all-wait2")
    check("the skip is recorded in the timeline",
          any("wait skipped" in (t.get("message") or "")
              for t in (run11.context or {}).get("timeline", [])))

    #  19) configure_accounts settles the escrow against the device's answer
    print("19) the managed-admin escrow is reconciled against the acknowledgement")

    async def account_task(device):
        return await Task.filter(
            device_id=device.id, type="account_configuration").order_by("-created_at").first()

    # AccountConfiguration is an Automated Device Enrollment command (account.configuration.yaml marks it requiresdep on
    # macOS), so every device in this section enrols that way.
    dev12 = await new_device("ACCT-1", "host-acct1", dep=True)
    await atc.start_run_from_start(dev12, "s-acct")
    sec12 = await DeviceSecret.get_or_none(device_id=dev12.id,
                                           kind=DeviceSecret.KIND_MANAGED_ADMIN)
    task12 = await account_task(dev12)
    check("managed-admin password escrowed", sec12 is not None)
    check("escrow is marked unconfirmed until the Mac answers",
          bool(sec12) and (sec12.meta or {}).get("unconfirmed_task_id") == str(task12.id))
    check("no confirmation stamp yet", bool(sec12) and "confirmed_at" not in (sec12.meta or {}))

    task12.status = "completed"
    await task12.save()
    await atc.advance_on_signal(str(dev12.id), "command_ack", ref=str(task12.id))
    await sec12.refresh_from_db()
    check("an acknowledgement clears the unconfirmed marker",
          "unconfirmed_task_id" not in (sec12.meta or {}))
    check("and stamps when it was confirmed", "confirmed_at" in (sec12.meta or {}))

    # A Mac that answers with an error keeps the marker, plus a reason.
    dev13 = await new_device("ACCT-2", "host-acct2", dep=True)
    await atc.start_run_from_start(dev13, "s-acct")
    task13 = await account_task(dev13)
    task13.status = "failed"
    task13.error = "AccountConfiguration rejected by the device"
    await task13.save()
    await atc.advance_on_signal(str(dev13.id), "command_ack", ref=str(task13.id))
    sec13 = await DeviceSecret.get_or_none(device_id=dev13.id,
                                           kind=DeviceSecret.KIND_MANAGED_ADMIN)
    check("a failed AccountConfiguration leaves the escrow unconfirmed",
          bool(sec13) and (sec13.meta or {}).get("unconfirmed_task_id") == str(task13.id))
    check("with the device's reason attached",
          bool(sec13) and "rejected by the device" in (sec13.meta or {}).get("unconfirmed_reason", ""))
    check("and no confirmation stamp", bool(sec13) and "confirmed_at" not in (sec13.meta or {}))

    # A send that never leaves the server: nothing was created, so nothing is kept.
    print("19b) a send that fails rolls the escrow back")
    ACCOUNT_SEND_FAILS["on"] = True
    dev14 = await new_device("ACCT-3", "host-acct3", dep=True)
    run14 = await atc.start_run_from_start(dev14, "s-acct")
    await run14.refresh_from_db()
    check("no escrow left behind for an account that was never created",
          await DeviceSecret.filter(device_id=dev14.id,
                                    kind=DeviceSecret.KIND_MANAGED_ADMIN).count() == 0)
    check("the audit task records the failure",
          (await account_task(dev14)).status == "failed")
    check("the rollback is visible in the run timeline",
          any("rolled back" in (t.get("message") or "")
              for t in (run14.context or {}).get("timeline", [])))

    # The same failure on a device that already had a password must not eat it.
    await sec12.refresh_from_db()
    kept_pw = crypto_secrets.decrypt(sec12.value_enc)
    sec12.revealed_by = "admin@x"
    sec12.reveal_count = 2
    await sec12.save()
    await atc.start_run_from_start(dev12, "s-acct")
    await sec12.refresh_from_db()
    check("the previously escrowed password survives a failed re-run",
          crypto_secrets.decrypt(sec12.value_enc) == kept_pw)
    check("and so does its reveal ledger",
          sec12.reveal_count == 2 and sec12.revealed_by == "admin@x")
    ACCOUNT_SEND_FAILS["on"] = False

    # ==19c) the two primary modes Apple ties to AutoSetupAdminAccounts==
    # Both require AutoSetupAdminAccounts when true; sending without one leaves no administrator.
    print("19c) skip / Standard with no managed admin: nothing is sent")

    def timeline_of(r):
        return " | ".join(t.get("message") or "" for t in (r.context or {}).get("timeline", []))

    sent_before = len(ACCOUNT_CMDS)
    dev15 = await new_device("ACCT-STD", "host-acct-std", dep=True)
    run15 = await atc.start_run_from_start(dev15, "s-acct-std")
    await run15.refresh_from_db()
    check("Standard with no managed admin sends no AccountConfiguration",
          len(ACCOUNT_CMDS) == sent_before)
    task15 = await account_task(dev15)
    check("an audit task records the refusal", bool(task15) and task15.status == "failed")
    check("and names Apple's rule",
          bool(task15) and "AutoSetupAdminAccounts" in (task15.error or ""))
    check("the timeline says why nothing was sent",
          "AutoSetupAdminAccounts" in timeline_of(run15))
    check("the refusal is on the gap ledger as broken, so a release cannot call the "
          "run clean",
          any(g.get("grade") == "broken"
              and any(i.get("id") == "account_configuration" for i in (g.get("items") or []))
              for g in (run15.context or {}).get("gaps") or []))
    check("no password is escrowed for an admin that was never asked for",
          await DeviceSecret.filter(device_id=dev15.id,
                                    kind=DeviceSecret.KIND_MANAGED_ADMIN).count() == 0)

    dev16 = await new_device("ACCT-SKIP", "host-acct-skip", dep=True)
    run16 = await atc.start_run_from_start(dev16, "s-acct-skip")
    await run16.refresh_from_db()
    check("skip with no managed admin sends nothing either",
          len(ACCOUNT_CMDS) == sent_before)
    check("and says so", "AutoSetupAdminAccounts" in timeline_of(run16))

    print("19c-i) near miss: the Admin mode needs no managed admin and still sends")
    dev17 = await new_device("ACCT-ADMIN", "host-acct-admin", dep=True)
    await atc.start_run_from_start(dev17, "s-acct-admin")
    check("prompt_admin with no managed admin is sent", len(ACCOUNT_CMDS) == sent_before + 1)
    task17 = await account_task(dev17)
    check("its audit task is running, not failed",
          bool(task17) and task17.status == "running")

    print("19c-ii) managed_admin on but no password produced: still refused")
    # The check reads what was built, not what was asked for: a managed admin whose password comes back empty leaves
    # auto_admins unset, which is the same command as never asking for one.
    import controller.services.account_hash as ah
    real_generate = ah.generate_password
    ah.generate_password = lambda *a, **k: ""
    try:
        dev18 = await new_device("ACCT-EMPTY", "host-acct-empty", dep=True)
        run18 = await atc.start_run_from_start(dev18, "s-acct")
    finally:
        ah.generate_password = real_generate
    await run18.refresh_from_db()
    check("nothing sent when the managed admin came out empty",
          len(ACCOUNT_CMDS) == sent_before + 1)
    check("and the refusal names Apple's rule rather than the empty password alone",
          "AutoSetupAdminAccounts" in timeline_of(run18))
    check("no escrow row for it",
          await DeviceSecret.filter(device_id=dev18.id,
                                    kind=DeviceSecret.KIND_MANAGED_ADMIN).count() == 0)

    # ==19d) AccountConfiguration only goes to a Mac that enrolled through ADE==
    print("19d) a hand-enrolled Mac skips the step instead of escrowing for an "
          "account that will never exist")
    dev19 = await new_device("ACCT-OTA", "host-acct-ota")
    run19 = await atc.start_run_from_start(dev19, "s-acct")
    await run19.refresh_from_db()
    check("nothing sent to a Mac that did not come through ADE",
          len(ACCOUNT_CMDS) == sent_before + 1)
    check("no audit task either, since the step never got that far",
          await account_task(dev19) is None)
    check("no managed-admin password escrowed for an account that will not exist",
          await DeviceSecret.filter(device_id=dev19.id,
                                    kind=DeviceSecret.KIND_MANAGED_ADMIN).count() == 0)
    check("the timeline names the reason",
          "Automated Device Enrollment" in timeline_of(run19))

    print("19d-i) the device's own answer is read only in the affirmative")
    # EnrolledViaDEP: a yes counts from any source, a no only from absence of all answers.
    dev20 = await new_device("ACCT-DEP-BUT-OTA", "host-acct-depota", dep=True)
    dev20.attributes = {"SecurityInfo": {"ManagementStatus": {"EnrolledViaDEP": False}}}
    await dev20.save()
    run20 = await atc.start_run_from_start(dev20, "s-acct")
    await run20.refresh_from_db()
    check("a False does not veto the ABM assignment beside it",
          len(ACCOUNT_CMDS) == sent_before + 2
          and "Automated Device Enrollment" not in timeline_of(run20))

    dev21 = await new_device("ACCT-OTA-BUT-DEP", "host-acct-otadep")
    dev21.attributes = {"SecurityInfo": {"ManagementStatus": {"EnrolledViaDEP": True}}}
    await dev21.save()
    await atc.start_run_from_start(dev21, "s-acct")
    check("and a True is enough on its own, with nothing on the server side",
          len(ACCOUNT_CMDS) == sent_before + 3)

    dev21b = await new_device("ACCT-OTA-SAYS-NO", "host-acct-otano")
    dev21b.attributes = {"SecurityInfo": {"ManagementStatus": {"EnrolledViaDEP": False}}}
    await dev21b.save()
    run21b = await atc.start_run_from_start(dev21b, "s-acct")
    await run21b.refresh_from_db()
    check("a False with nothing contradicting it is still a skip",
          len(ACCOUNT_CMDS) == sent_before + 3
          and "Automated Device Enrollment" in timeline_of(run21b))

    # ==19d-ii) the same rule, read from the release paths==
    # release_device and release_device_manual share _is_ade_device: stale answers hurt on release.
    print("19d-ii) a stale EnrolledViaDEP False does not block a release")
    dev24 = await new_device("REL-STALE", "host-rel-stale", dep=True)
    dev24.attributes = {"SecurityInfo": {"ManagementStatus": {"EnrolledViaDEP": False}}}
    await dev24.save()
    check("the console's Release button still works for an ABM-assigned Mac",
          await atc.release_device_manual(dev24, "admin@x") == (True, None))

    dev25 = await new_device("REL-SAYS-YES", "host-rel-yes")
    dev25.attributes = {"SecurityInfo": {"ManagementStatus": {"EnrolledViaDEP": True}}}
    await dev25.save()
    check("and for a Mac whose only evidence is its own answer",
          await atc.release_device_manual(dev25, "admin@x") == (True, None))

    dev26 = await new_device("REL-OTA", "host-rel-ota")
    dev26.attributes = {"SecurityInfo": {"ManagementStatus": {"EnrolledViaDEP": False}}}
    await dev26.save()
    ota_ok, ota_why = await atc.release_device_manual(dev26, "admin@x")
    check("near miss: a hand-enrolled Mac is still refused", ota_ok is False)
    # The refusal the console shows. It names the missing Automated Device Enrollment, not enrollment itself, which
    # would send a reader after a Mac that is enrolled and working.
    check("...and the refusal names Automated Device Enrollment, not enrollment",
          bool(ota_why) and "Automated Device Enrollment" in ota_why
          and "not enrolled" not in ota_why)

    dev26b = await new_device("REL-GONE", "host-rel-gone", dep=True)
    dev26b.enrollment_state = "unenrolled"
    await dev26b.save()
    gone_ok, gone_why = await atc.release_device_manual(dev26b, "admin@x")
    check("a device with no MDM channel is refused, and for that reason",
          gone_ok is False and bool(gone_why) and "unenrolled" in gone_why
          and "Automated Device Enrollment" not in gone_why)

    run24 = await atc.start_run_from_start(dev24, "s-verified")
    await run24.refresh_from_db()
    check("the flow's release node reads it the same way",
          not any("never held in Setup Assistant" in (t.get("message") or "")
                  for t in (run24.context or {}).get("timeline", [])))

    # ==19e) a declarative sync that sends nothing==
    # Both failure sentinels must reach ledger or no-op looks like nothing was computed.
    print("19e) a refused declarative sync is a gap, a no-op sync is not")
    import controller.services.ddm_manager as ddm

    tenant.ddm_enabled = True
    await tenant.save()
    real_sync, real_compute = ddm.sync_device, ddm.compute_device_declarations
    ddm.compute_device_declarations = _returns([{"Identifier": "mm.cfg.wifi"}])

    try:
        ddm.sync_device = _returns(
            ddm.EnqueueFailed("NanoMDM is unreachable (ConnectError)"))
        dev22 = await new_device("DDM-REFUSED", "host-ddm-refused")
        run22 = await atc.start_run_from_start(dev22, "s-ddm")
        await run22.refresh_from_db()
        check("the refusal reaches the timeline with Apple's side named",
              "could not be queued" in timeline_of(run22)
              and "unreachable" in timeline_of(run22))
        gaps22 = (run22.context or {}).get("gaps") or []
        check("and the ledger, graded broken",
              any(g.get("kind") == "not_queued" and g.get("grade") == "broken"
                  and g.get("signal") == "declaration_applied" for g in gaps22))
        check("the reason travels with the ledger item, not just the timeline",
              any("unreachable" in (i.get("why") or "")
                  for g in gaps22 for i in (g.get("items") or [])))
        check("nothing is expected, so the barrier below holds nothing and the run "
              "does not park",
              run22.status != "waiting"
              and not ((run22.context or {}).get("expected") or {}).get("declaration_applied"))
        check("the empty barrier inherits the broken grade rather than reading as policy",
              any(g.get("kind") == "barrier_empty" and g.get("grade") == "broken"
                  for g in gaps22))

        print("19e-i) a device waiting out an earlier refusal is a gap too")
        # A refused enqueue never stamps ddm_last_published_token, so backoff is distinguishable from "in sync".
        ddm.sync_device = _returns(ddm.SyncHeldOff(
            "waiting until 2026-08-17T04:00:00Z after 2 refused attempt(s): "
            "NanoMDM is unreachable (ConnectError)"))
        dev23 = await new_device("DDM-HELD", "host-ddm-held")
        run23 = await atc.start_run_from_start(dev23, "s-ddm")
        await run23.refresh_from_db()
        check("the timeline says the backoff is why, not that it is in sync",
              "backing off" in timeline_of(run23)
              and "already in sync" not in timeline_of(run23))
        check("the wait itself is quoted, so an admin knows how long",
              "2026-08-17T04:00:00Z" in timeline_of(run23))
        gaps23 = (run23.context or {}).get("gaps") or []
        check("the ledger carries it graded broken",
              any(g.get("kind") == "not_queued" and g.get("grade") == "broken"
                  and g.get("signal") == "declaration_applied" for g in gaps23))
        check("nothing is expected, so the run does not park on declarations "
              "that are not coming",
              run23.status != "waiting"
              and not ((run23.context or {}).get("expected") or {}).get("declaration_applied"))
        check("SyncHeldOff is told apart from EnqueueFailed, not folded into it",
              not isinstance(ddm.SyncHeldOff("x"), ddm.EnqueueFailed))

        print("19e-ii) near miss: a device already in sync is a no-op, not a gap")
        ddm.sync_device = _returns(False)
        dev27 = await new_device("DDM-INSYNC", "host-ddm-insync")
        run27 = await atc.start_run_from_start(dev27, "s-ddm")
        await run27.refresh_from_db()
        check("the timeline says already in sync", "already in sync" in timeline_of(run27))
        check("no broken gap for a device with nothing to send",
              not any(g.get("grade") == "broken"
                      for g in (run27.context or {}).get("gaps") or []))
        check("and the declarations are still expected, so the barrier holds",
              run27.status == "waiting" and run27.waiting_signal == "declaration_applied")

        print("19e-iii) the flow does not bypass the backoff")
        # ignore_backoff is for a caller acting on an explicit request. An enroll flow that passed it would put one
        # attempt per enrolling device against a NanoMDM that has already said no.
        seen_kwargs = {}

        async def _record_sync(*args, **kwargs):
            seen_kwargs.update(kwargs)
            return False

        ddm.sync_device = _record_sync
        dev28 = await new_device("DDM-BACKOFF", "host-ddm-backoff")
        await atc.start_run_from_start(dev28, "s-ddm")
        check("sync_device is called without ignore_backoff",
              seen_kwargs.get("ignore_backoff") is None)
    finally:
        ddm.sync_device, ddm.compute_device_declarations = real_sync, real_compute
        tenant.ddm_enabled = False
        await tenant.save()

    #  20) a finished run stops carrying the whole flow document
    print("20) terminal runs drop the pinned flow snapshot")
    done_run = await FlowRun.get(id=run.id)
    check("a completed run has no snapshot", "flow" not in (done_run.context or {}))
    check("but still records which definition ran", bool(done_run.flow_hash))
    check("the timeline it is rendered from survives",
          len((done_run.context or {}).get("timeline") or []) > 0)
    failed_run = await FlowRun.get(id=grun2.id)
    check("a failed run has no snapshot", "flow" not in (failed_run.context or {}))
    cancelled_run = await FlowRun.get(id=ra.id)
    check("a cancelled run has no snapshot", "flow" not in (cancelled_run.context or {}))
    live_run = await FlowRun.get(id=r1[0].id)
    check("a run that is still going keeps its snapshot",
          live_run.status == "waiting" and "flow" in (live_run.context or {}))

    #  21) finished runs ask the coalescer for a reconcile, not one apiece
    print("21) a run that dirtied device state goes through request_reconcile")
    check("the coalescer was asked to reconcile the tenant", "default" in RECONCILE_CALLS)

    async def failure_alerts(device):
        return await Alert.filter(
            device_id=device.id, rule_id="atc:flow-failed:main"
        ).exclude(status="resolved").all()

    def timeline_has(run, fragment):
        return any(fragment in (t.get("message") or "")
                   for t in (run.context or {}).get("timeline", []))

    #  22) no run ends silently
    print("22) a failed run puts one alert on the board")
    fdev = await new_device("FAIL-1", "host-fail1")
    frun = await atc.start_run_from_start(fdev, "s-held")
    await frun.refresh_from_db()
    check("parked at held-wait", frun.status == "waiting" and frun.current_node == "held-wait")
    check("no in-setup alert for a device that never came through ADE",
          await active_in_setup(fdev) is None)
    await FlowRun.filter(id=frun.id).update(
        wait_deadline=datetime.now(timezone.utc) - timedelta(minutes=1))
    await atc.sweep_timeouts(tenant)
    await frun.refresh_from_db()
    check("the run failed (there is no on_timeout edge to take)", frun.status == "failed")
    fa = await failure_alerts(fdev)
    check("exactly one alert was raised", len(fa) == 1)
    fdetail = (fa[0].detail or {}) if fa else {}
    check("it is open and yellow",
          bool(fa) and fa[0].status == "open" and fa[0].severity == "yellow")
    check("it is attached to the device that failed",
          bool(fa) and str(fa[0].device_id) == str(fdev.id))
    check("it names the flow", fdetail.get("flow_id") == "main")
    check("it names the node the run died on", fdetail.get("node_id") == "held-wait")
    check("it carries the error", "timed out" in (fdetail.get("error") or ""))
    check("it links back to the run", fdetail.get("flow_run_id") == str(frun.id))
    check("the summary names the device, the flow and the node",
          bool(fa) and "FAIL-1" in fa[0].summary and "main" in fa[0].summary
          and "held-wait" in fa[0].summary)

    #  23) the same failure over and over is still one row
    print("23) repeated failures of one flow on one device do not multiply rows")
    frun2 = await atc.start_run_from_start(fdev, "s-held")
    await FlowRun.filter(id=frun2.id).update(
        wait_deadline=datetime.now(timezone.utc) - timedelta(minutes=1))
    await atc.sweep_timeouts(tenant)
    await frun2.refresh_from_db()
    check("the second run failed too", frun2.status == "failed")
    fa2 = await failure_alerts(fdev)
    check("still exactly one active row", len(fa2) == 1)
    d2 = (fa2[0].detail or {}) if fa2 else {}
    check("the row counts the failures", d2.get("failure_count") == 2)
    check("and points at the most recent run", d2.get("flow_run_id") == str(frun2.id))
    check("the summary says it keeps happening",
          bool(fa2) and "2 failures" in fa2[0].summary)
    check("the first sighting is preserved",
          d2.get("first_failed_at") == fdetail.get("first_failed_at"))
    check("no resolve-and-reopen churn behind it",
          await Alert.filter(device_id=fdev.id, rule_id="atc:flow-failed:main").count() == 1)

    #  24) a run that gets to the end clears the row, and raises nothing itself
    print("24) a completed run resolves the failure alert and raises none of its own")
    okrun = await atc.start_run_from_start(fdev, "s-standalone")
    await okrun.refresh_from_db()
    check("a later run of the same flow completed", okrun.status == "completed")
    check("the failure alert resolved itself", await failure_alerts(fdev) == [])
    clean = await new_device("CLEAN-1", "host-clean")
    crun = await atc.start_run_from_start(clean, "s-standalone")
    await crun.refresh_from_db()
    check("a run that succeeds first time completes", crun.status == "completed")
    check("and raises no alert at all", await Alert.filter(device_id=clean.id).count() == 0)

    #  25) failing while holding an ADE device must not delete the evidence
    print("25) a failure while holding a device in Setup Assistant keeps that alert open")
    hdev = await new_device("HELD-1", "host-held", dep=True)
    hrun = await atc.start_run_from_start(hdev, "s-held")
    await hrun.refresh_from_db()
    ha = await active_in_setup(hdev)
    check("the green in-setup alert opened at the park",
          ha is not None and ha.severity == "green")
    await FlowRun.filter(id=hrun.id).update(
        wait_deadline=datetime.now(timezone.utc) - timedelta(minutes=1))
    await atc.sweep_timeouts(tenant)
    await hrun.refresh_from_db()
    check("the run failed while the device was still held", hrun.status == "failed")
    ha2 = await active_in_setup(hdev)
    check("the in-setup alert is STILL OPEN", ha2 is not None)
    check("escalated off informational green", bool(ha2) and ha2.severity == "yellow")
    check("its summary says the flow that would release the device failed",
          bool(ha2) and "Setup Assistant" in ha2.summary and "failed" in ha2.summary)
    check("it keeps the one-click release action",
          bool(ha2) and (ha2.detail or {}).get("actions"))
    hfa = await failure_alerts(hdev)
    check("the failure alert is red, because a device is stranded behind it",
          len(hfa) == 1 and hfa[0].severity == "red")
    check("and it says so in words",
          bool(hfa) and "Setup Assistant" in hfa[0].summary
          and (hfa[0].detail or {}).get("held_in_setup") is True)
    released, release_why = await atc.release_device_manual(hdev, "admin@x")
    check("an admin can still release the device from that alert",
          released and release_why is None)
    check("releasing resolves it", await active_in_setup(hdev) is None)

    #  26) completing without releasing is not the same as releasing
    print("26) a run that completes without releasing leaves the in-setup alert open")
    kdev = await new_device("KIOSK-1", "host-kiosk", dep=True)
    krun = await atc.start_run_from_start(kdev, "s-gate")
    await FlowRun.filter(id=krun.id).update(
        wait_deadline=datetime.now(timezone.utc) - timedelta(minutes=1))
    await atc.sweep_timeouts(tenant)
    await krun.refresh_from_db()
    check("parked on the gate with an in-setup alert open",
          krun.current_node == "g-gate" and await active_in_setup(kdev) is not None)
    await atc.resume_manual_gate(krun.id, "on_cancel", "admin@x")
    await krun.refresh_from_db()
    check("the run completed down the cancel branch", krun.status == "completed")
    check("release_device never ran",
          "g-release" not in (krun.context or {}).get("visited", []))
    check("the in-setup alert survives a completion that released nothing",
          await active_in_setup(kdev) is not None)
    check("the run timeline says why", timeline_has(krun, "without releasing"))
    check("and a completion still raises no failure alert",
          await failure_alerts(kdev) == [])

    #  27) an unexpected engine path reads differently from the normal one
    print("27) diagnostics: a barrier that held nothing back says so")
    check("an empty barrier says nothing was queued",
          timeline_has(run6, "nothing was queued for app_installed"))
    check("a barrier whose refs all landed early reads differently",
          timeline_has(run11, "already arrived"))
    ndev = await new_device("NOOP-1", "host-noop")
    nrun = await atc.start_run_from_start(ndev, "s-noop")
    await nrun.refresh_from_db()
    check("an install entitled to nothing still completes the run",
          nrun.status == "completed")
    check("the install node says it queued nothing",
          timeline_has(nrun, "none of ['held-back'] were queued"))
    check("and the barrier below it says it waited on nothing",
          timeline_has(nrun, "nothing was queued for app_installed"))

    # Hand-edited wait_for with no timeout: engine assigns 60 minute default on park.
    (tdir / "flows.yaml").write_text(yaml.safe_dump({"flow": {
        "id": "main", "name": "Hand edited", "enabled": True, "nodes": [
            {"id": "s-untimed", "type": "start",
             "params": {"kind": "enroll_profile", "match": {}}, "next": "u-wait"},
            {"id": "u-wait", "type": "wait_for", "params": {"signal": "device_info"},
             "next": "u-end"},
            {"id": "u-end", "type": "end"}]}}))
    udev = await new_device("UNTIMED-1", "host-untimed")
    urun = await atc.start_run_from_start(udev, "s-untimed")
    (tdir / "flows.yaml").write_text(yaml.safe_dump({"flow": BASE_FLOW}))
    await urun.refresh_from_db()
    check("a wait with no timeout in the document still gets a deadline",
          urun.status == "waiting" and urun.wait_deadline is not None)
    check("and the run records that the 60 minutes was the engine's default",
          timeline_has(urun, "60 minute default"))

    #  28) THE VACUOUS BARRIER: a flow that installs nothing must not be able to
    #      release a device from Setup Assistant and report that it worked.
    print("28) an install that resolves nothing cannot release a device quietly")

    def gaps(r):
        return (r.context or {}).get("gaps") or []

    # Hand-edited install_profiles with unknown id: barrier evaporates, release runs without verification.
    (tdir / "flows.yaml").write_text(yaml.safe_dump({"flow": {
        "id": "main", "name": "Hand edited", "enabled": True, "nodes": [
            {"id": "s-ghost", "type": "start",
             "params": {"kind": "enroll_profile", "match": {}}, "next": "gh-inst"},
            {"id": "gh-inst", "type": "install_profiles",
             "params": {"profile_ids": ["wifi-corp"]}, "next": "gh-wait"},
            {"id": "gh-wait", "type": "wait_for",
             "params": {"signal": "profile_installed", "timeout_minutes": 30},
             "next": "gh-release"},
            {"id": "gh-release", "type": "release_device", "next": "gh-end"},
            {"id": "gh-end", "type": "end"}]}}))
    gdev = await new_device("GHOST-1", "host-ghost", dep=True)
    grun = await atc.start_run_from_start(gdev, "s-ghost")
    (tdir / "flows.yaml").write_text(yaml.safe_dump({"flow": BASE_FLOW}))
    await grun.refresh_from_db()
    check("the run does NOT report success", grun.status != "completed")
    check("it is recorded as failed", grun.status == "failed")
    check("and its error names the release, not some internal detail",
          "Setup Assistant" in (grun.error or ""))
    check("the ledger kept the unresolvable profile id",
          any(i.get("id") == "wifi-corp"
              for g in gaps(grun) for i in (g.get("items") or [])))
    check("and the barrier that held nothing back",
          any(g.get("kind") == "barrier_empty" for g in gaps(grun)))
    check("the timeline says the device left unverified",
          timeline_has(grun, "nothing had confirmed its configuration"))
    galert = await failure_alerts(gdev)
    check("exactly one board item for it", len(galert) == 1)
    check("red, because the flow named protection the engine could not deliver",
          bool(galert) and galert[0].severity == "red")
    check("its summary names the device and what is missing",
          bool(galert) and "GHOST-1" in galert[0].summary
          and "wifi-corp" in galert[0].summary)
    check("and it leads with the release, not with a node that threw",
          bool(galert) and "left Setup Assistant before flow" in galert[0].summary)
    check("the board item carries the ledger for the run view",
          bool(galert) and (galert[0].detail or {}).get("released_unverified") is True
          and (galert[0].detail or {}).get("gaps"))

    #  29) the realistic trigger: a gradual rollout empties the barrier
    print("29) an app held back by a rollout wave trips the guard")
    rdev = await new_device("ROLL-1", "host-roll", dep=True)
    rrun = await atc.start_run_from_start(rdev, "s-rollout")
    await rrun.refresh_from_db()
    check("the run does not report success", rrun.status == "failed")
    check("the ledger says the rollout is why",
          any("gradual rollout" in (i.get("why") or "")
              for g in gaps(rrun) for i in (g.get("items") or [])))
    ralert = await failure_alerts(rdev)
    check("one board item", len(ralert) == 1)
    check("yellow, because nothing is missing that this device was owed",
          bool(ralert) and ralert[0].severity == "yellow")
    check("and it names the app by id",
          bool(ralert) and "waved" in ralert[0].summary)

    # A wait step with nothing above it to feed it is the same defect with no install node involved, and the ledger has
    # to catch it on its own.
    pdev = await new_device("ORPHAN-1", "host-orphan", dep=True)
    prun = await atc.start_run_from_start(pdev, "s-orphan")
    await prun.refresh_from_db()
    check("a barrier nothing feeds does not report success",
          prun.status == "failed")
    check("the only thing in the ledger is the empty barrier",
          [g.get("kind") for g in gaps(prun)] == ["barrier_empty"])
    palert = await failure_alerts(pdev)
    check("red, because nothing in the run explains the empty barrier",
          len(palert) == 1 and palert[0].severity == "red")
    check("and the board item names the wait step",
          bool(palert) and "or-wait" in palert[0].summary)

    #  30) the legitimate cases must keep working
    print("30) the flows that are supposed to do this keep working")
    odev = await new_device("OPTOUT-1", "host-optout", dep=True)
    orun = await atc.start_run_from_start(odev, "s-optout")
    await orun.refresh_from_db()
    check("gate: false on the install step completes the run", orun.status == "completed")
    check("with an empty ledger", gaps(orun) == [])
    check("and no alert", await failure_alerts(odev) == [])
    check("the timeline says the step was excused rather than silent",
          timeline_has(orun, "set not to hold the flow up"))

    bdev = await new_device("BAREWAIT-1", "host-bare", dep=True)
    brun = await atc.start_run_from_start(bdev, "s-barewait")
    await brun.refresh_from_db()
    check("gate: false on the wait step itself also completes",
          brun.status == "completed")
    check("with no alert", await failure_alerts(bdev) == [])

    vdev = await new_device("VERIFIED-1", "host-verified", dep=True)
    vrun = await atc.start_run_from_start(vdev, "s-verified")
    await vrun.refresh_from_db()
    check("a real barrier still parks", vrun.status == "waiting")
    await mark_installed(vdev, "P1")
    await atc.advance_on_signal(str(vdev.id), "profile_installed", ref="P1")
    await vrun.refresh_from_db()
    check("a barrier that really was satisfied completes the run",
          vrun.status == "completed")
    check("with an empty ledger", gaps(vrun) == [])
    check("no alert", await failure_alerts(vdev) == [])
    check("and the device really was released",
          "v-release" in (vrun.context or {}).get("visited", []))

    # An out-of-scope device that installs nothing and never releases is the flow the guard must not touch: nothing left
    # Setup Assistant.
    sdev = await new_device("SCOPED-OUT-1", "host-scoped")
    srun = await atc.start_run_from_start(sdev, "s-noop")
    await srun.refresh_from_db()
    check("a flow that installs nothing and releases nothing still completes",
          srun.status == "completed")
    check("and raises no alert", await failure_alerts(sdev) == [])

    #  31) a ref that was queued and never turned up
    print("31) a profile that never reported is named on the way out")
    ldev = await new_device("LATE-1", "host-late", dep=True)
    lrun = await atc.start_run_from_start(ldev, "s-late")
    await lrun.refresh_from_db()
    check("parked on the queued profile", lrun.status == "waiting")
    await FlowRun.filter(id=lrun.id).update(
        wait_deadline=datetime.now(timezone.utc) - timedelta(minutes=1))
    await atc.sweep_timeouts(tenant)
    await lrun.refresh_from_db()
    check("the timeout edge released the device and the run failed",
          lrun.status == "failed"
          and "late-release" in (lrun.context or {}).get("visited", []))
    check("the ledger kept the ref that never arrived",
          any(g.get("kind") == "never_arrived" and
              any(i.get("id") == "P3" for i in (g.get("items") or []))
              for g in gaps(lrun)))
    lalert = await failure_alerts(ldev)
    check("red on the board, since a profile the flow sent is not on the device",
          len(lalert) == 1 and lalert[0].severity == "red")

    #  32) a coalesced row must not let a stale guard verdict outlive its run
    print("32) released-unverified and its ledger do not survive past the run "
          "that set them")

    def ghost_doc(start_id, inst_id, wait_id, release_id, end_id):
        # The ghost flow from (28) again: a profile id the wait step can never resolve, so release_device trips the
        # guard on whichever run takes this document. Node ids are unique per call so two runs can be told apart.
        return {"flow": {"id": "main", "name": "Hand edited", "enabled": True, "nodes": [
            {"id": start_id, "type": "start",
             "params": {"kind": "enroll_profile", "match": {}}, "next": inst_id},
            {"id": inst_id, "type": "install_profiles",
             "params": {"profile_ids": ["wifi-corp"]}, "next": wait_id},
            {"id": wait_id, "type": "wait_for",
             "params": {"signal": "profile_installed", "timeout_minutes": 30},
             "next": release_id},
            {"id": release_id, "type": "release_device", "next": end_id},
            {"id": end_id, "type": "end"}]}}

    # Order A: guard failure, then an ordinary failure of the same flow on the same device. The row must drop the
    #    guard's verdict, not keep it.
    adev = await new_device("COALESCE-A", "host-coalesce-a", dep=True)
    (tdir / "flows.yaml").write_text(yaml.safe_dump(
        ghost_doc("s-ghost-a", "gh-inst-a", "gh-wait-a", "gh-release-a", "gh-end-a")))
    arun1 = await atc.start_run_from_start(adev, "s-ghost-a")
    (tdir / "flows.yaml").write_text(yaml.safe_dump({"flow": BASE_FLOW}))
    await arun1.refresh_from_db()
    check("run 1 trips the release guard", arun1.status == "failed")
    aa1 = await failure_alerts(adev)
    ad1 = (aa1[0].detail or {}) if aa1 else {}
    check("the row opens claiming released-unverified",
          len(aa1) == 1 and ad1.get("released_unverified") is True)
    check("and carries run 1's ledger", bool(ad1.get("gaps")))
    a_first_seen = ad1.get("first_failed_at")

    arun2 = await atc.start_run_from_start(adev, "s-held")
    await FlowRun.filter(id=arun2.id).update(
        wait_deadline=datetime.now(timezone.utc) - timedelta(minutes=1))
    await atc.sweep_timeouts(tenant)
    await arun2.refresh_from_db()
    check("run 2 fails for an ordinary reason, not the guard",
          arun2.status == "failed" and not (arun2.context or {}).get("unverified"))
    aa2 = await failure_alerts(adev)
    check("still one coalesced row", len(aa2) == 1)
    ad2 = (aa2[0].detail or {}) if aa2 else {}
    check("it now points at run 2", ad2.get("flow_run_id") == str(arun2.id))
    check("with run 2's own error", "timed out" in (ad2.get("error") or ""))
    check("released-unverified is cleared: run 2 never touched the guard",
          not ad2.get("released_unverified"))
    check("run 1's ledger does not linger behind run 2's failure",
          not ad2.get("gaps"))
    check("the failure count still accrues across the coalesce",
          ad2.get("failure_count") == 2)
    check("and the row remembers when the streak actually started",
          ad2.get("first_failed_at") == a_first_seen)

    # Order B: the reverse. An ordinary failure, then a guard failure of the same flow on the same device. The row
    #    must gain the flag and ledger.
    bdev2 = await new_device("COALESCE-B", "host-coalesce-b", dep=True)
    brun1 = await atc.start_run_from_start(bdev2, "s-held")
    await FlowRun.filter(id=brun1.id).update(
        wait_deadline=datetime.now(timezone.utc) - timedelta(minutes=1))
    await atc.sweep_timeouts(tenant)
    await brun1.refresh_from_db()
    check("run 1 fails for an ordinary reason", brun1.status == "failed")
    ba1 = await failure_alerts(bdev2)
    bd1 = (ba1[0].detail or {}) if ba1 else {}
    check("the row opens with no guard verdict to report",
          len(ba1) == 1 and not bd1.get("released_unverified") and not bd1.get("gaps"))
    b_first_seen = bd1.get("first_failed_at")

    (tdir / "flows.yaml").write_text(yaml.safe_dump(
        ghost_doc("s-ghost-b", "gh-inst-b", "gh-wait-b", "gh-release-b", "gh-end-b")))
    brun2 = await atc.start_run_from_start(bdev2, "s-ghost-b")
    (tdir / "flows.yaml").write_text(yaml.safe_dump({"flow": BASE_FLOW}))
    await brun2.refresh_from_db()
    check("run 2 trips the release guard", brun2.status == "failed")
    ba2 = await failure_alerts(bdev2)
    check("still one coalesced row", len(ba2) == 1)
    bd2 = (ba2[0].detail or {}) if ba2 else {}
    check("it now points at run 2", bd2.get("flow_run_id") == str(brun2.id))
    check("released-unverified is now correctly set", bd2.get("released_unverified") is True)
    check("and carries run 2's ledger, not an echo of run 1's silence",
          bool(bd2.get("gaps")))
    check("the failure count still accrues across the coalesce",
          bd2.get("failure_count") == 2)
    check("and the row remembers when the streak actually started",
          bd2.get("first_failed_at") == b_first_seen)

    #  33) the manual-gate escalation ladder
    print("33) an unanswered manual gate escalates on the ladder, then fails")

    def gate_ladder(r):
        return (r.context or {}).get("gate_ladder") or {}

    async def gate_alert_of(r):
        return await Alert.filter(rule_id=f"atc:gate:{r.id}").exclude(
            status="resolved").first()

    async def expire(r):
        await FlowRun.filter(id=r.id).update(
            wait_deadline=datetime.now(timezone.utc) - timedelta(minutes=1))

    edev = await new_device("ESC-1", "host-esc1")
    erun = await atc.start_run_from_start(edev, "s-gate")
    await expire(erun)
    await atc.sweep_timeouts(tenant)
    await erun.refresh_from_db()
    check("parked on the gate with the first-rung deadline",
          erun.current_node == "g-gate" and deadline_in(erun, 240))
    check("the park timeline says when it escalates",
          timeline_has(erun, "escalates in 4 hours"))
    ea0 = await gate_alert_of(erun)
    check("the decision alert opened at the authored severity",
          ea0 is not None and ea0.severity == "yellow")

    # rung one expires: escalate and re-park, do not fail
    await expire(erun)
    swept_manual = await atc.sweep_timeouts(tenant)
    await erun.refresh_from_db()
    check("the sweep now processes manual gates", swept_manual >= 1)
    check("the run is still waiting on the gate",
          erun.status == "waiting" and erun.waiting_signal == "manual"
          and erun.current_node == "g-gate")
    check("re-parked on the second rung (24h)", deadline_in(erun, 1440))
    check("the ladder step advanced", gate_ladder(erun).get("step") == 1)
    ea1 = await gate_alert_of(erun)
    check("one severity step louder", ea1 is not None and ea1.severity == "red")
    check("still the same alert row, decision buttons intact",
          bool(ea1) and bool(ea0) and str(ea1.id) == str(ea0.id)
          and (ea1.detail or {}).get("options"))
    check("the summary names the flow, the gate and the wait",
          bool(ea1) and "main" in ea1.summary and "g-gate" in ea1.summary
          and "4 hours" in ea1.summary)
    check("and says when it escalates again", bool(ea1) and "24 hours" in ea1.summary)
    check("the timeline recorded the escalation",
          timeline_has(erun, "no decision after 4 hours"))

    # rung two expires: one more step; the next expiry is terminal
    await expire(erun)
    await atc.sweep_timeouts(tenant)
    await erun.refresh_from_db()
    check("still waiting after the second escalation", erun.status == "waiting")
    check("re-parked on the last rung (7 days)", deadline_in(erun, 10080))
    ea2 = await gate_alert_of(erun)
    check("another severity step", ea2 is not None and ea2.severity == "black")
    check("the summary now says the run will fail",
          bool(ea2) and "fails in 7 days" in ea2.summary)

    # the last rung expires: the run fails through the normal path
    await expire(erun)
    await atc.sweep_timeouts(tenant)
    await erun.refresh_from_db()
    check("the run failed after the last rung", erun.status == "failed")
    check("the error names the gate and the total wait",
          "g-gate" in (erun.error or "") and "8 days" in (erun.error or ""))
    check("the decision alert resolved on failure", await gate_alert_of(erun) is None)
    efa = await failure_alerts(edev)
    check("the failure went on the board like any other failure", len(efa) == 1)
    check("a run the ladder failed drops its snapshot",
          "flow" not in (erun.context or {}))

    # a decision mid-ladder still works
    e2dev = await new_device("ESC-2", "host-esc2")
    e2run = await atc.start_run_from_start(e2dev, "s-gate")
    await expire(e2run)
    await atc.sweep_timeouts(tenant)  # park on the gate
    await expire(e2run)
    await atc.sweep_timeouts(tenant)  # first escalation
    await e2run.refresh_from_db()
    check("escalated once and still answerable", e2run.status == "waiting")
    resumed2 = await atc.resume_manual_gate(e2run.id, "on_release", "admin@x")
    await e2run.refresh_from_db()
    check("an escalated gate still resumes on a decision",
          e2run.status == "completed" and resumed2 is not None)

    print("33b) an authored timeout under the first rung fails at that deadline")
    sgdev = await new_device("ESC-SHORT", "host-esc-short")
    sgrun = await atc.start_run_from_start(sgdev, "s-gate-short")
    await sgrun.refresh_from_db()
    check("parked at the authored 30 minute deadline",
          sgrun.status == "waiting" and sgrun.current_node == "gs-gate"
          and deadline_in(sgrun, 30))
    check("the schedule is just the authored deadline",
          gate_ladder(sgrun).get("schedule") == [30])
    check("the park timeline says the run fails, not escalates",
          timeline_has(sgrun, "the run fails in 30 minutes"))
    sa0 = await gate_alert_of(sgrun)
    await expire(sgrun)
    await atc.sweep_timeouts(tenant)
    await sgrun.refresh_from_db()
    check("expiry fails the run with no escalation", sgrun.status == "failed")
    check("the error names the gate and the authored total",
          "gs-gate" in (sgrun.error or "") and "30 minutes" in (sgrun.error or ""))
    check("the decision alert resolved rather than escalated",
          await gate_alert_of(sgrun) is None)
    sa_row = await Alert.filter(id=sa0.id).first() if sa0 else None
    check("its severity never climbed", bool(sa_row) and sa_row.severity == "yellow")

    print("33c) an authored timeout past the first rung still runs that escalation")
    lgdev = await new_device("ESC-LONG", "host-esc-long")
    lgrun = await atc.start_run_from_start(lgdev, "s-gate-long")
    await lgrun.refresh_from_db()
    check("the schedule keeps the 4 hour escalation and fails at 5 hours",
          gate_ladder(lgrun).get("schedule") == [240, 300])
    check("parked on the first rung, not the authored total",
          deadline_in(lgrun, 240))
    await expire(lgrun)
    await atc.sweep_timeouts(tenant)
    await lgrun.refresh_from_db()
    check("the first-rung escalation ran inside the authored window",
          lgrun.status == "waiting" and gate_ladder(lgrun).get("step") == 1)
    la1 = await gate_alert_of(lgrun)
    check("severity climbed one step", la1 is not None and la1.severity == "red")
    check("the summary says the run fails in the hour that is left",
          bool(la1) and "fails in 1 hour" in la1.summary)
    check("re-parked for the last hour of the window", deadline_in(lgrun, 60))
    await expire(lgrun)
    await atc.sweep_timeouts(tenant)
    await lgrun.refresh_from_db()
    check("the authored total then fails the run", lgrun.status == "failed")
    check("the error carries the authored total", "5 hours" in (lgrun.error or ""))

    #  34) UPGRADE PATH: gates parked by the pre-ladder code have no deadline, which the sweep's <= query can never
    #      match. They must be adopted onto the ladder rather than left waiting forever.
    print("34) a gate parked by the pre-ladder code is adopted onto the ladder")
    legdev = await new_device("LEGACY-1", "host-legacy")
    legrun = await FlowRun.create(
        tenant=tenant, device=legdev, flow_id="main", flow_hash="legacyhash",
        status="waiting", event_kind="enroll_profile", start_node="s-gate",
        current_node="g-gate", waiting_signal="manual", waiting_ref=None,
        wait_deadline=None,
        context={"flow": BASE_FLOW, "visited": ["s-gate", "g-wait", "g-gate"],
                 "timeline": []},
    )
    swept_leg = await atc.sweep_timeouts(tenant)
    await legrun.refresh_from_db()
    check("the sweep picked the legacy row up", swept_leg >= 1)
    check("still waiting on the gate after adoption",
          legrun.status == "waiting" and legrun.waiting_signal == "manual"
          and legrun.current_node == "g-gate")
    check("adopted at rung 0 with the first-rung deadline",
          gate_ladder(legrun).get("step") == 0 and deadline_in(legrun, 240))
    check("the ladder schedule is now pinned",
          gate_ladder(legrun).get("schedule") == [240, 1680, 11760])
    check("the timeline says the gate was adopted",
          timeline_has(legrun, "adopted onto the escalation ladder"))

    await atc.sweep_timeouts(tenant)
    await legrun.refresh_from_db()
    check("a later sweep leaves the adopted gate parked until its rung expires",
          legrun.status == "waiting" and gate_ladder(legrun).get("step") == 0)

    await expire(legrun)
    await atc.sweep_timeouts(tenant)
    await legrun.refresh_from_db()
    check("the adopted gate escalates like any other",
          legrun.status == "waiting" and gate_ladder(legrun).get("step") == 1
          and deadline_in(legrun, 1440))
    leg_alert = await gate_alert_of(legrun)
    check("the escalation raised the decision card the legacy park never had",
          leg_alert is not None and (leg_alert.detail or {}).get("options"))

    await expire(legrun)
    await atc.sweep_timeouts(tenant)  # rung two
    await expire(legrun)
    await atc.sweep_timeouts(tenant)  # last rung: terminal
    await legrun.refresh_from_db()
    check("the adopted gate terminally fails after the last rung",
          legrun.status == "failed" and "g-gate" in (legrun.error or ""))
    check("its decision alert resolved on failure",
          await gate_alert_of(legrun) is None)
    check("and the snapshot is dropped", "flow" not in (legrun.context or {}))

    #  35) the webhook defers ATC fan-out, and the deferred signals still arrive, in order
    print("35) a webhook command response defers its ATC signals; the checkin-"
          "started run still resumes on device_info")
    from controller.services import webhook_handler

    wdev = await new_device("MAC-WEBHOOK", "host-webhook")
    winfo = await Task.create(
        tenant=tenant, type="refresh_info", status="running", device=wdev,
        user="system", description="Query device information",
        details={"command_uuid": "cmd-web-info"})
    await webhook_handler.WebhookHandler()._dispatch_command_response(
        wdev, "cmd-web-info", "Acknowledged",
        {"QueryResponses": {"SerialNumber": "MAC-WEBHOOK", "OSVersion": "14.6"}})
    await winfo.refresh_from_db()
    check("the task row is completed inline, on the request path",
          winfo.status == "completed")
    # The checkin signal starts s-checkin, which parks at c-wait on device_info, and the device_info signal deferred
    # after it resumes that same run. Per-device ordering is what makes the second signal find the parked run.
    await webhook_handler.drain_deferred()
    wrun = await FlowRun.filter(device_id=wdev.id, start_node="s-checkin").first()
    check("the deferred checkin signal started the checkin flow", wrun is not None)
    check("the deferred device_info signal resumed it through to completion",
          wrun is not None and wrun.status == "completed")
    await wdev.refresh_from_db()
    check("the inventory write itself stayed inline", wdev.os_version == "14.6")

    #  36) one rank table, one unknown-value default: both shared, so disagreement shows as misordered board.
    print("36) one shared severity rank table, one unknown-value rule")
    import re

    from controller.services import dispatcher as _dispatcher
    from controller.services import severity as _severity
    from controller.utils.yaml_validator import VALID_SEVERITIES as _VALID_SEV

    check("the board and the gate ladder share one table object, not a copy",
          _dispatcher.SEVERITY_RANK is _severity.RANK)
    check("the rank table covers exactly the validator's allow-list",
          set(_severity.ORDER) == set(_VALID_SEV)
          and set(_severity.RANK) == set(_VALID_SEV))
    # VALID_SEVERITIES is authored descending (black > red > yellow > green), the order the board sorts by. Ranks must
    # fall across it.
    ranks_desc = [_severity.rank(s) for s in _VALID_SEV]
    check("rank is strictly descending across the authored scale",
          all(a > b for a, b in zip(ranks_desc, ranks_desc[1:])))
    # The two engines' entry points, asked the same questions.
    board = [_dispatcher.SEVERITY_RANK.get(s, 0) for s in _VALID_SEV]
    gate = [atc._severity_rank(s) for s in _VALID_SEV]
    check("both engines rank every valid severity identically", board == gate)
    check("both engines rank an unknown severity identically, and below every "
          "valid one",
          _dispatcher.SEVERITY_RANK.get("mauve", 0) == atc._severity_rank("mauve")
          == _severity.UNKNOWN_RANK
          and _severity.UNKNOWN_RANK < min(ranks_desc))
    check("_bump_severity walks the shared ladder",
          [atc._bump_severity(s) for s in ("green", "yellow", "red")]
          == ["yellow", "red", "black"])
    check("_bump_severity pins the top rung", atc._bump_severity("black") == "black")
    check("_bump_severity leaves an unknown value alone, matching the shared default",
          atc._bump_severity("mauve") == "mauve" == _severity.escalate("mauve"))
    check("the board's escalation agrees on an unknown value",
          _severity.ESCALATE.get("mauve", "mauve") == "mauve")
    # A hand-edited gate severity never reaches the board as a string nothing can rank.
    check("a gate coerces an unauthored severity to the default",
          atc._gate_severity({"params": {"severity": "mauve"}}) == "yellow"
          and atc._gate_severity({"params": {"severity": "black"}}) == "black"
          and atc._gate_severity({}) == "yellow")
    # Structural: the allow-list has exactly one definition. atc.py restating it as a bare tuple would make a rename of
    # the scale coerce every new name to "yellow" here while the validator accepted it everywhere else.
    atc_src = Path(atc.__file__).read_text()
    restated = [
        ln for ln in atc_src.splitlines()
        if not ln.strip().startswith("#")
           and len({n for n in _VALID_SEV if f'"{n}"' in ln or f"'{n}'" in ln}) >= 3
    ]
    check("atc.py carries no severity allow-list of its own", restated == [], )
    check("atc.py imports the allow-list from the validator",
          re.search(r"from controller\.utils\.yaml_validator import [^\n]*"
                    r"VALID_SEVERITIES", atc_src) is not None)
    # ALIASES is empty today. Filling it in is all a rename needs, because both lookups already route through it.
    check("the alias map is empty and ready", _severity.ALIASES == {})
    _severity.ALIASES["mauve"] = "red"
    try:
        check("rank reads through the alias map", _severity.rank("mauve") == 3
              and atc._severity_rank("mauve") == 3)
        check("escalate reads through the alias map",
              _severity.escalate("mauve") == "black"
              and atc._bump_severity("mauve") == "black")
    finally:
        _severity.ALIASES.pop("mauve", None)
    check("and the alias map is back to empty", _severity.ALIASES == {})

    #  37) the flow document is read shared, and a run's pinned snapshot is its own copy.
    #      Copy on start, not on read, to avoid rewriting snapshots when the document edits.
    print("37) the flow doc is read shared; a run's snapshot is its own copy")
    from controller.services import tenant_config as _tc

    tid = str(tenant.id)
    # Re-parse from disk: cache is polluted from thirty-odd sections above.
    _tc.invalidate(tid)
    doc_before = copy.deepcopy(_tc._load_readonly(tid, "flows.yaml"))
    shared_doc = _tc._load_readonly(tid, "flows.yaml")
    # Wrapper dict is per read; nodes list is shared to keep the hot path cheap.
    check("_load_flows does not copy the flows it hands out: the nodes are the "
          "cached document's own list",
          atc._load_flows(tid)[0].get("nodes") is atc._load_flows(tid)[0].get("nodes"))
    m5dev = await new_device("MAC-M5", "host-m5", dep=True)
    m5runs = await atc.start_flows_for_event(m5dev, "enroll_dep")
    check("the start node matched and a run started", len(m5runs) == 1)
    check("a full match-and-start pass left the flow document untouched",
          _tc._load_readonly(tid, "flows.yaml") == doc_before)
    check("...and it is still the same cache entry, so that comparison was made "
          "against the object the pass actually read",
          _tc._load_readonly(tid, "flows.yaml") is shared_doc)

    # The snapshot's independence, asserted against the in-memory context rather than the stored row: the row was
    # serialized at create time and would look right even if the two aliased one object.
    live = atc._load_flows(tid)[0]
    live_nodes = live.get("nodes")
    live_id = live.get("id")
    try:
        live_nodes.append({"id": "__injected__", "type": "end"})
        live["id"] = "__mutated__"
        snap = (m5runs[0].context or {}).get("flow") or {}
        check("mutating the loaded document does not reach the run's pinned "
              "snapshot",
              snap.get("id") == live_id
              and all(n.get("id") != "__injected__"
                      for n in (snap.get("nodes") or [])))
        check("the snapshot is a distinct object from the loaded document",
              snap is not live and snap.get("nodes") is not live_nodes)
    finally:
        live_nodes[:] = [n for n in live_nodes if n.get("id") != "__injected__"]
        live["id"] = live_id
        _tc.invalidate(tid)
    check("the document is back to what it was on disk",
          _tc._load_readonly(tid, "flows.yaml") == doc_before)

    #  A command a flow sent is findable in the audit log: machine-attributed, flow-named.
    print("send_command steps are in the audit log")
    cmddev = await new_device("MAC-CMD", "host-cmd", dep=True)
    cmdrun = await atc.start_run_from_start(cmddev, "s-verified")
    before_cmd = {r.id for r in await AuditLog.filter(action="device.command").all()}
    await atc._send_command(cmdrun, cmddev, "certificate_list", {}, gate=False)
    cmd_rows = [r for r in await AuditLog.filter(action="device.command").all()
                if r.id not in before_cmd]
    check("a send_command step writes exactly one audit row", len(cmd_rows) == 1)
    if cmd_rows:
        d = cmd_rows[0].detail or {}
        check("the row is machine-attributed and names the flow",
              cmd_rows[0].actor_email is None and d.get("source") == "atc"
              and d.get("source_ref") == cmdrun.flow_id)
        check("it points at the device, the command and the task it created",
              cmd_rows[0].target_id == str(cmddev.id)
              and d.get("command_type") == "certificate_list"
              and d.get("outcome") == "sent" and d.get("task_id"))

    # A step naming a command this deployment does not offer sends nothing and creates no task, so the audit row is the
    # only trace it leaves.
    before_cmd = {r.id for r in await AuditLog.filter(action="device.command").all()}
    await atc._send_command(cmdrun, cmddev, "not_a_real_command", {}, gate=False)
    refused_rows = [r for r in await AuditLog.filter(action="device.command").all()
                    if r.id not in before_cmd]
    check("a refused send_command step is audited too, with no task",
          len(refused_rows) == 1
          and (refused_rows[0].detail or {}).get("outcome") == "refused"
          and (refused_rows[0].detail or {}).get("task_id") is None)

    #  The board's Release button, end to end
    # Helper answers (ok, reason); must read both to avoid false success.
    print("the Release action reads both halves of the helper's answer")
    from controller.api.main import AlertAction, alert_action
    from controller.auth.dependencies import Principal
    from controller.models.tenant import User as _User

    board_user = await _User.create(tenant=tenant, email="board@t", role="admin")
    board = Principal(tenant=tenant, user=board_user, email="board@t", role="admin")

    async def in_setup_alert(device):
        return await Alert.create(
            tenant=tenant, device=device, rule_id="atc:in-setup",
            severity="green", status="open",
            summary=f"{device.serial_number} held in Setup Assistant",
            detail={"kind": "atc_in_setup",
                    "actions": [{"key": "release", "label": "Release from setup"}]},
        )

    ade_board_dev = await new_device("BOARD-ADE", "host-board-ade", dep=True)
    ade_alert = await in_setup_alert(ade_board_dev)
    board_answer = await alert_action(str(ade_alert.id), AlertAction(action_key="release"),
                                      board)
    check("releasing an ADE device from the board reports it queued",
          "queued" in (board_answer.get("message") or "").lower())
    check("...and the alert it was pressed on is resolved",
          (await Alert.get(id=ade_alert.id)).status == "resolved")

    ota_board_dev = await new_device("BOARD-OTA", "host-board-ota")
    ota_alert = await in_setup_alert(ota_board_dev)
    try:
        await alert_action(str(ota_alert.id), AlertAction(action_key="release"), board)
        check("releasing a device that never saw Setup Assistant is refused", False)
    except Exception as exc:
        detail = str(getattr(exc, "detail", exc))
        check("releasing a device that never saw Setup Assistant is refused",
              getattr(exc, "status_code", None) == 409)
        check("...and the admin is told which of the two refusals this is",
              "Automated Device Enrollment" in detail and "not enrolled" not in detail)

    # == 39. A check-in start runs at most once per cooldown ==
    # Active-run guard only holds while running; cooldown holds after the flow completes.
    print("39) a burst of check-ins produces one run, not one run per check-in")

    async def checkin_runs(device, start_id):
        return await FlowRun.filter(device_id=device.id, start_node=start_id).count()

    async def backdate_runs(device, start_id, minutes):
        """Age every run from this start, standing in for the clock moving on."""
        for r in await FlowRun.filter(device_id=device.id, start_node=start_id).all():
            await FlowRun.filter(id=r.id).update(
                started_at=datetime.now(timezone.utc) - timedelta(minutes=minutes))

    loopdev = await new_device("LOOP-1", "host-loop")
    for _ in range(5):
        await atc.start_flows_for_event(loopdev, "checkin")
    check("five check-ins in a burst started exactly one run",
          await checkin_runs(loopdev, "s-loop") == 1)
    await loopdev.refresh_from_db()
    check("and the one run did its work", "looped" in (loopdev.tags or []))

    print("39a) a check-in after the cooldown starts a second run")
    await backdate_runs(loopdev, "s-loop", 61)
    await atc.start_flows_for_event(loopdev, "checkin")
    check("the next check-in past the cooldown started a second run",
          await checkin_runs(loopdev, "s-loop") == 2)
    check("and the one after that is held again",
          (await atc.start_flows_for_event(loopdev, "checkin")) == []
          and await checkin_runs(loopdev, "s-loop") == 2)

    print("39b) still inside the cooldown is not long enough")
    await backdate_runs(loopdev, "s-loop", 59)
    await atc.start_flows_for_event(loopdev, "checkin")
    check("59 minutes into a 60 minute cooldown starts nothing",
          await checkin_runs(loopdev, "s-loop") == 2)

    print("39c) an active run blocks even when the cooldown has passed")
    # Both guards have to hold on their own. This one is what protects a flow that does park.
    await backdate_runs(loopdev, "s-loop", 600)
    blocker = await FlowRun.filter(
        device_id=loopdev.id, start_node="s-loop").order_by("-started_at").first()
    await FlowRun.filter(id=blocker.id).update(status="waiting",
                                               waiting_signal="device_info")
    await atc.start_flows_for_event(loopdev, "checkin")
    check("a run still going blocks the start whatever the clock says",
          await checkin_runs(loopdev, "s-loop") == 2)
    await FlowRun.filter(id=blocker.id).update(status="completed", waiting_signal=None)

    print("39d) the default is an hour, and an unset cooldown never reads as zero")
    check("the default is at least an hour",
          atc.CHECKIN_COOLDOWN_DEFAULT_MINUTES >= 60)
    check("an unset cooldown takes the default",
          atc._checkin_cooldown_minutes({}) == atc.CHECKIN_COOLDOWN_DEFAULT_MINUTES)
    check("so does one that is not a number, instead of falling to zero",
          atc._checkin_cooldown_minutes({"cooldown_minutes": "soon"})
          == atc.CHECKIN_COOLDOWN_DEFAULT_MINUTES)
    check("a negative cooldown is not shorter than none, it reads as zero",
          atc._checkin_cooldown_minutes({"cooldown_minutes": -30}) == 0)
    check("an authored zero is honoured as written",
          atc._checkin_cooldown_minutes({"cooldown_minutes": 0}) == 0)
    # YAML reads a bare yes as True and int(True) is 1, so plain coercion would give a one-minute cooldown.
    check("a boolean cooldown takes the default rather than becoming one minute",
          atc._checkin_cooldown_minutes({"cooldown_minutes": True})
          == atc.CHECKIN_COOLDOWN_DEFAULT_MINUTES)
    check("a quoted 'false' turns 'once' off, the way whoever wrote it meant",
          atc._truthy_param("false") is False and atc._truthy_param("no") is False)
    check("and a quoted 'true' turns it on", atc._truthy_param("true") is True)
    # Read through the guard and not only the helper: plain truthiness on a hand-edited document would turn a quoted
    # once: "false" into a permanent block.
    quoted = await new_device("QUOTED-1", "host-quoted")
    await FlowRun.create(tenant=tenant, device=quoted, flow_id=BASE_FLOW["id"],
                         start_node="s-loop", event_kind="checkin",
                         flow_hash="0" * 64, status="completed", context={},
                         started_at=datetime.now(timezone.utc) - timedelta(minutes=90))
    check("a start carrying once: 'false' is due again once its cooldown passes",
          await atc._checkin_start_is_due(
              quoted, {"params": {"once": "false"}}, BASE_FLOW["id"], "s-loop") is True)
    check("while once: 'true' still holds it",
          await atc._checkin_start_is_due(
              quoted, {"params": {"once": "true"}}, BASE_FLOW["id"], "s-loop") is False)

    print("39e) an authored cooldown is read off the node")
    shortdev = await new_device("SHORT-1", "host-short")
    await atc.start_flows_for_event(shortdev, "checkin")
    await backdate_runs(shortdev, "s-short", 6)
    await atc.start_flows_for_event(shortdev, "checkin")
    check("six minutes clears a five minute cooldown that an hour would have held",
          await checkin_runs(shortdev, "s-short") == 2)

    print("39f) an explicit zero is the author asking for every check-in")
    nodev = await new_device("NOCOOL-1", "host-nocool")
    for _ in range(3):
        await atc.start_flows_for_event(nodev, "checkin")
    check("three check-ins, three runs", await checkin_runs(nodev, "s-nocool") == 3)

    print("39g) once: true never starts a second run on its own")
    oncedev = await new_device("ONCE-1", "host-once")
    await atc.start_flows_for_event(oncedev, "checkin")
    await backdate_runs(oncedev, "s-once", 60 * 24 * 30)
    await atc.start_flows_for_event(oncedev, "checkin")
    check("a month later it still has not started again",
          await checkin_runs(oncedev, "s-once") == 1)
    check("but an admin can still start it by hand",
          await atc.start_run_from_start(oncedev, "s-once") is not None)

    print("39g-i) a rebuilt flow does not inherit the dead flow's history")
    # Editor mints start ids per-flow: dedup on (device, flow, start) not just start id.
    inherit = await new_device("ONCE-1-B", "host-once-b")
    await FlowRun.create(tenant=tenant, device=inherit, flow_id="an-older-flow",
                         start_node="s-once", event_kind="checkin",
                         flow_hash="0" * 64, status="completed", context={})
    check("a run from another flow on the same start id does not hold this one",
          await atc._checkin_start_is_due(
              inherit, {"params": {"once": True}}, BASE_FLOW["id"], "s-once") is True)
    check("while this flow's own run still does",
          await atc._checkin_start_is_due(
              oncedev, {"params": {"once": True}}, BASE_FLOW["id"], "s-once") is False)

    print("39h) a lookup that fails holds the start rather than releasing it")
    # The other guards in this file fail open, since missing a cycle costs a device one pass. Not this one: past it is a
    # run that can queue a command whose acknowledgement starts the next run.
    real_last = atc._last_run_for_device

    async def _boom(*a, **k):
        raise RuntimeError("last-run lookup unavailable")

    atc._last_run_for_device = _boom
    try:
        faildev = await new_device("LOOP-1-FAIL", "host-loopfail")
        # Scoped to LOOP-1 by serial, so drive the guard directly rather than through a scope this device would not
        # match.
        due = await atc._checkin_start_is_due(
            faildev, {"params": {}}, BASE_FLOW["id"], "s-loop")
    finally:
        atc._last_run_for_device = real_last
    check("a failed lookup answers 'not due'", due is False)

    # == 40. A flow-installed profile records the flow that asked ==
    # Without the mark, the sync loop's removal pass would take it off as unwanted.
    print("40) an install_profiles step marks the deployment with its flow")
    from controller.services import profile_manager as _pm

    fp_task = await Task.filter(device=dev, type="profile_install").first()
    fp_source = (fp_task.details or {}).get(_pm.INSTALL_SOURCE_KEY) if fp_task else None
    check("the install task names the flow as the install source",
          fp_source == _pm.flow_source(BASE_FLOW["id"]))
    check("and it is written in the form the sync loop reads back",
          _pm.flow_source_id(fp_source) == BASE_FLOW["id"])
    check("which is not read as a compliance rule's mark",
          _pm.remediation_rule_id(fp_source) is None)

    print("40a) an install_apps step marks its task the same way")
    appdev = await new_device("APPMARK-1", "host-appmark")
    await atc.start_run_from_start(appdev, "s-appmark")
    fa_task = await Task.filter(device=appdev, type="app_install").first()
    fa_source = (fa_task.details or {}).get(_pm.INSTALL_SOURCE_KEY) if fa_task else None
    check("the app install task carries the flow mark too",
          fa_task is not None and _pm.flow_source_id(fa_source) == BASE_FLOW["id"])
    check("and the app definition beside it is untouched",
          (fa_task.details or {}).get("app_info", {}).get("app_id") == "ready")

    # == 41. A run orphaned mid-advance is settled, not just marked failed ==
    # Sweep must end it: device may be stranded, and snapshot holds passwords.
    print("41) a stale 'running' run is failed through the full settlement")
    odev = await new_device("STALERUN-1", "host-stalerun", dep=True)
    orun = await atc.start_run_from_start(odev, "s-held")
    await orun.refresh_from_db()
    check("parked at held-wait with a snapshot pinned",
          orun.status == "waiting" and "flow" in (orun.context or {}))
    oa = await active_in_setup(odev)
    check("the green in-setup alert opened", oa is not None and oa.severity == "green")
    # What a process dying mid-advance leaves behind: status running, no deadline, nothing waiting, and an updated_at
    # that stopped moving.
    await FlowRun.filter(id=orun.id).update(
        status="running", waiting_signal=None, waiting_ref=None, wait_deadline=None,
        updated_at=datetime.now(timezone.utc)
                   - timedelta(minutes=atc.STALE_RUNNING_MINUTES + 5))
    await atc.sweep_timeouts(tenant)
    await orun.refresh_from_db()
    check("the sweep failed the orphaned run", orun.status == "failed")
    check("with the interrupted error", "orphaned mid-execution" in (orun.error or ""))
    check("the pinned flow snapshot is gone", "flow" not in (orun.context or {}))
    check("and the run's own timeline says what happened",
          timeline_has(orun, "orphaned mid-execution"))
    ofa = await failure_alerts(odev)
    check("the failure reached the board", len(ofa) == 1)
    check("red, because a device is stranded behind it",
          bool(ofa) and ofa[0].severity == "red"
          and (ofa[0].detail or {}).get("held_in_setup") is True)
    check("naming the node it died on",
          bool(ofa) and (ofa[0].detail or {}).get("node_id") == "held-wait")
    check("and linking back to the run",
          bool(ofa) and (ofa[0].detail or {}).get("flow_run_id") == str(orun.id))
    oa2 = await active_in_setup(odev)
    check("the in-setup alert escalated instead of staying green",
          oa2 is not None and oa2.severity == "yellow")

    # Let any spawned background tasks settle, then close.
    await webhook_handler.drain_deferred()
    await Tortoise.close_connections()

    print()
    if _FAILURES:
        print(f"FAILED ({len(_FAILURES)}): {_FAILURES}")
        return 1
    print("ALL ATC E2E CHECKS PASSED")
    return 0


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
