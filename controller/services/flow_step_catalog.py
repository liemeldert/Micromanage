"""Catalog of ATC flow node types.

Registry of node types for flow.yaml; validator and web UI read from this. See docs for detailed format.
"""

from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

# The one sentence the configure_accounts node, the flow validator and the editor all say about Apple's managed-admin
# rule. Both AccountConfiguration keys the node's non-admin modes set require AutoSetupAdminAccounts, which is the
# managed admin; without one the Mac skips or downgrades the only account it was going to create and gets nothing in its
# place. https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/account.configuration.yaml
ACCOUNT_ADMIN_REQUIREMENT = (
    "Apple requires AutoSetupAdminAccounts when SkipPrimarySetupAccountCreation or SetPrimarySetupAccountAsRegularUser "
    "is set, which is what the 'skip' and 'prompt_standard' modes send, so both need a managed admin"
)

# Device signals a wait_for node can park on. Kept in lockstep with services.atc.advance_on_signal.
WAIT_SIGNALS: List[Dict[str, str]] = [
    {"value": "device_info", "label": "Device reports information",
     "description": "The device answered a DeviceInformation / SecurityInfo query."},
    {"value": "checkin", "label": "Device checks in",
     "description": "The device next contacts the server (any acknowledge)."},
    {"value": "ddm_status", "label": "A DDM status report arrives",
     "description": "The device delivers a Declarative Device Management status "
                    "report (any content)."},
    {"value": "profile_installed", "label": "Every queued profile is installed",
     "description": "The device has acknowledged each InstallProfile the flow "
                    "queued. One profile the device never installs holds the "
                    "barrier until it times out."},
    {"value": "app_installed", "label": "Every queued app install is accepted",
     "description": "The device has accepted each InstallApplication the flow "
                    "queued. The downloads may still be running: MDM acknowledges "
                    "acceptance, not completion."},
    {"value": "command_ack", "label": "Every queued command is acknowledged",
     "description": "The device has answered each send_command step's command."},
    {"value": "declaration_applied", "label": "Every queued declaration is applied",
     "description": "Each declaration a sync_declarations step queued is reported "
                    "active and valid. Refs are the declaration's yaml id from "
                    "declarations.yaml."},
]

_WAIT_SIGNAL_VALUES = frozenset(s["value"] for s in WAIT_SIGNALS)

# Events a start node runs on. Kept in lockstep with the event kinds services.atc.start_flows_for_event is called with
# from the enroll / checkin / schedule hooks.
START_KINDS: List[Dict[str, str]] = [
    {"value": "enroll_dep", "scope": "enrollment", "label": "Enrollment (Automated / DEP)",
     "description": "Runs when a device from Automated Device Enrollment (ABM/ASM) "
                    "enrolls or re-enrolls."},
    {"value": "enroll_profile", "scope": "enrollment", "label": "Enrollment (OTA / manual)",
     "description": "Runs when a device enrolls over-the-air or by installing the "
                    "enrollment profile manually (not DEP-assigned)."},
    {"value": "checkin", "scope": "universal", "label": "Device check-in",
     "description": "Runs when the device contacts the server, at most once per "
                    "cooldown (60 minutes unless you set one) and never while a run "
                    "from this start is still going. The cooldown matters because "
                    "almost every step worth putting under this trigger makes the "
                    "device connect again, and that connection is another check-in. "
                    "It still re-runs every cooldown, so a step that installs "
                    "something installs it again each time; use 'Run once per "
                    "device' for a one-shot."},
    {"value": "schedule", "scope": "universal", "label": "Scheduled interval",
     "description": "Runs periodically for in-scope devices; set the interval in "
                    "minutes."},
]

_START_KIND_VALUES = frozenset(s["value"] for s in START_KINDS)

# manual_gate uses a fixed set of decision handles, which keeps the handle set static and the validator simple. Each
# params.options[].edge names one of these; unused handles need no target.
GATE_EDGE_HANDLES: List[str] = ["on_release", "on_cancel", "on_wait"]

FLOW_STEP_CATALOG: List[Dict[str, Any]] = [
    {
        "type": "start",
        "label": "Start",
        "description": "Entry point of the flow. Runs on an event (enrollment, "
                       "check-in or a schedule) for devices matching its scope, then "
                       "flows into the graph. A flow can have several starts.",
        "category": "Flow",
        "scope": "universal",
        "waits": False,
        "edges": ["next"],
        "params": [
            {"name": "kind", "label": "Trigger", "type": "select", "required": True,
             "options": START_KINDS},
            {"name": "match", "label": "Applies to", "type": "scope", "required": False,
             "help": "Optional scope (conditions / groups / tags / device lists). "
                     "Empty matches every device of this trigger kind."},
            {"name": "interval_minutes", "label": "Interval (minutes)", "type": "int",
             "required": False,
             "help": "Required for a Scheduled interval start; ignored otherwise."},
            {"name": "cooldown_minutes", "label": "Cooldown (minutes)", "type": "int",
             "required": False,
             "help": "Device check-in starts only. Shortest gap between two runs on "
                     "one device; 60 if you leave it empty. Set 0 only when no step "
                     "below this start touches the device, since anything that does "
                     "makes the device check in again."},
            {"name": "once", "label": "Run once per device", "type": "bool",
             "required": False,
             "help": "Device check-in starts only. After one run this start does not "
                     "run again for that device on its own, for as long as that run "
                     "is kept: flow runs are pruned after FLOW_RUN_RETENTION_DAYS (30 "
                     "by default), and once the record is gone the start is due again. "
                     "For a one-shot that has to hold for good, have the flow tag the "
                     "device and exclude that tag in this start's scope. You can still "
                     "start it by hand from the device page, which restarts the "
                     "cooldown."},
        ],
    },
    {
        "type": "assign_tag",
        "label": "Assign tags",
        "description": "Add one or more tags to the device (idempotent). Tags can "
                       "drive group membership and profile/app scoping.",
        "category": "Tags",
        "scope": "universal",
        "waits": False,
        "edges": ["next"],
        "params": [
            {"name": "tags", "label": "Tags to add", "type": "tags", "required": True,
             "help": "Added to the device's tag set; existing tags are untouched."},
        ],
    },
    {
        "type": "remove_tag",
        "label": "Remove tags",
        "description": "Remove the named tags from the device (only those named; "
                       "other tags are left in place).",
        "category": "Tags",
        "scope": "universal",
        "waits": False,
        "edges": ["next"],
        "params": [
            {"name": "tags", "label": "Tags to remove", "type": "tags", "required": True},
        ],
    },
    {
        "type": "set_name",
        "label": "Set device name",
        "description": "Apply a naming template and push the managed name to the "
                       "device. The step does not wait; follow it with a wait_for to "
                       "hold the run until the device answers.",
        "category": "Naming",
        "scope": "universal",
        "waits": False,
        "edges": ["next"],
        "params": [
            {"name": "template", "label": "Name template", "type": "name_template",
             "required": True, "help": "e.g. IT-{serial}. Uses the naming variable registry."},
        ],
    },
    {
        "type": "install_profiles",
        "label": "Install profiles",
        "description": "Queue InstallProfile for the selected profiles now, while the "
                       "device is connected. Profiles stay installed only while the "
                       "device is scoped into them: to keep one, assign a tag here and "
                       "target the profile at that tag in profiles.yaml. Otherwise the "
                       "reconciler removes a profile the device is not scoped into.",
        "category": "Deploy",
        "scope": "universal",
        "waits": False,
        "edges": ["next"],
        "params": [
            {"name": "profile_ids", "label": "Profiles", "type": "profile_ids", "required": True},
            {"name": "gate", "label": "Wait for these before releasing the device",
             "type": "bool", "required": False,
             "help": "On by default. A wait step below this one holds the "
                     "run until every profile here is installed, and if the device "
                     "leaves Setup Assistant without one of them, the run is recorded "
                     "as failed and the device appears on the alert board. Turn this "
                     "off for profiles the device does not need before somebody starts "
                     "using it."},
        ],
    },
    {
        "type": "install_apps",
        "label": "Install apps",
        "description": "Queue InstallApplication for the selected apps now, using the "
                       "version the device is entitled to (apps.yaml scoping/rollout). An "
                       "app the device is not scoped into is skipped, so pair it with a "
                       "tag and scope the app version at that tag to install it.",
        "category": "Deploy",
        "scope": "universal",
        "waits": False,
        "edges": ["next"],
        "params": [
            {"name": "app_ids", "label": "Apps", "type": "app_ids", "required": True},
            {"name": "gate", "label": "Wait for these before releasing the device",
             "type": "bool", "required": False,
             "help": "On by default. A wait step below this one holds the "
                     "run until every app here is accepted, and if the device leaves "
                     "Setup Assistant without one of them, the run is recorded as "
                     "failed and the device appears on the alert board. Turn it off "
                     "when an app is on a gradual rollout, or when it is optional: a "
                     "device outside today's rollout wave gets no app to wait for, and "
                     "with this on that counts as a device released unverified."},
        ],
    },
    {
        "type": "sync_declarations",
        "label": "Sync declarations",
        "description": "Queue a DeclarativeManagement sync so the device pulls its "
                       "current declaration set (DDM). When the tenant has DDM "
                       "disabled or the device does not support it, the step is "
                       "skipped with a note. The run continues either way.",
        "category": "Deploy",
        "scope": "universal",
        "waits": False,
        "edges": ["next"],
        "params": [
            {"name": "gate", "label": "Wait for these before releasing the device",
             "type": "bool", "required": False,
             "help": "On by default. A wait step below this one holds the "
                     "run until the device reports its declarations active. Turn it "
                     "off if this tenant does not use DDM, or if no declarations are "
                     "scoped to the devices this flow runs on: there would be nothing "
                     "to wait for, and with this on that counts as a device released "
                     "unverified."},
        ],
    },
    {
        "type": "send_command",
        "label": "Send command",
        "description": "Send a catalog command to the device. Destructive commands "
                       "(erase, lock, ...) are not permitted in an automated flow.",
        "category": "Command",
        "scope": "universal",
        "waits": False,
        "edges": ["next"],
        "params": [
            {"name": "command", "label": "Command", "type": "command", "required": True,
             "help": "A non-destructive command from the command catalog."},
            {"name": "params", "label": "Parameters", "type": "command_params", "required": False},
            {"name": "gate", "label": "Wait for the acknowledgement before releasing",
             "type": "bool", "required": False,
             "help": "On by default. A wait step below this one holds the "
                     "run until the device answers this command. Turn it off for a "
                     "command whose answer the rest of the flow does not depend on."},
        ],
    },
    {
        "type": "branch",
        "label": "Branch",
        "description": "Fork the flow on a scope condition (true / false).",
        "category": "Flow",
        "scope": "universal",
        "waits": False,
        "edges": ["on_true", "on_false"],
        "params": [
            {"name": "condition", "label": "Condition", "type": "condition", "required": True},
        ],
    },
    {
        "type": "wait_for",
        "label": "Wait for signal",
        "description": "Pause the run until the device produces the signal, or the "
                       "timeout elapses (follows the timeout edge, else fails the "
                       "run). Signals that refer to work the flow queued wait for "
                       "all of it, so put this after the steps whose results the "
                       "rest of the flow depends on.",
        "category": "Flow",
        "scope": "universal",
        "waits": True,
        "edges": ["next", "on_timeout"],
        "params": [
            {"name": "signal", "label": "Wait for", "type": "signal", "required": True,
             "options": WAIT_SIGNALS},
            {"name": "timeout_minutes", "label": "Timeout (minutes)", "type": "int",
             "required": True, "help": "How long to wait before taking the timeout edge."},
            {"name": "gate", "label": "This wait must have something to wait for",
             "type": "bool", "required": False,
             "help": "On by default. If the steps above queued nothing, "
                     "this wait has nothing to hold and the run walks straight past "
                     "it, releasing a device before its profiles arrive. With this on "
                     "that is recorded, and a device released afterwards goes on the "
                     "alert board. Turn it off for a wait that is allowed to find "
                     "nothing waiting."},
        ],
    },
    {
        "type": "release_device",
        "label": "Release from Setup Assistant",
        "description": "Send DeviceConfigured to let an Automated Enrollment (ADE) "
                       "device leave Setup Assistant. Put this LAST, after your "
                       "mandatory profiles/apps are installed, so the user only "
                       "reaches the home screen once the device is fully provisioned. "
                       "Needs the DEP profile's 'Await device configured' option. A "
                       "device that enrolled over the air was never held in setup, so "
                       "the step is skipped there with a note. If anything the flow "
                       "queued above never arrived, the device is still released, but "
                       "the run is recorded as failed and the device goes on the alert "
                       "board naming what it is missing.",
        "category": "Flow",
        "scope": "enrollment",
        "waits": False,
        "edges": ["next"],
        "params": [],
    },
    {
        "type": "configure_accounts",
        "label": "Configure setup accounts",
        "description": "Decide which local accounts a Mac creates during Setup Assistant, "
                       "and optionally add a managed admin whose password is escrowed. "
                       "macOS only, only on a Mac that enrolled through Automated Device "
                       "Enrollment, and only while it is still awaiting configuration, so "
                       "keep it before the release step. Both the Standard and the skip "
                       "mode need the managed admin turned on: " + ACCOUNT_ADMIN_REQUIREMENT
                       + ". The step refuses to send without one rather than leave a Mac "
                         "with no administrator.",
        "category": "Accounts",
        "scope": "enrollment",
        "waits": False,
        "edges": ["next"],
        "params": [
            {"name": "primary_account", "label": "User account prompt", "type": "select",
             "required": True, "options": [
                {"value": "prompt_admin", "label": "Prompt: create an Admin account"},
                {"value": "prompt_standard", "label": "Prompt: create a Standard account"},
                {"value": "skip", "label": "Don't prompt (skip account creation)"},
            ], "help": "Standard maps to SetPrimarySetupAccountAsRegularUser; skip maps "
                       "to SkipPrimarySetupAccountCreation. Pair either one with a "
                       "managed admin, or the step will not send: " +
                       ACCOUNT_ADMIN_REQUIREMENT + "."},
            {"name": "lock_primary_account", "label": "Lock the account fields", "type": "bool",
             "required": False, "help": "The pre-filled name / short name can't be edited "
                                        "by the user during setup."},
            {"name": "primary_full_name", "label": "Pre-fill full name", "type": "string",
             "required": False},
            {"name": "primary_short_name", "label": "Pre-fill short name", "type": "string",
             "required": False},
            {"name": "managed_admin", "label": "Also create a managed admin", "type": "bool",
             "required": False, "help": "A hidden local admin owned by MDM (AutoSetupAdmin"
                                        "Accounts). Its password is escrowed so an admin can retrieve it."},
            {"name": "managed_admin_shortname", "label": "Managed admin short name",
             "type": "string", "required": False, "help": "Default: mmadmin"},
            {"name": "managed_admin_fullname", "label": "Managed admin full name",
             "type": "string", "required": False},
            {"name": "managed_admin_hidden", "label": "Hide the managed admin", "type": "bool",
             "required": False, "help": "Hidden from the login window and Users list. Default: on."},
            {"name": "managed_admin_password_source", "label": "Managed admin password",
             "type": "select", "required": False, "options": [
                {"value": "generate", "label": "Auto-generate & escrow"},
                {"value": "static", "label": "Use the value entered below"},
            ]},
            {"name": "managed_admin_password", "label": "Static password", "type": "string",
             "required": False, "secret": True,
             "help": "Used only when the source is 'Use the value entered below'."},
        ],
    },
    {
        "type": "set_firmware_lock",
        "label": "Set firmware lock",
        "description": "Lock a Mac's firmware and escrow the password so an admin can retrieve it. "
                       "Apple silicon gets a Recovery Lock; Intel gets an EFI firmware "
                       "password, which restarts the Mac when it is set. Put this after a "
                       "wait for device information, since the step needs to know the "
                       "architecture before it can pick the command. Skipped on a re-run "
                       "when the Mac already has a lock we hold the password for.",
        "category": "Security",
        "scope": "universal",
        "waits": False,
        "edges": ["next"],
        "params": [
            {"name": "password_source", "label": "Password", "type": "select", "required": True,
             "options": [
                 {"value": "generate", "label": "Auto-generate & escrow"},
                 {"value": "static", "label": "Use the value entered below"},
             ]},
            {"name": "password", "label": "Static password", "type": "string", "required": False,
             "secret": True,
             "help": "Used only when the source is 'Use the value entered below'. Editing it "
                     "later rotates the lock on the next run; the escrow keeps the old "
                     "password until the Mac confirms the new one."},
        ],
    },
    {
        "type": "manual_gate",
        "label": "Hold for manual intervention",
        "description": "Raise a Dispatcher alert and PAUSE the run until an admin "
                       "picks an option from the alert board. Typically wired to a "
                       "wait_for's timeout edge so a stuck device escalates to an "
                       "admin to review, who chooses whether to release it from Setup "
                       "Assistant, cancel the flow, or keep waiting. An unanswered "
                       "gate does not wait forever: its alert escalates on a "
                       "schedule and the run eventually fails.",
        "category": "Flow",
        "scope": "universal",
        "waits": True,
        "edges": GATE_EDGE_HANDLES,
        "params": [
            {"name": "summary", "label": "Alert summary", "type": "string", "required": True,
             "help": "Shown on the alert board, e.g. 'Device stuck in setup > 30m'."},
            {"name": "severity", "label": "Severity", "type": "select", "required": True,
             "options": [{"value": s, "label": s} for s in ("green", "yellow", "red", "black")]},
            {"name": "options", "label": "Decision options", "type": "gate_options",
             "required": True,
             "help": "Each option is a button on the alert. 'edge' is the handle the "
                     "run follows when chosen (on_release / on_cancel / on_wait)."},
            {"name": "timeout_minutes", "label": "Time limit (minutes)", "type": "int",
             "required": False,
             "help": "Optional. Total minutes this gate may wait before the run "
                     "fails. Escalations that fall inside the limit still run. "
                     "Without it the gate follows the server's ladder: by default "
                     "the alert escalates one step after 4 hours, again 24 hours "
                     "later, and the run fails 7 days after that."},
        ],
    },
    {
        "type": "end",
        "label": "End",
        "description": "Terminal node: the run completes when it reaches an end.",
        "category": "Flow",
        "scope": "universal",
        "waits": False,
        "edges": [],
        "params": [],
    },
]

_BY_TYPE: Dict[str, Dict[str, Any]] = {n["type"]: n for n in FLOW_STEP_CATALOG}
VALID_NODE_TYPES = frozenset(_BY_TYPE)

_BY_START_KIND: Dict[str, Dict[str, str]] = {k["value"]: k for k in START_KINDS}

# Derived from the catalog rather than restated, so a node that gains or loses its enrollment scope has one place to
# change.
ENROLLMENT_ONLY_NODE_TYPES = frozenset(
    n["type"] for n in FLOW_STEP_CATALOG if n.get("scope") == "enrollment"
)
ENROLLMENT_ONLY_START_KINDS = frozenset(
    k["value"] for k in START_KINDS if k.get("scope") == "enrollment"
)

# Enrollment flow id; immutable for backward compat (see docs).
DEFAULT_ENROLLMENT_FLOW_ID = "enrollment"

# Flow-level keys that mark a draft. A draft is a working copy of another flow that services.atc never executes; see
# _load_flows.
DRAFT_ID_SUFFIX = "--draft"
DRAFT_KEYS = ("draft_of", "draft_base_hash", "draft_note",
              "draft_created_by", "draft_created_at")


def node_edges(node_type: str) -> List[str]:
    """The output edge handles a node type wires from (empty for terminals)."""
    entry = _BY_TYPE.get(node_type)
    return list(entry["edges"]) if entry else []


def secret_param_names(node_type: Any) -> FrozenSet[str]:
    """The param names this node type marks secret, empty for unknown types."""
    entry = _BY_TYPE.get(node_type) if isinstance(node_type, str) else None
    if not entry:
        return frozenset()
    return frozenset(p["name"] for p in (entry.get("params") or []) if p.get("secret"))


def node_scope(node_type: Any) -> str:
    """"universal" or "enrollment" for a node type. An unknown type reads as universal, since the validator already
    rejects it by name and a scope complaint about a node type that does not exist would only confuse."""
    entry = _BY_TYPE.get(node_type) if isinstance(node_type, str) else None
    return str((entry or {}).get("scope") or "universal")


def start_kind_scope(kind: Any) -> str:
    """"universal" or "enrollment" for a start trigger kind. Unknown kinds read as universal, for the same reason as
    node_scope."""
    entry = _BY_START_KIND.get(kind) if isinstance(kind, str) else None
    return str((entry or {}).get("scope") or "universal")


def is_wait_signal(signal: Any) -> bool:
    return signal in _WAIT_SIGNAL_VALUES


def is_start_kind(kind: Any) -> bool:
    return kind in _START_KIND_VALUES


def is_draft(flow: Any) -> bool:
    """Whether this flow is a draft of another one. Truthiness of draft_of is the whole test, so a hand-typed empty
    draft_of reads as a live flow rather than as a draft with nowhere to go."""
    return bool(isinstance(flow, dict) and flow.get("draft_of"))


def draft_id_for(flow_id: str) -> str:
    """The derived id of a flow's draft. Never authored, which makes one draft per flow a property of the id rather than
    a rule somebody has to check."""
    return f"{flow_id}{DRAFT_ID_SUFFIX}"


def default_enrollment_flow() -> Dict[str, Any]:
    """The default enrollment flow for a newly provisioned tenant.

    Conservative by design: queues nothing, so cannot strand anything. Returns a fresh dict each call.
    """
    return {
        "id": DEFAULT_ENROLLMENT_FLOW_ID,
        "name": "Device enrollment",
        "description": (
            "Runs when a device enrolls. Waits for the device to report itself, then releases it from Setup Assistant. "
            "Add your profiles, apps and account setup between the two."
        ),
        "enabled": True,
        "permanent": True,
        "nodes": [
            {"id": "start-dep", "type": "start",
             "params": {"kind": "enroll_dep", "match": {}},
             "ui": {"x": -260, "y": -80}, "next": "await-info"},
            {"id": "start-ota", "type": "start",
             "params": {"kind": "enroll_profile", "match": {}},
             "ui": {"x": -260, "y": 80}, "next": "await-info"},
            {"id": "await-info", "type": "wait_for",
             "params": {"signal": "device_info", "timeout_minutes": 30},
             "ui": {"x": 0, "y": 0},
             "next": "release", "on_timeout": "gate-stuck"},
            {"id": "gate-stuck", "type": "manual_gate",
             "params": {
                 "summary": "Device has not reported in since it enrolled",
                 "severity": "yellow",
                 "options": [
                     {"label": "Release it from Setup Assistant", "edge": "on_release"},
                     {"label": "Stop this run", "edge": "on_cancel"},
                 ],
             },
             "ui": {"x": 0, "y": 240},
             "on_release": "release", "on_cancel": "done"},
            {"id": "release", "type": "release_device", "params": {},
             "ui": {"x": 280, "y": 0}, "next": "done"},
            {"id": "done", "type": "end", "params": {},
             "ui": {"x": 520, "y": 0}},
        ],
    }


def _looks_legacy_v0(entry: Dict[str, Any]) -> bool:
    """Whether this entry is a pre-start-node flow (v0 format)."""
    if any(k in entry for k in ("trigger", "priority")):
        return True
    if isinstance(entry.get("start"), str) and entry["start"]:
        return True
    nodes = [n for n in (entry.get("nodes") or []) if isinstance(n, dict)]
    if not nodes:
        return False
    return not any(n.get("type") == "start" for n in nodes)


def _collapse_legacy_v0(entries: List[Dict[str, Any]],
                        warnings: List[str]) -> Optional[Dict[str, Any]]:
    """Fold v0 entries into one flow. Keeps first enabled; synthesizes a start node for backward compat."""
    if not entries:
        return None
    chosen = next((f for f in entries if f.get("enabled", True)), entries[0])
    dropped = [str(f.get("id")) for f in entries if f is not chosen]

    migrated = {k: v for k, v in chosen.items()
                if k not in ("trigger", "priority", "start")}
    nodes = list(migrated.get("nodes") or [])
    existing_ids = {n.get("id") for n in nodes if isinstance(n, dict)}
    start_id = "migrated-start"
    while start_id in existing_ids:
        start_id += "-x"
    trigger = chosen.get("trigger") or {}
    migrated["nodes"] = [{
        "id": start_id,
        "type": "start",
        "params": {"kind": "enroll_dep", "match": trigger.get("match") or {}},
        "next": chosen.get("start"),
        "ui": {"x": -220, "y": 0},
    }] + nodes

    warnings.append(
        f"flows.yaml uses the original pre-start-node format; migrated to one flow "
        f"(kept '{chosen.get('id')}'"
        + (f", dropped {dropped}" if dropped else "") + "). "
                                                        "Re-save from the ATC editor to persist the current format."
    )
    return migrated


def normalize_flow_document(data: Any) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Normalize flows.yaml into (flows, warnings). Reads v0/v1/v2 formats and repairs silently (see docs)."""
    warnings: List[str] = []
    try:
        if not isinstance(data, dict) or not data:
            return [], warnings

        listed = data.get("flows")
        single = data.get("flow")

        if data.get("version") == 2 and isinstance(listed, list):
            entries: List[Any] = list(listed)
        elif isinstance(single, dict) and single:
            # v1. A silent, lossless upgrade to a one-element list: the editor's next save writes v2, and a warning here
            # would log on every check-in for every tenant that has not re-saved yet.
            entries = [single]
        elif isinstance(listed, list) and listed:
            entries = []
            legacy: List[Dict[str, Any]] = []
            legacy_slot: Optional[int] = None
            for item in listed:
                if isinstance(item, dict) and _looks_legacy_v0(item):
                    if legacy_slot is None:
                        legacy_slot = len(entries)
                        entries.append(None)  # placeholder, filled in below
                    legacy.append(item)
                else:
                    entries.append(item)
            if legacy_slot is not None:
                entries[legacy_slot] = _collapse_legacy_v0(legacy, warnings)
                if entries[legacy_slot] is None:
                    entries.pop(legacy_slot)
        else:
            return [], warnings

        flows: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                warnings.append(
                    "flows.yaml has an entry that is not a flow mapping; skipped")
                continue
            raw_id = entry.get("id")
            flow_id = raw_id.strip() if isinstance(raw_id, str) else ""
            if not flow_id:
                warnings.append("flows.yaml has a flow with no id; skipped")
                continue
            if flow_id in seen:
                warnings.append(
                    f"flows.yaml has more than one flow with the id '{flow_id}'; "
                    "kept the first")
                continue
            seen.add(flow_id)
            flows.append(entry if raw_id == flow_id else {**entry, "id": flow_id})

        live_ids = {f["id"] for f in flows if not is_draft(f)}
        kept: List[Dict[str, Any]] = []
        for flow in flows:
            if not is_draft(flow):
                kept.append(flow)
                continue
            target = flow.get("draft_of")
            if not isinstance(target, str) or target not in live_ids:
                warnings.append(
                    f"flows.yaml draft '{flow['id']}' drafts '{target}', which is "
                    "not a live flow in this document (a draft of a draft counts); "
                    "skipped")
                continue
            if flow.get("permanent"):
                warnings.append(
                    f"flows.yaml draft '{flow['id']}' is marked permanent, which a "
                    "draft cannot be; cleared")
                flow = {k: v for k, v in flow.items() if k != "permanent"}
            kept.append(flow)
        flows = kept

        live = [(i, f) for i, f in enumerate(flows) if not is_draft(f)]
        if live and not any(f.get("permanent") is True for _, f in live):
            index, first = live[0]
            flows[index] = {**first, "permanent": True}
            # Only warn when there was a choice to make. A single flow is unambiguously the enrollment flow, and warning
            # there would log on every hot-path read for every tenant migrating from v1.
            if len(live) > 1:
                warnings.append(
                    f"flows.yaml has no permanent enrollment flow, so '{first['id']}' "
                    "was adopted as one. Open the ATC editor and save to write that "
                    "down, or move the flag to the flow you meant.")

        return flows, warnings
    except Exception:
        return [], ["flows.yaml could not be read as a set of flows; treating as none"]


def catalog() -> Dict[str, Any]:
    """Payload for GET /api/v1/flows/step-catalog (palette + signal registry)."""
    return {
        "nodes": FLOW_STEP_CATALOG,
        "wait_signals": WAIT_SIGNALS,
        "start_kinds": START_KINDS,
        "gate_edges": GATE_EDGE_HANDLES,
    }
