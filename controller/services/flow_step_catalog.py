"""Catalog of ATC flow node types.

Single source of truth for the flow (ATC) node palette, consumed by BOTH the
validator (flows.yaml node params are checked against it) and the web UI
(GET /api/v1/flows/step-catalog), so the visual editor renders its palette and
per-node parameter forms data-driven -- adding a node type is a catalog +
engine change, no bespoke frontend wiring.

Mirrors the philosophy of services.command_catalog. Each entry:

  type        node ``type`` in flows.yaml
  label       human label (palette)
  description one-liner
  category    palette grouping ("Tags", "Naming", "Deploy", "Command", "Flow")
  waits       True if the node parks the run until a device signal arrives
  edges       output handles the node wires from, in UI order:
                ["next"]                 linear step
                ["on_true", "on_false"]  branch
                ["next", "on_timeout"]   barrier (resume edge + timeout edge)
                []                        terminal
  params      [{name, label, type, required, help, ...}] -- ``type`` tells the
              editor which control to render:
                tags | profile_ids | app_ids  -> multiselect from a registry
                name_template                  -> NameTemplateInput
                condition                      -> ConditionBuilder (one condition)
                command                        -> command-catalog-driven form
                signal | select                -> Select (from ``options``)
                int | string                   -> number / text input
"""

from typing import Any, Dict, List, Optional, Tuple

# Device signals a wait_for node can park on. Kept in lockstep with the signals
# services.atc.advance_on_signal is called with from the webhook/poller hooks.
WAIT_SIGNALS: List[Dict[str, str]] = [
    {"value": "device_info", "label": "Device reports information",
     "description": "The device answered a DeviceInformation / SecurityInfo query."},
    {"value": "checkin", "label": "Device checks in",
     "description": "The device next contacts the server (any acknowledge)."},
    {"value": "profile_installed", "label": "A profile is installed",
     "description": "An InstallProfile the flow queued was acknowledged."},
    {"value": "app_installed", "label": "An app install is accepted",
     "description": "An InstallApplication the flow queued was accepted by the device. "
                    "The on-device download/install may still be in progress -- MDM "
                    "acknowledges acceptance, not completion."},
    {"value": "command_ack", "label": "A command is acknowledged",
     "description": "A send_command step's command was acknowledged by the device."},
]

_WAIT_SIGNAL_VALUES = frozenset(s["value"] for s in WAIT_SIGNALS)

# Events a `start` node can fire on. Kept in lockstep with the event kinds
# services.atc.start_flows_for_event is called with from the enroll / checkin /
# schedule hooks.
START_KINDS: List[Dict[str, str]] = [
    {"value": "enroll_dep", "label": "Enrollment (Automated / DEP)",
     "description": "Fires when a device from Automated Device Enrollment (ABM/ASM) "
                    "enrolls or re-enrolls."},
    {"value": "enroll_profile", "label": "Enrollment (OTA / manual)",
     "description": "Fires when a device enrolls over-the-air or by installing the "
                    "enrollment profile manually (not DEP-assigned)."},
    {"value": "checkin", "label": "Device check-in",
     "description": "Fires each time the device contacts the server (dedup guards "
                    "against a new run while one is already active)."},
    {"value": "schedule", "label": "Scheduled interval",
     "description": "Fires periodically for in-scope devices; set the interval in "
                    "minutes."},
]

_START_KIND_VALUES = frozenset(s["value"] for s in START_KINDS)

# manual_gate uses a fixed set of decision handles so ReactFlow renders a static
# handle set and the validator stays simple. Each params.options[].edge names one
# of these; unused handles need no target.
GATE_EDGE_HANDLES: List[str] = ["on_release", "on_cancel", "on_wait"]


FLOW_STEP_CATALOG: List[Dict[str, Any]] = [
    {
        "type": "start",
        "label": "Start",
        "description": "Entry point of the flow. Fires on an event (enrollment, "
                       "check-in or a schedule) for devices matching its scope, then "
                       "flows into the graph. A flow can have several starts.",
        "category": "Flow",
        "waits": False,
        "edges": ["next"],
        "params": [
            {"name": "kind", "label": "Trigger", "type": "select", "required": True,
             "options": START_KINDS},
            {"name": "match", "label": "Applies to", "type": "scope", "required": False,
             "help": "Optional scope (conditions / groups / tags / device lists). "
                     "Empty fires for every device of this trigger kind."},
            {"name": "interval_minutes", "label": "Interval (minutes)", "type": "int",
             "required": False,
             "help": "Required for a Scheduled interval start; ignored otherwise."},
        ],
    },
    {
        "type": "assign_tag",
        "label": "Assign tags",
        "description": "Add one or more tags to the device (idempotent). Tags can "
                       "drive group membership and profile/app scoping.",
        "category": "Tags",
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
                       "device (fire-and-forget; follow with a wait_for to block on it).",
        "category": "Naming",
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
                       "target the profile at that tag in profiles.yaml -- otherwise the "
                       "reconciler removes a profile the device is not scoped into.",
        "category": "Deploy",
        "waits": False,
        "edges": ["next"],
        "params": [
            {"name": "profile_ids", "label": "Profiles", "type": "profile_ids", "required": True},
        ],
    },
    {
        "type": "install_apps",
        "label": "Install apps",
        "description": "Queue InstallApplication for the selected apps now, using the "
                       "version the device is entitled to (apps.yaml scoping/rollout). An "
                       "app the device is not scoped into is skipped -- pair with a tag "
                       "and scope the app version at that tag to install it.",
        "category": "Deploy",
        "waits": False,
        "edges": ["next"],
        "params": [
            {"name": "app_ids", "label": "Apps", "type": "app_ids", "required": True},
        ],
    },
    {
        "type": "send_command",
        "label": "Send command",
        "description": "Send a catalog command to the device. Destructive commands "
                       "(erase, lock, ...) are not permitted in an automated flow.",
        "category": "Command",
        "waits": False,
        "edges": ["next"],
        "params": [
            {"name": "command", "label": "Command", "type": "command", "required": True,
             "help": "A non-destructive command from the command catalog."},
            {"name": "params", "label": "Parameters", "type": "command_params", "required": False},
        ],
    },
    {
        "type": "branch",
        "label": "Branch",
        "description": "Fork the flow on a scope condition (true / false).",
        "category": "Flow",
        "waits": False,
        "edges": ["on_true", "on_false"],
        "params": [
            {"name": "condition", "label": "Condition", "type": "condition", "required": True},
        ],
    },
    {
        "type": "wait_for",
        "label": "Wait for signal",
        "description": "Pause the run until the device produces a signal, or the "
                       "timeout elapses (follows the timeout edge, else fails the run).",
        "category": "Flow",
        "waits": True,
        "edges": ["next", "on_timeout"],
        "params": [
            {"name": "signal", "label": "Wait for", "type": "signal", "required": True,
             "options": WAIT_SIGNALS},
            {"name": "timeout_minutes", "label": "Timeout (minutes)", "type": "int",
             "required": True, "help": "How long to wait before taking the timeout edge."},
        ],
    },
    {
        "type": "release_device",
        "label": "Release from Setup Assistant",
        "description": "Send DeviceConfigured to let an Automated Enrollment (ADE) "
                       "device leave Setup Assistant. Put this LAST, after your "
                       "mandatory profiles/apps are installed, so the user only "
                       "reaches the home screen once the device is fully provisioned. "
                       "Requires the DEP profile's 'Await device configured' option; a "
                       "no-op on non-ADE devices.",
        "category": "Flow",
        "waits": False,
        "edges": ["next"],
        "params": [],
    },
    {
        "type": "manual_gate",
        "label": "Human decision gate",
        "description": "Raise a Dispatcher alert and PAUSE the run until an admin "
                       "picks an option from the alert board. Typically wired to a "
                       "wait_for's timeout edge so a stuck device escalates to a "
                       "human, who chooses whether to release it from Setup "
                       "Assistant, cancel the flow, or keep waiting.",
        "category": "Flow",
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
        ],
    },
    {
        "type": "end",
        "label": "End",
        "description": "Terminal node: the run completes when it reaches an end.",
        "category": "Flow",
        "waits": False,
        "edges": [],
        "params": [],
    },
]

_BY_TYPE: Dict[str, Dict[str, Any]] = {n["type"]: n for n in FLOW_STEP_CATALOG}
VALID_NODE_TYPES = frozenset(_BY_TYPE)


def get_node_type(node_type: str) -> Optional[Dict[str, Any]]:
    return _BY_TYPE.get(node_type)


def node_edges(node_type: str) -> List[str]:
    """The output edge handles a node type wires from (empty for terminals)."""
    entry = _BY_TYPE.get(node_type)
    return list(entry["edges"]) if entry else []


def is_wait_signal(signal: Any) -> bool:
    return signal in _WAIT_SIGNAL_VALUES


def is_start_kind(kind: Any) -> bool:
    return kind in _START_KIND_VALUES


def normalize_flow_document(data: Any) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Return ``(flow, warnings)`` for a flows.yaml payload, tolerating both the
    new single-flow shape and the legacy multi-flow list.

    New shape::   {"flow": {id, name, enabled, nodes: [...]}}
    Legacy shape: {"flows": [{id, name, trigger, start, nodes, priority?}, ...]}

    A legacy doc is collapsed to a single flow: the first enabled flow (else the
    first) is kept and a synthesized ``start`` node (kind=enroll_dep, carrying the
    old trigger.match, wired to the old start) is prepended so an in-flight enroll
    keeps working. Other flows are dropped with a warning. Pure and defensive:
    any malformation yields ``(None, [warning])`` -- never raises."""
    warnings: List[str] = []
    try:
        if not isinstance(data, dict) or not data:
            return None, warnings

        flow = data.get("flow")
        if isinstance(flow, dict) and flow:
            return flow, warnings

        legacy = data.get("flows")
        if not isinstance(legacy, list) or not legacy:
            return None, warnings

        candidates = [f for f in legacy if isinstance(f, dict)]
        if not candidates:
            return None, warnings
        chosen = next((f for f in candidates if f.get("enabled", True)), candidates[0])
        dropped = [str(f.get("id")) for f in candidates if f is not chosen]

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
            f"flows.yaml uses the legacy multi-flow format; migrated to a single flow "
            f"(kept '{chosen.get('id')}'"
            + (f", dropped {dropped}" if dropped else "") + "). "
            "Re-save from the ATC editor to persist the new format."
        )
        return migrated, warnings
    except Exception:
        return None, ["flows.yaml could not be parsed as a flow; treating as no flow"]


def catalog() -> Dict[str, Any]:
    """Payload for GET /api/v1/flows/step-catalog (palette + signal registry)."""
    return {
        "nodes": FLOW_STEP_CATALOG,
        "wait_signals": WAIT_SIGNALS,
        "start_kinds": START_KINDS,
        "gate_edges": GATE_EDGE_HANDLES,
    }
