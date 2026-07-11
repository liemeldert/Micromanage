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

from typing import Any, Dict, List, Optional

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


FLOW_STEP_CATALOG: List[Dict[str, Any]] = [
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


def catalog() -> Dict[str, Any]:
    """Payload for GET /api/v1/flows/step-catalog (palette + signal registry)."""
    return {"nodes": FLOW_STEP_CATALOG, "wait_signals": WAIT_SIGNALS}
