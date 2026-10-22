"""Which flow runs, gate decisions and task actions a member may take, and the authority a run carries."""
from typing import Any, Dict, Optional, Tuple

from controller.auth import DESTRUCTIVE_COMMANDS
from controller.services import scoping
from controller.services.flow_step_catalog import VALID_NODE_TYPES

ROLE_SYSTEM = "system"

# Nodes that set a lock or credential on the device, or change the tags every scope reads.
ADMIN_ONLY_NODE_TYPES = frozenset({"set_firmware_lock", "configure_accounts", "assign_tag", "remove_tag"})

# send_command is member-safe here and admin-only per node when its command is in DESTRUCTIVE_COMMANDS.
MEMBER_SAFE_NODE_TYPES = frozenset({
    "start", "set_name", "install_profiles", "install_apps", "sync_declarations", "send_command", "branch",
    "wait_for", "release_device", "manual_gate", "end",
})

# Task types a member may not cancel or retry.
ADMIN_ONLY_TASK_TYPES = DESTRUCTIVE_COMMANDS | {"set_firmware_lock", "account_configuration"}

# Every node type is in exactly one of the two sets; an unclassified one fails at import.
assert ADMIN_ONLY_NODE_TYPES | MEMBER_SAFE_NODE_TYPES == VALID_NODE_TYPES, (
    f"unclassified flow node types: {VALID_NODE_TYPES - ADMIN_ONLY_NODE_TYPES - MEMBER_SAFE_NODE_TYPES}, "
    f"unknown: {(ADMIN_ONLY_NODE_TYPES | MEMBER_SAFE_NODE_TYPES) - VALID_NODE_TYPES}"
)
assert not ADMIN_ONLY_NODE_TYPES & MEMBER_SAFE_NODE_TYPES, "a node type is both admin-only and member-safe"

FLOW_PERMISSION_ERRORS = {
    "start_out_of_scope": ("Device {serial} is outside the scope of start node '{start}' in flow '{flow}'. Ask an "
                           "admin to start it, or add the device to that start node's scope."),
    "start_admin_only_node": "Flow '{flow}' has an admin-only step, '{node}' ({type}). Ask an admin to start it.",
    "gate_out_of_scope": ("Device {serial} is outside the scope of the flow this gate belongs to. Ask an admin to "
                          "decide this gate."),
    "gate_admin_only_node": ("Flow '{flow}' has an admin-only step, '{node}' ({type}). Ask an admin to decide this "
                             "gate."),
    "gate_flow_unavailable": ("The definition of flow '{flow}' is no longer available. Ask an admin to decide this "
                              "gate."),
    "node_refused": ("Step '{node}' ({type}) needs a run started by an admin, and a member started this run. An admin "
                     "can start the flow again."),
}


def admin_only_node(node: Any) -> bool:
    """True for a node a member-started run may not execute."""
    if not isinstance(node, dict):
        return False
    ntype = node.get("type")
    if ntype in ADMIN_ONLY_NODE_TYPES:
        return True
    if ntype == "send_command":
        return str((node.get("params") or {}).get("command")) in DESTRUCTIVE_COMMANDS
    return False


def flow_has_admin_only_node(flow: Any) -> Optional[Dict[str, Any]]:
    """The first admin-only node in the flow, or None."""
    if not isinstance(flow, dict):
        return None
    for node in (flow.get("nodes") or []):
        if admin_only_node(node):
            return node
    return None


def run_role(run: Any) -> str:
    """The role a run was started with; null counts as system."""
    return getattr(run, "started_role", None) or ROLE_SYSTEM


def member_flow_refusal(device: Any, flow: Dict[str, Any],
                        start_node_id: Optional[str]) -> Optional[Tuple[str, Optional[Dict[str, Any]]]]:
    """Why a member may not run this flow from this start node on this device, as (reason, node), or None."""
    node = flow_has_admin_only_node(flow)
    if node is not None:
        return "admin_only_node", node
    start = None
    for n in (flow.get("nodes") or []):
        if isinstance(n, dict) and n.get("id") == start_node_id and n.get("type") == "start":
            start = n
            break
    if start is None:
        return "out_of_scope", None
    if not scoping.matches_or_all(device, list(device.groups or []), (start.get("params") or {}).get("match")):
        return "out_of_scope", None
    return None


async def gate_refusal(principal: Any, run: Any) -> Optional[Tuple[str, Optional[Dict[str, Any]]]]:
    """Why this principal may not decide or dismiss the run's manual gate, as (reason, node), or None. An admin is
    never refused; a run whose device row is gone is out of scope for a member."""
    if principal.is_admin:
        return None
    from controller.models.tenant import Device
    from controller.services import atc

    flow = (run.context or {}).get("flow") or atc._load_flow(str(run.tenant_id), str(run.flow_id))
    if not flow:
        return "flow_unavailable", None
    device = await Device.get_or_none(id=run.device_id, tenant_id=run.tenant_id)
    if device is None:
        return "out_of_scope", None
    return member_flow_refusal(device, flow, run.start_node)


async def gate_refused(principal: Any, run: Any, *, alert_id: Optional[str], action: str) -> Optional[str]:
    """The 403 text when this principal may not decide or dismiss the run's gate, after writing flow.gate.refused, or
    None when the decision may go ahead."""
    refusal = await gate_refusal(principal, run)
    if refusal is None:
        return None
    reason, node = refusal
    from controller.models.tenant import Device
    from controller.services.audit import record_audit

    await record_audit(
        principal, "flow.gate.refused", target_type="flow_run", target_id=str(run.id),
        detail={"alert_id": alert_id, "flow_id": run.flow_id,
                "device_id": str(run.device_id) if run.device_id else None,
                "action": action, "reason": reason},
    )
    if reason == "admin_only_node":
        return FLOW_PERMISSION_ERRORS["gate_admin_only_node"].format(
            flow=run.flow_id, node=(node or {}).get("id"), type=(node or {}).get("type"))
    if reason == "flow_unavailable":
        return FLOW_PERMISSION_ERRORS["gate_flow_unavailable"].format(flow=run.flow_id)
    device = await Device.get_or_none(id=run.device_id)
    return FLOW_PERMISSION_ERRORS["gate_out_of_scope"].format(serial=device.serial_number if device else run.device_id)
