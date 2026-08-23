"""Dynamic device-naming templates. Derives a managed device name from a template like IT-{serial}, with placeholders from services.variables."""

from typing import Any, Dict, List, Optional, Tuple

from controller.services.variables import is_self_referential, render

# Well under Apple's DeviceName cap.
MAX_NAME_LEN = 63


def resolve_name(
    template: Optional[str], device: Any, owner: Optional[Dict[str, Any]] = None
) -> Optional[str]:
    """Render a naming template for a device. Returns None if the template is empty or renders to nothing (caller falls
    back to hostname/serial)."""
    return render(template, device, owner, max_length=MAX_NAME_LEN)


def _has_template(cfg: Optional[Dict[str, Any]]) -> bool:
    return bool(isinstance(cfg, dict) and str(cfg.get("template") or "").strip())


def select_naming_config(
    tenant_cfg: Optional[Dict[str, Any]],
    groups_config: Optional[List[Dict[str, Any]]],
    group_names: Optional[List[str]],
) -> Tuple[Optional[Dict[str, Any]], str]:
    """Pick the naming config that governs a device. Returns (cfg, source) where source is group:<name>, tenant or none."""
    members = set(group_names or [])
    for group in groups_config or []:
        if group.get("name") in members and _has_template(group.get("device_naming")):
            return group["device_naming"], f"group:{group['name']}"
    if _has_template(tenant_cfg):
        return tenant_cfg, "tenant"
    return None, "none"


def resolve_device_name(
    device: Any,
    tenant_cfg: Optional[Dict[str, Any]],
    groups_config: Optional[List[Dict[str, Any]]],
    group_names: Optional[List[str]],
    owner: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Resolve the name a device's governing template would produce (group-aware).

    Returns None when no scope defines a template or it renders to nothing.
    """
    cfg, _source = select_naming_config(tenant_cfg, groups_config, group_names)
    if not cfg:
        return None
    return resolve_name(cfg.get("template"), device, owner)


def suggested_name_for(
    device: Any,
    tenant_cfg: Optional[Dict[str, Any]],
    groups_config: Optional[List[Dict[str, Any]]],
    group_names: Optional[List[str]],
    owner: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """The rename suggestion for a device, with a loop guard to prevent self-referential templates from compounding."""
    cfg, _source = select_naming_config(tenant_cfg, groups_config, group_names)
    if not cfg:
        return None
    template = cfg.get("template")
    if getattr(device, "name", None) and is_self_referential(template):
        return None
    return resolve_name(template, device, owner)


def display_name(device: Any) -> str:
    """The name to show for a device: managed name, else DeviceName, else hostname, else serial number."""
    attributes = getattr(device, "attributes", None) or {}
    return (
        getattr(device, "name", None)
        or attributes.get("DeviceName")
        or getattr(device, "hostname", None)
        or getattr(device, "serial_number", None)
        or "Unknown device"
    )
