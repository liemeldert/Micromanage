"""Dynamic device-naming templates.

Derives a managed device name from a naming template. Templates use the
centralized variable system (services.variables) -- the same ``{variable}``
registry every templated field draws on -- so device state (and, in the future,
the owning user's directory record) can be interpolated into the name.

A naming config is a dict::

    {
        "template": "IT-{serial}",     # or "{owner.username}s {model}", etc.
        "apply_on_enroll": true,        # set the managed name on (re)enroll
    }

It can be defined at two scopes:

  * per-group   -- Group.device_naming in groups.yaml
  * per-tenant  -- Tenant.device_naming (mirrored from config.yaml)

When a device matches several groups, the FIRST group in groups.yaml order that
both matches the device and defines a template wins (config order = priority);
the tenant config is the fallback. A manually-set name always wins over any
template (auto-derivation only fills a blank name).

Kept platform-agnostic (reads generic Device fields) so the same scheme applies
to future non-Apple management types.
"""

from typing import Any, Dict, List, Optional, Tuple

from controller.services.variables import VARIABLE_SPECS, is_self_referential, render

# Advertised to the UI (rename helper / docs). The variable registry is the
# single source; this alias keeps existing importers working.
NAMING_VARIABLES = VARIABLE_SPECS

# Apple caps DeviceName well above this; keep names sane.
MAX_NAME_LEN = 63


def resolve_name(
    template: Optional[str], device: Any, owner: Optional[Dict[str, Any]] = None
) -> Optional[str]:
    """Render a naming template for a device. Returns None if the template is
    empty or renders to nothing (caller falls back to hostname/serial)."""
    return render(template, device, owner, max_length=MAX_NAME_LEN)


def _has_template(cfg: Optional[Dict[str, Any]]) -> bool:
    return bool(isinstance(cfg, dict) and str(cfg.get("template") or "").strip())


def select_naming_config(
    tenant_cfg: Optional[Dict[str, Any]],
    groups_config: Optional[List[Dict[str, Any]]],
    group_names: Optional[List[str]],
) -> Tuple[Optional[Dict[str, Any]], str]:
    """Pick the naming config that governs a device.

    The first group in ``groups_config`` order that the device belongs to AND
    that defines a ``device_naming.template`` wins; otherwise the tenant config.
    Returns ``(cfg, source)`` where source is ``group:<name>``, ``tenant`` or
    ``none``.
    """
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
    """The rename-UI suggestion for a device -- ``resolve_device_name`` with a
    reference-loop guard.

    A self-referential template (one using ``{hostname}``) feeds off the very
    field our pushed name overwrites, so re-suggesting it on an already-named
    device would compound (``MB-host`` -> ``MB-MB-host`` -> ...). Once the device
    carries a managed name, suppress the suggestion for such templates so the UI
    never offers a compounding rename. Fresh (unnamed) devices still get the
    one-shot derivation.
    """
    cfg, _source = select_naming_config(tenant_cfg, groups_config, group_names)
    if not cfg:
        return None
    template = cfg.get("template")
    if getattr(device, "name", None) and is_self_referential(template):
        return None
    return resolve_name(template, device, owner)


def display_name(device: Any) -> str:
    """The name to show for a device: managed name, else reported hostname,
    else serial."""
    return (
        getattr(device, "name", None)
        or getattr(device, "hostname", None)
        or getattr(device, "serial_number", None)
        or "Unknown device"
    )
