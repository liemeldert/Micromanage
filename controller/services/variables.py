"""Registry of {variable} placeholders for templated fields."""

import re
from typing import Any, Dict, List, Optional

# Each key is what an author types in braces, and build_context() maps it to device state. Served by GET
# /api/v1/naming/variables and mirrored in webui/lib/config.ts.
VARIABLE_SPECS: List[Dict[str, str]] = [
    {"key": "serial", "label": "Serial number",
     "description": "Hardware serial number", "category": "device"},
    {"key": "model", "label": "Model",
     "description": "Device model identifier", "category": "device"},
    {"key": "hostname", "label": "Hostname",
     "description": "Name the device reports for itself", "category": "device"},
    {"key": "os", "label": "OS version",
     "description": "Operating system version", "category": "device"},
    {"key": "os_version", "label": "OS version",
     "description": "Operating system version (alias of os)", "category": "device"},
    {"key": "udid", "label": "UDID",
     "description": "Full enrollment UDID", "category": "device"},
    {"key": "udid_short", "label": "Short UDID",
     "description": "First 8 characters of the UDID", "category": "device"},
    {"key": "management_type", "label": "Management type",
     "description": "Management backend (apple_mdm, ...)", "category": "device"},
]

VARIABLE_KEYS = frozenset(spec["key"] for spec in VARIABLE_SPECS)

# Variables the managed name overwrites once it is pushed: Settings/DeviceName replaces the reported DeviceName stored
# as hostname. A template using one of these reads its own output, so re-deriving compounds and callers have to check.
SELF_REFERENTIAL_KEYS = frozenset({"hostname"})

_PLACEHOLDER = re.compile(r"\{([^}]+)\}")
_STRAY_BRACES = re.compile(r"[{}]")


def build_context(device: Any, owner: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Resolve every known variable for a device into a {key: value} map."""
    udid = getattr(device, "udid", "") or ""
    return {
        "serial": getattr(device, "serial_number", "") or "",
        "model": getattr(device, "device_model", "") or "",
        "hostname": getattr(device, "hostname", "") or "",
        "os": getattr(device, "os_version", "") or "",
        "os_version": getattr(device, "os_version", "") or "",
        "udid": udid,
        "udid_short": udid[:8],
        "management_type": getattr(device, "management_type", "") or "",
    }


def template_variables(template: Optional[str]) -> List[str]:
    """Return the {variable} names referenced by a template (in order)."""
    if not template:
        return []
    return [m.group(1).strip() for m in _PLACEHOLDER.finditer(str(template))]


def unknown_variables(template: Optional[str]) -> List[str]:
    """Variables referenced by a template that aren't in the registry.

    An authoring warning rather than an error, since a template may reference a variable a future extension defines.
    """
    seen: List[str] = []
    for name in template_variables(template):
        if name not in VARIABLE_KEYS and name not in seen:
            seen.append(name)
    return seen


def is_self_referential(template: Optional[str]) -> bool:
    """True if the template uses a variable the managed name overwrites, so re-deriving it compounds."""
    return any(name in SELF_REFERENTIAL_KEYS for name in template_variables(template))


def render(
    template: Optional[str],
    device: Any,
    owner: Optional[Dict[str, Any]] = None,
    *,
    max_length: Optional[int] = None,
) -> Optional[str]:
    """Render a {variable} template against device state, or None if it renders to nothing."""
    if not template or not str(template).strip():
        return None
    ctx = build_context(device, owner)
    rendered = _PLACEHOLDER.sub(lambda m: ctx.get(m.group(1).strip(), ""), str(template))
    # A device name must never contain braces, so drop any left by a malformed template or by a value containing one.
    rendered = _STRAY_BRACES.sub("", rendered)
    rendered = re.sub(r"\s+", " ", rendered).strip(" -_.")
    if not rendered:
        return None
    return rendered[:max_length] if max_length else rendered
