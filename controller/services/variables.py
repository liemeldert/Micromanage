"""Centralized device-state variable system.

A single registry of the variables that can be interpolated into templated
fields. Today only the device *name* field consumes it (services.naming), but
every future templated field should resolve `{variables}` through here so the
set of variables -- and how each maps to device state -- lives in exactly one
place.

Kept platform-agnostic: variables read generic Device fields, so the same set
applies to future non-Apple management types.

Template syntax is ``{variable}``. Rendering is deliberately hardened:
  * single-pass -- a variable's *value* is never re-scanned, so a value that
    happens to contain ``{serial}`` is emitted literally, not re-expanded;
  * stray/unbalanced braces left by a malformed template are stripped, so a
    device name can never contain ``{`` or ``}``;
  * output is whitespace-collapsed, separator-trimmed and length-capped.

Owner/directory variables are intentionally NOT exposed yet: there is no
user/directory system, so they would resolve to empty and mislead authors.
Re-add them here (and to the resolver) when that system lands.
"""

import re
from typing import Any, Dict, List, Optional

# The canonical variable registry. ``key`` is what an author types as ``{key}``;
# the resolver in build_context() maps it to device state. Advertised to the UI
# via GET /api/v1/naming/variables and mirrored in webui/lib/config.ts.
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

# Just the keys, for fast membership checks (e.g. unknown-variable warnings).
VARIABLE_KEYS = frozenset(spec["key"] for spec in VARIABLE_SPECS)

# Variables whose value is itself derived from the managed name once it is pushed
# to the device (Settings/DeviceName overwrites the reported DeviceName, which we
# store as ``hostname``). A template that references one of these feeds off its
# own output, so re-deriving compounds -- callers guard against that.
SELF_REFERENTIAL_KEYS = frozenset({"hostname"})

_PLACEHOLDER = re.compile(r"\{([^}]+)\}")
_STRAY_BRACES = re.compile(r"[{}]")


def build_context(device: Any, owner: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Resolve every known variable for a device into a ``{key: value}`` map.

    Reads generic Device attributes with getattr so it also works on ORM-free
    stand-ins (dict-like shims) in tests. ``owner`` is accepted but unused --
    reserved for a future user/directory system.
    """
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
    """Return the ``{variable}`` names referenced by a template (in order)."""
    if not template:
        return []
    return [m.group(1).strip() for m in _PLACEHOLDER.finditer(str(template))]


def unknown_variables(template: Optional[str]) -> List[str]:
    """Variables referenced by a template that aren't in the registry.

    Used for authoring warnings; not an error, since a template may reference a
    variable a future extension will define.
    """
    seen: List[str] = []
    for name in template_variables(template):
        if name not in VARIABLE_KEYS and name not in seen:
            seen.append(name)
    return seen


def is_self_referential(template: Optional[str]) -> bool:
    """True if the template references a variable that the managed name itself
    overwrites (see SELF_REFERENTIAL_KEYS) -- i.e. re-deriving it compounds."""
    return any(name in SELF_REFERENTIAL_KEYS for name in template_variables(template))


def render(
    template: Optional[str],
    device: Any,
    owner: Optional[Dict[str, Any]] = None,
    *,
    max_length: Optional[int] = None,
) -> Optional[str]:
    """Render a ``{variable}`` template against device state.

    Single-pass substitution (values are never re-expanded). Unknown/empty
    variables collapse away; any stray ``{``/``}`` left by a malformed template
    is stripped; runs of whitespace are collapsed and leading/trailing
    separators (space, ``-``, ``_``, ``.``) are trimmed. Returns None if the
    template is empty or renders to nothing.
    """
    if not template or not str(template).strip():
        return None
    ctx = build_context(device, owner)
    rendered = _PLACEHOLDER.sub(lambda m: ctx.get(m.group(1).strip(), ""), str(template))
    # A device name must never contain braces: drop any that survived (malformed
    # template, or a variable value that itself contained a brace).
    rendered = _STRAY_BRACES.sub("", rendered)
    rendered = re.sub(r"\s+", " ", rendered).strip(" -_.")
    if not rendered:
        return None
    return rendered[:max_length] if max_length else rendered
