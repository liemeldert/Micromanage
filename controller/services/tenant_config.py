"""Centralized per-tenant YAML config cache with stat-checked memoization."""

import copy
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)

# Cached parsed docs, keyed by absolute path, stat-checked on every read against (mtime_ns, size, inode).
# Never evicted; bounded at one entry per (tenant, config file).
_cache: Dict[str, Tuple[int, int, int, Dict[str, Any]]] = {}


def yaml_base() -> Path:
    """Root of the per-tenant YAML config tree."""
    return Path(os.getenv("YAML_CONFIG_PATH", "./yaml-configs"))


def tenant_dir(tenant_id: str) -> Path:
    """Filesystem config dir for a tenant."""
    return yaml_base() / "tenants" / str(tenant_id)


def invalidate(tenant_id: Optional[str] = None) -> None:
    """Drop cached parses; escape hatch for tests and out-of-band edits."""
    if tenant_id is None:
        _cache.clear()
        return
    prefix = str(tenant_dir(tenant_id))
    for key in [k for k in _cache if k.startswith(prefix)]:
        _cache.pop(key, None)


def _load_cached(path: Path) -> Dict[str, Any]:
    """Stat-checked cache lookup; caller handles copying."""
    key = str(path)
    try:
        st = os.stat(path)
    except OSError:  # absent (the common case for an unused config file)
        _cache.pop(key, None)
        return {}

    stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
    hit = _cache.get(key)
    if hit is not None and hit[:3] == stamp:
        return hit[3]

    try:
        with open(path, "r") as f:
            parsed = yaml.safe_load(f) or {}
    except Exception:  # malformed YAML shouldn't take down the caller
        logger.exception("failed to load %s", path)
        return {}
    _cache[key] = (*stamp, parsed)
    return parsed


def load_file(path: Path) -> Dict[str, Any]:
    """A parsed YAML doc, deep-copied and owned by the caller."""
    return copy.deepcopy(_load_cached(path))


def load_file_readonly(path: Path) -> Dict[str, Any]:
    """Cache entry as-is, shared with other readers; read-and-discard only."""
    return _load_cached(path)


def _load(tenant_id: str, filename: str) -> Dict[str, Any]:
    """One of a tenant's config docs, by filename."""
    return load_file(tenant_dir(tenant_id) / filename)


def _load_readonly(tenant_id: str, filename: str) -> Dict[str, Any]:
    """One config doc by filename, cached; caller must not store or mutate it."""
    return load_file_readonly(tenant_dir(tenant_id) / filename)


def load_groups(tenant_id: str) -> List[Dict[str, Any]]:
    """The groups list from a tenant's groups.yaml (empty if absent)."""
    groups = _load(tenant_id, "groups.yaml").get("groups", [])
    return groups if isinstance(groups, list) else []


def load_groups_readonly(tenant_id: str) -> List[Dict[str, Any]]:
    """Groups list cached; caller must not store or mutate."""
    groups = _load_readonly(tenant_id, "groups.yaml").get("groups", [])
    return groups if isinstance(groups, list) else []


def load_apps(tenant_id: str) -> List[Dict[str, Any]]:
    """The apps list from a tenant's apps.yaml (empty if absent)."""
    apps = _load(tenant_id, "apps.yaml").get("apps", [])
    return apps if isinstance(apps, list) else []


def load_profiles(tenant_id: str) -> List[Dict[str, Any]]:
    """The profiles list from a tenant's profiles.yaml (empty if absent)."""
    profiles = _load(tenant_id, "profiles.yaml").get("profiles", [])
    return profiles if isinstance(profiles, list) else []


def load_declarations(tenant_id: str) -> Dict[str, Any]:
    """A tenant's declarations.yaml (DDM), normalized to its three keys with empty defaults when the file is absent or
    malformed."""
    return normalize_declarations(_load(tenant_id, "declarations.yaml"))


def normalize_declarations(data: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce a parsed declarations doc to DDM's three keys."""
    declarations = data.get("declarations", [])
    subscriptions = data.get("status_subscriptions", [])
    org_info = data.get("organization_info", {})
    return {
        "declarations": declarations if isinstance(declarations, list) else [],
        "status_subscriptions": (
            [str(s) for s in subscriptions if s] if isinstance(subscriptions, list) else []
        ),
        "organization_info": org_info if isinstance(org_info, dict) else {},
    }
