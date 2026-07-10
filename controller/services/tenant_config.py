"""Shared filesystem access to per-tenant YAML config (groups/apps/profiles).

The reconcile loop, the API (writer) and the webhook/enroll path all need to
read the same on-disk config; this centralizes base-path resolution
(``YAML_CONFIG_PATH``, default ``./yaml-configs``) so they can't drift.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List

import yaml

logger = logging.getLogger(__name__)


def yaml_base() -> Path:
    """Root of the per-tenant YAML config tree."""
    return Path(os.getenv("YAML_CONFIG_PATH", "./yaml-configs"))


def tenant_dir(tenant_id: str) -> Path:
    """Filesystem config dir for a tenant."""
    return yaml_base() / "tenants" / str(tenant_id)


def _load(tenant_id: str, filename: str) -> Dict[str, Any]:
    path = tenant_dir(tenant_id) / filename
    if not path.exists():
        return {}
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception:  # malformed YAML shouldn't take down the caller
        logger.exception("failed to load %s for tenant %s", filename, tenant_id)
        return {}


def load_groups(tenant_id: str) -> List[Dict[str, Any]]:
    """The ``groups`` list from a tenant's groups.yaml (empty if absent)."""
    groups = _load(tenant_id, "groups.yaml").get("groups", [])
    return groups if isinstance(groups, list) else []


def load_apps(tenant_id: str) -> List[Dict[str, Any]]:
    """The ``apps`` list from a tenant's apps.yaml (empty if absent)."""
    apps = _load(tenant_id, "apps.yaml").get("apps", [])
    return apps if isinstance(apps, list) else []


def load_profiles(tenant_id: str) -> List[Dict[str, Any]]:
    """The ``profiles`` list from a tenant's profiles.yaml (empty if absent)."""
    profiles = _load(tenant_id, "profiles.yaml").get("profiles", [])
    return profiles if isinstance(profiles, list) else []
