"""Device group membership. services.scoping is the shared matching engine.

See docs for membership rules, recursive resolution, and cycle handling.
"""

import logging
from typing import Any, Dict, List

from controller.models.tenant import Device
from controller.services.scoping import evaluate_condition

logger = logging.getLogger(__name__)


class GroupManager:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def evaluate_device_groups(
        self, device: Device, groups_config: List[Dict[str, Any]]
    ) -> List[str]:
        """All groups the device belongs to, in groups.yaml order. Memoized within this call only. See docs for cycle handling."""
        by_name: Dict[str, Dict[str, Any]] = {
            g["name"]: g for g in groups_config if isinstance(g, dict) and g.get("name")
        }

        # name -> membership, written only for cycle-free results (see in_group's tainted return value).
        memo: Dict[str, bool] = {}

        def in_group(name: str, visiting: frozenset):
            """Returns (matches, tainted). tainted signals a cycle was cut in this subtree."""
            cached = memo.get(name)
            if cached is not None:
                return cached, False
            if name in visiting:
                logger.warning(
                    f"group cycle detected at '{name}' (tenant {self.tenant_id}); "
                    "treating as no-match"
                )
                return False, True
            group = by_name.get(name)
            if group is None:
                memo[name] = False  # absence is a fact about groups_config, not the path
                return False, False
            nxt = visiting | {name}
            tainted = False

            def resolver(n: str) -> bool:
                nonlocal tainted
                val, was_tainted = in_group(n, nxt)
                if was_tainted:
                    tainted = True
                return val

            try:
                result = self._matches(device, group, resolver)
            except Exception:
                logger.exception(f"group '{name}' evaluation failed; treating as no-match")
                # Not memoized: recompute on every reference rather than assume a transient failure repeats.
                return False, True
            if not tainted:
                memo[name] = result
            return result, tainted

        return [name for name in by_name if in_group(name, frozenset())[0]]

    def _matches(self, device: Device, group: Dict[str, Any], resolver) -> bool:
        serial = getattr(device, "serial_number", "") or ""
        if serial and serial in (group.get("exclude_devices") or []):
            return False
        if serial and serial in (group.get("include_devices") or []):
            return True
        conditions = group.get("conditions") or []
        if not conditions:
            # No conditions: only include_devices members match.
            return False
        return all(
            evaluate_condition(device, c, group_resolver=resolver) for c in conditions
        )
