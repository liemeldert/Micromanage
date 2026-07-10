"""Device group membership.

A group matches a device by (see services.scoping for the shared engine):

  * ``exclude_devices``: serials never in the group (wins over everything);
  * ``include_devices``: cherry-picked serials that are always in the group
    (e.g. a hand-picked test cohort), regardless of conditions;
  * ``conditions``: ALL must match. Conditions support ``negate: true`` and the
    ``group`` type (membership in another group), so "device NOT IN group-x"
    is ``{type: group, operator: in, value: group-x, negate: true}``.

Group-referencing-group is evaluated recursively with memoization and a cycle
guard: a reference cycle (authoring error; the validator rejects it at save
time) resolves as "not a member" and logs, rather than recursing forever.

Runs on the enrollment hot path, the reconcile loop and the device-detail
endpoint -- so evaluation is defensive end to end (see scoping.py for the
regex ReDoS bounds).
"""

import logging
from typing import Any, Dict, List

from controller.models.tenant import Device
from controller.services.scoping import (  # re-exported for callers/tests
    GROUP_REGEX_TIMEOUT,
    _HAS_REGEX_TIMEOUT,
    evaluate_condition,
)

logger = logging.getLogger(__name__)


class GroupManager:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def evaluate_device_groups(
        self, device: Device, groups_config: List[Dict[str, Any]]
    ) -> List[str]:
        """All groups the device belongs to, in groups.yaml order.

        Deliberately un-memoized: memoizing a result computed while a reference
        cycle was in progress would cache a cycle-transient value and make
        membership depend on evaluation order. Group sets are small, and the
        validator rejects cycles at save time, so a plain recursive walk with a
        per-path ``visiting`` guard (mirroring the client) is both correct and
        cheap. A cycle resolves as no-match for every group on the cycle.
        """
        by_name: Dict[str, Dict[str, Any]] = {
            g["name"]: g for g in groups_config if isinstance(g, dict) and g.get("name")
        }

        def in_group(name: str, visiting: frozenset) -> bool:
            if name in visiting:
                logger.warning(
                    f"group cycle detected at '{name}' (tenant {self.tenant_id}); "
                    "treating as no-match"
                )
                return False
            group = by_name.get(name)
            if group is None:
                return False
            nxt = visiting | {name}
            try:
                return self._matches(device, group, lambda n: in_group(n, nxt))
            except Exception:
                logger.exception(f"group '{name}' evaluation failed; treating as no-match")
                return False

        return [name for name in by_name if in_group(name, frozenset())]

    def _matches(self, device: Device, group: Dict[str, Any], resolver) -> bool:
        serial = getattr(device, "serial_number", "") or ""
        if serial and serial in (group.get("exclude_devices") or []):
            return False
        if serial and serial in (group.get("include_devices") or []):
            return True
        conditions = group.get("conditions") or []
        if not conditions:
            # No conditions: only cherry-picked (include_devices) members match.
            return False
        return all(
            evaluate_condition(device, c, group_resolver=resolver) for c in conditions
        )
