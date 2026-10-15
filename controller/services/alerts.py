"""Device alerts the services open, update and resolve, keyed on the device and a rule id."""

import logging
from typing import Any

from controller.models.tenant import Alert, Device, Tenant
from controller.utils.timeutil import utcnow

logger = logging.getLogger(__name__)


async def raise_or_bump(device: Device, rule_id: str, kind: str, summary: str, detail: dict, *,
                        severity: str = "red") -> None:
    """Open an alert for the device, or merge detail into the one already open for rule_id, counting the repeat under
    detail.count and stamping detail.last_seen_at. Best-effort."""
    try:
        now = utcnow()
        existing = await Alert.filter(device_id=device.id, rule_id=rule_id).exclude(status="resolved").first()
        if existing is not None:
            merged = dict(existing.detail or {})
            merged.update(detail)
            merged["count"] = int(merged.get("count", 1)) + 1
            merged["last_seen_at"] = now.isoformat()
            existing.detail = merged
            existing.summary = summary[:255]
            await existing.save(update_fields=["detail", "summary", "updated_at"])
            return
        tenant = await Tenant.get_or_none(id=device.tenant_id)
        if tenant is None:
            return
        await Alert.create(tenant=tenant, device=device, rule_id=rule_id, severity=severity, status="open",
                           summary=summary[:255], opened_at=now,
                           detail={"kind": kind, "count": 1, "last_seen_at": now.isoformat(), **detail})
    except Exception:
        logger.exception("alerts: raising the %s alert failed for device %s", kind, device.id)


async def resolve(device_id: Any, rule_id: str, reason: str) -> int:
    """Resolve the device's unresolved alerts for rule_id, recording reason under detail.resolved_reason. Best-effort;
    returns how many were resolved."""
    resolved = 0
    try:
        for alert in await Alert.filter(device_id=device_id, rule_id=rule_id).exclude(status="resolved"):
            alert.status = "resolved"
            alert.resolved_at = utcnow()
            alert.detail = {**(alert.detail or {}), "resolved_reason": reason}
            await alert.save(update_fields=["status", "resolved_at", "detail", "updated_at"])
            resolved += 1
    except Exception:
        logger.exception("alerts: resolving the %s alerts failed for device %s", rule_id, device_id)
    return resolved
