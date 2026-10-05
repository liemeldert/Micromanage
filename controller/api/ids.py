"""UUID checks for row ids arriving as strings. Stops wrong ids before they reach uuid columns."""

import uuid
from typing import Any

from fastapi import HTTPException


def is_uuid(value: Any) -> bool:
    """True if value parses as a UUID."""
    try:
        uuid.UUID(str(value))
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def require_uuid(value: Any, detail: str) -> None:
    """404 a path id that is not a UUID. detail must be the 404 message for id-not-found (both answers identical)."""
    if not is_uuid(value):
        raise HTTPException(status_code=404, detail=detail)


def filter_device_id(query, device_id: str):
    """Narrow a list query to one device id, which arrives as a query string. Malformed ids yield empty list."""
    if is_uuid(device_id):
        return query.filter(device_id=device_id)
    return query.filter(id__isnull=True)


async def get_owned_or_404(model, row_id: str, tenant, detail: str, prefetch: tuple[str, ...] = ()):
    """The tenant's row with this id. A malformed, unknown or other tenant's id is the same 404 with detail."""
    require_uuid(row_id, detail)
    query = model.get_or_none(id=row_id, tenant=tenant)
    if prefetch:
        query = query.prefetch_related(*prefetch)
    row = await query
    if not row:
        raise HTTPException(status_code=404, detail=detail)
    return row
