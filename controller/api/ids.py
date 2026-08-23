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
