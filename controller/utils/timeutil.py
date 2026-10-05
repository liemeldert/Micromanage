"""UTC timestamps. A stored or parsed timestamp without a zone is read as UTC."""
from datetime import datetime, timezone
from typing import Any, Optional


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime) -> datetime:
    """value with UTC attached when it has no zone; an aware value unchanged."""
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def parse_iso_utc(value: Any) -> Optional[datetime]:
    """An ISO 8601 string as an aware datetime, or None for anything that is not one."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return as_utc(parsed)
