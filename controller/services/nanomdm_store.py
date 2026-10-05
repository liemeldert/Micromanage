"""Read-only access to NanoMDM's own database."""

import logging
import os
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit

from controller.models.database import current_database_url

logger = logging.getLogger(__name__)


def _nanomdm_dsn() -> str:
    """The libpq DSN for NanoMDM's database; prefers NANOMDM_DATABASE_URL."""
    explicit = os.getenv("NANOMDM_DATABASE_URL")
    if explicit:
        return explicit
    base = current_database_url()
    if not base:
        raise RuntimeError(
            "Neither NANOMDM_DATABASE_URL nor DATABASE_URL is set, so there is no DSN to reach NanoMDM's database "
            "with. Set DATABASE_URL to this deployment's Postgres DSN, or NANOMDM_DATABASE_URL if NanoMDM uses a "
            "different server or credentials. See .env.example.")
    parts = urlsplit(base)
    scheme = "postgresql" if parts.scheme.startswith("postgres") else parts.scheme
    return urlunsplit((scheme, parts.netloc, "/nanomdm", "", ""))


async def _fetch_device_column(enrollment_id: str, column: str, what: str, log_what: str) -> Any:
    """One column of NanoMDM's devices row for an enrollment, or None when there is no row. Raises RuntimeError on
    connection or query failure."""
    import asyncpg

    dsn = _nanomdm_dsn()
    try:
        conn = await asyncpg.connect(dsn)
    except Exception as exc:
        logger.error("nanomdm_store: cannot connect to NanoMDM's database: %s", exc)
        raise RuntimeError(f"Could not reach NanoMDM's database to read the {what}") from exc
    try:
        row = await conn.fetchrow(f"SELECT {column} FROM devices WHERE id = $1", enrollment_id)
    except Exception as exc:
        logger.error("nanomdm_store: reading the %s for %s failed: %s", log_what, enrollment_id, exc)
        raise RuntimeError(f"Could not read the {what} from NanoMDM's database") from exc
    finally:
        await conn.close()
    return None if row is None else row[column]


async def get_serial_number(enrollment_id: str) -> Optional[str]:
    """The serial NanoMDM recorded for one enrollment, or None. Raises RuntimeError on connection or query failure."""
    serial = await _fetch_device_column(enrollment_id, "serial_number", "serial number", "serial")
    return (serial or "").strip() or None


async def get_unlock_token(enrollment_id: str) -> Optional[bytes]:
    """The UnlockToken NanoMDM holds for one enrollment, or None. Raises RuntimeError on connection or query failure."""
    token = await _fetch_device_column(enrollment_id, "unlock_token", "UnlockToken", "UnlockToken")
    return bytes(token) if token else None
