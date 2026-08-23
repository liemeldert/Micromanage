"""Read-only access to NanoMDM's own database."""

import base64
import logging
import os
from typing import Optional
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
            "Neither NANOMDM_DATABASE_URL nor DATABASE_URL is set, so there is "
            "no DSN to reach NanoMDM's database with. Set DATABASE_URL to this "
            "deployment's Postgres DSN, or NANOMDM_DATABASE_URL if NanoMDM uses "
            "a different server or credentials. See .env.example.")
    parts = urlsplit(base)
    scheme = "postgresql" if parts.scheme.startswith("postgres") else parts.scheme
    return urlunsplit((scheme, parts.netloc, "/nanomdm", "", ""))


async def get_serial_number(enrollment_id: str) -> Optional[str]:
    """The serial NanoMDM recorded for one enrollment, or None. Raises RuntimeError on connection or query failure."""
    import asyncpg

    dsn = _nanomdm_dsn()
    try:
        conn = await asyncpg.connect(dsn)
    except Exception as exc:
        logger.error("nanomdm_store: cannot connect to NanoMDM's database: %s", exc)
        raise RuntimeError("Could not reach NanoMDM's database to read the "
                           "serial number") from exc
    try:
        row = await conn.fetchrow(
            "SELECT serial_number FROM devices WHERE id = $1", enrollment_id)
    except Exception as exc:
        logger.error("nanomdm_store: reading the serial for %s failed: %s",
                     enrollment_id, exc)
        raise RuntimeError("Could not read the serial number from NanoMDM's "
                           "database") from exc
    finally:
        await conn.close()
    if row is None:
        return None
    serial = (row["serial_number"] or "").strip()
    return serial or None


async def get_unlock_token(enrollment_id: str) -> Optional[bytes]:
    """The UnlockToken NanoMDM holds for one enrollment, or None. Raises RuntimeError on connection or query failure."""
    import asyncpg

    dsn = _nanomdm_dsn()
    try:
        conn = await asyncpg.connect(dsn)
    except Exception as exc:
        logger.error("nanomdm_store: cannot connect to NanoMDM's database: %s", exc)
        raise RuntimeError("Could not reach NanoMDM's database to read the "
                           "UnlockToken") from exc
    try:
        row = await conn.fetchrow(
            "SELECT unlock_token FROM devices WHERE id = $1", enrollment_id)
    except Exception as exc:
        logger.error("nanomdm_store: reading the UnlockToken for %s failed: %s",
                     enrollment_id, exc)
        raise RuntimeError("Could not read the UnlockToken from NanoMDM's "
                           "database") from exc
    finally:
        await conn.close()
    if row is None:
        return None
    token = row["unlock_token"]
    return bytes(token) if token else None


async def get_bootstrap_token(enrollment_id: str) -> Optional[bytes]:
    """The bootstrap token NanoMDM holds for one enrollment, or None. Raises RuntimeError on connection or query failure."""
    import asyncpg

    dsn = _nanomdm_dsn()
    try:
        conn = await asyncpg.connect(dsn)
    except Exception as exc:
        logger.error("nanomdm_store: cannot connect to NanoMDM's database: %s", exc)
        raise RuntimeError("Could not reach NanoMDM's database to read the "
                           "bootstrap token") from exc
    try:
        row = await conn.fetchrow(
            "SELECT bootstrap_token_b64 FROM devices WHERE id = $1", enrollment_id)
    except Exception as exc:
        logger.error("nanomdm_store: reading the bootstrap token for %s failed: %s",
                     enrollment_id, exc)
        raise RuntimeError("Could not read the bootstrap token from NanoMDM's "
                           "database") from exc
    finally:
        await conn.close()
    if row is None:
        return None
    raw = row["bootstrap_token_b64"]
    if not raw:
        return None
    try:
        token = base64.b64decode(raw)
    except Exception:
        return None
    return token or None
