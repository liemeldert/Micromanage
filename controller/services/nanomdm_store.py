"""Access to NanoMDM's own database.

 Handles device reads, the identity writes on cert_auth_associations, enrollments and
devices, bootstrap token writes, etc."""

import hashlib
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
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


# Bounds the connect at boot, where the cutover holds the schema lock for every controller process.
_CONNECT_TIMEOUT_SECONDS = 10

# Associations moved here are refused by NanoMDM for every other enrollment id, since it refuses a certificate hash
# already associated with a different id.
REFUSED_PREFIX = "refused:"


@dataclass(frozen=True)
class Identity:
    """The identity certificate NanoMDM holds for an enrollment. Hashes are lowercase hex."""
    cert_sha256: str
    spki_sha256: str
    subject_cn: str
    not_after: datetime
    pem: Optional[str] = field(default=None, compare=False, repr=False)


def spki_sha256(public_key) -> str:
    """The lowercase sha256 hex of a public key's DER SubjectPublicKeyInfo, the form challenge rows and identity
    certificates are compared on."""
    from cryptography.hazmat.primitives import serialization

    return hashlib.sha256(public_key.public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def identity_from_pem(pem: Optional[str]) -> Optional[Identity]:
    """Parse one PEM certificate, or None when it is missing or unreadable."""
    if not pem:
        return None
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID

    try:
        cert = x509.load_pem_x509_certificate(pem.encode("ascii") if isinstance(pem, str) else pem)
        der = cert.public_bytes(serialization.Encoding.DER)
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = names[0].value if names else ""
        return Identity(
            cert_sha256=hashlib.sha256(der).hexdigest(),
            spki_sha256=spki_sha256(cert.public_key()),
            subject_cn=cn if isinstance(cn, str) else cn.decode("utf-8", "replace"),
            not_after=cert.not_valid_after_utc,
            pem=pem if isinstance(pem, str) else pem.decode("ascii"),
        )
    except Exception as exc:
        logger.warning("nanomdm_store: identity certificate could not be parsed: %s", exc)
        return None


async def _connect():
    """One connection to NanoMDM's database. Raises RuntimeError when it cannot be reached."""
    import asyncpg

    try:
        dsn = _nanomdm_dsn()
        return await asyncpg.connect(dsn, timeout=_CONNECT_TIMEOUT_SECONDS)
    except Exception as exc:
        logger.error("nanomdm_store: cannot connect to NanoMDM's database: %s", exc)
        raise RuntimeError("Could not reach NanoMDM's database") from exc


async def _run(what: str, fn):
    """Run fn(conn) on a fresh connection and close it. Query failures become RuntimeError naming what."""
    conn = await _connect()
    try:
        return await fn(conn)
    except Exception as exc:
        logger.error("nanomdm_store: %s failed: %s", what, exc)
        raise RuntimeError(f"NanoMDM database: {what} failed") from exc
    finally:
        await conn.close()


async def _fetch_device_column(enrollment_id: str, column: str, what: str) -> Any:
    """One column of NanoMDM's devices row for an enrollment, or None when there is no row. Raises RuntimeError on
    connection or query failure."""
    row = await _run(what, lambda conn: conn.fetchrow(f"SELECT {column} FROM devices WHERE id = $1", enrollment_id))
    return None if row is None else row[column]


async def get_serial_number(enrollment_id: str) -> Optional[str]:
    """The serial NanoMDM recorded for one enrollment, or None. Raises RuntimeError on connection or query failure."""
    serial = await _fetch_device_column(enrollment_id, "serial_number", "reading the serial number")
    return (serial or "").strip() or None


async def get_unlock_token(enrollment_id: str) -> Optional[bytes]:
    """The UnlockToken NanoMDM holds for one enrollment, or None. Raises RuntimeError on connection or query failure."""
    token = await _fetch_device_column(enrollment_id, "unlock_token", "reading the UnlockToken")
    return bytes(token) if token else None


def _row_count(status: str) -> int:
    """The row count from an asyncpg command tag such as DELETE 3."""
    try:
        return int(str(status).rsplit(" ", 1)[-1])
    except ValueError:
        return 0


async def get_identity(udid: str) -> Optional[Identity]:
    """The identity certificate NanoMDM recorded for udid, or None when there is none or it does not parse. Raises
    RuntimeError on connection or query failure."""
    pem = await _run("reading the identity certificate", lambda conn: conn.fetchval(
        "SELECT identity_cert FROM devices WHERE id = $1", udid))
    return identity_from_pem(pem)


async def list_identities(udids: Optional[Iterable[str]] = None) -> Dict[str, Identity]:
    """Identities by udid in one query; every device with a certificate when udids is None. Unparseable ones are
    left out."""
    async def fetch(conn):
        if udids is None:
            return await conn.fetch("SELECT id, identity_cert FROM devices WHERE identity_cert IS NOT NULL")
        return await conn.fetch("SELECT id, identity_cert FROM devices WHERE id = ANY($1::text[])", list(udids))

    rows = await _run("reading identity certificates", fetch)
    out = {}
    for row in rows:
        identity = identity_from_pem(row["identity_cert"])
        if identity is not None:
            out[row["id"]] = identity
    return out


async def list_associations(udid: str) -> List[Tuple[str, datetime]]:
    """(sha256, created_at) for every certificate associated with udid, oldest first."""
    rows = await _run("reading certificate associations", lambda conn: conn.fetch(
        "SELECT sha256, created_at FROM cert_auth_associations WHERE id = $1 ORDER BY created_at", udid))
    return [(row["sha256"].strip().lower(), row["created_at"]) for row in rows]


def _group(rows) -> Dict[str, Set[str]]:
    """Association rows as hashes by enrollment id."""
    out: Dict[str, Set[str]] = {}
    for row in rows:
        out.setdefault(row["id"], set()).add(row["sha256"].strip().lower())
    return out


async def list_all_associations() -> Dict[str, Set[str]]:
    """Every association by enrollment id, parked ones excluded."""
    return _group(await _run("reading certificate associations", lambda conn: conn.fetch(
        "SELECT id, sha256 FROM cert_auth_associations WHERE id NOT LIKE $1", REFUSED_PREFIX + "%")))


async def list_aged_associations() -> Dict[str, Set[str]]:
    """Associations older than five minutes by enrollment id, parked ones excluded. The age is computed in NanoMDM's
    session, so no clock is compared across databases."""
    return _group(await _run("reading aged certificate associations", lambda conn: conn.fetch(
        "SELECT id, sha256 FROM cert_auth_associations "
        "WHERE created_at < now() - interval '5 minutes' AND id NOT LIKE $1", REFUSED_PREFIX + "%")))


async def add_association(udid: str, sha256: str) -> None:
    """Associate one certificate hash with udid; an association already present is left as it is."""
    await _run("adding a certificate association", lambda conn: conn.execute(
        "INSERT INTO cert_auth_associations (id, sha256) VALUES ($1, $2) ON CONFLICT DO NOTHING", udid,
        sha256.lower()))


async def park_association(udid: str, sha256: str) -> None:
    """Move one association to the id refused:<sha256>, so NanoMDM refuses that certificate for every enrollment."""
    sha256 = sha256.lower()

    async def park(conn):
        async with conn.transaction():
            await conn.execute(
                "INSERT INTO cert_auth_associations (id, sha256) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                REFUSED_PREFIX + sha256, sha256)
            await conn.execute("DELETE FROM cert_auth_associations WHERE id = $1 AND sha256 = $2", udid, sha256)

    await _run("parking a certificate association", park)


async def prune_associations(udid: str, keep: Set[str]) -> int:
    """Delete udid's associations whose hash is not in keep and return how many went. An empty keep deletes
    nothing, since that would leave the enrollment no certificate at all."""
    keep_list = sorted({h.lower() for h in keep if h})
    if not keep_list:
        logger.warning("nanomdm_store: refusing to prune every association for %s", udid)
        return 0
    status = await _run("pruning certificate associations", lambda conn: conn.execute(
        "DELETE FROM cert_auth_associations WHERE id = $1 AND NOT (sha256 = ANY($2::text[]))", udid, keep_list))
    return _row_count(status)


async def prune_associations_bulk(keep: Dict[str, Set[str]]) -> int:
    """prune_associations for many udids in one transaction. A udid with an empty keep set is left alone."""
    pairs = [(udid, h.lower()) for udid, hashes in keep.items() for h in hashes if h]
    udids = sorted({udid for udid, _ in pairs})
    if not udids:
        return 0
    status = await _run("pruning certificate associations", lambda conn: conn.execute(
        "DELETE FROM cert_auth_associations a WHERE a.id = ANY($1::text[]) AND NOT EXISTS ("
        "SELECT 1 FROM unnest($2::text[], $3::text[]) AS k(id, sha256) WHERE k.id = a.id AND k.sha256 = a.sha256)",
        udids, [u for u, _ in pairs], [h for _, h in pairs]))
    return _row_count(status)


async def restore_push(udid: str, token_hex: str, push_magic: str, enabled: bool = True) -> bool:
    """Write the device channel's push token, magic and enabled flag back. Returns whether a row was updated."""
    status = await _run("restoring the push token", lambda conn: conn.execute(
        "UPDATE enrollments SET token_hex = $2, push_magic = $3, enabled = $4 WHERE id = $1",
        udid, token_hex, push_magic, enabled))
    return _row_count(status) > 0


async def restore_identity(udid: str, pem: str, serial_number: Optional[str],
                           expect_pem: Optional[str] = None) -> bool:
    """Write an accepted identity certificate and serial back to udid's devices row, with expect_pem only while
    identity_cert is that text. PEMs are compared as stored, never normalized. Returns whether a row was updated."""
    sql = "UPDATE devices SET identity_cert = $2, serial_number = $3 WHERE id = $1"
    args = [udid, pem, serial_number or None]
    if expect_pem is not None:
        sql += " AND identity_cert = $4"
        args.append(expect_pem)
    status = await _run("restoring the identity certificate", lambda conn: conn.execute(sql, *args))
    return _row_count(status) > 0


async def get_bootstrap_token(udid: str) -> Optional[str]:
    """The base64 bootstrap token NanoMDM holds for udid, or None. Raises RuntimeError on connection or query
    failure."""
    value = await _run("reading the bootstrap token", lambda conn: conn.fetchval(
        "SELECT bootstrap_token_b64 FROM devices WHERE id = $1", udid))
    return value or None


async def list_bootstrap_token_udids(udids: Iterable[str]) -> Set[str]:
    """The udids among udids whose devices row holds a bootstrap token, in one query."""
    rows = await _run("reading bootstrap token holders", lambda conn: conn.fetch(
        "SELECT id FROM devices WHERE id = ANY($1::text[]) AND bootstrap_token_b64 IS NOT NULL", list(udids)))
    return {row["id"] for row in rows}


async def restore_bootstrap_token(udid: str, token_b64: str, only_if_unset: bool) -> bool:
    """Write a base64 bootstrap token to udid's devices row. With only_if_unset the write needs bootstrap_token_at to be
    NULL, which an Authenticate leaves and every SetBootstrapToken replaces. Returns whether a row was updated."""
    if not token_b64:
        raise ValueError("an empty bootstrap token is never written")
    sql = "UPDATE devices SET bootstrap_token_b64 = $2, bootstrap_token_at = CURRENT_TIMESTAMP WHERE id = $1"
    if only_if_unset:
        sql += " AND bootstrap_token_at IS NULL"
    status = await _run("restoring the bootstrap token", lambda conn: conn.execute(sql, udid, token_b64))
    return _row_count(status) > 0


async def clear_bootstrap_token(udid: str, only_if_empty: bool) -> bool:
    """Set udid's bootstrap token and its timestamp to NULL. With only_if_empty the write needs bootstrap_token_b64 to
    be NULL already, so a token stored meanwhile stays. Returns whether a row was updated."""
    sql = "UPDATE devices SET bootstrap_token_b64 = NULL, bootstrap_token_at = NULL WHERE id = $1"
    if only_if_empty:
        sql += " AND bootstrap_token_b64 IS NULL"
    status = await _run("clearing the bootstrap token", lambda conn: conn.execute(sql, udid))
    return _row_count(status) > 0
