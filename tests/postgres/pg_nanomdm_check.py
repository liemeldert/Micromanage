"""Runs nanomdm_store's identity statements against NanoMDM 0.9.0's own schema on a real Postgres.

Needs DATABASE_URL pointing at a Postgres server and PYTHONPATH=. ; it creates and drops a temporary database.
"""
import asyncio
import hashlib
import os
import secrets
import sys
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from tests._verify_harness import make_check, spki_sha256

FAILED = []
check = make_check(FAILED)

SCHEMA = Path(__file__).resolve().parent / "_nanomdm_schema_0_9_0.sql"


def make_cert(cn):
    """(PEM, cert sha256, spki sha256, notAfter) for a self-signed certificate with Subject CN cn."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc).replace(microsecond=0)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + timedelta(days=365)).sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    der = cert.public_bytes(serialization.Encoding.DER)
    return pem, hashlib.sha256(der).hexdigest(), spki_sha256(key), now + timedelta(days=365)


async def nanomdm_refuses(conn, enrollment_id, sha):
    """NanoMDM's check for a new enrollment: a hash already associated with any id is refused unless it is this
    enrollment's own (HasCertHash, IsCertHashAssociated in certauth.go)."""
    anywhere = await conn.fetchval("SELECT COUNT(*) FROM cert_auth_associations WHERE sha256 = $1;", sha)
    own = await conn.fetchval("SELECT COUNT(*) FROM cert_auth_associations WHERE id = $1 AND sha256 = $2;",
                              enrollment_id, sha)
    return anywhere > 0 and own == 0


async def seed(conn):
    await conn.execute("TRUNCATE devices, enrollments, cert_auth_associations CASCADE")
    pem, cert_sha, spki_sha, not_after = make_cert(f"mm {uuid.uuid4()}")
    await conn.execute(
        "INSERT INTO devices (id, identity_cert, serial_number, authenticate, authenticate_at) "
        "VALUES ('U1', $1, 'SER1', 'auth', now()), ('U2', NULL, 'SER2', 'auth', now())", pem)
    await conn.execute(
        "INSERT INTO enrollments (id, device_id, type, topic, push_magic, token_hex, enabled, last_seen_at) "
        "VALUES ('U1', 'U1', 'Device', 'com.apple.mgmt.x', 'magic-1', 'aa11', FALSE, now())")
    hashes = {"A": cert_sha, "B": "b" * 64, "C": "c" * 64, "D": "d" * 64}
    await conn.executemany("INSERT INTO cert_auth_associations (id, sha256) VALUES ($1, $2)",
                           [("U1", hashes["A"]), ("U1", hashes["B"]), ("U1", hashes["C"]), ("U2", hashes["D"])])
    return pem, hashes, spki_sha, not_after


async def run_checks(conn):
    from controller.services import nanomdm_store as store

    _, hashes, spki_sha, not_after = await seed(conn)

    print("1) identity readers")
    identity = await store.get_identity("U1")
    check("get_identity hashes the certificate DER", identity is not None and identity.cert_sha256 == hashes["A"])
    check("...and its SubjectPublicKeyInfo", identity.spki_sha256 == spki_sha)
    check("...and reads the Subject CN and notAfter",
          identity.subject_cn.startswith("mm ") and identity.not_after == not_after)
    check("a device without a certificate reads as None", await store.get_identity("U2") is None)
    check("an unknown id reads as None", await store.get_identity("nope") is None)
    check("list_identities by udid skips the one without a certificate",
          set(await store.list_identities(["U1", "U2"])) == {"U1"})
    check("list_identities with no udids reads every certificate", set(await store.list_identities()) == {"U1"})
    assoc = await store.list_associations("U1")
    check("list_associations returns the udid's hashes",
          {sha for sha, _ in assoc} == {hashes["A"], hashes["B"], hashes["C"]})
    check("...with their created_at", all(isinstance(created, datetime) for _, created in assoc))

    print("2) park")
    check("before parking NanoMDM would refuse B for another enrollment only because U1 holds it",
          await nanomdm_refuses(conn, "U3", hashes["B"]) and not await nanomdm_refuses(conn, "U1", hashes["B"]))
    await store.park_association("U1", hashes["B"].upper())
    rows = await conn.fetch("SELECT id FROM cert_auth_associations WHERE sha256 = $1", hashes["B"])
    check("the association moves to the refused id", [r["id"] for r in rows] == [f"refused:{hashes['B']}"])
    check("U1 itself is now refused that certificate", await nanomdm_refuses(conn, "U1", hashes["B"]))
    check("...and so is every other enrollment", await nanomdm_refuses(conn, "U9", hashes["B"]))
    await store.park_association("U1", hashes["B"])
    check("parking again changes nothing",
          await conn.fetchval("SELECT COUNT(*) FROM cert_auth_associations WHERE sha256 = $1", hashes["B"]) == 1)
    check("parked rows are not listed as a udid",
          "refused:" + hashes["B"] not in await store.list_all_associations())

    print("2b) add_association")
    await store.add_association("U2", hashes["C"].upper())
    check("add_association writes the lowercase hash for the udid",
          {sha for sha, _ in await store.list_associations("U2")} == {hashes["C"], hashes["D"]})
    await store.add_association("U2", hashes["C"])
    check("...and adding it again changes nothing",
          await conn.fetchval("SELECT COUNT(*) FROM cert_auth_associations WHERE id = 'U2' AND sha256 = $1",
                              hashes["C"]) == 1)
    await conn.execute("DELETE FROM cert_auth_associations WHERE id = 'U2' AND sha256 = $1", hashes["C"])

    print("3) prune")
    check("an empty keep set removes nothing", await store.prune_associations("U1", set()) == 0
          and len(await store.list_associations("U1")) == 2)
    removed = await store.prune_associations("U1", {hashes["A"]})
    check("prune removes what is not kept", removed == 1
          and [sha for sha, _ in await store.list_associations("U1")] == [hashes["A"]])
    check("...and leaves other udids alone", [sha for sha, _ in await store.list_associations("U2")] == [hashes["D"]])
    await conn.execute("INSERT INTO cert_auth_associations (id, sha256) VALUES ('U1', $1), ('U2', $2)",
                       "e" * 64, "f" * 64)
    removed = await store.prune_associations_bulk({"U1": {hashes["A"]}, "U2": {hashes["D"], "f" * 64}})
    check("the bulk prune applies each udid's keep set", removed == 1
          and {sha for sha, _ in await store.list_associations("U1")} == {hashes["A"]}
          and {sha for sha, _ in await store.list_associations("U2")} == {hashes["D"], "f" * 64})

    print("4) restore_push")
    check("restore_push writes the token, magic and enabled flag",
          await store.restore_push("U1", "bb22", "magic-2", True))
    row = await conn.fetchrow("SELECT token_hex, push_magic, enabled FROM enrollments WHERE id = 'U1'")
    check("...as given", (row["token_hex"], row["push_magic"], row["enabled"]) == ("bb22", "magic-2", True))
    check("an enrollment that does not exist reports False", not await store.restore_push("U9", "cc", "m", True))

    print("5) aged associations")
    await conn.execute("UPDATE cert_auth_associations SET created_at = now() - interval '10 minutes' "
                       "WHERE id = 'U1' OR id LIKE 'refused:%'")
    aged = await store.list_aged_associations()
    check("only associations older than five minutes are listed", aged == {"U1": {hashes["A"]}}, str(aged))
    check("...and a parked row older than five minutes is left out",
          f"refused:{hashes['B']}" in await conn.fetchval(
              "SELECT array_agg(id) FROM cert_auth_associations WHERE created_at < now() - interval '5 minutes'")
          and not any(key.startswith(store.REFUSED_PREFIX) for key in aged))

    print("6) restore_identity")
    new_pem, _, _, _ = make_cert("mm restored")
    check("restore_identity updates the row", await store.restore_identity("U2", new_pem, "SER2B"))
    row = await conn.fetchrow("SELECT identity_cert, serial_number FROM devices WHERE id = 'U2'")
    check("...writing the certificate and serial", (row["identity_cert"], row["serial_number"]) == (new_pem, "SER2B"))
    check("...and the certificate satisfies the CHECK on identity_cert",
          row["identity_cert"].startswith("-----BEGIN CERTIFICATE-----"))
    check("a missing serial is stored as NULL", await store.restore_identity("U2", new_pem, None)
          and await conn.fetchval("SELECT serial_number FROM devices WHERE id = 'U2'") is None)
    check("an unknown udid reports False", not await store.restore_identity("U9", new_pem, "S"))
    other_pem, _, _, _ = make_cert("mm other")
    check("with expect_pem a row holding another certificate is not written",
          not await store.restore_identity("U2", other_pem, "SER2C", expect_pem=other_pem)
          and await conn.fetchval("SELECT identity_cert FROM devices WHERE id = 'U2'") == new_pem)
    check("...and the row holding the expected one is",
          await store.restore_identity("U2", other_pem, "SER2C", expect_pem=new_pem)
          and await conn.fetchval("SELECT identity_cert FROM devices WHERE id = 'U2'") == other_pem)

    print("6b) bootstrap token")
    import asyncpg

    async def stored():
        row = await conn.fetchrow("SELECT bootstrap_token_b64, bootstrap_token_at FROM devices WHERE id = 'U1'")
        return row["bootstrap_token_b64"], row["bootstrap_token_at"] is not None

    check("a device without a token reads as None", await store.get_bootstrap_token("U1") is None)
    check("...and is not a token holder", await store.list_bootstrap_token_udids(["U1", "U2", "U9"]) == set())
    check("a write that needs bootstrap_token_at unset updates the row",
          await store.restore_bootstrap_token("U1", "dG9rZW4=", only_if_unset=True))
    check("...writing the token and its timestamp", await stored() == ("dG9rZW4=", True))
    check("get_bootstrap_token reads it back", await store.get_bootstrap_token("U1") == "dG9rZW4=")
    check("list_bootstrap_token_udids names the holder only",
          await store.list_bootstrap_token_udids(["U1", "U2", "U9"]) == {"U1"})
    check("once bootstrap_token_at is set the same write updates no row",
          not await store.restore_bootstrap_token("U1", "bmV3", only_if_unset=True)
          and await stored() == ("dG9rZW4=", True))
    check("an unconditional write replaces it", await store.restore_bootstrap_token("U1", "bmV3", only_if_unset=False)
          and await stored() == ("bmV3", True))
    # What StoreAuthenticate does to the row.
    await conn.execute("UPDATE devices SET bootstrap_token_b64 = NULL, bootstrap_token_at = NULL WHERE id = 'U1'")
    check("after an Authenticate the conditional write applies again",
          await store.restore_bootstrap_token("U1", "dG9rZW4=", only_if_unset=True)
          and await stored() == ("dG9rZW4=", True))
    check("an unknown udid reports False", not await store.restore_bootstrap_token("U9", "eA==", only_if_unset=False))
    try:
        await store.restore_bootstrap_token("U1", "", only_if_unset=False)
        refused_empty = False
    except ValueError:
        refused_empty = True
    check("an empty token is refused before any SQL", refused_empty and await stored() == ("dG9rZW4=", True))
    try:
        await conn.execute("UPDATE devices SET bootstrap_token_b64 = '' WHERE id = 'U1'")
        violated = False
    except asyncpg.CheckViolationError:
        violated = True
    check("...which NanoMDM's CHECK constraint would reject", violated)
    check("a clear that needs the token gone leaves a stored one",
          not await store.clear_bootstrap_token("U1", only_if_empty=True) and await stored() == ("dG9rZW4=", True))
    check("an unconditional clear sets both columns NULL",
          await store.clear_bootstrap_token("U1", only_if_empty=False) and await stored() == (None, False))
    await conn.execute("UPDATE devices SET bootstrap_token_at = now() WHERE id = 'U1'")
    check("a clear that needs the token gone resets the timestamp of an empty one",
          await store.clear_bootstrap_token("U1", only_if_empty=True) and await stored() == (None, False))


async def run_cutover(conn):
    print("7) the cutover against this schema")
    from tortoise import Tortoise
    from controller.models.tenant import IdentityCutover, LegacyIdentity
    from controller.services import identity

    _, hashes, _, _ = await seed(conn)
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()
    identity.reset_cutover_cache()
    try:
        check("the cutover runs", await identity.run_cutover() is True)
        rows = await conn.fetch("SELECT id, sha256 FROM cert_auth_associations ORDER BY id, sha256")
        check("U1 is pruned to its identity and U2, without a certificate, keeps everything",
              [(r["id"], r["sha256"]) for r in rows] == [("U1", hashes["A"]), ("U2", hashes["D"])])
        snapshot = set(await LegacyIdentity.all().values_list("udid", "cert_sha256"))
        check("the snapshot holds the remaining pairs", snapshot == {("U1", hashes["A"]), ("U2", hashes["D"])})
        check("the stamp is written", await IdentityCutover.filter(id=1, snapshot_done=True).exists())
    finally:
        await Tortoise.close_connections()


async def main() -> int:
    url = os.environ.get("DATABASE_URL", "")
    if not url.startswith("postgres"):
        print("DATABASE_URL must point at a Postgres database", file=sys.stderr)
        return 2
    import asyncpg

    parts = urlsplit(url)
    dbname = f"nanomdm_check_{secrets.token_hex(4)}"
    target = urlunsplit(("postgresql", parts.netloc, f"/{dbname}", "", ""))
    admin = await asyncpg.connect(urlunsplit(("postgresql", parts.netloc, parts.path, "", "")))
    await admin.execute(f'CREATE DATABASE "{dbname}"')
    os.environ["NANOMDM_DATABASE_URL"] = target
    try:
        conn = await asyncpg.connect(target)
        try:
            await conn.execute(SCHEMA.read_text())
            await run_checks(conn)
            await run_cutover(conn)
        finally:
            await conn.close()
    finally:
        await admin.execute(f'DROP DATABASE IF EXISTS "{dbname}"')
        await admin.close()

    print(f"\nRESULT: {'PASS' if not FAILED else 'FAIL'} ({len(FAILED)} failed)")
    return 1 if FAILED else 0


if __name__ == "__main__":
    try:
        code = asyncio.run(main())
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        code = 1
    sys.exit(code)
