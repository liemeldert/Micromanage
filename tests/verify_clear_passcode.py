"""ClearPasscode: the UnlockToken read from NanoMDM's store and the command built from it.

Run: PYTHONPATH=. python tests/verify_clear_passcode.py

ClearPasscode requires an UnlockToken. The device sends one in its TokenUpdate check-in and NanoMDM keeps it in its own
database, so nanomdm_store reads that table directly and device_commands passes the raw bytes into the command as plist
data. Covered at unit level: the DSN derivation, the built plist, the catalog entry, the refusal on a Mac and
get_bootstrap_token's None-or-raise handling. The live send waits on iOS hardware.
"""
import base64
import os
import plistlib
import sys

os.environ.pop("NANOMDM_DATABASE_URL", None)

from tortoise import Tortoise

from controller.models.tenant import Device, Tenant
from controller.services import nanomdm_store
from controller.services.command_catalog import get_command
from controller.services.mdm_connector import MDMConnector

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def main():
    print("1) the NanoMDM DSN follows the controller's, database swapped")
    os.environ["DATABASE_URL"] = "postgres://postgres:pw@postgres:5432/mdm_iac?minsize=2&maxsize=8"
    os.environ.pop("NANOMDM_DATABASE_URL", None)
    dsn = nanomdm_store._nanomdm_dsn()
    check("it points at the nanomdm database", dsn.endswith("/nanomdm"))
    check("it keeps the host and credentials", "postgres:pw@postgres:5432" in dsn)
    check("it drops the asyncpg-only pool args the ORM added",
          "minsize" not in dsn and "maxsize" not in dsn)
    check("it uses a scheme asyncpg accepts", dsn.startswith("postgresql://"))

    os.environ["NANOMDM_DATABASE_URL"] = "postgresql://u:p@other:5432/nmdm"
    check("an explicit NANOMDM_DATABASE_URL wins",
          nanomdm_store._nanomdm_dsn() == "postgresql://u:p@other:5432/nmdm")
    os.environ.pop("NANOMDM_DATABASE_URL", None)

    print("\n2) the connector builds ClearPasscode only with a token")
    import asyncio

    async def build_with_token():
        conn = MDMConnector()
        sent = {}

        async def fake_dispatch(udid, plist, command_uuid=None, no_push=False):
            sent["udid"] = udid
            sent["plist"] = plist
            sent["uuid"] = command_uuid
            return {"command_uuid": command_uuid}

        conn._dispatch = fake_dispatch
        token = b"\x01\x02\x03unlock"
        await conn.clear_passcode("udid-1", token)
        await conn.close()
        return sent

    async def build_without_token():
        conn = MDMConnector()
        try:
            await conn.clear_passcode("udid-1", b"")
            return None
        except ValueError as exc:
            return str(exc)
        finally:
            await conn.close()

    sent = asyncio.get_event_loop().run_until_complete(build_with_token())
    parsed = plistlib.loads(sent["plist"])
    check("the request type is ClearPasscode",
          parsed["Command"]["RequestType"] == "ClearPasscode")
    check("the UnlockToken goes out as raw bytes, which plist encodes as data",
          parsed["Command"]["UnlockToken"] == b"\x01\x02\x03unlock")
    check("a CommandUUID was generated", bool(parsed.get("CommandUUID")))

    refusal = asyncio.get_event_loop().run_until_complete(build_without_token())
    check("no token is refused before anything is sent",
          refusal is not None and "UnlockToken" in refusal)

    print("\n3) the catalog entry is iOS-only and destructive")
    from controller.auth import DESTRUCTIVE_COMMANDS
    entry = get_command("clear_passcode")
    check("it exists", entry is not None)
    check("it is scoped to the iOS family", entry["platforms"] == ["iPhone", "iPad", "iPod"])
    check("it is listed as destructive", "clear_passcode" in DESTRUCTIVE_COMMANDS)
    check("it is marked irreversible", entry.get("reversible") is False)
    check("it carries no parameters (the token is read server-side)",
          entry["params"] == [])

    print("\n4) dispatch refuses ClearPasscode on a Mac, before a task exists")

    async def refuse_on_mac():
        await Tortoise.init(db_url="sqlite://:memory:",
                            modules={"models": ["controller.models.tenant"]})
        await Tortoise.generate_schemas()
        tenant = await Tenant.create(id="cp", name="CP", allowed_users=[])
        mac = await Device.create(tenant=tenant, serial_number="MAC1", udid="u-mac",
                                  device_model="MacBookPro18,1", os_version="15",
                                  enrollment_state="enrolled")
        from controller.services.device_commands import (
            CommandError, dispatch_catalog_command,
        )
        try:
            await dispatch_catalog_command(mac, "clear_passcode", {},
                                           user="admin@t", tenant=tenant,
                                           allow_destructive=True)
            return None
        except CommandError as exc:
            return str(exc)
        finally:
            await Tortoise.close_connections()

    reason = asyncio.get_event_loop().run_until_complete(refuse_on_mac())
    check("a Mac is refused with a platform reason",
          reason is not None and "Mac" in reason)

    print("\n5) get_bootstrap_token decodes devices.bootstrap_token_b64, or says None")

    class FakeConn:
        def __init__(self, row):
            self._row = row

        async def fetchrow(self, query, *args):
            return self._row

        async def close(self):
            pass

    class FakeAsyncpg:
        def __init__(self, row=None, connect_error=None):
            self._row = row
            self._connect_error = connect_error

        async def connect(self, dsn):
            if self._connect_error is not None:
                raise self._connect_error
            return FakeConn(self._row)

    def with_fake_asyncpg(fake):
        # nanomdm_store imports asyncpg inside each function, so swapping sys.modules right before the call is enough
        # for the local import to resolve to this fake.
        real = sys.modules.get("asyncpg")
        sys.modules["asyncpg"] = fake
        try:
            return asyncio.get_event_loop().run_until_complete(
                nanomdm_store.get_bootstrap_token("udid-1"))
        finally:
            if real is not None:
                sys.modules["asyncpg"] = real
            else:
                del sys.modules["asyncpg"]

    stored = base64.b64encode(b"\x01\x02\x03bootstrap").decode()
    token = with_fake_asyncpg(
        FakeAsyncpg(row={"bootstrap_token_b64": stored}))
    check("a stored base64 value comes back decoded",
          token == b"\x01\x02\x03bootstrap")

    token = with_fake_asyncpg(
        FakeAsyncpg(row={"bootstrap_token_b64": None}))
    check("a NULL column reads back as None", token is None)

    token = with_fake_asyncpg(
        FakeAsyncpg(row={"bootstrap_token_b64": ""}))
    check("an empty string column reads back as None", token is None)

    token = with_fake_asyncpg(FakeAsyncpg(row=None))
    check("no matching row reads back as None", token is None)

    token = with_fake_asyncpg(
        FakeAsyncpg(row={"bootstrap_token_b64": "not valid base64???"}))
    check("bad base64 from the device reads back as None, not a raise",
          token is None)

    def connection_failure():
        try:
            with_fake_asyncpg(FakeAsyncpg(connect_error=OSError("refused")))
            return None
        except RuntimeError as exc:
            return str(exc)

    error = connection_failure()
    check("an unreachable database raises RuntimeError, not a plain None",
          error is not None and "bootstrap token" in error)

    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} "
          f"({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
