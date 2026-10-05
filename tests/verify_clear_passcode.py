"""ClearPasscode: the UnlockToken read from NanoMDM's store and the command built from it.

Run: PYTHONPATH=. python tests/verify_clear_passcode.py

The device sends the UnlockToken in its TokenUpdate check-in and NanoMDM keeps it in its own database, so
nanomdm_store reads that table directly. The suite is unit level only, since the live send waits on iOS hardware.
"""
import os
import plistlib

os.environ.pop("NANOMDM_DATABASE_URL", None)

from tortoise import Tortoise

from controller.models.tenant import Device, Tenant
from controller.services import nanomdm_store
from controller.services.command_catalog import get_command
from controller.services.mdm_connector import MDMConnector
from tests._verify_harness import make_check

PASS, FAIL = [], []

check = make_check(FAIL, PASS)


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

    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} "
          f"({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
