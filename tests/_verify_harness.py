"""Shared entry point for tests/*/verify_*.py. Runs main and exits cleanly to avoid CPython's threading shutdown
hang."""

import asyncio
import dataclasses
import datetime
import hashlib
import inspect
import logging
import os
import re
import sys
import threading
import traceback

import yaml
from tortoise import Tortoise

# Bound on the close_connections() attempt in _finish(), so a close that hangs does not wait for the outer CI timeout.
_CLOSE_TIMEOUT_SECONDS = 5.0

# Grace period for a leftover non-daemon thread before the process is forced to exit.
_THREAD_JOIN_TIMEOUT_SECONDS = 2.0


def make_check(failed, passed=None):
    """Build a suite's check(label, cond, detail=""), which prints the result and records the label in failed, or in
    passed when it holds."""

    def check(label, cond, detail=""):
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f": {detail}" if detail and not cond else ""))
        if cond:
            if passed is not None:
                passed.append(label)
        else:
            failed.append(label)

    return check


def spki_sha256(private_key):
    """The sha256 hex of the key's SubjectPublicKeyInfo, as challenge rows and identities record it."""
    from controller.services import nanomdm_store

    return nanomdm_store.spki_sha256(private_key.public_key())


def admin_only(fn, param="admin"):
    """Whether the route function's param depends on require_admin."""
    from controller.auth.dependencies import require_admin

    guard = inspect.signature(fn).parameters[param].default
    return getattr(guard, "dependency", None) is require_admin


async def status_of(coro):
    """Run an endpoint coroutine, returning its HTTP status (200 on success)."""
    from fastapi import HTTPException

    try:
        await coro
    except HTTPException as exc:
        return exc.status_code
    return 200


class LogCapture(logging.Handler):
    """Collects the records a logger emits while the handler is attached."""

    def __init__(self, level=logging.NOTSET):
        super().__init__(level)
        self.records = []

    def emit(self, record):
        self.records.append(record)

    @property
    def messages(self):
        return [r.getMessage() for r in self.records]

    def warnings(self):
        return [r for r in self.records if r.levelno >= logging.WARNING]

    def clear(self):
        self.records.clear()


class SqlSpy:
    """Context manager that records the SQL issued on conn into self.seen, reset on entry."""

    def __init__(self, conn):
        self.conn = conn
        self.seen = []

    def __enter__(self):
        conn = self.conn
        self._q, self._qd = conn.execute_query, conn.execute_query_dict

        async def spy_q(sql, values=None):
            self.seen.append(sql)
            return await self._q(sql, values)

        async def spy_qd(sql, values=None):
            self.seen.append(sql)
            return await self._qd(sql, values)

        self.seen.clear()
        conn.execute_query, conn.execute_query_dict = spy_q, spy_qd
        return self

    def __exit__(self, *exc):
        self.conn.execute_query, self.conn.execute_query_dict = self._q, self._qd
        return False

    def statements(self, verb, table):
        return [s for s in self.seen if s.lstrip().upper().startswith(verb) and f'"{table}"' in s]

    def selects(self, table):
        return self.statements("SELECT", table)


def make_tally(counts):
    """Build a function that adds one to counts[table] for each SELECT naming that table."""

    def tally(sql):
        if sql.lstrip().upper().startswith("SELECT"):
            for table in counts:
                if f'"{table}"' in sql:
                    counts[table] += 1

    return tally


def seed_config_dir(base, tenant_id, minimal):
    """Write a tenant's config.yaml plus one YAML file per entry of minimal under base/tenants/<tenant_id>."""
    tdir = base / "tenants" / tenant_id
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "config.yaml").write_text(yaml.safe_dump({
        "tenant": {"id": tenant_id, "name": "Tenant One", "allowed_users": ["admin@t1"]}
    }))
    for name, doc in minimal.items():
        (tdir / f"{name}.yaml").write_text(yaml.safe_dump(doc))
    return tdir


def totp_code_at(secret, t):
    """Generate a TOTP code for the step covering timestamp t, returned with that step."""
    from controller.auth import totp

    step = int(t) // 30
    return totp._hotp(totp._decode_secret(secret), step), step


class IdentityStub:
    """In-memory stand-in for NanoMDM's identity tables; install_identity_stub patches nanomdm_store with it.

    calls records every write as (name, udid, argument). associations maps udid to its hashes, parked ones under
    refused:<sha256>. A name in fail_bootstrap makes that bootstrap token call raise; a udid in missing_rows makes every
    writer return False."""

    _PATCHED = ("get_identity", "list_identities", "list_associations", "list_all_associations",
                "list_aged_associations", "add_association", "park_association", "prune_associations",
                "prune_associations_bulk", "restore_push", "restore_identity", "get_bootstrap_token",
                "restore_bootstrap_token", "clear_bootstrap_token", "list_bootstrap_token_udids",
                "identity_from_pem")

    def __init__(self, overrides=None):
        from controller.services import nanomdm_store

        self.store = nanomdm_store
        self.overrides = dict(overrides or {})
        self.associations = {}
        self.calls = []
        self.by_pem = {}
        self.bootstrap = {}
        self.fail_bootstrap = set()
        self.created_at = datetime.datetime(2020, 1, 1)  # naive, as NanoMDM's TIMESTAMP columns arrive
        self.association_created = {}
        self.missing_rows = set()
        self._seeded = set()
        self._originals = {name: getattr(nanomdm_store, name) for name in self._PATCHED}
        for name in self._PATCHED:
            setattr(nanomdm_store, name, getattr(self, name))

    def uninstall(self):
        for name, fn in self._originals.items():
            setattr(self.store, name, fn)

    @property
    def parks(self):
        return [c for c in self.calls if c[0] == "park"]

    @property
    def prunes(self):
        return [c for c in self.calls if c[0] == "prune"]

    @property
    def restores(self):
        return [c for c in self.calls if c[0] == "restore_push"]

    @property
    def identity_restores(self):
        return [c for c in self.calls if c[0] == "restore_identity"]

    @property
    def bootstrap_restores(self):
        return [c for c in self.calls if c[0] == "restore_bootstrap_token"]

    @staticmethod
    def pem_for(identity):
        return f"-----BEGIN CERTIFICATE-----\nstub {identity.cert_sha256}\n-----END CERTIFICATE-----\n"

    @staticmethod
    def legacy_identity(udid, tenant_id="stub"):
        """The default identity for udid: a legacy Subject CN and hashes derived from the udid."""
        from controller.services.nanomdm_store import Identity

        return Identity(
            cert_sha256=hashlib.sha256(f"legacy-cert:{udid}".encode()).hexdigest(),
            spki_sha256=hashlib.sha256(f"legacy-spki:{udid}".encode()).hexdigest(),
            subject_cn=f"{tenant_id} MDM Device {hashlib.md5(udid.encode()).hexdigest()}",
            not_after=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365),
        )

    def set_identity(self, udid, identity):
        """Replace udid's identity (None reads as unreadable) and make it udid's only association."""
        self.overrides[udid] = identity
        self.associations[udid] = {identity.cert_sha256} if identity is not None else set()
        if identity is not None:
            self.association_created[(udid, identity.cert_sha256)] = self.created_at

    async def add_association(self, udid, sha256, age_seconds=0):
        """Associate sha256 with udid, created age_seconds ago by NanoMDM's clock."""
        self.calls.append(("add_association", udid, sha256))
        self.associations.setdefault(udid, set()).add(sha256)
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        self.association_created[(udid, sha256)] = now - datetime.timedelta(seconds=age_seconds)

    def _created(self, udid, sha256):
        return self.association_created.get((udid, sha256), self.created_at)

    def _identity(self, udid):
        if udid in self.overrides:
            return self.overrides[udid], False
        return self.legacy_identity(udid), True

    async def _seed(self, udid):
        """First touch of udid: its association, and for a default identity its snapshot row."""
        if udid in self._seeded:
            return
        self._seeded.add(udid)
        from controller.models.tenant import LegacyIdentity

        identity, default = self._identity(udid)
        if identity is not None and udid not in self.associations:
            self.associations[udid] = {identity.cert_sha256}
            self.association_created[(udid, identity.cert_sha256)] = self.created_at
        if default:
            await LegacyIdentity.get_or_create(udid=udid, cert_sha256=identity.cert_sha256)

    async def get_identity(self, udid):
        await self._seed(udid)
        identity, default = self._identity(udid)
        if default:
            from controller.models.tenant import Device
            device = await Device.get_or_none(udid=udid)
            if device is not None:
                identity = self.legacy_identity(udid, device.tenant_id)
        if identity is not None and identity.pem is None:
            identity = dataclasses.replace(identity, pem=self.pem_for(identity))
        if identity is not None:
            self.by_pem[identity.pem] = identity
        return identity

    async def list_identities(self, udids=None):
        targets = list(udids) if udids is not None else sorted(set(self.associations) | set(self.overrides))
        out = {}
        for udid in targets:
            if udid.startswith("refused:"):
                continue
            identity = await self.get_identity(udid)
            if identity is not None:
                out[udid] = identity
        return out

    async def list_associations(self, udid):
        await self._seed(udid)
        held = [(self._created(udid, sha), sha) for sha in self.associations.get(udid, set())]
        return [(sha, created) for created, sha in sorted(held)]

    async def list_all_associations(self):
        return {udid: set(h) for udid, h in self.associations.items() if h and not udid.startswith("refused:")}

    async def list_aged_associations(self):
        cutoff = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(minutes=5)
        aged = {udid: {h for h in hashes if self._created(udid, h) < cutoff}
                for udid, hashes in (await self.list_all_associations()).items()}
        return {udid: hashes for udid, hashes in aged.items() if hashes}

    async def park_association(self, udid, sha256):
        self.calls.append(("park", udid, sha256))
        self.associations.setdefault(f"refused:{sha256}", set()).add(sha256)
        self.associations.get(udid, set()).discard(sha256)

    async def prune_associations(self, udid, keep):
        self.calls.append(("prune", udid, set(keep)))
        keep = {h for h in keep if h}
        if not keep:
            return 0
        before = self.associations.get(udid, set())
        self.associations[udid] = before & keep
        return len(before - keep)

    async def prune_associations_bulk(self, keep):
        removed = 0
        for udid, hashes in keep.items():
            removed += await self.prune_associations(udid, hashes)
        return removed

    async def restore_push(self, udid, token_hex, push_magic, enabled=True):
        self.calls.append(("restore_push", udid, (token_hex, push_magic, enabled)))
        return udid not in self.missing_rows

    def identity_from_pem(self, pem):
        if pem in self.by_pem:
            return self.by_pem[pem]
        match = re.search(r"\nstub (\S+)\n", pem or "")
        if match is None:
            return self._originals["identity_from_pem"](pem)
        from controller.services.nanomdm_store import Identity

        return Identity(cert_sha256=match.group(1), spki_sha256="0" * 64, subject_cn="stub",
                        not_after=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365), pem=pem)

    async def restore_identity(self, udid, pem, serial_number, expect_pem=None):
        self.calls.append(("restore_identity", udid, (pem, serial_number, expect_pem)))
        if udid in self.missing_rows:
            return False
        if expect_pem is not None:
            current = self._identity(udid)[0]
            if current is None or (current.pem or self.pem_for(current)) != expect_pem:
                return False
        identity = self.identity_from_pem(pem)
        if identity is not None:
            known = [i for i in (*self.by_pem.values(), *self.overrides.values())
                     if i is not None and i.cert_sha256 == identity.cert_sha256]
            if known:
                identity = dataclasses.replace(known[0], pem=pem)
            self.overrides[udid] = identity
        return True

    def _bootstrap_call(self, name, op, udid, argument=None):
        self.calls.append((name, udid, argument))
        if op in self.fail_bootstrap:
            raise RuntimeError(f"NanoMDM database: {name} failed")

    async def get_bootstrap_token(self, udid):
        self._bootstrap_call("get_bootstrap_token", "get", udid)
        return self.bootstrap.get(udid, (None, False))[0]

    async def list_bootstrap_token_udids(self, udids):
        if "list" in self.fail_bootstrap:
            raise RuntimeError("NanoMDM database: reading bootstrap token holders failed")
        return {udid for udid in udids if self.bootstrap.get(udid, (None, False))[0]}

    async def restore_bootstrap_token(self, udid, token_b64, only_if_unset):
        self._bootstrap_call("restore_bootstrap_token", "restore", udid, (token_b64, only_if_unset))
        if not token_b64:
            raise ValueError("an empty bootstrap token is never written")
        if udid in self.missing_rows or (only_if_unset and self.bootstrap.get(udid, (None, False))[1]):
            return False
        self.bootstrap[udid] = (token_b64, True)
        return True

    async def clear_bootstrap_token(self, udid, only_if_empty):
        self._bootstrap_call("clear_bootstrap_token", "clear", udid, only_if_empty)
        if udid in self.missing_rows or (only_if_empty and self.bootstrap.get(udid, (None, False))[0] is not None):
            return False
        self.bootstrap[udid] = (None, False)
        return True


def install_identity_stub(overrides=None):
    """Replace nanomdm_store's identity readers and writers with an in-memory NanoMDM and return the recorder.

    overrides maps a udid to an Identity, or to None for an unreadable one. The cutover reads as done."""
    from controller.services import identity

    stub = IdentityStub(overrides)
    for udid, value in stub.overrides.items():
        if value is not None:
            stub.associations[udid] = {value.cert_sha256}
    identity.set_cutover_cache(True)
    return stub


def run(main):
    """Run one verify_*.py suite's main(), async or sync, and terminate the process.

    Never returns; _finish() ends the process, so control cannot fall through to the interpreter's shutdown path.
    """
    exc = None
    code = 0
    try:
        if inspect.iscoroutinefunction(main):
            result = asyncio.run(main())
        else:
            result = main()
        code = _code_from_return(result)
    except SystemExit as e:
        code = _code_from_systemexit(e)
    except BaseException as e:  # noqa: BLE001 - nothing may escape this frame
        exc = e
        code = 1
    _finish(code, exc)


def _code_from_return(result) -> int:
    """A suite's main() returns an explicit 0 or 1, or nothing at all, which is how most of them report success."""
    if isinstance(result, bool):
        return 1 if result else 0
    if isinstance(result, int):
        return result
    return 1 if result else 0


def _code_from_systemexit(exc: SystemExit) -> int:
    """Mirrors the interpreter's own SystemExit handling: None means success, an int is used as is, and anything else is
    printed to stderr and treated as failure."""
    code = exc.code
    if code is None:
        return 0
    if isinstance(code, bool):
        return 1 if code else 0
    if isinstance(code, int):
        return code
    print(code, file=sys.stderr)
    return 1


def _close_tortoise_best_effort() -> None:
    """Close any leftover Tortoise connections with a timeout. Safe to call at any time."""

    async def _bounded_close():
        await asyncio.wait_for(
            Tortoise.close_connections(), timeout=_CLOSE_TIMEOUT_SECONDS
        )

    try:
        asyncio.run(_bounded_close())
    except BaseException:
        # Never initialized, already closed, or the close failed outright. None of that is actionable here;
        # _finish() still checks for leftover threads.
        pass


def _finish(code: int, exc: BaseException | None) -> None:
    """Common tail for every exit path: print a real crash if there was one, close the database, then make sure the
    process actually exits."""
    if exc is not None:
        # Flush stdout first. Under redirection stdout is block-buffered and stderr is not, so the traceback would
        # otherwise appear above the suite's still-buffered PASS/FAIL lines instead of after them.
        sys.stdout.flush()
        traceback.print_exception(type(exc), exc, exc.__traceback__)

    _close_tortoise_best_effort()

    sys.stdout.flush()
    sys.stderr.flush()

    leftover = [
        t
        for t in threading.enumerate()
        if t is not threading.main_thread() and not t.daemon and t.is_alive()
    ]
    for t in leftover:
        t.join(timeout=_THREAD_JOIN_TIMEOUT_SECONDS)
    leftover = [t for t in leftover if t.is_alive()]

    if leftover:
        sys.stdout.flush()
        sys.stderr.flush()
        # A non-daemon thread survived the grace join. CPython's threading._shutdown() would join it with no timeout and
        # never exit, so os._exit() skips that join, along with atexit handlers and any pending finally blocks.
        os._exit(code)

    sys.exit(code)
