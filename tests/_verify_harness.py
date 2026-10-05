"""Shared entry point for tests/verify_*.py. Runs main and exits cleanly to avoid CPython's threading shutdown hang."""

import asyncio
import inspect
import logging
import os
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
