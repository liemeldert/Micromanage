"""Shared entry point for tests/verify_*.py. Runs main and exits cleanly to avoid CPython's threading shutdown hang.

See docs/tests/_verify_harness.md for the threading issue and failure handling details.
"""

import asyncio
import inspect
import os
import sys
import threading
import traceback

from tortoise import Tortoise

# Bound on the close_connections() attempt in _finish(), so a close that hangs does not ride the outer CI timeout.
_CLOSE_TIMEOUT_SECONDS = 5.0

# Grace period for a leftover non-daemon thread before the process is forced to exit.
_THREAD_JOIN_TIMEOUT_SECONDS = 2.0


def run(main):
    """Run one verify_*.py suite's main(), async or sync, and terminate the process.

    Never returns: _finish() ends the process, so control cannot fall through to the interpreter's shutdown path.
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
    """Close any leftover Tortoise connections with a timeout. Safe to call at any time.

    See docs/tests/_verify_harness.md for the shared ContextVar behavior.
    """

    async def _bounded_close():
        await asyncio.wait_for(
            Tortoise.close_connections(), timeout=_CLOSE_TIMEOUT_SECONDS
        )

    try:
        asyncio.run(_bounded_close())
    except BaseException:
        # Never initialized, already closed, or the close failed outright. None of that is actionable here; the thread
        # check in _finish() is the backstop.
        pass


def _finish(code: int, exc: BaseException | None) -> None:
    """Common tail for every exit path: print a real crash if there was one, close the database, then make sure the
    process actually exits."""
    if exc is not None:
        # Flush stdout first: under redirection stdout is block-buffered and stderr is not, so the traceback would
        # otherwise land above the suite's still-buffered PASS/FAIL lines instead of after them.
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
