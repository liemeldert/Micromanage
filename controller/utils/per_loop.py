"""State kept per running event loop, so a process that builds a new loop never reuses an object bound to a dead one."""
import asyncio
import weakref
from typing import Any, Callable, Dict, Hashable


class PerLoop:
    """One value per running event loop, made by factory on first use."""

    def __init__(self, factory: Callable[[], Any]):
        self._factory = factory
        self._values: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()

    def get(self) -> Any:
        loop = asyncio.get_running_loop()
        value = self._values.get(loop)
        if value is None:
            value = self._factory()
            self._values[loop] = value
        return value

    def pop(self) -> Any:
        """Forget the running loop's value and return it, or None if there was none."""
        return self._values.pop(asyncio.get_running_loop(), None)


class KeyedLocks:
    """An asyncio.Lock per key, per running event loop."""

    def __init__(self):
        self._locks: PerLoop = PerLoop(dict)

    def get(self, key: Hashable) -> asyncio.Lock:
        locks: Dict[Hashable, asyncio.Lock] = self._locks.get()
        lock = locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            locks[key] = lock
        return lock
