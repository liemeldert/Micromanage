"""Imperative tag writes shared by the console endpoint, Dispatcher and ATC."""
from typing import Iterable, List, Optional, Tuple

from controller.models.tenant import Device


def merge_tags(current: List[str], add: Iterable[str] = (), remove: Iterable[str] = ()) -> List[str]:
    """current without remove, then each tag in add that the remainder does not hold, in order."""
    drop = set(remove)
    kept = [t for t in current if t not in drop]
    held = set(kept)
    return kept + [t for t in add if t not in held]


async def write_tags(device: Device, add: Iterable[str] = (),
                     remove: Iterable[str] = ()) -> Optional[Tuple[List[str], List[str], List[str]]]:
    """Apply add and remove to device.tags and save them. Returns (tags, added, removed), or None when the set of tags
    would not change and nothing was written."""
    current = [str(t) for t in (device.tags or [])]
    before = set(current)
    result = merge_tags(current, add, remove)
    after = set(result)
    if after == before:
        return None
    device.tags = result
    await device.save(update_fields=["tags"])
    return result, sorted(after - before), sorted(before - after)
