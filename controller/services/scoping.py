"""Scope evaluation, gradual rollout logic, and conditions.

Mirrored client-side in webui/lib/config.ts.
"""

import hashlib
import logging
import math
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from packaging import version

logger = logging.getLogger(__name__)

try:
    import regex as _regex_engine

    _HAS_REGEX_TIMEOUT = True
except ImportError:  # pragma: no cover - regex is pinned in requirements
    _regex_engine = re
    _HAS_REGEX_TIMEOUT = False

# Hard ceiling on a single condition's regex match, seconds.
GROUP_REGEX_TIMEOUT = float(os.getenv("GROUP_REGEX_TIMEOUT_SECONDS", "2.0"))

# Advisory ceiling on how many conditions one scope should carry. See the module docstring for why it is not enforced
# here.
MAX_SCOPE_CONDITIONS = 64

# Resolves membership of one named group. GroupManager supplies one (with its cycle guard) so group conditions can
# reference other groups; without it, membership comes from a precomputed device_groups list.
GroupResolver = Callable[[str], bool]

# Coarse device family for the "platform" condition, derived from the model identifier ("MacBookPro18,3", "iPad13,8").
# Mirrored in webui/lib/config.ts.
PLATFORM_CATEGORIES = ["Mac", "iPhone", "iPad", "Apple TV", "Apple Watch", "iPod",
                       "Apple Vision Pro"]


def device_platform_category(model: Optional[str]) -> str:
    """Map a device model identifier to a coarse platform family."""
    m = (model or "").lower().replace(" ", "")
    if m.startswith("iphone"):
        return "iPhone"
    if m.startswith("ipad"):
        return "iPad"
    if m.startswith("ipod"):
        return "iPod"
    if m.startswith("appletv"):
        return "Apple TV"
    if m.startswith("watch"):
        return "Apple Watch"
    if m.startswith("realitydevice"):  # RealityDevice14,1 is Apple Vision Pro
        return "Apple Vision Pro"
    if "mac" in m:  # MacBook*, Macmini, MacPro, iMac, Mac14,2, ...
        return "Mac"
    return "Other"


# ==Conditions==

def evaluate_condition(
    device: Any,
    condition: Dict[str, Any],
    device_groups: Optional[List[str]] = None,
    group_resolver: Optional[GroupResolver] = None,
) -> bool:
    """Evaluate one condition against a device. negate: true inverts."""
    if not isinstance(condition, dict):
        # Hand-edited YAML can put a bare string or null where a mapping belongs.
        logger.warning("condition is not a mapping, treating as no-match: %r", condition)
        return False
    try:
        result = _evaluate_base(device, condition, device_groups or [], group_resolver)
        return (not result) if condition.get("negate") else result
    except Exception:
        # An authoring mistake must never break evaluation (enroll hot path).
        logger.exception("condition evaluation failed: %r", condition)
        return False


def _evaluate_base(
    device: Any,
    condition: Dict[str, Any],
    device_groups: List[str],
    group_resolver: Optional[GroupResolver],
) -> bool:
    ctype = condition.get("type")
    operator = condition.get("operator")
    value = condition.get("value")

    if ctype == "group":
        names = [str(n) for n in (value if isinstance(value, list) else [value]) if n]
        if group_resolver is not None:
            return any(group_resolver(n) for n in names)
        members = set(device_groups)
        return any(n in members for n in names)
    if ctype == "platform":
        want = [str(n) for n in (value if isinstance(value, list) else [value]) if n]
        return device_platform_category(getattr(device, "device_model", "")) in want
    if ctype == "device_model":
        return _string(getattr(device, "device_model", "") or "", operator, value)
    if ctype == "serial_number":
        return _string(getattr(device, "serial_number", "") or "", operator, value)
    if ctype == "hostname":
        return _string(getattr(device, "hostname", "") or "", operator, value)
    if ctype == "os_version":
        return _version(getattr(device, "os_version", "") or "", operator, value)
    if ctype == "enrollment_date":
        return _date(getattr(device, "enrollment_date", None), operator, value)
    if ctype == "tag":
        # The device's imperative tag set (Device.tags), written by ATC, Dispatcher, or by hand.
        want = [str(n) for n in (value if isinstance(value, list) else [value]) if n]
        have = set(getattr(device, "tags", []) or [])
        return any(n in have for n in want)
    if ctype == "enrollment_source":
        # "ade" if the device came in through ABM/ASM, "ota" for user-installed. Set at adoption time from the DEP
        # linkage; missing means "ota".
        want = [str(n) for n in (value if isinstance(value, list) else [value]) if n]
        source = (getattr(device, "attributes", {}) or {}).get("enrollment_source") or "ota"
        return source in want
    return False


def _string(device_value: str, operator: str, condition_value: Any) -> bool:
    """String conditions. A bad regex, a backtracking blowup or a wrong value type is a no-match rather than an
    exception."""
    try:
        if operator == "regex":
            if _HAS_REGEX_TIMEOUT:
                return bool(_regex_engine.match(
                    condition_value, device_value, timeout=GROUP_REGEX_TIMEOUT
                ))
            return bool(re.match(condition_value, device_value))
        elif operator == "in":
            # Exact-value membership. A scalar becomes a one-element list rather than a substring test, so the client
            # mirror (which always wraps in a list) agrees with us.
            values = condition_value if isinstance(condition_value, (list, tuple)) else [condition_value]
            return device_value in values
        elif operator == "equals":
            return device_value == condition_value
        elif operator == "contains":
            # A list matches if any of its substrings is present.
            if isinstance(condition_value, (list, tuple)):
                return any(str(v) in device_value for v in condition_value)
            return condition_value in device_value
    except TimeoutError:
        return False
    except (re.error, _regex_engine.error, TypeError):
        return False
    return False


# Memoized parses of condition version strings, never cleared.
_CONDITION_VERSION_CACHE: Dict[str, Any] = {}

# Sentinel distinguishing "parsed to an invalid version" from "not yet in the cache", since packaging.version.parse
# never itself returns None.
_INVALID_CONDITION_VERSION = object()


def _parse_condition_version(condition_value: Any) -> Any:
    """Parse (and memoize) the constant side of an os_version condition."""
    key = str(condition_value)
    cached = _CONDITION_VERSION_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        parsed = version.parse(key)
    except Exception:
        parsed = _INVALID_CONDITION_VERSION
    _CONDITION_VERSION_CACHE[key] = parsed
    return parsed


def _version(device_version: str, operator: str, condition_value: Any) -> bool:
    # The device's own version varies per call, so it is parsed fresh every time; only the authored comparison value is
    # memoized. One try wraps both parses and the comparison, so any failure reaches the same no-match return.
    try:
        dev = version.parse(device_version)
        cond = _parse_condition_version(condition_value)
        if cond is _INVALID_CONDITION_VERSION:
            return False
        if operator == "gte":
            return dev >= cond
        elif operator == "gt":
            return dev > cond
        elif operator == "lte":
            return dev <= cond
        elif operator == "lt":
            return dev < cond
        elif operator == "equals":
            return dev == cond
    except Exception:
        return False
    return False


def _date(device_date: Optional[datetime], operator: str, condition_value: Any) -> bool:
    try:
        cond = datetime.fromisoformat(str(condition_value))
        if device_date is None:
            return False
        # Normalize tz-awareness so aware/naive comparisons can't raise.
        if device_date.tzinfo is not None and cond.tzinfo is None:
            cond = cond.replace(tzinfo=timezone.utc)
        elif device_date.tzinfo is None and cond.tzinfo is not None:
            cond = cond.replace(tzinfo=None)
        if operator == "after":
            return device_date > cond
        elif operator == "before":
            return device_date < cond
        elif operator == "equals":
            return device_date.date() == cond.date()
    except Exception:
        return False
    return False


# ==Scopes (profiles / app versions)==

def evaluate_scope(
    device: Any,
    device_groups: List[str],
    scope: Dict[str, Any],
) -> bool:
    """Whether a device is inside a scope (groups/conditions/include/exclude)."""
    serial = getattr(device, "serial_number", "") or ""
    exclude = scope.get("exclude_devices") or []
    if serial and serial in exclude:
        return False
    include = scope.get("include_devices") or []
    if serial and serial in include:
        return True
    groups = scope.get("groups") or []
    conditions = scope.get("conditions") or []
    if not groups and not conditions:
        return False
    if groups and not any(g in device_groups for g in groups):
        return False
    if conditions and not all(
        evaluate_condition(device, c, device_groups) for c in conditions
    ):
        return False
    return True


# ==Gradual rollout==

# Iteration backstop for the wave walk (covers years of hourly steps).
_MAX_WAVE_STEPS = 20000


def _parse_start(value: Any) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(str(value))
    except Exception:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def rollout_coverage(rollout: Dict[str, Any], now: Optional[datetime] = None) -> int:
    """Percent of devices (0-100) the rollout currently covers."""
    try:
        percent = int(rollout.get("percent") or 0)
    except (TypeError, ValueError):
        return 100
    if percent <= 0 or percent >= 100:
        return 100
    start = _parse_start(rollout.get("start"))
    if start is None:
        return 100
    now = now or datetime.now(timezone.utc)
    if now < start:
        return 0
    try:
        interval_h = float(rollout.get("interval_hours") or 24)
    except (TypeError, ValueError):
        interval_h = 24.0
    if interval_h <= 0:
        interval_h = 24.0
    skip_weekends = bool(rollout.get("skip_weekends"))

    steps_needed = math.ceil(100 / percent)  # waves until full coverage
    interval = timedelta(hours=interval_h)
    completed = 0
    t = start
    guard = 0
    while completed < steps_needed and guard < _MAX_WAVE_STEPS:
        guard += 1
        nxt = t + interval
        if nxt > now:
            break
        # Window [t, nxt) fully elapsed, so its wave opens at nxt, unless skip_weekends pushes a weekend opening into
        # the next window.
        if not (skip_weekends and nxt.weekday() >= 5):
            completed += 1
        t = nxt
    return min(100, percent * (completed + 1))


def rollout_bucket(key: str) -> int:
    """Stable pseudo-random bucket 0-99 for a (device, item, rollout) key."""
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % 100


def device_in_rollout(
    device: Any,
    rollout: Optional[Dict[str, Any]],
    item_key: str,
    now: Optional[datetime] = None,
) -> bool:
    """Whether this device's wave has opened: True acts now, False holds."""
    if not isinstance(rollout, dict) or not rollout:
        return True
    coverage = rollout_coverage(rollout, now)
    if coverage >= 100:
        return True
    if coverage <= 0:
        return False
    key = f"{getattr(device, 'id', '')}:{item_key}:{rollout.get('start') or ''}"
    return rollout_bucket(key) < coverage
