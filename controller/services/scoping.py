"""Unified device-scoping engine.

One place that answers "does this device match?" for every scopeable object --
group conditions, profile scopes and app-version scopes all evaluate through
here (mirrored client-side in webui/lib/config.ts for previews).

A *condition* is ``{type, operator, value, negate?}``. Types: device_model,
serial_number, hostname, os_version, enrollment_date, ``group`` (membership in
another group -- combined with ``negate: true`` this expresses "device NOT IN
group"), ``platform`` (coarse device family) and ``tag`` (an imperative device
label). ``negate`` inverts any condition.

A *scope* is a dict with any of ``groups`` / ``conditions`` /
``include_devices`` / ``exclude_devices`` (profiles and app versions embed
these keys directly). Semantics, in precedence order:

  1. serial in ``exclude_devices``  -> never scoped (exclude always wins)
  2. serial in ``include_devices``  -> scoped (cherry-picked, e.g. test devices)
  3. otherwise: ANY listed group matches AND ALL conditions match. With
     neither groups nor conditions defined, nothing matches (explicit
     include-only scopes are how you cherry-pick).

*Gradual rollout* gates a scoped item by wave: ``rollout = {percent,
interval_hours, skip_weekends?, start}``. Every ``interval_hours`` another
``percent`` of devices become eligible (weekend windows can be skipped; UTC).
Assignment is a stable hash of (device id, item key, rollout start) so a
device never hops between waves, and a new rollout (new start) reshuffles the
order. A device outside the current wave is *held*: the reconciler makes no
change for that (device, item) pair -- it neither installs nor removes.

All evaluation is defensive: malformed input means "no match", never an
exception -- this runs on the enrollment hot path. Regex conditions are
ReDoS-bounded via the ``regex`` module's per-match timeout (checked during
matching, so it interrupts even a GIL-holding match; stdlib ``re`` fallback
has no timeout).
"""

import hashlib
import logging
import math
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import regex as _regex_engine
    _HAS_REGEX_TIMEOUT = True
except ImportError:  # pragma: no cover - regex is pinned in requirements
    _regex_engine = re
    _HAS_REGEX_TIMEOUT = False

# Hard ceiling on a single condition's regex match, seconds.
GROUP_REGEX_TIMEOUT = float(os.getenv("GROUP_REGEX_TIMEOUT_SECONDS", "2.0"))

# A group_resolver answers "is this device in group <name>?" -- supplied by
# GroupManager so group-type conditions can reference other groups (with its
# cycle guard). Absent a resolver, membership is looked up in a precomputed
# device_groups list.
GroupResolver = Callable[[str], bool]

# Coarse device family, for the "platform" condition (premade options so an
# "all Macs" group is one click). Derived from the device model identifier
# (ProductName, e.g. "MacBookPro18,3", "iPad13,8"). Mirrored in
# webui/lib/config.ts (PLATFORM_OPTIONS / devicePlatformCategory).
PLATFORM_CATEGORIES = ["Mac", "iPhone", "iPad", "Apple TV", "Apple Watch", "iPod"]


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
    if "mac" in m:  # MacBook*, Macmini, MacPro, iMac, Mac14,2, ...
        return "Mac"
    return "Other"


# ── Conditions ────────────────────────────────────────────────────────────────

def evaluate_condition(
    device: Any,
    condition: Dict[str, Any],
    device_groups: Optional[List[str]] = None,
    group_resolver: Optional[GroupResolver] = None,
) -> bool:
    """Evaluate one condition against a device. ``negate: true`` inverts."""
    try:
        result = _evaluate_base(device, condition, device_groups or [], group_resolver)
    except Exception:
        # An authoring mistake must never break evaluation (enroll hot path).
        logger.exception("condition evaluation failed: %r", condition)
        result = False
    return (not result) if condition.get("negate") else result


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
        # Membership in the device's imperative tag set (models.Device.tags),
        # written by ATC/Dispatcher and by hand. Operator is ``in`` like
        # ``group``/``platform``; combine with ``negate: true`` for "NOT tagged X".
        want = [str(n) for n in (value if isinstance(value, list) else [value]) if n]
        have = set(getattr(device, "tags", []) or [])
        return any(n in have for n in want)
    if ctype == "enrollment_source":
        # How the device enrolled: "ade" (Automated Device Enrollment via ABM/ASM)
        # or "ota" (user-installed / manual). Set at adoption time from the device's
        # DEP linkage (services.webhook_handler); absent ⇒ treated as "ota". Operator
        # is ``in`` like ``platform``; combine with ``negate: true`` for "NOT ADE".
        want = [str(n) for n in (value if isinstance(value, list) else [value]) if n]
        source = (getattr(device, "attributes", {}) or {}).get("enrollment_source") or "ota"
        return source in want
    return False


def _string(device_value: str, operator: str, condition_value: Any) -> bool:
    """String conditions. Guarded: a malformed regex (re.error), a
    catastrophic-backtracking pattern (TimeoutError) or an unexpected value
    type (TypeError) is a no-match, never an exception."""
    try:
        if operator == "regex":
            if _HAS_REGEX_TIMEOUT:
                return bool(_regex_engine.match(
                    condition_value, device_value, timeout=GROUP_REGEX_TIMEOUT
                ))
            return bool(re.match(condition_value, device_value))
        elif operator == "in":
            # Membership in a set of exact values. A scalar is treated as a
            # one-element list (equality), not a substring test, so the
            # client mirror (which always wraps in a list) agrees.
            values = condition_value if isinstance(condition_value, (list, tuple)) else [condition_value]
            return device_value in values
        elif operator == "equals":
            return device_value == condition_value
        elif operator == "contains":
            # A list value matches if ANY listed substring is present, so an
            # author can match several fragments at once.
            if isinstance(condition_value, (list, tuple)):
                return any(str(v) in device_value for v in condition_value)
            return condition_value in device_value
    except TimeoutError:
        return False
    except (re.error, _regex_engine.error, TypeError):
        return False
    return False


def _version(device_version: str, operator: str, condition_value: Any) -> bool:
    from packaging import version
    try:
        dev = version.parse(device_version)
        cond = version.parse(str(condition_value))
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


# ── Scopes (profiles / app versions) ─────────────────────────────────────────

def evaluate_scope(
    device: Any,
    device_groups: List[str],
    scope: Dict[str, Any],
) -> bool:
    """Is a device inside a scope (groups/conditions/include/exclude)?

    Exclude wins over everything; include wins over groups/conditions; with
    neither groups nor conditions, only included devices match.
    """
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


# ── Gradual rollout ───────────────────────────────────────────────────────────

# Iteration backstop for the wave walk (covers years of hourly steps).
_MAX_WAVE_STEPS = 20000


def _parse_start(value: Any) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(str(value))
    except Exception:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def rollout_coverage(rollout: Dict[str, Any], now: Optional[datetime] = None) -> int:
    """Percent of devices (0-100) the rollout currently covers.

    Wave 1 (the first ``percent``) opens at ``start``; each completed
    ``interval_hours`` window opens another wave at the moment it ends. With
    ``skip_weekends``, waves whose opening moment falls on a Saturday/Sunday
    (UTC) are deferred -- no new devices start updating over the weekend; the
    rollout resumes with the first weekday-ending window.
    A missing/invalid start fails OPEN (100%) so a hand-edited config can't
    silently freeze deployments; a future start means 0%.
    """
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
        # This window [t, nxt) has fully elapsed. Its wave opens at nxt; with
        # skip_weekends a weekend opening moment defers the wave (nothing new
        # starts updating on a Saturday/Sunday, UTC).
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
    """Has this device's wave opened yet? (True = act now, False = hold.)

    Salted by the rollout ``start`` so restarting a rollout reshuffles which
    devices go first, while within one rollout assignment never changes.
    """
    if not isinstance(rollout, dict) or not rollout:
        return True
    coverage = rollout_coverage(rollout, now)
    if coverage >= 100:
        return True
    if coverage <= 0:
        return False
    key = f"{getattr(device, 'id', '')}:{item_key}:{rollout.get('start') or ''}"
    return rollout_bucket(key) < coverage
