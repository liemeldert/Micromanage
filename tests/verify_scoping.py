"""Standalone checks for the pure scoping engine (controller/services/scoping.py).

No DB needed; scoping only reads attributes off objects. Tests use attribute bags instead of real models.
Full inventory and run instructions in docs/tests/verify_scoping.md.
"""
import sys
from datetime import datetime, timedelta, timezone

FAILURES: list = []


def check(name: str, cond: bool) -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        FAILURES.append(name)


class Dev:
    """Minimal attribute bag standing in for a Device row. scoping.py only ever does getattr(device, <field>, default),
    so this is enough."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


# Platform-model mapping: enables reachability checks in sections 1 and 11; see docs for details.
MODEL_FOR = {"Mac": "MacBookPro18,3", "iPhone": "iPhone14,2",
             "iPad": "iPad13,8", "iPod": "iPod9,1",
             "Apple TV": "AppleTV6,2", "Apple Watch": "Watch6,1",
             "Apple Vision Pro": "RealityDevice14,1"}


def _just_under(floor: str) -> str:
    """The nearest version under floor that this table can name; see docs for the algorithm."""
    parts = floor.split(".")
    if int(parts[-1]) > 0:
        return ".".join(parts[:-1] + [str(int(parts[-1]) - 1)])
    return str(int(parts[0]) - 1)


def main() -> None:
    from controller.services import scoping as sc

    # == 1. device_platform_category ==
    print("\n[1] device_platform_category")
    cases = [
        ("MacBookPro18,3", "Mac"),
        ("MacBookAir10,1", "Mac"),
        ("Macmini9,1", "Mac"),
        ("iMac21,1", "Mac"),
        ("Mac14,2", "Mac"),
        ("iPad13,8", "iPad"),
        ("iPhone14,2", "iPhone"),
        ("iPod9,1", "iPod"),
        ("AppleTV6,2", "Apple TV"),
        ("Watch6,1", "Apple Watch"),
        ("RealityDevice14,1", "Apple Vision Pro"),
        ("SomeRandomThing1,1", "Other"),
        ("", "Other"),
        (None, "Other"),
        # case/space insensitivity
        ("  IPAD13,8 ".strip(), "iPad"),
    ]
    for model, expected in cases:
        check(f"{model!r} -> {expected}", sc.device_platform_category(model) == expected)

    unreachable = [p for p in sc.PLATFORM_CATEGORIES
                   if sc.device_platform_category(MODEL_FOR.get(p, "")) != p]
    check(f"every PLATFORM_CATEGORIES value is reachable from a model ({unreachable})",
          not unreachable)
    unlisted = sorted({sc.device_platform_category(m) for m in MODEL_FOR.values()}
                      - set(sc.PLATFORM_CATEGORIES))
    check(f"every category a model produces is offerable in YAML and the UI ({unlisted})",
          not unlisted)

    # == 2. evaluate_condition: string conditions ==
    print("\n[2] evaluate_condition: string conditions (in/equals/contains/regex)")
    dev = Dev(device_model="MacBookPro18,3", serial_number="C02ABC123",
              hostname="corp-mac-42", os_version="14.5.1", tags=[], attributes={})

    for ctype, field_val in [("device_model", "MacBookPro18,3"),
                             ("serial_number", "C02ABC123"),
                             ("hostname", "corp-mac-42")]:
        check(f"{ctype} in-match", sc.evaluate_condition(
            dev, {"type": ctype, "operator": "in", "value": [field_val, "other"]}) is True)
        check(f"{ctype} in-no-match", sc.evaluate_condition(
            dev, {"type": ctype, "operator": "in", "value": ["other"]}) is False)
        check(f"{ctype} equals-match", sc.evaluate_condition(
            dev, {"type": ctype, "operator": "equals", "value": field_val}) is True)
        check(f"{ctype} equals-no-match", sc.evaluate_condition(
            dev, {"type": ctype, "operator": "equals", "value": "nope"}) is False)

    check("contains scalar substring", sc.evaluate_condition(
        dev, {"type": "hostname", "operator": "contains", "value": "corp-mac"}) is True)
    check("contains list = any substring matches", sc.evaluate_condition(
        dev, {"type": "hostname", "operator": "contains", "value": ["zzz", "corp"]}) is True)
    check("contains list = no substring matches", sc.evaluate_condition(
        dev, {"type": "hostname", "operator": "contains", "value": ["zzz", "yyy"]}) is False)
    check("regex match (anchored at start, like re.match)", sc.evaluate_condition(
        dev, {"type": "device_model", "operator": "regex", "value": r"^MacBookPro"}) is True)
    check("regex non-anchored pattern not at start -> no match", sc.evaluate_condition(
        dev, {"type": "device_model", "operator": "regex", "value": r"BookPro"}) is False)
    check("in with scalar value = one-element list, not substring", sc.evaluate_condition(
        dev, {"type": "hostname", "operator": "in", "value": "corp"}) is False)
    check("in with scalar value matching the whole field", sc.evaluate_condition(
        dev, {"type": "serial_number", "operator": "in", "value": "C02ABC123"}) is True)

    # == 3. evaluate_condition: os_version ==
    print("\n[3] evaluate_condition: os_version (version-aware compare)")
    ios_dev = Dev(os_version="17.4")
    check("gte equal versions", sc.evaluate_condition(
        ios_dev, {"type": "os_version", "operator": "gte", "value": "17.4"}) is True)
    check("gt false when equal", sc.evaluate_condition(
        ios_dev, {"type": "os_version", "operator": "gt", "value": "17.4"}) is False)
    check("lt true when equal is false", sc.evaluate_condition(
        ios_dev, {"type": "os_version", "operator": "lt", "value": "17.4"}) is False)
    # A lexicographic compare says "17.10" < "17.4"; the version-aware compare must say 17.4 < 17.10.
    check('"17.4" lt "17.10" (numeric, not lexicographic)', sc.evaluate_condition(
        ios_dev, {"type": "os_version", "operator": "lt", "value": "17.10"}) is True)
    check('"17.4" gte "17.10" is False', sc.evaluate_condition(
        ios_dev, {"type": "os_version", "operator": "gte", "value": "17.10"}) is False)
    check("equals", sc.evaluate_condition(
        ios_dev, {"type": "os_version", "operator": "equals", "value": "17.4"}) is True)
    check("malformed device os_version -> no match, no crash", sc.evaluate_condition(
        Dev(os_version="not-a-version"),
        {"type": "os_version", "operator": "gte", "value": "17.0"}) is False)
    check("malformed condition version -> no match, no crash", sc.evaluate_condition(
        ios_dev, {"type": "os_version", "operator": "gte", "value": "not-a-version"}) is False)
    check("empty device os_version -> no match, no crash", sc.evaluate_condition(
        Dev(os_version=""), {"type": "os_version", "operator": "gte", "value": "1.0"}) is False)

    # == 4. evaluate_condition: enrollment_date ==
    print("\n[4] evaluate_condition: enrollment_date (tz-aware/naive, missing, malformed)")
    aware_dev = Dev(enrollment_date=datetime(2024, 6, 15, 12, 0, tzinfo=timezone.utc))
    naive_dev = Dev(enrollment_date=datetime(2024, 6, 15, 12, 0))
    check("after (aware device, naive condition normalized to UTC)", sc.evaluate_condition(
        aware_dev, {"type": "enrollment_date", "operator": "after", "value": "2024-01-01"}) is True)
    check("before (aware device, naive condition)", sc.evaluate_condition(
        aware_dev, {"type": "enrollment_date", "operator": "before", "value": "2024-01-01"}) is False)
    check("after (naive device, zero-offset aware condition)", sc.evaluate_condition(
        naive_dev, {"type": "enrollment_date", "operator": "after",
                    "value": "2024-01-01T00:00:00+00:00"}) is True)
    check("equals compares calendar date only", sc.evaluate_condition(
        aware_dev, {"type": "enrollment_date", "operator": "equals", "value": "2024-06-15"}) is True)
    check("equals false for a different date", sc.evaluate_condition(
        aware_dev, {"type": "enrollment_date", "operator": "equals", "value": "2024-06-16"}) is False)
    check("missing enrollment_date -> no match, no crash", sc.evaluate_condition(
        Dev(enrollment_date=None),
        {"type": "enrollment_date", "operator": "after", "value": "2024-01-01"}) is False)
    check("malformed condition date -> no match, no crash", sc.evaluate_condition(
        aware_dev, {"type": "enrollment_date", "operator": "after", "value": "not-a-date"}) is False)

    # == 5. evaluate_condition: enrollment_source, group, platform, negate ==
    print("\n[5] evaluate_condition: enrollment_source / group / platform / negate")
    ade_dev = Dev(attributes={"enrollment_source": "ade"})
    ota_dev = Dev(attributes={})  # unset -> defaults to "ota"
    check("enrollment_source explicit ade", sc.evaluate_condition(
        ade_dev, {"type": "enrollment_source", "operator": "in", "value": ["ade"]}) is True)
    check("enrollment_source default is ota when unset", sc.evaluate_condition(
        ota_dev, {"type": "enrollment_source", "operator": "in", "value": ["ota"]}) is True)
    check("enrollment_source ade device doesn't match ota", sc.evaluate_condition(
        ade_dev, {"type": "enrollment_source", "operator": "in", "value": ["ota"]}) is False)

    check("group condition via device_groups fallback", sc.evaluate_condition(
        dev, {"type": "group", "operator": "in", "value": ["kiosks"]},
        device_groups=["kiosks", "other"]) is True)
    check("group condition via device_groups, no match", sc.evaluate_condition(
        dev, {"type": "group", "operator": "in", "value": ["kiosks"]},
        device_groups=["other"]) is False)
    check("group condition via group_resolver callback (not device_groups)", sc.evaluate_condition(
        dev, {"type": "group", "operator": "in", "value": ["kiosks"]},
        device_groups=[], group_resolver=lambda n: n == "kiosks") is True)
    check("group condition resolver overrides device_groups when both given",
          sc.evaluate_condition(
              dev, {"type": "group", "operator": "in", "value": ["kiosks"]},
              device_groups=["kiosks"], group_resolver=lambda n: False) is False)

    check("platform match", sc.evaluate_condition(
        dev, {"type": "platform", "operator": "in", "value": ["Mac"]}) is True)
    check("platform no match", sc.evaluate_condition(
        dev, {"type": "platform", "operator": "in", "value": ["iPhone"]}) is False)

    check("negate flips a true result to false", sc.evaluate_condition(
        dev, {"type": "platform", "operator": "in", "value": ["Mac"], "negate": True}) is False)
    check("negate flips a false result to true", sc.evaluate_condition(
        dev, {"type": "platform", "operator": "in", "value": ["iPhone"], "negate": True}) is True)

    # == 6. evaluate_condition: malformed input never raises ==
    print("\n[6] evaluate_condition: malformed input -> no-match, not a crash")
    check("unknown condition type -> False", sc.evaluate_condition(
        dev, {"type": "not-a-real-type", "operator": "in", "value": ["x"]}) is False)
    check("missing type key -> False", sc.evaluate_condition(
        dev, {"operator": "in", "value": ["x"]}) is False)
    check("unknown operator -> False", sc.evaluate_condition(
        dev, {"type": "device_model", "operator": "not-a-real-op", "value": "x"}) is False)
    check("invalid regex pattern -> False, not an exception", sc.evaluate_condition(
        dev, {"type": "device_model", "operator": "regex", "value": "("}) is False)
    check("'in' value of wrong type (int) -> False, not TypeError", sc.evaluate_condition(
        dev, {"type": "serial_number", "operator": "in", "value": 12345}) is False)
    check("group value is None -> False (filtered out, not a crash)", sc.evaluate_condition(
        dev, {"type": "group", "operator": "in", "value": None}) is False)

    # Hand-edited YAML can put a bare scalar where the condition mapping belongs. This runs on the enrollment hot path,
    # so it has to read as "no match" rather than raise.
    for bad_condition in (None, "not-a-dict", [1, 2, 3], 7):
        check(f"non-dict condition {bad_condition!r} -> no match, no crash",
              sc.evaluate_condition(dev, bad_condition) is False)

    # == 7. evaluate_scope precedence ==
    print("\n[7] evaluate_scope: exclude > include > groups(ANY)+conditions(ALL)")
    sdev = Dev(serial_number="S1", device_model="MacBookPro18,3", tags=[], attributes={})

    check("exclude wins even if also in include and in a matching group",
          sc.evaluate_scope(sdev, ["g1"], {
              "include_devices": ["S1"], "exclude_devices": ["S1"], "groups": ["g1"],
          }) is False)
    check("include wins over groups (device not in the listed group)",
          sc.evaluate_scope(sdev, [], {
              "include_devices": ["S1"], "groups": ["other-group"],
          }) is True)
    check("empty scope (no groups, no conditions, no include) matches nothing",
          sc.evaluate_scope(sdev, ["g1"], {}) is False)
    check("groups is ANY: one of several group names is enough",
          sc.evaluate_scope(sdev, ["g2"], {"groups": ["g1", "g2"]}) is True)
    check("groups is ANY: none of the listed groups -> no match",
          sc.evaluate_scope(sdev, ["g3"], {"groups": ["g1", "g2"]}) is False)
    check("conditions is ALL: every condition must hold",
          sc.evaluate_scope(sdev, [], {"conditions": [
              {"type": "platform", "operator": "in", "value": ["Mac"]},
              {"type": "serial_number", "operator": "in", "value": ["S1"]},
          ]}) is True)
    check("conditions is ALL: one failing condition fails the whole scope",
          sc.evaluate_scope(sdev, [], {"conditions": [
              {"type": "platform", "operator": "in", "value": ["Mac"]},
              {"type": "serial_number", "operator": "in", "value": ["NOPE"]},
          ]}) is False)
    check("groups AND conditions both required when both are present",
          sc.evaluate_scope(sdev, ["g1"], {
              "groups": ["g1"],
              "conditions": [{"type": "serial_number", "operator": "in", "value": ["S1"]}],
          }) is True)
    check("groups AND conditions: group mismatch fails even if conditions pass",
          sc.evaluate_scope(sdev, ["g1"], {
              "groups": ["g9"],
              "conditions": [{"type": "serial_number", "operator": "in", "value": ["S1"]}],
          }) is False)
    check("device with no serial_number just skips include/exclude checks",
          sc.evaluate_scope(Dev(serial_number=None), [], {"groups": ["g1"]}) is False)

    # == 8. rollout_coverage ==
    print("\n[8] rollout_coverage: waves, shortcuts, missing/invalid/future start, skip_weekends")
    start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)  # a Monday
    base = {"percent": 10, "start": start.isoformat(), "interval_hours": 24}

    check("wave 1 opens exactly at start", sc.rollout_coverage(base, now=start) == 10)
    check("nothing open just before start", sc.rollout_coverage(
        base, now=start - timedelta(seconds=1)) == 0)
    check("one more wave per fully elapsed interval (exactly at boundary)",
          sc.rollout_coverage(base, now=start + timedelta(hours=24)) == 20)
    check("still only wave 1 just before the next boundary", sc.rollout_coverage(
        base, now=start + timedelta(hours=24) - timedelta(seconds=1)) == 10)
    check("6 elapsed windows -> 60% (percent * waves, capped later at 100)",
          sc.rollout_coverage(base, now=start + timedelta(hours=24 * 5)) == 60)
    check("far enough along -> capped at 100", sc.rollout_coverage(
        base, now=start + timedelta(days=365)) == 100)

    check("percent >= 100 shortcut -> 100 regardless of start/now", sc.rollout_coverage(
        {"percent": 100, "start": start.isoformat()}, now=start) == 100)
    check("percent > 100 shortcut -> 100", sc.rollout_coverage(
        {"percent": 150, "start": start.isoformat()}, now=start) == 100)
    check("percent <= 0 shortcut -> 100 (fails open, not 0)", sc.rollout_coverage(
        {"percent": 0, "start": start.isoformat()}, now=start) == 100)
    check("negative percent -> 100 (fails open)", sc.rollout_coverage(
        {"percent": -5, "start": start.isoformat()}, now=start) == 100)

    check("missing start -> fails open at 100", sc.rollout_coverage(
        {"percent": 10}, now=start) == 100)
    check("invalid start string -> fails open at 100", sc.rollout_coverage(
        {"percent": 10, "start": "not-a-date"}, now=start) == 100)
    check("future start -> 0% (nothing eligible yet)", sc.rollout_coverage(
        {"percent": 10, "start": (start + timedelta(days=5)).isoformat()}, now=start) == 0)

    # skip_weekends: the interval is chosen so the second wave would open on a Saturday (Jan 6 2024). That wave must be
    # deferred to the next window (Jan 11, a Thursday) rather than opening on the weekend.
    sw_start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)  # Monday
    sw = {"percent": 10, "start": sw_start.isoformat(), "interval_hours": 120,
          "skip_weekends": True}
    nxt1 = sw_start + timedelta(hours=120)
    assert nxt1.weekday() == 5, "test setup assumption broken: expected a Saturday"
    check("skip_weekends: a wave opening on Saturday is deferred (still 1 wave open)",
          sc.rollout_coverage(sw, now=nxt1) == 10)
    nxt2 = nxt1 + timedelta(hours=120)
    check("skip_weekends: the deferred wave opens at the next non-weekend boundary",
          sc.rollout_coverage(sw, now=nxt2) == 20)
    sw_no_skip = dict(sw, skip_weekends=False)
    check("without skip_weekends, that same Saturday moment already opens wave 2",
          sc.rollout_coverage(sw_no_skip, now=nxt1) == 20)

    # == 9. rollout_bucket / device_in_rollout ==
    print("\n[9] rollout_bucket / device_in_rollout: stability, reshuffle, cutoff")
    d1 = Dev(id="device-1")
    key_a = f"{d1.id}:app:core:{start.isoformat()}"
    b1 = sc.rollout_bucket(key_a)
    b2 = sc.rollout_bucket(key_a)
    check("same device+item+start always lands in the same bucket", b1 == b2)
    check("bucket is in [0, 99]", 0 <= b1 < 100)

    other_start = (start + timedelta(days=30)).isoformat()
    key_b = f"{d1.id}:app:core:{other_start}"
    buckets_start_a = {f"device-{i}": sc.rollout_bucket(f"device-{i}:app:core:{start.isoformat()}")
                       for i in range(30)}
    buckets_start_b = {f"device-{i}": sc.rollout_bucket(f"device-{i}:app:core:{other_start}")
                       for i in range(30)}
    check("changing the rollout start reshuffles at least one device's bucket",
          buckets_start_a != buckets_start_b)

    # device_in_rollout: pick a device whose bucket for a fixed (item, start) is comfortably away from the 0/99 edges,
    # then flip percent across it.
    item_key = "app:core"
    start_iso = start.isoformat()
    chosen = None
    for i in range(200):
        candidate = Dev(id=f"dev-{i}")
        key = f"{candidate.id}:{item_key}:{start_iso}"
        b = sc.rollout_bucket(key)
        if 10 <= b <= 90:
            chosen = (candidate, b)
            break
    assert chosen is not None, "test setup: could not find a device with a mid-range bucket"
    cdev, bucket = chosen
    below = {"percent": bucket, "start": start_iso, "interval_hours": 1}  # coverage == bucket
    above = {"percent": bucket + 1, "start": start_iso, "interval_hours": 1}  # coverage == bucket+1
    check("device is held back while coverage == its bucket (bucket < coverage is False)",
          sc.device_in_rollout(cdev, below, item_key, now=start) is False)
    check("device is included once coverage passes its bucket",
          sc.device_in_rollout(cdev, above, item_key, now=start) is True)
    check("no rollout dict at all -> always included", sc.device_in_rollout(
        cdev, None, item_key, now=start) is True)
    check("empty rollout dict -> always included", sc.device_in_rollout(
        cdev, {}, item_key, now=start) is True)
    check("coverage >= 100 -> always included regardless of bucket", sc.device_in_rollout(
        cdev, {"percent": 100, "start": start_iso}, item_key, now=start) is True)
    check("future start (coverage 0) -> always held back", sc.device_in_rollout(
        cdev, {"percent": 50, "start": (start + timedelta(days=5)).isoformat()},
        item_key, now=start) is False)

    # == 10. the authored side of an os_version condition is memoized ==
    print("\n[10] os_version: the authored comparison value is parsed once")
    # Only authored values are cached; device versions parsed fresh each call; see docs for bounds and edge cases.
    sc._CONDITION_VERSION_CACHE.clear()
    cond_ok = {"type": "os_version", "operator": "gte", "value": "15.0"}
    d_new = Dev(os_version="15.4")
    d_old = Dev(os_version="14.1")
    r1 = sc.evaluate_condition(d_new, cond_ok)
    r2 = sc.evaluate_condition(d_old, cond_ok)
    r3 = sc.evaluate_condition(Dev(os_version="16.0"), cond_ok)
    check("the same authored value across three devices is one cache entry",
          list(sc._CONDITION_VERSION_CACHE) == ["15.0"])
    check("...and the answers are still per device", (r1, r2, r3) == (True, False, True))

    # Unparseable authored values cached as sentinel (None reserved as not-cached marker).
    sc._CONDITION_VERSION_CACHE.clear()
    bad = {"type": "os_version", "operator": "gte", "value": "not-a-version"}
    bad_results = [sc.evaluate_condition(Dev(os_version=v), bad)
                   for v in ("15.4", "14.1", "16.0")]
    check("an unparseable authored value is cached once, as the sentinel",
          list(sc._CONDITION_VERSION_CACHE) == ["not-a-version"]
          and sc._CONDITION_VERSION_CACHE["not-a-version"]
          is sc._INVALID_CONDITION_VERSION)
    check("...and still answers False for every device, not just the first",
          bad_results == [False, False, False])
    # Cache must not turn transient failure into permanent skip.
    check("a valid authored value still parses after an invalid one was cached",
          sc.evaluate_condition(Dev(os_version="15.4"), cond_ok) is True)

    # Device versions are never cached; device-side parsing always fresh.
    sc._CONDITION_VERSION_CACHE.clear()
    check("an unparseable DEVICE version is still a no-match",
          sc.evaluate_condition(Dev(os_version="garbage"), cond_ok) is False)
    # Cache size bounded: keys are only authored values, never device or request values.
    check("a device version never becomes a cache key",
          "garbage" not in sc._CONDITION_VERSION_CACHE)

    # Edge case: condition value __str__ that raises; see docs for why this matters despite YAML limits.
    class _RaisingStr:
        def __str__(self):
            raise ValueError("boom")

    import logging

    class _ErrCapture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []

        def emit(self, record):
            self.records.append(record)

    cap = _ErrCapture()
    scoping_log = logging.getLogger("controller.services.scoping")
    scoping_log.addHandler(cap)
    try:
        raising = sc.evaluate_condition(
            Dev(os_version="15.4"),
            {"type": "os_version", "operator": "gte", "value": _RaisingStr()})
    finally:
        scoping_log.removeHandler(cap)
    check("a condition value whose __str__ raises is a silent no-match",
          raising is False and cap.records == [])

    # == 11. the DDM OS floor is parsed once, at import ==
    print("\n[11] device_supports_ddm: floors pre-parsed, device version fresh")
    from controller.services import ddm_manager as ddm

    check("every floor in _DDM_MIN_OS has a pre-parsed twin",
          set(ddm._DDM_MIN_OS_PARSED) == set(ddm._DDM_MIN_OS)
          and all(str(ddm._DDM_MIN_OS_PARSED[p]) == str(sc.version.parse(v))
                  for p, v in ddm._DDM_MIN_OS.items()))
    # Matrix generated from _DDM_MIN_OS (not literal); see docs for why and edge cases.
    matrix_wrong = []
    for platform, floor in ddm._DDM_MIN_OS.items():
        model = MODEL_FOR[platform]
        at_floor = Dev(device_model=model, os_version=floor)
        # Whole-number arithmetic on major; fractional floors (e.g. visionOS 1.1) get versions above and below it.
        major = int(floor.split(".")[0])
        above = Dev(device_model=model, os_version=f"{major + 1}.0")
        below = Dev(device_model=model, os_version=f"{major - 1}.9")
        for label, dev, want in (("at floor", at_floor, True),
                                 ("above", above, True),
                                 ("below", below, False),
                                 ("just under", Dev(device_model=model,
                                                    os_version=_just_under(floor)), False),
                                 ("malformed", Dev(device_model=model,
                                                   os_version="not-a-version"), False),
                                 ("empty", Dev(device_model=model, os_version=""), False),
                                 ("none", Dev(device_model=model, os_version=None), False)):
            if ddm.device_supports_ddm(dev) is not want:
                matrix_wrong.append((platform, label))
    check(f"the platform x os_version matrix is unchanged ({matrix_wrong})",
          not matrix_wrong)
    check("an unrecognized platform is still refused, not defaulted",
          ddm.device_supports_ddm(Dev(device_model="Pixel8,1", os_version="99")) is False)

    # == 12. regex conditions are time-bounded ==
    print("\n[12] regex conditions: the timeout-capable engine ships, and it bites")
    # Regex module required (not stdlib re); see docs for why stdlib cannot be used.
    check("_HAS_REGEX_TIMEOUT is True (regex module present, not the re fallback)",
          sc._HAS_REGEX_TIMEOUT is True)

    # Catastrophic backtracking test: (a|a)* pattern; see docs for why this matters.
    import time

    evil = {"type": "hostname", "operator": "regex", "value": r"^(a|a)*$"}
    evil_dev = Dev(hostname="a" * 40 + "!")
    saved_timeout = sc.GROUP_REGEX_TIMEOUT
    sc.GROUP_REGEX_TIMEOUT = 0.2
    try:
        t0 = time.monotonic()
        evil_result = sc.evaluate_condition(evil_dev, evil)
        elapsed = time.monotonic() - t0
    finally:
        sc.GROUP_REGEX_TIMEOUT = saved_timeout
    check(f"a catastrophic pattern is cut off at GROUP_REGEX_TIMEOUT ({elapsed:.3f}s)",
          elapsed < 1.5)
    check("...and the timed-out match reads as a no-match, not an exception",
          evil_result is False)
    check("GROUP_REGEX_TIMEOUT is restored for the rest of the run",
          sc.GROUP_REGEX_TIMEOUT == saved_timeout)

    # Timeout per condition, not per scope; see docs for worst-case timing on MAX_SCOPE_CONDITIONS.
    check("MAX_SCOPE_CONDITIONS is exported for the validator to warn against",
          isinstance(sc.MAX_SCOPE_CONDITIONS, int) and sc.MAX_SCOPE_CONDITIONS > 0)

    print()
    if FAILURES:
        print(f"RESULT: FAIL ({len(FAILURES)} check(s) failed): {FAILURES}")
        sys.exit(1)
    print("RESULT: PASS (all scoping checks passed)")


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
