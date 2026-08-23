"""Standalone sqlite E2E check for device tags.

Run (from repo root, with the project venv):

    PYTHONPATH=. ./.venv/bin/python tests/verify_tags.py

No docker or Postgres needed: in-memory sqlite through Tortoise, with generate_schemas() for the full column set. Covers
the tag scope condition, the tags-to-groups recompute chain, and the tags.yaml validator with its unknown-tag warning.
"""
import sys
import tempfile
from pathlib import Path

import yaml
from tortoise import Tortoise

FAILURES: list = []


def check(name: str, cond: bool) -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        FAILURES.append(name)


async def main() -> None:
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    from controller.models.tenant import Tenant, Device
    from controller.services import scoping
    from controller.services.group_manager import GroupManager
    from controller.utils.yaml_validator import YAMLValidator

    tenant = await Tenant.create(id="default", name="Default")
    dev = await Device.create(
        tenant=tenant, serial_number="KIOSK01", device_model="iPad13,8",
        os_version="17.4", tags=["kiosk", "lobby"],
    )
    plain = await Device.create(
        tenant=tenant, serial_number="LAP01", device_model="MacBookPro18,1",
        os_version="14.5", tags=[],
    )

    print("\n[1] tags field persists")
    reloaded = await Device.get(id=dev.id)
    check("tags round-trip via sqlite", reloaded.tags == ["kiosk", "lobby"])
    check("default empty tags", plain.tags == [])

    print("\n[2] tag scope condition")
    tag_cond = {"type": "tag", "operator": "in", "value": ["kiosk"]}
    check("tagged device matches", scoping.evaluate_condition(dev, tag_cond) is True)
    check("untagged device does not match", scoping.evaluate_condition(plain, tag_cond) is False)
    check("multi-value OR match", scoping.evaluate_condition(
        dev, {"type": "tag", "operator": "in", "value": ["missing", "lobby"]}) is True)
    check("negate = NOT tagged (untagged -> True)", scoping.evaluate_condition(
        plain, {"type": "tag", "operator": "in", "value": ["kiosk"], "negate": True}) is True)
    check("negate = NOT tagged (tagged -> False)", scoping.evaluate_condition(
        dev, {"type": "tag", "operator": "in", "value": ["kiosk"], "negate": True}) is False)
    # Malformed input must be a no-match, never a crash.
    check("malformed value -> no crash/no match", scoping.evaluate_condition(
        dev, {"type": "tag", "operator": "in", "value": {"bad": 1}}) is False)
    check("scalar value works", scoping.evaluate_condition(
        dev, {"type": "tag", "operator": "in", "value": "kiosk"}) is True)

    print("\n[3] tag drives group membership (evaluate_device_groups)")
    groups_config = [
        {"name": "kiosks", "conditions": [
            {"type": "tag", "operator": "in", "value": ["kiosk"]}]},
        {"name": "laptops", "conditions": [
            {"type": "platform", "operator": "in", "value": ["Mac"]}]},
    ]
    gm = GroupManager(tenant.id)
    check("tagged device joins tag group", "kiosks" in gm.evaluate_device_groups(dev, groups_config))
    check("untagged device excluded from tag group",
          "kiosks" not in gm.evaluate_device_groups(plain, groups_config))
    check("mac joins platform group", "laptops" in gm.evaluate_device_groups(plain, groups_config))

    print("\n[4] evaluate_scope with a tag condition")
    scope = {"conditions": [{"type": "tag", "operator": "in", "value": ["lobby"]}]}
    check("scope matches tagged", scoping.evaluate_scope(dev, [], scope) is True)
    check("scope excludes untagged", scoping.evaluate_scope(plain, [], scope) is False)

    print("\n[5] validator: tag condition + tags.yaml registry + unknown-tag warning")
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "config.yaml").write_text(yaml.safe_dump(
            {"tenant": {"id": "default", "name": "Default", "allowed_users": ["a@b.c"]}}))
        (tdp / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
        (tdp / "profiles.yaml").write_text(yaml.safe_dump({"profiles": []}))
        # A group using a tag condition, referencing one known + one unknown tag.
        (tdp / "groups.yaml").write_text(yaml.safe_dump({"groups": [
            {"name": "kiosks", "conditions": [
                {"type": "tag", "operator": "in", "value": ["kiosk"]}]},
            {"name": "typo-group", "conditions": [
                {"type": "tag", "operator": "in", "value": ["kiosl"]}]},
        ]}))
        (tdp / "tags.yaml").write_text(yaml.safe_dump({"tags": [
            {"name": "kiosk", "label": "Kiosk", "color": "blue"},
            {"name": "lobby"},
        ]}))
        valid, errors, warnings = YAMLValidator(tdp).validate_all()
        check("config with tag conditions is valid", valid is True)
        check("no errors", errors == [])
        unknown_warn = [w for w in warnings if "kiosl" in w and "not defined" in w]
        check("unknown tag 'kiosl' -> warning", len(unknown_warn) == 1)
        known_warn = [w for w in warnings if "'kiosk'" in w and "not defined" in w]
        check("known tag 'kiosk' -> no warning", len(known_warn) == 0)

    print("\n[6] validator: invalid tag operator rejected; free-form ok when no registry")
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "config.yaml").write_text(yaml.safe_dump(
            {"tenant": {"id": "default", "name": "Default", "allowed_users": ["a@b.c"]}}))
        (tdp / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
        (tdp / "profiles.yaml").write_text(yaml.safe_dump({"profiles": []}))
        # No tags.yaml -> free-form: a tag ref must NOT warn.
        (tdp / "groups.yaml").write_text(yaml.safe_dump({"groups": [
            {"name": "kiosks", "conditions": [
                {"type": "tag", "operator": "in", "value": ["anything"]}]},
        ]}))
        valid, errors, warnings = YAMLValidator(tdp).validate_all()
        check("free-form tag valid (no registry)", valid is True)
        check("no unknown-tag warning without a registry",
              not any("not defined in" in w for w in warnings))
        # Bad operator on a tag condition -> error.
        (tdp / "groups.yaml").write_text(yaml.safe_dump({"groups": [
            {"name": "bad", "conditions": [
                {"type": "tag", "operator": "equals", "value": ["x"]}]},
        ]}))
        valid2, errors2, _ = YAMLValidator(tdp).validate_all()
        check("invalid tag operator rejected", valid2 is False and len(errors2) >= 1)

    print("\n[7] evaluate_device_groups memoizes within one call")
    # Without the memo, a group referenced by N others is resolved once per referencer, and a leaf condition can cost
    # the regex module's 2 second worst case. The memo is a local dict, fresh per call. Cycle-guarded results stay out
    # of it, so every graph below is compared against a memo-free walk rather than hand-written expectations.
    import logging

    import controller.services.group_manager as gm_mod

    def naive_groups(manager, device_, groups_cfg):
        """Reference walk: per-path cycle guard, no memo at all."""
        by_name = {g["name"]: g for g in groups_cfg if g.get("name")}

        def in_group(name, visiting):
            if name in visiting:
                return False
            group = by_name.get(name)
            if group is None:
                return False
            nxt = visiting | {name}
            try:
                return manager._matches(device_, group, lambda n: in_group(n, nxt))
            except Exception:
                return False

        return [name for name in by_name if in_group(name, frozenset())]

    def counted(fn, *args):
        """Run fn, returning (result, evaluate_condition call count)."""
        calls = {"n": 0}
        real = gm_mod.evaluate_condition

        def spy(*a, **kw):
            calls["n"] += 1
            return real(*a, **kw)

        gm_mod.evaluate_condition = spy
        try:
            return fn(*args), calls["n"]
        finally:
            gm_mod.evaluate_condition = real

    def ref(name, negate=False):
        cond = {"type": "group", "operator": "in", "value": name}
        if negate:
            cond["negate"] = True
        return cond

    # Fan-in plus a chain: one leaf under ten middles under one top, so the leaf is referenced eleven times.
    fan_in = [{"name": "leaf", "conditions": [
        {"type": "platform", "operator": "in", "value": ["Mac"]}]}]
    fan_in += [{"name": f"mid-{i}", "conditions": [ref("leaf")]} for i in range(10)]
    fan_in.append({"name": "top", "conditions": [ref(f"mid-{i}") for i in range(10)]})

    memo_groups, memo_calls = counted(gm.evaluate_device_groups, plain, fan_in)
    naive_result, naive_calls = counted(naive_groups, gm, plain, fan_in)
    check(f"fan-in membership is unchanged from a naive re-resolution "
          f"({memo_groups})", memo_groups == naive_result
          and memo_groups == ["leaf"] + [f"mid-{i}" for i in range(10)] + ["top"])
    check(f"...at strictly fewer condition evaluations "
          f"(memoized {memo_calls}, naive {naive_calls})",
          memo_calls < naive_calls)

    class _WarnCapture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.messages = []

        def emit(self, record):
            self.messages.append(record.getMessage())

    group_log = logging.getLogger("controller.services.group_manager")

    def with_warnings(fn, *args):
        cap = _WarnCapture()
        group_log.addHandler(cap)
        try:
            return fn(*args), cap.messages
        finally:
            group_log.removeHandler(cap)

    # A two-group ring. Both members resolve to no-match and the guard says so.
    ring = [{"name": "ring-a", "conditions": [ref("ring-b")]},
            {"name": "ring-b", "conditions": [ref("ring-a")]}]
    (ring_groups, ring_warnings) = with_warnings(
        gm.evaluate_device_groups, plain, ring)
    check("a two-group cycle resolves to no-match for both members",
          ring_groups == [] == naive_groups(gm, plain, ring))
    check("...and the cycle guard logs it",
          any("group cycle detected" in m for m in ring_warnings))

    # The path-dependent ring, and the reason a cycle-tainted result must never reach the memo. Either entry point cuts
    # the ring somewhere different and both members still come out True, which a name-keyed memo cannot hold.
    neg_ring = [{"name": "neg-a", "conditions": [ref("neg-b", negate=True)]},
                {"name": "neg-b", "conditions": [ref("neg-a")]}]
    neg_groups = gm.evaluate_device_groups(plain, neg_ring)
    check(f"a negated ring agrees with the naive walk in both entry orders "
          f"({neg_groups})",
          neg_groups == naive_groups(gm, plain, neg_ring)
          and neg_groups == ["neg-a", "neg-b"])

    # The memo is per call. Same graph, two devices, opposite answers.
    check("the memo does not leak between devices",
          gm.evaluate_device_groups(plain, fan_in) != []
          and gm.evaluate_device_groups(dev, fan_in) == []
          and gm.evaluate_device_groups(plain, fan_in) != [])

    # Self-loops, both polarities. The guard substitutes no-match for the recursive reference, so the plain one cannot
    # match and the negated one necessarily does.
    selfies = [{"name": "self-plain", "conditions": [ref("self-plain")]},
               {"name": "self-neg", "conditions": [ref("self-neg", negate=True)]}]
    self_groups = gm.evaluate_device_groups(plain, selfies)
    check("a self-loop is no-match, its negation is a match",
          self_groups == ["self-neg"] == naive_groups(gm, plain, selfies))

    # One acyclic group referenced from inside a ring and from outside it in the same call. The reference from outside
    # still has to get the right answer with nothing inside the ring cached.
    mixed = [
        {"name": "shared", "conditions": [
            {"type": "platform", "operator": "in", "value": ["Mac"]}]},
        {"name": "mix-a", "conditions": [ref("mix-b"), ref("shared")]},
        {"name": "mix-b", "conditions": [ref("mix-a")]},
        {"name": "plain-user", "conditions": [ref("shared")]},
    ]
    mixed_groups = gm.evaluate_device_groups(plain, mixed)
    check(f"a mixed cyclic/acyclic graph agrees with the naive walk "
          f"({mixed_groups})",
          mixed_groups == naive_groups(gm, plain, mixed)
          and mixed_groups == ["shared", "plain-user"])

    # A reference to a name absent from groups_config is a fact about the config, not the path, so it is safe to cache.
    missing = [{"name": "points-nowhere", "conditions": [ref("no-such-group")]},
               {"name": "points-nowhere-2", "conditions": [ref("no-such-group")]}]
    check("a reference to an absent group is a no-match, not an error",
          gm.evaluate_device_groups(plain, missing)
          == naive_groups(gm, plain, missing) == [])

    await Tortoise.close_connections()

    print()
    if FAILURES:
        print(f"RESULT: FAIL ({len(FAILURES)} check(s) failed): {FAILURES}")
        sys.exit(1)
    print("RESULT: PASS (all device tag checks passed)")


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
