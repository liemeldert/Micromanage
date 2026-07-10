"""Standalone sqlite E2E check for Phase 0 (Device Tags).

Run (from repo root, with the project venv):

    PYTHONPATH=. ./.venv/bin/python tests/verify_tags.py

No docker/Postgres needed: it spins up an in-memory sqlite via Tortoise,
generate_schemas() to create every model column (incl. the new ``tags``), and
exercises the tag scope condition, the tags->groups recompute chain, and the
tags.yaml validator (including the unknown-tag warning). Prints PASS/FAIL and
exits non-zero on any failure.
"""
import asyncio
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

    await Tortoise.close_connections()

    print()
    if FAILURES:
        print(f"RESULT: FAIL ({len(FAILURES)} check(s) failed): {FAILURES}")
        sys.exit(1)
    print("RESULT: PASS (all Phase 0 tag checks passed)")


if __name__ == "__main__":
    asyncio.run(main())
