"""Standalone checks for the device-naming template pipeline: controller/services/variables.py (the {variable} registry
and renderer) and controller/services/naming.py (template selection and resolution on top of it).

No database: both modules only read attributes off whatever device object they are given, so these checks use a plain
attribute bag instead of a Device model.

Run (from repo root, with the project venv):

    PYTHONPATH=. ./.venv/bin/python tests/verify_variables_naming.py
"""
import sys

FAILURES: list = []


def check(name: str, cond: bool) -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        FAILURES.append(name)


class Dev:
    """Minimal attribute bag standing in for a Device row."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def main() -> None:
    from controller.services import variables as v
    from controller.services import naming as n

    dev = Dev(serial_number="C02ABC123", device_model="MacBookPro18,3",
              hostname="corp-mac-42", os_version="14.5.1",
              udid="0123456789ABCDEF0123456789ABCDEF01234567",
              management_type="apple_mdm", name=None)

    print("\n[1] build_context")
    ctx = v.build_context(dev)
    check("serial maps to serial_number", ctx["serial"] == "C02ABC123")
    check("model maps to device_model", ctx["model"] == "MacBookPro18,3")
    check("hostname maps to hostname", ctx["hostname"] == "corp-mac-42")
    check("os maps to os_version", ctx["os"] == "14.5.1")
    check("os_version is an alias of os", ctx["os_version"] == ctx["os"])
    check("udid is the full value", ctx["udid"] == dev.udid)
    check("udid_short is the first 8 chars", ctx["udid_short"] == dev.udid[:8])
    check("management_type passes through", ctx["management_type"] == "apple_mdm")

    empty_dev = Dev()
    ctx2 = v.build_context(empty_dev)
    check("missing fields resolve to empty string, not None/crash",
          all(val == "" for val in ctx2.values()))

    short_udid_dev = Dev(udid="AB")
    check("udid_short on a short udid doesn't pad or crash",
          v.build_context(short_udid_dev)["udid_short"] == "AB")

    print("\n[2] template_variables / unknown_variables / is_self_referential")
    check("template_variables extracts names in order", v.template_variables(
        "IT-{serial}-{model}") == ["serial", "model"])
    check("template_variables strips inner whitespace", v.template_variables(
        "{ serial }") == ["serial"])
    check("template_variables on empty/None template -> []",
          v.template_variables(None) == [] and v.template_variables("") == [])
    check("unknown_variables finds names outside the registry", v.unknown_variables(
        "IT-{serial}-{bogus}") == ["bogus"])
    check("unknown_variables dedupes repeats, keeps first-seen order",
          v.unknown_variables("{bogus}-{serial}-{bogus}") == ["bogus"])
    check("unknown_variables is empty when every variable is known",
          v.unknown_variables("IT-{serial}-{model}") == [])
    check("is_self_referential true for {hostname}",
          v.is_self_referential("H-{hostname}") is True)
    check("is_self_referential false for other known variables",
          v.is_self_referential("H-{serial}-{model}") is False)
    check("is_self_referential false for no template",
          v.is_self_referential(None) is False)

    print("\n[3] render: substitution, cleanup, truncation")
    check("basic substitution", v.render("IT-{serial}", dev) == "IT-C02ABC123")
    check("multiple variables", v.render("{model}-{serial}", dev)
          == "MacBookPro18,3-C02ABC123")
    check("unknown variable collapses to empty and the dangling separator trims",
          v.render("IT-{serial}-{totally_unknown}", dev) == "IT-C02ABC123")
    check("stray braces from a malformed/unclosed template never survive",
          "{" not in (v.render("IT-{serial}-{oops", dev) or "")
          and "}" not in (v.render("IT-{serial}-{oops", dev) or ""))
    check("internal whitespace runs collapse to one space",
          v.render("{model}   {serial}", dev) == "MacBookPro18,3 C02ABC123")
    check("leading/trailing separators (space - _ .) are trimmed",
          v.render("  --{serial}--  ", dev) == "C02ABC123")
    check("empty template string -> None", v.render("", dev) is None)
    check("None template -> None", v.render(None, dev) is None)
    check("whitespace-only template -> None", v.render("   ", dev) is None)
    check("template that renders to nothing (all-unknown vars) -> None",
          v.render("{totally_unknown}", dev) is None)
    check("single-pass substitution: a value containing braces isn't re-expanded",
          v.render("{hostname}", Dev(hostname="{serial}")) == "serial")
    check("max_length truncates the final rendered string",
          v.render("{serial}", dev, max_length=4) == "C02A")
    check("max_length larger than the result has no effect",
          v.render("{serial}", dev, max_length=999) == "C02ABC123")
    check("no max_length (None) leaves the result untouched",
          v.render("{serial}", dev, max_length=None) == "C02ABC123")

    print("\n[4] select_naming_config: group order precedence, then tenant, then none")
    groups_cfg = [
        {"name": "g1", "device_naming": {}},  # matches device, no template -> skipped
        {"name": "g2", "device_naming": {"template": "G2-{serial}"}},
        {"name": "g3", "device_naming": {"template": "G3-{serial}"}},
    ]
    tenant_cfg = {"template": "T-{serial}"}

    cfg, src = n.select_naming_config(tenant_cfg, groups_cfg, ["g1", "g2", "g3"])
    check("first group in yaml order that both matches AND has a template wins",
          src == "group:g2" and cfg == {"template": "G2-{serial}"})

    cfg, src = n.select_naming_config(tenant_cfg, groups_cfg, ["g3", "g2"])
    check("group_names membership order doesn't matter, groups_config order does",
          src == "group:g2")

    cfg, src = n.select_naming_config(tenant_cfg, groups_cfg, ["g1"])
    check("device only in the template-less group -> falls through to tenant",
          src == "tenant" and cfg == tenant_cfg)

    cfg, src = n.select_naming_config(None, groups_cfg, [])
    check("no tenant config and no matching group -> none", (cfg, src) == (None, "none"))

    cfg, src = n.select_naming_config({"template": "   "}, groups_cfg, [])
    check("blank/whitespace-only tenant template does not count as a template",
          (cfg, src) == (None, "none"))

    cfg, src = n.select_naming_config(tenant_cfg, None, None)
    check("select_naming_config tolerates None groups_config/group_names",
          src == "tenant")

    print("\n[5] resolve_name / resolve_device_name / suggested_name_for / display_name")
    check("resolve_name delegates to render with MAX_NAME_LEN",
          n.resolve_name("IT-{serial}", dev) == "IT-C02ABC123")
    check("resolve_name enforces naming.MAX_NAME_LEN as the cap",
          len(n.resolve_name("{udid}" * 5, dev)) <= n.MAX_NAME_LEN)
    check("resolve_name of an empty template is None", n.resolve_name("", dev) is None)

    check("resolve_device_name uses the winning group template",
          n.resolve_device_name(dev, tenant_cfg, groups_cfg, ["g2"]) == "G2-C02ABC123")
    check("resolve_device_name falls back to tenant when no group matches",
          n.resolve_device_name(dev, tenant_cfg, groups_cfg, []) == "T-C02ABC123")
    check("resolve_device_name is None when nothing defines a template",
          n.resolve_device_name(dev, None, [], []) is None)

    unnamed = Dev(hostname="HOST1", serial_number="S1", name=None)
    named = Dev(hostname="HOST1", serial_number="S1", name="MB-HOST1")
    self_ref_cfg = {"template": "MB-{hostname}"}
    check("suggested_name_for gives a one-shot derivation for an unnamed device",
          n.suggested_name_for(unnamed, self_ref_cfg, [], []) == "MB-HOST1")
    check("suggested_name_for suppresses a self-referential template once the "
          "device already carries a managed name (loop guard)",
          n.suggested_name_for(named, self_ref_cfg, [], []) is None)
    check("suggested_name_for still suggests a non-self-referential template "
          "even on an already-named device",
          n.suggested_name_for(named, {"template": "MB-{serial}"}, [], []) == "MB-S1")
    check("resolve_device_name has no loop guard: it renders {hostname} "
          "unconditionally regardless of the device's current name",
          n.resolve_device_name(named, self_ref_cfg, [], []) == "MB-HOST1")

    check("display_name prefers the managed name",
          n.display_name(Dev(name="Managed", hostname="H", serial_number="S",
                             attributes={"DeviceName": "Alice's iPad"})) == "Managed")
    # hostname holds the reported HostName, which on a Mac is often a network name like macos.shared, while the name
    # typed into Settings arrives as DeviceName.
    check("display_name prefers the device's own DeviceName over its hostname",
          n.display_name(Dev(name=None, hostname="macos.shared", serial_number="S",
                             attributes={"DeviceName": "Alice's iPad"}))
          == "Alice's iPad")
    check("display_name falls back to hostname when unnamed",
          n.display_name(Dev(name=None, hostname="H", serial_number="S")) == "H")
    check("display_name falls back to hostname when DeviceName was never reported",
          n.display_name(Dev(name=None, hostname="H", serial_number="S",
                             attributes={"SerialNumber": "S"})) == "H")
    check("display_name falls back to serial when unnamed and no hostname",
          n.display_name(Dev(name=None, hostname=None, serial_number="S")) == "S")
    check("display_name's last resort is a literal placeholder",
          n.display_name(Dev(name=None, hostname=None, serial_number=None))
          == "Unknown device")
    check("display_name treats an empty-string name as absent (falls through)",
          n.display_name(Dev(name="", hostname="H", serial_number="S")) == "H")
    # A device row that has never reported anything has attributes = None, and this runs on every row of the list.
    check("display_name survives a device with no attributes at all",
          n.display_name(Dev(name=None, hostname="H", serial_number="S",
                             attributes=None)) == "H")

    print()
    if FAILURES:
        print(f"RESULT: FAIL ({len(FAILURES)} check(s) failed): {FAILURES}")
        sys.exit(1)
    print("RESULT: PASS (all variables/naming checks passed)")


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
