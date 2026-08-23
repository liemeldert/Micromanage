"""Tests for the FileVault recovery-key escrow guard in controller/utils/yaml_validator.py.

Run: PYTHONPATH=. ./.venv/bin/python tests/verify_filevault_guard.py

See docs/tests/verify_filevault_guard.md for detailed behavior notes.
"""
import tempfile
from pathlib import Path

import yaml

from controller.utils.yaml_validator import YAMLValidator

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


FV_ENFORCE = {
    "PayloadType": "com.apple.MCX.FileVault2",
    "PayloadDisplayName": "Enforce FileVault",
    "Enable": "On",
}
ESCROW_CERT_UUID = "6B1E4E2A-0F1C-45D8-9E0B-1B3C6A5D7E90"
# The certificate the recovery key is encrypted to. Its PayloadUUID has to be authored: a missing one is filled with a
# fresh random uuid on every render, so EncryptCertPayloadUUID could never name it.
FV_ESCROW_CERT = {
    "PayloadType": "com.apple.security.pkcs1",
    "PayloadDisplayName": "FileVault Escrow Certificate",
    "PayloadUUID": ESCROW_CERT_UUID,
    "PayloadContent": "MIIBIjANBgkqhkiG9w0BAQ==",
}
FV_ESCROW = {
    "PayloadType": "com.apple.security.FDERecoveryKeyEscrow",
    "PayloadDisplayName": "Escrow FileVault Recovery Key",
    "Location": "Micromanage",
    "EncryptCertPayloadUUID": ESCROW_CERT_UUID,
}
# The payload type and nothing else, which escrows nothing.
FV_ESCROW_BARE = {
    "PayloadType": "com.apple.security.FDERecoveryKeyEscrow",
    "PayloadDisplayName": "Escrow FileVault Recovery Key",
}
OTHER_PAYLOAD = {
    "PayloadType": "com.apple.wifi.managed",
    "PayloadDisplayName": "Corporate Wi-Fi",
    "SSID_STR": "CorpNet",
}


def profile(profile_id, *payloads, name=None):
    return {
        "id": profile_id,
        "name": name or profile_id,
        "type": "configuration",
        "payloads": list(payloads),
    }


def run(profiles, tenant_extra=None, escrow_configured=False):
    """Validate profiles in a synthetic tenant. escrow_configured simulates tenant keypair injection."""
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        tenant = {"id": "t1", "name": "T1", "allowed_users": ["admin@t1"]}
        tenant.update(tenant_extra or {})
        (tdir / "config.yaml").write_text(yaml.safe_dump({"tenant": tenant}))
        (tdir / "groups.yaml").write_text(yaml.safe_dump({"groups": []}))
        (tdir / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
        (tdir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": profiles}))
        return YAMLValidator(
            tdir, filevault_escrow_configured=escrow_configured).validate_all()


def has(items, *substrings):
    return any(all(s in item for s in substrings) for item in items)


def main():
    print("1) FileVault enforced, no escrow anywhere in the tenant -> rejected")
    ok, errors, warnings = run([profile("fv", FV_ENFORCE)])
    check("config rejected", not ok)
    check("error names the profile and explains the consequence",
          has(errors, "fv", "escrow", "recover"))
    check("error mentions the escape hatch",
          has(errors, "allow_unescrowed_filevault"))
    check("a per-profile warning is raised too",
          has(warnings, "fv", "escrow"))

    print("\n2) FileVault enforced on one profile, escrow on a SEPARATE profile -> accepted")
    ok, errors, warnings = run([profile("fv", FV_ENFORCE),
                                profile("escrow", FV_ESCROW, FV_ESCROW_CERT)])
    check("config accepted", ok)
    check("no tenant-level filevault error", not has(errors, "FileVault"))
    check("per-profile warning still raised on 'fv' (it has no escrow of its own)",
          has(warnings, "fv", "escrow"))

    print("\n3) FileVault enforced and escrowed on the SAME profile -> accepted")
    ok, errors, warnings = run([profile("fv", FV_ENFORCE, FV_ESCROW, FV_ESCROW_CERT)])
    check("config accepted", ok)
    check("no filevault error", not has(errors, "FileVault"))
    check("no per-profile filevault warning (this profile carries its own escrow)",
          not has(warnings, "fv", "escrow"))

    print("\n4) Escrow payload alone, no enforcement anywhere -> accepted")
    ok, errors, warnings = run([profile("escrow", FV_ESCROW, FV_ESCROW_CERT)])
    check("config accepted", ok)
    check("no filevault error or warning",
          not has(errors, "FileVault") and not has(warnings, "FileVault"))

    print("\n5) Escape hatch: enforced, no escrow, allow_unescrowed_filevault: true -> accepted")
    ok, errors, warnings = run([profile("fv", FV_ENFORCE)],
                               tenant_extra={"allow_unescrowed_filevault": True})
    check("config accepted", ok)
    check("no tenant-level filevault error", not has(errors, "FileVault"))
    check("per-profile warning still raised (the hatch silences the error, not the warning)",
          has(warnings, "fv", "escrow"))

    print("\n6) No FileVault profile at all -> unaffected")
    ok, errors, warnings = run([profile("wifi", OTHER_PAYLOAD)])
    check("config accepted", ok)
    check("no filevault error or warning",
          not has(errors, "FileVault") and not has(warnings, "FileVault"))

    print("\n7) com.apple.MCX.FileVault2 payload present but Enable: Off -> not treated as enforcement")
    ok, errors, warnings = run([profile("fv-off", dict(FV_ENFORCE, Enable="Off"))])
    check("config accepted", ok)
    check("no filevault error or warning",
          not has(errors, "FileVault") and not has(warnings, "FileVault"))

    # ==Escrow completeness: the payload type alone is not escrow==

    print("\n8) Escrow payload carrying only its type does not satisfy the guard")
    ok, errors, warnings = run([profile("fv", FV_ENFORCE),
                                profile("escrow", FV_ESCROW_BARE)])
    check("config rejected", not ok)
    check("the tenant-wide error still stands", has(errors, "fv", "escrow", "recover"))
    check("and points at the profile that has an escrow payload it cannot use",
          has(errors, "escrow", "not one the Mac would install"))
    check("a warning names both missing keys",
          has(warnings, "escrow", "Location", "EncryptCertPayloadUUID"))

    print("\n9) Escrow payload with Location but no certificate reference")
    ok, errors, warnings = run([
        profile("fv", FV_ENFORCE),
        profile("escrow", dict(FV_ESCROW_BARE, Location="Micromanage")),
    ])
    check("config rejected", not ok)
    check("the warning names the key that is missing, not the one that is there",
          has(warnings, "escrow", "EncryptCertPayloadUUID")
          and not has(warnings, "escrow", "no 'Location'"))

    print("\n10) EncryptCertPayloadUUID naming a pkcs1 payload that is not in this profile")
    ok, errors, warnings = run([
        profile("fv", FV_ENFORCE),
        profile("escrow", FV_ESCROW),
        # The certificate is real but lives on a different profile, so the UUID resolves to nothing where the Mac looks
        # for it.
        profile("cert", FV_ESCROW_CERT),
    ])
    check("config rejected", not ok)
    check("the warning says the UUID names nothing in this profile",
          has(warnings, "escrow", ESCROW_CERT_UUID, "does not name"))

    print("\n11) EncryptCertPayloadUUID pointing at a payload of the wrong type")
    wrong_type = dict(OTHER_PAYLOAD, PayloadUUID=ESCROW_CERT_UUID)
    ok, errors, warnings = run([profile("fv", FV_ENFORCE),
                                profile("escrow", FV_ESCROW, wrong_type)])
    check("config rejected", not ok)
    check("the warning names the type the reference has to point at",
          has(warnings, "escrow", "com.apple.security.pkcs1"))

    print("\n12) A certificate payload with no authored PayloadUUID cannot be referenced")
    # A missing PayloadUUID is filled with a fresh random one on every render, so the reference can never match.
    unnamed_cert = {k: v for k, v in FV_ESCROW_CERT.items() if k != "PayloadUUID"}
    ok, errors, warnings = run([profile("fv", FV_ENFORCE),
                                profile("escrow", FV_ESCROW, unnamed_cert)])
    check("config rejected", not ok)
    check("the warning says the reference resolves to nothing",
          has(warnings, "escrow", "does not name"))

    # ==One escrow payload per Mac==

    print("\n13) Two escrow payloads in the SAME profile -> hard error")
    ok, errors, warnings = run([profile("escrow", FV_ESCROW, FV_ESCROW_CERT,
                                        dict(FV_ESCROW, PayloadDisplayName="Second"))])
    check("config rejected", not ok)
    check("the error says a Mac accepts one and errors on a second",
          has(errors, "escrow", "errors on a second"))

    print("\n14) Two escrow payloads on DIFFERENT profiles -> warning, not an error")
    ok, errors, warnings = run([profile("escrow-a", FV_ESCROW, FV_ESCROW_CERT),
                                profile("escrow-b", FV_ESCROW, FV_ESCROW_CERT)])
    check("config accepted (scope decides whether any Mac gets both)", ok)
    check("a warning names both profiles",
          has(warnings, "escrow-a", "escrow-b", "errors on a second"))

    # ==Enable as a YAML boolean==

    print("\n15) Enable written as YAML's bare On ships <true/>, so the author is warned")
    ok, errors, warnings = run([profile("fv", dict(FV_ENFORCE, Enable=True),
                                        FV_ESCROW, FV_ESCROW_CERT)])
    check("config accepted (a warning, not a block)", ok)
    check("the warning says what ships and what Apple wants",
          has(warnings, "fv", "Enable", "<true/>", "'On'"))
    check("and the profile still counts as turning FileVault on",
          not has(errors, "allow_unescrowed_filevault"))

    print("\n16) Enable: Off unquoted is the same mistake in the other direction")
    ok, errors, warnings = run([profile("fv-off", dict(FV_ENFORCE, Enable=False))])
    check("config accepted", ok)
    check("the warning names <false/> and the string 'Off'",
          has(warnings, "fv-off", "<false/>", "'Off'"))

    print("\n17) A quoted Enable draws no warning")
    ok, errors, warnings = run([profile("fv", FV_ENFORCE, FV_ESCROW, FV_ESCROW_CERT)])
    check("config accepted", ok)
    check("nothing said about Enable", not has(warnings, "Enable"))

    # ==Tenant escrow keypair: Micromanage injects the payload at build time==

    print("\n18) FileVault enforced, no authored escrow, but a tenant keypair exists "
          "-> accepted")
    ok, errors, warnings = run([profile("fv", FV_ENFORCE)], escrow_configured=True)
    check("config accepted (the escrow payload is injected at build time)", ok)
    check("no tenant-level filevault error", not has(errors, "FileVault"))
    check("and no per-profile 'no escrow of its own' warning either",
          not has(warnings, "fv", "escrow"))

    print("\n19) The keypair does not silence real breakage: a broken authored "
          "escrow payload still warns")
    ok, errors, warnings = run([profile("fv", FV_ENFORCE),
                                profile("escrow", FV_ESCROW_BARE)],
                               escrow_configured=True)
    check("config still accepted (the injected payload carries escrow)", ok)
    check("the broken authored payload is still called out",
          has(warnings, "escrow", "Location", "EncryptCertPayloadUUID"))

    print("\n20) two FileVault profiles with a tenant keypair each get an escrow "
          "payload injected -> multi-escrow warning")
    ok, errors, warnings = run([profile("fv-a", FV_ENFORCE),
                                profile("fv-b", FV_ENFORCE)],
                               escrow_configured=True)
    check("config accepted (scope decides whether any Mac gets both)", ok)
    check("a warning names both profiles and says they get one injected",
          has(warnings, "fv-a", "fv-b", "injected", "errors on a second"))

    print("\n21) a complete authored escrow stands injection down, so one authored "
          "plus one FileVault profile draws no multi-escrow warning")
    ok, errors, warnings = run([profile("fv", FV_ENFORCE),
                                profile("escrow", FV_ESCROW, FV_ESCROW_CERT)],
                               escrow_configured=True)
    check("config accepted", ok)
    check("no multi-escrow warning (injection stands down tenant-wide)",
          not has(warnings, "errors on a second"))

    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


if __name__ == "__main__":
    # aliased: this file has its own module-level run() helper
    from tests._verify_harness import run as _run_verify_suite

    _run_verify_suite(main)
