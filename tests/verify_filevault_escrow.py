"""FileVault recovery-key escrow: keypair, payload injection, CMS decrypt, and the device-secret store
(controller/services/filevault_escrow.py).

Run: PYTHONPATH=. python tests/verify_filevault_escrow.py

macOS escrows a FileVault personal recovery key by encrypting it to a certificate the escrow profile carries, wrapping
it as CMS EnvelopedData and handing it to the MDM server in SecurityInfo (FDE_PersonalRecoveryKeyCMS) and in a
RotateFileVaultKey answer. This suite mints a real per-tenant keypair, builds a real CMS envelope to that certificate
the way a Mac would, and proves the controller opens it and stores the key like the firmware and recovery-lock
passwords.
"""
import base64
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

# A real Fernet key, set before any controller import reads it, so encryption at rest is configured for the store.
os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

from tortoise import Tortoise

from controller.models.tenant import Device, DeviceSecret, Tenant
from controller.services import crypto_secrets, filevault_escrow

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def seal_to_cert(cert_pem: str, plaintext: bytes) -> bytes:
    """A DER CMS EnvelopedData sealing plaintext to a certificate, the way a Mac seals a recovery key."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    return (
        pkcs7.PKCS7EnvelopeBuilder()
        .set_data(plaintext)
        .add_recipient(cert)
        .encrypt(Encoding.DER, [])
    )


async def make_tenant(tid="fve"):
    tenant = await Tenant.create(id=tid, name="FV Escrow Lab", allowed_users=[])
    return tenant


async def make_device(tenant, serial="FVLAB1", udid=None):
    return await Device.create(
        tenant=tenant, serial_number=serial, udid=udid or f"udid-{serial}",
        device_model="MacBookPro18,1", os_version="15.0", enrollment_state="enrolled")


async def main():
    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    print("1) generate_keypair stores an encrypted key and a public certificate")
    tenant = await make_tenant()
    check("a fresh tenant is not configured", not filevault_escrow.is_configured(tenant))
    await filevault_escrow.generate_keypair(tenant)
    check("now it is", filevault_escrow.is_configured(tenant))
    check("the certificate is real PEM",
          "BEGIN CERTIFICATE" in (tenant.fv_escrow_cert_pem or ""))
    check("the private key is stored encrypted, not in the clear",
          tenant.fv_escrow_private_key_enc
          and "BEGIN" not in tenant.fv_escrow_private_key_enc)
    check("the stored private key decrypts under the tenant binding",
          crypto_secrets.decrypt(
              tenant.fv_escrow_private_key_enc,
              aad=filevault_escrow._key_binding(tenant.id)) is not None)
    check("an expiry was recorded", tenant.fv_escrow_cert_expires_at is not None)

    print("\n2) generate_keypair refuses to replace silently, obeys replace=True")
    first_cert = tenant.fv_escrow_cert_pem
    raised = False
    try:
        await filevault_escrow.generate_keypair(tenant)
    except ValueError:
        raised = True
    check("a second call without replace=True is refused", raised)
    await filevault_escrow.generate_keypair(tenant, replace=True)
    check("replace=True mints a different certificate",
          tenant.fv_escrow_cert_pem != first_cert)

    print("\n3) certificate_info reports the shape without leaking the key")
    info = filevault_escrow.certificate_info(tenant)
    check("it says configured", info["configured"] is True)
    check("it carries a fingerprint", bool(info["fingerprint_sha256"]))
    check("it confirms the key decrypts", info["key_decrypts"] is True)
    check("it never includes private-key material",
          "private" not in " ".join(str(v).lower() for v in info.values()))

    print("\n4) inject_payloads adds the pair beside a FileVault payload, only then")
    fv_only = [{"PayloadType": "com.apple.MCX.FileVault2", "Enable": "On"}]
    added = filevault_escrow.inject_payloads(tenant, fv_only, "com.mdm.fve.p")
    check("it reports it injected", added is True)
    types = [p["PayloadType"] for p in fv_only]
    check("the certificate payload is there", "com.apple.security.pkcs1" in types)
    check("the escrow payload is there",
          "com.apple.security.FDERecoveryKeyEscrow" in types)
    escrow = next(p for p in fv_only
                  if p["PayloadType"] == "com.apple.security.FDERecoveryKeyEscrow")
    cert_payload = next(p for p in fv_only
                        if p["PayloadType"] == "com.apple.security.pkcs1")
    check("the escrow payload names the certificate payload by its UUID",
          escrow["EncryptCertPayloadUUID"] == cert_payload["PayloadUUID"])
    check("the certificate payload carries DER bytes, not base64 text",
          isinstance(cert_payload["PayloadContent"], bytes))
    check("the escrow payload has a Location string Apple marks required",
          bool(escrow.get("Location")))

    no_fv = [{"PayloadType": "com.apple.wifi.managed"}]
    check("nothing is injected when there is no FileVault payload",
          filevault_escrow.inject_payloads(tenant, no_fv, "com.mdm.fve.p") is False
          and len(no_fv) == 1)
    authored = [{"PayloadType": "com.apple.MCX.FileVault2", "Enable": "On"},
                {"PayloadType": "com.apple.security.FDERecoveryKeyEscrow"}]
    check("an author's own escrow payload is left as the only one",
          filevault_escrow.inject_payloads(tenant, authored, "com.mdm.fve.p") is False
          and len(authored) == 2)
    unconfigured = await make_tenant("fve-none")
    check("a tenant with no keypair injects nothing",
          filevault_escrow.inject_payloads(
              unconfigured, [{"PayloadType": "com.apple.MCX.FileVault2"}],
              "com.mdm.x.p") is False)

    print("\n5) profile_manager builds the escrow pair into a real profile")
    from controller.services.profile_manager import ProfileManager
    built = ProfileManager(tenant)._build_profile_payload({
        "id": "fv-enforce", "name": "Enforce FileVault",
        "payloads": [{"PayloadType": "com.apple.MCX.FileVault2", "Enable": "On"}],
    })
    built_types = [p["PayloadType"] for p in built["PayloadContent"]]
    check("the built profile carries the FileVault payload",
          "com.apple.MCX.FileVault2" in built_types)
    check("...and the injected escrow pair",
          "com.apple.security.pkcs1" in built_types
          and "com.apple.security.FDERecoveryKeyEscrow" in built_types)
    import plistlib
    # The <data> handling has to survive plist encoding.
    rendered = plistlib.dumps(built)
    check("the profile plist-encodes without error", rendered.startswith(b"<?xml"))

    print("\n6) decrypt_prk opens a real CMS envelope sealed to our certificate")
    prk = "ABCD-EFGH-IJKL-MNOP-QRST-UVWX"
    envelope = seal_to_cert(tenant.fv_escrow_cert_pem, prk.encode())
    check("the recovery key comes back exactly",
          filevault_escrow.decrypt_prk(tenant, envelope) == prk)
    check("a base64 string of the same envelope opens too",
          filevault_escrow.decrypt_prk(
              tenant, base64.b64encode(envelope).decode()) == prk)

    print("\n7) an envelope sealed to a different certificate does not open")
    other = await make_tenant("fve-other")
    await filevault_escrow.generate_keypair(other)
    foreign = seal_to_cert(other.fv_escrow_cert_pem, prk.encode())
    check("the wrong key returns None, never the plaintext",
          filevault_escrow.decrypt_prk(tenant, foreign) is None)

    print("\n8) ingest_security_info files the key as a filevault_prk secret")
    device = await make_device(tenant)
    stored = await filevault_escrow.ingest_security_info(
        device, {"FDE_Enabled": True, "FDE_PersonalRecoveryKeyCMS": envelope})
    check("it reports it stored one", stored is True)
    secret = await DeviceSecret.get_or_none(
        device_id=device.id, kind=DeviceSecret.KIND_FILEVAULT_PRK)
    check("a filevault_prk row exists", secret is not None)
    check("the escrowed value decrypts to the recovery key",
          await filevault_escrow.escrowed_prk(device) == prk)
    check("its metadata records how it was escrowed",
          (secret.meta or {}).get("escrowed_via") == "security_info")
    check("the non-secret projection never carries the key",
          "value" not in secret.to_dict() and prk not in str(secret.to_dict()))

    print("\n9) escrow-if-changed: a repeated SecurityInfo poll does not churn")
    # Put the reveal ledger in a revealed state, which a repeat poll must not touch: re-storing the same key would reset
    # the ledger and close the alert that a revealed key keeps open.
    secret.revealed_at = datetime(2024, 5, 6, 7, 8, 9, tzinfo=timezone.utc)
    secret.revealed_by = "admin@fve"
    secret.reveal_count = 3
    await secret.save()
    saved = await DeviceSecret.get(id=secret.id)
    before_updated = saved.updated_at
    before_revealed = saved.revealed_at
    check("the ledger is in a revealed state to begin with",
          before_revealed is not None and saved.reveal_count == 3)
    again = await filevault_escrow.ingest_security_info(
        device, {"FDE_PersonalRecoveryKeyCMS": envelope})
    check("the unchanged key is not re-stored", again is False)
    after = await DeviceSecret.get(id=secret.id)
    check("the row was not rewritten (updated_at unchanged)",
          after.updated_at == before_updated)
    check("the reveal timestamp survived the repeat poll",
          after.revealed_at == before_revealed)
    check("the reveal count survived too", after.reveal_count == 3)

    print("\n10) a rotated key in a RotateResult is escrowed")
    new_prk = "9999-8888-7777-6666-5555-4444"
    new_env = seal_to_cert(tenant.fv_escrow_cert_pem, new_prk.encode())
    rotated = await filevault_escrow.ingest_rotate_result(
        device, {"RotateResult": {"EncryptedNewRecoveryKey": new_env}})
    check("it reports it stored the rotated key", rotated is True)
    check("reading it back now returns the new key",
          await filevault_escrow.escrowed_prk(device) == new_prk)
    rotated_row = await DeviceSecret.get(
        device_id=device.id, kind=DeviceSecret.KIND_FILEVAULT_PRK)
    check("a rotated key resets the reveal ledger",
          rotated_row.reveal_count == 0 and rotated_row.revealed_at is None
          and rotated_row.revealed_by is None)

    print("\n11) a device whose tenant has no keypair stores nothing, quietly")
    bare_dev = await make_device(unconfigured, serial="NONE1")
    check("SecurityInfo escrow is a no-op with no keypair",
          await filevault_escrow.ingest_security_info(
              bare_dev, {"FDE_PersonalRecoveryKeyCMS": envelope}) is False)
    check("and nothing was stored for it",
          await filevault_escrow.escrowed_prk(bare_dev) is None)

    print("\n12) a complete authored escrow payload anywhere stands injection down")
    from controller.services import tenant_config
    cert_uuid = "6B1E4E2A-0F1C-45D8-9E0B-1B3C6A5D7E90"
    authored_doc = {"profiles": [{
        "id": "byo-escrow", "name": "BYO escrow", "type": "configuration",
        "payloads": [
            {"PayloadType": "com.apple.security.FDERecoveryKeyEscrow",
             "Location": "Corp IT", "EncryptCertPayloadUUID": cert_uuid},
            {"PayloadType": "com.apple.security.pkcs1",
             "PayloadUUID": cert_uuid,
             "PayloadContent": "MIIBIjANBgkqhkiG9w0BAQ=="},
        ],
    }]}
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td) / "tenants" / str(tenant.id)
        tdir.mkdir(parents=True)
        (tdir / "profiles.yaml").write_text(yaml.safe_dump(authored_doc))
        os.environ["YAML_CONFIG_PATH"] = td
        tenant_config.invalidate()
        try:
            fv = [{"PayloadType": "com.apple.MCX.FileVault2", "Enable": "On"}]
            check("inject_payloads declines when another profile escrows",
                  filevault_escrow.inject_payloads(
                      tenant, fv, "com.mdm.fve.p") is False)
            check("the FileVault profile is left untouched", len(fv) == 1)
            built2 = ProfileManager(tenant)._build_profile_payload({
                "id": "fv2", "name": "FV2",
                "payloads": [{"PayloadType": "com.apple.MCX.FileVault2",
                              "Enable": "On"}],
            })
            built2_types = [p["PayloadType"] for p in built2["PayloadContent"]]
            check("profile_manager builds no injected pair either",
                  "com.apple.security.FDERecoveryKeyEscrow" not in built2_types
                  and "com.apple.security.pkcs1" not in built2_types)
            # An incomplete authored payload proves nothing, since the Mac refuses to install it, so injection runs.
            (tdir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": [{
                "id": "bare", "name": "bare", "type": "configuration",
                "payloads": [{"PayloadType":
                                  "com.apple.security.FDERecoveryKeyEscrow"}],
            }]}))
            tenant_config.invalidate()
            fv_again = [{"PayloadType": "com.apple.MCX.FileVault2",
                         "Enable": "On"}]
            check("an incomplete authored payload does not stand injection down",
                  filevault_escrow.inject_payloads(
                      tenant, fv_again, "com.mdm.fve.p") is True)
        finally:
            del os.environ["YAML_CONFIG_PATH"]
            tenant_config.invalidate()

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} "
          f"({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
