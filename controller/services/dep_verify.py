"""Verify the CMS signature on an ADE device's ``x-apple-aspen-deviceinfo``.

During Automated Device Enrollment the device POSTs a CMS/PKCS#7 SignedData blob
(base64 in the header) whose eContent is the MachineInfo plist, signed by the
device's identity certificate, which chains to Apple's device CA
("Apple iPhone Device CA" -> ... -> "Apple Root CA"). Verifying it proves the
request genuinely came from an Apple device and lets us trust the MachineInfo
fields (serial/udid/product).

Two things are checked (RFC 5652):
  1. **Signature** -- the SignerInfo signature over the content (via signed
     attributes when present, incl. the messageDigest binding to the eContent).
  2. **Trust chain** -- the signer certificate chains to a bundled Apple anchor.
     Per Apple's guidance, certificate **validity dates are IGNORED** (device
     certs may be expired); ``verify_directly_issued_by`` checks issuer +
     signature only, not notBefore/notAfter.

Anchors: ``controller/data/apple_ca_anchors.pem`` plus any file named by
``DEP_APPLE_ANCHOR_CERTS`` (the exact anchor a device chains to is OS/hardware-
dependent, so operators can supplement the bundle). The verifier NEVER raises --
it returns ``(content, verified, detail)`` so the caller decides policy; a parse
failure degrades to ``verified=False`` with the content still best-effort
extracted, so enrollment is never broken by a verification bug.
"""

import logging
import os
from functools import lru_cache
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding

logger = logging.getLogger(__name__)

_BUNDLED_ANCHORS = os.path.join(os.path.dirname(__file__), "..", "data", "apple_ca_anchors.pem")
_MAX_CHAIN_DEPTH = 10


@lru_cache(maxsize=1)
def _anchors() -> List[x509.Certificate]:
    """Trusted Apple root/intermediate CAs (bundled + operator-supplied)."""
    certs: List[x509.Certificate] = []
    paths = [os.path.normpath(_BUNDLED_ANCHORS)]
    extra = os.getenv("DEP_APPLE_ANCHOR_CERTS")
    if extra:
        paths.append(extra)
    for path in paths:
        try:
            with open(path, "rb") as fh:
                certs.extend(x509.load_pem_x509_certificates(fh.read()))
        except FileNotFoundError:
            if path != os.path.normpath(_BUNDLED_ANCHORS):
                logger.warning("DEP_APPLE_ANCHOR_CERTS path not found: %s", path)
        except Exception:
            logger.exception("Failed to load Apple anchor certs from %s", path)
    return certs


def _fp(cert: x509.Certificate) -> bytes:
    return cert.fingerprint(hashes.SHA256())


def _chain_trusted(leaf: x509.Certificate, pool: List[x509.Certificate]) -> bool:
    """Does ``leaf`` chain to a bundled Apple anchor? Ignores validity dates
    (``verify_directly_issued_by`` checks issuer + signature only)."""
    anchors = _anchors()
    if not anchors:
        return False
    anchor_fps = {_fp(a) for a in anchors}
    by_subject: dict = {}
    for c in list(pool) + anchors:
        by_subject.setdefault(c.subject.public_bytes(), []).append(c)

    current = leaf
    seen = set()
    for _ in range(_MAX_CHAIN_DEPTH):
        cur_fp = _fp(current)
        if cur_fp in anchor_fps:
            return True
        if cur_fp in seen:  # loop guard
            return False
        seen.add(cur_fp)
        issued = None
        for cand in by_subject.get(current.issuer.public_bytes(), []):
            if _fp(cand) == cur_fp:
                continue  # skip self (non-anchor self-signed can't be trusted)
            try:
                current.verify_directly_issued_by(cand)
                issued = cand
                break
            except Exception:
                continue
        if issued is None:
            return False
        if _fp(issued) in anchor_fps:
            return True
        current = issued
    return False


def _to_crypto_cert(asn1_cert) -> Optional[x509.Certificate]:
    try:
        return x509.load_der_x509_certificate(asn1_cert.dump())
    except Exception:
        return None


def _verify_signature(signer_cert: x509.Certificate, signed_bytes: bytes,
                      signature: bytes, hash_alg) -> bool:
    """Verify a SignerInfo signature with the signer's public key (RSA PKCS1v15 or
    ECDSA). Returns False on any mismatch/error."""
    pub = signer_cert.public_key()
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, signed_bytes, ec.ECDSA(hash_alg))
        else:  # RSA (Apple device certs)
            pub.verify(signature, signed_bytes, padding.PKCS1v15(), hash_alg)
        return True
    except Exception:
        return False


_HASH_BY_OID = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


def verify_cms(cms_der: bytes) -> Tuple[Optional[bytes], bool, str]:
    """Verify an ADE MachineInfo CMS SignedData blob.

    Returns ``(content, verified, detail)``: ``content`` is the eContent bytes
    (the MachineInfo plist) when extractable, ``verified`` is True only when BOTH
    the signature and the Apple trust chain check out. Never raises."""
    try:
        from asn1crypto import cms as asn1_cms
    except Exception:
        return None, False, "asn1crypto unavailable"

    try:
        ci = asn1_cms.ContentInfo.load(cms_der)
        if ci["content_type"].native != "signed_data":
            return None, False, "not signed_data"
        sd = ci["content"]
        signer_infos = sd["signer_infos"]
        if len(signer_infos) == 0:
            return None, False, "no signer_infos"
        si = signer_infos[0]

        # eContent (the MachineInfo plist).
        encap = sd["encap_content_info"]
        content = None
        if encap["content"].native is not None:
            content = encap["content"].native
            if not isinstance(content, (bytes, bytearray)):
                content = encap["content"].contents

        # Signer certificate (match by issuer+serial).
        crypto_certs = [c for c in (
            _to_crypto_cert(cc.chosen) for cc in (sd["certificates"] or [])
        ) if c is not None]
        signer_cert = _find_signer_cert(si, crypto_certs)
        if signer_cert is None:
            return content, False, "signer cert not found"

        digest_alg = si["digest_algorithm"]["algorithm"].native
        hash_cls = _HASH_BY_OID.get(digest_alg)
        if hash_cls is None:
            return content, False, f"unsupported digest {digest_alg}"
        hash_alg = hash_cls()

        # What the signature covers: the DER of signed_attrs (re-tagged SET) when
        # present, else the eContent directly.
        signed_attrs = si["signed_attrs"]
        if signed_attrs is not None and len(signed_attrs) > 0:
            # messageDigest attr MUST equal digest(eContent).
            if content is None:
                return None, False, "signed_attrs without content"
            md = _attr_value(signed_attrs, "message_digest")
            if md is None:
                return content, False, "no messageDigest attr"
            h = hashes.Hash(hash_alg)
            h.update(bytes(content))
            if not _consttime_eq(h.finalize(), bytes(md)):
                return content, False, "messageDigest mismatch"
            signed_bytes = signed_attrs.untag().dump()  # SET OF encoding per RFC 5652
        else:
            if content is None:
                return None, False, "no content to verify"
            signed_bytes = bytes(content)

        signature = si["signature"].native
        if not _verify_signature(signer_cert, signed_bytes, signature, hash_alg):
            return content, False, "signature invalid"

        if not _chain_trusted(signer_cert, crypto_certs):
            return content, False, "not chained to an Apple anchor"

        return content, True, f"verified via {signer_cert.issuer.rfc4514_string()}"
    except Exception as exc:  # defensive: never raise into the enroll path
        logger.warning("ADE CMS verification error: %s", exc)
        return None, False, f"error: {exc}"


def _find_signer_cert(si, certs: List[x509.Certificate]) -> Optional[x509.Certificate]:
    sid = si["sid"]
    if sid.name == "issuer_and_serial_number":
        serial = sid.chosen["serial_number"].native
        for c in certs:
            if c.serial_number == serial:
                return c
    elif sid.name == "subject_key_identifier":
        want = sid.chosen.native
        for c in certs:
            try:
                ski = c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
                if ski.value.digest == want:
                    return c
            except x509.ExtensionNotFound:
                continue
    return certs[0] if len(certs) == 1 else None


def _attr_value(signed_attrs, attr_name):
    for attr in signed_attrs:
        if attr["type"].native == attr_name:
            values = attr["values"]
            if len(values) > 0:
                return values[0].native
    return None


def _consttime_eq(a: bytes, b: bytes) -> bool:
    import hmac
    return hmac.compare_digest(a, b)
