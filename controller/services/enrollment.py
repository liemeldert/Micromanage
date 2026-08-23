"""Builds the over-the-air enrollment .mobileconfig.

A SCEP payload for the device identity from step-ca and a com.apple.mdm payload pointing at the MDM server.
"""

import base64
import hmac
import logging
import os
import plistlib
import re
import unicodedata
import uuid
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote

from controller.auth.tokens import _secret as _jwt_secret, AuthConfigError
from controller.services import readiness

logger = logging.getLogger(__name__)


def _token_eq(provided: Optional[str], expected: str) -> bool:
    """Constant-time token compare that survives arbitrary attacker input.

    Compares UTF-8 bytes, not str: hmac.compare_digest over str raises TypeError on non-ASCII input, and the
    left operand here always comes off an unauthenticated request.
    """
    try:
        provided_b = (provided or "").encode("utf-8", "surrogatepass")
        expected_b = expected.encode("utf-8", "surrogatepass")
    except Exception:
        return False
    return hmac.compare_digest(provided_b, expected_b)


def enrollment_token(tenant_id: str) -> str:
    """The per-tenant token the unauthenticated enrollment endpoints require.

    Raises AuthConfigError when JWT_SECRET is unset or the shipped placeholder, since an empty key would make
    the token a constant anyone can compute to fetch the SCEP challenge.
    """
    return hmac.new(
        _jwt_secret().encode(), f"enroll:{tenant_id}".encode(), sha256
    ).hexdigest()[:32]


def verify_enrollment_token(tenant_id: str, token: str) -> bool:
    """Constant-time compare against the tenant's token.

    False when no token can be computed at all, so an unconfigured server rejects every caller instead of
    accepting a guessable one.
    """
    try:
        expected = enrollment_token(tenant_id)
    except AuthConfigError:
        logger.error(
            "JWT_SECRET is not configured; rejecting every enrollment token for tenant %s",
            tenant_id,
        )
        return False
    return _token_eq(token, expected)


def tenant_url_token(tenant_id: str) -> str:
    """The signature that binds the ?tenant= on the MDM ServerURL to this server.

    Without it a device could edit its own ServerURL to join another tenant's fleet. See
    docs/controller/services/enrollment.md for why the HMAC label differs from enrollment_token's.
    """
    return hmac.new(
        _jwt_secret().encode(), f"mdm-tenant:{tenant_id}".encode(), sha256
    ).hexdigest()[:32]


def verify_tenant_url_token(tenant_id: str, token: str) -> bool:
    """Constant-time check of a device-supplied tenant signature.

    False when no signature can be computed at all, so an unconfigured server trusts no tenant claim. Never
    raises: both arguments come off the device's own ServerURL query string.
    """
    if not tenant_id:
        return False
    try:
        expected = tenant_url_token(tenant_id)
    except AuthConfigError:
        logger.error(
            "JWT_SECRET is not configured; rejecting every tenant claim (tenant %s)",
            tenant_id,
        )
        return False
    return _token_eq(token, expected)


def log_token_refusal(endpoint: str, tenant_id: str, reason: str,
                      remote_addr: Optional[str]) -> None:
    """Record why an unauthenticated device endpoint refused a caller.

    The three device-facing endpoints answer the same 404 whether the tenant is unknown or the token is wrong,
    so this log line is the only place the distinction survives.
    """
    logger.warning(
        "%s: refused (tenant=%s, remote=%s): %s",
        _loggable(endpoint), _loggable(tenant_id), _loggable(remote_addr or "unknown"),
        _loggable(reason),
    )


def _loggable(value: Any, limit: int = 200) -> str:
    """One caller-supplied value, safe to interpolate into a log line.

    Control, format and bidi-override characters become a single space.
    """
    text = str(value or "")[:limit]
    # 日本語や絵文字はそのまま残る。置き換えるのは制御文字と書式文字だけ。
    return "".join(
        " " if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") else ch
        for ch in text
    )


def _hostname() -> Optional[str]:
    """The public hostname of the MDM endpoints, or None when nothing is set.

    No default: a placeholder like mdm.example.com would build URLs naming a host this deployment does not own.
    """
    return os.getenv("MDM_HOSTNAME") or None


def _scep_name() -> str:
    return os.getenv("SCEP_NAME", "mdm_device_scep")


def _mdm_server_url() -> Optional[str]:
    """The MDM ServerURL, explicit or built from the hostname. None if neither."""
    explicit = os.getenv("MDM_SERVER_URL")
    if explicit:
        return explicit
    host = _hostname()
    return f"https://{host}/mdm" if host else None


def _server_url_for(tenant_id: str) -> str:
    """MDM ServerURL with tenant and tsig query params, so the webhook can map check-ins to a verified tenant.
    """
    # Empty rather than None: plistlib cannot represent None, and every caller has already checked readiness.
    base = _mdm_server_url() or ""
    sep = "&" if "?" in base else "?"
    return (
        f"{base}{sep}tenant={quote(tenant_id, safe='')}"
        f"&tsig={tenant_url_token(tenant_id)}"
    )


def _scep_url() -> Optional[str]:
    """The SCEP enrolment URL, explicit or built from the hostname.

    None when neither is set, same as _hostname: a SCEP URL naming an unowned host carries the real challenge to it.
    """
    explicit = os.getenv("SCEP_URL")
    if explicit:
        return explicit
    host = _hostname()
    return f"https://{host}/scep/{_scep_name()}" if host else None


def _topic() -> str:
    return os.getenv("MDM_TOPIC", "")


def _scep_challenge() -> str:
    return os.getenv("SCEP_CHALLENGE", "")


# The armour around a certificate in a PEM file. Only the first block is read; see _embed_ca_der.
_PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.DOTALL
)


def _embed_ca_der() -> Optional[bytes]:
    """DER of the CA certificate to ship inside the enrollment profile, if any.

    Off unless MDM_EMBED_CA_CERT_PATH names a PEM file. Only the first certificate in the file is used; point this at
    the root, not a chain bundle.
    """
    return _read_embedded_ca()[0]


def _read_embedded_ca() -> Tuple[Optional[bytes], Optional[str]]:
    """(der, error) for MDM_EMBED_CA_CERT_PATH. Both None when it is unset, and never raises: an unusable path comes
    back as the error string."""
    path = os.getenv("MDM_EMBED_CA_CERT_PATH")
    if not path:
        return None, None
    try:
        with open(path, "rb") as fh:
            m = _PEM_CERT_RE.search(fh.read())
        if not m:
            raise ValueError("there is no CERTIFICATE block in it")
        # Strip the armour and the line breaks, then decode PEM to DER.
        der = base64.b64decode(b"".join(m.group(1).split()), validate=True)
        if not der:
            # An empty block decodes to b"" without raising, which would skip the payload silently.
            raise ValueError("its CERTIFICATE block is empty")
        return der, None
    except Exception as exc:
        return None, (
            f"MDM_EMBED_CA_CERT_PATH is set to {path} but no certificate can be read from it ({exc}). Enrollment "
            "profiles are meant to carry that certificate, so they are refused until you correct the path, or unset "
            "MDM_EMBED_CA_CERT_PATH if this deployment's device-facing URLs already have publicly trusted TLS."
        )


def embedded_ca_error() -> Optional[str]:
    """Why a set MDM_EMBED_CA_CERT_PATH cannot be used, or None.

    None both when the setting is unset and when the file behind it reads cleanly.
    """
    return _read_embedded_ca()[1]


def _days_remaining(expires_at: Optional[datetime]) -> Optional[int]:
    """Whole days from now until expires_at (may be negative if already past). None when the date is unset."""
    if expires_at is None:
        return None
    now = datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return (expires_at - now).days


def enrollment_details(tenant) -> Dict[str, Any]:
    """Non-secret enrollment details for the console, without the SCEP challenge.

    configured and missing come from readiness.check('enroll'), the same source the readiness endpoint reports and the
    download refuses on, so the three cannot disagree.
    """
    public = readiness.public_api_url()
    try:
        token = enrollment_token(tenant.id)
    except AuthConfigError:
        # No token means no working enrollment link, so none is returned rather than a URL that can never authenticate.
        # The readiness predicate reports JWT_SECRET for the same reason.
        token = None
    enroll_url = f"{public}/api/v1/enroll/{tenant.id}/{token}" if public and token else None

    status = readiness.check(readiness.ENROLL)
    missing = list(status.missing)

    apns_expires = getattr(tenant, "apns_cert_expires_at", None)
    dep_expires = getattr(tenant, "dep_token_expires_at", None)

    return {
        "tenant_id": tenant.id,
        "organization": tenant.name,
        "mdm_server_url": _mdm_server_url(),
        "scep_url": _scep_url(),
        "scep_name": _scep_name(),
        "topic": _topic() or None,
        "hostname": _hostname(),
        "enroll_url": enroll_url,
        "token": token,
        "configured": status.ready,
        "missing": missing,
        # Set-but-broken settings, kept apart from "missing": an admin shouldn't be told to set what's already set.
        "broken": list(status.broken),
        "reason": status.reason,
        # Admin-entered renewal dates (manual-entry MVP; see models.tenant).
        "apns_cert_expires_at": apns_expires,
        "apns_days_remaining": _days_remaining(apns_expires),
        "dep_token_expires_at": dep_expires,
        "dep_days_remaining": _days_remaining(dep_expires),
    }


def ade_enroll_url(tenant_id: str) -> Optional[str]:
    """The device-facing URL a DEP profile's url points at.

    Setup Assistant POSTs its signed MachineInfo here and gets back the enrollment .mobileconfig. Returns None
    when the 'ade' readiness capability is not ready.
    """
    status = readiness.check(readiness.ADE)
    if not status.ready:
        logger.error("Cannot build an ADE enrollment URL: %s", status.reason)
        return None
    try:
        token = enrollment_token(tenant_id)
    except AuthConfigError:  # pragma: no cover - the predicate above covers it
        return None
    return f"{readiness.public_api_url()}/api/v1/dep/enroll/{tenant_id}/{token}"


# The XML plist Setup Assistant embeds in its signed MachineInfo.
_PLIST_XML_RE = re.compile(rb"<\?xml.*?</plist>", re.DOTALL)


def _extract_plist(data: bytes) -> Optional[Dict[str, Any]]:
    """Best-effort extraction of a plist embedded in raw CMS/DER bytes.

    Finds the embedded plist (XML or binary bplist00) rather than pulling in a whole ASN.1 stack. Observability
    only: the device identifies itself for real later, through SCEP and the Authenticate webhook.
    """
    m = _PLIST_XML_RE.search(data)
    if m:
        try:
            obj = plistlib.loads(m.group(0))
            return obj if isinstance(obj, dict) else None
        except Exception:
            pass
    idx = data.find(b"bplist00")
    if idx != -1:
        try:
            obj = plistlib.loads(data[idx:])
            return obj if isinstance(obj, dict) else None
        except Exception:
            pass
    return None


def parse_machine_info(header_value: Optional[str]) -> Tuple[Dict[str, Any], bool]:
    """Parse and verify the CMS-signed MachineInfo in the aspen-deviceinfo header.

    Returns (machine_info, verified). Never raises: an unverifiable header comes back as verified=False with
    whatever MachineInfo could be extracted.
    """
    if not header_value:
        return {}, False
    try:
        raw = base64.b64decode(header_value, validate=False)
    except Exception:
        logger.warning("ADE: x-apple-aspen-deviceinfo header is not valid base64")
        return {}, False

    verified = False
    info: Dict[str, Any] = {}
    try:
        from controller.services.dep_verify import verify_cms

        content, verified, detail = verify_cms(raw)
        if content:
            info = _extract_plist(bytes(content)) or {}
        # detail carries the signer's issuer name (and any exception text) off the same unverified header.
        logger.info("ADE: machine-info verification: %s", _loggable(detail))
    except Exception:
        logger.exception("ADE: CMS verification path failed; falling back to extract")

    # Fallback: pull the plist straight out of the CMS bytes when verification could not return the content.
    if not info:
        info = _extract_plist(raw) or {}
    if info:
        # These fields come out of a header that may have failed verification, so they go through _loggable like any
        # other caller-supplied value.
        logger.info("ADE: machine-info SERIAL=%s PRODUCT=%s VERSION=%s verified=%s",
                    _loggable(info.get("SERIAL")), _loggable(info.get("PRODUCT")),
                    _loggable(info.get("OS_VERSION")), verified)
    return info, verified


def build_enrollment_profile(tenant) -> Dict[str, Any]:
    scep_uuid = str(uuid.uuid4()).upper()
    org = tenant.name or tenant.id
    profile: Dict[str, Any] = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadDisplayName": f"{org} MDM Enrollment",
        "PayloadDescription": f"Enroll this device into {org} device management.",
        "PayloadIdentifier": f"com.micromanage.{tenant.id}.enroll",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadOrganization": org,
        # No PayloadScope here on purpose: setting it to System freezes the user-channel capability below off
        # at enrollment.
        "PayloadContent": [
            {
                "PayloadType": "com.apple.security.scep",
                "PayloadVersion": 1,
                "PayloadIdentifier": f"com.micromanage.{tenant.id}.enroll.scep",
                "PayloadUUID": scep_uuid,
                "PayloadDisplayName": "Device Identity (SCEP)",
                "PayloadContent": {
                    # Empty rather than None, as in _server_url_for: plistlib cannot represent None.
                    "URL": _scep_url() or "",
                    "Name": _scep_name(),
                    "Subject": [[["CN", f"{tenant.id} MDM Device {uuid.uuid4().hex}"]]],
                    "Challenge": _scep_challenge(),
                    "Keysize": 2048,
                    "Key Type": "RSA",
                    # 5 = digitalSignature(1) | keyEncipherment(4). step-ca's SCEP flow encrypts the issued
                    # certificate back to the device key, so a signing-only key (1) breaks SCEP.
                    "Key Usage": 5,
                    "Retries": 3,
                    "RetryDelay": 10,
                },
            },
            {
                "PayloadType": "com.apple.mdm",
                "PayloadVersion": 1,
                "PayloadIdentifier": f"com.micromanage.{tenant.id}.enroll.mdm",
                "PayloadUUID": str(uuid.uuid4()).upper(),
                "PayloadDisplayName": "Mobile Device Management",
                "IdentityCertificateUUID": scep_uuid,
                "ServerURL": _server_url_for(tenant.id),
                "Topic": _topic(),
                "AccessRights": 8191,
                "CheckOutWhenRemoved": True,
                "SignMessage": True,
                # Required despite reading as optional: macOS 26.6.1 refuses the install without it.
                "ServerCapabilities": ["com.apple.mdm.per-user-connections", "com.apple.mdm.bootstraptoken"],
            },
        ],
    }

    ca_der = _embed_ca_der()
    if ca_der:
        profile["PayloadContent"].append(
            {
                "PayloadType": "com.apple.security.root",
                "PayloadVersion": 1,
                "PayloadIdentifier": f"com.micromanage.{tenant.id}.enroll.root",
                "PayloadUUID": str(uuid.uuid4()).upper(),
                "PayloadDisplayName": f"{org} Certificate Authority",
                "PayloadContent": ca_der,
            }
        )
    return profile


def build_enrollment_mobileconfig(tenant) -> bytes:
    return plistlib.dumps(build_enrollment_profile(tenant))


def build_wifi_profile(
    ssid: str,
    password: str = None,
    hidden: bool = False,
    encryption: str = None,
    org: str = None,
) -> Dict[str, Any]:
    """A minimal Wi-Fi configuration profile.

    Used by Return to Service so a freshly-wiped device can reach the MDM server during Setup Assistant.
    EncryptionType defaults to "Any" rather than a named protocol: naming the wrong one can exclude the network
    the device is meant to join, which is unrecoverable once the device is wiped.
    https://raw.githubusercontent.com/apple/device-management/release/mdm/profiles/com.apple.wifi.managed.yaml
    """
    payload_uuid = str(uuid.uuid4()).upper()
    wifi: Dict[str, Any] = {
        "PayloadType": "com.apple.wifi.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"com.micromanage.rts.wifi.{payload_uuid}",
        "PayloadUUID": payload_uuid,
        "PayloadDisplayName": f"Wi-Fi ({ssid})",
        "SSID_STR": ssid,
        "HIDDEN_NETWORK": bool(hidden),
        "AutoJoin": True,
        "EncryptionType": encryption or ("Any" if password else "None"),
    }
    if password:
        wifi["Password"] = password
    return {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadDisplayName": "Return to Service Wi-Fi",
        "PayloadIdentifier": f"com.micromanage.rts.wifi.{payload_uuid}.profile",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadOrganization": org or "",
        "PayloadScope": "System",
        "PayloadContent": [wifi],
    }


def build_wifi_mobileconfig(
    ssid: str,
    password: str = None,
    hidden: bool = False,
    encryption: str = None,
    org: str = None,
) -> bytes:
    return plistlib.dumps(
        build_wifi_profile(ssid, password=password, hidden=hidden,
                           encryption=encryption, org=org)
    )
