"""Automatic MDM enrollment-profile generation.

Builds the over-the-air enrollment ``.mobileconfig`` a device installs to enroll
into NanoMDM: a SCEP payload (device identity from step-ca) plus an ``com.apple.mdm``
payload pointing at the MDM server. Values come from environment configuration so
the admin never hand-crafts the profile.

The public download URL is gated by a per-tenant token derived via HMAC of the
JWT secret, so no schema change is needed and the link is unguessable.
"""

import hmac
import os
import plistlib
import uuid
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, Optional


def enrollment_token(tenant_id: str) -> str:
    secret = (os.getenv("JWT_SECRET") or "").encode()
    return hmac.new(secret, f"enroll:{tenant_id}".encode(), sha256).hexdigest()[:32]


def verify_enrollment_token(tenant_id: str, token: str) -> bool:
    return hmac.compare_digest(token or "", enrollment_token(tenant_id))


def _hostname() -> str:
    return os.getenv("MDM_HOSTNAME") or "mdm.example.com"


def _scep_name() -> str:
    return os.getenv("SCEP_NAME", "mdm_device_scep")


def _mdm_server_url() -> str:
    return os.getenv("MDM_SERVER_URL") or f"https://{_hostname()}/mdm"


def _server_url_for(tenant_id: str) -> str:
    """MDM ServerURL with the tenant encoded as a query param so NanoMDM forwards it
    to the webhook (url_params), letting the controller map check-ins to the tenant."""
    base = _mdm_server_url()
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}tenant={tenant_id}"


def _scep_url() -> str:
    return os.getenv("SCEP_URL") or f"https://{_hostname()}/scep/{_scep_name()}"


def _topic() -> str:
    return os.getenv("MDM_TOPIC", "")


def _scep_challenge() -> str:
    return os.getenv("SCEP_CHALLENGE", "")


def _days_remaining(expires_at: Optional[datetime]) -> Optional[int]:
    """Whole days from now until ``expires_at`` (may be negative if already
    past). ``None`` when the date is unset."""
    if expires_at is None:
        return None
    now = datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return (expires_at - now).days


def enrollment_details(tenant) -> Dict[str, Any]:
    """Non-secret details for the Enrollment page (no SCEP challenge)."""
    public = (os.getenv("PUBLIC_API_URL") or "").rstrip("/")
    token = enrollment_token(tenant.id)
    enroll_url = f"{public}/api/v1/enroll/{tenant.id}/{token}" if public else None

    missing = []
    if not _topic():
        missing.append("MDM_TOPIC")
    if not _scep_challenge():
        missing.append("SCEP_CHALLENGE")
    if not public:
        missing.append("PUBLIC_API_URL")

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
        "configured": len(missing) == 0,
        "missing": missing,
        # Admin-entered renewal dates (manual-entry MVP; see models.tenant).
        "apns_cert_expires_at": apns_expires,
        "apns_days_remaining": _days_remaining(apns_expires),
        "dep_token_expires_at": dep_expires,
        "dep_days_remaining": _days_remaining(dep_expires),
    }


def build_enrollment_profile(tenant) -> Dict[str, Any]:
    scep_uuid = str(uuid.uuid4()).upper()
    org = tenant.name or tenant.id
    return {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadDisplayName": f"{org} MDM Enrollment",
        "PayloadDescription": f"Enroll this device into {org} device management.",
        "PayloadIdentifier": f"com.micromanage.{tenant.id}.enroll",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadOrganization": org,
        "PayloadScope": "System",
        "PayloadContent": [
            {
                "PayloadType": "com.apple.security.scep",
                "PayloadVersion": 1,
                "PayloadIdentifier": f"com.micromanage.{tenant.id}.enroll.scep",
                "PayloadUUID": scep_uuid,
                "PayloadDisplayName": "Device Identity (SCEP)",
                "PayloadContent": {
                    "URL": _scep_url(),
                    "Name": _scep_name(),
                    "Subject": [[["CN", f"{tenant.id} MDM Device"]]],
                    "Challenge": _scep_challenge(),
                    "Keysize": 2048,
                    "Key Type": "RSA",
                    # 5 = digitalSignature(1) | keyEncipherment(4). keyEncipherment is
                    # required: step-ca's SCEP flow encrypts the issued cert back to the
                    # device key, so a signing-only key (1) would break SCEP. Keep at 5.
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
                "ServerCapabilities": ["com.apple.mdm.per-user-connections"],
            },
        ],
    }


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

    Used by Return to Service so a freshly-wiped device can reach the MDM
    server during Setup Assistant. ``encryption`` defaults to WPA (Apple's
    "WPA" covers WPA/WPA2/WPA3 Personal) when a password is given, else None
    (open network).
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
        "EncryptionType": encryption or ("WPA" if password else "None"),
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
