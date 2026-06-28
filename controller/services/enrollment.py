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
from hashlib import sha256
from typing import Any, Dict


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


def _scep_url() -> str:
    return os.getenv("SCEP_URL") or f"https://{_hostname()}/scep/{_scep_name()}"


def _topic() -> str:
    return os.getenv("MDM_TOPIC", "")


def _scep_challenge() -> str:
    return os.getenv("SCEP_CHALLENGE", "")


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
                "ServerURL": _mdm_server_url(),
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
