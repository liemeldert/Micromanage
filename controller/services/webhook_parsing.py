"""Plist decoding, response parsing, and device-channel classification for the webhook handler."""
import base64
import logging
import plistlib
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Only the device channel says anything about whether the DEVICE is enrolled; a per-user message must not write
# enrollment state (https://github.com/micromdm/nanomdm/blob/v0.9.0/service/webhook/event.go).
_DEVICE_CHANNEL_TYPES = ("Device", "User Enrollment (Device)")

# The rest of what NanoMDM posts is proof of life with no evidence about enrollment either way, and must not flip a
# checked-out device back to enrolled.
_ENROLLMENT_STATE_TOPICS = ("mdm.Authenticate", "mdm.TokenUpdate", "mdm.Connect")

# Task types whose acknowledgement means the change is already on the device, so an inventory query then sees it. App
# installs are not listed, since InstallApplication is acknowledged before the download and install.
_PROFILE_INVENTORY_TASK_TYPES = ("profile_install", "profile_remove")


def _is_device_channel(event: Dict[str, Any]) -> bool:
    """True when the event arrived on the device channel rather than a user channel.

    Absent or unreadable ids reads as the device channel, for compatibility with pre-0.9.0 NanoMDM.
    """
    ids = event.get("ids")
    channel = ids.get("type") if isinstance(ids, dict) else None
    if not channel:
        return True
    return channel in _DEVICE_CHANNEL_TYPES


def _decode_plist(raw_b64: Optional[str]) -> Dict[str, Any]:
    """Decode a NanoMDM webhook raw_payload (base64-encoded plist) into a dict."""
    if not raw_b64:
        return {}
    try:
        return plistlib.loads(base64.b64decode(raw_b64))
    except Exception as e:  # malformed / non-plist body
        logger.warning(f"webhook: could not decode raw_payload: {e}")
        return {}


def _json_safe(value: Any):
    """Make a decoded plist JSON-serializable (datetimes -> ISO strings, bytes dropped)."""
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items() if not isinstance(v, bytes)}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value if not isinstance(v, bytes)]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _error_chain(response: Dict[str, Any]) -> list:
    """The device's ErrorChain as a list of dictionaries; anything malformed reads as no chain instead of raising."""
    chain = response.get("ErrorChain")
    if not isinstance(chain, list):
        return []
    return [entry for entry in chain if isinstance(entry, dict)]


def _error_line(entry: Dict[str, Any], fallback: str) -> str:
    """One readable line for a single ErrorChain entry: "domain code: description".

    Domain and code lead because they are identical across devices and languages, so failures can be searched on them.
    """
    domain = str(entry.get("ErrorDomain") or "").strip()
    code = entry.get("ErrorCode")
    description = str(
        entry.get("USEnglishDescription") or entry.get("LocalizedDescription") or ""
    ).strip()
    prefix = " ".join(p for p in (domain, "" if code is None else str(code)) if p)
    if not description:
        return f"{prefix}: {fallback}" if prefix else fallback
    return f"{prefix}: {description}" if prefix else description


# InstallApplication State values that mean the app is not going to arrive
# (https://github.com/apple/device-management/blob/release/mdm/commands/application.install.yaml); every other value
# is the install in progress or already done.
_APP_INSTALL_REFUSED_STATES = (
    "Failed", "UserRejected", "UpdateRejected", "ManagementRejected",
)

# Two RejectionReason values do not mean the install failed: the app is already there, or an earlier request for it
# is still pending.
_APP_INSTALL_BENIGN_REASONS = ("AppAlreadyInstalled", "AppAlreadyQueued")


def _app_install_state(response: Dict[str, Any]) -> Dict[str, Any]:
    """What an InstallApplication acknowledgement said about the app, if anything. Every key is optional, so this is
    often empty."""
    return {
        key: response[key]
        for key in ("State", "RejectionReason", "Identifier")
        if response.get(key) is not None
    }


def _app_install_refusal(app_state: Dict[str, Any]) -> Optional[str]:
    """A readable reason when an acknowledgement is really a refusal.

    Apple answers a refused install with Status: Acknowledged, so an acknowledgement alone is not a success.
    """
    state = app_state.get("State")
    reason = app_state.get("RejectionReason")
    refused = (
        state in _APP_INSTALL_REFUSED_STATES
        or (bool(reason) and reason not in _APP_INSTALL_BENIGN_REASONS)
    )
    if not refused:
        return None
    named = state or "refused"
    return f"The device did not install the app ({named}{f': {reason}' if reason else ''})"


def _reconciled_enrollment_source(attrs: Dict[str, Any]) -> Optional[str]:
    """What enrollment_source should say once the device has answered, or None when it has said nothing.

    SecurityInfo's ManagementStatus.EnrolledViaDEP overrides the server-side inference from ABM assignment.
    """
    sec = attrs.get("SecurityInfo")
    mgmt = sec.get("ManagementStatus") if isinstance(sec, dict) else None
    if isinstance(mgmt, dict) and isinstance(mgmt.get("EnrolledViaDEP"), bool):
        return "ade" if mgmt["EnrolledViaDEP"] else "ota"
    return None


def _reported_hostname(info: Dict[str, Any]) -> Optional[str]:
    """The device's network hostname out of a check-in or DeviceInformation.

    HostName is the stable ASCII name; DeviceName is a free-form label, used only until DeviceInformation answers.
    """
    # 表示名は「マイクロ仮想マシン」のような任意の文字列になりうる。ホスト名とは別物。
    return info.get("HostName") or info.get("DeviceName")


def _summarize_certificates(items: Any) -> Any:
    """Turn a CertificateList answer into stored fields.

    Data is DER-encoded X.509 bytes that _json_safe drops, parsed here into the issuer, serial and expiry instead
    (https://github.com/apple/device-management/blob/release/mdm/commands/certificate.list.yaml).
    """
    if not isinstance(items, list):
        return items
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    summarized = []
    for item in items:
        if not isinstance(item, dict):
            summarized.append(item)
            continue
        out = {"CommonName": item.get("CommonName"), "IsIdentity": item.get("IsIdentity")}
        der = item.get("Data")
        if not isinstance(der, bytes):
            summarized.append(out)
            continue
        try:
            cert = x509.load_der_x509_certificate(der)
            out.update({
                "Subject": cert.subject.rfc4514_string(),
                "Issuer": cert.issuer.rfc4514_string(),
                # Hex, and unbounded width: a certificate serial is a big integer, not a machine word.
                "SerialNumber": format(cert.serial_number, "x"),
                "NotBefore": cert.not_valid_before_utc.isoformat(),
                "NotAfter": cert.not_valid_after_utc.isoformat(),
                "SHA256Fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
            })
        except Exception as exc:
            out["ParseError"] = str(exc)[:200]
        summarized.append(out)
    return summarized


# InstalledApplicationList keys that mean an entry is on its way and not there yet
# (https://github.com/apple/device-management/blob/release/mdm/commands/application.installed.list.yaml). An iOS
# device lists an app while still fetching it; a Mac does not, so these only arrive from the other platforms.
_INVENTORY_PENDING_KEYS = (
    "Installing", "DownloadFailed", "DownloadWaiting", "DownloadPaused",
    "DownloadCancelled",
)


def _inventory_bundle_versions(installed_apps: Any) -> Dict[str, set]:
    """Bundle id to the versions the device reported, for apps it holds.

    An entry with neither Version nor ShortVersion maps to an empty set. Entries still being fetched are left out.
    """
    out: Dict[str, set] = {}
    if not isinstance(installed_apps, list):
        return out
    for entry in installed_apps:
        if not isinstance(entry, dict):
            continue
        identifier = entry.get("Identifier")
        if not identifier:
            continue
        if any(entry.get(key) is True for key in _INVENTORY_PENDING_KEYS):
            continue
        versions = {str(entry[key]) for key in ("Version", "ShortVersion")
                    if entry.get(key) not in (None, "")}
        out.setdefault(str(identifier), set()).update(versions)
    return out


def _version_fingerprint(versions: set) -> str:
    """The versions an inventory entry named, as one comparable string.

    Compares the pair as a whole, since either CFBundleVersion or CFBundleShortVersionString may change on an upgrade.
    """
    return "/".join(sorted(versions))
