"""Summary fields and RTS compatibility helpers for devices."""
from typing import Any, Dict, List, Optional

from controller.models.tenant import Device
from controller.utils import coerce

_truthy = coerce.truthy


def _os_at_least(os_version: Optional[str], major: int) -> bool:
    """True if the device OS major version is >= major (False if unparseable)."""
    from packaging import version
    try:
        return version.parse(str(os_version or "")).major >= major
    except Exception:
        return False


# ReturnToService floors by model identifier prefix (iOS/iPadOS 17, tvOS 18, visionOS 26; never macOS/watchOS).
# https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/device.erase.yaml

_RTS_FLOORS = (
    ("iphone", "iOS", 17),
    ("ipad", "iPadOS", 17),
    ("ipod", "iOS", 17),
    ("appletv", "tvOS", 18),
    ("realitydevice", "visionOS", 26),
    ("watch", "watchOS", None),
)


def _rts_floor(device_model: Optional[str]) -> tuple:
    """(platform name, first OS major that has Return to Service)."""
    model = (device_model or "").lower().replace(" ", "")
    for prefix, platform, floor in _RTS_FLOORS:
        if model.startswith(prefix):
            return platform, floor
    # MacBook*, Macmini, MacPro, iMac, Mac14,2 and anything else with mac in it.
    if "mac" in model:
        return "macOS", None
    return None, None


# Stable identifiers for the Return-to-Service warnings, paired with the sentences below by position. The sentences are
# written for a person and may be reworded; these codes are the contract and do not change.
RTS_WARNING_NO_WIFI = "no_wifi"
RTS_WARNING_ACTIVATION_LOCK = "activation_lock"


def _rts_warnings(attributes: Dict[str, Any], wifi_ssid: str) -> List[tuple]:
    """What could make a Return-to-Service wipe fail, as (code, sentence) pairs in reading order.

    Both are conditional (warn, not refuse): Wi-Fi is only required when the device has no Ethernet/cellular.
    https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/device.erase.yaml
    """
    warnings: List[tuple] = []
    if not wifi_ssid:
        warnings.append((
            RTS_WARNING_NO_WIFI,
            "No Wi-Fi network was given. The wiped device will only get back to the server if it has Ethernet or "
            "cellular; otherwise it stops at setup with no way to re-enroll.",
        ))
    if attributes.get("IsActivationLockEnabled") is True:
        warnings.append((
            RTS_WARNING_ACTIVATION_LOCK,
            "Activation Lock is on for this device. It has to be turned off before the wipe, or the device stops at "
            "the activation screen and cannot re-enroll.",
        ))
    return warnings


# Exactly the Device columns _device_summary reads. Anything added to _device_summary belongs here too,
# display_name() included, or the name breaks silently for list rows; enforced by tests/verify_devices.py.
_DEVICE_SUMMARY_FIELDS = (
    "id", "udid", "name", "serial_number", "device_model", "os_version",
    "hostname", "groups", "tags", "enrollment_state", "management_type",
    "enrollment_date", "unenrolled_at", "last_seen",
    "last_polled_at", "poll_interval_minutes", "attributes",
    "bootstrap_token_escrowed",
)


def _device_summary(device: Device) -> Dict[str, Any]:
    """Identity + lifecycle fields shared by the list and detail responses."""
    from controller.services.naming import display_name
    return {
        "id": str(device.id),
        "udid": device.udid,
        "name": device.name,
        "display_name": display_name(device),
        "serial_number": device.serial_number,
        "device_model": device.device_model,
        "os_version": device.os_version,
        "hostname": device.hostname,
        "groups": device.groups,
        "tags": device.tags or [],
        "enrollment_state": device.enrollment_state,
        "management_type": device.management_type,
        "enrollment_date": device.enrollment_date,
        "unenrolled_at": device.unenrolled_at,
        "last_seen": device.last_seen,
        # Without these two, a stale last_seen cannot be told apart from the server having stopped asking.
        "last_polled_at": device.last_polled_at,
        "poll_interval_minutes": device.poll_interval_minutes,
        "bootstrap_token_escrowed": device.bootstrap_token_escrowed,
    }
