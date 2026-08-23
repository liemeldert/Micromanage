"""Setup Assistant panes an ADE profile can skip (skip_setup_items).

Curated from https://github.com/apple/device-management/blob/release/other/skipkeys.yaml and served at GET
/api/v1/dep/skip-keys. See https://developer.apple.com/documentation/devicemanagement/define-profile for context.
"""

from typing import Dict, List, Tuple

# name -> (label, platform hint, deprecated)
_SKIP_KEYS: Dict[str, Tuple[str, str, bool]] = {
    "Accessibility": ("Accessibility (new user only)", "macOS 11+", False),
    "ActionButton": ("Action Button", "iOS 17+", False),
    "Android": ("Migrate from Android", "iOS 9+", False),
    "Appearance": ("Appearance (Light/Dark)", "iOS 13+, macOS 10.14+", False),
    "AppleID": ("Apple ID sign-in", "iOS, macOS, tvOS", False),
    "AppStore": ("App Store", "iOS 14.3+, macOS 11.1+", False),
    "Biometric": ("Touch ID / Face ID", "iOS 8.1+, macOS 10.12.4+", False),
    "CameraButton": ("Camera Control", "iOS 18+", False),
    "DeviceToDeviceMigration": ("Device-to-Device Migration", "iOS 12.4+", False),
    "Diagnostics": ("Diagnostics / Analytics", "iOS, macOS, tvOS", False),
    "DisplayTone": ("Display Tone", "iOS 9.3.2+, macOS 10.13.6+", True),
    "EnableLockdownMode": ("Enable Lockdown Mode", "iOS 17.1+, macOS 14+", False),
    "FileVault": ("FileVault", "macOS 10.10+", False),
    "HomeButtonSensitivity": ("Home Button Sensitivity", "iOS 10+", True),
    "iCloudDiagnostics": ("iCloud Analytics", "macOS 10.12.4+", False),
    "iCloudStorage": ("iCloud Documents & Desktop", "macOS 10.13.4+", False),
    "iMessageAndFaceTime": ("iMessage & FaceTime", "iOS 12+", False),
    "Intelligence": ("Apple Intelligence", "iOS 18+, macOS 15+", False),
    "Keyboard": ("Keyboard", "iOS 13+", False),
    "Location": ("Location Services", "iOS, macOS 10.11+, tvOS", False),
    "MessagingActivationUsingPhoneNumber": ("Messaging Activation", "iOS 10+", False),
    "Multitasking": ("Multitasking (iPad)", "iOS 26+", False),
    "OnBoarding": ("Onboarding", "iOS 11+", True),
    "OSShowcase": ("OS Showcase", "iOS 26+, macOS 26.1+", False),
    "Passcode": ("Passcode / Lock", "iOS, macOS", False),
    "Payment": ("Apple Pay", "iOS 8.1+, macOS 10.12.4+", False),
    "Privacy": ("Privacy", "iOS 11.3+, macOS 10.13.4+, tvOS 11.3+", False),
    "Restore": ("Apps & Data / Restore", "iOS, macOS", False),
    "RestoreCompleted": ("Restore Completed", "iOS 14+", False),
    "Safety": ("Safety", "iOS 16+", False),
    "SafetyAndHandling": ("Safety and Handling", "iOS 18.4+", False),
    "ScreenSaver": ("Screen Saver", "tvOS", False),
    "ScreenTime": ("Screen Time", "iOS 12+, macOS 10.15+", False),
    "SIMSetup": ("SIM Setup", "iOS 12+", False),
    "Siri": ("Siri", "iOS, macOS 10.12+, tvOS", False),
    "SoftwareUpdate": ("Mandatory Software Update", "iOS 12+, macOS 15.4+", False),
    "SpokenLanguage": ("Spoken Language", "iOS 13+", False),
    "TapToSetup": ("Tap to Set Up", "tvOS", False),
    "TermsOfAddress": ("Terms of Address", "iOS 16+, macOS 13+", False),
    "Tips": ("Tips", "visionOS 26+", False),
    "TOS": ("Terms of Service", "iOS, macOS, tvOS", False),
    "TVHomeScreenSync": ("TV Home Screen Sync", "tvOS 11+", False),
    "TVProviderSignIn": ("TV Provider Sign-In", "tvOS 11+", False),
    "TVRoom": ("TV Room", "tvOS 11.4+", False),
    "UnlockWithWatch": ("Unlock with Apple Watch", "macOS 15+", False),
    "UpdateCompleted": ("Update Completed", "iOS 14+, macOS 26.1+", False),
    "Wallpaper": ("Wallpaper", "macOS 14.1+, gone in macOS 26", True),
    "WatchMigration": ("Watch Migration", "iOS 11+", False),
    "WebContentFiltering": ("Web Content Filtering", "iOS 18.2+", False),
    "Welcome": ("Welcome / Get Started", "iOS 13+, macOS 15+", False),
    "Zoom": ("Zoom", "iOS 8.3+", True),
}

VALID_SKIP_KEYS = frozenset(_SKIP_KEYS.keys())


def catalog() -> List[Dict[str, object]]:
    """Every known skip key with its label, platform hint and deprecation flag, sorted by name."""
    return [
        {"name": name, "label": label, "platforms": platforms, "deprecated": dep}
        for name, (label, platforms, dep) in sorted(_SKIP_KEYS.items())
    ]


def filter_valid_skip_keys(keys: List[str]) -> Tuple[List[str], List[str]]:
    """Split a requested skip-key list into (valid, unknown), de-duplicated and in input order."""
    valid, unknown, seen = [], [], set()
    for k in keys:
        if k in seen:
            continue
        seen.add(k)
        (valid if k in VALID_SKIP_KEYS else unknown).append(k)
    return valid, unknown
