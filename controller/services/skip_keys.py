"""Apple ADE Setup-Assistant SkipKeys registry (the valid ``skip_setup_items``).

Curated from Apple's machine-readable list
(https://github.com/apple/device-management/blob/release/other/skipkeys.yaml) and the
``SkipKeys`` doc. Published to the UI via ``GET /api/v1/dep/skip-keys`` so the DEP
profile editor offers a labelled picker.

Apple adds keys per OS release; the validator therefore *warns* on an unknown key
rather than erroring (a newer key must not block a valid profile). ``filter_valid_skip_keys``
keeps only known keys when building the Apple /profile payload, so an unknown key is
silently dropped there (Apple would reject the whole profile otherwise).
"""

from typing import Dict, List, Tuple

# name -> (label, platform hint, deprecated)
_SKIP_KEYS: Dict[str, Tuple[str, str, bool]] = {
    "Accessibility": ("Accessibility", "iOS, tvOS", False),
    "AccessibilityAppearance": ("Accessibility Appearance", "iOS", False),
    "ActionButton": ("Action Button", "iOS", False),
    "Android": ("Migrate from Android", "iOS", False),
    "Appearance": ("Appearance (Light/Dark)", "iOS, macOS", False),
    "AppleID": ("Apple ID sign-in", "iOS, macOS, tvOS", False),
    "AppStore": ("App Store", "macOS", False),
    "Biometric": ("Touch ID / Face ID", "iOS, macOS", False),
    "CameraButton": ("Camera Button", "iOS", False),
    "DeviceToDeviceMigration": ("Device-to-Device Migration", "iOS", False),
    "Diagnostics": ("Diagnostics / Analytics", "iOS, macOS, tvOS", False),
    "DisplayTone": ("Display Tone", "iOS", True),
    "EnableLockdownMode": ("Enable Lockdown Mode", "iOS", False),
    "FileVault": ("FileVault", "macOS", False),
    "HomeButtonSensitivity": ("Home Button Sensitivity", "iOS", True),
    "iCloudDiagnostics": ("iCloud Analytics", "iOS, macOS", False),
    "iCloudStorage": ("iCloud Documents & Desktop", "iOS, macOS", False),
    "iMessageAndFaceTime": ("iMessage & FaceTime", "iOS", False),
    "Intelligence": ("Apple Intelligence", "iOS, macOS", False),
    "Keyboard": ("Keyboard", "iOS", False),
    "LiquidGlass": ("Liquid Glass", "iOS, macOS", False),
    "Location": ("Location Services", "iOS, macOS, tvOS", False),
    "MessagingActivationUsingPhoneNumber": ("Messaging Activation", "iOS", False),
    "Multitasking": ("Multitasking (iPad)", "iOS", False),
    "OnBoarding": ("Onboarding", "iOS", True),
    "OSShowcase": ("OS Showcase", "iOS, macOS", False),
    "Passcode": ("Passcode / Lock", "iOS, macOS", False),
    "Payment": ("Apple Pay", "iOS, macOS", False),
    "Privacy": ("Privacy", "iOS, macOS, tvOS", False),
    "Restore": ("Apps & Data / Restore", "iOS, macOS", False),
    "RestoreCompleted": ("Restore Completed", "iOS", False),
    "Safety": ("Safety", "iOS", False),
    "SafetyAndHandling": ("Safety and Handling", "iOS", False),
    "ScreenSaver": ("Screen Saver", "tvOS", False),
    "ScreenTime": ("Screen Time", "iOS, macOS", False),
    "SIMSetup": ("SIM Setup", "iOS", False),
    "Siri": ("Siri", "iOS, macOS, tvOS", False),
    "SoftwareUpdate": ("Mandatory Software Update", "iOS", False),
    "SpokenLanguage": ("Spoken Language", "iOS", False),
    "TapToSetup": ("Tap to Set Up", "tvOS", False),
    "TermsOfAddress": ("Terms of Address", "iOS, macOS", False),
    "Tips": ("Tips", "iOS", False),
    "TOS": ("Terms of Service", "iOS, macOS, tvOS", False),
    "TVHomeScreenSync": ("TV Home Screen Sync", "tvOS", False),
    "TVProviderSignIn": ("TV Provider Sign-In", "tvOS", False),
    "TVRoom": ("TV Room", "tvOS", False),
    "UnlockWithWatch": ("Unlock with Apple Watch", "macOS", False),
    "UpdateCompleted": ("Update Completed", "iOS", False),
    "Wallpaper": ("Wallpaper", "iOS", True),
    "WatchMigration": ("Watch Migration", "iOS", False),
    "WebContentFiltering": ("Web Content Filtering", "iOS", False),
    "Welcome": ("Welcome / Get Started", "iOS, macOS", False),
    "Zoom": ("Zoom", "iOS", True),
}

VALID_SKIP_KEYS = frozenset(_SKIP_KEYS.keys())


def catalog() -> List[Dict[str, object]]:
    """The published SkipKeys catalog for the UI picker."""
    return [
        {"name": name, "label": label, "platforms": platforms, "deprecated": dep}
        for name, (label, platforms, dep) in sorted(_SKIP_KEYS.items())
    ]


def filter_valid_skip_keys(keys: List[str]) -> Tuple[List[str], List[str]]:
    """Split a requested skip-key list into (valid, unknown), de-duplicated and in
    input order."""
    valid, unknown, seen = [], [], set()
    for k in keys:
        if k in seen:
            continue
        seen.add(k)
        (valid if k in VALID_SKIP_KEYS else unknown).append(k)
    return valid, unknown
