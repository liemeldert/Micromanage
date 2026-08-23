"""The profile payload types this server recognizes.

Both sets and the data-key tables further down are copies of their sources, not runtime-read.
See docs/controller/utils/payload_types.md for regeneration and validation details.
"""

from typing import Any

# Generated: the com.apple.* payloadtypes of Apple's mdm/profiles schemas.
_APPLE_DOCUMENTED_PAYLOAD_TYPES = frozenset({
    "com.apple.ADCertificate.managed", "com.apple.AIM.account",
    "com.apple.AssetCache.managed", "com.apple.Dictionary",
    "com.apple.DirectoryService.managed", "com.apple.DiscRecording", "com.apple.MCX",
    "com.apple.MCX.FileVault2", "com.apple.MCX.TimeMachine",
    "com.apple.ManagedClient.preferences", "com.apple.NSExtension",
    "com.apple.SetupAssistant.managed", "com.apple.ShareKitHelper",
    "com.apple.SoftwareUpdate", "com.apple.SystemConfiguration",
    "com.apple.TCC.configuration-profile-policy", "com.apple.airplay",
    "com.apple.airplay.security", "com.apple.airprint", "com.apple.apn.managed",
    "com.apple.app.lock", "com.apple.applicationaccess",
    "com.apple.applicationaccess.new", "com.apple.appstore", "com.apple.asam",
    "com.apple.associated-domains", "com.apple.caldav.account",
    "com.apple.carddav.account", "com.apple.cellular",
    "com.apple.cellularprivatenetwork.managed", "com.apple.conferenceroomdisplay",
    "com.apple.configurationprofile.identification", "com.apple.dashboard",
    "com.apple.declarations", "com.apple.desktop", "com.apple.dnsProxy.managed",
    "com.apple.dnsSettings.managed", "com.apple.dock", "com.apple.domains",
    "com.apple.eas.account", "com.apple.education", "com.apple.ews.account",
    "com.apple.extensiblesso", "com.apple.familycontrols.contentfilter",
    "com.apple.familycontrols.timelimits.v2", "com.apple.fileproviderd",
    "com.apple.finder", "com.apple.firstactiveethernet.managed",
    "com.apple.firstethernet.managed", "com.apple.font", "com.apple.gamed",
    "com.apple.globalethernet.managed", "com.apple.google-oauth",
    "com.apple.homescreenlayout", "com.apple.ironwood.support",
    "com.apple.jabber.account", "com.apple.ldap.account",
    "com.apple.loginitems.managed", "com.apple.loginwindow", "com.apple.lom",
    "com.apple.mail.managed", "com.apple.mcxMenuExtras", "com.apple.mcxloginscripts",
    "com.apple.mcxprinting", "com.apple.mdm", "com.apple.mobiledevice.passwordpolicy",
    "com.apple.networkusagerules", "com.apple.notificationsettings",
    "com.apple.osxserver.account", "com.apple.preference.security",
    "com.apple.preference.users", "com.apple.profileRemovalPassword",
    "com.apple.proxy.http.global", "com.apple.relay.managed", "com.apple.screensaver",
    "com.apple.screensaver.user", "com.apple.secondactiveethernet.managed",
    "com.apple.secondethernet.managed", "com.apple.security.FDERecoveryKeyEscrow",
    "com.apple.security.FDERecoveryRedirect", "com.apple.security.acme",
    "com.apple.security.certificatepreference",
    "com.apple.security.certificaterevocation",
    "com.apple.security.certificatetransparency", "com.apple.security.firewall",
    "com.apple.security.identitypreference", "com.apple.security.pem",
    "com.apple.security.pkcs1", "com.apple.security.pkcs12", "com.apple.security.root",
    "com.apple.security.scep", "com.apple.security.smartcard",
    "com.apple.servicemanagement", "com.apple.shareddeviceconfiguration",
    "com.apple.sso", "com.apple.subscribedcalendar.account",
    "com.apple.syspolicy.kernel-extension-policy", "com.apple.system-extension-policy",
    "com.apple.system.logging", "com.apple.systemmigration",
    "com.apple.systempolicy.control", "com.apple.systempolicy.managed",
    "com.apple.systempolicy.rule", "com.apple.systempreferences",
    "com.apple.systemuiserver", "com.apple.thirdactiveethernet.managed",
    "com.apple.thirdethernet.managed", "com.apple.tvremote",
    "com.apple.universalaccess", "com.apple.vpn.managed",
    "com.apple.vpn.managed.applayer", "com.apple.vpn.managed.appmapping",
    "com.apple.webClip.managed", "com.apple.webcontent-filter",
    "com.apple.wifi.managed", "com.apple.xsan", "com.apple.xsan.preferences",
})

# Generated: the domains of webui/lib/manifests.generated.json.
_MANIFEST_PAYLOAD_TYPES = frozenset({
    "com.apple.ADCertificate.managed", "com.apple.AIM.account",
    "com.apple.AssetCache.managed", "com.apple.Dictionary",
    "com.apple.DirectoryService.managed", "com.apple.DiscRecording", "com.apple.MCX",
    "com.apple.MCX.FileVault2", "com.apple.MCX.TimeMachine", "com.apple.NSExtension",
    "com.apple.SetupAssistant.managed", "com.apple.ShareKitHelper",
    "com.apple.SoftwareUpdate", "com.apple.SubmitDiagInfo",
    "com.apple.SystemConfiguration", "com.apple.TCC.configuration-profile-policy",
    "com.apple.airplay", "com.apple.airplay.security", "com.apple.airprint",
    "com.apple.app.lock", "com.apple.applicationaccess",
    "com.apple.applicationaccess.new", "com.apple.appstore", "com.apple.asam",
    "com.apple.associated-domains", "com.apple.caldav.account",
    "com.apple.carddav.account", "com.apple.cellular",
    "com.apple.cellularprivatenetwork.managed", "com.apple.conferenceroomdisplay",
    "com.apple.configurationprofile.identification", "com.apple.dashboard",
    "com.apple.declarations", "com.apple.desktop", "com.apple.dnsProxy.managed",
    "com.apple.dnsSettings.managed", "com.apple.dock", "com.apple.domains",
    "com.apple.eas.account", "com.apple.education", "com.apple.ews.account",
    "com.apple.extensiblesso", "com.apple.familycontrols.contentfilter",
    "com.apple.familycontrols.timelimits.v2", "com.apple.fileproviderd",
    "com.apple.finder", "com.apple.firstactiveethernet.managed",
    "com.apple.firstethernet.managed", "com.apple.font", "com.apple.gamed",
    "com.apple.globalethernet.managed", "com.apple.google-oauth",
    "com.apple.ironwood.support", "com.apple.jabber.account", "com.apple.ldap.account",
    "com.apple.loginitems.managed", "com.apple.loginwindow", "com.apple.lom",
    "com.apple.mail.managed", "com.apple.mcxloginscripts", "com.apple.mcxprinting",
    "com.apple.mdm", "com.apple.mobiledevice.passwordpolicy",
    "com.apple.networkusagerules", "com.apple.notificationsettings",
    "com.apple.osxserver.account", "com.apple.preference.security",
    "com.apple.profileRemovalPassword", "com.apple.proxy.http.global",
    "com.apple.relay.managed", "com.apple.screensaver", "com.apple.screensaver.user",
    "com.apple.secondactiveethernet.managed", "com.apple.secondethernet.managed",
    "com.apple.security.FDERecoveryKeyEscrow",
    "com.apple.security.FDERecoveryRedirect", "com.apple.security.acme",
    "com.apple.security.certificatepreference",
    "com.apple.security.certificatetransparency", "com.apple.security.firewall",
    "com.apple.security.pem", "com.apple.security.pkcs1", "com.apple.security.pkcs12",
    "com.apple.security.root", "com.apple.security.scep",
    "com.apple.security.smartcard", "com.apple.servicemanagement",
    "com.apple.shareddeviceconfiguration", "com.apple.sso",
    "com.apple.subscribedcalendar.account",
    "com.apple.syspolicy.kernel-extension-policy", "com.apple.system-extension-policy",
    "com.apple.system.logging", "com.apple.systemmigration",
    "com.apple.systempolicy.control", "com.apple.systempolicy.managed",
    "com.apple.systempreferences", "com.apple.systemuiserver",
    "com.apple.thirdactiveethernet.managed", "com.apple.thirdethernet.managed",
    "com.apple.tvremote", "com.apple.universalaccess", "com.apple.webClip.managed",
    "com.apple.webcontent-filter", "com.apple.wifi.managed", "com.apple.xsan",
    "com.apple.xsan.preferences", "loginwindow",
})

KNOWN_PAYLOAD_TYPES = _APPLE_DOCUMENTED_PAYLOAD_TYPES | _MANIFEST_PAYLOAD_TYPES


def is_undocumented_apple_payload_type(payload_type: Any) -> bool:
    """True for a payload type in Apple's namespace that neither known set describes; matching is exact including case."""
    name = str(payload_type or "").strip()
    return name.startswith("com.apple.") and name not in KNOWN_PAYLOAD_TYPES


# Payload keys that must be decoded from base64 to bytes for plist <data> tags.
# Not all <data> keys are base64 (e.g. SharedSecret, script text); see data_keys_for_profile for per-profile overrides.
DATA_PAYLOAD_KEYS = {
    "com.apple.MCX.FileVault2": frozenset({"Certificate"}),
    "com.apple.applicationaccess.new": frozenset({"detachedSignature"}),
    "com.apple.eas.account": frozenset({"Certificate"}),
    "com.apple.font": frozenset({"Font"}),
    "com.apple.relay.managed": frozenset({"RawPublicKeys"}),
    "com.apple.security.certificaterevocation": frozenset({"Hash"}),
    "com.apple.security.certificatetransparency": frozenset({"Hash"}),
    "com.apple.security.pem": frozenset({"PayloadContent"}),
    "com.apple.security.pkcs1": frozenset({"PayloadContent"}),
    "com.apple.security.pkcs12": frozenset({"PayloadContent"}),
    "com.apple.security.root": frozenset({"PayloadContent"}),
    "com.apple.security.scep": frozenset({"CAFingerprint"}),
    "com.apple.systempolicy.rule": frozenset({"LeafCertificate"}),
    "com.apple.webClip.managed": frozenset({"Icon"}),
    "com.barebones.bbedit": frozenset({"BBEditorFont", "BBPrintingFont"}),
    "com.jamf.connect.sync": frozenset({"LicenseFile"}),
    "com.twocanoes.xcreds": frozenset({"menuItemIconCheckedData", "menuItemIconData"}),
    "menu.nomad.NoMADPro": frozenset({"LicenseFile"}),
    "menu.nomad.login.ad": frozenset({"BackgroundImageData", "LoginLogoData"}),
}

# Dictionary and array keys containing the data keys above; only domains with nested data keys appear.
DATA_PAYLOAD_CONTAINERS = {
    "com.apple.applicationaccess.new": frozenset({"subApps", "whiteList"}),
    "com.apple.relay.managed": frozenset({"Relays"}),
    "com.apple.security.certificaterevocation": frozenset({"EnabledForCerts"}),
    "com.apple.security.certificatetransparency": frozenset({"DisabledForCerts"}),
    "com.apple.security.scep": frozenset({"PayloadContent"}),
}


def data_keys_for(payload_type: Any) -> frozenset:
    """The keys of payload_type that a plist carries as <data>."""
    return DATA_PAYLOAD_KEYS.get(str(payload_type or ""), frozenset())


def data_containers_for(payload_type: Any) -> frozenset:
    """The container keys payload_type's data keys are nested under."""
    return DATA_PAYLOAD_CONTAINERS.get(str(payload_type or ""), frozenset())


def data_keys_for_profile(profile_info: Any, payload_type: Any) -> frozenset:
    """Data keys for one payload: the static table's plus any declared in the profile under data_keys."""
    declared = profile_info.get('data_keys') if isinstance(profile_info, dict) else None
    return data_keys_for(payload_type) | frozenset(declared or [])
