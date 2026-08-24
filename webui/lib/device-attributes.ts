// Registry over the keys in Device.attributes, which holds what the device reports about itself
// (DeviceInformation QueryResponses plus a nested SecurityInfo). A known key gets a label, a category
// that becomes a tab, and a formatter. An unknown key still renders, under its raw key in "Other".

export type AttrCategory =
    | "Hardware"
    | "Software"
    | "Security"
    | "Network"
    | "Cellular"
    | "Management";

export type AttrFormat = "text" | "bool" | "gb" | "date" | "percent";

interface AttrDef {
    label: string;
    category: AttrCategory;
    format?: AttrFormat;
}

// Order here is also the tab order.
export const ATTR_CATEGORIES: AttrCategory[] = [
    "Hardware", "Software", "Security", "Network", "Cellular", "Management",
];

const ATTRS: Record<string, AttrDef> = {
    //  Hardware
    SerialNumber: {label: "Serial number", category: "Hardware"},
    Model: {label: "Model identifier", category: "Hardware"},
    ModelName: {label: "Model name", category: "Hardware"},
    ProductName: {label: "Product", category: "Hardware"},
    DeviceName: {label: "Device name", category: "Hardware"},
    IsAppleSilicon: {label: "Apple silicon", category: "Hardware", format: "bool"},
    DeviceCapacity: {label: "Storage capacity", category: "Hardware", format: "gb"},
    AvailableDeviceCapacity: {label: "Available storage", category: "Hardware", format: "gb"},
    HasBattery: {label: "Has battery", category: "Hardware", format: "bool"},
    BatteryLevel: {label: "Battery level", category: "Hardware", format: "percent"},

    //  Software
    OSVersion: {label: "OS version", category: "Software"},
    SupplementalBuildVersion: {label: "Supplemental build", category: "Software"},
    BuildVersion: {label: "Build", category: "Software"},
    LocalHostName: {label: "Local hostname", category: "Software"},
    HostName: {label: "Hostname", category: "Software"},
    TimeZone: {label: "Time zone", category: "Software"},
    ActiveManagedUsers: {label: "Active managed users", category: "Software"},
    MaximumResidentUsers: {label: "Max resident users", category: "Software"},
    SoftwareUpdateDeviceID: {label: "Software update ID", category: "Software"},

    //  Security
    IsSupervised: {label: "Supervised", category: "Security", format: "bool"},
    IsActivationLockEnabled: {label: "Activation Lock", category: "Security", format: "bool"},
    IsMDMLostModeEnabled: {label: "MDM Lost Mode", category: "Security", format: "bool"},
    IsDeviceLocatorServiceEnabled: {label: "Find My", category: "Security", format: "bool"},
    IsCloudBackupEnabled: {label: "iCloud Backup", category: "Security", format: "bool"},
    LastCloudBackupDate: {label: "Last iCloud backup", category: "Security", format: "date"},
    SystemIntegrityProtectionEnabled: {label: "SIP enabled", category: "Security", format: "bool"},
    PINRequiredForDeviceLock: {label: "PIN required to lock", category: "Security", format: "bool"},
    PINRequiredForEraseDevice: {label: "PIN required to erase", category: "Security", format: "bool"},
    // Flattened out of the nested SecurityInfo by organizeAttributes below.
    FDE_Enabled: {label: "FileVault enabled", category: "Security", format: "bool"},
    FDE_HasPersonalRecoveryKey: {label: "FileVault personal key", category: "Security", format: "bool"},
    FDE_HasInstitutionalRecoveryKey: {label: "FileVault institutional key", category: "Security", format: "bool"},
    // Also where FirewallSettings.FirewallEnabled lands once flattened, so both spellings share a label.
    FirewallEnabled: {label: "Firewall enabled", category: "Security", format: "bool"},
    BlockAllIncoming: {label: "Block all incoming connections", category: "Security", format: "bool"},
    StealthMode: {label: "Stealth mode", category: "Security", format: "bool"},
    // Apple's SecurityInfo schema lists these two keys without describing them. The labels are read off
    // the matching com.apple.alf preferences (allowsignedenabled, allowdownloadsignedenabled), which is
    // a fair reading of them and not something the MDM schema states.
    AllowSigned: {label: "Allow signed built-in software", category: "Security", format: "bool"},
    AllowSignedApp: {label: "Allow signed downloaded apps", category: "Security", format: "bool"},
    Applications: {label: "Firewall app exceptions", category: "Security"},
    EnrolledViaDEP: {label: "Enrolled via DEP", category: "Security", format: "bool"},
    IsUserEnrollment: {label: "User enrollment", category: "Security", format: "bool"},
    UserApprovedEnrollment: {label: "User approved enrollment", category: "Security", format: "bool"},
    IsActivationLockManageable: {label: "Activation Lock manageable", category: "Security", format: "bool"},
    SecureBootLevel: {label: "Secure boot level", category: "Security"},
    ExternalBootLevel: {label: "External boot level", category: "Security"},
    WindowsBootLevel: {label: "Windows boot level (Boot Camp)", category: "Security"},
    PasscodePresent: {label: "Passcode set", category: "Security", format: "bool"},
    PasscodeCompliant: {label: "Passcode compliant", category: "Security", format: "bool"},
    PasscodeCompliantWithProfiles: {label: "Passcode meets profiles", category: "Security", format: "bool"},
    RemoteDesktopEnabled: {label: "Remote Desktop", category: "Security", format: "bool"},

    //  Network
    WiFiMAC: {label: "Wi-Fi MAC", category: "Network"},
    BluetoothMAC: {label: "Bluetooth MAC", category: "Network"},
    EthernetMAC: {label: "Ethernet MAC", category: "Network"},
    IsNetworkTethered: {label: "Network tethered", category: "Network", format: "bool"},
    PersonalHotspotEnabled: {label: "Personal Hotspot", category: "Network", format: "bool"},
    DataRoamingEnabled: {label: "Data roaming", category: "Network", format: "bool"},

    //  Cellular
    IMEI: {label: "IMEI", category: "Cellular"},
    MEID: {label: "MEID", category: "Cellular"},
    ICCID: {label: "ICCID", category: "Cellular"},
    PhoneNumber: {label: "Phone number", category: "Cellular"},
    CellularTechnology: {label: "Cellular technology", category: "Cellular"},
    ModemFirmwareVersion: {label: "Modem firmware", category: "Cellular"},
    CurrentCarrierNetwork: {label: "Carrier", category: "Cellular"},
    CarrierSettingsVersion: {label: "Carrier settings", category: "Cellular"},

    //  Management
    UDID: {label: "UDID", category: "Management"},
    ProvisioningUDID: {label: "Provisioning UDID", category: "Management"},
    EASDeviceIdentifier: {label: "EAS device ID", category: "Management"},
    IsMultiUser: {label: "Multi-user", category: "Management", format: "bool"},
    AppAnalyticsEnabled: {label: "App analytics", category: "Management", format: "bool"},
};

function humanizeKey(key: string): string {
    // "SomeCamelCaseKey" / "FDE_Enabled" -> "Some Camel Case Key" / "FDE Enabled"
    const words = key
        .replace(/_/g, " ")
        .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
        .replace(/\b([A-Z]{2,})([A-Z][a-z])/g, "$1 $2")
        .trim();
    // Capitalize so lower-case server keys such as enrollment_source match the rest of the Other list.
    return words.charAt(0).toUpperCase() + words.slice(1);
}

export function formatAttrValue(value: unknown, format?: AttrFormat): string {
    if (value === null || value === undefined || value === "") return "--";
    if (Array.isArray(value) || (typeof value === "object")) {
        return JSON.stringify(value);
    }
    switch (format) {
        case "bool":
            return value === true ? "Yes" : value === false ? "No" : String(value);
        case "gb": {
            const n = Number(value);
            return Number.isFinite(n) ? `${n.toFixed(1)} GB` : String(value);
        }
        case "percent": {
            const n = Number(value);
            // -1 is Apple's sentinel for not applicable, and nothing formatted here has a real
            // negative percentage, so both read as unreported.
            if (!Number.isFinite(n) || n < 0) return "--";
            return `${Math.round(n * 100)}%`;
        }
        case "date": {
            const d = new Date(String(value));
            return isNaN(d.getTime()) ? String(value) : d.toLocaleString();
        }
        default:
            return String(value);
    }
}

export interface AttrItem {
    key: string;
    label: string;
    value: string;
    isBool: boolean;
    boolValue?: boolean;
}

export interface AttrGroup {
    category: AttrCategory | "Other";
    items: AttrItem[];
}

// ddm_sync_failure is controller bookkeeping rather than a device report, and a failed sync already
// shows on the Commands and Activity surfaces.
const META_KEYS = new Set(["Status", "CommandUUID", "UDID_meta", "ddm_sync_failure"]);

/**
 * Turn a device's raw attributes into ordered, categorized display groups.
 * SecurityInfo is flattened in; unknown keys fall into "Other".
 */
export function organizeAttributes(attributes: Record<string, unknown> | undefined): AttrGroup[] {
    if (!attributes) return [];

    // Flatten SecurityInfo alongside the top-level keys. FirewallSettings, ManagementStatus and
    // SecureBoot hold dictionaries and go one level further, or each renders as a row of raw JSON.
    const flat: Record<string, unknown> = {...attributes};
    const sec = attributes.SecurityInfo;
    const NESTED_SECURITY_GROUPS = new Set(["FirewallSettings", "ManagementStatus", "SecureBoot"]);
    if (sec && typeof sec === "object" && !Array.isArray(sec)) {
        for (const [k, v] of Object.entries(sec as Record<string, unknown>)) {
            if (NESTED_SECURITY_GROUPS.has(k) && v && typeof v === "object" && !Array.isArray(v)) {
                for (const [k2, v2] of Object.entries(v as Record<string, unknown>)) {
                    if (!(k2 in flat)) flat[k2] = v2;
                }
            } else if (!(k in flat)) {
                flat[k] = v;
            }
        }
        delete flat.SecurityInfo;
    }

    // Hardware with no battery still reports BatteryLevel as -1, so drop the row instead of showing
    // a placeholder next to "Has battery: No".
    if (flat.HasBattery === false) delete flat.BatteryLevel;

    const groups = new Map<AttrCategory | "Other", AttrItem[]>();
    const push = (cat: AttrCategory | "Other", item: AttrItem) => {
        if (!groups.has(cat)) groups.set(cat, []);
        groups.get(cat)!.push(item);
    };

    for (const [key, value] of Object.entries(flat)) {
        if (META_KEYS.has(key)) continue;
        const def = ATTRS[key];
        const isBool = def?.format === "bool" || typeof value === "boolean";
        push(def?.category ?? "Other", {
            key,
            label: def?.label ?? humanizeKey(key),
            value: formatAttrValue(value, def?.format),
            isBool,
            boolValue: typeof value === "boolean" ? value : undefined,
        });
    }

    const ordered: AttrGroup[] = [];
    for (const cat of ATTR_CATEGORIES) {
        const items = groups.get(cat);
        if (items?.length) ordered.push({category: cat, items: items.sort((a, b) => a.label.localeCompare(b.label))});
    }
    const other = groups.get("Other");
    if (other?.length) ordered.push({category: "Other", items: other.sort((a, b) => a.label.localeCompare(b.label))});
    return ordered;
}

// Flatten a nested object into dot-path leaves, turning a nested active count into the single path
// management.declarations.active. Used for DDM StatusItems, which have no fixed schema to register.
export interface DotPathItem {
    path: string;
    value: string;
    isBool: boolean;
    boolValue?: boolean;
}

export function flattenToDotPaths(
    obj: Record<string, unknown> | undefined | null,
    prefix = "",
): DotPathItem[] {
    if (!obj || typeof obj !== "object") return [];
    const out: DotPathItem[] = [];
    for (const [key, value] of Object.entries(obj)) {
        const path = prefix ? `${prefix}.${key}` : key;
        if (value !== null && typeof value === "object" && !Array.isArray(value)) {
            out.push(...flattenToDotPaths(value as Record<string, unknown>, path));
        } else {
            out.push({
                path,
                value: formatAttrValue(value),
                isBool: typeof value === "boolean",
                boolValue: typeof value === "boolean" ? value : undefined,
            });
        }
    }
    return out;
}
