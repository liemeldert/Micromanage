// Data-driven device property display.
//
// Device.attributes holds whatever the device reports about itself
// (DeviceInformation QueryResponses + a nested SecurityInfo). Rather than a
// hardcoded column per property, we keep a light registry that gives KNOWN keys
// a friendly label, a category (→ tab) and a value formatter. Anything the
// device reports that we don't recognize still shows up automatically -- it just
// lands in the "Other" tab with its raw key. So new MDM keys surface with zero
// code changes, while the ones we care about get first-class presentation.

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
  // ── Hardware ──────────────────────────────────────────────────────────────
  SerialNumber:            { label: "Serial number", category: "Hardware" },
  Model:                   { label: "Model identifier", category: "Hardware" },
  ModelName:               { label: "Model name", category: "Hardware" },
  ProductName:             { label: "Product", category: "Hardware" },
  DeviceName:              { label: "Device name", category: "Hardware" },
  IsAppleSilicon:          { label: "Apple Silicon", category: "Hardware", format: "bool" },
  DeviceCapacity:          { label: "Storage capacity", category: "Hardware", format: "gb" },
  AvailableDeviceCapacity: { label: "Available storage", category: "Hardware", format: "gb" },
  HasBattery:              { label: "Has battery", category: "Hardware", format: "bool" },
  BatteryLevel:            { label: "Battery level", category: "Hardware", format: "percent" },

  // ── Software ──────────────────────────────────────────────────────────────
  OSVersion:                 { label: "OS version", category: "Software" },
  SupplementalBuildVersion:  { label: "Supplemental build", category: "Software" },
  BuildVersion:              { label: "Build", category: "Software" },
  LocalHostName:             { label: "Local hostname", category: "Software" },
  HostName:                  { label: "Hostname", category: "Software" },
  TimeZone:                  { label: "Time zone", category: "Software" },
  ActiveManagedUsers:        { label: "Active managed users", category: "Software" },
  MaximumResidentUsers:      { label: "Max resident users", category: "Software" },
  SoftwareUpdateDeviceID:    { label: "Software update ID", category: "Software" },

  // ── Security ──────────────────────────────────────────────────────────────
  IsSupervised:                     { label: "Supervised", category: "Security", format: "bool" },
  IsActivationLockEnabled:          { label: "Activation Lock", category: "Security", format: "bool" },
  IsMDMLostModeEnabled:             { label: "MDM Lost Mode", category: "Security", format: "bool" },
  IsDeviceLocatorServiceEnabled:    { label: "Find My", category: "Security", format: "bool" },
  IsCloudBackupEnabled:             { label: "iCloud Backup", category: "Security", format: "bool" },
  LastCloudBackupDate:              { label: "Last iCloud backup", category: "Security", format: "date" },
  SystemIntegrityProtectionEnabled: { label: "SIP enabled", category: "Security", format: "bool" },
  PINRequiredForDeviceLock:         { label: "PIN required to lock", category: "Security", format: "bool" },
  PINRequiredForEraseDevice:        { label: "PIN required to erase", category: "Security", format: "bool" },
  // SecurityInfo (flattened from the nested response)
  FDE_Enabled:                      { label: "FileVault enabled", category: "Security", format: "bool" },
  FDE_HasPersonalRecoveryKey:       { label: "FileVault personal key", category: "Security", format: "bool" },
  FDE_HasInstitutionalRecoveryKey:  { label: "FileVault institutional key", category: "Security", format: "bool" },
  FirewallEnabled:                  { label: "Firewall enabled", category: "Security", format: "bool" },
  PasscodePresent:                  { label: "Passcode set", category: "Security", format: "bool" },
  PasscodeCompliant:                { label: "Passcode compliant", category: "Security", format: "bool" },
  PasscodeCompliantWithProfiles:    { label: "Passcode meets profiles", category: "Security", format: "bool" },
  SecureBoot:                       { label: "Secure Boot", category: "Security" },
  RemoteDesktopEnabled:             { label: "Remote Desktop", category: "Security", format: "bool" },

  // ── Network ───────────────────────────────────────────────────────────────
  WiFiMAC:                { label: "Wi-Fi MAC", category: "Network" },
  BluetoothMAC:           { label: "Bluetooth MAC", category: "Network" },
  EthernetMAC:            { label: "Ethernet MAC", category: "Network" },
  IsNetworkTethered:      { label: "Network tethered", category: "Network", format: "bool" },
  PersonalHotspotEnabled: { label: "Personal Hotspot", category: "Network", format: "bool" },
  DataRoamingEnabled:     { label: "Data roaming", category: "Network", format: "bool" },

  // ── Cellular ──────────────────────────────────────────────────────────────
  IMEI:                     { label: "IMEI", category: "Cellular" },
  MEID:                     { label: "MEID", category: "Cellular" },
  ICCID:                    { label: "ICCID", category: "Cellular" },
  PhoneNumber:              { label: "Phone number", category: "Cellular" },
  CellularTechnology:       { label: "Cellular technology", category: "Cellular" },
  ModemFirmwareVersion:     { label: "Modem firmware", category: "Cellular" },
  CurrentCarrierNetwork:    { label: "Carrier", category: "Cellular" },
  CarrierSettingsVersion:   { label: "Carrier settings", category: "Cellular" },

  // ── Management ────────────────────────────────────────────────────────────
  UDID:               { label: "UDID", category: "Management" },
  ProvisioningUDID:   { label: "Provisioning UDID", category: "Management" },
  EASDeviceIdentifier:{ label: "EAS device ID", category: "Management" },
  IsMultiUser:        { label: "Multi-user", category: "Management", format: "bool" },
  AppAnalyticsEnabled:{ label: "App analytics", category: "Management", format: "bool" },
};

function humanizeKey(key: string): string {
  // "SomeCamelCaseKey" / "FDE_Enabled" → "Some Camel Case Key" / "FDE Enabled"
  return key
    .replace(/_/g, " ")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/\b([A-Z]{2,})([A-Z][a-z])/g, "$1 $2")
    .trim();
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
      return Number.isFinite(n) ? `${Math.round(n * 100)}%` : String(value);
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

const META_KEYS = new Set(["Status", "CommandUUID", "UDID_meta"]);

/**
 * Turn a device's raw attributes into ordered, categorized display groups.
 * SecurityInfo is flattened in; unknown keys fall into "Other".
 */
export function organizeAttributes(attributes: Record<string, unknown> | undefined): AttrGroup[] {
  if (!attributes) return [];

  // Flatten the nested SecurityInfo blob alongside the top-level keys.
  const flat: Record<string, unknown> = { ...attributes };
  const sec = attributes.SecurityInfo;
  if (sec && typeof sec === "object" && !Array.isArray(sec)) {
    for (const [k, v] of Object.entries(sec as Record<string, unknown>)) {
      if (!(k in flat)) flat[k] = v;
    }
    delete flat.SecurityInfo;
  }

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
    if (items?.length) ordered.push({ category: cat, items: items.sort((a, b) => a.label.localeCompare(b.label)) });
  }
  const other = groups.get("Other");
  if (other?.length) ordered.push({ category: "Other", items: other.sort((a, b) => a.label.localeCompare(b.label)) });
  return ordered;
}

// A few curated keys for the compact Overview panel.
export const OVERVIEW_KEYS = [
  "OSVersion", "IsSupervised", "FDE_Enabled", "PasscodePresent",
  "AvailableDeviceCapacity", "BatteryLevel", "IsActivationLockEnabled", "LastCloudBackupDate",
];
