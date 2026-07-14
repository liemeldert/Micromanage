// Payload manifests for the profile editor. The bulk are GENERATED from the
// community ProfileManifests project (run `python3 webui/scripts/build-manifests.py`)
// into manifests.generated.json, so the editor always has the *full* key set for
// each payload type (e.g. ~200 Restrictions keys) rather than a hand-curated
// subset. A couple of hand-authored manifests (VPN, the synthetic DEP/enrollment
// form) are appended.

import generated from "./manifests.generated.json";

export type Platform = "iOS" | "macOS" | "tvOS";
export const ALL_PLATFORMS: Platform[] = ["iOS", "macOS", "tvOS"];

export type FieldType =
  | "string"
  | "integer"
  | "real"
  | "boolean"
  | "array"
  | "dictionary"
  | "data"
  | "date";

export interface ManifestField {
  name: string;
  title: string;
  description?: string;
  type: FieldType;
  default?: unknown;
  required?: boolean;
  options?: string[];
  optionLabels?: Record<string, string>;
  min?: number;
  max?: number;
  secret?: boolean;
  placeholder?: string;
  supervised?: boolean; // requires the device to be supervised
  platforms?: string[]; // platforms this key applies to (subset of the manifest's)
  parent?: string; // nested container key (e.g. "PayloadContent" for SCEP/certs)
}

export type PayloadCategory =
  | "Network"
  | "Security"
  | "Certificates"
  | "Accounts"
  | "Web"
  | "Restrictions"
  | "System"
  | "Other";

export interface PayloadManifest {
  domain: string;
  title: string;
  description?: string;
  category: PayloadCategory;
  platforms: string[];
  multiple?: boolean;
  fields: ManifestField[];
}

const GENERATED = generated as unknown as PayloadManifest[];

// VPN's manifest filename differs upstream; keep a focused hand-authored entry.
const VPN: PayloadManifest = {
  domain: "com.apple.vpn.managed",
  title: "VPN",
  description: "Configure a VPN connection.",
  category: "Network",
  platforms: ["iOS", "macOS"],
  multiple: true,
  fields: [
    { name: "UserDefinedName", title: "Connection name", type: "string", required: true },
    { name: "VPNType", title: "Connection type", type: "string", default: "IKEv2",
      options: ["IKEv2", "IPSec", "L2TP", "VPN", "AlwaysOn"] },
    { name: "OnDemandEnabled", title: "Connect on demand", type: "integer", default: 0, min: 0, max: 1 },
    { name: "IKEv2", title: "IKEv2 settings", type: "dictionary",
      description: "RemoteAddress, RemoteIdentifier, AuthenticationMethod, etc. Edit as JSON." },
    { name: "IPSec", title: "IPSec settings", type: "dictionary", description: "Cisco IPSec settings. Edit as JSON." },
    { name: "PPP", title: "PPP settings (L2TP)", type: "dictionary", description: "Edit as JSON." },
  ],
};

export const PAYLOAD_MANIFESTS: PayloadManifest[] = [...GENERATED, VPN];

export function getManifest(domain: string | undefined | null): PayloadManifest | undefined {
  if (!domain) return undefined;
  return PAYLOAD_MANIFESTS.find((m) => m.domain === domain);
}

export function manifestSupportsPlatforms(m: PayloadManifest, platforms?: Platform[]): boolean {
  if (!platforms || platforms.length === 0) return true;
  return m.platforms.some((p) => platforms.includes(p as Platform));
}

export function fieldSupportsPlatforms(f: ManifestField, platforms?: Platform[]): boolean {
  if (!platforms || platforms.length === 0) return true;
  if (!f.platforms || f.platforms.length === 0) return true;
  return f.platforms.some((p) => platforms.includes(p as Platform));
}

export function manifestsByCategory(
  platforms?: Platform[],
): { category: PayloadCategory; items: PayloadManifest[] }[] {
  const cats: PayloadCategory[] = [
    "Network", "Security", "Certificates", "Accounts", "Web", "Restrictions", "System", "Other",
  ];
  return cats
    .map((category) => ({
      category,
      items: PAYLOAD_MANIFESTS.filter(
        (m) => m.category === category && manifestSupportsPlatforms(m, platforms),
      ),
    }))
    .filter((g) => g.items.length > 0);
}

export function blankPayload(m: PayloadManifest): Record<string, unknown> {
  const out: Record<string, unknown> = { PayloadType: m.domain };
  for (const f of m.fields) {
    if (f.required && f.default !== undefined) out[f.name] = f.default;
  }
  return out;
}

//  Enrollment (Automated Device Enrollment / DEP) manifest 

// Setup Assistant panes that can be skipped (skip_setup_items). Mirrors the
// controller's skip-keys registry (controller/services/skip_keys.py, itself from
// Apple's skipkeys.yaml). The controller drops any key it doesn't recognise, so an
// out-of-date entry here is harmless; the DEP profile editor also offers the live
// list from GET /api/v1/dep/skip-keys.
export const SETUP_PANE_OPTIONS = [
  "Accessibility", "Android", "Appearance", "AppleID", "AppStore", "Biometric",
  "DeviceToDeviceMigration", "Diagnostics", "FileVault", "iCloudDiagnostics",
  "iCloudStorage", "iMessageAndFaceTime", "Intelligence", "Keyboard", "Location",
  "Passcode", "Payment", "Privacy", "Restore", "RestoreCompleted", "Safety",
  "ScreenTime", "SIMSetup", "Siri", "SoftwareUpdate", "TermsOfAddress", "Tips",
  "TOS", "TVHomeScreenSync", "TVProviderSignIn", "UnlockWithWatch", "Wallpaper",
  "WebContentFiltering", "Welcome", "Zoom",
];

export const ENROLLMENT_MANIFEST: PayloadManifest = {
  domain: "__enrollment__",
  title: "Automated Enrollment (DEP)",
  description: "Settings applied during Automated Device Enrollment via Apple Business/School Manager.",
  category: "System",
  platforms: ["iOS", "macOS", "tvOS"],
  fields: [
    { name: "is_supervised", title: "Supervised", type: "boolean", default: true,
      description: "Place the device into supervised mode." },
    { name: "is_mandatory", title: "Mandatory enrollment", type: "boolean", default: true,
      description: "User cannot skip MDM enrollment during setup." },
    { name: "is_mdm_removable", title: "MDM profile removable", type: "boolean", default: false,
      description: "Allow the user to remove the MDM profile later." },
    { name: "await_device_configured", title: "Await final configuration", type: "boolean", default: false,
      description: "Hold the device in Setup Assistant until the server releases it. Pair with an ATC flow ending in a “Release from Setup Assistant” step so the user only reaches the home screen once profiles/apps are installed (true zero-touch)." },
    { name: "allow_pairing", title: "Allow host pairing", type: "boolean", default: true },
    { name: "auto_advance_setup", title: "Auto-advance setup (tvOS)", type: "boolean", default: false },
    { name: "support_phone_number", title: "Support phone number", type: "string" },
    { name: "support_email_address", title: "Support email", type: "string" },
    { name: "department", title: "Department / location", type: "string" },
    { name: "skip_setup_items", title: "Skip setup panes", type: "array", options: SETUP_PANE_OPTIONS,
      description: "Setup Assistant panes to hide during enrollment." },
  ],
};
