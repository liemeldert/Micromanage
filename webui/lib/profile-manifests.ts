// Payload manifests for the profile editor. Most are generated from the community ProfileManifests
// project into manifests.generated.json (webui/scripts/build-manifests.py), which gives the full key set
// for each payload type. Manifests sharing a domain are merged; VPN and the DEP form are hand-written.

import generated from "./manifests.generated.json";

// A profile's target platforms, mirroring the controller's enum. iOS covers iPhone, iPad and iPod only.
export type Platform = "iOS" | "macOS" | "tvOS" | "watchOS" | "visionOS";
export const ALL_PLATFORMS: Platform[] = ["iOS", "macOS", "tvOS", "watchOS", "visionOS"];

// Upstream ProfileManifests tags keys iOS, macOS or tvOS only, so watchOS and visionOS map onto the iOS
// set before the catalog is filtered. Without that a watchOS-only profile offers no payloads at all.
const MANIFEST_PLATFORM: Record<Platform, string> = {
    iOS: "iOS",
    macOS: "macOS",
    tvOS: "tvOS",
    watchOS: "iOS",
    visionOS: "iOS",
};

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
    group?: string; // section heading, set only on a domain several manifests merged into
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
    keywords?: string[]; // extra search terms: the section titles a merged domain absorbed
}

// Title, category and description for a domain several manifests merge into. With no entry the merge
// joins the section titles instead, which is legible enough to spot after a rebuild adds a collision.
const MERGED_IDENTITY: Record<string, { title: string; category: PayloadCategory; description: string }> = {
    "com.apple.MCX": {
        title: "Managed Preferences (MCX)",
        category: "System",
        description:
            "macOS managed preferences: guest and mobile accounts, FileVault options, energy saver, time server and Wi-Fi settings.",
    },
};

function fieldKey(f: ManifestField): string {
    return `${f.parent ?? ""}::${f.name}`;
}

// Upstream splits one payload type across several manifest files when the keys cover unrelated ground:
// six of them describe com.apple.MCX. A payload records only PayloadType, so a lookup by domain resolves
// to whichever file came first. Fold them into one manifest holding the union, tagged by source section.
function mergeByDomain(list: PayloadManifest[]): PayloadManifest[] {
    const out: PayloadManifest[] = [];
    const at = new Map<string, number>();
    for (const m of list) {
        const i = at.get(m.domain);
        if (i === undefined) {
            at.set(m.domain, out.length);
            out.push({...m, platforms: [...m.platforms], fields: m.fields.map((f) => ({...f}))});
            continue;
        }
        const merged = out[i];
        if (!merged.keywords) {
            // First collision on this domain: what is already here becomes section one.
            merged.keywords = [merged.title];
            for (const f of merged.fields) f.group = merged.title;
        }
        merged.keywords.push(m.title);
        const seen = new Set(merged.fields.map(fieldKey));
        for (const f of m.fields) {
            if (seen.has(fieldKey(f))) continue;
            seen.add(fieldKey(f));
            merged.fields.push({...f, group: m.title});
        }
        for (const p of m.platforms) if (!merged.platforms.includes(p)) merged.platforms.push(p);
        if (m.multiple) merged.multiple = true;
        const id = MERGED_IDENTITY[m.domain];
        merged.title = id?.title ?? merged.keywords.join(" / ");
        if (id) {
            merged.category = id.category;
            merged.description = id.description;
        }
    }
    return out;
}

const GENERATED = mergeByDomain(generated as unknown as PayloadManifest[]);

// VPN's manifest filename differs upstream; keep a focused hand-authored entry.
const VPN: PayloadManifest = {
    domain: "com.apple.vpn.managed",
    title: "VPN",
    description: "Configure a VPN connection.",
    category: "Network",
    platforms: ["iOS", "macOS"],
    multiple: true,
    fields: [
        {name: "UserDefinedName", title: "Connection name", type: "string", required: true},
        {
            name: "VPNType", title: "Connection type", type: "string", default: "IKEv2",
            options: ["IKEv2", "IPSec", "L2TP", "VPN", "AlwaysOn"]
        },
        {name: "OnDemandEnabled", title: "Connect on demand", type: "integer", default: 0, min: 0, max: 1},
        {
            name: "IKEv2", title: "IKEv2 settings", type: "dictionary",
            description: "RemoteAddress, RemoteIdentifier, AuthenticationMethod, etc. Edit as JSON."
        },
        {
            name: "IPSec",
            title: "IPSec settings",
            type: "dictionary",
            description: "Cisco IPSec settings. Edit as JSON."
        },
        {name: "PPP", title: "PPP settings (L2TP)", type: "dictionary", description: "Edit as JSON."},
    ],
};

export const PAYLOAD_MANIFESTS: PayloadManifest[] = [...GENERATED, VPN];

export function getManifest(domain: string | undefined | null): PayloadManifest | undefined {
    if (!domain) return undefined;
    return PAYLOAD_MANIFESTS.find((m) => m.domain === domain);
}

function manifestPlatforms(platforms: Platform[]): string[] {
    return platforms.map((p) => MANIFEST_PLATFORM[p] ?? p);
}

export function manifestSupportsPlatforms(m: PayloadManifest, platforms?: Platform[]): boolean {
    if (!platforms || platforms.length === 0) return true;
    const want = manifestPlatforms(platforms);
    return m.platforms.some((p) => want.includes(p));
}

export function fieldSupportsPlatforms(f: ManifestField, platforms?: Platform[]): boolean {
    if (!platforms || platforms.length === 0) return true;
    if (!f.platforms || f.platforms.length === 0) return true;
    const want = manifestPlatforms(platforms);
    return f.platforms.some((p) => want.includes(p));
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
    const out: Record<string, unknown> = {PayloadType: m.domain};
    for (const f of m.fields) {
        if (f.required && f.default !== undefined) out[f.name] = f.default;
    }
    return out;
}

//  Enrollment (Automated Device Enrollment / DEP) manifest 

// Setup Assistant panes that can be skipped. Mirrors the controller's skip-key registry, which drops
// anything it does not recognise, so a stale entry here is harmless. The DEP profile editor also offers
// the live list from GET /api/v1/dep/skip-keys.
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
        {
            name: "is_supervised", title: "Supervised", type: "boolean", default: true,
            description: "Place the device into supervised mode."
        },
        {
            name: "is_mandatory", title: "Mandatory enrollment", type: "boolean", default: true,
            description: "User cannot skip MDM enrollment during setup."
        },
        {
            name: "is_mdm_removable", title: "MDM profile removable", type: "boolean", default: false,
            description: "Allow the user to remove the MDM profile later."
        },
        {
            name: "await_device_configured", title: "Await final configuration", type: "boolean", default: false,
            description: "Holds the device in Setup Assistant until the server releases it. Pair this with a flow ending in a \"Release from Setup Assistant\" step, so the user reaches the home screen only once the profiles and apps are installed."
        },
        {name: "allow_pairing", title: "Allow host pairing", type: "boolean", default: true},
        {name: "auto_advance_setup", title: "Auto-advance setup (tvOS)", type: "boolean", default: false},
        {name: "support_phone_number", title: "Support phone number", type: "string"},
        {name: "support_email_address", title: "Support email", type: "string"},
        {name: "department", title: "Department / location", type: "string"},
        {
            name: "skip_setup_items", title: "Skip setup panes", type: "array", options: SETUP_PANE_OPTIONS,
            description: "Setup Assistant panes to hide during enrollment."
        },
    ],
};
