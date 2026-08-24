// Minimal XML property-list (.plist / .mobileconfig) reader and writer for Apple configuration profiles.
// Data and date leaves parse to plain strings; their type is re-derived on write or in the manifest.

import {getManifest} from "./profile-manifests";
import generatedDataKeys from "./data-keys.generated.json";

// Generated data-key index by payload type, built from ProfileManifests and Apple's mdm/profiles schemas.
// Kept separate because the form catalog is bundled into the client whole.
const GENERATED_DATA_KEYS: Record<string, { keys: string[] }> = generatedDataKeys;

// Every key the built-in tables type as data for these payload types. A profile only has to declare what this misses.
function knownDataKeys(payloads: Record<string, unknown>[]): Set<string> {
    const known = new Set<string>();
    for (const pl of payloads) {
        const type = pl?.PayloadType as string;
        for (const name of GENERATED_DATA_KEYS[type]?.keys ?? []) known.add(name);
        for (const f of getManifest(type)?.fields ?? []) {
            if (f.type === "data") known.add(f.name);
        }
    }
    return known;
}

export function parsePlist(xml: string): unknown {
    return parsePlistTyped(xml).value;
}

// The same parse, plus the plist type of every data and date leaf, by key name, the granularity
// typeHintsForPayloads matches on.
export function parsePlistTyped(xml: string): { value: unknown; types: PlistTypes } {
    const doc = new DOMParser().parseFromString(xml, "application/xml");
    if (doc.querySelector("parsererror")) {
        throw new Error("Not valid XML. The file may be a signed or binary profile.");
    }
    const root = doc.querySelector("plist")?.firstElementChild;
    if (!root) throw new Error("Empty or malformed plist.");
    const types: PlistTypes = {};
    return {value: parseNode(root, types), types};
}

function parseNode(node: Element, types: PlistTypes, key?: string): unknown {
    switch (node.nodeName) {
        case "dict": {
            const obj: Record<string, unknown> = {};
            const kids = Array.from(node.children);
            for (let i = 0; i < kids.length; i += 2) {
                const k = kids[i];
                const val = kids[i + 1];
                if (k?.nodeName === "key" && val) {
                    const name = k.textContent ?? "";
                    obj[name] = parseNode(val, types, name);
                }
            }
            return obj;
        }
        case "array":
            // Every element of an array shares its key's type, like the hints do.
            return Array.from(node.children).map((child) => parseNode(child, types, key));
        case "string":
            return node.textContent ?? "";
        case "integer":
            return parseInt(node.textContent ?? "0", 10);
        case "real":
            return parseFloat(node.textContent ?? "0");
        case "true":
            return true;
        case "false":
            return false;
        case "data":
            if (key) types[key] = "data";
            return (node.textContent ?? "").replace(/\s/g, "");
        case "date":
            if (key) types[key] = "date";
            return node.textContent ?? "";
        default:
            return node.textContent ?? "";
    }
}

function escapeXml(s: string): string {
    return s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}

// Which plist element a string value should be written as, resolved from the key path. Array indices are not part
// of the path, since every element of an array shares its key's type.
export type PlistStringType = "data" | "date";
export type TypeHint = (path: string[]) => PlistStringType | undefined;
// Plist types recovered from a parsed document, by key name.
export type PlistTypes = Record<string, PlistStringType>;

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

function asBase64(value: string): string | null {
    const compact = value.replace(/\s/g, "");
    if (!compact || compact.length % 4 !== 0 || !BASE64_RE.test(compact)) return null;
    return compact;
}

// Apple wants ISO 8601 with a literal Z, seconds precision, no milliseconds.
function asPlistDate(value: string | Date): string | null {
    const d = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(d.getTime())) return null;
    return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function buildNode(value: unknown, indent: number, path: string[], hint?: TypeHint): string {
    const pad = "  ".repeat(indent);
    if (typeof value === "boolean") return `${pad}<${value ? "true" : "false"}/>`;
    if (typeof value === "number") {
        return Number.isInteger(value)
            ? `${pad}<integer>${value}</integer>`
            : `${pad}<real>${value}</real>`;
    }
    if (value instanceof Date) {
        const iso = asPlistDate(value);
        if (iso) return `${pad}<date>${iso}</date>`;
    }
    if (typeof value === "string") {
        // A hint only applies when the value really is one: data around a non-base64 string, or date around free
        // text, produces a profile the device rejects. Falling back to string at worst leaves that one key untyped.
        const want = hint?.(path);
        if (want === "data") {
            const b64 = asBase64(value);
            if (b64) return `${pad}<data>${b64}</data>`;
        } else if (want === "date") {
            const iso = asPlistDate(value);
            if (iso) return `${pad}<date>${iso}</date>`;
        }
        return `${pad}<string>${escapeXml(value)}</string>`;
    }
    if (Array.isArray(value)) {
        if (value.length === 0) return `${pad}<array/>`;
        const inner = value.map((v) => buildNode(v, indent + 1, path, hint)).join("\n");
        return `${pad}<array>\n${inner}\n${pad}</array>`;
    }
    if (value && typeof value === "object") {
        const entries = Object.entries(value as Record<string, unknown>);
        if (entries.length === 0) return `${pad}<dict/>`;
        const inner = entries
            .map(
                ([k, v]) =>
                    `${"  ".repeat(indent + 1)}<key>${escapeXml(k)}</key>\n` +
                    buildNode(v, indent + 1, [...path, k], hint),
            )
            .join("\n");
        return `${pad}<dict>\n${inner}\n${pad}</dict>`;
    }
    return `${pad}<string></string>`;
}

export function buildPlist(value: unknown, hint?: TypeHint): string {
    return (
        `<?xml version="1.0" encoding="UTF-8"?>\n` +
        `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
        `<plist version="1.0">\n${buildNode(value, 0, [], hint)}\n</plist>\n`
    );
}

//  .mobileconfig helpers

export interface ImportedProfile {
    name?: string;
    identifier?: string;
    description?: string;
    payloads: Record<string, unknown>[];
    // What the file declared each data and date key to be, covering the payload types the manifests do not. The data
    // half becomes the profile's data_keys on import; the date half does not survive the tab.
    plistTypes: PlistTypes;
}

export function parseMobileconfig(xml: string): ImportedProfile {
    const {value: root, types} = parsePlistTyped(xml);
    if (!root || typeof root !== "object" || Array.isArray(root)) {
        throw new Error("This file is not a configuration profile.");
    }
    const r = root as Record<string, unknown>;
    const content = Array.isArray(r.PayloadContent)
        ? (r.PayloadContent as Record<string, unknown>[])
        : [];
    return {
        name: typeof r.PayloadDisplayName === "string" ? r.PayloadDisplayName : undefined,
        identifier: typeof r.PayloadIdentifier === "string" ? r.PayloadIdentifier : undefined,
        description: typeof r.PayloadDescription === "string" ? r.PayloadDescription : undefined,
        payloads: content,
        plistTypes: types,
    };
}

// Payload types with no manifest that carry values distinguishable only by plist type.
// The base64 test only keeps warnings off payloads with no binary; it never decides a type.
export function untypedDataPayloadTypes(
    payloads: Record<string, unknown>[],
    recorded: PlistTypes = {},
): string[] {
    const out: string[] = [];
    for (const pl of payloads) {
        const type = typeof pl?.PayloadType === "string" ? pl.PayloadType : "";
        if (!type || getManifest(type) || out.includes(type)) continue;
        if (hasUntypedBase64(pl, recorded, knownDataKeys([pl]))) out.push(type);
    }
    return out;
}

function hasUntypedBase64(
    value: unknown,
    recorded: PlistTypes,
    known: Set<string>,
    key?: string,
): boolean {
    if (typeof value === "string") {
        return !!key && !recorded[key] && !known.has(key) && asBase64(value) !== null;
    }
    if (Array.isArray(value)) return value.some((v) => hasUntypedBase64(v, recorded, known, key));
    if (value && typeof value === "object") {
        return Object.entries(value).some(([k, v]) => hasUntypedBase64(v, recorded, known, k));
    }
    return false;
}

// The data key names an imported file used that the built-in tables do not already cover, which are the only ones a
// profile has to carry in its data_keys. Sorted, so re-importing the same file writes the same list.
export function undeclaredDataKeys(
    payloads: Record<string, unknown>[],
    types: PlistTypes,
): string[] {
    const known = knownDataKeys(payloads);
    const out = new Set<string>();
    for (const [key, type] of Object.entries(types)) {
        if (type === "data" && !known.has(key)) out.add(key);
    }
    return Array.from(out).sort();
}

// The date half of a parsed document's types. Data types belong in the profile's
// data_keys; only dates have nowhere durable to go.
export function dateTypes(types: PlistTypes): PlistTypes {
    const out: PlistTypes = {};
    for (const [key, type] of Object.entries(types)) {
        if (type === "date") out[key] = type;
    }
    return out;
}

// Keys Apple defines as date in every payload type. No manifest declares a date key, so these and whatever an
// import recorded are all there is.
const UNIVERSAL_DATE_KEYS = new Set([
    "PayloadExpirationDate",
    "PayloadRemovalDate",
    "RemovalDate",
    "ExpirationDate",
]);

// Recover plist types for payloads from the generated index and manifests, matching by key name (last path segment).
// The recorded argument covers payload types neither the index nor a manifest describes.
export function typeHintsForPayloads(
    payloads: Record<string, unknown>[],
    recorded: PlistTypes = {},
): TypeHint {
    const data = knownDataKeys(payloads);
    const date = new Set<string>(UNIVERSAL_DATE_KEYS);
    for (const [key, type] of Object.entries(recorded)) {
        if (type === "data") data.add(key);
        else if (type === "date") date.add(key);
    }
    for (const pl of payloads) {
        for (const f of getManifest(pl?.PayloadType as string)?.fields ?? []) {
            if (f.type === "date") date.add(f.name);
        }
    }
    return (path) => {
        const key = path[path.length - 1];
        if (!key) return undefined;
        if (data.has(key)) return "data";
        if (date.has(key)) return "date";
        return undefined;
    };
}

function uuid(): string {
    try {
        return crypto.randomUUID().toUpperCase();
    } catch {
        return "00000000-0000-0000-0000-000000000000";
    }
}

// Build a downloadable .mobileconfig wrapping one or more payloads, matching how the controller assembles the
// profile.
export function profileToMobileconfig(p: {
    id: string;
    name: string;
    description?: string;
    payloads: Record<string, unknown>[];
    plistTypes?: PlistTypes;
}): string {
    const content = p.payloads.map((payload, idx) => {
        const inner: Record<string, unknown> = {...payload};
        inner.PayloadType = inner.PayloadType ?? "Configuration";
        inner.PayloadVersion = inner.PayloadVersion ?? 1;
        inner.PayloadIdentifier = inner.PayloadIdentifier ?? `com.micromanage.${p.id}.${idx}`;
        inner.PayloadUUID = inner.PayloadUUID ?? uuid();
        inner.PayloadDisplayName = inner.PayloadDisplayName ?? p.name;
        return inner;
    });

    const top: Record<string, unknown> = {
        PayloadContent: content,
        PayloadDisplayName: p.name,
        PayloadIdentifier: `com.micromanage.${p.id}`,
        PayloadType: "Configuration",
        PayloadUUID: uuid(),
        PayloadVersion: 1,
        ...(p.description ? {PayloadDescription: p.description} : {}),
    };
    return buildPlist(top, typeHintsForPayloads(content, p.plistTypes));
}
