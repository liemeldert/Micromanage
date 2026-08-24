// Shared types and helpers for the visual config editors (groups, apps, profiles). The types mirror the
// controller's YAML schema, and the evaluation helpers below mirror its group and scope evaluation.

import {useCallback, useEffect, useMemo, useState} from "react";
import {modals} from "@mantine/modals";
import {notifications} from "@mantine/notifications";
import yaml from "js-yaml";
import {api, ApiError, configConflict, type Device} from "./api";
import {useAuth} from "./auth-context";

//  Schema types

export type ConditionType =
    | "device_model"
    | "serial_number"
    | "hostname"
    | "os_version"
    | "enrollment_date"
    | "group"
    | "platform"
    | "tag"
    | "enrollment_source";

export interface Condition {
    type: ConditionType;
    operator: string;
    value: string | string[];
    // Inverts the condition ("device NOT IN group", "model NOT equals ...").
    negate?: boolean;
}

// Wave-based rollout: every interval another percent of scoped devices becomes eligible, and the server
// stamps start on save when it is left out.
export interface Rollout {
    percent: number;
    interval_hours: number;
    skip_weekends?: boolean;
    start?: string;
}

// Cherry-pick overrides shared by groups / profiles / app versions:
// exclude always wins; include forces scoping regardless of conditions.
export interface ScopeOverrides {
    include_devices?: string[];
    exclude_devices?: string[];
}

// Optional on a group: a device in the group derives its managed name from this template.
export interface DeviceNaming {
    template: string;
    apply_on_enroll?: boolean;
}

export interface Group extends ScopeOverrides {
    name: string;
    description?: string;
    // Optional on the wire: GET /api/v1/config/groups returns the parsed YAML as authored, so a group
    // written by hand with only a name and include_devices has no conditions key. Always default it.
    conditions?: Condition[];
    device_naming?: DeviceNaming;
}

export interface GroupsConfig {
    groups: Group[];
}

export interface AppVersion extends ScopeOverrides {
    version: string;
    s3_key: string;
    sha256: string;
    groups: string[];
    conditions?: Condition[];
    rollout?: Rollout;
    install_options?: Record<string, unknown>;
}

export interface App {
    id: string;
    name: string;
    bundle_id: string;
    versions: AppVersion[];
    // Apple's InstallAsManaged, macOS only. True gives ManagementFlags its meaning and lets MDM remove
    // the app later; false suits a package with no .app inside it, which InstallAsManaged rejects.
    // Unset means the deployment default applies instead of a value pinned here.
    install_as_managed?: boolean;
}

export interface AppsConfig {
    apps: App[];
}

export type ProfileKind = "configuration" | "enrollment";

export interface Profile extends ScopeOverrides {
    id: string;
    name: string;
    description?: string;
    payload_type?: string;
    type?: ProfileKind;
    platforms?: string[]; // target platforms: iOS | macOS | tvOS | watchOS | visionOS
    groups?: string[];
    conditions?: Condition[];
    rollout?: Rollout;
    dep_profile?: boolean;
    payload?: Record<string, unknown>; // legacy single payload
    payloads?: Record<string, unknown>[]; // multiple payloads (preferred)
    enrollment?: Record<string, unknown>; // DEP settings under their own key; dep_manager reads payload or enrollment
    // Key names whose base64 values have to reach the device as plist data. The controller adds its own
    // table of manifest-known data keys (controller/utils/payload_types.py), so only a key no manifest
    // describes needs listing here.
    data_keys?: string[];
}

export interface ProfilesConfig {
    profiles: Profile[];
}

// Advisory tag registry (tags.yaml). Free-form tags stay valid everywhere; a registered entry drives
// the picker and the chip colour.
export interface TagDef {
    name: string;
    label?: string;
    description?: string;
    color?: string; // Mantine colour name for the chip
}

export interface TagsConfig {
    tags: TagDef[];
}

// Normalise a profile's payloads to a list regardless of which form it was saved in.
export function profilePayloads(p: Profile): Record<string, unknown>[] {
    if (Array.isArray(p.payloads)) return p.payloads;
    if (p.payload && Object.keys(p.payload).length) return [p.payload];
    return [];
}

//  Condition metadata (drives the visual builder)

export type ValueKind =
    | "text" | "version" | "date" | "list" | "group" | "platform" | "tag" | "enrollment_source";

// How a device enrolled, as stamped on the device: ade for ABM/ASM enrollment, ota for manual.
export const ENROLLMENT_SOURCE_OPTIONS = [
    {value: "ade", label: "Automated (ABM/ASM)"},
    {value: "ota", label: "Manual / OTA"},
];

// Device families for the platform condition, mirroring the controller's categories.
export const PLATFORM_OPTIONS = ["Mac", "iPhone", "iPad", "Apple TV", "Apple Watch", "iPod", "Apple Vision Pro"];

// Map a device model identifier to a platform family, mirroring the controller.
export function devicePlatformCategory(model: string | null | undefined): string {
    const m = (model ?? "").toLowerCase().replace(/\s/g, "");
    if (m.startsWith("iphone")) return "iPhone";
    if (m.startsWith("ipad")) return "iPad";
    if (m.startsWith("ipod")) return "iPod";
    if (m.startsWith("appletv")) return "Apple TV";
    if (m.startsWith("watch")) return "Apple Watch";
    if (m.startsWith("realitydevice")) return "Apple Vision Pro"; // RealityDevice14,1 is Apple Vision Pro
    if (m.includes("mac")) return "Mac";
    return "Other";
}

export interface ConditionTypeMeta {
    value: ConditionType;
    label: string;
    operators: string[];
    // value kind per operator; "list" means a tags input (e.g. serial_number "in")
    valueKindFor: (operator: string) => ValueKind;
}

export const CONDITION_TYPES: ConditionTypeMeta[] = [
    {
        // "platform" first: the most common everyday grouping (all Macs / iPhones).
        value: "platform",
        label: "Platform",
        operators: ["in"],
        valueKindFor: () => "platform",
    },
    {
        value: "device_model",
        label: "Device model",
        operators: ["contains", "equals", "regex"],
        valueKindFor: (op) => (op === "contains" ? "list" : "text"),
    },
    {
        value: "serial_number",
        label: "Serial number",
        operators: ["in", "equals"],
        valueKindFor: (op) => (op === "in" ? "list" : "text"),
    },
    {
        value: "hostname",
        label: "Hostname",
        operators: ["contains", "equals", "regex"],
        valueKindFor: (op) => (op === "contains" ? "list" : "text"),
    },
    {
        value: "os_version",
        label: "OS version",
        operators: ["gte", "gt", "lte", "lt", "equals"],
        valueKindFor: () => "version",
    },
    {
        value: "enrollment_date",
        label: "Enrollment date",
        operators: ["after", "before", "equals"],
        valueKindFor: () => "date",
    },
    {
        // Membership in other groups; with "is not" this reads as device not in group.
        value: "group",
        label: "Group membership",
        operators: ["in"],
        valueKindFor: () => "group",
    },
    {
        // Membership in the device's tag set, assigned by hand, by ATC flows or by Dispatcher rules.
        value: "tag",
        label: "Tag",
        operators: ["in"],
        valueKindFor: () => "tag",
    },
    {
        // How the device enrolled; with "is not" this reads as not enrolled via ABM/ASM.
        value: "enrollment_source",
        label: "Enrollment source",
        operators: ["in"],
        valueKindFor: () => "enrollment_source",
    },
];

// Operator labels, worded to read after an "is" / "is not" polarity dropdown
// (e.g. "device model | is not | contains | Mac").
export const OPERATOR_LABELS: Record<string, string> = {
    regex: "matching regex",
    equals: "exactly",
    contains: "containing",
    in: "one of",
    gte: "≥",
    gt: ">",
    lte: "≤",
    lt: "<",
    after: "after",
    before: "before",
};

export function conditionTypeMeta(type: ConditionType): ConditionTypeMeta {
    return CONDITION_TYPES.find((c) => c.value === type) ?? CONDITION_TYPES[0];
}

export function describeCondition(c: Condition): string {
    const pol = c.negate ? "is not" : "is";
    const v = Array.isArray(c.value) ? c.value.join(", ") : c.value;
    if (c.type === "group") return `device ${pol} in group ${v}`;
    if (c.type === "platform") return `platform ${pol} ${v}`;
    if (c.type === "tag") return `device ${pol} tagged ${v}`;
    if (c.type === "enrollment_source") {
        const labels = (Array.isArray(c.value) ? c.value : [c.value])
            .map((x) => ENROLLMENT_SOURCE_OPTIONS.find((o) => o.value === x)?.label ?? String(x));
        return `enrollment ${pol} ${labels.join(", ")}`;
    }
    const op = OPERATOR_LABELS[c.operator] ?? c.operator;
    return `${conditionTypeMeta(c.type).label} ${pol} ${op} ${v}`;
}

//  Validation helpers (mirror the backend validators)

export const GROUP_NAME_RE = /^[a-zA-Z0-9-_]+$/;
export const BUNDLE_ID_RE = /^[a-zA-Z0-9.-]+$/;
export const SHA256_RE = /^[a-fA-F0-9]{64}$/;
export const SLUG_RE = /^[a-zA-Z0-9._-]+$/;

/** A config id derived from a display name, filled in by the create forms as you type. Lowercased, with
 * spaces and punctuation collapsed to single hyphens, so the result always satisfies SLUG_RE. Matches
 * the ATC flow editor's slugifyFlowId. */
export function slugifyConfigId(name: string): string {
    return name
        .toLowerCase()
        .normalize("NFKD")
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 60);
}

//  Client-side group evaluation (for the "matches N devices" preview)
// Best-effort mirror of group_manager.py; labelled as an estimate in the UI.

function compareVersions(a: string, b: string): number {
    const pa = a.split(".").map((n) => parseInt(n, 10) || 0);
    const pb = b.split(".").map((n) => parseInt(n, 10) || 0);
    const len = Math.max(pa.length, pb.length);
    for (let i = 0; i < len; i++) {
        const d = (pa[i] ?? 0) - (pb[i] ?? 0);
        if (d !== 0) return d < 0 ? -1 : 1;
    }
    return 0;
}

function evalString(deviceVal: string, op: string, value: string | string[]): boolean {
    switch (op) {
        case "regex":
            try {
                // Anchor at the start to mirror Python's re.match (start-anchored).
                return new RegExp("^(?:" + String(value) + ")").test(deviceVal);
            } catch {
                return false;
            }
        case "equals":
            return deviceVal === String(value ?? "");
        case "contains":
            // A list matches if ANY listed substring is present.
            if (Array.isArray(value)) return value.some((x) => deviceVal.includes(String(x)));
            return deviceVal.includes(String(value ?? ""));
        case "in": {
            // Membership in a set of exact values (a scalar is one exact value).
            const list = Array.isArray(value) ? value : [value];
            return list.map(String).includes(deviceVal);
        }
        default:
            return false;
    }
}

// A plain numeric dotted version such as 17.1.2. The backend treats anything it cannot parse as a
// non-match, mirrored here by refusing anything non-numeric.
function isPlainNumericVersion(s: string): boolean {
    return /^\d+(\.\d+)*$/.test(s);
}

function evalConditionBase(
    device: Device,
    c: Condition,
    allGroups: Group[],
    stack: Set<string>,
): boolean {
    switch (c.type) {
        case "group": {
            const names = (Array.isArray(c.value) ? c.value : [c.value]).filter(Boolean).map(String);
            return names.some((n) => {
                if (stack.has(n)) return false; // cycle: mirrors the backend guard
                const g = allGroups.find((x) => x.name === n);
                return g ? deviceInGroup(device, g, allGroups, stack) : false;
            });
        }
        case "platform": {
            const want = (Array.isArray(c.value) ? c.value : [c.value]).filter(Boolean).map(String);
            return want.includes(devicePlatformCategory(device.device_model));
        }
        case "tag": {
            // Membership in the device's tag set.
            const want = (Array.isArray(c.value) ? c.value : [c.value]).filter(Boolean).map(String);
            const have = new Set((device.tags ?? []).map(String));
            return want.some((t) => have.has(t));
        }
        case "enrollment_source": {
            // An absent attribute defaults to ota, as on the server.
            const want = (Array.isArray(c.value) ? c.value : [c.value]).filter(Boolean).map(String);
            const src = String((device.attributes as Record<string, unknown> | undefined)?.enrollment_source ?? "ota");
            return want.includes(src);
        }
        case "device_model":
            return evalString(device.device_model ?? "", c.operator, c.value);
        case "serial_number":
            return evalString(device.serial_number ?? "", c.operator, c.value);
        case "hostname":
            return evalString(device.hostname ?? "", c.operator, c.value);
        case "os_version": {
            // An unparseable version on either side matches nothing.
            const dv = device.os_version ?? "";
            if (!isPlainNumericVersion(dv) || !isPlainNumericVersion(String(c.value))) return false;
            const cmp = compareVersions(dv, String(c.value));
            switch (c.operator) {
                case "gte":
                    return cmp >= 0;
                case "gt":
                    return cmp > 0;
                case "lte":
                    return cmp <= 0;
                case "lt":
                    return cmp < 0;
                case "equals":
                    return cmp === 0;
                default:
                    return false;
            }
        }
        case "enrollment_date": {
            const dvDate = new Date(device.enrollment_date);
            const cvDate = new Date(String(c.value));
            if (Number.isNaN(dvDate.getTime()) || Number.isNaN(cvDate.getTime())) return false;
            switch (c.operator) {
                case "after":
                    return dvDate.getTime() > cvDate.getTime();
                case "before":
                    return dvDate.getTime() < cvDate.getTime();
                case "equals":
                    // Compare UTC calendar dates, as the server does.
                    return dvDate.toISOString().slice(0, 10) === cvDate.toISOString().slice(0, 10);
                default:
                    return false;
            }
        }
        default:
            return false;
    }
}

export function evalCondition(
    device: Device,
    c: Condition,
    allGroups: Group[] = [],
    stack: Set<string> = new Set(),
): boolean {
    const base = evalConditionBase(device, c, allGroups, stack);
    return c.negate ? !base : base;
}

// Full group membership: exclude beats include cherry-picks, and every condition has to hold.
// allGroups resolves group-type conditions, stack is the cycle guard.
export function deviceInGroup(
    device: Device,
    group: Group,
    allGroups: Group[] = [],
    stack: Set<string> = new Set(),
): boolean {
    const serial = device.serial_number ?? "";
    if (serial && group.exclude_devices?.includes(serial)) return false;
    if (serial && group.include_devices?.includes(serial)) return true;
    const conditions = group.conditions ?? [];
    if (conditions.length === 0) return false;
    const nextStack = new Set(stack);
    nextStack.add(group.name);
    return conditions.every((c) => evalCondition(device, c, allGroups, nextStack));
}

// Scope evaluation for profiles and app versions. Mirrors evaluate_scope.
export interface Scope extends ScopeOverrides {
    groups?: string[];
    conditions?: Condition[];
}

export function evaluateScope(
    device: Device,
    deviceGroups: string[],
    scope: Scope,
    allGroups: Group[] = [],
): boolean {
    const serial = device.serial_number ?? "";
    if (serial && scope.exclude_devices?.includes(serial)) return false;
    if (serial && scope.include_devices?.includes(serial)) return true;
    const groups = scope.groups ?? [];
    const conditions = scope.conditions ?? [];
    if (groups.length === 0 && conditions.length === 0) return false;
    if (groups.length > 0 && !groups.some((g) => deviceGroups.includes(g))) return false;
    return !(conditions.length > 0 &&
        !conditions.every((c) => evalCondition(device, c, allGroups)));

}

// Groups a device belongs to, for previews. Mirrors evaluate_device_groups.
export function deviceGroupNames(device: Device, allGroups: Group[]): string[] {
    return allGroups.filter((g) => deviceInGroup(device, g, allGroups)).map((g) => g.name);
}

//  Naming templates
// Device-state variables usable in naming templates, mirroring GET /api/v1/naming/variables. Kept
// inline so the editor's live preview needs no round trip, the same way CONDITION_TYPES is.

export interface NameVariable {
    key: string;
    description: string;
}

// Owner and directory variables are absent because there is no directory system yet and they would
// resolve to empty. Keep in sync with the server registry (controller/services/variables.py
// VARIABLE_SPECS).
export const NAME_VARIABLES: NameVariable[] = [
    {key: "serial", description: "Hardware serial number"},
    {key: "model", description: "Device model identifier"},
    {key: "hostname", description: "Name the device reports for itself"},
    {key: "os", description: "Operating system version"},
    {key: "udid", description: "Full enrollment UDID"},
    {key: "udid_short", description: "First 8 characters of the UDID"},
    {key: "management_type", description: "Management backend (apple_mdm, …)"},
];

function nameContext(d: Device): Record<string, string> {
    const udid = d.udid ?? "";
    return {
        serial: d.serial_number ?? "",
        model: d.device_model ?? "",
        hostname: d.hostname ?? "",
        os: d.os_version ?? "",
        os_version: d.os_version ?? "",
        udid,
        udid_short: udid.slice(0, 8),
        management_type: d.management_type ?? "",
    };
}

// Render a naming template against a device, mirroring the controller: one pass, stray braces stripped,
// whitespace and separators tidied, capped at 63. Empty when the template renders to nothing.
export function renderNameTemplate(template: string, d: Device): string {
    if (!template || !template.trim()) return "";
    const ctx = nameContext(d);
    const out = template
        .replace(/\{([^}]+)}/g, (_, k) => ctx[String(k).trim()] ?? "")
        .replace(/[{}]/g, "") // drop stray braces left by a malformed template
        .replace(/\s+/g, " ")
        .replace(/^[ \-_.]+|[ \-_.]+$/g, "");
    // Cap by code points as the server does; .slice() counts UTF-16 units and can split a surrogate pair.
    return Array.from(out).slice(0, 63).join("");
}

// Variables referenced by a template that aren't in the registry (typo warnings).
export function unknownNameVariables(template: string): string[] {
    const known = new Set(NAME_VARIABLES.map((v) => v.key).concat("os_version"));
    const out: string[] = [];
    const re = /\{([^}]+)}/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(template)) !== null) {
        const k = m[1].trim();
        if (!known.has(k) && !out.includes(k)) out.push(k);
    }
    return out;
}

// True if the template references {hostname}, which is self-referential: the managed name reaches the
// device, comes back as its hostname, and each re-derivation compounds. Tokenized like the server, by
// parsing brace tokens and trimming, so a malformed template gets the same answer on both sides.
export function isSelfReferentialTemplate(template: string): boolean {
    const re = /\{([^}]+)}/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(template)) !== null) {
        if (m[1].trim() === "hostname") return true;
    }
    return false;
}

//  Concurrent edits

// Config editors read a whole document, edit a local copy and PUT the whole thing back, so two admins
// in one document at once meant the second save erased the first. Each read carries the document's
// version, each save returns it, and the server answers 409 when it is stale. This is where that
// refusal becomes a choice, and the only answer that proceeds is a reload, which discards the local
// edits rather than the ones already saved.
export function showConfigConflict(message: string, onReload: () => void) {
    modals.openConfirmModal({
        title: "Changed by someone else",
        children: message,
        labels: {confirm: "Reload", cancel: "Keep editing"},
        confirmProps: {color: "orange"},
        onConfirm: onReload,
    });
}

//  Config resource hook (load / save a single config type)

type ConfigType = "groups" | "apps" | "profiles" | "tags" | "flows" | "dispatcher";

// Documents the server rewrites as it saves them: a rollout with no start gets one stamped. Re-read
// those, or the next save omits the start again, the server stamps a new one and the wave restarts.
const REWRITTEN_ON_SAVE = new Set<ConfigType>(["profiles", "apps"]);

export function useConfigResource<T>(type: ConfigType, empty: T) {
    const {token} = useAuth();
    const [data, setData] = useState<T | null>(null);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    // Version of the document as loaded, sent back on save. Undefined until a load has answered.
    const [version, setVersion] = useState<string | undefined>(undefined);

    // silent skips the loading flag for the post-save re-read; editors that hide their form while
    // loading would otherwise rebuild after every save.
    const load = useCallback(async (silent = false) => {
        if (!token) return;
        if (!silent) setLoading(true);
        try {
            const res = await api.getConfigWithVersion(token, type);
            setData((res.data as T) ?? empty);
            setVersion(res.version);
        } catch (e: unknown) {
            // A missing config file (404) is just an empty config to be created.
            if (e instanceof ApiError && e.status === 404) {
                setData(empty);
                setVersion(undefined);
            } else {
                notifications.show({color: "red", message: (e as Error).message});
            }
        } finally {
            if (!silent) setLoading(false);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [token, type]);

    const reload = useCallback(() => load(), [load]);

    useEffect(() => {
        reload();
    }, [reload]);

    // quiet drops the success and warning toasts for an unrequested save, such as the ATC editor's
    // draft autosave. Failures are still shown.
    // keepNewerEdits puts an identity check in front of the post-save setData, for an editor that keeps
    // accepting edits while the PUT is unanswered (the ATC canvas), where a plain install would roll
    // those edits back. Opt-in: the other editors build a fresh document per save and rely on save()
    // installing it.
    const save = useCallback(
        async (next: T, opts: { quiet?: boolean; keepNewerEdits?: boolean } = {}): Promise<boolean> => {
            if (!token) return false;
            setSaving(true);
            try {
                const res = await api.updateConfig(token, type, next as Record<string, unknown>,
                    undefined, {ifMatch: version});
                if (opts.keepNewerEdits) {
                    setData((current) => (current === next ? next : current));
                } else {
                    setData(next);
                }
                setVersion(res.version);
                if (!opts.quiet) notifications.show({color: "teal", message: res.message});
                // Re-read what the server actually wrote, without the loading flag.
                if (REWRITTEN_ON_SAVE.has(type)) await load(true);
                if (!opts.quiet) {
                    (res.warnings ?? []).forEach((w) =>
                        notifications.show({color: "yellow", title: "Warning", message: w}),
                    );
                }
                return true;
            } catch (e: unknown) {
                const conflict = configConflict(e);
                if (conflict) {
                    showConfigConflict(conflict.message, reload);
                    return false;
                }
                const detail =
                    e instanceof ApiError && typeof e.message === "string" ? e.message : String(e);
                notifications.show({
                    color: "red",
                    title: "Could not save",
                    message: detail,
                    autoClose: 8000,
                });
                return false;
            } finally {
                setSaving(false);
            }
        },
        [token, type, version, load, reload],
    );

    // YAML text of the live data, used as the current baseline by the History drawer's diff. The visual
    // editors hold parsed JSON only, so this re-serializes on the client instead of a second request.
    // A dump failure falls back to an empty baseline, leaving the drawer to diff against nothing.
    const currentDocText = useMemo(() => {
        if (data == null) return "";
        try {
            return yaml.dump(data);
        } catch {
            return "";
        }
    }, [data]);

    return {data, setData, loading, saving, reload, save, currentDocText, version, setVersion};
}

// Load the advisory tag registry (tags.yaml) for pickers, autocomplete and chip colours. A missing
// registry or a failed load is an empty list, and free-form tags stay valid everywhere.
export function useTagRegistry() {
    const {token} = useAuth();
    const [tags, setTags] = useState<TagDef[]>([]);
    const [loading, setLoading] = useState(true);

    const reload = useCallback(async () => {
        if (!token) return;
        setLoading(true);
        try {
            const res = (await api.getConfig(token, "tags")) as { tags?: TagDef[] } | null;
            setTags(Array.isArray(res?.tags) ? (res!.tags as TagDef[]) : []);
        } catch {
            setTags([]);
        } finally {
            setLoading(false);
        }
    }, [token]);

    useEffect(() => {
        reload();
    }, [reload]);

    const tagNames = useMemo(() => tags.map((t) => t.name), [tags]);
    const colorOf = useCallback(
        (name: string): string | undefined => tags.find((t) => t.name === name)?.color,
        [tags],
    );
    const labelOf = useCallback(
        (name: string): string => tags.find((t) => t.name === name)?.label || name,
        [tags],
    );

    return {tags, tagNames, colorOf, labelOf, loading, reload};
}
