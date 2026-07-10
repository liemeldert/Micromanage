// Shared types + helpers for the visual config editors (groups / apps / profiles).
// Types mirror the controller's YAML schema (controller/utils/yaml_validator.py)
// and group evaluation logic (controller/services/group_manager.py).

import { useCallback, useEffect, useMemo, useState } from "react";
import { notifications } from "@mantine/notifications";
import { api, ApiError, type Device } from "./api";
import { useAuth } from "./auth-context";

// ── Schema types ─────────────────────────────────────────────────────────────

export type ConditionType =
  | "device_model"
  | "serial_number"
  | "hostname"
  | "os_version"
  | "enrollment_date"
  | "group"
  | "platform"
  | "tag";

export interface Condition {
  type: ConditionType;
  operator: string;
  value: string | string[];
  // Inverts the condition ("device NOT IN group", "model NOT equals ...").
  negate?: boolean;
}

// Gradual (wave-based) rollout gate -- mirrors controller/services/scoping.py.
// Every interval another `percent` of scoped devices become eligible; `start`
// is stamped by the server on save when omitted.
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

// A naming-template scope (see controller/services/naming.py). Optional on a
// group; a device in the group derives its managed name from here.
export interface DeviceNaming {
  template: string;
  apply_on_enroll?: boolean;
}
export interface Group extends ScopeOverrides {
  name: string;
  description?: string;
  conditions: Condition[];
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
  platforms?: string[]; // target platforms: iOS | macOS | tvOS
  groups?: string[];
  conditions?: Condition[];
  rollout?: Rollout;
  dep_profile?: boolean;
  payload?: Record<string, unknown>; // legacy single payload
  payloads?: Record<string, unknown>[]; // multiple payloads (preferred)
}
export interface ProfilesConfig {
  profiles: Profile[];
}

// Advisory tag registry (tags.yaml). Optional: free-form tags are always
// allowed; registered entries drive the picker + chip colours. Mirrors the
// controller's Tag / TagRegistry models (controller/utils/yaml_validator.py).
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

// ── Condition metadata (drives the visual builder) ───────────────────────────

export type ValueKind = "text" | "version" | "date" | "list" | "group" | "platform" | "tag";

// Device families for the "platform" condition -- premade options so an
// "all Macs" group is one click. Mirrors scoping.PLATFORM_CATEGORIES.
export const PLATFORM_OPTIONS = ["Mac", "iPhone", "iPad", "Apple TV", "Apple Watch", "iPod"];

// Map a device model identifier to a platform family (mirrors
// scoping.device_platform_category).
export function devicePlatformCategory(model: string | null | undefined): string {
  const m = (model ?? "").toLowerCase().replace(/\s/g, "");
  if (m.startsWith("iphone")) return "iPhone";
  if (m.startsWith("ipad")) return "iPad";
  if (m.startsWith("ipod")) return "iPod";
  if (m.startsWith("appletv")) return "Apple TV";
  if (m.startsWith("watch")) return "Apple Watch";
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
    // Membership in other group(s). With "is not" this expresses
    // "device NOT IN group" -- e.g. everyone except a pilot cohort.
    value: "group",
    label: "Group membership",
    operators: ["in"],
    valueKindFor: () => "group",
  },
  {
    // Membership in the device's imperative tag set (assigned by hand, ATC
    // flows or Dispatcher rules). "is not" expresses "NOT tagged X".
    value: "tag",
    label: "Tag",
    operators: ["in"],
    valueKindFor: () => "tag",
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
  const op = OPERATOR_LABELS[c.operator] ?? c.operator;
  return `${conditionTypeMeta(c.type).label} ${pol} ${op} ${v}`;
}

// ── Validation helpers (mirror the backend validators) ───────────────────────

export const GROUP_NAME_RE = /^[a-zA-Z0-9-_]+$/;
export const BUNDLE_ID_RE = /^[a-zA-Z0-9.-]+$/;
export const SHA256_RE = /^[a-fA-F0-9]{64}$/;
export const SLUG_RE = /^[a-zA-Z0-9._-]+$/;

// ── Client-side group evaluation (for the "matches N devices" preview) ───────
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

// A plain numeric dotted version ("15", "15.5", "17.1.2"). The backend uses
// packaging.parse, which raises on empty/non-numeric strings -> no-match; we
// mirror that by treating anything non-numeric as unparseable.
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
      // Membership in the device's tag set -- mirrors scoping._evaluate_base.
      const want = (Array.isArray(c.value) ? c.value : [c.value]).filter(Boolean).map(String);
      const have = new Set((device.tags ?? []).map(String));
      return want.some((t) => have.has(t));
    }
    case "device_model":
      return evalString(device.device_model ?? "", c.operator, c.value);
    case "serial_number":
      return evalString(device.serial_number ?? "", c.operator, c.value);
    case "hostname":
      return evalString(device.hostname ?? "", c.operator, c.value);
    case "os_version": {
      // Mirror the backend: an empty/non-numeric version is unparseable and
      // matches nothing (packaging.parse would raise).
      const dv = device.os_version ?? "";
      if (!isPlainNumericVersion(dv) || !isPlainNumericVersion(String(c.value))) return false;
      const cmp = compareVersions(dv, String(c.value));
      switch (c.operator) {
        case "gte": return cmp >= 0;
        case "gt": return cmp > 0;
        case "lte": return cmp <= 0;
        case "lt": return cmp < 0;
        case "equals": return cmp === 0;
        default: return false;
      }
    }
    case "enrollment_date": {
      const dvDate = new Date(device.enrollment_date);
      const cvDate = new Date(String(c.value));
      if (Number.isNaN(dvDate.getTime()) || Number.isNaN(cvDate.getTime())) return false;
      switch (c.operator) {
        case "after": return dvDate.getTime() > cvDate.getTime();
        case "before": return dvDate.getTime() < cvDate.getTime();
        case "equals":
          // Compare UTC calendar dates to mirror Python's date() comparison.
          return dvDate.toISOString().slice(0, 10) === cvDate.toISOString().slice(0, 10);
        default: return false;
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

// Full group membership: exclude wins > include cherry-picks > ALL conditions.
// `allGroups` resolves group-type conditions; `stack` is the cycle guard.
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

export function deviceMatchesGroup(
  device: Device,
  conditions: Condition[],
  allGroups: Group[] = [],
): boolean {
  if (!conditions || conditions.length === 0) return false; // mirrors backend
  return conditions.every((c) => evalCondition(device, c, allGroups));
}

// Scope evaluation for profiles / app versions -- mirrors scoping.evaluate_scope.
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
  if (
    conditions.length > 0 &&
    !conditions.every((c) => evalCondition(device, c, allGroups))
  ) {
    return false;
  }
  return true;
}

// Groups a device belongs to, for previews -- mirrors evaluate_device_groups.
export function deviceGroupNames(device: Device, allGroups: Group[]): string[] {
  return allGroups.filter((g) => deviceInGroup(device, g, allGroups)).map((g) => g.name);
}

// Percent of devices a rollout currently covers -- mirrors rollout_coverage.
// Weekend-opening waves are deferred when skip_weekends (UTC weekdays).
export function rolloutCoverage(rollout: Rollout, now: Date = new Date()): number {
  const percent = Math.trunc(rollout.percent ?? 0);
  if (percent <= 0 || percent >= 100) return 100;
  if (!rollout.start) return 100; // server stamps start on save; fail open
  // A tz-naive start is UTC on the server; make JS agree (it would otherwise
  // parse a bare datetime as local time).
  const hasTz = /[zZ]|[+-]\d{2}:?\d{2}$/.test(rollout.start);
  const start = new Date(hasTz ? rollout.start : rollout.start + "Z");
  if (Number.isNaN(start.getTime())) return 100;
  if (now < start) return 0;
  const intervalH = rollout.interval_hours > 0 ? rollout.interval_hours : 24;
  const stepMs = intervalH * 3600 * 1000;
  const stepsNeeded = Math.ceil(100 / percent);
  let completed = 0;
  let t = start.getTime();
  let guard = 0;
  while (completed < stepsNeeded && guard < 20000) {
    guard += 1;
    const nxt = t + stepMs;
    if (nxt > now.getTime()) break;
    const day = new Date(nxt).getUTCDay(); // 0=Sun, 6=Sat
    if (!(rollout.skip_weekends && (day === 0 || day === 6))) completed += 1;
    t = nxt;
  }
  return Math.min(100, percent * (completed + 1));
}

// ── Naming templates ─────────────────────────────────────────────────────────
// Device-state variables usable in naming templates. Mirrors the server registry
// (controller/services/variables.py, GET /api/v1/naming/variables); kept inline
// so the editor's live preview needs no round-trip, same pattern as CONDITION_TYPES.

export interface NameVariable {
  key: string;
  description: string;
}

// Owner/directory variables are intentionally absent: there is no user/directory
// system yet, so they'd resolve to empty and mislead. Keep in sync with the
// server registry (controller/services/variables.py VARIABLE_SPECS).
export const NAME_VARIABLES: NameVariable[] = [
  { key: "serial", description: "Hardware serial number" },
  { key: "model", description: "Device model identifier" },
  { key: "hostname", description: "Name the device reports for itself" },
  { key: "os", description: "Operating system version" },
  { key: "udid", description: "Full enrollment UDID" },
  { key: "udid_short", description: "First 8 characters of the UDID" },
  { key: "management_type", description: "Management backend (apple_mdm, …)" },
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

// Render a naming template against a device -- mirror of variables.render() in
// the controller (single-pass, stray braces stripped, whitespace/separator
// tidied, 63-char cap). Returns "" when the template renders to nothing.
export function renderNameTemplate(template: string, d: Device): string {
  if (!template || !template.trim()) return "";
  const ctx = nameContext(d);
  const out = template
    .replace(/\{([^}]+)\}/g, (_, k) => ctx[String(k).trim()] ?? "")
    .replace(/[{}]/g, "") // drop stray braces left by a malformed template
    .replace(/\s+/g, " ")
    .replace(/^[ \-_.]+|[ \-_.]+$/g, "");
  // Cap by code points (like Python's str[:63]) so we never split a surrogate
  // pair -- a plain .slice() counts UTF-16 units and could truncate mid-emoji.
  return Array.from(out).slice(0, 63).join("");
}

// Variables referenced by a template that aren't in the registry (typo warnings).
export function unknownNameVariables(template: string): string[] {
  const known = new Set(NAME_VARIABLES.map((v) => v.key).concat("os_version"));
  const out: string[] = [];
  const re = /\{([^}]+)\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(template)) !== null) {
    const k = m[1].trim();
    if (!known.has(k) && !out.includes(k)) out.push(k);
  }
  return out;
}

// True if the template references {hostname} -- self-referential, since the
// managed name is pushed to the device and becomes its reported hostname, so
// re-deriving compounds. Tokenizes exactly like the server (variables
// .is_self_referential): parse {name} tokens, trim, membership-test -- so a
// malformed `{{hostname}` (whose token is `{hostname`) agrees with Python.
export function isSelfReferentialTemplate(template: string): boolean {
  const re = /\{([^}]+)\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(template)) !== null) {
    if (m[1].trim() === "hostname") return true;
  }
  return false;
}

// Best-effort map a device model to an Apple platform (mirrors the controller).
export function devicePlatform(model: string | null | undefined): "iOS" | "macOS" | "tvOS" {
  const m = (model ?? "").toLowerCase();
  if (m.includes("mac")) return "macOS";
  if (m.includes("appletv") || m.includes("apple tv")) return "tvOS";
  return "iOS";
}

// ── Config resource hook (load / save a single config type) ──────────────────

type ConfigType = "groups" | "apps" | "profiles" | "tags";

export function useConfigResource<T>(type: ConfigType, empty: T) {
  const { token } = useAuth();
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const reload = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = (await api.getConfig(token, type)) as T;
      setData(res ?? empty);
    } catch (e: unknown) {
      // A missing config file (404) is just an empty config to be created.
      if (e instanceof ApiError && e.status === 404) {
        setData(empty);
      } else {
        notifications.show({ color: "red", message: (e as Error).message });
      }
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, type]);

  useEffect(() => {
    reload();
  }, [reload]);

  const save = useCallback(
    async (next: T): Promise<boolean> => {
      if (!token) return false;
      setSaving(true);
      try {
        const res = await api.updateConfig(token, type, next as Record<string, unknown>);
        setData(next);
        notifications.show({ color: "teal", message: res.message });
        (res.warnings ?? []).forEach((w) =>
          notifications.show({ color: "yellow", title: "Warning", message: w }),
        );
        return true;
      } catch (e: unknown) {
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
    [token, type],
  );

  return { data, setData, loading, saving, reload, save };
}

// Load the advisory tag registry (tags.yaml) for pickers / autocomplete / chip
// colours. Silent by design: a missing registry (404) or any load error is just
// an empty list -- free-form tags remain valid everywhere.
export function useTagRegistry() {
  const { token } = useAuth();
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

  return { tags, tagNames, colorOf, labelOf, loading, reload };
}

export async function sha256Hex(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
