// Shared types + helpers for the visual config editors (groups / apps / profiles).
// Types mirror the controller's YAML schema (controller/utils/yaml_validator.py)
// and group evaluation logic (controller/services/group_manager.py).

import { useCallback, useEffect, useState } from "react";
import { notifications } from "@mantine/notifications";
import { api, ApiError, type Device } from "./api";
import { useAuth } from "./auth-context";

// ── Schema types ─────────────────────────────────────────────────────────────

export type ConditionType =
  | "device_model"
  | "serial_number"
  | "hostname"
  | "os_version"
  | "enrollment_date";

export interface Condition {
  type: ConditionType;
  operator: string;
  value: string | string[];
}

export interface Group {
  name: string;
  description?: string;
  conditions: Condition[];
}
export interface GroupsConfig {
  groups: Group[];
}

export interface AppVersion {
  version: string;
  s3_key: string;
  sha256: string;
  groups: string[];
  conditions?: Condition[];
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

export interface Profile {
  id: string;
  name: string;
  description?: string;
  payload_type?: string;
  type?: ProfileKind;
  platforms?: string[]; // target platforms: iOS | macOS | tvOS
  groups?: string[];
  dep_profile?: boolean;
  payload?: Record<string, unknown>; // legacy single payload
  payloads?: Record<string, unknown>[]; // multiple payloads (preferred)
}
export interface ProfilesConfig {
  profiles: Profile[];
}

// Normalise a profile's payloads to a list regardless of which form it was saved in.
export function profilePayloads(p: Profile): Record<string, unknown>[] {
  if (Array.isArray(p.payloads)) return p.payloads;
  if (p.payload && Object.keys(p.payload).length) return [p.payload];
  return [];
}

// ── Condition metadata (drives the visual builder) ───────────────────────────

export type ValueKind = "text" | "version" | "date" | "list";

export interface ConditionTypeMeta {
  value: ConditionType;
  label: string;
  operators: string[];
  // value kind per operator; "list" means a tags input (e.g. serial_number "in")
  valueKindFor: (operator: string) => ValueKind;
}

export const CONDITION_TYPES: ConditionTypeMeta[] = [
  {
    value: "device_model",
    label: "Device model",
    operators: ["regex", "equals", "contains"],
    valueKindFor: () => "text",
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
    operators: ["regex", "equals", "contains"],
    valueKindFor: () => "text",
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
];

export const OPERATOR_LABELS: Record<string, string> = {
  regex: "matches regex",
  equals: "equals",
  contains: "contains",
  in: "is one of",
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
  const t = conditionTypeMeta(c.type).label;
  const op = OPERATOR_LABELS[c.operator] ?? c.operator;
  const v = Array.isArray(c.value) ? c.value.join(", ") : c.value;
  return `${t} ${op} ${v}`;
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
  const v = Array.isArray(value) ? value : String(value ?? "");
  switch (op) {
    case "regex":
      try {
        return new RegExp(v as string).test(deviceVal);
      } catch {
        return false;
      }
    case "equals":
      return deviceVal === v;
    case "contains":
      return deviceVal.includes(v as string);
    case "in":
      return (Array.isArray(value) ? value : [value]).includes(deviceVal);
    default:
      return false;
  }
}

function evalCondition(device: Device, c: Condition): boolean {
  switch (c.type) {
    case "device_model":
      return evalString(device.device_model ?? "", c.operator, c.value);
    case "serial_number":
      return evalString(device.serial_number ?? "", c.operator, c.value);
    case "hostname":
      return evalString(device.hostname ?? "", c.operator, c.value);
    case "os_version": {
      const cmp = compareVersions(device.os_version ?? "0", String(c.value));
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
      const dv = new Date(device.enrollment_date).getTime();
      const cv = new Date(String(c.value)).getTime();
      if (Number.isNaN(dv) || Number.isNaN(cv)) return false;
      switch (c.operator) {
        case "after": return dv > cv;
        case "before": return dv < cv;
        case "equals":
          return new Date(device.enrollment_date).toDateString() ===
            new Date(String(c.value)).toDateString();
        default: return false;
      }
    }
    default:
      return false;
  }
}

export function deviceMatchesGroup(device: Device, conditions: Condition[]): boolean {
  if (!conditions || conditions.length === 0) return false; // mirrors backend
  return conditions.every((c) => evalCondition(device, c));
}

// Best-effort map a device model to an Apple platform (mirrors the controller).
export function devicePlatform(model: string | null | undefined): "iOS" | "macOS" | "tvOS" {
  const m = (model ?? "").toLowerCase();
  if (m.includes("mac")) return "macOS";
  if (m.includes("appletv") || m.includes("apple tv")) return "tvOS";
  return "iOS";
}

// ── Config resource hook (load / save a single config type) ──────────────────

type ConfigType = "groups" | "apps" | "profiles";

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

export async function sha256Hex(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
