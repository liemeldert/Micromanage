// API client -- all requests go through the Next.js proxy at /api/proxy/*,
// which forwards them to the controller on the internal Docker network.
// The browser never contacts the controller directly.

function proxyPath(controllerPath: string) {
  // controllerPath: /api/v1/devices  → /api/proxy/api/v1/devices
  // Strip leading slash for the proxy prefix
  const stripped = controllerPath.startsWith("/") ? controllerPath.slice(1) : controllerPath;
  return `/api/proxy/${stripped}`;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

// A 401 on any authenticated call means the session is dead (expired or
// revoked token). Clear it and force a fresh sign-in instead of leaving the
// user on a page that just error-toasts forever.
function handleUnauthorized(path: string) {
  if (typeof window === "undefined") return;
  // login/discover legitimately 401 on bad input -- those surface inline. But a
  // 401 on /auth/me or any authed call means the session is dead → force login.
  if (path.startsWith("/api/v1/auth/login") || path.startsWith("/api/v1/auth/discover")) return;
  localStorage.removeItem("mm_auth");
  if (!window.location.pathname.startsWith("/login")) {
    window.location.href = "/login?expired=1";
  }
}

async function request<T>(
  path: string,
  token: string | undefined,
  options: RequestInit = {},
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(proxyPath(path), { ...options, headers });

  if (res.status === 401) handleUnauthorized(path);

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      const d = body?.detail;
      if (d && typeof d === "object") {
        // Config validation errors arrive as { errors: [...], warnings: [...] }.
        detail = Array.isArray(d.errors) && d.errors.length
          ? d.errors.join("; ")
          : JSON.stringify(d);
      } else {
        detail = d || JSON.stringify(body);
      }
    } catch {}
    throw new ApiError(res.status, detail);
  }

  const text = await res.text();
  return text ? JSON.parse(text) : ({} as T);
}

// Config documents editable via the validated PUT (+ version history). "config"
// is readable but not editable (it embeds secrets). Kept in sync with the
// controller allow-list (controller/api/main.py).
export type EditableConfigType = "groups" | "apps" | "profiles" | "tags" | "flows";
export type ReadableConfigType = EditableConfigType | "config";

export const api = {
  // Auth
  login(tenantId: string, email: string, password: string) {
    return request<{ access_token: string; token_type: string; expires_in: number }>(
      "/api/v1/auth/login",
      undefined,
      {
        method: "POST",
        body: JSON.stringify({ tenant_id: tenantId, user_email: email, password }),
      },
    );
  },

  me(token: string) {
    return request<{ tenant_id: string; email: string; role: string; is_admin: boolean }>(
      "/api/v1/auth/me",
      token,
    );
  },

  // Email-first sign-in: which tenants can this email use, and how (local
  // password vs external IdP). Rate-limited server-side.
  discoverLogin(email: string) {
    return request<{ tenants: DiscoveredTenant[] }>("/api/v1/auth/discover", undefined, {
      method: "POST",
      body: JSON.stringify({ email }),
    });
  },

  // Stats
  getStats(token: string) {
    return request<{
      devices: { total: number; active_7d: number };
      tasks: Record<string, number>;
      deployments: { apps: number; profiles: number };
    }>("/api/v1/stats/overview", token);
  },

  getDevicesByModel(token: string) {
    return request<{ device_model: string; count: number }[]>(
      "/api/v1/stats/devices/by-model",
      token,
    );
  },

  getDevicesByOs(token: string) {
    return request<{ os_version: string; count: number }[]>(
      "/api/v1/stats/devices/by-os",
      token,
    );
  },

  // Devices
  listDevices(
    token: string,
    params: { skip?: number; limit?: number; group?: string; tag?: string; model?: string; search?: string; state?: string } = {},
  ) {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== undefined)
        .map(([k, v]) => [k, String(v)]),
    ).toString();
    return request<{
      total: number;
      counts: { all: number; enrolled: number; unenrolled: number; pending: number };
      devices: Device[];
    }>(`/api/v1/devices${qs ? `?${qs}` : ""}`, token);
  },

  createPlaceholderDevice(
    token: string,
    body: { serial_number: string; device_model?: string; management_type?: string; groups?: string[] },
  ) {
    return request<Device>("/api/v1/devices", token, {
      method: "POST",
      body: JSON.stringify(body),
    });
  },

  getDevice(token: string, id: string) {
    return request<DeviceDetail>(`/api/v1/devices/${id}`, token);
  },

  // Set the managed name and push it to the device (if enrolled + supervised).
  renameDevice(token: string, id: string, name: string) {
    return request<{ device: Device; pushed: boolean; task_id: string | null }>(
      `/api/v1/devices/${id}/name`,
      token,
      { method: "PATCH", body: JSON.stringify({ name }) },
    );
  },

  sendCommand(
    token: string,
    deviceId: string,
    commandType: string,
    parameters: Record<string, unknown> = {},
  ) {
    return request<{ message: string; task_id?: string }>(
      `/api/v1/devices/${deviceId}/command`,
      token,
      { method: "POST", body: JSON.stringify({ command_type: commandType, parameters }) },
    );
  },

  // Add and/or remove imperative tags on a device. The controller recomputes
  // group membership and queues a reconcile (tags -> groups -> scoping).
  updateDeviceTags(
    token: string,
    id: string,
    body: { add?: string[]; remove?: string[] },
  ) {
    return request<{
      device: Device;
      changed: boolean;
      added: string[];
      removed: string[];
      groups_changed?: boolean;
    }>(`/api/v1/devices/${id}/tags`, token, {
      method: "POST",
      body: JSON.stringify(body),
    });
  },

  // YAML configs
  getConfig(token: string, type: ReadableConfigType) {
    return request<Record<string, unknown>>(`/api/v1/config/${type}`, token);
  },

  // Raw YAML document (text) -- for the YAML viewer. Server-side redaction of
  // credentials still applies to config.yaml.
  async getConfigRaw(token: string, type: ReadableConfigType) {
    const res = await fetch(proxyPath(`/api/v1/config/${type}?raw=true`), {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 401) handleUnauthorized("/api/v1/config");
    if (!res.ok) {
      let detail = res.statusText;
      try {
        const body = await res.json();
        detail = body.detail || JSON.stringify(body);
      } catch {}
      throw new ApiError(res.status, detail);
    }
    return res.text();
  },

  // Reconcile declared state against devices now (also runs after each config save).
  syncNow(token: string) {
    return request<{
      message: string;
      profiles_queued: number;
      removals_queued: number;
      apps_queued: number;
      tasks_timed_out: number;
      devices: number;
      errors: number;
    }>("/api/v1/sync", token, { method: "POST" });
  },

  updateConfig(
    token: string,
    type: EditableConfigType,
    data: Record<string, unknown>,
  ) {
    return request<{ message: string; warnings: string[] }>(
      `/api/v1/config/${type}`,
      token,
      { method: "PUT", body: JSON.stringify(data) },
    );
  },

  validateConfigs(token: string) {
    return request<{ valid: boolean; errors: string[]; warnings: string[] }>(
      "/api/v1/config/validate",
      token,
      { method: "POST" },
    );
  },

  // Config version history: every save snapshots the previous document.
  listConfigHistory(token: string, type: EditableConfigType) {
    return request<{ versions: ConfigVersion[] }>(
      `/api/v1/config/${type}/history`,
      token,
    );
  },

  getConfigVersion(token: string, type: EditableConfigType, id: string) {
    return request<ConfigVersion & { content: string }>(
      `/api/v1/config/${type}/history/${encodeURIComponent(id)}`,
      token,
    );
  },

  // Restore runs the same validate → snapshot → write → reconcile path as a
  // save, so a restore is itself undoable.
  restoreConfigVersion(token: string, type: EditableConfigType, id: string) {
    return request<{ message: string; warnings: string[] }>(
      `/api/v1/config/${type}/history/${encodeURIComponent(id)}/restore`,
      token,
      { method: "POST" },
    );
  },

  // App package upload (multipart). Returns the S3 key the controller stored it under.
  async uploadApp(token: string, file: File, appId: string, version: string) {
    const fd = new FormData();
    fd.append("file", file);
    const qs = new URLSearchParams({ app_id: appId, version }).toString();
    // Direct fetch (not the JSON `request` helper) so the browser sets the
    // multipart Content-Type + boundary itself.
    const res = await fetch(proxyPath(`/api/v1/apps/upload?${qs}`), {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: fd,
    });
    if (!res.ok) {
      let detail = res.statusText;
      try {
        const body = await res.json();
        detail = body.detail || JSON.stringify(body);
      } catch {}
      throw new ApiError(res.status, detail);
    }
    return res.json() as Promise<{ s3_key: string; message: string }>;
  },

  // Tasks
  listTasks(
    token: string,
    params: { skip?: number; limit?: number; status?: string; device_id?: string } = {},
  ) {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== undefined)
        .map(([k, v]) => [k, String(v)]),
    ).toString();
    return request<{ total: number; tasks: Task[] }>(
      `/api/v1/tasks${qs ? `?${qs}` : ""}`,
      token,
    );
  },

  getTask(token: string, id: string) {
    return request<Task>(`/api/v1/tasks/${id}`, token);
  },

  // Server-published device command catalog (role-aware). The UI builds its
  // command menus from this, so new server commands appear automatically.
  getCommandCatalog(token: string) {
    return request<{ commands: CatalogCommand[] }>("/api/v1/commands/catalog", token);
  },

  // ── ATC flows ──────────────────────────────────────────────────────────────
  // Node palette + wait-signal registry -- drives the visual editor data-driven.
  getFlowStepCatalog(token: string) {
    return request<FlowStepCatalog>("/api/v1/flows/step-catalog", token);
  },
  // Runs for a device (observability / run viewer entry points).
  getDeviceFlowRuns(token: string, deviceId: string) {
    return request<{ flow_runs: FlowRunSummary[] }>(
      `/api/v1/devices/${deviceId}/flow-runs`,
      token,
    );
  },
  // One run, including the pinned flow snapshot it is executing.
  getFlowRun(token: string, runId: string) {
    return request<FlowRunDetail>(`/api/v1/flow-runs/${runId}`, token);
  },
  // Manually start a flow against a device (testing / re-run).
  startFlowRun(token: string, deviceId: string, flowId: string) {
    return request<FlowRunSummary>(`/api/v1/devices/${deviceId}/flow-runs`, token, {
      method: "POST",
      body: JSON.stringify({ flow_id: flowId }),
    });
  },

  cancelTask(token: string, id: string) {
    return request<{ message: string }>(`/api/v1/tasks/${id}/cancel`, token, {
      method: "POST",
    });
  },

  // Tenant
  getTenant(token: string) {
    return request<TenantInfo>("/api/v1/tenant", token);
  },

  // Enrollment
  getEnrollment(token: string) {
    return request<EnrollmentDetails>("/api/v1/enrollment", token);
  },
  // Same-origin download path (through the proxy) for the enrollment profile.
  enrollmentDownloadPath(tenantId: string, enrollToken: string) {
    return `/api/proxy/api/v1/enroll/${encodeURIComponent(tenantId)}/${encodeURIComponent(enrollToken)}`;
  },

  // Health
  health() {
    return request<{ status: string }>("/api/v1/health", undefined);
  },
};

// ── Types ────────────────────────────────────────────────────────────────────

export interface DiscoveredTenant {
  tenant_id: string;
  name: string;
  provider: string; // "local" | "clerk" | "oidc"
  login_url?: string;
}

export interface CommandParam {
  name: string;
  label: string;
  type: "string" | "text" | "pin";
  required: boolean | "mac"; // "mac" = required when the target device is a Mac
  secret?: boolean;
  help?: string;
}

export interface CatalogCommand {
  type: string;
  label: string;
  description: string;
  category: string;
  common: boolean;
  contextual: boolean; // tab-backed refresh -- offered on its tab, not the menu
  params: CommandParam[];
  destructive: boolean;
  allowed: boolean;
}

export interface ConfigVersion {
  id: string;
  saved_at: string | null;
  user: string | null;
  size?: number;
}

export type EnrollmentState = "enrolled" | "unenrolled" | "pending";

export interface Device {
  id: string;
  udid: string | null;
  name: string | null;          // managed name (manual/templated); null = none
  display_name: string;         // name || hostname || serial
  serial_number: string;
  device_model: string;
  os_version: string;
  hostname: string | null;
  groups: string[];
  // Imperative labels (manual / ATC / Dispatcher); matched by the "tag" condition.
  tags: string[];
  enrollment_state: EnrollmentState;
  management_type: string; // "apple_mdm"
  enrollment_date: string;
  unenrolled_at: string | null;
  last_seen: string;
  // Name the tenant's naming template would produce (detail endpoint only).
  suggested_name?: string | null;
  // Full device-reported state (DeviceInformation QueryResponses, SecurityInfo)
  // -- present on the detail endpoint, rendered data-driven.
  attributes?: Record<string, unknown>;
}

export interface DeviceDetail {
  device: Device;
  // Inventory as reported by the device itself
  device_profiles: Record<string, unknown>[];
  device_apps: Record<string, unknown>[];
  // Management-intent deployments (what we pushed)
  installed_apps: { app_id: string; version: string; status: string; install_date: string | null }[];
  installed_profiles: { profile_id: string; status: string; install_date: string | null }[];
  recent_tasks: Task[];
}

export interface Task {
  id: string;
  type: string;
  status: string;
  device_id: string | null;
  user?: string | null;
  description: string;
  progress: number;
  error: string | null;
  created_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  details: Record<string, unknown>;
  // Present on /api/v1/tasks responses (device is prefetched server-side).
  device?: {
    serial_number: string;
    hostname: string | null;
    device_model: string;
  } | null;
}

export interface EnrollmentDetails {
  tenant_id: string;
  organization: string;
  mdm_server_url: string;
  scep_url: string;
  scep_name: string;
  topic: string | null;
  hostname: string;
  enroll_url: string | null;
  token: string;
  configured: boolean;
  missing: string[];
}

export interface TenantInfo {
  id: string;
  name: string;
  allowed_users: string[];
  s3_config?: Record<string, unknown>;
  auth_provider?: string;
  dep_enabled: boolean;
  created_at: string;
  is_active: boolean;
}

// ── ATC flow types ─────────────────────────────────────────────────────────

export interface FlowNodeParamSpec {
  name: string;
  label: string;
  // tags | profile_ids | app_ids | name_template | condition | command |
  // command_params | signal | int | string
  type: string;
  required?: boolean;
  help?: string;
  options?: { value: string; label: string; description?: string }[];
}

export interface FlowNodeSpec {
  type: string;
  label: string;
  description: string;
  category: string;
  waits: boolean;
  // Output handles this node type wires from, in UI order.
  edges: ("next" | "on_true" | "on_false" | "on_timeout")[];
  params: FlowNodeParamSpec[];
}

export interface WaitSignal {
  value: string;
  label: string;
  description: string;
}

export interface FlowStepCatalog {
  nodes: FlowNodeSpec[];
  wait_signals: WaitSignal[];
}

export interface FlowRunSummary {
  id: string;
  tenant_id: string;
  device_id: string | null;
  flow_id: string;
  flow_hash: string;
  status: string; // running | waiting | completed | failed | cancelled
  current_node: string | null;
  waiting_signal: string | null;
  waiting_ref: string | null;
  wait_deadline: string | null;
  error: string | null;
  timeline: { at: string; node: string | null; message: string }[];
  visited: string[];
  started_at: string | null;
  updated_at: string | null;
  completed_at: string | null;
}

// The run detail additionally carries the pinned flow definition so the run
// viewer can render the exact graph it executed, with the taken path highlighted.
export interface FlowRunDetail extends FlowRunSummary {
  flow: FlowDoc | null;
}

// ── flows.yaml document shape (authored by the visual editor) ──────────────

export interface FlowNode {
  id: string;
  type: string;
  params?: Record<string, unknown>;
  next?: string;
  on_true?: string;
  on_false?: string;
  on_timeout?: string;
  ui?: { x: number; y: number };
}

export interface FlowTrigger {
  on: string; // "enroll"
  match?: Record<string, unknown>;
}

export interface FlowDoc {
  id: string;
  name: string;
  enabled?: boolean;
  priority?: number;
  trigger: FlowTrigger;
  start: string;
  nodes: FlowNode[];
}

export interface FlowsConfig {
  flows: FlowDoc[];
}
