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
export type EditableConfigType = "groups" | "apps" | "profiles" | "tags" | "flows" | "dispatcher" | "declarations";
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

  // Forget a device (admin only). 409 if it is still enrolled -- unenroll first.
  deleteDevice(token: string, id: string) {
    return request<{ message: string }>(`/api/v1/devices/${id}`, token, {
      method: "DELETE",
    });
  },

  // Read-only "why does / doesn't this device receive X" troubleshooting.
  explainDeviceScope(token: string, id: string) {
    return request<ScopeExplain>(`/api/v1/devices/${id}/scope-explain`, token);
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
    params: { skip?: number; limit?: number; status?: string; device_id?: string; user?: string } = {},
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

  // Non-secret projection (kinds, labels, reveal ledger) -- never the plaintext.
  getDeviceSecrets(token: string, deviceId: string) {
    return request<{ secrets: DeviceSecret[] }>(
      `/api/v1/devices/${deviceId}/secrets`,
      token,
    );
  },
  // Break the glass: returns the plaintext ONCE, audits, and raises a board alert.
  revealDeviceSecret(token: string, deviceId: string, kind: string) {
    return request<RevealedSecret>(
      `/api/v1/devices/${deviceId}/secrets/${kind}/reveal`,
      token,
      { method: "POST" },
    );
  },

  //  ATC flows 
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
  // Manually start a run from a specific start node against a device.
  startFlowRun(token: string, deviceId: string, startNodeId: string) {
    return request<FlowRunSummary>(`/api/v1/devices/${deviceId}/flow-runs`, token, {
      method: "POST",
      body: JSON.stringify({ start_node_id: startNodeId }),
    });
  },
  // Resume a run parked on a manual_gate down the chosen decision edge.
  resumeFlowRun(token: string, runId: string, edge: string) {
    return request<FlowRunSummary>(`/api/v1/flow-runs/${runId}/resume`, token, {
      method: "POST",
      body: JSON.stringify({ edge }),
    });
  },

  //  Dispatcher (compliance) 
  getDispatcherCheckCatalog(token: string) {
    return request<{ checks: DispatcherCheckSpec[] }>("/api/v1/dispatcher/check-catalog", token);
  },
  listAlerts(
    token: string,
    params: { severity?: string; status?: string; device_id?: string } = {},
  ) {
    const qs = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v !== undefined).map(([k, v]) => [k, String(v)]),
    ).toString();
    return request<{ alerts: DispatcherAlert[]; counts: Record<string, number>; active: number }>(
      `/api/v1/alerts${qs ? `?${qs}` : ""}`,
      token,
    );
  },
  getAlert(token: string, id: string) {
    return request<DispatcherAlert>(`/api/v1/alerts/${id}`, token);
  },
  acknowledgeAlert(token: string, id: string) {
    return request<DispatcherAlert>(`/api/v1/alerts/${id}/acknowledge`, token, { method: "POST" });
  },
  resolveAlert(token: string, id: string) {
    return request<DispatcherAlert>(`/api/v1/alerts/${id}/resolve`, token, { method: "POST" });
  },
  // Take a typed action on an ATC alert (in-setup release / gate decision).
  alertAction(token: string, id: string, actionKey: string) {
    return request<{ message: string; alert?: DispatcherAlert; run?: FlowRunSummary }>(
      `/api/v1/alerts/${id}/action`,
      token,
      { method: "POST", body: JSON.stringify({ action_key: actionKey }) },
    );
  },
  // Admin-approve a queued destructive remediation.
  approveRemediation(token: string, id: string, actionKey: string) {
    return request<{ message: string; outcome: string; alert: DispatcherAlert }>(
      `/api/v1/alerts/${id}/remediate`,
      token,
      { method: "POST", body: JSON.stringify({ action_key: actionKey }) },
    );
  },
  dispatcherEvaluate(token: string) {
    return request<{ message: string; devices_evaluated: number }>(
      "/api/v1/dispatcher/evaluate",
      token,
      { method: "POST" },
    );
  },

  cancelTask(token: string, id: string) {
    return request<{ message: string }>(`/api/v1/tasks/${id}/cancel`, token, {
      method: "POST",
    });
  },

  // Re-run a failed or cancelled task through its original handler as a fresh
  // task (server rejects in-flight/completed tasks and non-re-runnable types).
  retryTask(token: string, id: string) {
    return request<{ task_id: string; message: string }>(
      `/api/v1/tasks/${id}/retry`,
      token,
      { method: "POST" },
    );
  },

  // Tenant
  getTenant(token: string) {
    return request<TenantInfo>("/api/v1/tenant", token);
  },

  // Update tenant settings (admin only). Any omitted field is left unchanged.
  updateTenant(
    token: string,
    body: {
      name?: string;
      allowed_users?: string[];
      s3_config?: Record<string, unknown>;
      dep_enabled?: boolean;
      // Declarative Device Management (DDM). Enabling queues a declarative
      // sync to every supported device on the next reconcile.
      ddm_enabled?: boolean;
      is_active?: boolean;
      // Renewal reminders (manual-entry MVP). "YYYY-MM-DD" or a full ISO
      // datetime; omitted leaves the stored value unchanged (there is no
      // way to clear a date via this endpoint today).
      apns_cert_expires_at?: string;
      dep_token_expires_at?: string;
      // Tenant-default device-naming template (services.naming). Empty template
      // ({ template: "" }) clears it; omitted leaves it unchanged.
      device_naming?: { template: string; apply_on_enroll?: boolean };
    },
  ) {
    return request<{ message: string }>("/api/v1/tenant", token, {
      method: "PUT",
      body: JSON.stringify(body),
    });
  },

  // Users (admin only -- server enforces via require_admin; a non-admin call
  // 403s and the caller should surface that through notifications).
  listUsers(token: string) {
    return request<{ users: User[] }>("/api/v1/users", token);
  },

  createUser(
    token: string,
    body: { email: string; role: string; password?: string; external_id?: string },
  ) {
    return request<{ id: string; email: string; role: string }>("/api/v1/users", token, {
      method: "POST",
      body: JSON.stringify(body),
    });
  },

  updateUser(
    token: string,
    id: string,
    body: { role?: string; password?: string; is_active?: boolean },
  ) {
    return request<{ message: string }>(`/api/v1/users/${id}`, token, {
      method: "PUT",
      body: JSON.stringify(body),
    });
  },

  deleteUser(token: string, id: string) {
    return request<{ message: string }>(`/api/v1/users/${id}`, token, {
      method: "DELETE",
    });
  },

  // Enrollment
  getEnrollment(token: string) {
    return request<EnrollmentDetails>("/api/v1/enrollment", token);
  },
  // Same-origin download path (through the proxy) for the enrollment profile.
  enrollmentDownloadPath(tenantId: string, enrollToken: string) {
    return `/api/proxy/api/v1/enroll/${encodeURIComponent(tenantId)}/${encodeURIComponent(enrollToken)}`;
  },

  // Recent POST-SCEP webhook check-ins that never became a device (diagnostic;
  // SCEP-stage failures are invisible -- see EnrollmentAttempt).
  getEnrollmentAttempts(
    token: string,
    params: { skip?: number; limit?: number; outcome?: string } = {},
  ) {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== undefined)
        .map(([k, v]) => [k, String(v)]),
    ).toString();
    return request<{ total: number; attempts: EnrollmentAttempt[] }>(
      `/api/v1/enrollment-attempts${qs ? `?${qs}` : ""}`,
      token,
    );
  },

  // Admin actions taken through the console (admin-only, tenant-scoped).
  listAuditLog(
    token: string,
    params: {
      skip?: number;
      limit?: number;
      action?: string;
      actor?: string;
      target_type?: string;
    } = {},
  ) {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== undefined)
        .map(([k, v]) => [k, String(v)]),
    ).toString();
    return request<{ total: number; entries: AuditLogEntry[] }>(
      `/api/v1/audit-log${qs ? `?${qs}` : ""}`,
      token,
    );
  },

  //  Automated Device Enrollment (ADE/DEP) + ABM/ASM 
  listDepServers(token: string) {
    return request<{ servers: DepServer[] }>("/api/v1/dep/servers", token);
  },
  getDepServer(token: string, id: string) {
    return request<DepServerDetail>(`/api/v1/dep/servers/${id}`, token);
  },
  createDepServer(token: string, name: string) {
    return request<DepServerDetail>("/api/v1/dep/servers", token, {
      method: "POST",
      body: JSON.stringify({ name }),
    });
  },
  async uploadDepToken(token: string, id: string, file: File) {
    const fd = new FormData();
    fd.append("file", file);
    // Direct fetch so the browser sets the multipart boundary itself.
    const res = await fetch(proxyPath(`/api/v1/dep/servers/${id}/token`), {
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
    return res.json() as Promise<DepServer>;
  },
  unlinkDepServer(token: string, id: string) {
    return request<{ status: string }>(`/api/v1/dep/servers/${id}`, token, { method: "DELETE" });
  },
  // Fully remove a connection (never-finished or retired), rather than unlinking it.
  removeDepServer(token: string, id: string) {
    return request<{ status: string }>(`/api/v1/dep/servers/${id}?purge=true`, token, {
      method: "DELETE",
    });
  },
  syncDepServer(token: string, id: string) {
    return request<DepSyncSummary>(`/api/v1/dep/servers/${id}/sync`, token, { method: "POST" });
  },
  listDepDevices(token: string, id: string) {
    return request<{ devices: DepDevice[] }>(`/api/v1/dep/servers/${id}/devices`, token);
  },
  setDepDefaultProfile(token: string, id: string, profileId: string | null) {
    return request<DepServer>(`/api/v1/dep/servers/${id}/default-profile`, token, {
      method: "POST",
      body: JSON.stringify({ profile_id: profileId }),
    });
  },
  pushDepProfile(token: string, id: string, profileId: string) {
    return request<DepProfileMapping>(
      `/api/v1/dep/servers/${id}/profiles/${encodeURIComponent(profileId)}/push`,
      token,
      { method: "POST" },
    );
  },
  assignDepProfile(token: string, id: string, profileId: string, serials: string[]) {
    return request<{ results: Record<string, string> }>(`/api/v1/dep/servers/${id}/assign`, token, {
      method: "POST",
      body: JSON.stringify({ profile_id: profileId, serials }),
    });
  },
  unassignDepProfile(token: string, id: string, serials: string[]) {
    return request<{ results: Record<string, string> }>(`/api/v1/dep/servers/${id}/unassign`, token, {
      method: "POST",
      body: JSON.stringify({ serials }),
    });
  },
  disownDepDevices(token: string, id: string, serials: string[]) {
    return request<{ results: Record<string, string> }>(`/api/v1/dep/servers/${id}/disown`, token, {
      method: "POST",
      body: JSON.stringify({ serials }),
    });
  },
  getDepSkipKeys(token: string) {
    return request<{ skip_keys: DepSkipKey[] }>("/api/v1/dep/skip-keys", token);
  },

  //  Declarative Device Management (DDM) 
  // Per-device DDM state: desired vs. reported declarations, sync status, drift.
  // include_payloads=1 additionally returns each desired declaration's raw payload.
  getDeviceDdm(token: string, deviceId: string, includePayloads = false) {
    const qs = includePayloads ? "?include_payloads=1" : "";
    return request<DdmDeviceState>(`/api/v1/devices/${deviceId}/ddm${qs}`, token);
  },
  // Queue an immediate DDM sync for this device (admin).
  syncDeviceDdm(token: string, deviceId: string) {
    return request<{ queued: boolean }>(`/api/v1/devices/${deviceId}/ddm/sync`, token, {
      method: "POST",
    });
  },
  // Declarations catalog for the Declarations page (mirrors the declarations.yaml
  // document, one row per declaration with its scope summary).
  listDeclarations(token: string) {
    return request<{ declarations: DeclarationSummary[] }>("/api/v1/declarations", token);
  },

  // Health
  health() {
    return request<{ status: string }>("/api/v1/health", undefined);
  },
};

//  Types 

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

// Break-The-Glass: an escrowed per-device secret (non-secret projection). The
// plaintext is never in this shape -- it only arrives in RevealedSecret.
export interface DeviceSecret {
  id: string;
  device_id: string;
  kind: string;         // managed_admin_password | firmware_password | recovery_lock
  kind_label: string;
  label: string | null;
  meta: Record<string, unknown>;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
  revealed_at: string | null;
  revealed_by: string | null;
  reveal_count: number;
  sealed: boolean;      // true == the glass has never been broken
}

export interface RevealedSecret {
  kind: string;
  kind_label: string;
  label: string | null;
  value: string;        // the plaintext, returned once
  meta: Record<string, unknown>;
  revealed_at: string | null;
  reveal_count: number;
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
  // Most recent failed task for this device (detail endpoint only), so a failed
  // deployment surfaces its reason without opening the Activity tab.
  last_task_error?: {
    task_id: string;
    task_type: string;
    error: string | null;
    created_at: string | null;
    completed_at: string | null;
  } | null;
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

// One profile/app/group in a device's scope-explain response: whether the
// device receives it and a human-readable reason for the decision.
export interface ScopeExplainEntry {
  id: string;
  name: string;
  matched: boolean;
  reason: string;
}

export interface ScopeExplain {
  profiles: ScopeExplainEntry[];
  apps: ScopeExplainEntry[];
  groups: ScopeExplainEntry[];
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
  // Admin-entered renewal reminders (manual-entry MVP -- not live cert/token
  // introspection). days_remaining may be negative (already expired); both
  // are null when the corresponding date is unset.
  apns_cert_expires_at: string | null;
  apns_days_remaining: number | null;
  dep_token_expires_at: string | null;
  dep_days_remaining: number | null;
}

// A logged POST-SCEP webhook check-in that could not be turned into (or
// matched to) a device. Mirrors EnrollmentAttempt.to_dict()
// (controller/models/tenant.py). tenant_id is null for no_tenant rows (the
// requested tenant was unverified) or this tenant's own id for no_serial rows;
// the tenant-scoped list endpoint can never return another tenant's rows.
export interface EnrollmentAttempt {
  id: string;
  tenant_id: string | null;
  udid: string | null;
  serial_number: string | null;
  topic: string | null;
  outcome: string; // "no_tenant" | "no_serial"
  detail: Record<string, unknown>;
  created_at: string | null;
}

//  ADE/DEP + ABM/ASM. Mirror DepServer.to_dict() (controller/models/tenant.py)
// and controller/api/dep.py. Secret token/key material is NEVER present. 
export type DepServerStatus = "unlinked" | "awaiting_token" | "linked" | "error";

export interface DepServer {
  id: string;
  tenant_id: string;
  name: string;
  status: DepServerStatus;
  has_public_cert: boolean;
  has_token: boolean;
  cert_expires_at: string | null;
  token_expires_at: string | null;
  account: {
    org_name?: string | null;
    server_name?: string | null;
    org_id?: string | null;
    org_email?: string | null;
    admin_id?: string | null;
    org_type?: string | null;
  };
  sync_cursor_at: string | null;
  last_sync_at: string | null;
  last_sync_status: string | null;
  last_sync_error: string | null;
  default_profile_id: string | null;
  last_error: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface DepProfileMapping {
  id: string;
  dep_server_id: string;
  profile_id: string;
  profile_uuid: string | null;
  pushed_at: string | null;
  last_error: string | null;
  updated_at: string | null;
}

// getDepServer adds the public cert (for re-download), the enrollment URL, and
// the pushed-profile mappings.
export interface DepServerDetail extends DepServer {
  public_cert_pem: string | null;
  enroll_url: string | null;
  profiles: DepProfileMapping[];
}

export interface DepDevice {
  id: string;
  serial_number: string;
  device_model: string;
  enrollment_state: EnrollmentState;
  enrolled: boolean;
  dep_profile_uuid: string | null;
  dep_profile_status: string | null;
  name: string | null;
  dep_last_synced_at: string | null;
}

export interface DepSyncSummary {
  ok: boolean;
  added?: number;
  modified?: number;
  deleted?: number;
  pages?: number;
  error?: string;
}

export interface DepSkipKey {
  name: string;
  label: string;
  platforms: string;
  deprecated: boolean;
}

//  Declarative Device Management (DDM) 
// Mirrors controller/services/ddm_manager.py's computed declaration set and
// the device's DDM status report (StatusItems from the DeclarativeManagement
// status channel). One declaration the controller wants the device to have.
export interface DdmDeclarationDesired {
  identifier: string;
  type: string; // e.g. "com.apple.configuration.legacy"
  server_token: string;
  source: string; // where this declaration came from (profile bridge, native, etc.)
  name: string;
  // Only present when the caller passed include_payloads=1.
  payload?: Record<string, unknown>;
}

// What the device itself reported back for one declaration (keyed by identifier
// in DdmDeviceState.reported).
export interface DdmDeclarationReported {
  active: boolean;
  valid: "unknown" | "invalid" | "valid";
  "server-token"?: string;
  reasons?: Array<{ code?: string; description?: string; details?: Record<string, unknown> }>;
}

export interface DdmDeviceState {
  supported: boolean;
  tenant_enabled: boolean;
  enabled_at: string | null;
  last_sync_at: string | null;
  last_published_token: string | null;
  desired: DdmDeclarationDesired[];
  reported: Record<string, DdmDeclarationReported>;
  // Nested/dot-path status facts (StatusItems), rendered data-driven like
  // Device.attributes.
  status_items: Record<string, unknown>;
  client_capabilities: Record<string, unknown>;
  // Identifiers present in `desired` but missing/inactive/invalid in `reported`.
  drift: string[];
}

// One row on the Declarations page. Mirrors DeclarationItem (declarations.yaml,
// controller/utils/yaml_validator.py) -- id, type, and the same scoping fields
// as a Profile (groups/conditions/include-exclude/rollout) -- summarized by
// GET /api/v1/declarations. Scope details are summarized server-side into the
// `scope` object; counts stand in for the raw condition/cherry-pick lists.
export interface DeclarationSummary {
  id: string;
  name: string;
  type: string;
  description?: string;
  scope?: {
    platforms?: string[];
    groups?: string[];
    conditions?: number;
    include_devices?: number;
    exclude_devices?: number;
    rollout?: boolean;
  };
  scoped_count?: number;
}

// An admin action recorded through the console. Mirrors AuditLog.to_dict()
// (controller/models/tenant.py). detail carries only non-secret context.
export interface AuditLogEntry {
  id: string;
  tenant_id: string | null;
  actor_email: string | null;
  actor_role: string | null;
  action: string; // e.g. "user.create" | "user.update" | "user.delete" | "device.forget"
  target_type: string | null; // e.g. "user" | "device"
  target_id: string | null;
  detail: Record<string, unknown>;
  created_at: string | null;
}

export interface TenantInfo {
  id: string;
  name: string;
  allowed_users: string[];
  s3_config?: Record<string, unknown>;
  auth_provider?: string;
  dep_enabled: boolean;
  // Declarative Device Management (DDM). enabled_at is null until the tenant
  // has ever turned it on.
  ddm_enabled: boolean;
  ddm_enabled_at?: string | null;
  created_at: string;
  is_active: boolean;
  // Admin-entered renewal reminders (manual-entry MVP).
  apns_cert_expires_at: string | null;
  dep_token_expires_at: string | null;
  // Tenant-default device-naming template (services.naming).
  device_naming?: { template?: string; apply_on_enroll?: boolean };
}

// Console user (tenant-scoped admin/member account). Mirrors the shape
// returned by GET /api/v1/users (controller/api/main.py::list_users).
export interface User {
  id: string;
  email: string;
  role: string; // "admin" | "member"
  is_active: boolean;
  has_password: boolean; // false for external-IdP (Clerk/OIDC) accounts
  external_id: string | null;
}

//  ATC flow types 

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
  edges: ("next" | "on_true" | "on_false" | "on_timeout" | "on_release" | "on_cancel" | "on_wait")[];
  params: FlowNodeParamSpec[];
}

export interface WaitSignal {
  value: string;
  label: string;
  description: string;
}

export interface StartKind {
  value: string; // enroll_dep | enroll_profile | checkin | schedule
  label: string;
  description?: string;
}

export interface FlowStepCatalog {
  nodes: FlowNodeSpec[];
  wait_signals: WaitSignal[];
  start_kinds: StartKind[];
  gate_edges: string[];
}

export interface FlowRunSummary {
  id: string;
  tenant_id: string;
  device_id: string | null;
  flow_id: string;
  start_node?: string | null;
  event_kind?: string | null;
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

//  flows.yaml document shape (authored by the visual editor) 

export interface FlowNode {
  id: string;
  type: string;
  params?: Record<string, unknown>;
  next?: string;
  on_true?: string;
  on_false?: string;
  on_timeout?: string;
  // manual_gate decision handles (fixed enum, wired from params.options[].edge).
  on_release?: string;
  on_cancel?: string;
  on_wait?: string;
  ui?: { x: number; y: number };
}

// The single ATC flow. Entry points are `start` nodes inside `nodes` (there is
// no per-flow trigger); each start carries its own kind + match scope.
export interface FlowDoc {
  id: string;
  name: string;
  enabled?: boolean;
  nodes: FlowNode[];
}

export interface FlowsConfig {
  flow: FlowDoc;
}

//  Dispatcher (compliance) types 

export interface DispatcherCheckParamSpec {
  name: string;
  label: string;
  type: string; // string | int | tags | select
  required?: boolean;
  help?: string;
  options?: string[];
}

export interface DispatcherCheckSpec {
  type: string;
  label: string;
  description: string;
  category: string;
  params: DispatcherCheckParamSpec[];
}

export type Severity = "black" | "red" | "yellow" | "green";

export interface DispatcherAlert {
  id: string;
  tenant_id: string;
  device_id: string | null;
  rule_id: string;
  severity: Severity;
  status: string; // pending | open | acknowledged | resolved
  summary: string;
  detail: Record<string, unknown>;
  first_detected_at: string | null;
  opened_at: string | null;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
  updated_at: string | null;
  device?: { serial_number: string | null; display_name: string | null } | null;
}

export interface DispatcherWebhook {
  name: string;
  url: string;
  secret?: string;
}

export interface DispatcherAction {
  type: string; // webhook | assign_tag | remove_tag | install_profiles | install_apps | send_command
  params?: Record<string, unknown>;
  dry_run?: boolean;
}

export interface DispatcherRule {
  id: string;
  name: string;
  enabled?: boolean;
  severity: Severity;
  scope?: Record<string, unknown>;
  check: Record<string, unknown>;
  grace_minutes?: number;
  actions?: DispatcherAction[];
  auto_resolve?: boolean;
}

export interface DispatcherConfig {
  webhooks?: DispatcherWebhook[];
  rules?: DispatcherRule[];
  auto_remediation_enabled?: boolean;
}
