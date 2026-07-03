// API client — all requests go through the Next.js proxy at /api/proxy/*,
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
    params: { skip?: number; limit?: number; group?: string; model?: string } = {},
  ) {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== undefined)
        .map(([k, v]) => [k, String(v)]),
    ).toString();
    return request<{
      total: number;
      devices: Device[];
    }>(`/api/v1/devices${qs ? `?${qs}` : ""}`, token);
  },

  getDevice(token: string, id: string) {
    return request<DeviceDetail>(`/api/v1/devices/${id}`, token);
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

  // YAML configs
  getConfig(token: string, type: "groups" | "apps" | "profiles" | "config") {
    return request<Record<string, unknown>>(`/api/v1/config/${type}`, token);
  },

  // Raw YAML document (text) — for the YAML viewer. Server-side redaction of
  // credentials still applies to config.yaml.
  async getConfigRaw(token: string, type: "groups" | "apps" | "profiles" | "config") {
    const res = await fetch(proxyPath(`/api/v1/config/${type}?raw=true`), {
      headers: { Authorization: `Bearer ${token}` },
    });
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
    type: "groups" | "apps" | "profiles",
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

export interface Device {
  id: string;
  udid: string;
  serial_number: string;
  device_model: string;
  os_version: string;
  hostname: string | null;
  groups: string[];
  enrollment_date: string;
  last_seen: string;
}

export interface DeviceDetail {
  device: Device;
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
