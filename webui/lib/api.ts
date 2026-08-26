// API client. Everything goes through the Next.js proxy at /api/proxy/*, which forwards to the controller over the
// internal Docker network. The browser never talks to the controller directly.

function proxyPath(controllerPath: string) {
    // /api/v1/devices -> /api/proxy/api/v1/devices
    const stripped = controllerPath.startsWith("/") ? controllerPath.slice(1) : controllerPath;
    return `/api/proxy/${stripped}`;
}

export class ApiError extends Error {
    constructor(
        public status: number,
        message: string,
        // Raw detail from response body, structured when it's an object (config validation, command confirmation).
        public detail?: unknown,
    ) {
        super(message);
    }
}

// A 401 on any authenticated call means the session is dead, expired or revoked. Clear it and force a fresh sign-in
// rather than leave the page toasting errors.
function handleUnauthorized(path: string) {
    if (typeof window === "undefined") return;
    // login, discover, password-change, and MFA-verify all legitimately 401 on bad input; elsewhere it means dead session.
    if (
        path.startsWith("/api/v1/auth/login") ||
        path.startsWith("/api/v1/auth/discover") ||
        path.startsWith("/api/v1/auth/password") ||
        // A wrong or expired code fails the login attempt; there is no session yet to lose.
        path.startsWith("/api/v1/auth/mfa/verify")
    ) return;
    localStorage.removeItem("mm_auth");
    if (!window.location.pathname.startsWith("/login")) {
        window.location.href = "/login?expired=1";
    }
}

// The same call as request, handing back the Response as well, for the few callers that need a header off it
// (X-Config-Version on a config read or save).
async function requestWithResponse<T>(
    path: string,
    token: string | undefined,
    options: RequestInit = {},
): Promise<{ data: T; res: Response }> {
    const headers: Record<string, string> = {
        "Content-Type": "application/json",
        ...(options.headers as Record<string, string>),
    };
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const res = await fetch(proxyPath(path), {...options, headers});

    if (res.status === 401) handleUnauthorized(path);

    if (!res.ok) {
        let message = res.statusText;
        let rawDetail: unknown;
        try {
            const body = await res.json();
            rawDetail = body?.detail;
            if (rawDetail && typeof rawDetail === "object") {
                // Config validation errors and a confirmable command warning both arrive carrying errors and
                // warnings arrays; a save conflict carries error "conflict", a message and current_version.
                const d = rawDetail as { errors?: unknown; message?: unknown };
                if (Array.isArray(d.errors) && d.errors.length) {
                    message = (d.errors as string[]).join("; ");
                } else if (typeof d.message === "string" && d.message) {
                    message = d.message;
                } else {
                    message = JSON.stringify(rawDetail);
                }
            } else {
                message = (rawDetail as string) || JSON.stringify(body);
            }
        } catch {
        }
        throw new ApiError(res.status, message, rawDetail);
    }

    const text = await res.text();
    return {data: text ? JSON.parse(text) : ({} as T), res};
}

async function request<T>(
    path: string,
    token: string | undefined,
    options: RequestInit = {},
): Promise<T> {
    return (await requestWithResponse<T>(path, token, options)).data;
}

// Config documents editable through the validated PUT, with version history. "config" is readable but not editable,
// since it embeds secrets. Kept in sync with the controller allow-list (controller/api/main.py).
export type EditableConfigType = "groups" | "apps" | "profiles" | "tags" | "flows" | "dispatcher" | "declarations";
export type ReadableConfigType = EditableConfigType | "config";

// Version of a config document, reported on every read and write and sent back as If-Match on a save.
const CONFIG_VERSION_HEADER = "X-Config-Version";

// What the server sends when a save's If-Match is stale: the document changed since it was read, nothing was written.
export interface ConfigConflict {
    error: "conflict";
    message: string;
    current_version?: string;
}

export function configConflict(e: unknown): ConfigConflict | null {
    if (!(e instanceof ApiError) || e.status !== 409) return null;
    const detail = e.detail as Partial<ConfigConflict> | undefined;
    return detail && detail.error === "conflict" ? (detail as ConfigConflict) : null;
}

// GET /api/v1/stats/overview. Tasks have a total, per-status counts, and process-local running handlers count.
export interface StatsOverview {
    devices: { total: number; active_7d: number };
    tasks: { total: number; by_status: Record<string, number>; running: number };
    deployments: {
        apps: number;
        profiles: number;
        // Apps pending, installing, or accepted (not yet confirmed by device).
        apps_pending?: number;
    };
}

export const api = {
    // Auth
    login(tenantId: string, email: string, password: string) {
        return request<{ access_token: string; token_type: string; expires_in: number }>(
            "/api/v1/auth/login",
            undefined,
            {
                method: "POST",
                body: JSON.stringify({tenant_id: tenantId, user_email: email, password}),
            },
        );
    },

    me(token: string) {
        return request<{
            tenant_id: string;
            email: string;
            role: string;
            is_admin: boolean;
            // false for an external-IdP account: it has no local password to change.
            has_password: boolean;
        }>(
            "/api/v1/auth/me",
            token,
        );
    },

    // Changes every other session for the account; returned token keeps caller signed in.
    changePassword(token: string, currentPassword: string, newPassword: string) {
        return request<{ access_token: string; token_type: string; expires_in: number }>(
            "/api/v1/auth/password",
            token,
            {
                method: "POST",
                body: JSON.stringify({current_password: currentPassword, new_password: newPassword}),
            },
        );
    },

    // Email discovery (which tenants, local or external IdP).
    discoverLogin(email: string) {
        return request<{ tenants: DiscoveredTenant[] }>("/api/v1/auth/discover", undefined, {
            method: "POST",
            body: JSON.stringify({email}),
        });
    },

    // Separate from login() to support two-factor: returns mfa_token or access_token.
    loginPassword(tenantId: string, email: string, password: string) {
        return request<{
            access_token?: string;
            token_type: string;
            expires_in?: number;
            mfa_required?: boolean;
            mfa_token?: string;
        }>("/api/v1/auth/login", undefined, {
            method: "POST",
            body: JSON.stringify({tenant_id: tenantId, user_email: email, password}),
        });
    },

    // Verify MFA code (TOTP or recovery; same generic failure either way).
    verifyMfa(mfaToken: string, code: string) {
        return request<{ access_token: string; token_type: string; expires_in: number }>(
            "/api/v1/auth/mfa/verify",
            undefined,
            {
                method: "POST",
                body: JSON.stringify({mfa_token: mfaToken, code}),
            },
        );
    },

    // Current MFA status for signed-in account.
    getMfaStatus(token: string) {
        return request<{
            enabled: boolean;
            confirmed_at: string | null;
            recovery_codes_remaining: number;
        }>("/api/v1/auth/mfa", token);
    },

    // Start MFA enrollment (secret and provisioning URI; not active until confirmed).
    enrollMfa(token: string) {
        return request<{ secret: string; provisioning_uri: string }>(
            "/api/v1/auth/mfa/enroll",
            token,
            {method: "POST"},
        );
    },

    // Confirm MFA enrollment (recovery codes returned once, never refetchable).
    confirmMfaEnrollment(token: string, code: string) {
        return request<{ recovery_codes: string[] }>(
            "/api/v1/auth/mfa/confirm",
            token,
            {
                method: "POST",
                body: JSON.stringify({code}),
            },
        );
    },

    // Disable two-factor (controller re-asks password).
    disableMfa(token: string, password: string) {
        return request<void>(
            "/api/v1/auth/mfa",
            token,
            {
                method: "DELETE",
                body: JSON.stringify({password}),
            },
        );
    },

    // Stats
    getStats(token: string) {
        return request<StatsOverview>("/api/v1/stats/overview", token);
    },

    // Admin-only health check. 404 without session (security), 404 without data (not a readiness answer).
    getReadiness(token: string) {
        return request<Readiness>("/api/v1/readiness", token);
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

    // Per-app/profile deployment rollup (grouped query, not device-by-device).
    getRolloutStats(token: string, kind: "app" | "profile") {
        return request<RolloutStatsResponse>(
            `/api/v1/stats/rollout?kind=${kind}`,
            token,
        );
    },

    // Devices
    listDevices(
        token: string,
        params: {
            skip?: number;
            limit?: number;
            group?: string;
            tag?: string;
            model?: string;
            os?: string;
            search?: string;
            state?: string
        } = {},
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

    // Delete device (admin only). 409 if enrolled or holds escrowed secrets (retryable with discardSecrets).
    deleteDevice(token: string, id: string, discardSecrets = false) {
        const qs = discardSecrets ? "?discard_secrets=true" : "";
        return request<{ message: string; discarded_secret_kinds: string[] }>(
            `/api/v1/devices/${id}${qs}`,
            token,
            {method: "DELETE"},
        );
    },

    // Read-only "why does / doesn't this device receive X" troubleshooting.
    explainDeviceScope(token: string, id: string) {
        return request<ScopeExplain>(`/api/v1/devices/${id}/scope-explain`, token);
    },

    // Scope preview (read-only). empty_scope is required: "all" for flows, "none" for profiles.
    previewScope(token: string, body: ScopePreviewRequest) {
        return request<ScopePreview>("/api/v1/scope/preview", token, {
            method: "POST",
            body: JSON.stringify(body),
        });
    },

    // Set the managed name and send it to the device, when it is enrolled and supervised.
    renameDevice(token: string, id: string, name: string) {
        return request<{ device: Device; pushed: boolean; task_id: string | null }>(
            `/api/v1/devices/${id}/name`,
            token,
            {method: "PATCH", body: JSON.stringify({name})},
        );
    },

    sendCommand(
        token: string,
        deviceId: string,
        commandType: string,
        parameters: Record<string, unknown> = {},
    ) {
        return request<{
            message: string;
            task_id?: string;
            // Connector result (e.g. command_uuid); push_failed and push_errors always present.
            result?: { push_failed?: boolean; push_errors?: Record<string, string>; [key: string]: unknown };
            // Present only on confirmable warnings (acknowledged via acknowledge_warnings parameter).
            warnings?: string[];
            warning_codes?: string[];
        }>(
            `/api/v1/devices/${deviceId}/command`,
            token,
            {method: "POST", body: JSON.stringify({command_type: commandType, parameters})},
        );
    },

    // Add/remove tags; triggers group recompute and reconcile.
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

    // Config read with version (from X-Config-Version header) for optimistic locking.
    async getConfigWithVersion(token: string, type: ReadableConfigType) {
        const {data, res} = await requestWithResponse<Record<string, unknown>>(
            `/api/v1/config/${type}`,
            token,
        );
        return {data, version: res.headers.get(CONFIG_VERSION_HEADER) ?? undefined};
    },

    // Raw YAML text for the YAML viewer, with the same version. Credential redaction still applies to config.yaml.
    async getConfigRaw(token: string, type: ReadableConfigType) {
        const res = await fetch(proxyPath(`/api/v1/config/${type}?raw=true`), {
            headers: {Authorization: `Bearer ${token}`},
        });
        if (res.status === 401) handleUnauthorized("/api/v1/config");
        if (!res.ok) {
            let detail = res.statusText;
            try {
                const body = await res.json();
                detail = body.detail || JSON.stringify(body);
            } catch {
            }
            throw new ApiError(res.status, detail);
        }
        return {
            text: await res.text(),
            version: res.headers.get(CONFIG_VERSION_HEADER) ?? undefined,
        };
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
        }>("/api/v1/sync", token, {method: "POST"});
    },

    // ifMatch (document version for optimistic locking); returned version for continued saves.
    async updateConfig(
        token: string,
        type: EditableConfigType,
        data: Record<string, unknown>,
        yamlText?: string,
        opts: { ifMatch?: string } = {},
    ) {
        // The server writes this text as it stands when it parses back to exactly data, which is what keeps the
        // document's comments through a save. The form editors have no text and leave it out.
        const body = yamlText === undefined ? data : {...data, __yaml_text__: yamlText};
        const {data: result, res} = await requestWithResponse<{
            message: string;
            warnings: string[];
            flow_warnings?: FlowWarning[];
        }>(`/api/v1/config/${type}`, token, {
            method: "PUT",
            body: JSON.stringify(body),
            headers: opts.ifMatch ? {"If-Match": opts.ifMatch} : undefined,
        });
        return {...result, version: res.headers.get(CONFIG_VERSION_HEADER) ?? undefined};
    },

    // Dry-run validate (same validation as save, nothing written).
    validateConfig(
        token: string,
        type: EditableConfigType,
        data: Record<string, unknown>,
    ) {
        return request<{
            valid: boolean;
            errors: string[];
            warnings: string[];
            flow_warnings: FlowWarning[];
        }>(`/api/v1/config/${type}?dry_run=true`, token, {
            method: "PUT",
            body: JSON.stringify(data),
        });
    },

    // Config version history (every save snapshots previous document).
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

    // Restore runs same validate/snapshot/write/reconcile as save (itself undoable, conflicts like save).
    async restoreConfigVersion(
        token: string,
        type: EditableConfigType,
        id: string,
        opts: { ifMatch?: string } = {},
    ) {
        const {data, res} = await requestWithResponse<{ message: string; warnings: string[] }>(
            `/api/v1/config/${type}/history/${encodeURIComponent(id)}/restore`,
            token,
            {
                method: "POST",
                headers: opts.ifMatch ? {"If-Match": opts.ifMatch} : undefined,
            },
        );
        return {...data, version: res.headers.get(CONFIG_VERSION_HEADER) ?? undefined};
    },

    // App package upload (multipart). Returns S3 key and warnings from .pkg ToC.
    async uploadApp(token: string, file: File, appId: string, version: string) {
        const fd = new FormData();
        fd.append("file", file);
        const qs = new URLSearchParams({app_id: appId, version}).toString();
        // Direct fetch rather than the JSON request helper, so the browser sets the multipart boundary itself.
        const res = await fetch(proxyPath(`/api/v1/apps/upload?${qs}`), {
            method: "POST",
            headers: {Authorization: `Bearer ${token}`},
            body: fd,
        });
        if (res.status === 401) handleUnauthorized("/api/v1/apps/upload");
        if (!res.ok) {
            let detail = res.statusText;
            try {
                const body = await res.json();
                detail = body.detail || JSON.stringify(body);
            } catch {
            }
            throw new ApiError(res.status, detail);
        }
        return res.json() as Promise<{
            s3_key: string;
            // Digest from stored bytes (recorded on object).
            sha256: string;
            message: string;
            warnings?: string[];
        }>;
    },

    // List tenant's object store, newest first (admin only). 400 if no bucket configured.
    listAppPackages(token: string) {
        return request<AppPackageList>("/api/v1/apps/packages", token);
    },

    // Every device this app has a deployment row on, one row per device.
    getAppDeployments(token: string, appId: string) {
        return request<AppDeploymentsResponse>(
            `/api/v1/apps/${encodeURIComponent(appId)}/deployments`,
            token,
        );
    },

    // Checksum of package arriving outside upload endpoint (server streams and records digest).
    checksumAppPackage(token: string, s3Key: string) {
        return request<{ s3_key: string; sha256: string }>("/api/v1/apps/packages/checksum", token, {
            method: "POST",
            body: JSON.stringify({s3_key: s3Key}),
        });
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

    // Kinds, labels, and reveal ledger (never plaintext).
    getDeviceSecrets(token: string, deviceId: string) {
        return request<{ secrets: DeviceSecret[] }>(
            `/api/v1/devices/${deviceId}/secrets`,
            token,
        );
    },
    // Reveal plaintext (once, audited, raises alert).
    revealDeviceSecret(token: string, deviceId: string, kind: string) {
        return request<RevealedSecret>(
            `/api/v1/devices/${deviceId}/secrets/${kind}/reveal`,
            token,
            {method: "POST"},
        );
    },

    // Node palette and wait-signal registry (for visual editor).
    getFlowStepCatalog(token: string) {
        return request<FlowStepCatalog>("/api/v1/flows/step-catalog", token);
    },
    // Fleet-wide flow runs (per-device endpoint shows which one device did not provision).
    listFlowRuns(
        token: string,
        params: {
            skip?: number;
            limit?: number;
            status?: string; // one state, or a comma-separated set
            flow?: string;
            event_kind?: string;
            device_id?: string;
            waiting_signal?: string;
            released_unverified?: boolean;
            since?: string;
            until?: string;
            parked_before?: string;
        } = {},
    ) {
        const qs = new URLSearchParams(
            Object.entries(params)
                // Leave off false values (the server assumes false by default).
                .filter(([, v]) => v !== undefined && v !== false && v !== "")
                .map(([k, v]) => [k, String(v)]),
        ).toString();
        return request<FlowRunList>(`/api/v1/flow-runs${qs ? `?${qs}` : ""}`, token);
    },
    // Flow runs for one device (for run viewer).
    getDeviceFlowRuns(token: string, deviceId: string) {
        return request<{ flow_runs: FlowRunSummary[] }>(
            `/api/v1/devices/${deviceId}/flow-runs`,
            token,
        );
    },
    // Single run (includes pinned flow snapshot).
    getFlowRun(token: string, runId: string) {
        return request<FlowRunDetail>(`/api/v1/flow-runs/${runId}`, token);
    },
    // All flows and drafts (for switcher and limits).
    getFlowsSummary(token: string) {
        return request<FlowsSummaryResponse>("/api/v1/flows/summary", token);
    },
    // Create flow draft.
    async createFlowDraft(token: string, flowId: string, note?: string, ifMatch?: string) {
        const {data, res} = await requestWithResponse<FlowDoc>(
            `/api/v1/flows/${flowId}/draft`,
            token,
            {
                method: "POST",
                body: JSON.stringify({note: note ?? ""}),
                headers: ifMatch ? {"If-Match": ifMatch} : undefined,
            },
        );
        return {data, version: res.headers.get(CONFIG_VERSION_HEADER) ?? null};
    },
    // Semantic diff (live flow vs draft).
    getFlowDraftDiff(token: string, flowId: string) {
        return request<DraftDiff>(`/api/v1/flows/${flowId}/draft/diff`, token);
    },
    // Promote draft to replace live flow.
    async promoteFlowDraft(
        token: string,
        flowId: string,
        options: { acknowledge?: string[]; force?: boolean } = {},
        ifMatch?: string,
    ) {
        const {data, res} = await requestWithResponse<{
            promoted: boolean;
            summary: DraftDiffSummary;
            history_id?: string;
            gate_findings?: GateFinding[];
        }>(
            `/api/v1/flows/${flowId}/promote-draft`,
            token,
            {
                method: "POST",
                body: JSON.stringify({
                    acknowledge: options.acknowledge ?? [],
                    force: Boolean(options.force),
                }),
                headers: ifMatch ? {"If-Match": ifMatch} : undefined,
            },
        );
        return {...data, version: res.headers.get(CONFIG_VERSION_HEADER) ?? null};
    },
    // Discard draft.
    async discardFlowDraft(token: string, flowId: string, ifMatch?: string) {
        const {data, res} = await requestWithResponse<{ deleted: boolean }>(
            `/api/v1/flows/${flowId}/draft`,
            token,
            {
                method: "DELETE",
                headers: ifMatch ? {"If-Match": ifMatch} : undefined,
            },
        );
        return {...data, version: res.headers.get(CONFIG_VERSION_HEADER) ?? null};
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
    acknowledgeAlert(token: string, id: string) {
        return request<DispatcherAlert>(`/api/v1/alerts/${id}/acknowledge`, token, {method: "POST"});
    },
    unacknowledgeAlert(token: string, id: string) {
        return request<DispatcherAlert>(`/api/v1/alerts/${id}/unacknowledge`, token, {method: "POST"});
    },
    // Dismissing a break-glass alert takes an admin, and only that kind of alert reads the reason.
    resolveAlert(token: string, id: string, reason?: string) {
        return request<DispatcherAlert>(`/api/v1/alerts/${id}/resolve`, token, {
            method: "POST",
            ...(reason ? {body: JSON.stringify({reason})} : {}),
        });
    },
    // Action on ATC alert (in-setup release or gate decision).
    alertAction(token: string, id: string, actionKey: string) {
        return request<{ message: string; alert?: DispatcherAlert; run?: FlowRunSummary }>(
            `/api/v1/alerts/${id}/action`,
            token,
            {method: "POST", body: JSON.stringify({action_key: actionKey})},
        );
    },
    // Admin-approve a queued destructive remediation.
    approveRemediation(token: string, id: string, actionKey: string) {
        return request<{ message: string; outcome: string; alert: DispatcherAlert }>(
            `/api/v1/alerts/${id}/remediate`,
            token,
            {method: "POST", body: JSON.stringify({action_key: actionKey})},
        );
    },
    // Veto queued remediation (allowed on resolved alerts, unlike approval).
    rejectRemediation(token: string, id: string, actionKey: string, reason?: string) {
        return request<{ message: string; alert: DispatcherAlert }>(
            `/api/v1/alerts/${id}/remediation/reject`,
            token,
            {
                method: "POST",
                body: JSON.stringify({action_key: actionKey, ...(reason ? {reason} : {})}),
            },
        );
    },
    dispatcherEvaluate(token: string) {
        return request<{ message: string; devices_evaluated: number }>(
            "/api/v1/dispatcher/evaluate",
            token,
            {method: "POST"},
        );
    },

    cancelTask(token: string, id: string) {
        return request<{ message: string }>(`/api/v1/tasks/${id}/cancel`, token, {
            method: "POST",
        });
    },

    // Retry failed or cancelled task through original handler.
    retryTask(token: string, id: string) {
        return request<{ task_id: string; message: string }>(
            `/api/v1/tasks/${id}/retry`,
            token,
            {method: "POST"},
        );
    },

    // Tenant
    getTenant(token: string) {
        return request<TenantInfo>("/api/v1/tenant", token);
    },

    //  FileVault recovery-key escrow (admin only)
    getFileVaultEscrow(token: string) {
        return request<FileVaultEscrowStatus>("/api/v1/tenant/filevault-escrow", token);
    },
    // Mint keypair (409 if one exists; replace=true reconciles by minting fresh).
    generateFileVaultEscrow(token: string, replace = false) {
        return request<FileVaultEscrowStatus>(
            `/api/v1/tenant/filevault-escrow?replace=${replace}`,
            token,
            {method: "POST"},
        );
    },
    // Certificate as PEM text, fetched with auth header (not linked).
    async getFileVaultCertificate(token: string) {
        const res = await fetch(proxyPath("/api/v1/tenant/filevault-escrow/certificate"), {
            headers: {Authorization: `Bearer ${token}`},
        });
        if (res.status === 401) handleUnauthorized("/api/v1/tenant/filevault-escrow/certificate");
        if (!res.ok) {
            let detail = res.statusText;
            try {
                const body = await res.json();
                detail = body.detail || JSON.stringify(body);
            } catch {
            }
            throw new ApiError(res.status, detail);
        }
        return res.text();
    },

    // Update tenant settings (admin only). Any omitted field is left unchanged.
    updateTenant(
        token: string,
        body: {
            name?: string;
            allowed_users?: string[];
            s3_config?: Record<string, unknown>;
            dep_enabled?: boolean;
            // Enabling queues sync to every supported device on next reconcile.
            ddm_enabled?: boolean;
            is_active?: boolean;
            // Renewal reminders ("YYYY-MM-DD" or ISO datetime); null clears, omitting leaves unchanged.
            apns_cert_expires_at?: string | null;
            dep_token_expires_at?: string | null;
            // Tenant-default device-naming template. An empty template clears it, omitting it leaves it unchanged.
            device_naming?: { template: string; apply_on_enroll?: boolean };
            // Reverse-DNS base for PayloadIdentifiers (empty string clears back to built-in).
            payload_identifier_prefix?: string;
        },
    ) {
        return request<{ message: string }>("/api/v1/tenant", token, {
            method: "PUT",
            body: JSON.stringify(body),
        });
    },

    // Users, admin only. The server enforces it via require_admin, so a non-admin
    // call 403s and the caller should surface that through notifications.
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

    // POST-SCEP check-ins that never became a device (diagnostic only).
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

    // Check-ins with no tenant (admin only, all have null tenant_id).
    getUnattributedEnrollmentAttempts(
        token: string,
        params: { skip?: number; limit?: number; outcome?: string } = {},
    ) {
        const qs = new URLSearchParams(
            Object.entries(params)
                .filter(([, v]) => v !== undefined)
                .map(([k, v]) => [k, String(v)]),
        ).toString();
        return request<{ total: number; attempts: EnrollmentAttempt[] }>(
            `/api/v1/enrollment-attempts/unattributed${qs ? `?${qs}` : ""}`,
            token,
        );
    },

    // Audit log (admin only, tenant-scoped). Every filter is an exact match on server-written value.
    listAuditLog(
        token: string,
        params: {
            skip?: number;
            limit?: number;
            action?: string;
            actor?: string;
            target_type?: string;
            target_id?: string;
            // true for system rows (no human); false for person-written; omitted for both. Test undefined, not truthiness.
            system?: boolean;
            // ISO-8601 datetimes (inclusive at both ends).
            since?: string;
            until?: string;
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
    // Returns server + public_cert_pem; enroll_url and profiles from GET endpoint only.
    createDepServer(token: string, name: string) {
        return request<DepServerCreated>("/api/v1/dep/servers", token, {
            method: "POST",
            body: JSON.stringify({name}),
        });
    },
    async uploadDepToken(token: string, id: string, file: File) {
        const fd = new FormData();
        fd.append("file", file);
        // Direct fetch so the browser sets the multipart boundary itself.
        const res = await fetch(proxyPath(`/api/v1/dep/servers/${id}/token`), {
            method: "POST",
            headers: {Authorization: `Bearer ${token}`},
            body: fd,
        });
        if (res.status === 401) handleUnauthorized(`/api/v1/dep/servers/${id}/token`);
        if (!res.ok) {
            let detail = res.statusText;
            try {
                const body = await res.json();
                detail = body.detail || JSON.stringify(body);
            } catch {
            }
            throw new ApiError(res.status, detail);
        }
        return res.json() as Promise<DepServer>;
    },
    unlinkDepServer(token: string, id: string) {
        return request<{ status: string }>(`/api/v1/dep/servers/${id}`, token, {method: "DELETE"});
    },
    // Fully remove a connection (never-finished or retired), rather than unlinking it.
    removeDepServer(token: string, id: string) {
        return request<{ status: string }>(`/api/v1/dep/servers/${id}?purge=true`, token, {
            method: "DELETE",
        });
    },
    syncDepServer(token: string, id: string) {
        return request<DepSyncSummary>(`/api/v1/dep/servers/${id}/sync`, token, {method: "POST"});
    },
    listDepDevices(token: string, id: string) {
        return request<{ devices: DepDevice[] }>(`/api/v1/dep/servers/${id}/devices`, token);
    },
    setDepDefaultProfile(token: string, id: string, profileId: string | null) {
        return request<DepServer>(`/api/v1/dep/servers/${id}/default-profile`, token, {
            method: "POST",
            body: JSON.stringify({profile_id: profileId}),
        });
    },
    pushDepProfile(token: string, id: string, profileId: string) {
        return request<DepProfileMapping>(
            `/api/v1/dep/servers/${id}/profiles/${encodeURIComponent(profileId)}/push`,
            token,
            {method: "POST"},
        );
    },
    assignDepProfile(token: string, id: string, profileId: string, serials: string[]) {
        // Apple sends retry_after_seconds only on assignment, only when at least one device came back THROTTLED,
        // and only above server protocol version 10. Unassign and disown never carry it.
        return request<{ results: Record<string, string>; retry_after_seconds?: number | null }>(
            `/api/v1/dep/servers/${id}/assign`,
            token,
            {
                method: "POST",
                body: JSON.stringify({profile_id: profileId, serials}),
            },
        );
    },
    unassignDepProfile(token: string, id: string, serials: string[]) {
        return request<{ results: Record<string, string> }>(`/api/v1/dep/servers/${id}/unassign`, token, {
            method: "POST",
            body: JSON.stringify({serials}),
        });
    },
    disownDepDevices(token: string, id: string, serials: string[]) {
        return request<{ results: Record<string, string> }>(`/api/v1/dep/servers/${id}/disown`, token, {
            method: "POST",
            body: JSON.stringify({serials}),
        });
    },
    getDepSkipKeys(token: string) {
        return request<{ skip_keys: DepSkipKey[] }>("/api/v1/dep/skip-keys", token);
    },

    //  Declarative Device Management (DDM)
    // Device DDM state (desired vs reported, sync status, drift); include_payloads returns payloads.
    getDeviceDdm(token: string, deviceId: string, includePayloads = false) {
        const qs = includePayloads ? "?include_payloads=1" : "";
        return request<DdmDeviceState>(`/api/v1/devices/${deviceId}/ddm${qs}`, token);
    },
    // Queue immediate DDM sync (admin).
    syncDeviceDdm(token: string, deviceId: string) {
        return request<{ queued: boolean }>(`/api/v1/devices/${deviceId}/ddm/sync`, token, {
            method: "POST",
        });
    },
    // Declarations catalog (one row per declaration with scope).
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
    // "list" takes several of options below, comma separated; the server refuses a value outside them.
    type: "string" | "text" | "pin" | "list";
    required: boolean | "mac"; // "mac" = required when the target device is a Mac
    secret?: boolean;
    help?: string;
    // The values a "list" param accepts, published so the form can refuse one before the command is sent.
    options?: string[];
}

export interface CatalogCommand {
    type: string;
    label: string;
    description: string;
    category: string;
    common: boolean;
    contextual: boolean; // tab-backed refresh, offered on its tab, not the menu
    // Whether the effect can be walked back, as a flag rather than in the description's words. null when the
    // question does not apply.
    reversible: boolean | null;
    // What Apple accepts, enforced server-side and mirrored here only so the UI can grey a command out instead of
    // collecting a form for a 400.
    platforms: string[] | null; // device families, null = any
    supervised: boolean;        // needs a supervised device, on every platform it runs on
    // Per-platform supervised requirement (when supervised above doesn't apply to all platforms).
    supervised_platforms?: string[] | null;
    apple_silicon: boolean | null; // true = Apple silicon only, false = Intel only
    params: CommandParam[];
    destructive: boolean;
    allowed: boolean;
}

// Detail on confirmable 400s (errors and warnings carry the same sentences; warning_codes follow same order).
export interface CommandConfirmation {
    errors: string[];
    warnings: string[];
    warning_codes: string[];
    requires_confirmation: true;
}

export interface ConfigVersion {
    id: string;
    saved_at: string | null;
    user: string | null;
    size?: number;
}

// Escrowed per-device secret (without plaintext; see RevealedSecret).
export interface DeviceSecret {
    id: string;
    device_id: string;
    kind: string;         // managed_admin_password | firmware_password | recovery_lock | filevault_prk
    kind_label: string;
    label: string | null;
    // Lifecycle bookkeeping (non-secret or ciphertext, never plaintext).
    meta: Record<string, unknown>;
    created_by: string | null;
    created_at: string | null;
    updated_at: string | null;
    revealed_at: string | null;
    revealed_by: string | null;
    reveal_count: number;
    sealed: boolean;      // true == the glass has never been broken
}

// DeviceSecret.meta keys describing device confirmation state.
export interface SecretLifecycle {
    // Written but not yet acknowledged by device.
    unconfirmed_task_id?: string;
    unconfirmed_since?: string;
    unconfirmed_reason?: string;
    // Newer password sent and waiting on device answer (reveal serves live, older value until confirmed).
    pending_task_id?: string;
    pending_since?: string;
    pending_set_by?: string;
    // Device acknowledged the command that set this value.
    confirmed_at?: string;
    // What a Verify command said when run against this escrowed password.
    verified_at?: string;
    verify_failed_at?: string;
}

const LIFECYCLE_KEYS = [
    "unconfirmed_task_id", "unconfirmed_since", "unconfirmed_reason",
    "pending_task_id", "pending_since", "pending_set_by",
    "confirmed_at", "verified_at", "verify_failed_at",
] as const;

// Extract lifecycle keys from secret's meta (drop non-string values to avoid "[object Object]").
export function secretLifecycle(secret: DeviceSecret): SecretLifecycle {
    const meta = secret.meta ?? {};
    const out: SecretLifecycle = {};
    for (const key of LIFECYCLE_KEYS) {
        const value = meta[key];
        if (typeof value === "string" && value) out[key] = value;
    }
    return out;
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
    // Imperative tags (manual / ATC / Dispatcher); matched by "tag" condition.
    tags: string[];
    enrollment_state: EnrollmentState;
    management_type: string; // "apple_mdm"
    enrollment_date: string;
    unenrolled_at: string | null;
    last_seen: string;
    // Adaptive info-poll schedule: last polled and current cadence (backs off when quiet).
    last_polled_at: string | null;
    poll_interval_minutes: number;
    // Name the tenant's naming template would produce (detail endpoint only).
    suggested_name?: string | null;
    // Full device-reported state (DeviceInformation QueryResponses, SecurityInfo). Detail endpoint only.
    attributes?: Record<string, unknown>;
    // Most recent failed task for this device (detail endpoint only), so a failed deployment can show its reason
    // without opening the Activity tab.
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
    // Management intent (what was sent). last_task_id and last_error let rows be joined to their attempts.
    installed_apps: {
        app_id: string;
        version: string;
        status: string;
        install_date: string | null;
        last_error: string | null;
        last_task_id: string | null;
        // "remediation:<rule_id>" if a rule asked for it, null otherwise.
        install_source?: string | null;
        updated_at: string | null;
    }[];
    installed_profiles: {
        profile_id: string;
        status: string;
        install_date: string | null;
        last_error: string | null;
        last_task_id: string | null;
        install_source?: string | null;
        updated_at: string | null;
    }[];
    recent_tasks: Task[];
}

// One profile, app or group in a device's scope-explain response: whether the device receives it, and why.
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

// == Scope preview (POST /api/v1/scope/preview) ==

// A flow start's trigger kind, narrowing the preview to the devices that kind can reach: enroll_dep counts devices
// that came in through ADE, enroll_profile the rest, and checkin and schedule the whole enrolled fleet.
export type ScopePreviewTriggerKind =
    | "enroll_dep"
    | "enroll_profile"
    | "checkin"
    | "schedule";

export interface ScopePreviewRequest {
    scope?: Record<string, unknown>;
    // "all" for flow starts and dispatcher rules, "none" for profiles and app versions. The server 422s without it
    // rather than guess.
    empty_scope: "all" | "none";
    trigger_kind?: ScopePreviewTriggerKind | null;
    sample_limit?: number;
}

export interface ScopePreviewDevice {
    id: string;
    display_name: string;
    serial_number: string | null;
    device_model: string | null;
}

export interface ScopePreview {
    // Devices the scope matches, under the empty reading the request stated.
    matched: number;
    // Devices the trigger kind can reach, the whole enrolled fleet when no kind is given, and the whole fleet.
    eligible: number;
    total: number;
    // The reading that produced matched, echoed so a rendered number cannot be attributed to the wrong one.
    scope_is_empty: boolean;
    empty_scope: "all" | "none";
    trigger_kind: ScopePreviewTriggerKind | null;
    // The device walk, which only a non-empty scope costs. truncated makes matched a floor, rendered as at least N.
    scanned: number;
    truncated: boolean;
    sample: ScopePreviewDevice[];
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
    // Entered by admin (not live introspection); days_remaining goes negative if expired.
    apns_cert_expires_at: string | null;
    apns_days_remaining: number | null;
    dep_token_expires_at: string | null;
    dep_days_remaining: number | null;
}

// POST-SCEP check-in that could not be turned into or matched to a device.
export interface EnrollmentAttempt {
    id: string;
    tenant_id: string | null;
    udid: string | null;
    serial_number: string | null;
    topic: string | null;
    // Known outcomes: no_tenant, no_serial, bad_tenant_claim, unsigned_tenant_claim, unknown_serial, serial_conflict.
    outcome: string;
    detail: Record<string, unknown>;
    created_at: string | null;
}

//  ADE/DEP and ABM/ASM. No token or key material is ever in here.
export type DepServerStatus = "unlinked" | "awaiting_token" | "linked" | "error";

// FileVault recovery-key escrow keypair. key_decrypts null until checked, false when key doesn't match.
export interface FileVaultEscrowStatus {
    configured: boolean;
    cert_pem: string | null;
    cert_expires_at: string | null;
    fingerprint_sha256: string | null;
    key_decrypts: boolean | null;
}

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

// What POST /api/v1/dep/servers returns.
export interface DepServerCreated extends DepServer {
    public_cert_pem: string | null;
}

// What GET /api/v1/dep/servers/{id} returns: the created server plus the two fields only that endpoint computes.
export interface DepServerDetail extends DepServerCreated {
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

// One declaration the controller wants the device to have.
export interface DdmDeclarationDesired {
    identifier: string;
    type: string; // e.g. "com.apple.configuration.legacy"
    server_token: string;
    source: string; // where this declaration came from (profile bridge, native, etc.)
    name: string;
    // Present only when caller passed include_payloads=1.
    payload?: Record<string, unknown>;
}

// What the device reported back for one declaration, keyed by identifier in DdmDeviceState.reported.
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
    // Nested dot-path status facts (StatusItems, like Device.attributes).
    status_items: Record<string, unknown>;
    client_capabilities: Record<string, unknown>;
    // Identifiers present in desired but missing, inactive or invalid in reported.
    drift: string[];
}

// One row on the Declarations page: an id, a type, and the same scoping fields a Profile has. The scope object is
// summarized server-side, with counts standing in for the raw condition and cherry-pick lists.
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
    // Why item reaches no device (e.g., invalid PUBLIC_API_URL); absent if nothing blocks.
    not_served?: string;
}

// Event in this tenant. null actor_email = system row (Dispatcher, ATC, enrollment webhook); retention prunes system rows only.
export interface AuditLogEntry {
    id: string;
    tenant_id: string | null;
    actor_email: string | null;
    actor_role: string | null;
    action: string; // e.g. "user.create" | "device.forget" | "device.tags"
    target_type: string | null; // "user" | "device" | "config" | "app" | "dep_server"
    target_id: string | null;
    detail: Record<string, unknown>;
    created_at: string | null;
}

// The one action name for a device tag change, whoever made it.
export const AUDIT_TAG_ACTION = "device.tags";

/** device.tags audit detail: source (subsystem), source_ref (flow_id:node_id or rule id), reason (Dispatcher revert only). */
export interface TagAuditDetail {
    added?: string[];
    removed?: string[];
    tags?: string[];
    source?: "console" | "atc" | "dispatcher" | string;
    source_ref?: string;
    reason?: string;
    serial_number?: string | null;
}

// Readiness capability status (one row per capability, always in same order).
export interface ReadinessCapability {
    capability: string;
    ready: boolean;
    // One sentence for a human. Empty when ready.
    reason: string;
    // Names of settings not set (empty when ready).
    missing: string[];
    // Names of settings that cannot be used (empty when ready).
    broken: string[];
    // "deployment" (env var) or "tenant" (Settings); both reports "deployment".
    scope: "deployment" | "tenant";
    // Informational sentences (never block, present on all rows).
    warnings: string[];
}

export interface Readiness {
    // True only when every capability is ready (warnings never block).
    ready: boolean;
    capabilities: ReadinessCapability[];
}

// Object in package store. sha256 null when arrived outside upload endpoint.
export interface AppPackage {
    key: string;
    size: number;
    last_modified: string | null;
    sha256: string | null;
}

// quota_bytes null = unlimited; usage_bytes counts all objects under tenant's prefix.
export interface AppPackageList {
    packages: AppPackage[];
    usage_bytes: number;
    quota_bytes: number | null;
}

// One device's deployment row for a single app. status is a deployment status: pending, installing,
// accepted, installed, failed or unscoped.
export interface AppDeploymentDevice {
    device_id: string;
    hostname: string | null;
    serial_number: string;
    device_model: string;
    status: string;
    desired_version: string | null;
    reported_version: string | null;
    last_error: string | null;
    failed_attempts: number;
    install_date: string | null;
    updated_at: string;
}

// Device-by-device deployment list for one app, unlike the grouped rollout stats.
export interface AppDeploymentsResponse {
    app_id: string;
    counted_at: string;
    total: number;
    devices: AppDeploymentDevice[];
}

// Rollout stats; status keys are deployment statuses (absent = zero). Version breakdowns are apps only.
export interface RolloutItemStats {
    total: number;
    by_status: Record<string, number>;
    by_device_model: Record<string, Record<string, number>>;
    by_desired_version?: Record<string, Record<string, number>>;
    // Installed rows only, keyed by device-reported version.
    by_reported_version?: Record<string, number>;
}

export interface RolloutStatsResponse {
    kind: "app" | "profile";
    counted_at: string;
    devices_enrolled: number;
    items: Record<string, RolloutItemStats>;
}

export interface TenantInfo {
    id: string;
    name: string;
    allowed_users: string[];
    s3_config?: Record<string, unknown>;
    auth_provider?: string;
    dep_enabled: boolean;
    // enabled_at is null until DDM is first turned on.
    ddm_enabled: boolean;
    ddm_enabled_at?: string | null;
    // Object-storage ceiling (read-only, set by operator). null means unlimited.
    storage_quota_bytes?: number | null;
    created_at: string;
    is_active: boolean;
    // Renewal reminders, entered by an admin.
    apns_cert_expires_at: string | null;
    dep_token_expires_at: string | null;
    // Tenant-default device-naming template.
    device_naming?: { template?: string; apply_on_enroll?: boolean };
    // Reverse-DNS base for PayloadIdentifiers (null = built-in "com.mdm.<tenant id>").
    payload_identifier_prefix?: string | null;
    // FileVault escrow at a glance (details from getFileVaultEscrow).
    filevault_escrow?: { configured: boolean; cert_expires_at: string | null };
}

// Console user: a tenant-scoped admin or member account, as GET /api/v1/users returns it.
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
    // Warns the editor to say this value lands in plain-text, versioned yaml.
    secret?: boolean;
    // scope rides along on the start node's trigger options, which are the start kinds.
    options?: { value: string; label: string; description?: string; scope?: string }[];
}

export interface FlowNodeSpec {
    type: string;
    label: string;
    description: string;
    category: string;
    scope?: string;
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
    scope?: string;
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
    // Append-only ledger of gaps (snapshotted to alert when device released).
    gaps?: FlowGap[];
    started_at: string | null;
    updated_at: string | null;
    completed_at: string | null;
}

/** Fleet-wide run list row: lighter than FlowRunSummary (no timeline, visited, gap ledger). */
export interface FlowRunRow {
    id: string;
    device_id: string | null;
    device: {
        serial_number: string;
        hostname: string | null;
        device_model: string;
    } | null;
    flow_id: string;
    start_node: string | null;
    event_kind: string | null;
    status: string; // running | waiting | completed | failed | cancelled
    current_node: string | null;
    waiting_signal: string | null;
    waiting_ref: string | null;
    wait_deadline: string | null;
    error: string | null;
    // Device released from Setup Assistant while barrier was holding less than flow named.
    released_unverified: boolean;
    // Gap ledger reduced to count and grade (policy or broken).
    gap_count: number;
    gap_grade: "policy" | "broken" | null;
    started_at: string | null;
    updated_at: string | null;
    completed_at: string | null;
}

/** Run counts before any status filter. on_gate is subset of waiting; released_unverified is subset of failed. */
export interface FlowRunCounts {
    all: number;
    running: number;
    waiting: number;
    completed: number;
    failed: number;
    cancelled: number;
    on_gate: number;
    released_unverified: number;
}

export interface FlowRunList {
    total: number;
    counts: FlowRunCounts;
    // True when released-unverified scan hit its bound; count is a floor.
    scan_capped: boolean;
    // How far back the list can go (finished runs deleted after this many days).
    retention_days: number;
    flow_ids: string[];
    flow_runs: FlowRunRow[];
}

/** Whether the flow definition with the run is the one that actually ran (pinned/current) or not (edited/unavailable). */
export type FlowSource = "pinned" | "current" | "edited" | "unavailable";

// Run detail includes flow definition (for graphing) and flow_source (whether it records the run).
export interface FlowRunDetail extends FlowRunSummary {
    flow: FlowDoc | null;
    flow_source?: FlowSource;
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
    // manual_gate decision handles, a fixed set wired from each option's edge.
    on_release?: string;
    on_cancel?: string;
    on_wait?: string;
    ui?: { x: number; y: number };
}

// ATC multi-flow document (v2). Entry points are start nodes inside nodes, each carrying its own kind and scope.
export interface FlowDoc {
    id: string;
    name: string;
    description?: string;
    enabled?: boolean;
    permanent?: boolean;
    draft_of?: string;
    draft_base_hash?: string;
    draft_note?: string;
    draft_created_by?: string;
    draft_created_at?: string;
    nodes: FlowNode[];
}

export interface FlowsConfig {
    version?: number;
    flows?: FlowDoc[];
    flow?: FlowDoc;
}

export interface GateFinding {
    code: string;
    message: string;
    flow_id?: string | null;
    node_id?: string | null;
    advisory?: boolean;
    acknowledgeable?: boolean;
}

export interface FlowSummary {
    id: string;
    name: string;
    description?: string;
    enabled: boolean;
    permanent: boolean;
    draft_of?: string | null;
    draft_note?: string | null;
    draft_created_by?: string | null;
    draft_created_at?: string | null;
    node_count: number;
    start_kinds: string[];
    runs_in_window: number;
    active_runs: number;
    failed_in_window: number;
    last_run_at?: string | null;
    warning_count: number;
    gate_findings: GateFinding[];
}

export interface FlowsLimits {
    max_flows_per_tenant: number;
    max_drafts_per_tenant: number;
    max_nodes_per_flow: number;
    max_nodes_per_tenant: number;
    max_schedule_starts_per_tenant: number;
    max_checkin_starts_per_tenant: number;
    min_schedule_interval_minutes: number;
    min_checkin_cooldown_minutes: number;
}

export interface FlowsSummaryResponse {
    flows: FlowSummary[];
    limits: FlowsLimits;
    retention_days: number;
}

export interface DraftDiffSummary {
    added: number;
    removed: number;
    changed: number;
    unchanged: number;
    // Present on a promotion response: whether the live flow had moved since the draft was taken, which is what
    // force overrode. Recorded in the audit row too.
    base_drifted?: boolean;
}

export interface DraftDiffNode {
    id: string;
    change: "added" | "removed" | "changed";
    type?: string;
    params?: Record<string, unknown>;
    params_diff?: Record<string, { from: unknown; to: unknown }> | null;
}

export interface DraftDiffEdge {
    from: string;
    handle: string;
    change: "added" | "removed" | "changed";
    to_from?: string;
    to_to?: string;
}

export interface DraftDiff {
    flow_id: string;
    draft_id: string;
    base_hash: string;
    base_drifted: boolean;
    note?: string;
    created_by?: string;
    created_at?: string;
    summary: DraftDiffSummary;
    nodes: DraftDiffNode[];
    edges: DraftDiffEdge[];
    meta_diff: {
        name?: { from?: string; to?: string } | null;
        description?: { from?: string; to?: string } | null;
    };
}

// One structured warning from the server's flow validation.
export interface FlowWarning {
    flow_id?: string | null;
    node_id: string | null;
    code: string;
    message: string;
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

/** Whether an alert is the record of somebody being handed a device password. Only an admin may close one of
 * these, and closing it is audited. */
export function isBreakGlassAlert(alert: DispatcherAlert): boolean {
    return (alert.rule_id ?? "").startsWith("breakglass:");
}

/** Reveal record; burst set only when reveal happened inside a run (turns alert red). */
export interface BreakGlassAlertDetail {
    kind?: "break_glass";
    secret_kind?: string;
    secret_label?: string | null;
    first_revealed_by?: string;
    last_revealed_by?: string;
    last_revealed_at?: string;
    reveal_count?: number;
    burst?: boolean;
    reveals_in_window?: number;
}

/** One id that a flow step named and device did not get, with the reason. grade overrides parent gap's grade. */
export interface FlowGapItem {
    id: string;
    why: string;
    grade?: "policy" | "broken";
}

/** Entry in run's append-only gap ledger (snapshotted on device release). */
export interface FlowGap {
    at?: string;
    // Kind: not_queued, barrier_empty, never_arrived.
    kind: "not_queued" | "barrier_empty" | "never_arrived" | string;
    // Grade: policy (not entitled yet) or broken (engine couldn't deliver).
    grade: "policy" | "broken" | string;
    node?: string | null;
    signal?: string | null;
    items?: FlowGapItem[];
    note?: string;
}

export interface AtcRunFailedDetail {
    kind: "atc_run_failed";
    flow_id: string;
    flow_run_id: string;
    start_node?: string | null;
    event_kind?: string | null;
    node_id?: string | null;
    error?: string;
    held_in_setup?: boolean;
    failure_count?: number;
    first_failed_at?: string;
    last_failed_at?: string;
    // Set when device released from Setup Assistant with gaps open (ledger snapshot persists).
    released_unverified?: boolean;
    gaps?: FlowGap[];
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

/** Resume run parked on manual gate (second call on decided run is idempotent). */
export function resumeFlowRun(token: string, runId: string, edge: string) {
    return request<FlowRunSummary>(`/api/v1/flow-runs/${runId}/resume`, token, {
        method: "POST",
        body: JSON.stringify({edge}),
    });
}
