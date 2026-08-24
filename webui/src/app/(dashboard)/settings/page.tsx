"use client";

import {useEffect, useRef, useState} from "react";
import {
    ActionIcon,
    Alert,
    Badge,
    Box,
    Button,
    Code,
    CopyButton,
    Divider,
    Grid,
    Group,
    Loader,
    Modal,
    PasswordInput,
    Radio,
    Stack,
    Switch,
    Text,
    TextInput,
    ThemeIcon,
} from "@mantine/core";
import {useLocalStorage} from "@mantine/hooks";
import {notifications} from "@mantine/notifications";
import {
    IconAlertTriangle,
    IconBuildingStore,
    IconCalendarDue,
    IconCheck,
    IconChevronRight,
    IconCloud,
    IconCode,
    IconCopy,
    IconDeviceFloppy,
    IconHistory,
    IconInfoCircle,
    IconLock,
    IconShieldCheck,
    IconShieldLock,
    IconShieldOff,
} from "@tabler/icons-react";
import Link from "next/link";
import QRCode from "react-qr-code";
import {api, ApiError, type TenantInfo} from "../../../../lib/api";
import {useAuth} from "../../../../lib/auth-context";
import {SHOW_YAML_STORAGE_KEY} from "../../../../lib/preferences";
import {useReadiness} from "../../../../lib/readiness";
import {useBeforeUnload} from "../../../../lib/use-unsaved-changes";
import {TagRegistryEditor} from "@/components/config/TagRegistryEditor";
import {UsersManager} from "@/components/config/UsersManager";
import {FileVaultEscrowCard} from "@/components/settings/FileVaultEscrowCard";
import {ReadinessSection} from "@/components/ReadinessStatus";
import {PageHeader} from "@/components/layout/PageHeader";
import {GlassCard} from "@/components/ui/GlassCard";

// Write-only credential material: a GET redacts these to "***redacted***", so the form never echoes
// them back into an input. Mirrors _SECRET_S3_KEYS in controller/api/main.py. session_token is
// redacted the same way and has no input here; buildS3Payload sends the sentinel to keep it.
type S3SecretKey = "access_key_id" | "secret_access_key";
const S3_REDACTED_PLACEHOLDER = "***redacted***";

// Setting any one of these declares that the tenant runs its own object store, and a bucket and both
// credentials then become required. Mirrors TENANT_S3_KEYS in controller/services/app_manager.py.
// prefix is absent from both lists: it picks a path inside whichever bucket is in force.
const TENANT_S3_KEYS = [
    "bucket", "access_key_id", "secret_access_key", "session_token",
    "endpoint_url", "region", "use_ssl", "path_style",
] as const;

// The keys this form owns an input for. PUT /api/v1/tenant replaces s3_config wholesale, so
// everything else the controller returns is carried back on save (see buildS3Payload).
const FORM_S3_KEYS = new Set<string>([
    "bucket", "region", "prefix", "endpoint_url", "use_ssl", "path_style",
    "access_key_id", "secret_access_key",
]);

// Mirrors _is_set in controller/services/app_manager.py: use_ssl false is a setting someone chose,
// an empty string is a field they cleared.
function s3IsSet(value: unknown): boolean {
    if (value === null || value === undefined) return false;
    if (typeof value === "string") return value.trim() !== "";
    return true;
}

// Whether a stored config describes the tenant's own object store, as opposed
// to leaving the tenant on the server's bucket and credentials.
function declaresOwnS3(cfg: Record<string, unknown>): boolean {
    return TENANT_S3_KEYS.some((k) => s3IsSet(cfg[k]));
}

function s3Bool(value: unknown, fallback: boolean): boolean {
    if (typeof value === "boolean") return value;
    if (typeof value === "string") {
        const t = value.trim().toLowerCase();
        if (["true", "yes", "on", "1"].includes(t)) return true;
        if (["false", "no", "off", "0", ""].includes(t)) return false;
    }
    return fallback;
}

// "server" leaves the tenant on the host's own bucket and credentials and is
// stored as an empty s3_config. "tenant" is the bring-your-own-bucket case.
type S3Mode = "server" | "tenant";

interface S3FormState {
    mode: S3Mode;
    bucket: string;
    region: string;
    prefix: string;
    endpoint_url: string;
    use_ssl: boolean;
    path_style: boolean;
    access_key_id: string; // new value only; blank = leave unchanged
    secret_access_key: string; // new value only; blank = leave unchanged
}

// Defaults match DEFAULT_S3_USE_SSL and DEFAULT_S3_PATH_STYLE in controller/services/app_manager.py,
// so a config that omits them reads here as what the controller does.
const EMPTY_S3_FORM: S3FormState = {
    mode: "server",
    bucket: "",
    region: "",
    prefix: "",
    endpoint_url: "",
    use_ssl: true,
    path_style: false,
    access_key_id: "",
    secret_access_key: "",
};

// Matches the controller's default minimum (password_policy_error), which stays the authority. This
// only keeps the button from posting a password already known to be too short.
const MIN_PASSWORD_LENGTH = 12;

export default function SettingsPage() {
    const {token, tenantId, email, isAdmin, setToken} = useAuth();
    const [tenant, setTenant] = useState<TenantInfo | null>(null);
    const [loading, setLoading] = useState(true);
    const [health, setHealth] = useState<"ok" | "error" | "loading">("loading");
    const [showYaml, setShowYaml] = useLocalStorage({
        key: SHOW_YAML_STORAGE_KEY,
        defaultValue: false,
    });
    const {readiness, loading: readinessLoading, error: readinessError} = useReadiness();

    // Own-password change (any role). null until /auth/me answers; false means an
    // external-IdP account, which has no local password to change here.
    const [hasPassword, setHasPassword] = useState<boolean | null>(null);
    const [currentPw, setCurrentPw] = useState("");
    const [newPw, setNewPw] = useState("");
    const [confirmPw, setConfirmPw] = useState("");
    const [changingPw, setChangingPw] = useState(false);
    // The controller's rejection names the rule that was broken, so it belongs
    // next to the fields rather than in a toast.
    const [pwError, setPwError] = useState<string | null>(null);

    // Two-factor auth (any role, own account only). null until /auth/mfa answers.
    const [mfaStatus, setMfaStatus] = useState<{
        enabled: boolean;
        confirmed_at: string | null;
        recovery_codes_remaining: number;
    } | null>(null);
    // Enrollment in progress: the secret/URI from enrollMfa, kept only in memory
    // until confirmMfaEnrollment succeeds or the admin backs out.
    const [enrolling, setEnrolling] = useState(false);
    const [enrollData, setEnrollData] = useState<{ secret: string; provisioning_uri: string } | null>(null);
    const [enrollCode, setEnrollCode] = useState("");
    const [enrollError, setEnrollError] = useState<string | null>(null);
    const [confirmingEnroll, setConfirmingEnroll] = useState(false);
    // Recovery codes are shown once, right after confirmation, and cannot be fetched again, so this
    // is the only copy.
    const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
    const [disableModalOpen, setDisableModalOpen] = useState(false);
    const [disablePassword, setDisablePassword] = useState("");
    const [disableError, setDisableError] = useState<string | null>(null);
    const [disabling, setDisabling] = useState(false);

    // Tenant edit form (admin only). Populated from the loaded tenant unless there are unsaved edits.
    const [nameDraft, setNameDraft] = useState("");
    const [depDraft, setDepDraft] = useState(false);
    const [ddmDraft, setDdmDraft] = useState(false);
    // Reverse-DNS base for composed PayloadIdentifiers; empty means the
    // built-in com.mdm.<tenant id> base.
    const [payloadPrefixDraft, setPayloadPrefixDraft] = useState("");
    const [s3Draft, setS3Draft] = useState<S3FormState>(EMPTY_S3_FORM);
    // Renewal reminders: plain "YYYY-MM-DD", as a native date input reads and writes. Empty means no
    // date on file; emptying a loaded value sends an explicit null on save.
    const [apnsExpiryDraft, setApnsExpiryDraft] = useState("");
    const [depExpiryDraft, setDepExpiryDraft] = useState("");
    const [tenantDirty, setTenantDirty] = useState(false);
    // Tracked apart from tenantDirty because s3_config is a whole-object replace: it goes in the body
    // only when the S3 section was touched, never as a side effect of renaming the tenant.
    const [s3Dirty, setS3Dirty] = useState(false);
    // A rejected S3 block names the keys that are missing, so that message gets a place on the page
    // rather than a toast that scrolls away.
    const [s3Error, setS3Error] = useState<string | null>(null);
    const [savingTenant, setSavingTenant] = useState(false);
    // Mirror tenantDirty into a ref so the async loadTenant reads the live value rather than the one
    // its effect captured. A slow initial GET otherwise returns mid-edit and overwrites the form.
    const tenantDirtyRef = useRef(false);
    useEffect(() => {
        tenantDirtyRef.current = tenantDirty;
    }, [tenantDirty]);

    // Freshly typed S3 credentials are never echoed back by a GET, so a reload with unsaved edits
    // loses the only copy.
    useBeforeUnload(tenantDirty || s3Dirty);

    const loadTenant = () => {
        if (!token) return Promise.resolve();
        return api.getTenant(token).then((t) => {
            setTenant(t);
            if (!tenantDirtyRef.current) {
                setNameDraft(t.name ?? "");
                setDepDraft(t.dep_enabled);
                setDdmDraft(t.ddm_enabled);
                setPayloadPrefixDraft(t.payload_identifier_prefix ?? "");
                const cfg = (t.s3_config ?? {}) as Record<string, unknown>;
                setS3Draft({
                    mode: declaresOwnS3(cfg) ? "tenant" : "server",
                    bucket: typeof cfg.bucket === "string" ? cfg.bucket : "",
                    region: typeof cfg.region === "string" ? cfg.region : "",
                    prefix: typeof cfg.prefix === "string" ? cfg.prefix : "",
                    endpoint_url: typeof cfg.endpoint_url === "string" ? cfg.endpoint_url : "",
                    use_ssl: s3Bool(cfg.use_ssl, true),
                    path_style: s3Bool(cfg.path_style, false),
                    // Never populated from a GET. Blank means keep whatever is stored.
                    access_key_id: "",
                    secret_access_key: "",
                });
                setS3Dirty(false);
                setS3Error(null);
                // ISO datetime -> "YYYY-MM-DD" for the native date input.
                setApnsExpiryDraft(t.apns_cert_expires_at ? t.apns_cert_expires_at.slice(0, 10) : "");
                setDepExpiryDraft(t.dep_token_expires_at ? t.dep_token_expires_at.slice(0, 10) : "");
            }
        });
    };

    useEffect(() => {
        if (!token) return;
        Promise.all([
            loadTenant(),
            api.health().then(() => setHealth("ok")).catch(() => setHealth("error")),
            api.me(token).then((m) => setHasPassword(m.has_password)).catch(() => {
            }),
            api.getMfaStatus(token).then(setMfaStatus).catch(() => {
            }),
        ])
            .catch((e: unknown) => notifications.show({color: "red", message: (e as Error).message}))
            .finally(() => setLoading(false));
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [token]);

    // True if the tenant currently has a credential on file for this key
    // (GET redacts the value but still reports the key as present).
    function hasExistingSecret(key: S3SecretKey): boolean {
        const cfg = (tenant?.s3_config ?? {}) as Record<string, unknown>;
        return cfg[key] === S3_REDACTED_PLACEHOLDER;
    }

    const existingCfg = (tenant?.s3_config ?? {}) as Record<string, unknown>;
    // Access key ID and secret access key go together: one fresh value would pair a new key with a
    // restored or absent partner. Neither means keep the stored pair, sent back as the sentinel.
    const s3SecretsPartial =
        (s3Draft.access_key_id.trim() !== "") !== (s3Draft.secret_access_key.trim() !== "");
    // Tenant mode with a blank bucket would PUT an empty object, which the controller reads as
    // clearing the block back to the server's storage: the opposite of what the radio says.
    const s3MissingBucket = s3Draft.mode === "tenant" && s3Draft.bucket.trim() === "";
    // A blank display name is refused: the name labels this tenant everywhere.
    const nameBlank = nameDraft.trim() === "";
    // Mirrors the server's reverse-DNS check so a bad base is named while it is
    // being typed rather than by a 400 after Save.
    const PAYLOAD_PREFIX_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
    const payloadPrefixError =
        payloadPrefixDraft.trim() === "" || PAYLOAD_PREFIX_RE.test(payloadPrefixDraft.trim())
            ? null
            : "Reverse-DNS notation: two or more dot-separated labels of lowercase letters, digits and hyphens, like com.example.mdm";
    // Stored under a key this form has no input for. Round-tripped on save, and named below.
    const hasStoredSessionToken = s3IsSet(existingCfg.session_token);
    const unknownS3Keys = Object.keys(existingCfg).filter(
        (k) => !FORM_S3_KEYS.has(k) && k !== "session_token",
    );

    /**
     * The s3_config to PUT. The endpoint replaces it wholesale, so this carries every key that has
     * to survive: a key this form has no input for is copied across untouched, and a secret nobody
     * retyped goes back as the redaction sentinel for the server to swap for the stored value
     * (_restore_tenant_s3_secrets). Server mode returns an empty object on purpose, credentials and
     * unknown keys included, since anything left behind keeps the block declared and fails the
     * controller's all-or-nothing check.
     */
    function buildS3Payload(): Record<string, unknown> {
        const prefix = s3Draft.prefix.trim();
        if (s3Draft.mode === "server") {
            // prefix is not one of TENANT_S3_KEYS, so it survives in server mode.
            return prefix ? {prefix} : {};
        }

        const next: Record<string, unknown> = {};
        for (const key of unknownS3Keys) next[key] = existingCfg[key];
        if (hasStoredSessionToken) next.session_token = S3_REDACTED_PLACEHOLDER;

        if (s3Draft.bucket.trim()) next.bucket = s3Draft.bucket.trim();
        if (s3Draft.region.trim()) next.region = s3Draft.region.trim();
        if (s3Draft.endpoint_url.trim()) next.endpoint_url = s3Draft.endpoint_url.trim();
        if (prefix) next.prefix = prefix;
        // Written whenever there is a bucket: the block is declared by then, so an explicit use_ssl
        // and an absent one resolve the same way, and writing both keeps the switches and the stored
        // config in step. Held back without a bucket so a rejection names the settings truly missing.
        if (s3Draft.bucket.trim()) {
            next.use_ssl = s3Draft.use_ssl;
            next.path_style = s3Draft.path_style;
        }

        if (s3Draft.access_key_id.trim()) next.access_key_id = s3Draft.access_key_id.trim();
        else if (hasExistingSecret("access_key_id")) next.access_key_id = S3_REDACTED_PLACEHOLDER;
        if (s3Draft.secret_access_key.trim()) next.secret_access_key = s3Draft.secret_access_key.trim();
        else if (hasExistingSecret("secret_access_key")) next.secret_access_key = S3_REDACTED_PLACEHOLDER;

        return next;
    }

    function editS3(patch: Partial<S3FormState>) {
        setS3Draft((s) => ({...s, ...patch}));
        setTenantDirty(true);
        setS3Dirty(true);
        setS3Error(null);
    }

    async function handleSaveTenant() {
        if (!token || !tenant) return;
        if (s3SecretsPartial) return; // the Save button is disabled for this too
        if (s3Dirty && s3MissingBucket) return;
        if (nameBlank) return;
        if (payloadPrefixError) return;
        setSavingTenant(true);
        try {
            const body: Parameters<typeof api.updateTenant>[1] = {};
            if (nameDraft.trim() !== (tenant.name ?? "")) body.name = nameDraft.trim();
            if (payloadPrefixDraft.trim() !== (tenant.payload_identifier_prefix ?? "")) {
                body.payload_identifier_prefix = payloadPrefixDraft.trim();
            }
            if (depDraft !== tenant.dep_enabled) body.dep_enabled = depDraft;
            if (ddmDraft !== tenant.ddm_enabled) body.ddm_enabled = ddmDraft;
            // Sent whenever the input differs from what was loaded, emptied included: these two fields
            // key off __fields_set__, so an explicit null clears the reminder and omitting the field
            // keeps the stored date.
            const apnsLoaded = tenant.apns_cert_expires_at ? tenant.apns_cert_expires_at.slice(0, 10) : "";
            if (apnsExpiryDraft.trim() !== apnsLoaded) {
                body.apns_cert_expires_at = apnsExpiryDraft.trim() || null;
            }
            const depLoaded = tenant.dep_token_expires_at ? tenant.dep_token_expires_at.slice(0, 10) : "";
            if (depExpiryDraft.trim() !== depLoaded) {
                body.dep_token_expires_at = depExpiryDraft.trim() || null;
            }

            if (s3Dirty) body.s3_config = buildS3Payload();

            if (Object.keys(body).length === 0) {
                notifications.show({color: "gray", message: "No changes to save."});
                return;
            }

            setS3Error(null);
            await api.updateTenant(token, body);
            notifications.show({color: "teal", message: "Tenant settings saved."});
            // Reset the ref synchronously rather than via the effect, so the loadTenant below
            // repopulates the form with the values that were just saved.
            tenantDirtyRef.current = false;
            setTenantDirty(false);
            await loadTenant();
        } catch (e: unknown) {
            const message = (e as Error).message;
            // A 400 on an S3 save names the missing keys, so keep it next to those fields.
            if (s3Dirty && e instanceof ApiError && e.status === 400) {
                setS3Error(message);
                notifications.show({
                    color: "red",
                    title: "Could not save",
                    message: "The S3 settings are incomplete. See the App package storage section.",
                });
            } else {
                notifications.show({color: "red", title: "Could not save", message});
            }
        } finally {
            setSavingTenant(false);
        }
    }

    // Only a definite false locks the form; null means /auth/me has not answered yet.
    const noLocalPassword = hasPassword === false;
    const pwMismatch = confirmPw.length > 0 && newPw !== confirmPw;
    const pwFormValid =
        currentPw.length > 0 && newPw.length >= MIN_PASSWORD_LENGTH && newPw === confirmPw;

    async function handleChangePassword() {
        if (!token || !pwFormValid) return;
        setChangingPw(true);
        setPwError(null);
        try {
            const res = await api.changePassword(token, currentPw, newPw);
            // The change invalidates every session for this account, this tab's old token included.
            // The token that came back keeps this tab signed in.
            setToken(res.access_token);
            setCurrentPw("");
            setNewPw("");
            setConfirmPw("");
            notifications.show({
                color: "teal",
                message: "Password changed. Other sessions were signed out.",
            });
        } catch (e: unknown) {
            setPwError((e as Error).message);
        } finally {
            setChangingPw(false);
        }
    }

    async function loadMfaStatus() {
        if (!token) return;
        try {
            setMfaStatus(await api.getMfaStatus(token));
        } catch {
        }
    }

    async function handleStartMfaEnroll() {
        if (!token) return;
        setEnrolling(true);
        setEnrollError(null);
        try {
            setEnrollData(await api.enrollMfa(token));
        } catch (e: unknown) {
            notifications.show({color: "red", title: "Could not start setup", message: (e as Error).message});
        } finally {
            setEnrolling(false);
        }
    }

    function cancelMfaEnroll() {
        setEnrollData(null);
        setEnrollCode("");
        setEnrollError(null);
    }

    async function handleConfirmMfaEnroll() {
        if (!token || !enrollCode.trim()) return;
        setConfirmingEnroll(true);
        setEnrollError(null);
        try {
            const res = await api.confirmMfaEnrollment(token, enrollCode.trim());
            setRecoveryCodes(res.recovery_codes);
            setEnrollData(null);
            setEnrollCode("");
            await loadMfaStatus();
        } catch (e: unknown) {
            setEnrollError(e instanceof ApiError ? e.message : "Could not confirm the code.");
        } finally {
            setConfirmingEnroll(false);
        }
    }

    async function handleDisableMfa() {
        if (!token || !disablePassword) return;
        setDisabling(true);
        setDisableError(null);
        try {
            await api.disableMfa(token, disablePassword);
            setDisableModalOpen(false);
            setDisablePassword("");
            await loadMfaStatus();
            notifications.show({color: "teal", message: "Two-factor authentication turned off."});
        } catch (e: unknown) {
            setDisableError(e instanceof ApiError ? e.message : "Could not turn off two-factor authentication.");
        } finally {
            setDisabling(false);
        }
    }

    if (loading) return <Box py={80} style={{textAlign: "center"}}><Loader/></Box>;

    return (
        <Stack gap="lg">
            <PageHeader description={null}/>

            {/* Controller health. One of the few places a positive glow earns its keep: this card exists to be
              looked at, and an unreachable controller is the thing every other page depends on. */}
            <GlassCard
                withBorder
                p="md"
                tone={health === "loading" ? "neutral" : health === "ok" ? "positive" : "negative"}
                toneLevel={health === "ok" ? 0.5 : 1}
            >
                <Group mb="xs">
                    <ThemeIcon variant="light" color={health === "ok" ? "teal" : "red"} size="sm">
                        <IconCheck size={14}/>
                    </ThemeIcon>
                    <Text fz="sm" fw={600}>Controller status</Text>
                    <Badge color={health === "ok" ? "teal" : "red"} size="sm" variant="light">
                        {health === "loading" ? "checking…" : health === "ok" ? "healthy" : "unreachable"}
                    </Badge>
                </Group>
            </GlassCard>

            <GlassCard withBorder p="md">
                <Group mb="xs">
                    <ThemeIcon variant="light" color="grape" size="sm">
                        <IconLock size={14}/>
                    </ThemeIcon>
                    <Text fz="sm" fw={600}>Account</Text>
                </Group>
                <Text fz="xs" c="dimmed" mb="md">
                    Signed in as <Code fz="xs">{email}</Code>. Changing your password signs out your other
                    sessions; this one stays open.
                </Text>

                <Stack gap="sm" maw={420}>
                    {hasPassword === false && (
                        <Alert color="gray" variant="light" icon={<IconInfoCircle size={16}/>}>
                            This account signs in through an external identity provider, so its password is
                            managed there rather than here.
                        </Alert>
                    )}

                    <PasswordInput
                        label="Current password"
                        autoComplete="current-password"
                        disabled={noLocalPassword}
                        value={currentPw}
                        onChange={(e) => {
                            setCurrentPw(e.currentTarget.value);
                            setPwError(null);
                        }}
                    />
                    <PasswordInput
                        label="New password"
                        description={`At least ${MIN_PASSWORD_LENGTH} characters. Well-known placeholder passwords are refused.`}
                        autoComplete="new-password"
                        disabled={noLocalPassword}
                        value={newPw}
                        onChange={(e) => {
                            setNewPw(e.currentTarget.value);
                            setPwError(null);
                        }}
                    />
                    <PasswordInput
                        label="Confirm new password"
                        autoComplete="new-password"
                        disabled={noLocalPassword}
                        value={confirmPw}
                        onChange={(e) => {
                            setConfirmPw(e.currentTarget.value);
                            setPwError(null);
                        }}
                        error={pwMismatch ? "The two passwords do not match." : null}
                    />

                    {pwError && (
                        <Alert color="red" variant="light" icon={<IconAlertTriangle size={16}/>}>
                            <Text fz="sm">{pwError}</Text>
                        </Alert>
                    )}

                    <Group justify="flex-end">
                        <Button
                            leftSection={<IconLock size={14}/>}
                            onClick={handleChangePassword}
                            loading={changingPw}
                            disabled={noLocalPassword || !pwFormValid}
                        >
                            Change password
                        </Button>
                    </Group>
                </Stack>

                <Divider my="lg" label="Two-factor authentication" labelPosition="left"/>

                {recoveryCodes ? (
                    <Stack gap="sm" maw={480}>
                        <Alert color="orange" variant="light" icon={<IconAlertTriangle size={16}/>}>
                            Save these recovery codes now. They will not be shown again, and each one can be
                            used in place of a code from your authenticator app if you lose access to it.
                        </Alert>
                        <Code block fz="sm">{recoveryCodes.join("\n")}</Code>
                        <Group justify="flex-end">
                            <CopyButton value={recoveryCodes.join("\n")}>
                                {({copied, copy}) => (
                                    <Button variant="default" leftSection={<IconCopy size={14}/>} onClick={copy}>
                                        {copied ? "Copied" : "Copy codes"}
                                    </Button>
                                )}
                            </CopyButton>
                            <Button onClick={() => setRecoveryCodes(null)}>
                                I&apos;ve saved these
                            </Button>
                        </Group>
                    </Stack>
                ) : enrollData ? (
                    <Stack gap="sm" maw={480}>
                        <Text fz="sm" c="dimmed">
                            Scan this code with your authenticator app, or enter the secret manually, then
                            type the 6-digit code it shows to turn two-factor authentication on.
                        </Text>
                        <Group align="flex-start" gap="lg" wrap="wrap">
                            <Box p="md" bg="white" style={{borderRadius: "var(--mantine-radius-sm)"}}>
                                <QRCode value={enrollData.provisioning_uri} size={160}/>
                            </Box>
                            <Stack gap={4} style={{flex: 1, minWidth: 200}}>
                                <Text fz="xs" c="dimmed">Can&apos;t scan? Enter this secret manually:</Text>
                                <Group gap="xs">
                                    <Code fz="sm">{enrollData.secret}</Code>
                                    <CopyButton value={enrollData.secret}>
                                        {({copied, copy}) => (
                                            <ActionIcon variant="default" onClick={copy} aria-label="Copy secret">
                                                {copied ? <IconCheck size={14}/> : <IconCopy size={14}/>}
                                            </ActionIcon>
                                        )}
                                    </CopyButton>
                                </Group>
                            </Stack>
                        </Group>
                        <TextInput
                            label="Code from your authenticator app"
                            placeholder="123456"
                            value={enrollCode}
                            onChange={(e) => {
                                setEnrollCode(e.currentTarget.value);
                                setEnrollError(null);
                            }}
                            error={enrollError}
                            maw={200}
                        />
                        <Group justify="flex-end">
                            <Button variant="default" onClick={cancelMfaEnroll}>
                                Cancel
                            </Button>
                            <Button
                                onClick={handleConfirmMfaEnroll}
                                loading={confirmingEnroll}
                                disabled={!enrollCode.trim()}
                            >
                                Confirm
                            </Button>
                        </Group>
                    </Stack>
                ) : mfaStatus?.enabled ? (
                    <Stack gap="xs" maw={480}>
                        <Group gap="xs">
                            <ThemeIcon variant="light" color="teal" size="sm">
                                <IconShieldCheck size={14}/>
                            </ThemeIcon>
                            <Text fz="sm">Two-factor authentication is on.</Text>
                        </Group>
                        {mfaStatus.confirmed_at && (
                            <Text fz="xs" c="dimmed">
                                Turned on {new Date(mfaStatus.confirmed_at).toLocaleDateString()}.
                            </Text>
                        )}
                        <Text fz="xs" c="dimmed">
                            {mfaStatus.recovery_codes_remaining} recovery code
                            {mfaStatus.recovery_codes_remaining === 1 ? "" : "s"} remaining.
                        </Text>
                        <Group justify="flex-end">
                            <Button
                                variant="default"
                                color="red"
                                leftSection={<IconShieldOff size={14}/>}
                                onClick={() => setDisableModalOpen(true)}
                            >
                                Turn off
                            </Button>
                        </Group>
                    </Stack>
                ) : (
                    <Stack gap="xs" maw={480}>
                        <Text fz="sm" c="dimmed">
                            Two-factor authentication is off. Turning it on asks for a code from an
                            authenticator app in addition to your password when you sign in.
                        </Text>
                        <Group justify="flex-end">
                            <Button
                                leftSection={<IconShieldLock size={14}/>}
                                onClick={handleStartMfaEnroll}
                                loading={enrolling}
                            >
                                Set up two-factor auth
                            </Button>
                        </Group>
                    </Stack>
                )}
            </GlassCard>

            <Modal
                opened={disableModalOpen}
                onClose={() => {
                    setDisableModalOpen(false);
                    setDisablePassword("");
                    setDisableError(null);
                }}
                title="Turn off two-factor authentication"
                size="sm"
            >
                <Stack gap="sm">
                    <Text fz="sm" c="dimmed">
                        Enter your password to turn off two-factor authentication for this account.
                    </Text>
                    <PasswordInput
                        label="Password"
                        autoFocus
                        data-autofocus
                        value={disablePassword}
                        onChange={(e) => {
                            setDisablePassword(e.currentTarget.value);
                            setDisableError(null);
                        }}
                        error={disableError}
                    />
                    <Group justify="flex-end">
                        <Button variant="default" onClick={() => setDisableModalOpen(false)}>
                            Cancel
                        </Button>
                        <Button
                            color="red"
                            onClick={handleDisableMfa}
                            loading={disabling}
                            disabled={!disablePassword}
                        >
                            Turn off
                        </Button>
                    </Group>
                </Stack>
            </Modal>

            {/* Interface preferences (stored in this browser) */}
            <GlassCard withBorder p="md">
                <Group mb="xs">
                    <ThemeIcon variant="light" color="indigo" size="sm">
                        <IconCode size={14}/>
                    </ThemeIcon>
                    <Text fz="sm" fw={600}>Interface</Text>
                </Group>
                <Switch
                    label="Show YAML configuration tab (advanced)"
                    description="Shows the editor for tenant's YAML-based declarative config. Changes here can be destructive, so only enable if you know what you're doing."
                    checked={showYaml}
                    onChange={(e) => setShowYaml(e.currentTarget.checked)}
                />
            </GlassCard>

            {/* Advisory tag registry (tags.yaml) */}
            <TagRegistryEditor/>

            {/* Tenant info */}
            <GlassCard withBorder p="md">
                <Group mb="md" justify="space-between">
                    <Text fz="sm" fw={600}>Tenant</Text>
                    {!isAdmin && (
                        <Badge size="sm" variant="light" color="gray">
                            Read-only, admin required to edit
                        </Badge>
                    )}
                </Group>

                <Stack gap="xs" mb={isAdmin ? "md" : 0}>
                    <Group gap="xs">
                        <Text fz="sm" c="dimmed" w={120}>Tenant ID</Text>
                        <Code fz="sm">{tenant?.id ?? tenantId}</Code>
                    </Group>
                    <Group gap="xs">
                        <Text fz="sm" c="dimmed" w={120}>Signed in as</Text>
                        <Code fz="sm">{email}</Code>
                    </Group>
                </Stack>

                {!isAdmin ? (
                    <Stack gap="xs">
                        <Group gap="xs">
                            <Text fz="sm" c="dimmed" w={120}>Tenant display name</Text>
                            <Text fz="sm">{tenant?.name}</Text>
                        </Group>
                        <Group gap="xs">
                            <Text fz="sm" c="dimmed" w={160}>Automated enrollment</Text>
                            <Badge size="sm" variant="light" color={tenant?.dep_enabled ? "teal" : "gray"}>
                                {tenant?.dep_enabled ? "Yes" : "No"}
                            </Badge>
                        </Group>
                        <Group gap="xs">
                            <Text fz="sm" c="dimmed" w={120}>DDM enabled</Text>
                            <Badge size="sm" variant="light" color={tenant?.ddm_enabled ? "teal" : "gray"}>
                                {tenant?.ddm_enabled ? "Yes" : "No"}
                            </Badge>
                        </Group>
                    </Stack>
                ) : (
                    <Stack gap="md">
                        <Divider label="General" labelPosition="left"/>
                        <TextInput
                            label="Tenant display name"
                            value={nameDraft}
                            onChange={(e) => {
                                setNameDraft(e.currentTarget.value);
                                setTenantDirty(true);
                            }}
                            error={nameBlank ? "A display name is required." : null}
                            withAsterisk
                        />
                        <TextInput
                            label="Profile identifier prefix"
                            placeholder={`com.mdm.${tenant?.id ?? tenantId}`}
                            description="Reverse-DNS base for the payload identifiers this tenant's profiles carry on devices, like com.example.mdm. Leave empty for the default shown."
                            value={payloadPrefixDraft}
                            onChange={(e) => {
                                setPayloadPrefixDraft(e.currentTarget.value);
                                setTenantDirty(true);
                            }}
                            error={payloadPrefixError}
                        />
                        {payloadPrefixDraft.trim() !== (tenant?.payload_identifier_prefix ?? "") && (
                            <Alert color="orange" variant="light" icon={<IconInfoCircle size={16}/>} py={6}>
                                Changing the prefix renames every profile this tenant deploys. Devices treat the
                                renamed profiles as new ones: the next sync re-installs them under the new name,
                                and the copies installed under the old name stay on the device until removed by
                                hand. Best set once, before profiles are deployed.
                            </Alert>
                        )}
                        <Switch
                            label="Automated Device Enrollment enabled"
                            description="Lets this tenant enroll devices assigned to it in Apple Business or School Manager."
                            checked={depDraft}
                            onChange={(e) => {
                                setDepDraft(e.currentTarget.checked);
                                setTenantDirty(true);
                            }}
                        />

                        <Switch
                            label="Declarative Device Management (DDM) enabled"
                            description="Apple's modern declaration-based management tools. Older devices do not support these features."
                            checked={ddmDraft}
                            onChange={(e) => {
                                setDdmDraft(e.currentTarget.checked);
                                setTenantDirty(true);
                            }}
                        />
                        {ddmDraft && !tenant?.ddm_enabled && (
                            <Alert color="orange" variant="light" icon={<IconInfoCircle size={16}/>} py={6}>
                                Enabling queues a declarative sync to all supported devices.
                            </Alert>
                        )}

                        <Divider
                            label={
                                <Group gap={6}>
                                    <IconCalendarDue size={14}/>
                                    <Text fz="xs" fw={500}>Renewal reminders</Text>
                                </Group>
                            }
                            labelPosition="left"
                        />
                        <Text fz="xs" c="dimmed" mt={-8}>
                            Used to remind you as each of these dates approaches.
                        </Text>
                        <Grid gutter="sm">
                            <Grid.Col span={{base: 12, sm: 6}}>
                                <TextInput
                                    type="date"
                                    label="APNs certificate expires"
                                    value={apnsExpiryDraft}
                                    onChange={(e) => {
                                        setApnsExpiryDraft(e.currentTarget.value);
                                        setTenantDirty(true);
                                    }}
                                />
                            </Grid.Col>
                            <Grid.Col span={{base: 12, sm: 6}}>
                                <TextInput
                                    type="date"
                                    label="ABM/ASM server token expires"
                                    value={depExpiryDraft}
                                    onChange={(e) => {
                                        setDepExpiryDraft(e.currentTarget.value);
                                        setTenantDirty(true);
                                    }}
                                />
                            </Grid.Col>
                        </Grid>

                        <Divider
                            label={
                                <Group gap={6}>
                                    <IconCloud size={14}/>
                                    <Text fz="xs" fw={500}>App package storage (S3)</Text>
                                </Group>
                            }
                            labelPosition="left"
                        />
                        <Text fz="xs" c="dimmed" mt={-8}>
                            Where uploaded app packages (Apps page) are stored.
                        </Text>

                        <Radio.Group
                            value={s3Draft.mode}
                            onChange={(v) => editS3({mode: v as S3Mode})}
                        >
                            <Stack gap={6}>
                                <Radio
                                    value="server"
                                    label="Use the storage this Micromanage server is configured with"
                                    description="Packages go to the bucket and credentials set on the host."
                                />
                                <Radio
                                    value="tenant"
                                    label="Use own S3 config"
                                    description="Bucket and credentials both come from the settings below. Micromanage will not pair a bucket named here with the host's credentials."
                                />
                            </Stack>
                        </Radio.Group>

                        {s3Draft.mode === "tenant" && (
                            <Grid gutter="sm">
                                <Grid.Col span={{base: 12, sm: 6}}>
                                    <TextInput
                                        label="Bucket"
                                        placeholder="my-mdm-packages"
                                        value={s3Draft.bucket}
                                        onChange={(e) => editS3({bucket: e.currentTarget.value})}
                                    />
                                </Grid.Col>
                                <Grid.Col span={{base: 12, sm: 6}}>
                                    <TextInput
                                        label="Region"
                                        description="Defaults to us-east-1 when blank."
                                        placeholder="us-east-1"
                                        value={s3Draft.region}
                                        onChange={(e) => editS3({region: e.currentTarget.value})}
                                    />
                                </Grid.Col>
                                <Grid.Col span={{base: 12, sm: 6}}>
                                    <PasswordInput
                                        label="Access key ID"
                                        description={
                                            hasExistingSecret("access_key_id")
                                                ? "A credential is on file. Leave it blank to keep it; it is never shown here."
                                                : "No credential on file yet."
                                        }
                                        placeholder={hasExistingSecret("access_key_id") ? "•••••••• (unchanged)" : "AKIA..."}
                                        value={s3Draft.access_key_id}
                                        onChange={(e) => editS3({access_key_id: e.currentTarget.value})}
                                    />
                                </Grid.Col>
                                <Grid.Col span={{base: 12, sm: 6}}>
                                    <PasswordInput
                                        label="Secret access key"
                                        description={
                                            hasExistingSecret("secret_access_key")
                                                ? "A credential is on file. Leave it blank to keep it; it is never shown here."
                                                : "No credential on file yet."
                                        }
                                        placeholder={hasExistingSecret("secret_access_key") ? "•••••••• (unchanged)" : "secret..."}
                                        value={s3Draft.secret_access_key}
                                        onChange={(e) => editS3({secret_access_key: e.currentTarget.value})}
                                    />
                                </Grid.Col>
                                <Grid.Col span={12}>
                                    <TextInput
                                        label="Endpoint URL"
                                        description="Leave blank for Amazon S3. Set it to reach MinIO or another S3-compatible host."
                                        placeholder="https://minio.example.org:9000"
                                        value={s3Draft.endpoint_url}
                                        onChange={(e) => editS3({endpoint_url: e.currentTarget.value})}
                                    />
                                </Grid.Col>
                                <Grid.Col span={{base: 12, sm: 6}}>
                                    <Switch
                                        label="Connect over HTTPS"
                                        description="Turn this off only for a plaintext endpoint on a network you trust."
                                        checked={s3Draft.use_ssl}
                                        onChange={(e) => editS3({use_ssl: e.currentTarget.checked})}
                                    />
                                </Grid.Col>
                                <Grid.Col span={{base: 12, sm: 6}}>
                                    <Switch
                                        label="Path-style addressing"
                                        description="MinIO and most S3-compatible hosts need this. Amazon S3 does not."
                                        checked={s3Draft.path_style}
                                        onChange={(e) => editS3({path_style: e.currentTarget.checked})}
                                    />
                                </Grid.Col>
                            </Grid>
                        )}

                        <TextInput
                            label="Key prefix"
                            description="Optional. Prepended to every object key written for this tenant, in either mode."
                            placeholder="tenant-acme/"
                            value={s3Draft.prefix}
                            onChange={(e) => editS3({prefix: e.currentTarget.value})}
                        />

                        {s3Draft.mode === "tenant" && hasStoredSessionToken && (
                            <Text fz="xs" c="dimmed">
                                A session token is stored for this tenant. It has no field here, and saving keeps
                                it as it is.
                            </Text>
                        )}

                        {s3Draft.mode === "tenant" && unknownS3Keys.length > 0 && (
                            <Text fz="xs" c="dimmed">
                                Also stored, and kept as it is when you save: {unknownS3Keys.join(", ")}.
                            </Text>
                        )}

                        {s3Draft.mode === "server" && declaresOwnS3(existingCfg) && (
                            <Alert color="orange" variant="light" icon={<IconInfoCircle size={16}/>}>
                                Saving now deletes this tenant&apos;s bucket, credentials and endpoint. Uploaded app
                                packages already in that bucket stay where they are, but Micromanage will stop
                                reading from it.
                            </Alert>
                        )}

                        {s3MissingBucket && (
                            <Alert color="orange" variant="light" icon={<IconInfoCircle size={16}/>}>
                                Name the bucket this tenant should use, or switch back to the server&apos;s own
                                storage above.
                            </Alert>
                        )}

                        {s3SecretsPartial && (
                            <Alert color="orange" variant="light" icon={<IconInfoCircle size={16}/>}>
                                Enter both the access key ID and secret access key together, or leave both blank to
                                keep the existing pair unchanged.
                            </Alert>
                        )}

                        {s3Error && (
                            <Alert
                                color="red"
                                variant="light"
                                icon={<IconAlertTriangle size={16}/>}
                                title="The controller rejected these S3 settings"
                                withCloseButton
                                onClose={() => setS3Error(null)}
                            >
                                <Text fz="sm">{s3Error}</Text>
                            </Alert>
                        )}

                        <Group justify="flex-end">
                            <Button
                                leftSection={<IconDeviceFloppy size={14}/>}
                                onClick={handleSaveTenant}
                                loading={savingTenant}
                                disabled={
                                    !tenantDirty || s3SecretsPartial || nameBlank || (s3Dirty && s3MissingBucket)
                                }
                            >
                                Save tenant settings
                            </Button>
                        </Group>
                    </Stack>
                )}
            </GlassCard>

            {/* Automated Enrollment (ADE/DEP): the admin-only entry point to the ABM/ASM link. */}
            {isAdmin && (
                <GlassCard withBorder p="md">
                    <Group justify="space-between" wrap="nowrap">
                        <Group gap="sm" wrap="nowrap">
                            <ThemeIcon variant="light" color="blue" size="lg">
                                <IconBuildingStore size={18}/>
                            </ThemeIcon>
                            <Box>
                                <Text fz="sm" fw={600}>Automated Device Enrollment</Text>
                                <Text fz="xs" c="dimmed">
                                    Connect Apple Business or School Manager and let devices provision out of the box.
                                </Text>
                            </Box>
                        </Group>
                        <Button
                            component={Link}
                            href="/dep"
                            variant="light"
                            rightSection={<IconChevronRight size={14}/>}
                        >
                            Manage
                        </Button>
                    </Group>
                </GlassCard>
            )}

            {isAdmin && <FileVaultEscrowCard/>}

            {isAdmin && <ReadinessSection readiness={readiness} loading={readinessLoading} error={readinessError}/>}

            <UsersManager/>

            {isAdmin && (
                <GlassCard withBorder p="md">
                    <Group justify="space-between" wrap="nowrap">
                        <Group gap="sm" wrap="nowrap">
                            <ThemeIcon variant="light" color="gray" size="lg">
                                <IconHistory size={18}/>
                            </ThemeIcon>
                            <Box>
                                <Text fz="sm" fw={600}>Audit log</Text>
                                <Text fz="xs" c="dimmed">
                                    Everything done in this tenant, by admins and by Micromanage itself.
                                </Text>
                            </Box>
                        </Group>
                        <Button
                            component={Link}
                            href="/settings/audit-log"
                            variant="light"
                            rightSection={<IconChevronRight size={14}/>}
                        >
                            View audit log
                        </Button>
                    </Group>
                </GlassCard>
            )}
        </Stack>
    );
}
