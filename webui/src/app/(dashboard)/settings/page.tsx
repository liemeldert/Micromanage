"use client";

import { useEffect, useState } from "react";
import {
  Alert,
  Badge,
  Box,
  Button,
  Card,
  Code,
  Divider,
  Grid,
  Group,
  Loader,
  PasswordInput,
  Stack,
  Switch,
  Text,
  TextInput,
  ThemeIcon,
  Title,
} from "@mantine/core";
import { useLocalStorage } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import {
  IconCheck,
  IconCloud,
  IconCode,
  IconDeviceFloppy,
  IconInfoCircle,
} from "@tabler/icons-react";
import { api, type TenantInfo } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";
import { SHOW_YAML_STORAGE_KEY } from "../../../../lib/preferences";
import { TagRegistryEditor } from "../../../components/config/TagRegistryEditor";
import { UsersManager } from "../../../components/config/UsersManager";

// Keys the controller treats as write-only credential material: it never
// returns their real value (GET redacts them to "***redacted***"), so the
// form must never echo them back in an input. Mirrors _SECRET_S3_KEYS in
// controller/api/main.py -- access_key_id is redacted there too, not just
// the secret key, so both get PasswordInput write-only treatment. (A third
// key, session_token, is redacted server-side too but isn't exposed as a
// form field here -- there's no UI for STS temporary credentials yet.)
type S3SecretKey = "access_key_id" | "secret_access_key";
const S3_REDACTED_PLACEHOLDER = "***redacted***";

interface S3FormState {
  bucket: string;
  region: string;
  prefix: string;
  access_key_id: string; // new value only; blank = leave unchanged
  secret_access_key: string; // new value only; blank = leave unchanged
}

const EMPTY_S3_FORM: S3FormState = {
  bucket: "",
  region: "",
  prefix: "",
  access_key_id: "",
  secret_access_key: "",
};

export default function SettingsPage() {
  const { token, tenantId, email, isAdmin } = useAuth();
  const [tenant, setTenant]         = useState<TenantInfo | null>(null);
  const [loading, setLoading]       = useState(true);
  const [health, setHealth]         = useState<"ok" | "error" | "loading">("loading");
  const [showYaml, setShowYaml]     = useLocalStorage({
    key: SHOW_YAML_STORAGE_KEY,
    defaultValue: false,
  });

  // Tenant edit form (admin only). Populated from `tenant` whenever it's
  // (re)loaded and the admin has no unsaved edits in flight.
  const [nameDraft, setNameDraft] = useState("");
  const [depDraft, setDepDraft] = useState(false);
  const [s3Draft, setS3Draft] = useState<S3FormState>(EMPTY_S3_FORM);
  const [tenantDirty, setTenantDirty] = useState(false);
  const [savingTenant, setSavingTenant] = useState(false);

  const loadTenant = () => {
    if (!token) return Promise.resolve();
    return api.getTenant(token).then((t) => {
      setTenant(t);
      if (!tenantDirty) {
        setNameDraft(t.name ?? "");
        setDepDraft(!!t.dep_enabled);
        const cfg = (t.s3_config ?? {}) as Record<string, unknown>;
        setS3Draft({
          bucket: typeof cfg.bucket === "string" ? cfg.bucket : "",
          region: typeof cfg.region === "string" ? cfg.region : "",
          prefix: typeof cfg.prefix === "string" ? cfg.prefix : "",
          // Secret fields are never populated from a GET response -- see
          // S3_SECRET_KEYS. Left blank means "keep existing value".
          access_key_id: "",
          secret_access_key: "",
        });
      }
    });
  };

  useEffect(() => {
    if (!token) return;
    Promise.all([
      loadTenant(),
      api.health().then(() => setHealth("ok")).catch(() => setHealth("error")),
    ])
      .catch((e: unknown) => notifications.show({ color: "red", message: (e as Error).message }))
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
  const nonSecretS3Changed =
    s3Draft.bucket !== (typeof existingCfg.bucket === "string" ? existingCfg.bucket : "") ||
    s3Draft.region !== (typeof existingCfg.region === "string" ? existingCfg.region : "") ||
    s3Draft.prefix !== (typeof existingCfg.prefix === "string" ? existingCfg.prefix : "");
  const s3SecretsTyped = s3Draft.access_key_id.trim() !== "" || s3Draft.secret_access_key.trim() !== "";
  // Access key ID and secret access key are a pair: typing exactly one fresh
  // would pin a new key against a mismatched (restored or absent) partner.
  // Require both or neither -- neither means "keep the stored pair", echoed as
  // the redaction sentinel and restored server-side (see handleSaveTenant).
  const s3SecretsPartial =
    (s3Draft.access_key_id.trim() !== "") !== (s3Draft.secret_access_key.trim() !== "");

  async function handleSaveTenant() {
    if (!token || !tenant) return;
    if (s3SecretsPartial) return; // guarded off in the UI too
    setSavingTenant(true);
    try {
      const body: Parameters<typeof api.updateTenant>[1] = {};
      if (nameDraft.trim() !== (tenant.name ?? "")) body.name = nameDraft.trim();
      if (depDraft !== !!tenant.dep_enabled) body.dep_enabled = depDraft;

      // s3_config is a whole-object replace server-side, so the PUT must carry
      // every field we intend to keep. For each secret: send a freshly typed
      // value as-is; otherwise, if a credential is already on file, echo the
      // redaction sentinel -- the server swaps it back to the stored value
      // (_restore_tenant_s3_secrets), so editing a non-secret field preserves
      // the credentials without ever revealing or re-entering them. A blank
      // with nothing on file is simply omitted, never written as a secret.
      if (nonSecretS3Changed || s3SecretsTyped) {
        const nextS3: Record<string, unknown> = {};
        if (s3Draft.bucket.trim()) nextS3.bucket = s3Draft.bucket.trim();
        if (s3Draft.region.trim()) nextS3.region = s3Draft.region.trim();
        if (s3Draft.prefix.trim()) nextS3.prefix = s3Draft.prefix.trim();
        if (s3Draft.access_key_id.trim()) nextS3.access_key_id = s3Draft.access_key_id.trim();
        else if (hasExistingSecret("access_key_id")) nextS3.access_key_id = S3_REDACTED_PLACEHOLDER;
        if (s3Draft.secret_access_key.trim()) nextS3.secret_access_key = s3Draft.secret_access_key.trim();
        else if (hasExistingSecret("secret_access_key")) nextS3.secret_access_key = S3_REDACTED_PLACEHOLDER;
        body.s3_config = nextS3;
      }

      if (Object.keys(body).length === 0) {
        notifications.show({ color: "gray", message: "No changes to save." });
        return;
      }

      await api.updateTenant(token, body);
      notifications.show({ color: "teal", message: "Tenant settings saved." });
      setTenantDirty(false);
      await loadTenant();
    } catch (e: unknown) {
      notifications.show({ color: "red", title: "Could not save", message: (e as Error).message });
    } finally {
      setSavingTenant(false);
    }
  }

  if (loading) return <Box py={80} style={{ textAlign: "center" }}><Loader /></Box>;

  return (
    <Stack gap="lg">
      <Title order={2}>Settings</Title>

      {/* Controller health */}
      <Card withBorder radius="md" p="md">
        <Group mb="xs">
          <ThemeIcon variant="light" color={health === "ok" ? "teal" : "red"} size="sm">
            <IconCheck size={14} />
          </ThemeIcon>
          <Text fz="sm" fw={600}>Controller Status</Text>
          <Badge color={health === "ok" ? "teal" : "red"} size="sm" variant="light">
            {health === "loading" ? "checking…" : health === "ok" ? "healthy" : "unreachable"}
          </Badge>
        </Group>
      </Card>

      {/* Interface preferences (stored in this browser) */}
      <Card withBorder radius="md" p="md">
        <Group mb="xs">
          <ThemeIcon variant="light" color="indigo" size="sm">
            <IconCode size={14} />
          </ThemeIcon>
          <Text fz="sm" fw={600}>Interface</Text>
        </Group>
        <Switch
          label="Show YAML configuration tab (advanced)"
          description="Shows the editor for tenant's YAML-based declarative config. Changes here can be destructive, so only enable if you know what you're doing."
          checked={showYaml}
          onChange={(e) => setShowYaml(e.currentTarget.checked)}
        />
      </Card>

      {/* Advisory tag registry (tags.yaml) */}
      <TagRegistryEditor />

      {/* Tenant info */}
      <Card withBorder radius="md" p="md">
        <Group mb="md" justify="space-between">
          <Text fz="sm" fw={600}>Tenant</Text>
          {!isAdmin && (
            <Badge size="sm" variant="light" color="gray">
              Read-only -- admin required to edit
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
              <Text fz="sm" c="dimmed" w={120}>Display name</Text>
              <Text fz="sm">{tenant?.name}</Text>
            </Group>
            <Group gap="xs">
              <Text fz="sm" c="dimmed" w={120}>DEP enabled</Text>
              <Badge size="sm" variant="light" color={tenant?.dep_enabled ? "teal" : "gray"}>
                {tenant?.dep_enabled ? "Yes" : "No"}
              </Badge>
            </Group>
          </Stack>
        ) : (
          <Stack gap="md">
            <Divider label="General" labelPosition="left" />
            <TextInput
              label="Display name"
              value={nameDraft}
              onChange={(e) => {
                setNameDraft(e.currentTarget.value);
                setTenantDirty(true);
              }}
            />
            <Switch
              label="DEP enabled"
              description="Automated Device Enrollment (Apple Business/School Manager) for this tenant."
              checked={depDraft}
              onChange={(e) => {
                setDepDraft(e.currentTarget.checked);
                setTenantDirty(true);
              }}
            />

            <Divider
              label={
                <Group gap={6}>
                  <IconCloud size={14} />
                  <Text fz="xs" fw={500}>App package storage (S3)</Text>
                </Group>
              }
              labelPosition="left"
            />
            <Text fz="xs" c="dimmed" mt={-8}>
              Where uploaded app packages (Apps page) are stored. Leave the bucket blank if this
              tenant doesn&apos;t use S3-backed app hosting.
            </Text>
            <Grid gutter="sm">
              <Grid.Col span={{ base: 12, sm: 6 }}>
                <TextInput
                  label="Bucket"
                  placeholder="my-mdm-packages"
                  value={s3Draft.bucket}
                  onChange={(e) => {
                    setS3Draft((s) => ({ ...s, bucket: e.currentTarget.value }));
                    setTenantDirty(true);
                  }}
                />
              </Grid.Col>
              <Grid.Col span={{ base: 12, sm: 6 }}>
                <TextInput
                  label="Region"
                  placeholder="us-east-1"
                  value={s3Draft.region}
                  onChange={(e) => {
                    setS3Draft((s) => ({ ...s, region: e.currentTarget.value }));
                    setTenantDirty(true);
                  }}
                />
              </Grid.Col>
              <Grid.Col span={12}>
                <TextInput
                  label="Key prefix"
                  description="Optional. Prepended to every object key written for this tenant."
                  placeholder="tenant-acme/"
                  value={s3Draft.prefix}
                  onChange={(e) => {
                    setS3Draft((s) => ({ ...s, prefix: e.currentTarget.value }));
                    setTenantDirty(true);
                  }}
                />
              </Grid.Col>
              <Grid.Col span={{ base: 12, sm: 6 }}>
                <PasswordInput
                  label="Access key ID"
                  description={
                    hasExistingSecret("access_key_id")
                      ? "A credential is on file. Leave blank to keep it -- it is never shown here."
                      : "No credential on file yet."
                  }
                  placeholder={hasExistingSecret("access_key_id") ? "•••••••• (unchanged)" : "AKIA..."}
                  value={s3Draft.access_key_id}
                  onChange={(e) => {
                    setS3Draft((s) => ({ ...s, access_key_id: e.currentTarget.value }));
                    setTenantDirty(true);
                  }}
                />
              </Grid.Col>
              <Grid.Col span={{ base: 12, sm: 6 }}>
                <PasswordInput
                  label="Secret access key"
                  description={
                    hasExistingSecret("secret_access_key")
                      ? "A credential is on file. Leave blank to keep it -- it is never shown here."
                      : "No credential on file yet."
                  }
                  placeholder={hasExistingSecret("secret_access_key") ? "•••••••• (unchanged)" : "secret..."}
                  value={s3Draft.secret_access_key}
                  onChange={(e) => {
                    setS3Draft((s) => ({ ...s, secret_access_key: e.currentTarget.value }));
                    setTenantDirty(true);
                  }}
                />
              </Grid.Col>
            </Grid>

            {s3SecretsPartial && (
              <Alert color="orange" variant="light" icon={<IconInfoCircle size={16} />}>
                Enter both the access key ID and secret access key together, or leave both blank to
                keep the existing pair unchanged.
              </Alert>
            )}

            <Group justify="flex-end">
              <Button
                leftSection={<IconDeviceFloppy size={14} />}
                onClick={handleSaveTenant}
                loading={savingTenant}
                disabled={!tenantDirty || s3SecretsPartial}
              >
                Save tenant settings
              </Button>
            </Group>
          </Stack>
        )}
      </Card>

      {/* Users (add / role / password reset / activate / delete) */}
      <UsersManager />
    </Stack>
  );
}
