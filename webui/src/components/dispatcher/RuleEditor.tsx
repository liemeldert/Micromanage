"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Divider,
  Group,
  MultiSelect,
  NumberInput,
  Paper,
  PasswordInput,
  Select,
  Stack,
  Switch,
  TagsInput,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconAlertTriangle,
  IconDeviceFloppy,
  IconInfoCircle,
  IconPlus,
  IconTrash,
} from "@tabler/icons-react";
import {
  api,
  type CatalogCommand,
  type Device,
  type DispatcherAction,
  type DispatcherCheckSpec,
  type DispatcherConfig,
  type DispatcherRule,
  type DispatcherWebhook,
  type Severity,
} from "../../../lib/api";
import {
  useConfigResource,
  useTagRegistry,
  type Group as GroupDef,
  type Scope,
} from "../../../lib/config";
import { useAuth } from "../../../lib/auth-context";
import { ScopeEditor } from "../config/ScopeEditor";

const SEVERITIES: Severity[] = ["black", "red", "yellow", "green"];
const REMEDIATION_TYPES = new Set(["install_profiles", "install_apps", "send_command"]);
const ACTION_TYPES = ["webhook", "assign_tag", "remove_tag", "install_profiles", "install_apps", "send_command"];

export function RuleEditor() {
  const { token, isAdmin } = useAuth();
  const { data, setData, loading, saving, save } = useConfigResource<DispatcherConfig>("dispatcher", {
    rules: [],
    webhooks: [],
  });
  const { tagNames } = useTagRegistry();
  const [checks, setChecks] = useState<DispatcherCheckSpec[]>([]);
  const [commands, setCommands] = useState<CatalogCommand[]>([]);
  const [profileIds, setProfileIds] = useState<string[]>([]);
  const [appIds, setAppIds] = useState<string[]>([]);
  const [groups, setGroups] = useState<GroupDef[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    api.getDispatcherCheckCatalog(token).then((c) => setChecks(c.checks)).catch(() => {});
    api.getCommandCatalog(token).then((c) => setCommands(c.commands)).catch(() => {});
    api.getConfig(token, "profiles").then((p) => setProfileIds(((p?.profiles as { id: string }[]) ?? []).map((x) => x.id))).catch(() => {});
    api.getConfig(token, "apps").then((a) => setAppIds(((a?.apps as { id: string }[]) ?? []).map((x) => x.id))).catch(() => {});
    api.getConfig(token, "groups").then((g) => setGroups((g?.groups as GroupDef[]) ?? [])).catch(() => {});
    api.listDevices(token, { limit: 500 }).then((r) => setDevices(r.devices)).catch(() => {});
  }, [token]);

  const rules = useMemo(() => data?.rules ?? [], [data]);
  const webhooks = useMemo(() => data?.webhooks ?? [], [data]);
  useEffect(() => {
    if (!selectedId && rules.length) setSelectedId(rules[0].id);
  }, [rules, selectedId]);

  const rule = rules.find((r) => r.id === selectedId) ?? null;
  const ruleIdx = rules.findIndex((r) => r.id === selectedId);

  const patchRule = useCallback(
    (patch: Partial<DispatcherRule>) => {
      setData((prev) => {
        const next: DispatcherConfig = { ...prev, rules: [...(prev?.rules ?? [])], webhooks: prev?.webhooks ?? [] };
        if (ruleIdx >= 0) next.rules![ruleIdx] = { ...next.rules![ruleIdx], ...patch };
        return next;
      });
    },
    [setData, ruleIdx],
  );

  const setWebhooks = (next: DispatcherWebhook[]) =>
    setData((prev) => ({ ...prev, rules: prev?.rules ?? [], webhooks: next }));

  const createRule = () => {
    const base = "rule";
    let id = base;
    let n = 1;
    while (rules.some((r) => r.id === id)) id = `${base}-${++n}`;
    const doc: DispatcherRule = {
      id,
      name: "New rule",
      enabled: true,
      severity: "yellow",
      scope: {},
      check: { type: "filevault_disabled" },
      grace_minutes: 60,
      actions: [],
      auto_resolve: true,
    };
    setData((prev) => ({ ...prev, webhooks: prev?.webhooks ?? [], rules: [...(prev?.rules ?? []), doc] }));
    setSelectedId(id);
  };

  const deleteRule = () => {
    if (!rule) return;
    setData((prev) => ({ ...prev, webhooks: prev?.webhooks ?? [], rules: (prev?.rules ?? []).filter((r) => r.id !== rule.id) }));
    setSelectedId(null);
  };

  const onSave = async () => {
    if (!isAdmin) {
      notifications.show({ color: "red", message: "Editing dispatcher rules requires the admin role." });
      return;
    }
    await save(data ?? { rules: [], webhooks: [] });
  };

  if (loading) return <Text c="dimmed">Loading…</Text>;

  return (
    <Stack gap="md">
      {!isAdmin && (
        <Alert color="yellow" icon={<IconInfoCircle size={16} />}>
          Compliance rules can act on devices and reach external webhooks, so authoring them is
          admin-only. You can view them here.
        </Alert>
      )}

      <WebhooksSection webhooks={webhooks} onChange={setWebhooks} disabled={!isAdmin} />

      <Group justify="space-between" align="flex-end">
        <Select
          label="Rule"
          placeholder="Select a rule"
          data={rules.map((r) => ({ value: r.id, label: `${r.name}${r.enabled === false ? " (disabled)" : ""}` }))}
          value={selectedId}
          onChange={setSelectedId}
          w={280}
          searchable
        />
        <Group>
          <Button variant="light" leftSection={<IconPlus size={16} />} onClick={createRule} disabled={!isAdmin}>
            New rule
          </Button>
          {rule && (
            <ActionIcon variant="light" color="red" size="lg" onClick={deleteRule} disabled={!isAdmin}>
              <IconTrash size={18} />
            </ActionIcon>
          )}
          <Button leftSection={<IconDeviceFloppy size={16} />} onClick={onSave} loading={saving} disabled={!isAdmin}>
            Save
          </Button>
        </Group>
      </Group>

      {rule && (
        <Paper withBorder radius="md" p="md">
          <Group align="flex-end" gap="md" wrap="wrap">
            <TextInput label="Name" value={rule.name} onChange={(e) => patchRule({ name: e.currentTarget.value })} w={240} disabled={!isAdmin} />
            <TextInput label="Id" value={rule.id} disabled w={180} />
            <Select
              label="Severity"
              data={SEVERITIES.map((s) => ({ value: s, label: s }))}
              value={rule.severity}
              onChange={(v) => patchRule({ severity: (v as Severity) ?? "yellow" })}
              w={140}
              disabled={!isAdmin}
            />
            <NumberInput
              label="Grace (minutes)"
              description="Anti-flap: fire only after this long"
              value={rule.grace_minutes ?? 0}
              onChange={(v) => patchRule({ grace_minutes: typeof v === "number" ? v : 0 })}
              min={0}
              w={150}
              disabled={!isAdmin}
            />
            <Switch label="Enabled" checked={rule.enabled !== false} onChange={(e) => patchRule({ enabled: e.currentTarget.checked })} mb={6} disabled={!isAdmin} />
            <Switch label="Auto-resolve" checked={rule.auto_resolve !== false} onChange={(e) => patchRule({ auto_resolve: e.currentTarget.checked })} mb={6} disabled={!isAdmin} />
          </Group>

          <Divider my="sm" label="Applies to" labelPosition="left" />
          <ScopeEditor
            scope={(rule.scope ?? {}) as Scope}
            onChange={(scope) => patchRule({ scope: scope as Record<string, unknown> })}
            devices={devices}
            allGroups={groups}
            groupsLabel="Target groups"
            groupsDescription="Empty scope applies the rule to every device."
            emptyMatchesAll
          />

          <Divider my="sm" label="Compliance check (fires when true)" labelPosition="left" />
          <CheckPicker checks={checks} value={rule.check ?? {}} onChange={(check) => patchRule({ check })} profileIds={profileIds} tagNames={tagNames} disabled={!isAdmin} />

          <Divider my="sm" label="Actions" labelPosition="left" />
          <ActionsEditor
            actions={rule.actions ?? []}
            onChange={(actions) => patchRule({ actions })}
            webhooks={webhooks}
            tagNames={tagNames}
            profileIds={profileIds}
            appIds={appIds}
            commands={commands}
            disabled={!isAdmin}
          />
        </Paper>
      )}
    </Stack>
  );
}

function WebhooksSection({ webhooks, onChange, disabled }: { webhooks: DispatcherWebhook[]; onChange: (w: DispatcherWebhook[]) => void; disabled: boolean }) {
  const patch = (i: number, p: Partial<DispatcherWebhook>) => onChange(webhooks.map((w, j) => (i === j ? { ...w, ...p } : w)));
  return (
    <Paper withBorder radius="md" p="md">
      <Group justify="space-between" mb="xs">
        <Title order={5}>Webhook targets</Title>
        <Button size="compact-xs" variant="light" leftSection={<IconPlus size={14} />} disabled={disabled} onClick={() => onChange([...webhooks, { name: `hook-${webhooks.length + 1}`, url: "" }])}>
          Add
        </Button>
      </Group>
      {webhooks.length === 0 ? (
        <Text fz="xs" c="dimmed">
          No webhook targets. Add one to notify Slack/Teams/Discord (or any endpoint) when a rule fires.
        </Text>
      ) : (
        <Stack gap="xs">
          {webhooks.map((w, i) => (
            <Group key={i} gap="xs" wrap="nowrap">
              <TextInput placeholder="name" value={w.name} onChange={(e) => patch(i, { name: e.currentTarget.value })} w={140} disabled={disabled} />
              <TextInput placeholder="https://hooks.slack.com/…" value={w.url ?? ""} onChange={(e) => patch(i, { url: e.currentTarget.value })} style={{ flex: 1 }} disabled={disabled} />
              <PasswordInput placeholder="HMAC secret (optional)" value={w.secret ?? ""} onChange={(e) => patch(i, { secret: e.currentTarget.value })} w={200} disabled={disabled} />
              <ActionIcon variant="subtle" color="red" disabled={disabled} onClick={() => onChange(webhooks.filter((_, j) => j !== i))}>
                <IconTrash size={16} />
              </ActionIcon>
            </Group>
          ))}
          <Text fz="xs" c="dimmed">
            url + secret are stored server-side and shown redacted; leave a field as “***redacted***” to keep the saved value.
          </Text>
        </Stack>
      )}
    </Paper>
  );
}

function CheckPicker({ checks, value, onChange, profileIds, tagNames, disabled }: { checks: DispatcherCheckSpec[]; value: Record<string, unknown>; onChange: (c: Record<string, unknown>) => void; profileIds: string[]; tagNames: string[]; disabled: boolean }) {
  const spec = checks.find((c) => c.type === value.type);
  const patch = (p: Record<string, unknown>) => onChange({ ...value, ...p });
  return (
    <Stack gap="xs">
      <Select
        label="Check"
        data={checks.map((c) => ({ value: c.type, label: c.label }))}
        value={typeof value.type === "string" ? value.type : null}
        onChange={(v) => onChange({ type: v ?? undefined })}
        description={spec?.description}
        searchable
        disabled={disabled}
      />
      {(spec?.params ?? []).map((p) => {
        if (p.type === "tags") {
          return <TagsInput key={p.name} label={p.label} data={tagNames} value={Array.isArray(value[p.name]) ? (value[p.name] as string[]) : []} onChange={(v) => patch({ [p.name]: v })} disabled={disabled} />;
        }
        if (p.name === "profile_id") {
          return <Select key={p.name} label={p.label} data={profileIds} value={typeof value[p.name] === "string" ? (value[p.name] as string) : null} onChange={(v) => patch({ [p.name]: v ?? undefined })} searchable disabled={disabled} />;
        }
        if (p.type === "select") {
          return <Select key={p.name} label={p.label} data={p.options ?? []} value={typeof value[p.name] === "string" ? (value[p.name] as string) : null} onChange={(v) => patch({ [p.name]: v ?? undefined })} disabled={disabled} />;
        }
        if (p.type === "int") {
          return <NumberInput key={p.name} label={p.label} value={typeof value[p.name] === "number" ? (value[p.name] as number) : undefined} onChange={(v) => patch({ [p.name]: v })} disabled={disabled} />;
        }
        return <TextInput key={p.name} label={p.label} description={p.help} value={String(value[p.name] ?? "")} onChange={(e) => patch({ [p.name]: e.currentTarget.value })} disabled={disabled} />;
      })}
    </Stack>
  );
}

function ActionsEditor({ actions, onChange, webhooks, tagNames, profileIds, appIds, commands, disabled }: { actions: DispatcherAction[]; onChange: (a: DispatcherAction[]) => void; webhooks: DispatcherWebhook[]; tagNames: string[]; profileIds: string[]; appIds: string[]; commands: CatalogCommand[]; disabled: boolean }) {
  const patch = (i: number, p: Partial<DispatcherAction>) => onChange(actions.map((a, j) => (i === j ? { ...a, ...p } : a)));
  const setParams = (i: number, params: Record<string, unknown>) => patch(i, { params });
  return (
    <Stack gap="xs">
      {actions.map((a, i) => {
        const p = a.params ?? {};
        const cmd = commands.find((c) => c.type === p.command);
        const isDestructive = a.type === "send_command" && cmd?.destructive;
        return (
          <Paper key={i} withBorder radius="sm" p="xs">
            <Group justify="space-between" mb={6}>
              <Group gap="xs">
                <Select
                  size="xs"
                  data={ACTION_TYPES}
                  value={a.type}
                  onChange={(v) => patch(i, { type: v ?? "webhook", params: {} })}
                  w={160}
                  disabled={disabled}
                />
                {REMEDIATION_TYPES.has(a.type) && (
                  <Switch size="xs" label="Dry run" checked={Boolean(a.dry_run)} onChange={(e) => patch(i, { dry_run: e.currentTarget.checked })} disabled={disabled} />
                )}
                {isDestructive && (
                  <Tooltip label="Destructive commands never auto-fire; they require admin approval on the alert." multiline w={240}>
                    <Badge color="orange" variant="light" leftSection={<IconAlertTriangle size={12} />}>
                      approval required
                    </Badge>
                  </Tooltip>
                )}
              </Group>
              <ActionIcon variant="subtle" color="red" disabled={disabled} onClick={() => onChange(actions.filter((_, j) => j !== i))}>
                <IconTrash size={14} />
              </ActionIcon>
            </Group>

            {a.type === "webhook" && (
              <Select size="xs" label="Target" data={webhooks.map((w) => w.name)} value={typeof p.target === "string" ? (p.target as string) : null} onChange={(v) => setParams(i, { target: v ?? undefined })} disabled={disabled} />
            )}
            {(a.type === "assign_tag" || a.type === "remove_tag") && (
              <TagsInput size="xs" label="Tags" data={tagNames} value={Array.isArray(p.tags) ? (p.tags as string[]) : []} onChange={(v) => setParams(i, { tags: v })} disabled={disabled} />
            )}
            {a.type === "install_profiles" && (
              <MultiSelect size="xs" label="Profiles" data={profileIds} value={Array.isArray(p.profile_ids) ? (p.profile_ids as string[]) : []} onChange={(v) => setParams(i, { profile_ids: v })} searchable disabled={disabled} />
            )}
            {a.type === "install_apps" && (
              <MultiSelect size="xs" label="Apps" data={appIds} value={Array.isArray(p.app_ids) ? (p.app_ids as string[]) : []} onChange={(v) => setParams(i, { app_ids: v })} searchable disabled={disabled} />
            )}
            {a.type === "send_command" && (
              <Select size="xs" label="Command" data={commands.map((c) => ({ value: c.type, label: `${c.label}${c.destructive ? " (destructive)" : ""}` }))} value={typeof p.command === "string" ? (p.command as string) : null} onChange={(v) => setParams(i, { command: v ?? undefined })} searchable disabled={disabled} />
            )}
          </Paper>
        );
      })}
      <Button size="compact-xs" variant="light" leftSection={<IconPlus size={14} />} disabled={disabled} onClick={() => onChange([...actions, { type: "webhook", params: {} }])}>
        Add action
      </Button>
      <Text fz="xs" c="dimmed">
        Remediations are off unless added here. New remediations default to dry-run; destructive
        commands are never auto-fired (they queue for admin approval on the alert).
      </Text>
    </Stack>
  );
}
