"use client";

// The tenant's declarative IaC config, as the controller sees it on disk.
// groups/apps/profiles are editable here (parsed client-side, validated
// server-side against the full cross-file ruleset before committing, and a
// save triggers reconciliation). config.yaml stays read-only — it is
// server-managed and served with credentials redacted.

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Alert,
  Badge,
  Box,
  Button,
  FileButton,
  Group,
  Loader,
  Stack,
  Tabs,
  Text,
  Textarea,
  Title,
} from "@mantine/core";
import { CodeHighlight } from "@mantine/code-highlight";
import { notifications } from "@mantine/notifications";
import yaml from "js-yaml";
import {
  IconApps,
  IconDeviceFloppy,
  IconDownload,
  IconEdit,
  IconFileCertificate,
  IconInfoCircle,
  IconRefresh,
  IconSettings,
  IconStack2,
  IconUpload,
  IconX,
} from "@tabler/icons-react";
import { api, ApiError } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";

type ConfigType = "profiles" | "groups" | "apps" | "config";
type EditableType = Exclude<ConfigType, "config">;

const TABS: { value: ConfigType; label: string; icon: React.FC<{ size?: number }> }[] = [
  { value: "profiles", label: "profiles.yaml", icon: IconFileCertificate },
  { value: "groups",   label: "groups.yaml",   icon: IconStack2 },
  { value: "apps",     label: "apps.yaml",     icon: IconApps },
  { value: "config",   label: "config.yaml",   icon: IconSettings },
];

const EDITABLE: ConfigType[] = ["profiles", "groups", "apps"];

export default function YamlPage() {
  const { token } = useAuth();
  const [active, setActive] = useState<ConfigType>("profiles");
  const [docs, setDocs]     = useState<Partial<Record<ConfigType, string | null>>>({});
  const [loading, setLoading] = useState(false);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft]     = useState("");
  const [saving, setSaving]   = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);
  const resetRef = useRef<() => void>(null);

  const load = useCallback(async (type: ConfigType, force = false) => {
    if (!token) return;
    if (!force && docs[type] !== undefined) return; // cached for this visit
    setLoading(true);
    try {
      const text = await api.getConfigRaw(token, type);
      setDocs((d) => ({ ...d, [type]: text }));
    } catch (e: unknown) {
      if (e instanceof ApiError && e.status === 404) {
        setDocs((d) => ({ ...d, [type]: null })); // no file yet
      } else {
        notifications.show({ color: "red", message: (e as Error).message });
      }
    } finally {
      setLoading(false);
    }
  }, [token, docs]);

  useEffect(() => { load(active); }, [active, load]);

  const doc = docs[active];
  const editable = EDITABLE.includes(active);

  const startEditing = () => {
    // Editing an absent file starts from the minimal valid document.
    setDraft(doc ?? `${active}: []\n`);
    setParseError(null);
    setEditing(true);
  };

  const cancelEditing = () => {
    setEditing(false);
    setDraft("");
    setParseError(null);
  };

  const validateDraft = (text: string): Record<string, unknown> | null => {
    try {
      const parsed = yaml.load(text);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        setParseError(`Document must be a mapping with a top-level "${active}:" key`);
        return null;
      }
      if (!(active in (parsed as Record<string, unknown>))) {
        setParseError(`Missing top-level "${active}:" key`);
        return null;
      }
      setParseError(null);
      return parsed as Record<string, unknown>;
    } catch (e) {
      setParseError((e as Error).message);
      return null;
    }
  };

  const handleSave = async () => {
    if (!token) return;
    const parsed = validateDraft(draft);
    if (!parsed) return;
    setSaving(true);
    try {
      // Server re-validates against the full cross-file ruleset and, on
      // success, reconciles devices against the new declared state.
      const res = await api.updateConfig(token, active as EditableType, parsed);
      notifications.show({
        color: "teal",
        title: "Saved",
        message: res.warnings?.length ? `Warnings: ${res.warnings.join("; ")}` : res.message,
      });
      setEditing(false);
      await load(active, true);
    } catch (e) {
      notifications.show({
        color: "red",
        title: "Validation failed",
        message: (e as Error).message,
        autoClose: 8000,
      });
    } finally {
      setSaving(false);
    }
  };

  const handleExport = () => {
    const blob = new Blob([editing ? draft : (doc ?? "")], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${active}.yaml`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleImport = async (file: File | null) => {
    resetRef.current?.();
    if (!file) return;
    const text = await file.text();
    setDraft(text);
    setParseError(null);
    setEditing(true);
    validateDraft(text);
    notifications.show({
      color: "blue",
      message: `Loaded ${file.name} into the editor — review and save to apply.`,
    });
  };

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Group gap="sm">
          <Title order={2}>YAML Configuration</Title>
          {editing && <Badge color="orange" variant="light">editing {active}.yaml</Badge>}
        </Group>
        <Group gap="xs">
          {editable && !editing && (
            <>
              <FileButton onChange={handleImport} accept=".yaml,.yml" resetRef={resetRef}>
                {(props) => (
                  <Button {...props} variant="light" leftSection={<IconUpload size={14} />}>
                    Import
                  </Button>
                )}
              </FileButton>
              <Button variant="light" leftSection={<IconEdit size={14} />} onClick={startEditing}>
                Edit
              </Button>
            </>
          )}
          {editing && (
            <>
              <Button
                color="teal"
                leftSection={<IconDeviceFloppy size={14} />}
                loading={saving}
                disabled={!!parseError}
                onClick={handleSave}
              >
                Save & apply
              </Button>
              <Button variant="subtle" color="gray" leftSection={<IconX size={14} />} onClick={cancelEditing}>
                Cancel
              </Button>
            </>
          )}
          <Button variant="light" leftSection={<IconDownload size={14} />} onClick={handleExport}>
            Export
          </Button>
          {!editing && (
            <Button variant="light" leftSection={<IconRefresh size={14} />} onClick={() => load(active, true)}>
              Refresh
            </Button>
          )}
        </Group>
      </Group>

      <Alert icon={<IconInfoCircle size={14} />} color="blue" variant="light">
        This is the declarative state the controller reconciles devices against.
        Saving here validates the document server-side and immediately queues the
        resulting device tasks. config.yaml is server-managed and read-only.
      </Alert>

      <Tabs
        value={active}
        onChange={(v) => {
          if (editing) {
            notifications.show({ color: "orange", message: "Save or cancel your edits first." });
            return;
          }
          setActive((v as ConfigType) ?? "profiles");
        }}
      >
        <Tabs.List>
          {TABS.map((t) => (
            <Tabs.Tab key={t.value} value={t.value} leftSection={<t.icon size={14} />}>
              {t.label}
            </Tabs.Tab>
          ))}
        </Tabs.List>
      </Tabs>

      {editing ? (
        <Stack gap="xs">
          {parseError && (
            <Alert color="red" variant="light" title="YAML error">
              <Text fz="xs" style={{ fontFamily: "monospace", whiteSpace: "pre-wrap" }}>
                {parseError}
              </Text>
            </Alert>
          )}
          <Textarea
            value={draft}
            onChange={(e) => {
              setDraft(e.currentTarget.value);
              if (parseError) validateDraft(e.currentTarget.value);
            }}
            onBlur={() => validateDraft(draft)}
            autosize
            minRows={16}
            maxRows={32}
            styles={{
              input: { fontFamily: "var(--mantine-font-family-monospace)", fontSize: 13 },
            }}
            spellCheck={false}
          />
        </Stack>
      ) : loading && doc === undefined ? (
        <Box py={60} style={{ textAlign: "center" }}><Loader /></Box>
      ) : doc === null ? (
        <Stack align="center" py="xl" gap="sm">
          <Text c="dimmed">
            No {active}.yaml yet — it is created the first time you save.
          </Text>
          {editable && (
            <Button variant="light" leftSection={<IconEdit size={14} />} onClick={startEditing}>
              Create it now
            </Button>
          )}
        </Stack>
      ) : (
        <CodeHighlight
          code={doc ?? ""}
          language="yaml"
          radius="md"
          withBorder
          style={{ maxHeight: "70vh", overflow: "auto" }}
        />
      )}
    </Stack>
  );
}
