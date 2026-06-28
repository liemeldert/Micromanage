"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  Group,
  List,
  Loader,
  ScrollArea,
  Stack,
  Tabs,
  Text,
  Textarea,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { CodeHighlight } from "@mantine/code-highlight";
import {
  IconAlertTriangle,
  IconCheck,
  IconDevices,
  IconFileCode,
  IconPackage,
  IconPencil,
  IconShieldCheck,
  IconX,
} from "@tabler/icons-react";
import { api } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";

type ConfigType = "groups" | "apps" | "profiles";

const CONFIG_TABS: { value: ConfigType; label: string; icon: React.ElementType }[] = [
  { value: "groups",   label: "Groups",   icon: IconDevices },
  { value: "apps",     label: "Apps",     icon: IconPackage },
  { value: "profiles", label: "Profiles", icon: IconFileCode },
];

function toYaml(obj: unknown): string {
  return JSON.stringify(obj, null, 2);
}

interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export default function CompliancePage() {
  const { token } = useAuth();

  const [activeTab, setActiveTab]           = useState<ConfigType>("groups");
  const [configs, setConfigs]               = useState<Partial<Record<ConfigType, unknown>>>({});
  const [editorText, setEditorText]         = useState<Partial<Record<ConfigType, string>>>({});
  const [editMode, setEditMode]             = useState<Partial<Record<ConfigType, boolean>>>({});
  const [loading, setLoading]               = useState(true);
  const [saving, setSaving]                 = useState(false);
  const [validating, setValidating]         = useState(false);
  const [validation, setValidation]         = useState<ValidationResult | null>(null);

  const loadAll = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const [groups, apps, profiles] = await Promise.all([
        api.getConfig(token, "groups"),
        api.getConfig(token, "apps"),
        api.getConfig(token, "profiles"),
      ]);
      setConfigs({ groups, apps, profiles });
      setEditorText({
        groups:   toYaml(groups),
        apps:     toYaml(apps),
        profiles: toYaml(profiles),
      });
    } catch (e: unknown) {
      notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { loadAll(); }, [loadAll]);

  const handleValidate = async () => {
    if (!token) return;
    setValidating(true);
    setValidation(null);
    try {
      const res = await api.validateConfigs(token);
      setValidation(res);
    } catch (e: unknown) {
      notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      setValidating(false);
    }
  };

  const handleSave = async (type: ConfigType) => {
    if (!token) return;
    setSaving(true);
    try {
      const raw = editorText[type] ?? "";
      // The server accepts JSON; for YAML input we send the text as a plain string
      // wrapped in { _raw: ... } — but actually, the current API accepts Dict[str, Any].
      // We'll parse the editor text as JSON for now (users edit JSON-compatible YAML subset).
      let data: Record<string, unknown>;
      try {
        data = JSON.parse(raw);
      } catch {
        notifications.show({
          color: "orange",
          title: "Parse error",
          message: "Editor content must be valid JSON. YAML-only format coming soon.",
        });
        return;
      }
      const res = await api.updateConfig(token, type, data);
      notifications.show({ color: "teal", message: res.message });
      if (res.warnings.length) {
        res.warnings.forEach((w) =>
          notifications.show({ color: "yellow", title: "Warning", message: w }),
        );
      }
      setEditMode((prev) => ({ ...prev, [type]: false }));
      await loadAll();
    } catch (e: unknown) {
      notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      setSaving(false);
    }
  };

  const handleCancel = (type: ConfigType) => {
    setEditorText((prev) => ({ ...prev, [type]: toYaml(configs[type]) }));
    setEditMode((prev) => ({ ...prev, [type]: false }));
  };

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Stack gap={0}>
          <Title order={2}>Compliance</Title>
          <Text fz="sm" c="dimmed">
            YAML configuration defines the desired state of all enrolled devices.
          </Text>
        </Stack>
        <Button
          leftSection={validating ? <Loader size={14} /> : <IconShieldCheck size={14} />}
          variant="light"
          color="teal"
          onClick={handleValidate}
          loading={validating}
        >
          Validate All
        </Button>
      </Group>

      {/* Validation result banner */}
      {validation && (
        <Alert
          icon={validation.valid ? <IconCheck size={16} /> : <IconX size={16} />}
          color={validation.valid ? "teal" : "red"}
          title={validation.valid ? "Configuration valid" : "Validation failed"}
          withCloseButton
          onClose={() => setValidation(null)}
        >
          {validation.errors.length > 0 && (
            <List size="sm" spacing={2} mt="xs">
              {validation.errors.map((e, i) => (
                <List.Item key={i} icon={<IconX size={12} />}>
                  {e}
                </List.Item>
              ))}
            </List>
          )}
          {validation.warnings.length > 0 && (
            <>
              <Text fz="xs" mt="xs" fw={500} c="yellow.7">Warnings</Text>
              <List size="sm" spacing={2}>
                {validation.warnings.map((w, i) => (
                  <List.Item key={i} icon={<IconAlertTriangle size={12} />}>
                    {w}
                  </List.Item>
                ))}
              </List>
            </>
          )}
        </Alert>
      )}

      {loading ? (
        <Box py={80} style={{ textAlign: "center" }}><Loader /></Box>
      ) : (
        <Tabs value={activeTab} onChange={(v) => setActiveTab(v as ConfigType)}>
          <Tabs.List mb="md">
            {CONFIG_TABS.map((tab) => (
              <Tabs.Tab
                key={tab.value}
                value={tab.value}
                leftSection={<tab.icon size={14} />}
              >
                {tab.label}
              </Tabs.Tab>
            ))}
          </Tabs.List>

          {CONFIG_TABS.map((tab) => (
            <Tabs.Panel key={tab.value} value={tab.value}>
              <ConfigPanel
                type={tab.value}
                text={editorText[tab.value] ?? ""}
                isEditing={!!editMode[tab.value]}
                saving={saving}
                onEdit={() => setEditMode((p) => ({ ...p, [tab.value]: true }))}
                onSave={() => handleSave(tab.value)}
                onCancel={() => handleCancel(tab.value)}
                onChange={(v) => setEditorText((p) => ({ ...p, [tab.value]: v }))}
              />
            </Tabs.Panel>
          ))}
        </Tabs>
      )}
    </Stack>
  );
}

function ConfigPanel({
  type,
  text,
  isEditing,
  saving,
  onEdit,
  onSave,
  onCancel,
  onChange,
}: {
  type: ConfigType;
  text: string;
  isEditing: boolean;
  saving: boolean;
  onEdit: () => void;
  onSave: () => void;
  onCancel: () => void;
  onChange: (v: string) => void;
}) {
  const descriptions: Record<ConfigType, string> = {
    groups:
      "Groups dynamically segment enrolled devices using regex, equals, or version conditions. Apps and profiles reference these group names to target deployments.",
    apps:
      "Define managed app packages and which device groups each version should be installed on. Packages are hosted in S3 / object storage.",
    profiles:
      "Configuration profiles (WiFi, VPN, restrictions, certificates) to push to devices. Each profile targets one or more groups.",
  };

  return (
    <Card withBorder radius="md" p={0}>
      {/* Header */}
      <Box
        px="md"
        py="sm"
        style={{
          borderBottom: "1px solid var(--mantine-color-default-border)",
          background: "var(--mantine-color-default-hover)",
        }}
      >
        <Group justify="space-between">
          <Stack gap={2}>
            <Text fz="sm" fw={600} tt="capitalize">
              {type}.yaml
            </Text>
            <Text fz="xs" c="dimmed" maw={500}>
              {descriptions[type]}
            </Text>
          </Stack>
          <Group gap="xs">
            {!isEditing ? (
              <Button
                leftSection={<IconPencil size={14} />}
                variant="light"
                size="xs"
                onClick={onEdit}
              >
                Edit
              </Button>
            ) : (
              <>
                <Button
                  variant="light"
                  color="gray"
                  size="xs"
                  onClick={onCancel}
                  disabled={saving}
                >
                  Cancel
                </Button>
                <Button
                  leftSection={<IconCheck size={14} />}
                  size="xs"
                  loading={saving}
                  onClick={onSave}
                >
                  Save
                </Button>
              </>
            )}
          </Group>
        </Group>
      </Box>

      {/* Body */}
      {isEditing ? (
        <Textarea
          value={text}
          onChange={(e) => onChange(e.currentTarget.value)}
          autosize
          minRows={16}
          maxRows={40}
          styles={{
            input: {
              fontFamily: "var(--mantine-font-family-monospace)",
              fontSize: 13,
              border: "none",
              borderRadius: 0,
            },
            wrapper: { border: "none" },
          }}
        />
      ) : (
        <ScrollArea mah={600}>
          {text ? (
            <CodeHighlight
              code={text}
              language="json"
              withCopyButton
            />
          ) : (
            <Box p="xl">
              <Text c="dimmed" fz="sm" ta="center">
                No configuration found. Click Edit to create one.
              </Text>
            </Box>
          )}
        </ScrollArea>
      )}
    </Card>
  );
}
