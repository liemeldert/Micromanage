"use client";

// Read-only view of the tenant's declarative IaC config as the controller
// sees it on disk. Enabled via Settings → Interface → "Show YAML configuration
// tab". config.yaml is served with S3 credentials redacted server-side.

import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Group,
  Loader,
  Stack,
  Tabs,
  Text,
  Title,
} from "@mantine/core";
import { CodeHighlight } from "@mantine/code-highlight";
import { notifications } from "@mantine/notifications";
import {
  IconApps,
  IconFileCertificate,
  IconInfoCircle,
  IconRefresh,
  IconSettings,
  IconStack2,
} from "@tabler/icons-react";
import { api, ApiError } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";

type ConfigType = "profiles" | "groups" | "apps" | "config";

const TABS: { value: ConfigType; label: string; icon: React.FC<{ size?: number }> }[] = [
  { value: "profiles", label: "profiles.yaml", icon: IconFileCertificate },
  { value: "groups",   label: "groups.yaml",   icon: IconStack2 },
  { value: "apps",     label: "apps.yaml",     icon: IconApps },
  { value: "config",   label: "config.yaml",   icon: IconSettings },
];

export default function YamlPage() {
  const { token } = useAuth();
  const [active, setActive] = useState<ConfigType>("profiles");
  const [docs, setDocs]     = useState<Partial<Record<ConfigType, string | null>>>({});
  const [loading, setLoading] = useState(false);

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

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Title order={2}>YAML Configuration</Title>
        <Button
          leftSection={<IconRefresh size={14} />}
          variant="light"
          onClick={() => load(active, true)}
        >
          Refresh
        </Button>
      </Group>

      <Alert icon={<IconInfoCircle size={14} />} color="blue" variant="light">
        This is the declarative state the controller reconciles devices against —
        exactly as stored on disk. Edit it through the Groups / Apps / Profiles pages.
      </Alert>

      <Tabs value={active} onChange={(v) => setActive((v as ConfigType) ?? "profiles")}>
        <Tabs.List>
          {TABS.map((t) => (
            <Tabs.Tab key={t.value} value={t.value} leftSection={<t.icon size={14} />}>
              {t.label}
            </Tabs.Tab>
          ))}
        </Tabs.List>
      </Tabs>

      {loading && doc === undefined ? (
        <Box py={60} style={{ textAlign: "center" }}><Loader /></Box>
      ) : doc === null ? (
        <Text c="dimmed" ta="center" py="xl">
          No {active}.yaml yet — it is created the first time you save from the editor.
        </Text>
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
