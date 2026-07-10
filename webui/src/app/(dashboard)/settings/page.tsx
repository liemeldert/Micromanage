"use client";

import { useEffect, useState } from "react";
import {
  Alert,
  Badge,
  Box,
  Card,
  Code,
  Divider,
  Group,
  List,
  Loader,
  Stack,
  Switch,
  Text,
  ThemeIcon,
  Title,
} from "@mantine/core";
import { useLocalStorage } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import {
  IconCheck,
  IconCode,
  IconInfoCircle,
  IconShieldLock,
  IconCloud,
} from "@tabler/icons-react";
import { api, type TenantInfo } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";
import { SHOW_YAML_STORAGE_KEY } from "../../../../lib/preferences";
import { TagRegistryEditor } from "../../../components/config/TagRegistryEditor";
import { UsersManager } from "../../../components/config/UsersManager";

export default function SettingsPage() {
  const { token, tenantId, email } = useAuth();
  const [tenant, setTenant]         = useState<TenantInfo | null>(null);
  const [loading, setLoading]       = useState(true);
  const [health, setHealth]         = useState<"ok" | "error" | "loading">("loading");
  const [showYaml, setShowYaml]     = useLocalStorage({
    key: SHOW_YAML_STORAGE_KEY,
    defaultValue: false,
  });

  useEffect(() => {
    if (!token) return;
    Promise.all([
      api.getTenant(token).then(setTenant),
      api.health().then(() => setHealth("ok")).catch(() => setHealth("error")),
    ])
      .catch((e: unknown) => notifications.show({ color: "red", message: (e as Error).message }))
      .finally(() => setLoading(false));
  }, [token]);

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
        <Text fz="sm" fw={600} mb="md">Tenant</Text>
        <Stack gap="xs">
          <Group gap="xs">
            <Text fz="sm" c="dimmed" w={120}>Tenant ID</Text>
            <Code fz="sm">{tenant?.id ?? tenantId}</Code>
          </Group>
          <Group gap="xs">
            <Text fz="sm" c="dimmed" w={120}>Display name</Text>
            <Text fz="sm">{tenant?.name}</Text>
          </Group>
          <Group gap="xs">
            <Text fz="sm" c="dimmed" w={120}>Signed in as</Text>
            <Code fz="sm">{email}</Code>
          </Group>
          <Group gap="xs">
            <Text fz="sm" c="dimmed" w={120}>DEP enabled</Text>
            <Badge size="sm" variant="light" color={tenant?.dep_enabled ? "teal" : "gray"}>
              {tenant?.dep_enabled ? "Yes" : "No"}
            </Badge>
          </Group>
        </Stack>
      </Card>

      {/* Users (add / role / password reset / activate / delete) */}
      <UsersManager />
    </Stack>
  );
}
