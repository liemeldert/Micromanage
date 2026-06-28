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
  Text,
  ThemeIcon,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconCheck,
  IconInfoCircle,
  IconShieldLock,
  IconCloud,
} from "@tabler/icons-react";
import { api, type TenantInfo } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";

export default function SettingsPage() {
  const { token, tenantId, email } = useAuth();
  const [tenant, setTenant]         = useState<TenantInfo | null>(null);
  const [loading, setLoading]       = useState(true);
  const [health, setHealth]         = useState<"ok" | "error" | "loading">("loading");

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
        <Text fz="xs" c="dimmed">
          The controller syncs YAML compliance state every{" "}
          <Code fz="xs">SYNC_INTERVAL_MINUTES</Code> minutes and enqueues MDM commands.
        </Text>
      </Card>

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
          <Group align="flex-start" gap="xs">
            <Text fz="sm" c="dimmed" w={120}>Allowed users</Text>
            <Stack gap={4}>
              {(tenant?.allowed_users ?? []).map((u) => (
                <Code key={u} fz="xs">{u}</Code>
              ))}
            </Stack>
          </Group>
        </Stack>
      </Card>

      <Divider label="APNs Push Certificate" labelPosition="left" />

      {/* APNs setup guide */}
      <Card withBorder radius="md" p="md">
        <Group mb="sm">
          <ThemeIcon variant="light" color="blue" size="sm">
            <IconShieldLock size={14} />
          </ThemeIcon>
          <Text fz="sm" fw={600}>Apple Push Notification Certificate</Text>
        </Group>

        <Alert icon={<IconInfoCircle size={14} />} color="blue" variant="light" mb="md">
          APNs is required for NanoMDM to send push notifications to devices. Without it, MDM
          commands will not be delivered until devices next check in.
        </Alert>

        <Text fz="sm" mb="xs" fw={500}>Setup steps:</Text>
        <List size="sm" spacing="xs" type="ordered">
          <List.Item>
            Run <Code fz="xs">./setup.sh apns</Code> on the server — it generates a CSR and
            walks you through the Apple portal steps.
          </List.Item>
          <List.Item>
            Submit the CSR to{" "}
            <Text component="a" href="https://mdmcert.download" target="_blank" fz="sm" c="blue">
              mdmcert.download
            </Text>{" "}
            or the Apple Push Certificates Portal.
          </List.Item>
          <List.Item>
            Download the resulting <Code fz="xs">.pem</Code> certificate and save it as{" "}
            <Code fz="xs">certs/apns/MDM_Certificate.pem</Code>.
          </List.Item>
          <List.Item>
            Run <Code fz="xs">./setup.sh push-cert</Code> to upload it to NanoMDM.
          </List.Item>
        </List>

        <Box
          mt="md"
          p="sm"
          style={{
            background: "var(--mantine-color-dark-8, #1a1b1e)",
            borderRadius: 6,
            fontFamily: "monospace",
          }}
        >
          <Text fz="xs" c="green.4">$ ./setup.sh apns</Text>
          <Text fz="xs" c="gray.5">  → generates certs/apns/push.csr</Text>
          <Text fz="xs" c="gray.5">  → guides you through Apple portal</Text>
          <Text fz="xs" c="green.4" mt={4}>$ ./setup.sh push-cert</Text>
          <Text fz="xs" c="gray.5">  → uploads certificate to NanoMDM</Text>
        </Box>
      </Card>

      <Divider label="Object Storage (S3)" labelPosition="left" />

      {/* S3 info */}
      <Card withBorder radius="md" p="md">
        <Group mb="sm">
          <ThemeIcon variant="light" color="grape" size="sm">
            <IconCloud size={14} />
          </ThemeIcon>
          <Text fz="sm" fw={600}>App Package Storage</Text>
        </Group>
        <Text fz="sm" c="dimmed" mb="xs">
          App packages (<Code fz="xs">.ipa</Code> / <Code fz="xs">.pkg</Code>) must be hosted in
          S3-compatible object storage. Configure the following variables in your{" "}
          <Code fz="xs">.env</Code>:
        </Text>
        <List size="sm" spacing={4}>
          {[
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_DEFAULT_REGION",
            "AWS_S3_BUCKET",
            "AWS_S3_ENDPOINT_URL  (optional — for MinIO / R2)",
          ].map((v) => (
            <List.Item key={v}>
              <Code fz="xs">{v}</Code>
            </List.Item>
          ))}
        </List>
      </Card>
    </Stack>
  );
}
