"use client";

import { useEffect, useState } from "react";
import { use } from "react";
import { useRouter } from "next/navigation";
import {
  ActionIcon,
  Badge,
  Box,
  Button,
  Card,
  Grid,
  Group,
  Loader,
  Menu,
  Progress,
  SimpleGrid,
  Stack,
  Table,
  Text,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconArrowLeft,
  IconChevronDown,
  IconRefresh,
  IconPower,
  IconRestore,
  IconLockOpen,
} from "@tabler/icons-react";
import { api, type DeviceDetail, type Task } from "../../../../../lib/api";
import { useAuth } from "../../../../../lib/auth-context";
import { TaskDetailDrawer } from "../../../../components/TaskDetailDrawer";

function timeSince(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

const STATUS_COLORS: Record<string, string> = {
  installed: "teal",
  installing: "blue",
  pending: "yellow",
  failed: "red",
  completed: "teal",
  running: "blue",
  cancelled: "gray",
};

export default function DeviceDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const { token } = useAuth();
  const router = useRouter();
  const [detail, setDetail]   = useState<DeviceDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [cmdLoading, setCmdLoading] = useState(false);
  const [selectedTask, setSelectedTask] = useState<Task | null>(null);

  const load = async (background = false) => {
    if (!token) return;
    if (!background) setLoading(true);
    try {
      const d = await api.getDevice(token, id);
      setDetail(d);
      // Keep an open task drawer in sync with fresh data.
      setSelectedTask((cur) =>
        cur ? d.recent_tasks.find((t) => t.id === cur.id) ?? cur : cur,
      );
    } catch (e: unknown) {
      if (!background) notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      if (!background) setLoading(false);
    }
  };

  useEffect(() => { load(); }, [token, id]); // eslint-disable-line react-hooks/exhaustive-deps

  // Task/deployment statuses change as the device responds — refresh quietly.
  useEffect(() => {
    const iv = setInterval(() => {
      if (document.visibilityState === "visible") load(true);
    }, 15_000);
    return () => clearInterval(iv);
  }, [token, id]); // eslint-disable-line react-hooks/exhaustive-deps

  const sendCommand = async (type: string, label: string) => {
    if (!token) return;
    setCmdLoading(true);
    try {
      const res = await api.sendCommand(token, id, type);
      notifications.show({ color: "teal", message: res.message || `${label} sent` });
    } catch (e: unknown) {
      notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      setCmdLoading(false);
    }
  };

  if (loading) return <Box py={80} style={{ textAlign: "center" }}><Loader /></Box>;
  if (!detail)  return <Text c="red">Device not found.</Text>;

  const { device, installed_apps, installed_profiles, recent_tasks } = detail;

  return (
    <Stack gap="lg">
      <Group>
        <ActionIcon variant="subtle" onClick={() => router.push("/devices")}>
          <IconArrowLeft size={18} />
        </ActionIcon>
        <Title order={2}>{device.serial_number}</Title>
        <Badge variant="light" size="lg">{device.device_model}</Badge>
      </Group>

      {/* Device info cards */}
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }} spacing="md">
        {[
          { label: "Serial Number", value: device.serial_number },
          { label: "OS Version",    value: device.os_version },
          { label: "Hostname",      value: device.hostname ?? "—" },
          { label: "Last Seen",     value: timeSince(device.last_seen) },
        ].map(({ label, value }) => (
          <Card key={label} withBorder radius="md" p="md">
            <Text fz="xs" c="dimmed" mb={4}>{label}</Text>
            <Text fz="sm" fw={600}>{value}</Text>
          </Card>
        ))}
      </SimpleGrid>

      {/* Groups */}
      <Card withBorder radius="md" p="md">
        <Text fz="sm" fw={600} mb="xs">Group Membership</Text>
        <Group gap={6}>
          {device.groups.length > 0
            ? device.groups.map((g) => (
                <Badge key={g} variant="dot" color="blue">{g}</Badge>
              ))
            : <Text fz="sm" c="dimmed">No groups assigned</Text>
          }
        </Group>
      </Card>

      {/* Commands */}
      <Card withBorder radius="md" p="md">
        <Group justify="space-between" mb="md">
          <Text fz="sm" fw={600}>Device Commands</Text>
        </Group>
        <Group gap="sm">
          <Button
            leftSection={<IconRefresh size={14} />}
            variant="light"
            size="sm"
            loading={cmdLoading}
            onClick={() => sendCommand("refresh_info", "Refresh")}
          >
            Refresh Info
          </Button>
          <Menu shadow="md">
            <Menu.Target>
              <Button
                variant="light"
                color="orange"
                size="sm"
                rightSection={<IconChevronDown size={14} />}
                loading={cmdLoading}
              >
                Power
              </Button>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Item
                leftSection={<IconRestore size={14} />}
                onClick={() => sendCommand("restart", "Restart")}
              >
                Restart
              </Menu.Item>
              <Menu.Item
                leftSection={<IconPower size={14} />}
                color="red"
                onClick={() => sendCommand("shutdown", "Shutdown")}
              >
                Shutdown
              </Menu.Item>
            </Menu.Dropdown>
          </Menu>
          <Button
            leftSection={<IconLockOpen size={14} />}
            variant="light"
            color="red"
            size="sm"
            loading={cmdLoading}
            onClick={() => sendCommand("clear_passcode", "Clear Passcode")}
          >
            Clear Passcode
          </Button>
        </Group>
      </Card>

      <Grid gutter="md">
        {/* Installed apps */}
        <Grid.Col span={{ base: 12, md: 6 }}>
          <Card withBorder radius="md" h="100%">
            <Text fz="sm" fw={600} mb="md">
              Installed Apps ({installed_apps.length})
            </Text>
            {installed_apps.length === 0 ? (
              <Text fz="sm" c="dimmed">No managed apps</Text>
            ) : (
              <Table fz="sm" verticalSpacing="xs">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>App ID</Table.Th>
                    <Table.Th>Version</Table.Th>
                    <Table.Th>Status</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {installed_apps.map((a) => (
                    <Table.Tr key={a.app_id}>
                      <Table.Td>{a.app_id}</Table.Td>
                      <Table.Td>{a.version}</Table.Td>
                      <Table.Td>
                        <Badge size="xs" color={STATUS_COLORS[a.status] ?? "gray"} variant="light">
                          {a.status}
                        </Badge>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}
          </Card>
        </Grid.Col>

        {/* Installed profiles */}
        <Grid.Col span={{ base: 12, md: 6 }}>
          <Card withBorder radius="md" h="100%">
            <Text fz="sm" fw={600} mb="md">
              Installed Profiles ({installed_profiles.length})
            </Text>
            {installed_profiles.length === 0 ? (
              <Text fz="sm" c="dimmed">No managed profiles</Text>
            ) : (
              <Table fz="sm" verticalSpacing="xs">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Profile ID</Table.Th>
                    <Table.Th>Status</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {installed_profiles.map((p) => (
                    <Table.Tr key={p.profile_id}>
                      <Table.Td>{p.profile_id}</Table.Td>
                      <Table.Td>
                        <Badge size="xs" color={STATUS_COLORS[p.status] ?? "gray"} variant="light">
                          {p.status}
                        </Badge>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}
          </Card>
        </Grid.Col>
      </Grid>

      {/* Recent tasks */}
      <Card withBorder radius="md">
        <Text fz="sm" fw={600} mb="md">Recent Tasks</Text>
        {recent_tasks.length === 0 ? (
          <Text fz="sm" c="dimmed">No recent tasks</Text>
        ) : (
          <Stack gap="xs">
            {recent_tasks.map((t) => (
              <Box
                key={t.id}
                p="sm"
                onClick={() => setSelectedTask(t)}
                style={{
                  border: "1px solid var(--mantine-color-default-border)",
                  borderRadius: 6,
                  cursor: "pointer",
                }}
              >
                <Group justify="space-between" mb={4}>
                  <Text fz="sm" fw={500}>{t.description}</Text>
                  <Badge
                    size="sm"
                    color={STATUS_COLORS[t.status] ?? "gray"}
                    variant="light"
                  >
                    {t.status}
                  </Badge>
                </Group>
                {t.status === "running" && (
                  <Progress value={t.progress} size="xs" mt={4} />
                )}
                {t.error && <Text fz="xs" c="red" mt={4}>{t.error}</Text>}
                <Text fz="xs" c="dimmed" mt={4}>
                  {t.created_at ? new Date(t.created_at).toLocaleString() : ""}
                </Text>
              </Box>
            ))}
          </Stack>
        )}
      </Card>

      <TaskDetailDrawer
        task={selectedTask}
        opened={selectedTask !== null}
        onClose={() => setSelectedTask(null)}
      />
    </Stack>
  );
}
