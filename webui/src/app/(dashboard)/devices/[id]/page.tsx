"use client";

import { useEffect, useState, use } from "react";
import { useRouter } from "next/navigation";
import {
  ActionIcon,
  Badge,
  Box,
  Card,
  Group,
  Loader,
  Progress,
  SimpleGrid,
  Stack,
  Table,
  Tabs,
  Text,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconArrowLeft, IconClock } from "@tabler/icons-react";
import { api, type DeviceDetail, type Task } from "../../../../../lib/api";
import { useAuth } from "../../../../../lib/auth-context";
import { TaskDetailDrawer } from "../../../../components/TaskDetailDrawer";
import { DeviceCommands } from "../../../../components/DeviceCommands";
import {
  organizeAttributes,
  formatAttrValue,
  type AttrItem,
} from "../../../../../lib/device-attributes";

function timeSince(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function seenColor(iso: string): string {
  const age = Date.now() - new Date(iso).getTime();
  if (age < 60 * 60 * 1000) return "teal";      // within an hour
  if (age < 7 * 86400 * 1000) return "yellow";  // within a week
  return "gray";
}

const STATUS_COLORS: Record<string, string> = {
  installed: "teal", installing: "blue", pending: "yellow", failed: "red",
  completed: "teal", running: "blue", cancelled: "gray",
};

// str-ish getter over a device-reported dict with key fallbacks
function pick(obj: Record<string, unknown>, ...keys: string[]): string {
  for (const k of keys) {
    const v = obj[k];
    if (v !== undefined && v !== null && v !== "") return String(v);
  }
  return "—";
}

function BoolOrText({ item }: { item: AttrItem }) {
  if (item.isBool && typeof item.boolValue === "boolean") {
    return (
      <Badge size="sm" variant="light" color={item.boolValue ? "teal" : "gray"}>
        {item.boolValue ? "Yes" : "No"}
      </Badge>
    );
  }
  return <Text fz="sm" style={{ wordBreak: "break-word" }}>{item.value}</Text>;
}

function PropertyGrid({ items }: { items: AttrItem[] }) {
  return (
    <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="xs" verticalSpacing={2}>
      {items.map((it) => (
        <Group key={it.key} justify="space-between" wrap="nowrap" gap="lg"
               style={{ borderBottom: "1px solid var(--mantine-color-default-border)", padding: "6px 0" }}>
          <Text fz="sm" c="dimmed" style={{ whiteSpace: "nowrap" }}>{it.label}</Text>
          <div style={{ textAlign: "right", minWidth: 0 }}><BoolOrText item={it} /></div>
        </Group>
      ))}
    </SimpleGrid>
  );
}

export default function DeviceDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { token } = useAuth();
  const router = useRouter();
  const [detail, setDetail]   = useState<DeviceDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedTask, setSelectedTask] = useState<Task | null>(null);

  const load = async (background = false) => {
    if (!token) return;
    if (!background) setLoading(true);
    try {
      const d = await api.getDevice(token, id);
      setDetail(d);
      setSelectedTask((cur) => (cur ? d.recent_tasks.find((t) => t.id === cur.id) ?? cur : cur));
    } catch (e: unknown) {
      if (!background) notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      if (!background) setLoading(false);
    }
  };

  useEffect(() => { load(); }, [token, id]); // eslint-disable-line react-hooks/exhaustive-deps

  // Refresh quietly — command responses land asynchronously via the webhook.
  useEffect(() => {
    const iv = setInterval(() => {
      if (document.visibilityState === "visible") load(true);
    }, 15_000);
    return () => clearInterval(iv);
  }, [token, id]); // eslint-disable-line react-hooks/exhaustive-deps

  if (loading) return <Box py={80} style={{ textAlign: "center" }}><Loader /></Box>;
  if (!detail)  return <Text c="red">Device not found.</Text>;

  const { device, installed_apps, installed_profiles, recent_tasks } = detail;
  const deviceProfiles = detail.device_profiles ?? [];
  const deviceApps = detail.device_apps ?? [];
  const groups = organizeAttributes(device.attributes);
  const hasAttributes = groups.length > 0;

  const overview: AttrItem[] = [
    { key: "model", label: "Model", value: device.device_model || "—", isBool: false },
    { key: "os", label: "OS version", value: device.os_version || "—", isBool: false },
    { key: "hostname", label: "Hostname", value: device.hostname ?? "—", isBool: false },
    { key: "udid", label: "UDID", value: device.udid, isBool: false },
    { key: "enrolled", label: "Enrolled", value: new Date(device.enrollment_date).toLocaleDateString(), isBool: false },
    { key: "seen", label: "Last seen", value: timeSince(device.last_seen), isBool: false },
  ];

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Group>
          <ActionIcon variant="subtle" onClick={() => router.push("/devices")}>
            <IconArrowLeft size={18} />
          </ActionIcon>
          <Title order={2}>{device.serial_number}</Title>
          <Badge variant="light" size="lg">{device.device_model}</Badge>
          <Tooltip label={`Last seen ${new Date(device.last_seen).toLocaleString()}`}>
            <Badge variant="dot" color={seenColor(device.last_seen)} leftSection={<IconClock size={11} />}>
              {timeSince(device.last_seen)}
            </Badge>
          </Tooltip>
        </Group>
        <DeviceCommands device={device} onDispatched={() => load(true)} />
      </Group>

      <Tabs defaultValue="overview" keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="overview">Overview</Tabs.Tab>
          {groups.map((g) => (
            <Tabs.Tab key={g.category} value={g.category}>{g.category}</Tabs.Tab>
          ))}
          <Tabs.Tab value="profiles">Profiles</Tabs.Tab>
          <Tabs.Tab value="apps">Apps</Tabs.Tab>
          <Tabs.Tab value="tasks">Tasks{recent_tasks.length ? ` (${recent_tasks.length})` : ""}</Tabs.Tab>
        </Tabs.List>

        {/* ── Overview ─────────────────────────────────────────────────────── */}
        <Tabs.Panel value="overview" pt="md">
          <Stack gap="md">
            <Card withBorder radius="md" p="md">
              <Text fz="sm" fw={600} mb="sm">Summary</Text>
              <PropertyGrid items={overview} />
            </Card>

            <Card withBorder radius="md" p="md">
              <Text fz="sm" fw={600} mb="xs">Group membership</Text>
              <Group gap={6}>
                {device.groups.length > 0
                  ? device.groups.map((g) => <Badge key={g} variant="dot" color="blue">{g}</Badge>)
                  : <Text fz="sm" c="dimmed">No groups assigned</Text>}
              </Group>
            </Card>

            {!hasAttributes && (
              <Card withBorder radius="md" p="md">
                <Text fz="sm" c="dimmed">
                  No inventory collected yet. Use <b>Commands → Device information</b> to query this
                  device; the results populate the tabs here once it responds.
                </Text>
              </Card>
            )}
          </Stack>
        </Tabs.Panel>

        {/* ── Data-driven attribute category tabs ──────────────────────────── */}
        {groups.map((g) => (
          <Tabs.Panel key={g.category} value={g.category} pt="md">
            <Card withBorder radius="md" p="md">
              <PropertyGrid items={g.items} />
            </Card>
          </Tabs.Panel>
        ))}

        {/* ── Profiles ─────────────────────────────────────────────────────── */}
        <Tabs.Panel value="profiles" pt="md">
          <Stack gap="md">
            <Card withBorder radius="md" p="md">
              <Text fz="sm" fw={600} mb="md">On device ({deviceProfiles.length})</Text>
              {deviceProfiles.length === 0 ? (
                <Text fz="sm" c="dimmed">
                  Not queried yet — use <b>Commands → Installed profiles</b>.
                </Text>
              ) : (
                <Box style={{ overflowX: "auto" }}>
                  <Table fz="sm" verticalSpacing="xs">
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th>Name</Table.Th><Table.Th>Identifier</Table.Th>
                        <Table.Th>Version</Table.Th><Table.Th>Managed</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {deviceProfiles.map((p, i) => (
                        <Table.Tr key={i}>
                          <Table.Td>{pick(p, "PayloadDisplayName", "PayloadIdentifier")}</Table.Td>
                          <Table.Td><Text fz="xs" style={{ fontFamily: "monospace" }}>{pick(p, "PayloadIdentifier")}</Text></Table.Td>
                          <Table.Td>{pick(p, "PayloadVersion")}</Table.Td>
                          <Table.Td>{p.IsManaged ? <Badge size="xs" color="blue" variant="light">managed</Badge> : "—"}</Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Box>
              )}
            </Card>

            <Card withBorder radius="md" p="md">
              <Text fz="sm" fw={600} mb="md">Managed deployments ({installed_profiles.length})</Text>
              {installed_profiles.length === 0 ? (
                <Text fz="sm" c="dimmed">No managed profiles targeted at this device.</Text>
              ) : (
                <Table fz="sm" verticalSpacing="xs">
                  <Table.Thead><Table.Tr><Table.Th>Profile ID</Table.Th><Table.Th>Status</Table.Th></Table.Tr></Table.Thead>
                  <Table.Tbody>
                    {installed_profiles.map((p) => (
                      <Table.Tr key={p.profile_id}>
                        <Table.Td>{p.profile_id}</Table.Td>
                        <Table.Td><Badge size="xs" color={STATUS_COLORS[p.status] ?? "gray"} variant="light">{p.status}</Badge></Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              )}
            </Card>
          </Stack>
        </Tabs.Panel>

        {/* ── Apps ─────────────────────────────────────────────────────────── */}
        <Tabs.Panel value="apps" pt="md">
          <Stack gap="md">
            <Card withBorder radius="md" p="md">
              <Text fz="sm" fw={600} mb="md">On device ({deviceApps.length})</Text>
              {deviceApps.length === 0 ? (
                <Text fz="sm" c="dimmed">
                  Not queried yet — use <b>Commands → Installed apps</b>.
                </Text>
              ) : (
                <Box style={{ overflowX: "auto" }}>
                  <Table fz="sm" verticalSpacing="xs">
                    <Table.Thead>
                      <Table.Tr><Table.Th>Name</Table.Th><Table.Th>Identifier</Table.Th><Table.Th>Version</Table.Th></Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {deviceApps.map((a, i) => (
                        <Table.Tr key={i}>
                          <Table.Td>{pick(a, "Name", "AppName")}</Table.Td>
                          <Table.Td><Text fz="xs" style={{ fontFamily: "monospace" }}>{pick(a, "Identifier", "BundleId")}</Text></Table.Td>
                          <Table.Td>{pick(a, "ShortVersion", "Version")}</Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Box>
              )}
            </Card>

            <Card withBorder radius="md" p="md">
              <Text fz="sm" fw={600} mb="md">Managed deployments ({installed_apps.length})</Text>
              {installed_apps.length === 0 ? (
                <Text fz="sm" c="dimmed">No managed apps targeted at this device.</Text>
              ) : (
                <Table fz="sm" verticalSpacing="xs">
                  <Table.Thead><Table.Tr><Table.Th>App ID</Table.Th><Table.Th>Version</Table.Th><Table.Th>Status</Table.Th></Table.Tr></Table.Thead>
                  <Table.Tbody>
                    {installed_apps.map((a) => (
                      <Table.Tr key={a.app_id}>
                        <Table.Td>{a.app_id}</Table.Td>
                        <Table.Td>{a.version}</Table.Td>
                        <Table.Td><Badge size="xs" color={STATUS_COLORS[a.status] ?? "gray"} variant="light">{a.status}</Badge></Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              )}
            </Card>
          </Stack>
        </Tabs.Panel>

        {/* ── Tasks ────────────────────────────────────────────────────────── */}
        <Tabs.Panel value="tasks" pt="md">
          <Card withBorder radius="md" p="md">
            {recent_tasks.length === 0 ? (
              <Text fz="sm" c="dimmed">No recent tasks</Text>
            ) : (
              <Stack gap="xs">
                {recent_tasks.map((t) => (
                  <Box
                    key={t.id}
                    p="sm"
                    onClick={() => setSelectedTask(t)}
                    style={{ border: "1px solid var(--mantine-color-default-border)", borderRadius: 6, cursor: "pointer" }}
                  >
                    <Group justify="space-between" mb={4}>
                      <Text fz="sm" fw={500}>{t.description}</Text>
                      <Badge size="sm" color={STATUS_COLORS[t.status] ?? "gray"} variant="light">{t.status}</Badge>
                    </Group>
                    {t.status === "running" && <Progress value={t.progress} size="xs" mt={4} />}
                    {t.error && <Text fz="xs" c="red" mt={4}>{t.error}</Text>}
                    <Text fz="xs" c="dimmed" mt={4}>
                      {t.created_at ? new Date(t.created_at).toLocaleString() : ""}
                    </Text>
                  </Box>
                ))}
              </Stack>
            )}
          </Card>
        </Tabs.Panel>
      </Tabs>

      <TaskDetailDrawer
        task={selectedTask}
        opened={selectedTask !== null}
        onClose={() => setSelectedTask(null)}
      />
    </Stack>
  );
}
