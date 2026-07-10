"use client";

import { useEffect, useState } from "react";
import {
  Badge,
  Box,
  Card,
  Grid,
  Group,
  Loader,
  RingProgress,
  SimpleGrid,
  Stack,
  Text,
  Title,
} from "@mantine/core";
import {
  IconDeviceLaptop,
  IconCircleCheck,
  IconPackage,
  IconClock,
  IconActivityHeartbeat,
} from "@tabler/icons-react";
import { useRouter } from "next/navigation";
import { BarChart } from "@mantine/charts";
import { api } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";
import { notifications } from "@mantine/notifications";

interface Stats {
  devices: { total: number; active_7d: number };
  tasks: Record<string, number>;
  deployments: { apps: number; profiles: number };
}

function StatCard({
  label,
  value,
  sub,
  icon: Icon,
  color,
}: {
  label: string;
  value: number;
  sub?: string;
  icon: React.ElementType;
  color: string;
}) {
  return (
    <Card withBorder radius="md" p="lg">
      <Group justify="space-between" align="flex-start">
        <Stack gap={4}>
          <Text fz="sm" c="dimmed" fw={500}>
            {label}
          </Text>
          <Text fz={32} fw={700} lh={1}>
            {value.toLocaleString()}
          </Text>
          {sub && (
            <Text fz="xs" c="dimmed">
              {sub}
            </Text>
          )}
        </Stack>
        <Box
          style={{
            background: `var(--mantine-color-${color}-1)`,
            borderRadius: 8,
            padding: 10,
          }}
        >
          <Icon size={22} color={`var(--mantine-color-${color}-6)`} />
        </Box>
      </Group>
    </Card>
  );
}

export default function DashboardPage() {
  const { token } = useAuth();
  const router = useRouter();
  const [stats, setStats] = useState<Stats | null>(null);
  const [byModel, setByModel] = useState<{ device_model: string; count: number }[]>([]);
  const [byOs, setByOs] = useState<{ os_version: string; count: number }[]>([]);
  const [compliance, setCompliance] = useState<{ active: number; counts: Record<string, number> } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) return;
    Promise.all([api.getStats(token), api.getDevicesByModel(token), api.getDevicesByOs(token)])
      .then(([s, m, o]) => {
        setStats(s);
        setByModel(m.slice(0, 8));
        setByOs(o.slice(0, 8));
      })
      .catch((e) => notifications.show({ color: "red", message: e.message }))
      .finally(() => setLoading(false));
    // Compliance summary is independent + best-effort (feature may be unconfigured).
    api.listAlerts(token).then((a) => setCompliance({ active: a.active, counts: a.counts })).catch(() => {});
  }, [token]);

  if (loading) {
    return (
      <Box pt={80} style={{ textAlign: "center" }}>
        <Loader />
      </Box>
    );
  }

  const taskPending = stats?.tasks?.pending ?? 0;
  const taskRunning = stats?.tasks?.running ?? 0;
  const taskFailed  = stats?.tasks?.failed ?? 0;
  const taskDone    = stats?.tasks?.completed ?? 0;
  const taskTotal   = taskPending + taskRunning + taskFailed + taskDone;

  const activeRatio = stats
    ? Math.round((stats.devices.active_7d / Math.max(stats.devices.total, 1)) * 100)
    : 0;

  return (
    <Stack gap="lg">
      <Title order={2}>Dashboard</Title>

      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }} spacing="md">
        <Box style={{ cursor: "pointer" }} onClick={() => router.push("/devices")}>
          <StatCard
            label="Total Devices"
            value={stats?.devices.total ?? 0}
            sub={`${stats?.devices.active_7d ?? 0} active in last 7 days`}
            icon={IconDeviceLaptop}
            color="blue"
          />
        </Box>
        <Box style={{ cursor: "pointer" }} onClick={() => router.push("/apps")}>
          <StatCard
            label="App Deployments"
            value={stats?.deployments.apps ?? 0}
            icon={IconPackage}
            color="grape"
          />
        </Box>
        <Box style={{ cursor: "pointer" }} onClick={() => router.push("/profiles")}>
          <StatCard
            label="Profile Deployments"
            value={stats?.deployments.profiles ?? 0}
            icon={IconCircleCheck}
            color="teal"
          />
        </Box>
        <Box style={{ cursor: "pointer" }} onClick={() => router.push("/tasks")}>
          <StatCard
            label="Pending Tasks"
            value={taskPending + taskRunning}
            sub={taskFailed > 0 ? `${taskFailed} failed` : undefined}
            icon={IconClock}
            color={taskFailed > 0 ? "red" : "orange"}
          />
        </Box>
        <Box style={{ cursor: "pointer" }} onClick={() => router.push("/compliance")}>
          <StatCard
            label="Compliance Alerts"
            value={compliance?.active ?? 0}
            sub={
              compliance && compliance.active > 0
                ? (["black", "red", "yellow", "green"] as const)
                    .filter((s) => (compliance.counts[s] ?? 0) > 0)
                    .map((s) => `${compliance.counts[s]} ${s}`)
                    .join(" · ")
                : "all clear"
            }
            icon={IconActivityHeartbeat}
            color={
              compliance && ((compliance.counts.black ?? 0) > 0 || (compliance.counts.red ?? 0) > 0)
                ? "red"
                : compliance && compliance.active > 0
                  ? "yellow"
                  : "teal"
            }
          />
        </Box>
      </SimpleGrid>

      <Grid gutter="md">
        {/* Device activity ring */}
        <Grid.Col span={{ base: 12, md: 4 }}>
          <Card withBorder radius="md" h="100%">
            <Stack align="center" gap="xs">
              <Text fw={600} fz="sm">
                Device Activity (7 days)
              </Text>
              <RingProgress
                size={160}
                thickness={16}
                roundCaps
                sections={[{ value: activeRatio, color: "blue" }]}
                label={
                  <Text ta="center" fw={700} fz="xl">
                    {activeRatio}%
                  </Text>
                }
              />
              <Text fz="xs" c="dimmed">
                {stats?.devices.active_7d ?? 0} / {stats?.devices.total ?? 0} devices checked in
              </Text>
            </Stack>

            <Stack mt="md" gap={6}>
              {[
                { label: "Completed", count: taskDone, color: "teal" },
                { label: "Running",   count: taskRunning, color: "blue" },
                { label: "Pending",   count: taskPending, color: "yellow" },
                { label: "Failed",    count: taskFailed, color: "red" },
              ].map((row) => (
                <Group key={row.label} justify="space-between">
                  <Text fz="xs" c="dimmed">
                    {row.label}
                  </Text>
                  <Badge size="sm" color={row.color} variant="light">
                    {row.count}
                  </Badge>
                </Group>
              ))}
              <Group justify="space-between" mt={4}>
                <Text fz="xs" fw={500}>
                  Total tasks
                </Text>
                <Text fz="xs" fw={500}>
                  {taskTotal}
                </Text>
              </Group>
            </Stack>
          </Card>
        </Grid.Col>

        {/* Devices by model bar chart */}
        <Grid.Col span={{ base: 12, md: 8 }}>
          <Card withBorder radius="md">
            <Text fw={600} fz="sm" mb="md">
              Devices by Model
            </Text>
            {byModel.length > 0 ? (
              <BarChart
                h={220}
                data={byModel.map((d) => ({ name: d.device_model, Devices: d.count }))}
                dataKey="name"
                series={[{ name: "Devices", color: "blue" }]}
                tickLine="none"
                gridAxis="x"
              />
            ) : (
              <Text fz="sm" c="dimmed" ta="center" py="xl">
                No enrolled devices yet
              </Text>
            )}
          </Card>
        </Grid.Col>

        {/* Devices by OS */}
        {byOs.length > 0 && (
          <Grid.Col span={12}>
            <Card withBorder radius="md">
              <Text fw={600} fz="sm" mb="md">
                Devices by OS Version
              </Text>
              <BarChart
                h={200}
                data={byOs.map((d) => ({ name: d.os_version, Devices: d.count }))}
                dataKey="name"
                series={[{ name: "Devices", color: "grape" }]}
                tickLine="none"
                gridAxis="x"
              />
            </Card>
          </Grid.Col>
        )}
      </Grid>
    </Stack>
  );
}
