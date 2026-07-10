"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  ActionIcon,
  Badge,
  Box,
  Button,
  Group,
  Loader,
  Pagination,
  Progress,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { IconRefresh, IconRotateClockwise, IconX } from "@tabler/icons-react";
import { api, type Task } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";
import { TaskDetailDrawer, TASK_STATUS_COLORS } from "../../../components/TaskDetailDrawer";

const PAGE_SIZE = 25;
const POLL_MS = 10_000;

const STATUSES = ["pending", "running", "completed", "failed", "cancelled"];

function fmt(iso: string | null) {
  if (!iso) return "--";
  return new Date(iso).toLocaleString();
}

export default function TasksPage() {
  const { token } = useAuth();
  const [tasks, setTasks]           = useState<Task[]>([]);
  const [total, setTotal]           = useState(0);
  const [page, setPage]             = useState(1);
  const [statusFilter, setStatus]   = useState<string | null>(null);
  const [userFilter, setUserFilter] = useState("");
  const [loading, setLoading]       = useState(true);
  const [cancelling, setCancelling] = useState<string | null>(null);
  const [retrying, setRetrying]     = useState<string | null>(null);
  const [syncing, setSyncing]       = useState(false);
  const [selected, setSelected]     = useState<Task | null>(null);
  const loadingRef = useRef(false);
  const [debouncedUser] = useDebouncedValue(userFilter, 300);

  const load = useCallback(async (background = false) => {
    if (!token || loadingRef.current) return;
    loadingRef.current = true;
    if (!background) setLoading(true);
    try {
      const res = await api.listTasks(token, {
        skip: (page - 1) * PAGE_SIZE,
        limit: PAGE_SIZE,
        ...(statusFilter ? { status: statusFilter } : {}),
        ...(debouncedUser ? { user: debouncedUser } : {}),
      });
      setTasks(res.tasks);
      setTotal(res.total);
      // Keep the open drawer in sync with fresh data.
      setSelected((cur) => (cur ? res.tasks.find((t) => t.id === cur.id) ?? cur : cur));
    } catch (e: unknown) {
      if (!background) notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      loadingRef.current = false;
      if (!background) setLoading(false);
    }
  }, [token, page, statusFilter, debouncedUser]);

  useEffect(() => { load(); }, [load]);

  // Task statuses change as devices respond -- poll quietly so the page
  // doesn't sit on stale "running" rows.
  useEffect(() => {
    const id = setInterval(() => {
      if (document.visibilityState === "visible") load(true);
    }, POLL_MS);
    return () => clearInterval(id);
  }, [load]);

  const handleCancel = async (id: string) => {
    if (!token) return;
    setCancelling(id);
    try {
      const res = await api.cancelTask(token, id);
      notifications.show({ color: "teal", message: res.message });
      load(true);
    } catch (e: unknown) {
      notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      setCancelling(null);
    }
  };

  const handleRetry = async (id: string) => {
    if (!token) return;
    setRetrying(id);
    try {
      const res = await api.retryTask(token, id);
      notifications.show({ color: "teal", message: res.message });
      setSelected(null); // close the drawer if the retried task was open
      load(true);
    } catch (e: unknown) {
      notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      setRetrying(null);
    }
  };

  const handleSyncNow = async () => {
    if (!token) return;
    setSyncing(true);
    try {
      const res = await api.syncNow(token);
      const queued = res.profiles_queued + res.removals_queued + res.apps_queued;
      notifications.show({
        color: "teal",
        title: "Sync complete",
        message: queued
          ? `${res.profiles_queued} profile install(s), ${res.removals_queued} removal(s), ${res.apps_queued} app install(s) queued across ${res.devices} device(s)`
          : `Everything already matches the declared state (${res.devices} device(s) checked)`,
      });
      load(true);
    } catch (e: unknown) {
      notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      setSyncing(false);
    }
  };

  const rows = tasks.map((t) => (
    <Table.Tr
      key={t.id}
      onClick={() => setSelected(t)}
      style={{ cursor: "pointer" }}
    >
      <Table.Td>
        <Text fz="sm" fw={500}>{t.description}</Text>
        <Text fz="xs" c="dimmed">{t.type}</Text>
      </Table.Td>
      <Table.Td>
        <Badge
          size="sm"
          color={TASK_STATUS_COLORS[t.status] ?? "gray"}
          variant="light"
        >
          {t.status}
        </Badge>
        {t.status === "running" && (
          <Progress value={t.progress} size="xs" mt={4} w={80} />
        )}
      </Table.Td>
      <Table.Td>
        {t.device?.serial_number ? (
          <Text fz="xs">{t.device.serial_number}</Text>
        ) : (
          <Text fz="xs" c="dimmed" style={{ fontFamily: "monospace" }}>
            {t.device_id ? t.device_id.slice(0, 8) + "…" : "--"}
          </Text>
        )}
      </Table.Td>
      <Table.Td><Text fz="xs">{fmt(t.created_at)}</Text></Table.Td>
      <Table.Td>
        {t.error ? (
          <Tooltip label={t.error} multiline w={300}>
            <Text fz="xs" c="red" style={{ cursor: "help" }}>
              {t.error.slice(0, 40)}{t.error.length > 40 ? "…" : ""}
            </Text>
          </Tooltip>
        ) : (
          <Text fz="xs" c="dimmed">--</Text>
        )}
      </Table.Td>
      <Table.Td onClick={(e) => e.stopPropagation()}>
        <Group gap={4} wrap="nowrap" justify="flex-end">
          {(t.status === "pending" || t.status === "running") && (
            <Tooltip label="Cancel task">
              <ActionIcon
                variant="subtle"
                color="red"
                size="sm"
                loading={cancelling === t.id}
                onClick={() => handleCancel(t.id)}
              >
                <IconX size={14} />
              </ActionIcon>
            </Tooltip>
          )}
          {(t.status === "failed" || t.status === "cancelled") && (
            <Tooltip label="Retry task">
              <ActionIcon
                variant="subtle"
                color="blue"
                size="sm"
                loading={retrying === t.id}
                onClick={() => handleRetry(t.id)}
              >
                <IconRotateClockwise size={14} />
              </ActionIcon>
            </Tooltip>
          )}
        </Group>
      </Table.Td>
    </Table.Tr>
  ));

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Title order={2}>Tasks</Title>
        <Group gap="sm">
          <Tooltip label="Reconcile the declared YAML state against all devices now">
            <Button
              leftSection={<IconRotateClockwise size={14} />}
              variant="light"
              color="teal"
              loading={syncing}
              onClick={handleSyncNow}
            >
              Sync now
            </Button>
          </Tooltip>
          <Button leftSection={<IconRefresh size={14} />} variant="light" onClick={() => load()}>
            Refresh
          </Button>
        </Group>
      </Group>

      <Group gap="sm">
        <Select
          placeholder="All statuses"
          data={STATUSES.map((s) => ({ value: s, label: s.charAt(0).toUpperCase() + s.slice(1) }))}
          value={statusFilter}
          onChange={(v) => { setStatus(v); setPage(1); }}
          clearable
          w={180}
        />
        <TextInput
          placeholder="Filter by user (email)"
          value={userFilter}
          onChange={(e) => { setUserFilter(e.currentTarget.value); setPage(1); }}
          w={220}
        />
        <Text fz="sm" c="dimmed">{total} total</Text>
      </Group>

      {loading ? (
        <Box py={60} style={{ textAlign: "center" }}><Loader /></Box>
      ) : tasks.length === 0 ? (
        <Text c="dimmed" ta="center" py="xl">No tasks found.</Text>
      ) : (
        <>
          <Table highlightOnHover withTableBorder verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Description</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Device</Table.Th>
                <Table.Th>Created</Table.Th>
                <Table.Th>Error</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>{rows}</Table.Tbody>
          </Table>

          <Pagination
            total={Math.ceil(total / PAGE_SIZE)}
            value={page}
            onChange={setPage}
          />
        </>
      )}

      <TaskDetailDrawer
        task={selected}
        opened={selected !== null}
        onClose={() => setSelected(null)}
        onCancel={handleCancel}
        cancelling={cancelling !== null}
        onRetry={handleRetry}
        retrying={retrying !== null}
      />
    </Stack>
  );
}
