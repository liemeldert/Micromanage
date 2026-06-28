"use client";

import { useCallback, useEffect, useState } from "react";
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
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconRefresh, IconX } from "@tabler/icons-react";
import { api, type Task } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";

const PAGE_SIZE = 25;

const STATUS_COLORS: Record<string, string> = {
  pending: "yellow",
  running: "blue",
  completed: "teal",
  failed: "red",
  cancelled: "gray",
};

const STATUSES = ["pending", "running", "completed", "failed", "cancelled"];

function fmt(iso: string | null) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

export default function TasksPage() {
  const { token } = useAuth();
  const [tasks, setTasks]           = useState<Task[]>([]);
  const [total, setTotal]           = useState(0);
  const [page, setPage]             = useState(1);
  const [statusFilter, setStatus]   = useState<string | null>(null);
  const [loading, setLoading]       = useState(true);
  const [cancelling, setCancelling] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = await api.listTasks(token, {
        skip: (page - 1) * PAGE_SIZE,
        limit: PAGE_SIZE,
        ...(statusFilter ? { status: statusFilter } : {}),
      });
      setTasks(res.tasks);
      setTotal(res.total);
    } catch (e: unknown) {
      notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      setLoading(false);
    }
  }, [token, page, statusFilter]);

  useEffect(() => { load(); }, [load]);

  const handleCancel = async (id: string) => {
    if (!token) return;
    setCancelling(id);
    try {
      const res = await api.cancelTask(token, id);
      notifications.show({ color: "teal", message: res.message });
      load();
    } catch (e: unknown) {
      notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      setCancelling(null);
    }
  };

  const rows = tasks.map((t) => (
    <Table.Tr key={t.id}>
      <Table.Td>
        <Text fz="sm" fw={500}>{t.description}</Text>
        <Text fz="xs" c="dimmed">{t.type}</Text>
      </Table.Td>
      <Table.Td>
        <Badge
          size="sm"
          color={STATUS_COLORS[t.status] ?? "gray"}
          variant="light"
        >
          {t.status}
        </Badge>
        {t.status === "running" && (
          <Progress value={t.progress} size="xs" mt={4} w={80} />
        )}
      </Table.Td>
      <Table.Td>
        <Text fz="xs" c="dimmed" style={{ fontFamily: "monospace" }}>
          {t.device_id ? t.device_id.slice(0, 8) + "…" : "—"}
        </Text>
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
          <Text fz="xs" c="dimmed">—</Text>
        )}
      </Table.Td>
      <Table.Td>
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
      </Table.Td>
    </Table.Tr>
  ));

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Title order={2}>Tasks</Title>
        <Button leftSection={<IconRefresh size={14} />} variant="light" onClick={load}>
          Refresh
        </Button>
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
    </Stack>
  );
}
