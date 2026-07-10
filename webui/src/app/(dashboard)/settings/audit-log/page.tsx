"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Anchor,
  Badge,
  Box,
  Button,
  Code,
  Group,
  Loader,
  Pagination,
  Stack,
  Table,
  Text,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconArrowLeft, IconRefresh } from "@tabler/icons-react";
import Link from "next/link";
import { api, type AuditLogEntry } from "../../../../../lib/api";
import { useAuth } from "../../../../../lib/auth-context";

const PAGE_SIZE = 25;

function fmt(iso: string | null) {
  if (!iso) return "--";
  return new Date(iso).toLocaleString();
}

// Server-written action enums -> a friendly colour so the table scans quickly.
const ACTION_COLORS: Record<string, string> = {
  "user.create": "teal",
  "user.update": "blue",
  "user.delete": "red",
  "device.forget": "orange",
};

export default function AuditLogPage() {
  const { token, isAdmin } = useAuth();
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [total, setTotal]     = useState(0);
  const [page, setPage]       = useState(1);
  const [loading, setLoading] = useState(true);
  const loadingRef = useRef(false);

  const load = useCallback(async () => {
    if (!token || loadingRef.current) return;
    loadingRef.current = true;
    setLoading(true);
    try {
      const res = await api.listAuditLog(token, {
        skip: (page - 1) * PAGE_SIZE,
        limit: PAGE_SIZE,
      });
      setEntries(res.entries);
      setTotal(res.total);
    } catch (e: unknown) {
      notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      loadingRef.current = false;
      setLoading(false);
    }
  }, [token, page]);

  useEffect(() => { load(); }, [load]);

  // Frontend gate is convenience only -- the /api/v1/audit-log endpoint is the
  // real guard (require_admin) -- but hide the table from non-admins anyway.
  if (!isAdmin) {
    return (
      <Stack gap="lg">
        <Title order={2}>Audit log</Title>
        <Text c="dimmed">Admin role required to view the audit log.</Text>
        <Anchor component={Link} href="/settings" fz="sm">
          Back to settings
        </Anchor>
      </Stack>
    );
  }

  const rows = entries.map((e) => (
    <Table.Tr key={e.id}>
      <Table.Td><Text fz="xs">{fmt(e.created_at)}</Text></Table.Td>
      <Table.Td>
        <Text fz="sm">{e.actor_email ?? "--"}</Text>
        {e.actor_role && (
          <Text fz="xs" c="dimmed">{e.actor_role}</Text>
        )}
      </Table.Td>
      <Table.Td>
        <Badge size="sm" variant="light" color={ACTION_COLORS[e.action] ?? "gray"}>
          {e.action}
        </Badge>
      </Table.Td>
      <Table.Td>
        {e.target_type ? (
          <Text fz="xs">
            {e.target_type}
            {e.target_id && (
              <Code fz="xs" ml={6}>{e.target_id.slice(0, 8)}</Code>
            )}
          </Text>
        ) : (
          <Text fz="xs" c="dimmed">--</Text>
        )}
      </Table.Td>
    </Table.Tr>
  ));

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Group gap="sm">
          <Button
            component={Link}
            href="/settings"
            variant="subtle"
            size="compact-sm"
            leftSection={<IconArrowLeft size={14} />}
          >
            Settings
          </Button>
          <Title order={2}>Audit log</Title>
        </Group>
        <Button leftSection={<IconRefresh size={14} />} variant="light" onClick={() => load()}>
          Refresh
        </Button>
      </Group>

      <Text fz="sm" c="dimmed">{total} total</Text>

      {loading ? (
        <Box py={60} style={{ textAlign: "center" }}><Loader /></Box>
      ) : entries.length === 0 ? (
        <Text c="dimmed" ta="center" py="xl">No audit entries yet.</Text>
      ) : (
        <>
          <Table highlightOnHover withTableBorder verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>When</Table.Th>
                <Table.Th>Actor</Table.Th>
                <Table.Th>Action</Table.Th>
                <Table.Th>Target</Table.Th>
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
