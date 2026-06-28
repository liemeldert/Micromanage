"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  ActionIcon,
  Badge,
  Box,
  Button,
  Group,
  Loader,
  Pagination,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { IconRefresh, IconSearch, IconChevronRight } from "@tabler/icons-react";
import { api, type Device } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";

const PAGE_SIZE = 20;

function timeSince(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function DevicesPage() {
  const { token } = useAuth();
  const router = useRouter();

  const [devices, setDevices]   = useState<Device[]>([]);
  const [total, setTotal]       = useState(0);
  const [page, setPage]         = useState(1);
  const [search, setSearch]     = useState("");
  const [groupFilter, setGroup] = useState<string | null>(null);
  const [loading, setLoading]   = useState(true);

  const [debounced] = useDebouncedValue(search, 300);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = await api.listDevices(token, {
        skip: (page - 1) * PAGE_SIZE,
        limit: PAGE_SIZE,
        ...(debounced ? { model: debounced } : {}),
        ...(groupFilter ? { group: groupFilter } : {}),
      });
      setDevices(res.devices);
      setTotal(res.total);
    } catch (e: unknown) {
      notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      setLoading(false);
    }
  }, [token, page, debounced, groupFilter]);

  useEffect(() => { load(); }, [load]);

  const allGroups = Array.from(new Set(devices.flatMap((d) => d.groups))).sort();

  const rows = devices.map((d) => {
    const recent = new Date(d.last_seen).getTime() > Date.now() - 7 * 86400000;
    return (
      <Table.Tr
        key={d.id}
        style={{ cursor: "pointer" }}
        onClick={() => router.push(`/devices/${d.id}`)}
      >
        <Table.Td>
          <Text fz="sm" fw={500}>{d.serial_number}</Text>
          <Text fz="xs" c="dimmed">{d.udid.slice(0, 8)}…</Text>
        </Table.Td>
        <Table.Td>
          <Text fz="sm">{d.device_model}</Text>
        </Table.Td>
        <Table.Td>
          <Badge variant="light" size="sm">{d.os_version}</Badge>
        </Table.Td>
        <Table.Td>
          <Text fz="sm">{d.hostname ?? "—"}</Text>
        </Table.Td>
        <Table.Td>
          <Group gap={4} wrap="wrap">
            {d.groups.slice(0, 3).map((g) => (
              <Badge key={g} variant="dot" size="xs" color="blue">{g}</Badge>
            ))}
            {d.groups.length > 3 && (
              <Badge variant="dot" size="xs" color="gray">+{d.groups.length - 3}</Badge>
            )}
          </Group>
        </Table.Td>
        <Table.Td>
          <Badge
            variant="light"
            color={recent ? "teal" : "gray"}
            size="sm"
          >
            {timeSince(d.last_seen)}
          </Badge>
        </Table.Td>
        <Table.Td>
          <ActionIcon variant="subtle" color="gray" size="sm">
            <IconChevronRight size={14} />
          </ActionIcon>
        </Table.Td>
      </Table.Tr>
    );
  });

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Title order={2}>Devices</Title>
        <Button leftSection={<IconRefresh size={14} />} variant="light" onClick={load}>
          Refresh
        </Button>
      </Group>

      <Group gap="sm">
        <TextInput
          placeholder="Filter by model…"
          leftSection={<IconSearch size={14} />}
          value={search}
          onChange={(e) => { setSearch(e.currentTarget.value); setPage(1); }}
          w={240}
        />
        <Select
          placeholder="Group"
          data={allGroups}
          value={groupFilter}
          onChange={(v) => { setGroup(v); setPage(1); }}
          clearable
          w={200}
        />
      </Group>

      {loading ? (
        <Box py={60} style={{ textAlign: "center" }}><Loader /></Box>
      ) : devices.length === 0 ? (
        <Text c="dimmed" ta="center" py="xl">No devices enrolled yet.</Text>
      ) : (
        <>
          <Table highlightOnHover withTableBorder withColumnBorders={false} verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Serial / UDID</Table.Th>
                <Table.Th>Model</Table.Th>
                <Table.Th>OS</Table.Th>
                <Table.Th>Hostname</Table.Th>
                <Table.Th>Groups</Table.Th>
                <Table.Th>Last Seen</Table.Th>
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
