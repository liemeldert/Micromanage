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
  Modal,
  Pagination,
  SegmentedControl,
  Select,
  Stack,
  TagsInput,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import {
  IconBrandApple,
  IconChevronRight,
  IconDeviceDesktopOff,
  IconPlus,
  IconRefresh,
  IconSearch,
} from "@tabler/icons-react";
import { api, type Device, type EnrollmentState } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";

const PAGE_SIZE = 20;

const STATE_META: Record<EnrollmentState, { label: string; color: string }> = {
  enrolled:   { label: "Enrolled",   color: "teal" },
  unenrolled: { label: "Unenrolled", color: "gray" },
  pending:    { label: "Pending",    color: "indigo" },
};

function timeSince(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function DevicesPage() {
  const { token, isAdmin } = useAuth();
  const router = useRouter();

  const [devices, setDevices]   = useState<Device[]>([]);
  const [total, setTotal]       = useState(0);
  const [counts, setCounts]     = useState({ all: 0, enrolled: 0, unenrolled: 0, pending: 0 });
  const [page, setPage]         = useState(1);
  const [search, setSearch]     = useState("");
  const [groupFilter, setGroup] = useState<string | null>(null);
  const [stateFilter, setState] = useState<string>("all");
  const [loading, setLoading]   = useState(true);

  // Add-placeholder modal
  const [addOpen, setAddOpen]   = useState(false);
  const [addSerial, setAddSerial] = useState("");
  const [addModel, setAddModel]   = useState("");
  const [addGroups, setAddGroups] = useState<string[]>([]);
  const [adding, setAdding]       = useState(false);

  const [debounced] = useDebouncedValue(search, 300);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = await api.listDevices(token, {
        skip: (page - 1) * PAGE_SIZE,
        limit: PAGE_SIZE,
        ...(debounced ? { search: debounced } : {}),
        ...(groupFilter ? { group: groupFilter } : {}),
        ...(stateFilter !== "all" ? { state: stateFilter } : {}),
      });
      setDevices(res.devices);
      setTotal(res.total);
      setCounts(res.counts);
    } catch (e: unknown) {
      notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      setLoading(false);
    }
  }, [token, page, debounced, groupFilter, stateFilter]);

  useEffect(() => { load(); }, [load]);

  const allGroups = Array.from(new Set(devices.flatMap((d) => d.groups))).sort();

  const handleAdd = async () => {
    if (!token || !addSerial.trim()) return;
    setAdding(true);
    try {
      await api.createPlaceholderDevice(token, {
        serial_number: addSerial.trim(),
        device_model: addModel.trim() || undefined,
        groups: addGroups,
      });
      notifications.show({ color: "teal", message: `Placeholder created for ${addSerial.trim()}` });
      setAddOpen(false);
      setAddSerial(""); setAddModel(""); setAddGroups([]);
      // Jump to the Pending tab to show the new placeholder (triggers a reload).
      setPage(1);
      setState("pending");
    } catch (e) {
      notifications.show({ color: "red", title: "Couldn't add device", message: (e as Error).message });
    } finally {
      setAdding(false);
    }
  };

  const rows = devices.map((d) => {
    const active = d.enrollment_state === "enrolled";
    const recent = active && new Date(d.last_seen).getTime() > Date.now() - 7 * 86400000;
    return (
      <Table.Tr
        key={d.id}
        style={{ cursor: "pointer", opacity: active ? 1 : 0.6 }}
        onClick={() => router.push(`/devices/${d.id}`)}
      >
        <Table.Td>
          <Group gap={6} wrap="nowrap">
            {d.management_type === "apple_mdm" && (
              <Tooltip label="Apple MDM"><IconBrandApple size={15} style={{ opacity: 0.6 }} /></Tooltip>
            )}
            <div>
              <Text fz="sm" fw={500}>{d.display_name || d.serial_number || "--"}</Text>
              <Text fz="xs" c="dimmed">
                {d.serial_number || (d.udid ? d.udid.slice(0, 8) + "…" : "not enrolled")}
              </Text>
            </div>
          </Group>
        </Table.Td>
        <Table.Td>
          <Badge size="sm" variant="light" color={STATE_META[d.enrollment_state].color}>
            {STATE_META[d.enrollment_state].label}
          </Badge>
        </Table.Td>
        <Table.Td><Text fz="sm">{d.device_model || "--"}</Text></Table.Td>
        <Table.Td>
          {d.os_version ? <Badge variant="light" size="sm">{d.os_version}</Badge> : <Text fz="xs" c="dimmed">--</Text>}
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
          {active ? (
            <Badge variant="light" color={recent ? "teal" : "gray"} size="sm">{timeSince(d.last_seen)}</Badge>
          ) : d.enrollment_state === "unenrolled" && d.unenrolled_at ? (
            <Text fz="xs" c="dimmed">left {timeSince(d.unenrolled_at)}</Text>
          ) : (
            <Text fz="xs" c="dimmed">--</Text>
          )}
        </Table.Td>
        <Table.Td>
          <ActionIcon variant="subtle" color="gray" size="sm"><IconChevronRight size={14} /></ActionIcon>
        </Table.Td>
      </Table.Tr>
    );
  });

  const seg = (s: EnrollmentState | "all", label: string) => ({
    value: s,
    label: `${label} (${counts[s]})`,
  });

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Title order={2}>Devices</Title>
        <Group gap="sm">
          {isAdmin && (
            <Button leftSection={<IconPlus size={14} />} variant="light" onClick={() => setAddOpen(true)}>
              Add device
            </Button>
          )}
          <Button leftSection={<IconRefresh size={14} />} variant="light" onClick={load}>
            Refresh
          </Button>
        </Group>
      </Group>

      <SegmentedControl
        value={stateFilter}
        onChange={(v) => { setState(v); setPage(1); }}
        data={[
          seg("all", "All"),
          seg("enrolled", "Enrolled"),
          seg("unenrolled", "Unenrolled"),
          seg("pending", "Pending"),
        ]}
      />

      <Group gap="sm">
        <TextInput
          placeholder="Search serial, hostname, model, UDID…"
          leftSection={<IconSearch size={14} />}
          value={search}
          onChange={(e) => { setSearch(e.currentTarget.value); setPage(1); }}
          w={320}
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
        <Stack align="center" py="xl" gap="xs">
          <IconDeviceDesktopOff size={28} style={{ opacity: 0.4 }} />
          <Text c="dimmed">
            {stateFilter === "all" ? "No devices yet." : `No ${stateFilter} devices.`}
          </Text>
        </Stack>
      ) : (
        <>
          <Table highlightOnHover withTableBorder withColumnBorders={false} verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Serial / UDID</Table.Th>
                <Table.Th>State</Table.Th>
                <Table.Th>Model</Table.Th>
                <Table.Th>OS</Table.Th>
                <Table.Th>Groups</Table.Th>
                <Table.Th>Activity</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>{rows}</Table.Tbody>
          </Table>

          <Pagination total={Math.ceil(total / PAGE_SIZE)} value={page} onChange={setPage} />
        </>
      )}

      <Modal opened={addOpen} onClose={() => setAddOpen(false)} title={<Text fw={600}>Pre-provision a device</Text>}>
        <Stack gap="md">
          <Text fz="sm" c="dimmed">
            Register a device by serial number before it enrolls. Its group membership is
            applied automatically when the physical device enrolls (e.g. via DEP).
          </Text>
          <TextInput
            label="Serial number"
            placeholder="C02XY1234ABC"
            required
            value={addSerial}
            onChange={(e) => setAddSerial(e.currentTarget.value)}
            data-autofocus
          />
          <TextInput
            label="Model (optional)"
            placeholder="iPad Pro 12.9-inch"
            value={addModel}
            onChange={(e) => setAddModel(e.currentTarget.value)}
          />
          <TagsInput
            label="Groups (optional)"
            description="Pre-assign groups; membership is re-evaluated on enrollment."
            placeholder="Type a group and press Enter"
            data={allGroups}
            value={addGroups}
            onChange={setAddGroups}
          />
          <Group justify="flex-end">
            <Button variant="subtle" color="gray" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button loading={adding} disabled={!addSerial.trim()} onClick={handleAdd}>Add device</Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
}
