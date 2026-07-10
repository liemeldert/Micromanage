"use client";

// Device details, Jamf School-style: identity card + section navigation +
// quick actions in a left rail, and a rich Summary landing view (gauges,
// check/cross security posture, key facts) with deeper data-driven sections
// behind it. Commands come from the server's catalog (see DeviceCommandKit).

import { useEffect, useRef, useState, use } from "react";
import { useRouter } from "next/navigation";
import {
  ActionIcon,
  Alert,
  Badge,
  Box,
  Card,
  Grid,
  Group,
  Loader,
  NavLink,
  Progress,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  ThemeIcon,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconApps,
  IconArrowLeft,
  IconBattery3,
  IconBrandApple,
  IconCertificate,
  IconCheck,
  IconClock,
  IconCpu,
  IconDatabase,
  IconDeviceDesktop,
  IconDeviceIpad,
  IconDeviceLaptop,
  IconDeviceMobile,
  IconDeviceTv,
  IconDotsCircleHorizontal,
  IconInfoCircle,
  IconLayoutDashboard,
  IconMapPin,
  IconPencil,
  IconServer,
  IconWand,
  IconSettings,
  IconShieldLock,
  IconTerminal2,
  IconWifi,
  IconX,
} from "@tabler/icons-react";
import { api, type CatalogCommand, type DeviceDetail, type Task } from "../../../../../lib/api";
import { useAuth } from "../../../../../lib/auth-context";
import { TaskDetailDrawer } from "../../../../components/TaskDetailDrawer";
import { QuickActionsCard, CommandsPanel, RefreshButton } from "../../../../components/DeviceCommandKit";
import { DeviceLocationMap, type DeviceLocation } from "../../../../components/DeviceLocationMap";
import {
  organizeAttributes,
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
  if (age < 60 * 60 * 1000) return "teal";
  if (age < 7 * 86400 * 1000) return "yellow";
  return "gray";
}

function deviceIcon(model: string) {
  const m = (model || "").toLowerCase();
  if (m.includes("macbook")) return IconDeviceLaptop;
  if (m.includes("mac")) return IconDeviceDesktop;
  if (m.includes("ipad")) return IconDeviceIpad;
  if (m.includes("iphone") || m.includes("ipod")) return IconDeviceMobile;
  if (m.includes("appletv") || m.includes("apple tv")) return IconDeviceTv;
  return IconDeviceLaptop;
}

const STATUS_COLORS: Record<string, string> = {
  installed: "teal", installing: "blue", pending: "yellow", failed: "red",
  completed: "teal", running: "blue", cancelled: "gray",
};

const ENROLL_META: Record<string, { label: string; color: string }> = {
  enrolled:   { label: "Enrolled",   color: "teal" },
  unenrolled: { label: "Unenrolled", color: "gray" },
  pending:    { label: "Pending",    color: "indigo" },
};

// Per-category icons for the section nav (was a generic database icon for all).
const SECTION_ICONS: Record<string, React.FC<{ size?: number }>> = {
  Hardware: IconCpu,
  Software: IconBrandApple,
  Security: IconShieldLock,
  Network: IconWifi,
  Cellular: IconDeviceMobile,
  Management: IconServer,
  Other: IconDotsCircleHorizontal,
};

function pick(obj: Record<string, unknown>, ...keys: string[]): string {
  for (const k of keys) {
    const v = obj[k];
    if (v !== undefined && v !== null && v !== "") return String(v);
  }
  return "--";
}

// ── Small display primitives (Jamf-style rows) ────────────────────────────────

function FactRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Group justify="space-between" wrap="nowrap" gap="lg"
           style={{ borderBottom: "1px solid var(--mantine-color-default-border)", padding: "7px 0" }}>
      <Text fz="sm" c="dimmed" style={{ whiteSpace: "nowrap" }}>{label}</Text>
      <div style={{ textAlign: "right", minWidth: 0 }}>{children}</div>
    </Group>
  );
}

function CheckRow({ label, value }: { label: string; value: boolean | undefined }) {
  return (
    <FactRow label={label}>
      {value === undefined ? (
        <Text fz="sm" c="dimmed">--</Text>
      ) : (
        <ThemeIcon size="sm" radius="xl" variant="light" color={value ? "teal" : "gray"}>
          {value ? <IconCheck size={12} /> : <IconX size={12} />}
        </ThemeIcon>
      )}
    </FactRow>
  );
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
    <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="xl" verticalSpacing={0}>
      {items.map((it) => (
        <FactRow key={it.key} label={it.label}><BoolOrText item={it} /></FactRow>
      ))}
    </SimpleGrid>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function DeviceDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { token } = useAuth();
  const router = useRouter();
  const [detail, setDetail]   = useState<DeviceDetail | null>(null);
  const [catalog, setCatalog] = useState<CatalogCommand[]>([]);
  const [loading, setLoading] = useState(true);
  const [section, setSection] = useState("summary");
  const [selectedTask, setSelectedTask] = useState<Task | null>(null);
  const [renaming, setRenaming] = useState(false);
  const [nameDraft, setNameDraft] = useState("");
  const [savingName, setSavingName] = useState(false);

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

  // Command catalog is static per session -- fetch once.
  useEffect(() => {
    if (!token) return;
    api.getCommandCatalog(token).then((r) => setCatalog(r.commands)).catch(() => {});
  }, [token]);

  // Command results land asynchronously via the webhook, so we poll the device
  // for fresh data. Baseline is quiet (15s); after dispatching a command we
  // burst-poll every ~3s for ~45s so the result (a query response, a lock-state
  // flip) shows up promptly instead of on the next slow tick.
  const fastUntilRef = useRef(0);
  const handleDispatched = () => {
    fastUntilRef.current = Date.now() + 45_000;
    load(true);
  };
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      if (cancelled) return;
      if (document.visibilityState === "visible") await load(true);
      if (cancelled) return;
      const fast = Date.now() < fastUntilRef.current;
      timer = setTimeout(tick, fast ? 3_000 : 15_000);
    };
    timer = setTimeout(tick, 15_000);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [token, id]); // eslint-disable-line react-hooks/exhaustive-deps

  if (loading) return <Box py={80} style={{ textAlign: "center" }}><Loader /></Box>;
  if (!detail)  return <Text c="red">Device not found.</Text>;

  const { device, installed_apps, installed_profiles, recent_tasks } = detail;
  const attrs = (device.attributes ?? {}) as Record<string, unknown>;
  const sec = (attrs.SecurityInfo ?? {}) as Record<string, unknown>;
  const deviceProfiles = detail.device_profiles ?? [];
  const deviceApps = detail.device_apps ?? [];
  const groups = organizeAttributes(device.attributes);
  const DevIcon = deviceIcon(device.device_model);
  const enrolled = device.enrollment_state === "enrolled";

  const startRename = () => {
    setNameDraft(device.name ?? device.hostname ?? "");
    setRenaming(true);
  };
  const submitRename = async () => {
    if (!token) return;
    const name = nameDraft.trim();
    if (!name) return;
    setSavingName(true);
    try {
      const res = await api.renameDevice(token, id, name);
      notifications.show({
        color: "teal",
        message: res.pushed ? "Name saved and rename pushed to the device" : "Name saved",
      });
      setRenaming(false);
      await load(true);
    } catch (e) {
      notifications.show({ color: "red", title: "Rename failed", message: (e as Error).message });
    } finally {
      setSavingName(false);
    }
  };

  // Gauges
  const battery = typeof attrs.BatteryLevel === "number" ? attrs.BatteryLevel : null;
  const capacity = typeof attrs.DeviceCapacity === "number" ? attrs.DeviceCapacity : null;
  const available = typeof attrs.AvailableDeviceCapacity === "number" ? attrs.AvailableDeviceCapacity : null;
  const usedPct = capacity && available !== null ? Math.round(((capacity - available) / capacity) * 100) : null;

  const bool = (v: unknown): boolean | undefined => (typeof v === "boolean" ? v : undefined);

  // Location (from a DeviceLocation command -- Lost Mode only).
  const rawLoc = attrs.DeviceLocation as Record<string, unknown> | undefined;
  const location: DeviceLocation | null =
    rawLoc && typeof rawLoc.Latitude === "number" && typeof rawLoc.Longitude === "number"
      ? {
          Latitude: rawLoc.Latitude as number,
          Longitude: rawLoc.Longitude as number,
          HorizontalAccuracy: typeof rawLoc.HorizontalAccuracy === "number" ? rawLoc.HorizontalAccuracy : null,
          Timestamp: typeof rawLoc.Timestamp === "string" ? rawLoc.Timestamp : null,
        }
      : null;
  const lostMode = bool(attrs.IsMDMLostModeEnabled) === true;
  // Location can be requested from supervised iOS devices that are in Lost Mode,
  // or shown whenever we already have a fix.
  const isMacModel = (device.device_model || "").toLowerCase().includes("mac");
  const showLocationCard = location !== null || (bool(attrs.IsSupervised) && !isMacModel);

  const SECTIONS = [
    { value: "summary", label: "Summary", icon: IconLayoutDashboard },
    ...groups.map((g) => ({ value: g.category, label: g.category, icon: SECTION_ICONS[g.category] ?? IconDotsCircleHorizontal })),
    { value: "profiles", label: `Profiles (${deviceProfiles.length || installed_profiles.length})`, icon: IconCertificate },
    { value: "apps", label: `Apps (${deviceApps.length || installed_apps.length})`, icon: IconApps },
    { value: "tasks", label: `Activity (${recent_tasks.length})`, icon: IconClock },
    { value: "commands", label: "Commands", icon: IconTerminal2 },
  ];

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Group>
          <ActionIcon variant="subtle" onClick={() => router.push("/devices")}>
            <IconArrowLeft size={18} />
          </ActionIcon>
          {renaming ? (
            <Group gap={4} wrap="nowrap">
              <TextInput
                value={nameDraft}
                onChange={(e) => setNameDraft(e.currentTarget.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") submitRename();
                  if (e.key === "Escape") setRenaming(false);
                }}
                size="sm"
                w={240}
                autoFocus
                data-autofocus
                disabled={savingName}
              />
              <Tooltip label="Save & push">
                <ActionIcon variant="light" color="teal" loading={savingName}
                            disabled={!nameDraft.trim()} onClick={submitRename}>
                  <IconCheck size={16} />
                </ActionIcon>
              </Tooltip>
              <ActionIcon variant="subtle" color="gray" onClick={() => setRenaming(false)} disabled={savingName}>
                <IconX size={16} />
              </ActionIcon>
              {device.suggested_name && device.suggested_name !== nameDraft.trim() && (
                <Tooltip label={`Use naming template: ${device.suggested_name}`}>
                  <ActionIcon variant="subtle" color="blue" onClick={() => setNameDraft(device.suggested_name!)}>
                    <IconWand size={16} />
                  </ActionIcon>
                </Tooltip>
              )}
            </Group>
          ) : (
            <Group gap={4} wrap="nowrap">
              <Title order={2}>{device.display_name}</Title>
              <Tooltip label="Rename device">
                <ActionIcon variant="subtle" color="gray" size="sm" onClick={startRename}>
                  <IconPencil size={15} />
                </ActionIcon>
              </Tooltip>
            </Group>
          )}
          <Badge variant="light" color={ENROLL_META[device.enrollment_state].color}>
            {ENROLL_META[device.enrollment_state].label}
          </Badge>
          {enrolled && (
            <Tooltip label={`Last seen ${new Date(device.last_seen).toLocaleString()}`}>
              <Badge variant="dot" color={seenColor(device.last_seen)}>{timeSince(device.last_seen)}</Badge>
            </Tooltip>
          )}
        </Group>
        {/* Re-poll the whole device -- the common "get fresh data" action. */}
        {enrolled && (
          <RefreshButton
            device={device}
            catalog={catalog}
            commandType="refresh_info"
            label="Refresh device"
            size="sm"
            variant="default"
            onDispatched={handleDispatched}
          />
        )}
      </Group>

      {!enrolled && (
        <Alert
          color={device.enrollment_state === "pending" ? "indigo" : "gray"}
          variant="light"
          icon={<IconInfoCircle size={16} />}
        >
          {device.enrollment_state === "pending" ? (
            <>This device is <b>pre-provisioned</b> and hasn&apos;t enrolled yet. Its saved state
            (group membership) will apply automatically when it enrolls. Commands and live
            inventory become available after enrollment.</>
          ) : (
            <>This device is <b>unenrolled</b>
            {device.unenrolled_at ? ` (since ${new Date(device.unenrolled_at).toLocaleString()})` : ""}.
            Its history and last-known state are retained; if it re-enrolls, everything below is
            restored. Commands are unavailable while unenrolled.</>
          )}
        </Alert>
      )}

      <Grid gutter="lg">
        {/* ── Left rail: identity, sections, quick actions ─────────────────── */}
        <Grid.Col span={{ base: 12, md: 3.5, lg: 3 }}>
          <Stack gap="md">
            <Card withBorder radius="md" p="md">
              <Group wrap="nowrap" gap="sm">
                <ThemeIcon size={54} radius="md" variant="light">
                  <DevIcon size={34} />
                </ThemeIcon>
                <div style={{ minWidth: 0 }}>
                  <Text fw={700} truncate>{device.serial_number}</Text>
                  <Text fz="xs" c="dimmed" truncate>{device.device_model}</Text>
                  <Text fz="xs" c="dimmed">{attrs.OSVersion ? `OS ${attrs.OSVersion}` : device.os_version}</Text>
                </div>
              </Group>
              <Group gap={6} mt="sm">
                {bool(attrs.IsSupervised) && <Badge size="xs" variant="light" color="blue">Supervised</Badge>}
                {bool(attrs.IsAppleSilicon) && <Badge size="xs" variant="light" color="grape">Apple Silicon</Badge>}
                {bool(attrs.IsMDMLostModeEnabled) && <Badge size="xs" variant="light" color="red">Lost Mode</Badge>}
              </Group>
            </Card>

            <Card withBorder radius="md" p={6}>
              {SECTIONS.map((s) => (
                <NavLink
                  key={s.value}
                  label={s.label}
                  leftSection={<s.icon size={15} />}
                  active={section === s.value}
                  onClick={() => setSection(s.value)}
                  style={{ borderRadius: 6 }}
                />
              ))}
            </Card>

            {enrolled && (
              <QuickActionsCard
                device={device}
                catalog={catalog}
                onDispatched={handleDispatched}
                onShowAll={() => setSection("commands")}
              />
            )}
          </Stack>
        </Grid.Col>

        {/* ── Content ──────────────────────────────────────────────────────── */}
        <Grid.Col span={{ base: 12, md: 8.5, lg: 9 }}>
          {section === "summary" && (
            <Stack gap="md">
              <Card withBorder radius="md" p="md">
                <Text fz="sm" fw={600} mb="xs">Details</Text>
                <SimpleGrid cols={{ base: 1, md: 2 }} spacing="xl" verticalSpacing={0}>
                  <FactRow label="Name"><Text fz="sm">{device.hostname ?? "--"}</Text></FactRow>
                  <FactRow label="Model"><Text fz="sm">{pick(attrs, "ModelName", "ProductName") !== "--" ? pick(attrs, "ModelName", "ProductName") : device.device_model}</Text></FactRow>
                  <FactRow label="Serial"><Text fz="sm" style={{ fontFamily: "monospace" }}>{device.serial_number}</Text></FactRow>
                  <FactRow label="OS version">
                    <Text fz="sm">
                      {device.os_version}
                      {typeof attrs.BuildVersion === "string" ? <Text span fz="xs" c="dimmed"> ({attrs.BuildVersion})</Text> : null}
                    </Text>
                  </FactRow>
                  <FactRow label="UDID"><Text fz="xs" style={{ fontFamily: "monospace" }}>{device.udid ?? "--"}</Text></FactRow>
                  <FactRow label="Enrolled"><Text fz="sm">{new Date(device.enrollment_date).toLocaleDateString()}</Text></FactRow>
                  <CheckRow label="Supervised" value={bool(attrs.IsSupervised)} />
                  <FactRow label="Member of">
                    <Group gap={4} justify="flex-end">
                      {device.groups.length
                        ? device.groups.map((g) => <Badge key={g} size="xs" variant="dot" color="blue">{g}</Badge>)
                        : <Text fz="sm" c="dimmed">no groups</Text>}
                    </Group>
                  </FactRow>
                </SimpleGrid>
              </Card>

              {(battery !== null || usedPct !== null) && (
                <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md">
                  {battery !== null && (
                    <Card withBorder radius="md" p="md">
                      <Group gap="xs" mb={6}>
                        <IconBattery3 size={16} />
                        <Text fz="sm" fw={600}>Charge</Text>
                        <Text fz="sm" c="dimmed">{Math.round(battery * 100)}%</Text>
                      </Group>
                      <Progress value={battery * 100} color={battery > 0.2 ? "teal" : "red"} size="lg" radius="sm" />
                    </Card>
                  )}
                  {usedPct !== null && (
                    <Card withBorder radius="md" p="md">
                      <Group gap="xs" mb={6}>
                        <IconDatabase size={16} />
                        <Text fz="sm" fw={600}>Storage</Text>
                        <Text fz="sm" c="dimmed">
                          {available!.toFixed(1)} GB free of {capacity!.toFixed(0)} GB
                        </Text>
                      </Group>
                      <Progress value={usedPct} color={usedPct > 90 ? "red" : "blue"} size="lg" radius="sm" />
                    </Card>
                  )}
                </SimpleGrid>
              )}

              <Card withBorder radius="md" p="md">
                <Group justify="space-between" mb="xs">
                  <Text fz="sm" fw={600}>Security</Text>
                  <RefreshButton device={device} catalog={catalog} commandType="security_info" disabled={!enrolled} onDispatched={handleDispatched} />
                </Group>
                <SimpleGrid cols={{ base: 1, md: 2 }} spacing="xl" verticalSpacing={0}>
                  <CheckRow label="Passcode set" value={bool(sec.PasscodePresent)} />
                  <CheckRow label="Passcode compliant" value={bool(sec.PasscodeCompliant)} />
                  <CheckRow label="FileVault" value={bool(sec.FDE_Enabled)} />
                  <CheckRow label="Firewall" value={bool(sec.FirewallEnabled)} />
                  <CheckRow label="System Integrity Protection" value={bool(attrs.SystemIntegrityProtectionEnabled)} />
                  <CheckRow label="Activation Lock" value={bool(attrs.IsActivationLockEnabled)} />
                  <CheckRow label="Find My" value={bool(attrs.IsDeviceLocatorServiceEnabled)} />
                  <CheckRow label="iCloud Backup" value={bool(attrs.IsCloudBackupEnabled)} />
                </SimpleGrid>
                {Object.keys(sec).length === 0 && (
                  <Text fz="xs" c="dimmed" mt="xs">
                    Security posture not collected yet -- click <b>Refresh</b> above to ask the device.
                  </Text>
                )}
              </Card>

              {showLocationCard && (
                <Card withBorder radius="md" p="md">
                  <Group justify="space-between" mb="xs">
                    <Group gap="xs">
                      <IconMapPin size={16} />
                      <Text fz="sm" fw={600}>Location</Text>
                    </Group>
                    <Tooltip
                      label={lostMode ? "Ask the device to report its location" : "Only available while the device is in Lost Mode"}
                      withinPortal
                    >
                      <Box style={{ display: "flex" }}>
                        <RefreshButton
                          device={device}
                          catalog={catalog}
                          commandType="device_location"
                          label={location ? "Update" : "Request location"}
                          disabled={!lostMode}
                          onDispatched={handleDispatched}
                        />
                      </Box>
                    </Tooltip>
                  </Group>
                  {location ? (
                    <>
                      <DeviceLocationMap location={location} />
                      {location.Timestamp && (
                        <Text fz="xs" c="dimmed" mt={6}>
                          As of {new Date(location.Timestamp).toLocaleString()}
                        </Text>
                      )}
                    </>
                  ) : (
                    <Text fz="sm" c="dimmed">
                      No location reported. Put the device into Lost Mode, then request its
                      location -- the map appears here once it responds.
                    </Text>
                  )}
                </Card>
              )}

              {recent_tasks.length > 0 && (
                <Card withBorder radius="md" p="md">
                  <Group justify="space-between" mb="xs">
                    <Text fz="sm" fw={600}>Recent activity</Text>
                    <Text fz="xs" c="blue" style={{ cursor: "pointer" }} onClick={() => setSection("tasks")}>
                      View all
                    </Text>
                  </Group>
                  <Stack gap={6}>
                    {recent_tasks.slice(0, 3).map((t) => (
                      <Group key={t.id} justify="space-between" wrap="nowrap"
                             style={{ cursor: "pointer" }} onClick={() => setSelectedTask(t)}>
                        <Text fz="sm" truncate>{t.description}</Text>
                        <Badge size="xs" color={STATUS_COLORS[t.status] ?? "gray"} variant="light">{t.status}</Badge>
                      </Group>
                    ))}
                  </Stack>
                </Card>
              )}
            </Stack>
          )}

          {groups.map((g) => section === g.category && (
            <Card key={g.category} withBorder radius="md" p="md">
              <Text fz="sm" fw={600} mb="xs">{g.category}</Text>
              <PropertyGrid items={g.items} />
            </Card>
          ))}

          {section === "profiles" && (
            <Stack gap="md">
              <Card withBorder radius="md" p="md">
                <Group justify="space-between" mb="md">
                  <Text fz="sm" fw={600}>On device ({deviceProfiles.length})</Text>
                  <RefreshButton device={device} catalog={catalog} commandType="profile_list" disabled={!enrolled} onDispatched={handleDispatched} />
                </Group>
                {deviceProfiles.length === 0 ? (
                  <Text fz="sm" c="dimmed">Not queried yet -- click <b>Refresh</b> to ask the device.</Text>
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
                            <Table.Td>{p.IsManaged ? <Badge size="xs" color="blue" variant="light">managed</Badge> : "--"}</Table.Td>
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
          )}

          {section === "apps" && (
            <Stack gap="md">
              <Card withBorder radius="md" p="md">
                <Group justify="space-between" mb="md">
                  <Text fz="sm" fw={600}>On device ({deviceApps.length})</Text>
                  <RefreshButton device={device} catalog={catalog} commandType="app_list" disabled={!enrolled} onDispatched={handleDispatched} />
                </Group>
                {deviceApps.length === 0 ? (
                  <Text fz="sm" c="dimmed">Not queried yet -- click <b>Refresh</b> to ask the device.</Text>
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
          )}

          {section === "tasks" && (
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
          )}

          {section === "commands" && (
            enrolled ? (
              <CommandsPanel device={device} catalog={catalog} onDispatched={handleDispatched} />
            ) : (
              <Card withBorder radius="md" p="md">
                <Text fz="sm" c="dimmed">
                  Commands are unavailable while the device is {device.enrollment_state}. They become
                  available once it enrolls and has an active MDM channel.
                </Text>
              </Card>
            )
          )}
        </Grid.Col>
      </Grid>

      <TaskDetailDrawer
        task={selectedTask}
        opened={selectedTask !== null}
        onClose={() => setSelectedTask(null)}
      />
    </Stack>
  );
}
