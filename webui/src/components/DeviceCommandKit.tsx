"use client";

// Device command UI, driven by the server's command catalog
// (GET /api/v1/commands/catalog) rather than a hardcoded list:
//
//  * QuickActionsCard  -- the catalog's `common` commands, Jamf-style, for the
//    device page's left rail.
//  * CommandsPanel     -- every available command, grouped by category, with
//    role-gating ("requires admin") from the catalog.
//  * Known commands (KNOWN_FLOWS) get a tailored confirm/step-through modal --
//    e.g. erase demands the serial number and a Mac PIN.
//  * Unknown commands (in the catalog but with no custom flow here) still work:
//    they get a generic modal that shows a passthrough warning and renders the
//    fields straight from the catalog's params schema.

import { useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Box,
  Button,
  Card,
  Group,
  Modal,
  PasswordInput,
  PinInput,
  Stack,
  Text,
  Textarea,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconAlertTriangle,
  IconArrowRight,
  IconLock,
  IconLockOpen2,
  IconMapPin,
  IconPower,
  IconRefresh,
  IconShieldLock,
  IconTerminal2,
  IconUsers,
  IconVolume,
  IconVolumeOff,
} from "@tabler/icons-react";
import { api, type CatalogCommand, type Device } from "../../lib/api";
import { useAuth } from "../../lib/auth-context";

// ── Custom flows for commands we know well ────────────────────────────────────
const KNOWN_FLOWS: Record<string, { body: string; danger?: boolean; serialConfirm?: boolean }> = {
  restart:          { body: "The device will reboot now." },
  shutdown:         { body: "The device will power off and can only be turned back on physically." },
  clear_passcode:   { body: "Removes the device passcode. On iOS the user can then set a new one." },
  lock:             { body: "Locks the device immediately." },
  enable_lost_mode: { body: "Locks the device into Managed Lost Mode and shows your message on the lock screen. The user can't use the device until you disable Lost Mode." },
  disable_lost_mode:{ body: "Takes the device out of Managed Lost Mode and unlocks it." },
  erase:            { body: "Permanently erases ALL content and settings. This cannot be undone.", danger: true, serialConfirm: true },
};

const CATEGORY_ICONS: Record<string, React.FC<{ size?: number }>> = {
  Queries: IconRefresh,
  Power: IconPower,
  Security: IconShieldLock,
  "Lost Mode": IconMapPin,
  Users: IconUsers,
};

function isMac(device: Device) {
  return (device.device_model || "").toLowerCase().includes("mac");
}

// A small "Refresh" button for a specific contextual command, shown on the tab
// it populates (and the header) rather than buried in the commands menu.
export function RefreshButton({
  device, catalog, commandType, label, size = "xs", variant = "light", disabled = false, onDispatched,
}: {
  device: Device;
  catalog: CatalogCommand[];
  commandType: string;
  label?: string;
  size?: string;
  variant?: string;
  disabled?: boolean;
  onDispatched: () => void;
}) {
  const { token } = useAuth();
  const [busy, setBusy] = useState(false);
  const entry = catalog.find((c) => c.type === commandType);
  if (!entry) return null;

  const run = async () => {
    if (!token) return;
    setBusy(true);
    try {
      await api.sendCommand(token, device.id, commandType, {});
      notifications.show({ color: "teal", message: `${entry.label} requested -- updates when the device responds.` });
      onDispatched();
    } catch (e) {
      notifications.show({ color: "red", title: "Command failed", message: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Button size={size} variant={variant} leftSection={<IconRefresh size={14} />}
            loading={busy} disabled={disabled} onClick={run}>
      {label ?? "Refresh"}
    </Button>
  );
}

// ── The modal (custom or generic, decided by the catalog entry) ───────────────
function CommandModal({
  device, entry, opened, onClose, onDone,
}: {
  device: Device;
  entry: CatalogCommand | null;
  opened: boolean;
  onClose: () => void;
  onDone: () => void;
}) {
  const { token } = useAuth();
  const [values, setValues] = useState<Record<string, string>>({});
  const [serialText, setSerialText] = useState("");
  const [busy, setBusy] = useState(false);

  if (!entry) return null;
  const flow = KNOWN_FLOWS[entry.type];
  const mac = isMac(device);

  const requiredMissing = entry.params.some((p) => {
    const need = p.required === true || (p.required === "mac" && mac);
    return need && !(values[p.name] ?? "").trim();
  });
  const pinParam = entry.params.find((p) => p.type === "pin");
  const pinInvalid = !!pinParam && !!values[pinParam.name] && !/^\d{6}$/.test(values[pinParam.name]);
  const serialBlocked = !!flow?.serialConfirm && serialText.trim() !== device.serial_number;
  const canSubmit = !requiredMissing && !pinInvalid && !serialBlocked;

  const close = () => {
    setValues({});
    setSerialText("");
    onClose();
  };

  const submit = async () => {
    if (!token) return;
    setBusy(true);
    try {
      const parameters: Record<string, unknown> = {};
      for (const p of entry.params) {
        const v = (values[p.name] ?? "").trim();
        if (v) parameters[p.name] = v;
      }
      await api.sendCommand(token, device.id, entry.type, parameters);
      notifications.show({ color: "teal", message: `${entry.label} sent to ${device.serial_number}` });
      close();
      onDone();
    } catch (e) {
      notifications.show({ color: "red", title: "Command failed", message: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      opened={opened}
      onClose={close}
      title={
        <Group gap="xs">
          {(flow?.danger || entry.destructive) && (
            <IconAlertTriangle size={18} color={`var(--mantine-color-${flow?.danger ? "red" : "yellow"}-6)`} />
          )}
          <Text fw={600}>{entry.label} -- {device.serial_number}</Text>
        </Group>
      }
    >
      <Stack gap="md">
        {flow ? (
          <Alert color={flow.danger ? "red" : "yellow"} variant="light">{flow.body}</Alert>
        ) : (
          // No tailored flow for this command yet -- be explicit that the
          // fields below are passed through to the device untouched.
          <Alert color="orange" variant="light" icon={<IconAlertTriangle size={16} />}>
            <Text fz="sm" fw={500}>No guided flow exists for this command yet.</Text>
            <Text fz="xs" mt={4}>
              {entry.description} The fields below are sent to the device exactly as
              entered -- double-check them before running.
            </Text>
          </Alert>
        )}

        {entry.params.map((p) => {
          const need = p.required === true || (p.required === "mac" && mac);
          if (p.type === "pin") {
            // Macs require the PIN; skip the field entirely on non-Macs unless required.
            if (!need && !mac) return null;
            return (
              <Stack key={p.name} gap={4}>
                <Text fz="sm" fw={500}>{p.label}{need ? "" : " (optional)"}</Text>
                {p.help && <Text fz="xs" c="dimmed">{p.help}</Text>}
                <PinInput
                  length={6}
                  type="number"
                  value={values[p.name] ?? ""}
                  onChange={(v) => setValues((s) => ({ ...s, [p.name]: v }))}
                  oneTimeCode={false}
                />
              </Stack>
            );
          }
          // Secret params (passwords) render masked; free text as textarea; else input.
          const Field = p.secret ? PasswordInput : p.type === "text" ? Textarea : TextInput;
          return (
            <Field
              key={p.name}
              label={`${p.label}${need ? "" : " (optional)"}`}
              description={p.help}
              required={need}
              autoComplete={p.secret ? "new-password" : undefined}
              value={values[p.name] ?? ""}
              onChange={(e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
                // Read the value BEFORE the state updater runs -- React recycles
                // the synthetic event, so e.currentTarget is null inside it.
                const v = e.currentTarget.value;
                setValues((s) => ({ ...s, [p.name]: v }));
              }}
            />
          );
        })}

        {flow?.serialConfirm && (
          <TextInput
            label={`Type the serial number to confirm: ${device.serial_number}`}
            placeholder={device.serial_number}
            value={serialText}
            onChange={(e) => setSerialText(e.currentTarget.value)}
            error={serialText && serialBlocked ? "Doesn't match" : null}
          />
        )}

        <Group justify="flex-end" gap="sm">
          <Button variant="subtle" color="gray" onClick={close}>Cancel</Button>
          <Button
            color={flow?.danger ? "red" : "blue"}
            disabled={!canSubmit}
            loading={busy}
            onClick={submit}
          >
            {entry.label}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

// ── Shared runner hook: fire simple commands, open modals for the rest ────────
function useCommandRunner(device: Device, onDispatched: () => void) {
  const { token } = useAuth();
  const [modalEntry, setModalEntry] = useState<CatalogCommand | null>(null);
  const [busyType, setBusyType] = useState<string | null>(null);

  const runOrOpen = async (entry: CatalogCommand) => {
    // Plain refreshes fire immediately; anything destructive or parameterized
    // goes through a modal (custom if we know it, generic otherwise).
    if (!entry.destructive && entry.params.length === 0) {
      if (!token) return;
      setBusyType(entry.type);
      try {
        await api.sendCommand(token, device.id, entry.type, {});
        notifications.show({ color: "teal", message: `${entry.label} sent to ${device.serial_number}` });
        onDispatched();
      } catch (e) {
        notifications.show({ color: "red", title: "Command failed", message: (e as Error).message });
      } finally {
        setBusyType(null);
      }
      return;
    }
    setModalEntry(entry);
  };

  const modal = (
    <CommandModal
      device={device}
      entry={modalEntry}
      opened={modalEntry !== null}
      onClose={() => setModalEntry(null)}
      onDone={onDispatched}
    />
  );

  return { runOrOpen, busyType, modal };
}

// ── Quick actions (left rail) ─────────────────────────────────────────────────
export function QuickActionsCard({
  device, catalog, onDispatched, onShowAll,
}: {
  device: Device;
  catalog: CatalogCommand[];
  onDispatched: () => void;
  onShowAll: () => void;
}) {
  const { runOrOpen, busyType, modal } = useCommandRunner(device, onDispatched);

  // The lock cluster: a lock/unlock toggle + a "ring" (Lost Mode sound) button.
  // Lock state is what the device reports (IsMDMLostModeEnabled). Lost Mode is a
  // supervised-iOS feature; on Macs / unsupervised devices we fall back to a
  // plain DeviceLock and the ring stays disabled.
  const attrs = (device.attributes ?? {}) as Record<string, unknown>;
  const locked = attrs.IsMDMLostModeEnabled === true;
  const supervised = attrs.IsSupervised === true;
  const isMac = (device.device_model || "").toLowerCase().includes("mac");
  const lostCapable = supervised && !isMac;

  const byType = (t: string) => catalog.find((c) => c.type === t);
  const ringCmd = byType("play_lost_mode_sound");
  const lockEntry = lostCapable ? byType(locked ? "disable_lost_mode" : "enable_lost_mode") : byType("lock");
  const showUnlock = lostCapable && locked;
  const ringDisabled = !lostCapable || !locked || !ringCmd?.allowed;

  // Cluster owns these types; keep them out of the generic common-command list.
  const CLUSTER_TYPES = new Set(["lock", "enable_lost_mode", "disable_lost_mode", "play_lost_mode_sound"]);
  const quick = catalog.filter((c) => c.common && c.allowed && !c.contextual && !CLUSTER_TYPES.has(c.type));

  return (
    <Card withBorder radius="md" p="md">
      <Text fz="sm" fw={600} mb="sm">Quick Actions</Text>
      <Stack gap={6}>
        {lockEntry && (
          <Group gap={6} wrap="nowrap">
            <Tooltip label="Requires the admin role" disabled={lockEntry.allowed} withinPortal>
              <Box style={{ flex: 1, display: "flex" }}>
                <Button
                  variant="light"
                  color={showUnlock ? "blue" : "orange"}
                  justify="flex-start"
                  leftSection={showUnlock ? <IconLockOpen2 size={14} /> : <IconLock size={14} />}
                  disabled={!lockEntry.allowed}
                  onClick={() => runOrOpen(lockEntry)}
                  fullWidth
                >
                  {showUnlock ? "Unlock device" : "Lock device"}
                </Button>
              </Box>
            </Tooltip>
            <Tooltip
              label={
                !lostCapable ? "Ring requires Lost Mode (supervised iOS)"
                  : !locked ? "Available once the device is in Lost Mode"
                  : "Play a sound on the device"
              }
              withinPortal
            >
              <Box style={{ display: "flex" }}>
                <ActionIcon
                  variant="light"
                  color="blue"
                  size={36}
                  disabled={ringDisabled}
                  loading={busyType === "play_lost_mode_sound"}
                  onClick={() => ringCmd && runOrOpen(ringCmd)}
                  aria-label="Ring device"
                >
                  {ringDisabled ? <IconVolumeOff size={17} /> : <IconVolume size={17} />}
                </ActionIcon>
              </Box>
            </Tooltip>
          </Group>
        )}
        {quick.map((c) => {
          const Icon = CATEGORY_ICONS[c.category] ?? IconTerminal2;
          return (
            <Button
              key={c.type}
              variant="light"
              color={c.destructive ? "orange" : "blue"}
              justify="flex-start"
              leftSection={<Icon size={14} />}
              loading={busyType === c.type}
              onClick={() => runOrOpen(c)}
              fullWidth
            >
              {c.label}
            </Button>
          );
        })}
        <Button
          variant="subtle"
          color="gray"
          justify="flex-start"
          rightSection={<IconArrowRight size={14} />}
          onClick={onShowAll}
          fullWidth
        >
          All commands
        </Button>
      </Stack>
      {modal}
    </Card>
  );
}

// ── Full catalog, grouped by category ─────────────────────────────────────────
export function CommandsPanel({
  device, catalog, onDispatched,
}: {
  device: Device;
  catalog: CatalogCommand[];
  onDispatched: () => void;
}) {
  const { runOrOpen, busyType, modal } = useCommandRunner(device, onDispatched);
  // Contextual refreshes (device info, profile/app inventory) belong on their
  // own tabs, not in the command menu.
  const menu = catalog.filter((c) => !c.contextual);
  const categories = Array.from(new Set(menu.map((c) => c.category)));

  return (
    <Stack gap="lg">
      {categories.map((cat) => {
        const Icon = CATEGORY_ICONS[cat] ?? IconTerminal2;
        return (
          <Card key={cat} withBorder radius="md" p="md">
            <Group gap="xs" mb="sm">
              <Icon size={16} />
              <Text fz="sm" fw={600}>{cat}</Text>
            </Group>
            <Stack gap="xs">
              {menu.filter((c) => c.category === cat).map((c) => (
                <Group
                  key={c.type}
                  justify="space-between"
                  wrap="nowrap"
                  p="sm"
                  style={{ border: "1px solid var(--mantine-color-default-border)", borderRadius: 6 }}
                >
                  <div style={{ minWidth: 0 }}>
                    <Group gap={8}>
                      <Text fz="sm" fw={500}>{c.label}</Text>
                      {c.destructive && <Badge size="xs" color="red" variant="light">admin</Badge>}
                      {!KNOWN_FLOWS[c.type] && (c.destructive || c.params.length > 0) && (
                        <Badge size="xs" color="orange" variant="light">generic form</Badge>
                      )}
                    </Group>
                    <Text fz="xs" c="dimmed">{c.description}</Text>
                  </div>
                  <Tooltip label="Requires the admin role" disabled={c.allowed}>
                    <Button
                      size="xs"
                      variant="light"
                      color={c.destructive ? "red" : "blue"}
                      disabled={!c.allowed}
                      loading={busyType === c.type}
                      onClick={() => runOrOpen(c)}
                    >
                      Run
                    </Button>
                  </Tooltip>
                </Group>
              ))}
            </Stack>
          </Card>
        );
      })}
      {modal}
    </Stack>
  );
}
