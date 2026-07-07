"use client";

// Organized device command menu + the confirmation/PIN modals that back the
// disruptive ones. Non-destructive refreshes fire immediately; power/security
// actions require admin and an explicit confirmation; erase requires typing the
// serial number. macOS requires a 6-digit PIN for lock/erase.

import { useState } from "react";
import {
  Alert,
  Button,
  Group,
  Menu,
  Modal,
  PinInput,
  Stack,
  Text,
  TextInput,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconAlertTriangle,
  IconChevronDown,
  IconDeviceMobileCog,
  IconEraser,
  IconLock,
  IconPower,
  IconRefresh,
  IconReload,
  IconShieldLock,
} from "@tabler/icons-react";
import { api, type Device } from "../../lib/api";
import { useAuth } from "../../lib/auth-context";

type CmdKind = "restart" | "shutdown" | "clear_passcode" | "lock" | "erase";

const CONFIRM_LABELS: Record<CmdKind, { verb: string; danger: boolean; body: string }> = {
  restart:        { verb: "Restart", danger: false, body: "The device will reboot now." },
  shutdown:       { verb: "Shut down", danger: false, body: "The device will power off and can only be turned back on physically." },
  clear_passcode: { verb: "Clear passcode", danger: false, body: "Removes the device passcode. On iOS the user can set a new one; on shared iPads this may be blocked." },
  lock:           { verb: "Lock", danger: false, body: "Locks the device immediately." },
  erase:          { verb: "Erase", danger: true, body: "Permanently erases ALL content and settings. This cannot be undone." },
};

export function DeviceCommands({ device, onDispatched }: { device: Device; onDispatched: () => void }) {
  const { token, isAdmin } = useAuth();
  const isMac = (device.device_model || "").toLowerCase().includes("mac");

  const [busy, setBusy] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<CmdKind | null>(null);
  const [pin, setPin] = useState("");
  const [lockMessage, setLockMessage] = useState("");
  const [eraseConfirmText, setEraseConfirmText] = useState("");

  const run = async (type: string, parameters: Record<string, unknown> = {}, label?: string) => {
    if (!token) return;
    setBusy(type);
    try {
      await api.sendCommand(token, device.id, type, parameters);
      notifications.show({ color: "teal", message: `${label ?? type} sent to ${device.serial_number}` });
      onDispatched();
    } catch (e) {
      notifications.show({ color: "red", title: "Command failed", message: (e as Error).message });
    } finally {
      setBusy(null);
    }
  };

  const closeConfirm = () => {
    setConfirm(null);
    setPin("");
    setLockMessage("");
    setEraseConfirmText("");
  };

  const submitConfirm = async () => {
    if (!confirm) return;
    const params: Record<string, unknown> = {};
    if ((confirm === "lock" || confirm === "erase") && pin) params.pin = pin;
    if (confirm === "lock" && lockMessage) params.message = lockMessage;
    await run(confirm, params, CONFIRM_LABELS[confirm].verb);
    closeConfirm();
  };

  // Gate the submit button on the modal's specific requirements.
  const pinOk = !isMac || (confirm !== "lock" && confirm !== "erase") || /^\d{6}$/.test(pin);
  const eraseOk = confirm !== "erase" || eraseConfirmText.trim() === device.serial_number;
  const canSubmit = pinOk && eraseOk;

  return (
    <>
      <Menu shadow="md" width={230} position="bottom-end">
        <Menu.Target>
          <Button
            variant="light"
            leftSection={<IconDeviceMobileCog size={16} />}
            rightSection={<IconChevronDown size={14} />}
            loading={!!busy}
          >
            Commands
          </Button>
        </Menu.Target>
        <Menu.Dropdown>
          <Menu.Label>Refresh from device</Menu.Label>
          <Menu.Item leftSection={<IconRefresh size={14} />} onClick={() => run("refresh_info", {}, "Refresh info")}>
            Device information
          </Menu.Item>
          <Menu.Item leftSection={<IconShieldLock size={14} />} onClick={() => run("security_info", {}, "Security info")}>
            Security posture
          </Menu.Item>
          <Menu.Item leftSection={<IconReload size={14} />} onClick={() => run("profile_list", {}, "Profile list")}>
            Installed profiles
          </Menu.Item>
          <Menu.Item leftSection={<IconReload size={14} />} onClick={() => run("app_list", {}, "App list")}>
            Installed apps
          </Menu.Item>

          <Menu.Divider />
          <Menu.Label>Actions {isAdmin ? "" : "(admin only)"}</Menu.Label>
          <Menu.Item
            leftSection={<IconLock size={14} />}
            disabled={!isAdmin}
            onClick={() => setConfirm("lock")}
          >
            Lock device
          </Menu.Item>
          <Menu.Item
            leftSection={<IconPower size={14} />}
            disabled={!isAdmin}
            onClick={() => setConfirm("restart")}
          >
            Restart
          </Menu.Item>
          <Menu.Item
            leftSection={<IconPower size={14} />}
            disabled={!isAdmin}
            onClick={() => setConfirm("shutdown")}
          >
            Shut down
          </Menu.Item>
          <Menu.Item
            leftSection={<IconShieldLock size={14} />}
            disabled={!isAdmin}
            onClick={() => setConfirm("clear_passcode")}
          >
            Clear passcode
          </Menu.Item>

          <Menu.Divider />
          <Menu.Item
            color="red"
            leftSection={<IconEraser size={14} />}
            disabled={!isAdmin}
            onClick={() => setConfirm("erase")}
          >
            Erase all content…
          </Menu.Item>
        </Menu.Dropdown>
      </Menu>

      <Modal
        opened={confirm !== null}
        onClose={closeConfirm}
        title={
          <Group gap="xs">
            {confirm && CONFIRM_LABELS[confirm].danger && <IconAlertTriangle size={18} color="var(--mantine-color-red-6)" />}
            <Text fw={600}>{confirm ? `${CONFIRM_LABELS[confirm].verb} ${device.serial_number}` : ""}</Text>
          </Group>
        }
      >
        {confirm && (
          <Stack gap="md">
            <Alert color={CONFIRM_LABELS[confirm].danger ? "red" : "yellow"} variant="light">
              {CONFIRM_LABELS[confirm].body}
            </Alert>

            {confirm === "lock" && (
              <TextInput
                label="Lock screen message (optional)"
                placeholder="This device has been locked by IT"
                value={lockMessage}
                onChange={(e) => setLockMessage(e.currentTarget.value)}
              />
            )}

            {isMac && (confirm === "lock" || confirm === "erase") && (
              <Stack gap={4}>
                <Text fz="sm" fw={500}>6-digit PIN</Text>
                <Text fz="xs" c="dimmed">
                  Required on Macs — you&apos;ll need this exact PIN to unlock the machine afterwards. Store it somewhere safe.
                </Text>
                <PinInput length={6} type="number" value={pin} onChange={setPin} oneTimeCode={false} />
              </Stack>
            )}

            {confirm === "erase" && (
              <TextInput
                label={`Type the serial number to confirm: ${device.serial_number}`}
                placeholder={device.serial_number}
                value={eraseConfirmText}
                onChange={(e) => setEraseConfirmText(e.currentTarget.value)}
                error={eraseConfirmText && !eraseOk ? "Doesn't match" : null}
              />
            )}

            <Group justify="flex-end" gap="sm">
              <Button variant="subtle" color="gray" onClick={closeConfirm}>Cancel</Button>
              <Button
                color={CONFIRM_LABELS[confirm].danger ? "red" : "blue"}
                disabled={!canSubmit}
                loading={busy === confirm}
                onClick={submitConfirm}
              >
                {CONFIRM_LABELS[confirm].verb}
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </>
  );
}
