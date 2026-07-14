"use client";

// Yes I stole the name from EPIC.

import { useEffect, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  CopyButton,
  Group,
  Loader,
  Modal,
  Stack,
  Text,
  ThemeIcon,
} from "@mantine/core";
import {
  IconAlertTriangle,
  IconCopy,
  IconCheck,
  IconLockOpen,
  IconShieldLock,
} from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { api, type DeviceSecret, type RevealedSecret } from "../../lib/api";
import { useAuth } from "../../lib/auth-context";

function fmt(ts: string | null): string {
  if (!ts) return "";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

export function BreakTheGlassCard({ deviceId }: { deviceId: string }) {
  const { token } = useAuth();
  const [secrets, setSecrets] = useState<DeviceSecret[] | null>(null);
  const [target, setTarget] = useState<DeviceSecret | null>(null); // confirm modal
  const [revealing, setRevealing] = useState(false);
  const [revealed, setRevealed] = useState<RevealedSecret | null>(null);

  const load = () => {
    if (!token) return;
    api
      .getDeviceSecrets(token, deviceId)
      .then((r) => setSecrets(r.secrets))
      .catch(() => setSecrets([]));
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, deviceId]);

  const breakGlass = async () => {
    if (!token || !target) return;
    setRevealing(true);
    try {
      const res = await api.revealDeviceSecret(token, deviceId, target.kind);
      setRevealed(res);
      setTarget(null);
      load(); // refresh the ledger (broken state + reveal count)
    } catch (e) {
      notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      setRevealing(false);
    }
  };

  // Nothing escrowed: keep the card out of the way entirely.
  if (secrets !== null && secrets.length === 0) return null;

  return (
    <Card withBorder radius="md" p="md">
      <Group justify="space-between" mb="xs">
        <Group gap="xs">
          <IconShieldLock size={16} />
          <Text fz="sm" fw={600}>
            Break The Glass
          </Text>
        </Group>
        {secrets === null && <Loader size="xs" />}
      </Group>

      <Stack gap="sm">
        {(secrets ?? []).map((s) => (
          <Group key={s.id} justify="space-between" wrap="nowrap" align="flex-start">
            <div style={{ minWidth: 0 }}>
              <Group gap={6}>
                <Text fz="sm" fw={500}>
                  {s.kind_label}
                </Text>
                {s.sealed ? (
                  <Badge size="xs" variant="light" color="gray">
                    sealed
                  </Badge>
                ) : (
                  <Badge size="xs" variant="light" color="orange">
                    revealed &times;{s.reveal_count}
                  </Badge>
                )}
              </Group>
              {s.label && (
                <Text fz="xs" c="dimmed">
                  {s.label}
                </Text>
              )}
              {!s.sealed && (
                <Text fz="xs" c="dimmed">
                  Last by {s.revealed_by} at {fmt(s.revealed_at)}
                </Text>
              )}
            </div>
            <Button
              size="xs"
              variant="light"
              color="orange"
              leftSection={<IconLockOpen size={14} />}
              onClick={() => setTarget(s)}
            >
              Break the glass
            </Button>
          </Group>
        ))}
      </Stack>

      <Text fz="xs" c="dimmed" mt="sm">
        Retrieving a password is logged to the audit trail and raises an alert.
      </Text>

      {/* Step 1: consequence-forward confirmation. */}
      <Modal
        opened={target !== null}
        onClose={() => setTarget(null)}
        title="Break the glass?"
        centered
      >
        <Stack gap="sm">
          <Alert
            color="orange"
            variant="light"
            icon={<IconAlertTriangle size={16} />}
          >
            You are about to reveal the <b>{target?.kind_label.toLowerCase()}</b>
            {target?.label ? ` (${target.label})` : ""}. This is recorded against your
            account and raises an alert on the device. On device access may expose you to
            privilaged or classified information, ensure you are authorized to access this device.
          </Alert>
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setTarget(null)} disabled={revealing}>
              Cancel
            </Button>
            <Button color="orange" onClick={breakGlass} loading={revealing}>
              Reveal password
            </Button>
          </Group>
        </Stack>
      </Modal>

      {/* Step 2: the plaintext, shown once. */}
      <Modal
        opened={revealed !== null}
        onClose={() => setRevealed(null)}
        title={revealed?.kind_label ?? "Password"}
        centered
      >
        <Stack gap="sm">
          <Alert color="orange" variant="light" icon={<IconAlertTriangle size={16} />}>
            Shown once. You will raise another alert if you retrieve it again.
          </Alert>
          {revealed?.label && (
            <Text fz="sm">
              Account / label: <b>{revealed.label}</b>
            </Text>
          )}
          <Group
            justify="space-between"
            wrap="nowrap"
            p="xs"
            style={{
              border: "1px solid var(--mantine-color-default-border)",
              borderRadius: "var(--mantine-radius-sm)",
              fontFamily: "var(--mantine-font-family-monospace)",
            }}
          >
            <Text fz="sm" style={{ wordBreak: "break-all" }}>
              {revealed?.value}
            </Text>
            <CopyButton value={revealed?.value ?? ""}>
              {({ copied, copy }) => (
                <Button
                  size="xs"
                  variant="light"
                  color={copied ? "teal" : "gray"}
                  leftSection={
                    copied ? <IconCheck size={14} /> : <IconCopy size={14} />
                  }
                  onClick={copy}
                >
                  {copied ? "Copied" : "Copy"}
                </Button>
              )}
            </CopyButton>
          </Group>
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setRevealed(null)}>
              Done
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Card>
  );
}
