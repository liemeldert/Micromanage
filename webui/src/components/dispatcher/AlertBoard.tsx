"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  ActionIcon,
  Badge,
  Box,
  Button,
  Card,
  Chip,
  Code,
  Collapse,
  Group,
  Loader,
  Paper,
  ScrollArea,
  Stack,
  Text,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconCheck,
  IconChevronRight,
  IconRefresh,
  IconShieldCheck,
} from "@tabler/icons-react";
import { api, type DispatcherAlert } from "../../../lib/api";
import { useAuth } from "../../../lib/auth-context";

// Triage colours (black > red > yellow > green).
export const SEVERITY_COLOR: Record<string, string> = {
  black: "dark",
  red: "red",
  yellow: "yellow",
  green: "green",
};

const ACTIVE_STATUSES = ["pending", "open", "acknowledged"];

export function AlertBoard() {
  const { token, isAdmin } = useAuth();
  const router = useRouter();
  const [alerts, setAlerts] = useState<DispatcherAlert[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(true);
  const [sevFilter, setSevFilter] = useState<string | null>(null);
  const [showResolved, setShowResolved] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(
    async (background = false) => {
      if (!token) return;
      if (!background) setLoading(true);
      try {
        const res = await api.listAlerts(token, sevFilter ? { severity: sevFilter } : {});
        setAlerts(res.alerts);
        setCounts(res.counts);
      } catch (e) {
        if (!background) notifications.show({ color: "red", message: (e as Error).message });
      } finally {
        if (!background) setLoading(false);
      }
    },
    [token, sevFilter],
  );

  useEffect(() => {
    load();
    const t = setInterval(() => load(true), 15000);
    return () => clearInterval(t);
  }, [load]);

  const visible = useMemo(
    () => alerts.filter((a) => (showResolved ? true : ACTIVE_STATUSES.includes(a.status))),
    [alerts, showResolved],
  );

  const act = async (fn: () => Promise<unknown>, id: string) => {
    setBusy(id);
    try {
      await fn();
      await load(true);
    } catch (e) {
      notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      setBusy(null);
    }
  };

  const evaluateNow = () =>
    act(async () => {
      const r = await api.dispatcherEvaluate(token!);
      notifications.show({ color: "teal", message: `Evaluated ${r.devices_evaluated} devices` });
    }, "__eval");

  if (loading) return <Loader />;

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Group gap="xs">
          {(["black", "red", "yellow", "green"] as const).map((s) => (
            <Chip
              key={s}
              checked={sevFilter === s}
              onChange={() => setSevFilter(sevFilter === s ? null : s)}
              color={SEVERITY_COLOR[s]}
              variant="light"
              size="sm"
            >
              {s} · {counts[s] ?? 0}
            </Chip>
          ))}
        </Group>
        <Group gap="xs">
          <Chip checked={showResolved} onChange={() => setShowResolved((v) => !v)} size="sm" variant="light">
            Show resolved
          </Chip>
          <Button
            size="compact-sm"
            variant="light"
            leftSection={<IconRefresh size={14} />}
            onClick={evaluateNow}
            loading={busy === "__eval"}
          >
            Evaluate now
          </Button>
        </Group>
      </Group>

      {visible.length === 0 ? (
        <Paper withBorder p="xl" radius="md">
          <Group justify="center" gap="xs">
            <IconShieldCheck size={20} color="var(--mantine-color-teal-6)" />
            <Text c="dimmed">No {showResolved ? "" : "active "}alerts.</Text>
          </Group>
        </Paper>
      ) : (
        <Stack gap={6}>
          {visible.map((a) => (
            <AlertRow
              key={a.id}
              alert={a}
              isAdmin={isAdmin}
              busy={busy === a.id}
              expanded={expanded === a.id}
              onToggle={() => setExpanded(expanded === a.id ? null : a.id)}
              onOpenDevice={() => a.device_id && router.push(`/devices/${a.device_id}`)}
              onAck={() => act(() => api.acknowledgeAlert(token!, a.id), a.id)}
              onResolve={() => act(() => api.resolveAlert(token!, a.id), a.id)}
              onApprove={(key) =>
                act(async () => {
                  const r = await api.approveRemediation(token!, a.id, key);
                  notifications.show({ color: "teal", message: r.outcome });
                }, a.id)
              }
              onAction={(key) => act(() => api.alertAction(token!, a.id, key), a.id)}
            />
          ))}
        </Stack>
      )}
    </Stack>
  );
}

function AlertRow({
  alert,
  isAdmin,
  busy,
  expanded,
  onToggle,
  onOpenDevice,
  onAck,
  onResolve,
  onApprove,
  onAction,
}: {
  alert: DispatcherAlert;
  isAdmin: boolean;
  busy: boolean;
  expanded: boolean;
  onToggle: () => void;
  onOpenDevice: () => void;
  onAck: () => void;
  onResolve: () => void;
  onApprove: (actionKey: string) => void;
  onAction: (actionKey: string) => void;
}) {
  const detail = alert.detail || {};
  const pending = (detail.pending_approvals as { action_key: string; command: string }[]) || [];
  const remediations = (detail.remediations as { action: string; at: string; outcome: string; dry_run?: boolean }[]) || [];
  const color = SEVERITY_COLOR[alert.severity] ?? "gray";
  // ATC alerts carry typed actions in detail: an in-setup release, or a set of
  // manual_gate decision options (each resumes the run down its edge).
  const kind = detail.kind as string | undefined;
  const gateOptions = (detail.options as { label: string; edge: string }[]) || [];

  return (
    <Card withBorder radius="md" p="sm" style={{ borderLeft: `4px solid var(--mantine-color-${color}-6)` }}>
      <Group justify="space-between" wrap="nowrap">
        <Group gap="sm" wrap="nowrap" style={{ minWidth: 0 }}>
          <ActionIcon variant="subtle" color="gray" onClick={onToggle}>
            <IconChevronRight
              size={16}
              style={{ transform: expanded ? "rotate(90deg)" : "none", transition: "transform 120ms" }}
            />
          </ActionIcon>
          <Badge color={color} variant="filled" tt="uppercase">
            {alert.severity}
          </Badge>
          <Box style={{ minWidth: 0 }}>
            <Text fw={600} fz="sm" truncate>
              {alert.summary}
            </Text>
            <Group gap={6}>
              <Text fz="xs" c="dimmed">
                {alert.rule_id}
              </Text>
              {alert.device && (
                <Text
                  fz="xs"
                  c="blue"
                  style={{ cursor: "pointer" }}
                  onClick={onOpenDevice}
                >
                  {alert.device.display_name || alert.device.serial_number}
                </Text>
              )}
              <Badge size="xs" variant="light" color={alert.status === "open" ? color : "gray"}>
                {alert.status}
              </Badge>
              {pending.length > 0 && (
                <Badge size="xs" variant="outline" color="orange">
                  approval required
                </Badge>
              )}
            </Group>
          </Box>
        </Group>
        {alert.status !== "resolved" && (
          <Group gap={4} wrap="nowrap">
            {kind === "atc_in_setup" && (
              <Button size="compact-xs" variant="light" color="green" loading={busy} onClick={() => onAction("release")}>
                Release from setup
              </Button>
            )}
            {kind === "atc_gate" &&
              gateOptions.map((o) => (
                <Button
                  key={o.edge}
                  size="compact-xs"
                  variant="light"
                  color={o.edge === "on_release" ? "green" : o.edge === "on_cancel" ? "red" : "blue"}
                  loading={busy}
                  onClick={() => onAction(o.edge)}
                >
                  {o.label}
                </Button>
              ))}
            {alert.status !== "acknowledged" && (
              <Tooltip label="Acknowledge">
                <ActionIcon variant="light" color="blue" loading={busy} onClick={onAck}>
                  <IconCheck size={16} />
                </ActionIcon>
              </Tooltip>
            )}
            <Button size="compact-xs" variant="light" color="teal" loading={busy} onClick={onResolve}>
              Resolve
            </Button>
          </Group>
        )}
      </Group>

      <Collapse in={expanded}>
        <Stack gap="xs" mt="sm" pl={40}>
          {pending.length > 0 && (
            <Paper withBorder p="xs" radius="sm" bg="var(--mantine-color-orange-light)">
              <Text fz="xs" fw={700} mb={4}>
                Pending admin approval (destructive)
              </Text>
              {pending.map((pa) => (
                <Group key={pa.action_key} justify="space-between" mb={4}>
                  <Text fz="xs">
                    <Code>{pa.command}</Code> — never runs until approved
                  </Text>
                  {isAdmin ? (
                    <Button size="compact-xs" color="red" loading={busy} onClick={() => onApprove(pa.action_key)}>
                      Approve &amp; run
                    </Button>
                  ) : (
                    <Text fz="xs" c="dimmed">
                      admin only
                    </Text>
                  )}
                </Group>
              ))}
            </Paper>
          )}
          {remediations.length > 0 && (
            <Box>
              <Text fz="xs" fw={700} mb={2}>
                Remediation ledger
              </Text>
              <ScrollArea.Autosize mah={160}>
                {remediations.slice().reverse().map((r, i) => (
                  <Text key={i} fz="xs" c="dimmed">
                    {r.at ? new Date(r.at).toLocaleString() : ""} · {r.action}
                    {r.dry_run ? " (dry-run)" : ""} → {r.outcome}
                  </Text>
                ))}
              </ScrollArea.Autosize>
            </Box>
          )}
          {detail.check ? (
            <Box>
              <Text fz="xs" fw={700} mb={2}>
                Failing state
              </Text>
              <Code block fz={10}>
                {JSON.stringify(detail.check, null, 2)}
              </Code>
            </Box>
          ) : null}
        </Stack>
      </Collapse>
    </Card>
  );
}
