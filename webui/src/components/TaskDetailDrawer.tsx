"use client";

// Task detail drawer shared by the Tasks page and the device detail page.
// Shows the full lifecycle of a task (status, progress, timestamps, device,
// initiator, error) plus its details JSON (command_uuid, payload info, device
// response), which was previously fetched but never rendered anywhere.

import {
  Badge,
  Button,
  Code,
  Divider,
  Drawer,
  Group,
  Progress,
  Stack,
  Text,
  Alert,
} from "@mantine/core";
import { IconAlertTriangle, IconX } from "@tabler/icons-react";
import Link from "next/link";
import type { Task } from "../../lib/api";

export const TASK_STATUS_COLORS: Record<string, string> = {
  pending: "yellow",
  running: "blue",
  completed: "teal",
  failed: "red",
  cancelled: "gray",
};

function fmt(iso: string | null | undefined) {
  if (!iso) return "--";
  return new Date(iso).toLocaleString();
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Group justify="space-between" wrap="nowrap" gap="lg">
      <Text fz="sm" c="dimmed" style={{ whiteSpace: "nowrap" }}>{label}</Text>
      <div style={{ textAlign: "right", minWidth: 0 }}>{children}</div>
    </Group>
  );
}

export function TaskDetailDrawer({
  task,
  opened,
  onClose,
  onCancel,
  cancelling,
}: {
  task: Task | null;
  opened: boolean;
  onClose: () => void;
  onCancel?: (id: string) => void;
  cancelling?: boolean;
}) {
  if (!task) return null;

  const detailsJson = JSON.stringify(task.details ?? {}, null, 2);
  const commandUuid = (task.details as Record<string, unknown> | undefined)?.command_uuid;
  const cancellable = task.status === "pending" || task.status === "running";

  return (
    <Drawer
      opened={opened}
      onClose={onClose}
      position="right"
      size="md"
      title={<Text fw={600}>Task details</Text>}
    >
      <Stack gap="sm">
        <Text fz="sm" fw={600}>{task.description}</Text>

        <Row label="Status">
          <Badge color={TASK_STATUS_COLORS[task.status] ?? "gray"} variant="light">
            {task.status}
          </Badge>
        </Row>
        {task.status === "running" && (
          <Progress value={task.progress} size="sm" />
        )}

        <Row label="Type"><Code>{task.type}</Code></Row>
        {task.device ? (
          <Row label="Device">
            <Text fz="sm" component={Link} href={`/devices/${task.device_id}`} c="blue">
              {task.device.serial_number || task.device.hostname || task.device_id}
            </Text>
          </Row>
        ) : task.device_id ? (
          <Row label="Device">
            <Text fz="sm" component={Link} href={`/devices/${task.device_id}`} c="blue"
                  style={{ fontFamily: "monospace" }}>
              {task.device_id.slice(0, 8)}…
            </Text>
          </Row>
        ) : null}
        {task.user && <Row label="Initiated by"><Text fz="sm">{task.user}</Text></Row>}
        {typeof commandUuid === "string" && (
          <Row label="Command UUID">
            <Text fz="xs" style={{ fontFamily: "monospace" }}>{commandUuid}</Text>
          </Row>
        )}

        <Divider my={4} />
        <Row label="Created"><Text fz="sm">{fmt(task.created_at)}</Text></Row>
        <Row label="Started"><Text fz="sm">{fmt(task.started_at)}</Text></Row>
        <Row label="Completed"><Text fz="sm">{fmt(task.completed_at)}</Text></Row>

        {task.error && (
          <Alert color="red" icon={<IconAlertTriangle size={16} />} variant="light">
            <Text fz="sm" style={{ wordBreak: "break-word" }}>{task.error}</Text>
          </Alert>
        )}

        {detailsJson !== "{}" && (
          <>
            <Divider my={4} label="Details" labelPosition="left" />
            <Code block style={{ maxHeight: 320, overflow: "auto", fontSize: 12 }}>
              {detailsJson}
            </Code>
          </>
        )}

        {cancellable && onCancel && (
          <Button
            color="red"
            variant="light"
            leftSection={<IconX size={14} />}
            loading={cancelling}
            onClick={() => onCancel(task.id)}
            mt="sm"
          >
            Cancel task
          </Button>
        )}
      </Stack>
    </Drawer>
  );
}
