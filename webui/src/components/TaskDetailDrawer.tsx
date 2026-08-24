"use client";

// Task detail drawer shared by the Tasks page and the device detail page.

import {Badge, Button, Code, Divider, Drawer, Group, Progress, Stack, Text,} from "@mantine/core";
import {IconRotateClockwise, IconX} from "@tabler/icons-react";
import Link from "next/link";
import type {Task} from "../../lib/api";
import {TASK_STATUS_COLORS} from "../../lib/status-labels";
import {describeTaskType} from "../../lib/task-errors";
import {TaskErrorPanel} from "./TaskErrorPanel";

// The server describes command tasks as "<type slug> on <serial>", which puts raw slugs like rotate_filevault_key in
// task titles. Swap the slug for the display name the rest of the UI uses; any other description passes through.
export function taskTitle(t: Task): string {
    const prefix = `${t.type} on `;
    return t.description.startsWith(prefix)
        ? `${describeTaskType(t.type)}${t.description.slice(t.type.length)}`
        : t.description;
}

function fmt(iso: string | null | undefined) {
    if (!iso) return "--";
    return new Date(iso).toLocaleString();
}

function Row({label, children}: { label: string; children: React.ReactNode }) {
    return (
        <Group justify="space-between" wrap="nowrap" gap="lg">
            <Text fz="sm" c="dimmed" style={{whiteSpace: "nowrap"}}>{label}</Text>
            <div style={{textAlign: "right", minWidth: 0}}>{children}</div>
        </Group>
    );
}

export function TaskDetailDrawer({
                                     task,
                                     opened,
                                     onClose,
                                     onCancel,
                                     cancelling,
                                     onRetry,
                                     retrying,
                                 }: {
    task: Task | null;
    opened: boolean;
    onClose: () => void;
    onCancel?: (id: string) => void;
    cancelling?: boolean;
    onRetry?: (id: string) => void;
    retrying?: boolean;
}) {
    if (!task) return null;

    const detailsJson = JSON.stringify(task.details ?? {}, null, 2);
    const commandUuid = (task.details as Record<string, unknown> | undefined)?.command_uuid;
    const cancellable = task.status === "pending" || task.status === "running";
    const retryable = task.status === "failed" || task.status === "cancelled";

    return (
        <Drawer
            opened={opened}
            onClose={onClose}
            position="right"
            size="md"
            title={<Text fw={600}>Task details</Text>}
        >
            <Stack gap="sm">
                <Text fz="sm" fw={600}>{taskTitle(task)}</Text>

                <Row label="Status">
                    <Badge color={TASK_STATUS_COLORS[task.status] ?? "gray"} variant="light">
                        {task.status}
                    </Badge>
                </Row>
                {task.status === "running" && (
                    <Progress value={task.progress} size="sm"/>
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
                              style={{fontFamily: "monospace"}}>
                            {task.device_id.slice(0, 8)}…
                        </Text>
                    </Row>
                ) : null}
                {task.user && <Row label="Initiated by"><Text fz="sm">{task.user}</Text></Row>}
                {typeof commandUuid === "string" && (
                    <Row label="Command UUID">
                        <Text fz="xs" style={{fontFamily: "monospace"}}>{commandUuid}</Text>
                    </Row>
                )}

                <Divider my={4}/>
                <Row label="Created"><Text fz="sm">{fmt(task.created_at)}</Text></Row>
                <Row label="Started"><Text fz="sm">{fmt(task.started_at)}</Text></Row>
                <Row label="Completed"><Text fz="sm">{fmt(task.completed_at)}</Text></Row>

                {/* Explained rather than verbatim; the raw text stays under "Technical details" in the panel. */}
                <TaskErrorPanel error={task.error}/>

                {detailsJson !== "{}" && (
                    <>
                        <Divider my={4} label="Details" labelPosition="left"/>
                        <Code block style={{maxHeight: 320, overflow: "auto", fontSize: 12}}>
                            {detailsJson}
                        </Code>
                    </>
                )}

                {((cancellable && onCancel) || (retryable && onRetry)) && (
                    <Group mt="sm">
                        {cancellable && onCancel && (
                            <Button
                                color="red"
                                variant="light"
                                leftSection={<IconX size={14}/>}
                                loading={cancelling}
                                onClick={() => onCancel(task.id)}
                            >
                                Cancel task
                            </Button>
                        )}
                        {retryable && onRetry && (
                            <Button
                                color="blue"
                                variant="light"
                                leftSection={<IconRotateClockwise size={14}/>}
                                loading={retrying}
                                onClick={() => onRetry(task.id)}
                            >
                                Retry task
                            </Button>
                        )}
                    </Group>
                )}
            </Stack>
        </Drawer>
    );
}
