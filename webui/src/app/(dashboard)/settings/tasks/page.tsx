"use client";

import {Suspense, useCallback, useEffect, useRef, useState} from "react";
import {useRouter, useSearchParams} from "next/navigation";
import {
    ActionIcon,
    Badge,
    Button,
    Group,
    Pagination,
    Paper,
    Progress,
    Select,
    Stack,
    Table,
    Text,
    TextInput,
    Tooltip,
} from "@mantine/core";
import {useDebouncedValue} from "@mantine/hooks";
import {notifications} from "@mantine/notifications";
import {IconRefresh, IconRotateClockwise, IconX} from "@tabler/icons-react";
import {api, type Task} from "../../../../../lib/api";
import {clickable} from "../../../../../lib/a11y";
import {useAuth} from "../../../../../lib/auth-context";
import {TaskDetailDrawer, taskTitle} from "@/components/TaskDetailDrawer";
import {explainError} from "../../../../../lib/task-errors";
import {TASK_STATUS_COLORS} from "../../../../../lib/status-labels";
import {PageSkeleton} from "@/components/layout/PageSkeleton";
import {PageHeader} from "@/components/layout/PageHeader";

const PAGE_SIZE = 25;
const POLL_MS = 10_000;

const STATUSES = ["pending", "running", "completed", "failed", "cancelled"];

// Keeps the table layout from squeezing a status badge down to "COMPL...".
const NO_TRUNCATE_BADGE_STYLES = {root: {overflow: "visible" as const}, label: {overflow: "visible" as const}};

function fmt(iso: string | null) {
    if (!iso) return "--";
    return new Date(iso).toLocaleString();
}

export default function TasksPage() {
    return (
        // useSearchParams requires a Suspense boundary during prerender.
        <Suspense fallback={null}>
            <TasksPageInner/>
        </Suspense>
    );
}

function TasksPageInner() {
    const {token} = useAuth();
    const router = useRouter();
    const searchParams = useSearchParams();
    const [tasks, setTasks] = useState<Task[]>([]);
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const [statusFilter, setStatus] = useState<string | null>(null);
    const [userFilter, setUserFilter] = useState("");
    // Set from the device_id query param. deviceLabel shows a serial number once a matching row loads, and the raw
    // id until then.
    const [deviceIdFilter, setDeviceIdFilter] = useState<string | null>(null);
    const [deviceLabel, setDeviceLabel] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [cancelling, setCancelling] = useState<string | null>(null);
    const [retrying, setRetrying] = useState<string | null>(null);
    const [syncing, setSyncing] = useState(false);
    const [selected, setSelected] = useState<Task | null>(null);
    // Last request wins: dropping a load because another was still pending would leave the previous filter's rows
    // on screen.
    const reqSeq = useRef(0);
    const foregroundPending = useRef(false);
    const [debouncedUser] = useDebouncedValue(userFilter, 300);

    // Re-read on every query change, so a device link still filters when this page is already open.
    useEffect(() => {
        const fromUrl = searchParams.get("device_id");
        setDeviceIdFilter(fromUrl);
        setDeviceLabel(null);
        setPage(1);
    }, [searchParams]);

    const clearDeviceFilter = () => {
        setDeviceIdFilter(null);
        setDeviceLabel(null);
        setPage(1);
        router.replace("/settings/tasks");
    };

    const load = useCallback(async (background = false) => {
        if (!token) return;
        // A quiet poll never competes with an interactive load.
        if (background && foregroundPending.current) return;
        const seq = ++reqSeq.current;
        if (!background) {
            foregroundPending.current = true;
            setLoading(true);
        }
        try {
            const res = await api.listTasks(token, {
                skip: (page - 1) * PAGE_SIZE,
                limit: PAGE_SIZE,
                ...(statusFilter ? {status: statusFilter} : {}),
                ...(debouncedUser ? {user: debouncedUser} : {}),
                ...(deviceIdFilter ? {device_id: deviceIdFilter} : {}),
            });
            if (seq !== reqSeq.current) return; // superseded by a newer request
            setTasks(res.tasks);
            setTotal(res.total);
            // Keep the open drawer in sync with fresh data.
            setSelected((cur) => (cur ? res.tasks.find((t) => t.id === cur.id) ?? cur : cur));
            // Every task under a device filter carries the same device, so the first row is enough to name it.
            if (deviceIdFilter) {
                const named = res.tasks.find((t) => t.device?.serial_number)?.device?.serial_number;
                if (named) setDeviceLabel(named);
            }
        } catch (e: unknown) {
            if (!background && seq === reqSeq.current) {
                notifications.show({color: "red", message: (e as Error).message});
            }
        } finally {
            if (!background) {
                foregroundPending.current = false;
                if (seq === reqSeq.current) setLoading(false);
            }
        }
    }, [token, page, statusFilter, debouncedUser, deviceIdFilter]);

    useEffect(() => {
        load();
    }, [load]);

    // Task statuses move as devices answer, so poll quietly instead of leaving stale "running" rows on screen.
    useEffect(() => {
        const id = setInterval(() => {
            if (document.visibilityState === "visible") load(true);
        }, POLL_MS);
        return () => clearInterval(id);
    }, [load]);

    const handleCancel = async (id: string) => {
        if (!token) return;
        setCancelling(id);
        try {
            const res = await api.cancelTask(token, id);
            notifications.show({color: "teal", message: res.message});
        } catch (e: unknown) {
            notifications.show({color: "red", message: (e as Error).message});
        } finally {
            setCancelling(null);
            // Refresh after a refusal too: "already failed, cannot be cancelled" means this row is out of date.
            load(true);
        }
    };

    const handleRetry = async (id: string) => {
        if (!token) return;
        setRetrying(id);
        try {
            const res = await api.retryTask(token, id);
            notifications.show({color: "teal", message: res.message});
            setSelected(null); // close the drawer if the retried task was open
        } catch (e: unknown) {
            notifications.show({color: "red", message: (e as Error).message});
        } finally {
            setRetrying(null);
            load(true);
        }
    };

    const handleSyncNow = async () => {
        if (!token) return;
        setSyncing(true);
        try {
            const res = await api.syncNow(token);
            const queued = res.profiles_queued + res.removals_queued + res.apps_queued;
            notifications.show({
                color: "teal",
                title: "Sync complete",
                message: queued
                    ? `${res.profiles_queued} profile install(s), ${res.removals_queued} removal(s), ${res.apps_queued} app install(s) queued across ${res.devices} device(s)`
                    : `Everything already matches the declared state (${res.devices} device(s) checked)`,
            });
            load(true);
        } catch (e: unknown) {
            notifications.show({color: "red", message: (e as Error).message});
        } finally {
            setSyncing(false);
        }
    };

    const rows = tasks.map((t) => {
        const errorSummary = explainError(t.error)?.headline ?? null;
        return (
            <Table.Tr
                key={t.id}
                style={{cursor: "pointer"}}
                aria-label={`Open task ${taskTitle(t)}`}
                {...clickable(() => setSelected(t))}
            >
                <Table.Td>
                    <Text fz="sm" fw={500}>{taskTitle(t)}</Text>
                    <Text fz="xs" c="dimmed">{t.type}</Text>
                </Table.Td>
                <Table.Td>
                    <Badge
                        size="sm"
                        color={TASK_STATUS_COLORS[t.status] ?? "gray"}
                        variant="light"
                        styles={NO_TRUNCATE_BADGE_STYLES}
                    >
                        {t.status}
                    </Badge>
                    {t.status === "running" && (
                        <Progress value={t.progress} size="xs" mt={4} w={80}/>
                    )}
                </Table.Td>
                <Table.Td>
                    {t.device?.serial_number ? (
                        <Text fz="xs">{t.device.serial_number}</Text>
                    ) : (
                        <Text fz="xs" c="dimmed" style={{fontFamily: "monospace"}}>
                            {t.device_id ? t.device_id.slice(0, 8) + "…" : "--"}
                        </Text>
                    )}
                </Table.Td>
                <Table.Td><Text fz="xs">{fmt(t.created_at)}</Text></Table.Td>
                <Table.Td>
                    {/* The plain cause only; the raw text stays in the task drawer under "Technical details". */}
                    {errorSummary ? (
                        <Tooltip label={errorSummary} multiline w={300}>
                            <Text fz="xs" c="red" style={{cursor: "help"}}>
                                {errorSummary.slice(0, 40)}{errorSummary.length > 40 ? "…" : ""}
                            </Text>
                        </Tooltip>
                    ) : (
                        <Text fz="xs" c="dimmed">--</Text>
                    )}
                </Table.Td>
                <Table.Td onClick={(e) => e.stopPropagation()}>
                    <Group gap={4} wrap="nowrap" justify="flex-end">
                        {(t.status === "pending" || t.status === "running") && (
                            <Tooltip label="Cancel task">
                                <ActionIcon
                                    variant="subtle"
                                    color="red"
                                    size="sm"
                                    loading={cancelling === t.id}
                                    onClick={() => handleCancel(t.id)}
                                >
                                    <IconX size={14}/>
                                </ActionIcon>
                            </Tooltip>
                        )}
                        {(t.status === "failed" || t.status === "cancelled") && (
                            <Tooltip label="Retry task">
                                <ActionIcon
                                    variant="subtle"
                                    color="blue"
                                    size="sm"
                                    loading={retrying === t.id}
                                    onClick={() => handleRetry(t.id)}
                                >
                                    <IconRotateClockwise size={14}/>
                                </ActionIcon>
                            </Tooltip>
                        )}
                    </Group>
                </Table.Td>
            </Table.Tr>
        );
    });

    return (
        <Stack gap="lg">
            <PageHeader
                actions={<>
                    <Tooltip label="Reconcile the declared YAML state against all devices now">
                        <Button
                            leftSection={<IconRotateClockwise size={14}/>}
                            variant="light"
                            color="teal"
                            loading={syncing}
                            onClick={handleSyncNow}
                        >
                            Sync now
                        </Button>
                    </Tooltip>
                    <Button leftSection={<IconRefresh size={14}/>} variant="light" onClick={() => load()}>
                        Refresh
                    </Button>
                </>}
            />

            <Group gap="sm">
                <Select
                    placeholder="All statuses"
                    data={STATUSES.map((s) => ({value: s, label: s.charAt(0).toUpperCase() + s.slice(1)}))}
                    value={statusFilter}
                    onChange={(v) => {
                        setStatus(v);
                        setPage(1);
                    }}
                    clearable
                    w={180}
                />
                <TextInput
                    placeholder="Filter by user (email)"
                    value={userFilter}
                    onChange={(e) => {
                        setUserFilter(e.currentTarget.value);
                        setPage(1);
                    }}
                    w={220}
                />
                {deviceIdFilter && (
                    <Badge
                        variant="light"
                        color="blue"
                        size="lg"
                        rightSection={
                            <ActionIcon size="xs" variant="transparent" color="blue" onClick={clearDeviceFilter}>
                                <IconX size={12}/>
                            </ActionIcon>
                        }
                    >
                        Device: {deviceLabel ?? `${deviceIdFilter.slice(0, 8)}…`}
                    </Badge>
                )}
                <Text fz="sm" c="dimmed">{total} total</Text>
            </Group>

            {loading ? (
                <PageSkeleton variant="table"/>
            ) : tasks.length === 0 ? (
                <Text c="dimmed" ta="center" py="xl">
                    {deviceIdFilter ? "No tasks found for this device." : "No tasks found."}
                </Text>
            ) : (
                <>
                    <Paper withBorder style={{overflowX: "auto"}}>
                        <Table highlightOnHover verticalSpacing="sm">
                            <Table.Thead>
                                <Table.Tr>
                                    <Table.Th>Description</Table.Th>
                                    <Table.Th>Status</Table.Th>
                                    <Table.Th>Device</Table.Th>
                                    <Table.Th>Created</Table.Th>
                                    <Table.Th>Error</Table.Th>
                                    <Table.Th/>
                                </Table.Tr>
                            </Table.Thead>
                            <Table.Tbody>{rows}</Table.Tbody>
                        </Table>
                    </Paper>

                    {total > PAGE_SIZE && (
                        <Pagination
                            total={Math.ceil(total / PAGE_SIZE)}
                            value={page}
                            onChange={setPage}
                        />
                    )}
                </>
            )}

            <TaskDetailDrawer
                task={selected}
                opened={selected !== null}
                onClose={() => setSelected(null)}
                onCancel={handleCancel}
                cancelling={cancelling !== null}
                onRetry={handleRetry}
                retrying={retrying !== null}
            />
        </Stack>
    );
}
