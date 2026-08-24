"use client";

import {useCallback, useEffect, useRef, useState} from "react";
import Link from "next/link";
import {useRouter} from "next/navigation";
import {
    Anchor,
    Badge,
    Button,
    Chip,
    Group,
    Pagination,
    Paper,
    Select,
    Stack,
    Table,
    Text,
    Tooltip,
    UnstyledButton,
} from "@mantine/core";
import {notifications} from "@mantine/notifications";
import {IconRefresh} from "@tabler/icons-react";
import {api, type FlowRunCounts, type FlowRunRow} from "../../../../../lib/api";
import {clickable} from "../../../../../lib/a11y";
import {useAuth} from "../../../../../lib/auth-context";
import {timeSince, timeUntil} from "../../../../../lib/time";
import {FLOW_RUN_STATUS_COLORS as STATUS_COLOR} from "../../../../../lib/status-labels";
import {PageHeader} from "@/components/layout/PageHeader";
import {PageSkeleton} from "@/components/layout/PageSkeleton";

const PAGE_SIZE = 25;
const POLL_MS = 15_000;

const ANY = "any";
const GATE = "gate";

// Default filter: failed and waiting runs. Every other status comes from the status select.
const DEFAULT_STATUS = "failed,waiting";

const STATUS_OPTIONS = [
    {value: DEFAULT_STATUS, label: "Failed or waiting"},
    {value: "failed", label: "Failed"},
    {value: "waiting", label: "Waiting"},
    {value: GATE, label: "Waiting on a person"},
    {value: "running", label: "Running"},
    {value: "completed", label: "Completed"},
    {value: "cancelled", label: "Cancelled"},
    {value: ANY, label: "Any status"},
];

const EVENT_OPTIONS = [
    {value: "enroll_dep", label: "Enrolled through ADE"},
    {value: "enroll_profile", label: "Enrolled by profile"},
    {value: "checkin", label: "Checked in"},
    {value: "schedule", label: "On a schedule"},
];

const PARKED_OPTIONS = [
    {value: "15", label: "Silent over 15m"},
    {value: "60", label: "Silent over an hour"},
    {value: "240", label: "Silent over 4h"},
    {value: "1440", label: "Silent over a day"},
];

const WINDOW_OPTIONS = [
    {value: "1", label: "Started in the last hour"},
    {value: "24", label: "Started in the last 24h"},
    {value: "168", label: "Started in the last 7 days"},
];

function StatCard({
                      label,
                      value,
                      color,
                      active,
                      hint,
                      onClick,
                  }: {
    label: string;
    value: number;
    color: string;
    active: boolean;
    hint?: string;
    onClick: () => void;
}) {
    const card = (
        <UnstyledButton onClick={onClick} style={{flex: "1 1 130px", minWidth: 130}}>
            <Paper
                withBorder
                p="sm"
                style={{
                    borderColor: active ? `var(--mantine-color-${color}-6)` : undefined,
                    background: active ? `var(--mantine-color-${color}-light)` : undefined,
                }}
            >
                <Text fz={26} fw={700} lh={1.1} c={value > 0 ? color : "dimmed"}>
                    {value}
                </Text>
                <Text fz="xs" c="dimmed" mt={4}>
                    {label}
                </Text>
            </Paper>
        </UnstyledButton>
    );
    return hint ? (
        <Tooltip label={hint} multiline w={260} withArrow>
            {card}
        </Tooltip>
    ) : (
        card
    );
}

function StateCell({run}: { run: FlowRunRow }) {
    const onGate = run.status === "waiting" && run.waiting_signal === "manual";
    return (
        <>
            <Badge size="sm" variant="light" color={STATUS_COLOR[run.status] ?? "gray"}>
                {run.status}
            </Badge>
            {onGate && (
                <Text fz="xs" c="dimmed" mt={4}>
                    needs a decision
                </Text>
            )}
            {run.status === "waiting" && !onGate && run.waiting_signal && (
                <Text fz="xs" c="dimmed" mt={4}>
                    waiting for {run.waiting_signal}
                </Text>
            )}
        </>
    );
}

function AgeCell({run}: { run: FlowRunRow }) {
    if (run.status === "waiting") {
        const onGate = run.waiting_signal === "manual";
        const left = timeUntil(run.wait_deadline);
        return (
            <>
                <Text fz="xs">parked {timeSince(run.updated_at)}</Text>
                <Text fz="xs" c={onGate || !left ? "orange" : "dimmed"}>
                    {onGate
                        ? "no timeout, a person has to answer"
                        : left
                            ? `times out in ${left}`
                            : "past its timeout"}
                </Text>
            </>
        );
    }
    if (run.status === "running") {
        return <Text fz="xs">started {timeSince(run.started_at)}</Text>;
    }
    return (
        <Text fz="xs">
            {run.status === "completed" ? "finished" : "ended"}{" "}
            {timeSince(run.completed_at ?? run.updated_at)}
        </Text>
    );
}

function OutcomeCell({run}: { run: FlowRunRow }) {
    const short = run.error ? run.error.slice(0, 70) + (run.error.length > 70 ? "…" : "") : null;
    if (!short && !run.gap_count) {
        return (
            <Text fz="xs" c="dimmed">
                --
            </Text>
        );
    }
    return (
        <Stack gap={4}>
            {run.released_unverified && (
                <Badge size="sm" color="red" variant="filled">
                    released unverified
                </Badge>
            )}
            {short && (
                <Tooltip label={run.error} multiline w={380}>
                    <Text fz="xs" c="red" style={{cursor: "help"}}>
                        {short}
                    </Text>
                </Tooltip>
            )}
            {!short && run.gap_count > 0 && (
                <Badge size="sm" variant="light" color={run.gap_grade === "broken" ? "orange" : "gray"}>
                    {run.gap_count} gap{run.gap_count === 1 ? "" : "s"}
                </Badge>
            )}
        </Stack>
    );
}

const EMPTY_COUNTS: FlowRunCounts = {
    all: 0,
    running: 0,
    waiting: 0,
    completed: 0,
    failed: 0,
    cancelled: 0,
    on_gate: 0,
    released_unverified: 0,
};

export default function FlowRunsPage() {
    const {token} = useAuth();
    const router = useRouter();

    const [runs, setRuns] = useState<FlowRunRow[]>([]);
    const [total, setTotal] = useState(0);
    const [counts, setCounts] = useState<FlowRunCounts>(EMPTY_COUNTS);
    const [flowIds, setFlowIds] = useState<string[]>([]);
    const [retentionDays, setRetentionDays] = useState<number | null>(null);
    const [scanCapped, setScanCapped] = useState(false);
    const [loading, setLoading] = useState(true);
    const [page, setPage] = useState(1);

    const [status, setStatus] = useState<string>(DEFAULT_STATUS);
    const [flow, setFlow] = useState<string | null>(null);
    const [eventKind, setEventKind] = useState<string | null>(null);
    const [parkedMins, setParkedMins] = useState<string | null>(null);
    const [windowHours, setWindowHours] = useState<string | null>(null);
    const [unverified, setUnverified] = useState(false);

    // Last request wins: changing a filter mid-request would otherwise leave the previous rows under the new label.
    const reqSeq = useRef(0);
    const foregroundPending = useRef(false);

    const load = useCallback(
        async (background = false) => {
            if (!token) return;
            if (background && foregroundPending.current) return;
            const seq = ++reqSeq.current;
            if (!background) {
                foregroundPending.current = true;
                setLoading(true);
            }
            try {
                const state =
                    status === GATE
                        ? {status: "waiting", waiting_signal: "manual"}
                        : status === ANY
                            ? {}
                            : {status};
                const res = await api.listFlowRuns(token, {
                    skip: (page - 1) * PAGE_SIZE,
                    limit: PAGE_SIZE,
                    ...state,
                    ...(flow ? {flow} : {}),
                    ...(eventKind ? {event_kind: eventKind} : {}),
                    ...(unverified ? {released_unverified: true} : {}),
                    // Both windows are relative to the moment of the request, so they are computed here rather
                    // than held in state, where they would go stale.
                    ...(parkedMins
                        ? {
                            parked_before: new Date(
                                Date.now() - Number(parkedMins) * 60_000,
                            ).toISOString(),
                        }
                        : {}),
                    ...(windowHours
                        ? {
                            since: new Date(
                                Date.now() - Number(windowHours) * 3_600_000,
                            ).toISOString(),
                        }
                        : {}),
                });
                if (seq !== reqSeq.current) return;
                setRuns(res.flow_runs);
                setTotal(res.total);
                setCounts(res.counts);
                setFlowIds(res.flow_ids);
                setRetentionDays(res.retention_days);
                setScanCapped(res.scan_capped);
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
        },
        [token, page, status, flow, eventKind, parkedMins, windowHours, unverified],
    );

    useEffect(() => {
        load();
    }, [load]);

    // Runs change state while the page is open, so poll quietly in the background.
    useEffect(() => {
        const id = setInterval(() => {
            if (document.visibilityState === "visible") load(true);
        }, POLL_MS);
        return () => clearInterval(id);
    }, [load]);

    // Clicking a card selects exactly the set it counted, so every narrowing filter comes off. Otherwise the count
    // on the card and the count in the table disagree.
    const select = (next: string, guard = false) => {
        setStatus(next);
        setUnverified(guard);
        setParkedMins(null);
        setPage(1);
    };
    // A card reads as selected only when it describes the whole selection.
    const on = (want: string) => status === want && !unverified && !parkedMins;

    const filtered = Boolean(
        status !== DEFAULT_STATUS || unverified || flow || eventKind || parkedMins || windowHours,
    );

    const rows = runs.map((r) => (
        <Table.Tr
            key={r.id}
            style={{cursor: "pointer"}}
            aria-label={`Open run on ${r.device?.serial_number ?? "removed device"}`}
            {...clickable(() => router.push(`/atc/runs/${r.id}`))}
        >
            <Table.Td>
                {r.device ? (
                    <>
                        <Anchor
                            component={Link}
                            href={`/devices/${r.device_id}`}
                            fz="sm"
                            fw={500}
                            onClick={(e) => e.stopPropagation()}
                        >
                            {r.device.serial_number}
                        </Anchor>
                        <Text fz="xs" c="dimmed">
                            {r.device.hostname || r.device.device_model}
                        </Text>
                    </>
                ) : (
                    <Text fz="xs" c="dimmed">
                        device removed
                    </Text>
                )}
            </Table.Td>
            <Table.Td>
                <Text fz="sm">{r.flow_id}</Text>
                {r.event_kind && (
                    <Text fz="xs" c="dimmed">
                        {EVENT_OPTIONS.find((o) => o.value === r.event_kind)?.label ?? r.event_kind}
                    </Text>
                )}
            </Table.Td>
            <Table.Td>
                <StateCell run={r}/>
            </Table.Td>
            <Table.Td>
                <Text fz="xs" style={{fontFamily: "monospace", whiteSpace: "nowrap"}}>
                    {r.current_node ?? "--"}
                </Text>
            </Table.Td>
            <Table.Td>
                <AgeCell run={r}/>
            </Table.Td>
            <Table.Td>
                <OutcomeCell run={r}/>
            </Table.Td>
        </Table.Tr>
    ));

    return (
        <Stack gap="md">
            <PageHeader
                title="Run history"
                description="Every run a flow has started on a device: what it did, where it stopped, and what is waiting on somebody."
                actions={<Button leftSection={<IconRefresh size={14}/>} variant="light"
                                 onClick={() => load()}>Refresh</Button>}
            />

            <Group gap="sm" wrap="wrap" align="stretch">
                <StatCard
                    label="Failed"
                    value={counts.failed}
                    color="red"
                    active={on("failed")}
                    onClick={() => select("failed")}
                />
                <StatCard
                    label="Released unverified"
                    value={counts.released_unverified}
                    color="red"
                    active={unverified}
                    hint="The run released the device from Setup Assistant early, skipping steps. Also counted under Failed."
                    onClick={() => select(ANY, true)}
                />
                <StatCard
                    label="Waiting on a person"
                    value={counts.on_gate}
                    color="orange"
                    active={on(GATE)}
                    hint="Parked at a manual gate until somebody answers. Also counted under Waiting."
                    onClick={() => select(GATE)}
                />
                <StatCard
                    label="Waiting"
                    value={counts.waiting}
                    color="yellow"
                    active={on("waiting")}
                    hint="Parked on a wait step, either for the device to report back or for a person to answer."
                    onClick={() => select("waiting")}
                />
                <StatCard
                    label="Running"
                    value={counts.running}
                    color="blue"
                    active={on("running")}
                    onClick={() => select("running")}
                />
                <StatCard
                    label="Finished cleanly"
                    value={counts.completed}
                    color="teal"
                    active={on("completed")}
                    onClick={() => select("completed")}
                />
            </Group>

            <Group gap="sm" wrap="wrap">
                <Select
                    data={STATUS_OPTIONS}
                    value={status}
                    onChange={(v) => {
                        setStatus(v ?? ANY);
                        setPage(1);
                    }}
                    w={190}
                    allowDeselect={false}
                    aria-label="Status"
                />
                {flowIds.length > 1 && (
                    <Select
                        placeholder="Every flow"
                        data={flowIds.map((f) => ({value: f, label: f}))}
                        value={flow}
                        onChange={(v) => {
                            setFlow(v);
                            setPage(1);
                        }}
                        clearable
                        w={190}
                        aria-label="Flow"
                    />
                )}
                <Select
                    placeholder="Any trigger"
                    data={EVENT_OPTIONS}
                    value={eventKind}
                    onChange={(v) => {
                        setEventKind(v);
                        setPage(1);
                    }}
                    clearable
                    w={190}
                    aria-label="What started the run"
                />
                <Select
                    placeholder="Parked any length of time"
                    data={PARKED_OPTIONS}
                    value={parkedMins}
                    onChange={(v) => {
                        setParkedMins(v);
                        setPage(1);
                    }}
                    clearable
                    w={210}
                    aria-label="How long a run has been parked"
                />
                <Select
                    placeholder="Any time"
                    data={WINDOW_OPTIONS}
                    value={windowHours}
                    onChange={(v) => {
                        setWindowHours(v);
                        setPage(1);
                    }}
                    clearable
                    w={210}
                    aria-label="When the run started"
                />
                <Chip
                    checked={unverified}
                    onChange={(c) => {
                        setUnverified(c);
                        if (c) setStatus(ANY);
                        setPage(1);
                    }}
                    color="red"
                    variant="outline"
                >
                    Released unverified
                </Chip>
                {filtered && (
                    <Button
                        variant="subtle"
                        size="compact-sm"
                        color="gray"
                        onClick={() => {
                            setStatus(DEFAULT_STATUS);
                            setFlow(null);
                            setEventKind(null);
                            setParkedMins(null);
                            setWindowHours(null);
                            setUnverified(false);
                            setPage(1);
                        }}
                    >
                        Reset filters
                    </Button>
                )}
                <Text fz="sm" c="dimmed">
                    {total} run{total === 1 ? "" : "s"}
                </Text>
            </Group>

            {scanCapped && (
                <Text fz="xs" c="dimmed">
                    More runs have failed than this page reads at once, so the released-unverified
                    count is a floor rather than a total. Narrow the window to get an exact number.
                </Text>
            )}

            {loading ? (
                <PageSkeleton variant="table"/>
            ) : runs.length === 0 ? (
                <Paper withBorder p="xl">
                    <Text fw={600} fz="sm" ta="center">
                        {filtered ? "No runs match these filters" : "Nothing is failed or parked"}
                    </Text>
                    <Text fz="xs" c="dimmed" ta="center" mt={4}>
                        {filtered
                            ? "Widen the window or clear a filter."
                            : "Runs that finished are under the status filter above."}
                    </Text>
                </Paper>
            ) : (
                <>
                    {/* Six columns: narrow windows scroll the table rather than the page. */}
                    <Paper withBorder style={{overflowX: "auto"}}>
                        <Table highlightOnHover verticalSpacing="sm">
                            <Table.Thead>
                                <Table.Tr>
                                    <Table.Th>Device</Table.Th>
                                    <Table.Th>Flow</Table.Th>
                                    <Table.Th>State</Table.Th>
                                    <Table.Th>Step</Table.Th>
                                    <Table.Th>For how long</Table.Th>
                                    <Table.Th>What happened</Table.Th>
                                </Table.Tr>
                            </Table.Thead>
                            <Table.Tbody>{rows}</Table.Tbody>
                        </Table>
                    </Paper>
                    {total > PAGE_SIZE && (
                        <Pagination total={Math.ceil(total / PAGE_SIZE)} value={page} onChange={setPage}/>
                    )}
                </>
            )}

            {retentionDays !== null && (
                <Text fz="xs" c="dimmed">
                    A run that has finished is deleted after {retentionDays} days. A quiet stretch
                    further back than that means its rows are gone, not that nothing ran.
                </Text>
            )}
        </Stack>
    );
}
