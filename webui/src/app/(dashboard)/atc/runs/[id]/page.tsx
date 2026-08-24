"use client";

import {useCallback, useEffect, useMemo, useRef, useState} from "react";
import {useParams, useRouter} from "next/navigation";
import {Background, Controls, type Edge, MiniMap, ReactFlow, ReactFlowProvider,} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
    Alert,
    Badge,
    Button,
    Group,
    Loader,
    Paper,
    ScrollArea,
    Stack,
    Text,
    Timeline,
    Title,
    useComputedColorScheme,
} from "@mantine/core";
import {modals} from "@mantine/modals";
import {notifications} from "@mantine/notifications";
import {IconArrowLeft, IconSitemap} from "@tabler/icons-react";
import {api, ApiError, type FlowNodeSpec, type FlowRunDetail, resumeFlowRun,} from "../../../../../../lib/api";
import {useAuth} from "../../../../../../lib/auth-context";
import {FLOW_RUN_STATUS_COLORS as STATUS_COLOR} from "../../../../../../lib/status-labels";
import {FlowNodeCard, MINIMAP_MASK} from "@/components/atc/FlowEditor";
import {flowToGraph, type RFNode} from "@/components/atc/flow-utils";

const nodeTypes = {atc: FlowNodeCard};

const TERMINAL_STATUSES = new Set(["completed", "failed", "cancelled"]);

// Whether the graph below is the definition that ran. A run pins its own copy while it is still going and drops it
// when it finishes, after which the server falls back to the current flows.yaml. If that has been edited, the path
// drawn from run.visited sits over a different document: renamed steps do not light up, later additions look skipped.
const FLOW_SOURCE_BADGE: Record<string, { label: string; color: string }> = {
    current: {label: "flow unchanged since this run", color: "gray"},
    edited: {label: "flow edited since this run", color: "orange"},
};

export default function FlowRunViewer() {
    const {token} = useAuth();
    const router = useRouter();
    const params = useParams();
    const scheme = useComputedColorScheme("light");
    const id = String(params.id);
    const [run, setRun] = useState<FlowRunDetail | null>(null);
    const [catalog, setCatalog] = useState<FlowNodeSpec[]>([]);
    const [loading, setLoading] = useState(true);
    const [gone, setGone] = useState(false);
    // Mirrors run.status without being a dependency: the polling interval reads this instead of closing over run, so
    // a status update neither recreates the interval nor is read stale.
    const statusRef = useRef<string | undefined>(undefined);
    useEffect(() => {
        statusRef.current = run?.status;
    }, [run?.status]);

    useEffect(() => {
        if (!token) return;
        api.getFlowStepCatalog(token).then((c) => setCatalog(c.nodes)).catch(() => {
        });
    }, [token]);

    const refresh = useCallback(async () => {
        if (!token) return;
        try {
            const r = await api.getFlowRun(token, id);
            setRun(r);
            setGone(false);
        } catch (e) {
            // Runs are deleted once they pass the retention window, so a saved link can outlive the run.
            if (e instanceof ApiError && e.status === 404) setGone(true);
        } finally {
            setLoading(false);
        }
    }, [token, id]);

    useEffect(() => {
        if (!token) return;
        refresh();
        // Poll every 5s until the run reaches a terminal state, then stop.
        const t = setInterval(() => {
            if (statusRef.current && TERMINAL_STATUSES.has(statusRef.current)) {
                clearInterval(t);
                return;
            }
            refresh();
        }, 5000);
        return () => clearInterval(t);
    }, [token, refresh]);

    const graph = useMemo(() => {
        if (!run?.flow) return {nodes: [] as RFNode[], edges: [] as Edge[]};
        const g = flowToGraph(run.flow, catalog);
        const visited = new Set(run.visited ?? []);
        const nodes = g.nodes.map((n) => ({
            ...n,
            draggable: false,
            connectable: false,
            selectable: false,
            data: {
                ...n.data,
                highlight:
                    n.id === run.current_node ? "current" : visited.has(n.id) ? "visited" : undefined,
                dim: !(n.id === run.current_node || visited.has(n.id)),
            },
        }));
        return {nodes, edges: g.edges};
    }, [run, catalog]);

    // Only "current" and "edited" get a badge. "pinned" is the ordinary case and
    // needs no label; "unavailable" replaces the canvas outright below.
    const sourceBadge = run?.flow_source ? FLOW_SOURCE_BADGE[run.flow_source] : undefined;

    // Choices for a run parked on a manual gate, read from the run's own pinned copy of the flow, which is the
    // document the server validates the chosen edge against.
    const gateOptions = useMemo(() => {
        if (!run || run.status !== "waiting" || run.waiting_signal !== "manual") return [];
        const node = run.flow?.nodes?.find((n) => n.id === run.current_node);
        const opts = (node?.params?.options as { label?: string; edge?: string }[] | undefined) ?? [];
        return opts.filter((o): o is { label: string; edge: string } => !!o.label && !!o.edge);
    }, [run]);

    const [resuming, setResuming] = useState<string | null>(null);

    const confirmResume = (opt: { label: string; edge: string }) =>
        modals.openConfirmModal({
            title: "Resume this run",
            children: (
                <Text size="sm">
                    Continue down <b>{opt.label}</b>. The run carries on from{" "}
                    <b>{run?.current_node ?? "the gate"}</b> and acts on the device from there.
                </Text>
            ),
            labels: {confirm: opt.label, cancel: "Cancel"},
            onConfirm: async () => {
                if (!token) return;
                setResuming(opt.edge);
                try {
                    await resumeFlowRun(token, id, opt.edge);
                    notifications.show({color: "teal", message: `Resumed: ${opt.label}`});
                    await refresh();
                } catch (e) {
                    notifications.show({color: "red", message: (e as Error).message});
                } finally {
                    setResuming(null);
                }
            },
        });

    if (loading) return <Loader/>;
    if (!run && gone)
        return (
            <Stack gap="sm" align="flex-start">
                <Button
                    variant="subtle"
                    size="compact-sm"
                    leftSection={<IconArrowLeft size={14}/>}
                    onClick={() => router.back()}
                >
                    Back
                </Button>
                <Alert color="yellow" title="This run is no longer stored">
                    <Text fz="sm">
                        Finished runs are deleted once they pass the retention window, and a device&apos;s
                        runs go with the device when it is removed, so a saved link can outlive the run. The
                        alert that linked here keeps its own record of what failed.
                    </Text>
                </Alert>
            </Stack>
        );
    if (!run) return <Alert color="red">This run could not be loaded. Try again.</Alert>;

    return (
        <Stack gap="md">
            <Group justify="space-between" align="flex-start">
                <div>
                    <Button
                        variant="subtle"
                        size="compact-sm"
                        leftSection={<IconArrowLeft size={14}/>}
                        onClick={() => router.back()}
                        mb={4}
                    >
                        Back
                    </Button>
                    <Title order={3}>
                        <Group gap={8}>
                            <IconSitemap size={22}/> {run.flow_id}
                        </Group>
                    </Title>
                </div>
                <Group gap={8}>
                    {run.event_kind && (
                        <Badge size="lg" variant="light" color="grape">
                            {run.event_kind}
                        </Badge>
                    )}
                    <Badge size="lg" color={STATUS_COLOR[run.status] ?? "gray"} variant="light">
                        {run.status}
                    </Badge>
                    {run.status === "waiting" && run.waiting_signal && (
                        <Badge size="lg" variant="outline" color="yellow">
                            waiting: {run.waiting_signal}
                        </Badge>
                    )}
                    {sourceBadge && (
                        <Badge size="lg" variant="outline" color={sourceBadge.color}>
                            {sourceBadge.label}
                        </Badge>
                    )}
                </Group>
            </Group>

            {run.error && <Alert color="red" title="Run error">{run.error}</Alert>}

            {gateOptions.length > 0 && (
                <Alert color="yellow" title="Waiting for a decision">
                    <Text fz="sm">
                        Parked at <b>{run.current_node}</b> until someone answers. The same choice is on the
                        alert board; picking one here resumes the run down that edge.
                    </Text>
                    <Group gap="xs" mt="sm">
                        {gateOptions.map((o) => (
                            <Button
                                key={o.edge}
                                size="xs"
                                variant="light"
                                loading={resuming === o.edge}
                                disabled={resuming !== null}
                                onClick={() => confirmResume(o)}
                            >
                                {o.label}
                            </Button>
                        ))}
                    </Group>
                </Alert>
            )}

            {run.flow_source === "edited" && (
                <Alert color="orange" title="This graph is not the one that ran">
                    <Text fz="sm">
                        This run finished and let go of its own copy of the flow, so the canvas below is
                        today&apos;s flow, edited since. The highlighted path is this run&apos;s step names
                        drawn onto a different document: a renamed or deleted step will not light up, and a step
                        added since looks like one the run skipped. The timeline came from the run itself.
                    </Text>
                </Alert>
            )}

            <Group align="stretch" gap="md" wrap="nowrap" style={{minHeight: 520}}>
                <Paper withBorder p="xs" style={{flex: 1, height: 560}}>
                    {run.flow_source === "unavailable" || !run.flow ? (
                        // No definition came back, so there is no graph to draw and an empty canvas would read
                        // as a run that did nothing.
                        <Stack justify="center" align="center" h="100%" gap="xs" px="xl">
                            <IconSitemap size={32} opacity={0.35}/>
                            <Text fz="sm" fw={600}>
                                The flow this ran is no longer available
                            </Text>
                            <Text fz="xs" c="dimmed" ta="center" maw={420}>
                                This run finished and let go of its own copy of the flow, and the flow it came from
                                has since been deleted or no longer parses. The timeline is the run&apos;s own record
                                and is still complete.
                            </Text>
                        </Stack>
                    ) : (
                        <ReactFlowProvider>
                            <ReactFlow
                                nodes={graph.nodes}
                                edges={graph.edges}
                                nodeTypes={nodeTypes}
                                fitView
                                nodesDraggable={false}
                                nodesConnectable={false}
                                elementsSelectable={false}
                                proOptions={{hideAttribution: true}}
                            >
                                <Background gap={16}/>
                                <Controls showInteractive={false}/>
                                <MiniMap
                                    pannable
                                    maskColor={MINIMAP_MASK[scheme]}
                                    style={{background: "var(--mantine-color-body)"}}
                                />
                            </ReactFlow>
                        </ReactFlowProvider>
                    )}
                </Paper>

                <Paper withBorder p="md" style={{width: 340, flexShrink: 0}}>
                    <Text fw={700} fz="sm" mb="sm">
                        Timeline
                    </Text>
                    <ScrollArea.Autosize mah={480}>
                        <Timeline active={(run.timeline?.length ?? 1) - 1} bulletSize={14} lineWidth={2}>
                            {(run.timeline ?? []).map((t, i) => (
                                <Timeline.Item key={i} title={t.node ?? "flow"}>
                                    <Text fz="xs">{t.message}</Text>
                                    <Text fz={10} c="dimmed">
                                        {t.at ? new Date(t.at).toLocaleString() : ""}
                                    </Text>
                                </Timeline.Item>
                            ))}
                        </Timeline>
                        {!run.timeline?.length && (
                            <Text fz="xs" c="dimmed">
                                No timeline entries yet.
                            </Text>
                        )}
                    </ScrollArea.Autosize>
                </Paper>
            </Group>
        </Stack>
    );
}
