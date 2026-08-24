"use client";

import {useEffect, useMemo, useState} from "react";
import {useRouter} from "next/navigation";
import {Button, Group, SimpleGrid, Stack, Text, ThemeIcon, Tooltip} from "@mantine/core";
import {
    IconAlertTriangle,
    IconCircleOff,
    IconFileDescription,
    IconHistory,
    IconPlayerPlay,
    IconPlus,
    IconSitemap,
    IconVectorBezier2,
} from "@tabler/icons-react";
import {
    api,
    type FlowDoc,
    type FlowsConfig,
    type FlowsSummaryResponse,
    type FlowSummary,
} from "../../../../../lib/api";
import {useAuth} from "../../../../../lib/auth-context";
import {useConfigResource} from "../../../../../lib/config";
import {PageHeader} from "@/components/layout/PageHeader";
import {PageSkeleton} from "@/components/layout/PageSkeleton";
import {FlowOverviewCard} from "@/components/atc/FlowOverviewCard";
import {FlowPile} from "@/components/atc/FlowPile";
import {ADMIN_ONLY_REASON, flowsFromConfig} from "@/components/atc/flow-utils";
import {GlassCard} from "@/components/ui/GlassCard";

function StatTile({
                      label,
                      value,
                      sub,
                      icon: Icon,
                      color,
                  }: {
    label: string;
    value: number | null;
    sub?: string;
    icon: React.ElementType;
    color: string;
}) {
    return (
        <GlassCard withBorder p="md" h="100%">
            <Group justify="space-between" align="flex-start" wrap="nowrap">
                <Stack gap={2} style={{minWidth: 0}}>
                    <Text fz="xs" c="dimmed" fw={500}>
                        {label}
                    </Text>
                    <Text fz={26} fw={700} lh={1}>
                        {value === null ? "--" : value.toLocaleString()}
                    </Text>
                    {sub && (
                        <Text fz="xs" c="dimmed">
                            {sub}
                        </Text>
                    )}
                </Stack>
                <ThemeIcon variant="light" color={color} size={34}>
                    <Icon size={18}/>
                </ThemeIcon>
            </Group>
        </GlassCard>
    );
}

export default function FlowsOverviewPage() {
    const {token, isAdmin} = useAuth();
    const router = useRouter();
    const {data, loading} = useConfigResource<FlowsConfig>("flows", {version: 2, flows: []});
    const [summary, setSummary] = useState<FlowsSummaryResponse | null>(null);
    // The summary endpoint carries the run counts. If it refuses, the cards say so rather than counting forever.
    const [summaryFailed, setSummaryFailed] = useState(false);

    useEffect(() => {
        if (!token) return;
        api.getFlowsSummary(token)
            .then(setSummary)
            .catch(() => setSummaryFailed(true));
    }, [token]);

    const flows = useMemo(() => flowsFromConfig(data), [data]);

    // Live flows in name order, each with its own drafts behind it, so a flow and its drafts take one
    // place in the grid as a pile. A draft whose flow is missing stands on its own at the end.
    const stacks = useMemo(() => {
        const live = flows.filter((f) => !f.draft_of);
        live.sort((a, b) => {
            if (Boolean(a.permanent) !== Boolean(b.permanent)) return a.permanent ? -1 : 1;
            return (a.name || a.id).localeCompare(b.name || b.id);
        });
        const draftsByParent = new Map<string, FlowDoc[]>();
        for (const f of flows) {
            if (!f.draft_of) continue;
            const group = draftsByParent.get(f.draft_of) ?? [];
            group.push(f);
            draftsByParent.set(f.draft_of, group);
        }
        const out: FlowDoc[][] = [];
        for (const flow of live) {
            out.push([flow, ...(draftsByParent.get(flow.id) ?? [])]);
            draftsByParent.delete(flow.id);
        }
        for (const group of draftsByParent.values()) {
            for (const orphan of group) out.push([orphan]);
        }
        return out;
    }, [flows]);

    const summaryById = useMemo(() => {
        const map = new Map<string, FlowSummary>();
        for (const s of summary?.flows ?? []) map.set(s.id, s);
        return map;
    }, [summary]);

    // The editor reads ?flow= to select a flow and ?new=1 to open its create dialog.
    const openEditor = (flow: FlowDoc) => router.push(`/atc?flow=${encodeURIComponent(flow.id)}`);

    const newFlow = () => router.push("/atc?new=1");

    const statsState = summary !== null ? "ready" : summaryFailed ? "unavailable" : "loading";

    const totals = useMemo(() => {
        const live = flows.filter((f) => !f.draft_of);
        let runs = 0;
        let failed = 0;
        let active = 0;
        for (const s of summary?.flows ?? []) {
            if (s.draft_of) continue;
            runs += s.runs_in_window;
            failed += s.failed_in_window;
            active += s.active_runs;
        }
        return {
            live: live.length,
            disabled: live.filter((f) => f.enabled === false).length,
            drafts: flows.length - live.length,
            runs,
            failed,
            active,
        };
    }, [flows, summary]);

    const windowNote = summary?.retention_days
        ? `Over the last ${summary.retention_days} days`
        : "Over the retention window";
    const countsReady = statsState === "ready";
    const countsNote = statsState === "loading" ? "Counting runs…" : "Run counts unavailable";

    return (
        <Stack gap="lg">
            <PageHeader
                description="Every flow, what starts it, and how often it has run."
                actions={
                    <>
                        <Button
                            variant="light"
                            leftSection={<IconHistory size={14}/>}
                            onClick={() => router.push("/atc/runs")}
                        >
                            Run history
                        </Button>
                        <Button
                            variant="light"
                            leftSection={<IconVectorBezier2 size={16}/>}
                            onClick={() => router.push("/atc")}
                        >
                            Open editor
                        </Button>
                        <Tooltip label={ADMIN_ONLY_REASON} withArrow disabled={isAdmin}>
                            <span>
                                <Button
                                    leftSection={<IconPlus size={16}/>}
                                    onClick={newFlow}
                                    disabled={!isAdmin}
                                >
                                    New flow
                                </Button>
                            </span>
                        </Tooltip>
                    </>
                }
            />

            {!loading && stacks.length > 0 && (
                <SimpleGrid cols={{base: 2, sm: 3, lg: totals.active > 0 && countsReady ? 6 : 5}} spacing="md">
                    <StatTile
                        label="Flows"
                        value={totals.live}
                        sub={`${totals.live - totals.disabled} enabled`}
                        icon={IconVectorBezier2}
                        color="blue"
                    />
                    <StatTile
                        label="Disabled"
                        value={totals.disabled}
                        sub={totals.disabled === 0 ? "all switched on" : "nothing starts these"}
                        icon={IconCircleOff}
                        color={totals.disabled > 0 ? "orange" : "gray"}
                    />
                    <StatTile
                        label="Open drafts"
                        value={totals.drafts}
                        sub={totals.drafts === 0 ? "none waiting" : "not live until promoted"}
                        icon={IconFileDescription}
                        color={totals.drafts > 0 ? "grape" : "gray"}
                    />
                    <StatTile
                        label="Runs"
                        value={countsReady ? totals.runs : null}
                        sub={countsReady ? windowNote : countsNote}
                        icon={IconHistory}
                        color={countsReady ? "blue" : "gray"}
                    />
                    <StatTile
                        label="Failed runs"
                        value={countsReady ? totals.failed : null}
                        sub={countsReady ? windowNote : countsNote}
                        icon={IconAlertTriangle}
                        color={!countsReady ? "gray" : totals.failed > 0 ? "red" : "teal"}
                    />
                    {countsReady && totals.active > 0 && (
                        <StatTile
                            label="Running now"
                            value={totals.active}
                            sub="still going"
                            icon={IconPlayerPlay}
                            color="yellow"
                        />
                    )}
                </SimpleGrid>
            )}

            {loading ? (
                <PageSkeleton variant="grid"/>
            ) : stacks.length === 0 ? (
                <GlassCard withBorder py={48}>
                    <Stack align="center" gap="xs">
                        <IconSitemap size={36} opacity={0.4}/>
                        <Text c="dimmed">No flows yet.</Text>
                        <Tooltip label={ADMIN_ONLY_REASON} withArrow disabled={isAdmin}>
                            <span>
                                <Button
                                    variant="light"
                                    leftSection={<IconPlus size={16}/>}
                                    onClick={newFlow}
                                    disabled={!isAdmin}
                                >
                                    Build your first flow
                                </Button>
                            </span>
                        </Tooltip>
                    </Stack>
                </GlassCard>
            ) : (
                <SimpleGrid cols={{base: 1, sm: 2, lg: 3}} spacing="md">
                    {stacks.map((stack) =>
                        stack.length === 1 ? (
                            <FlowOverviewCard
                                key={stack[0].id}
                                flow={stack[0]}
                                stats={summaryById.get(stack[0].id)}
                                statsState={statsState}
                                retentionDays={summary?.retention_days ?? null}
                                onEdit={() => openEditor(stack[0])}
                            />
                        ) : (
                            <FlowPile
                                key={stack[0].id}
                                stack={stack}
                                statsFor={(flow) => summaryById.get(flow.id)}
                                statsState={statsState}
                                retentionDays={summary?.retention_days ?? null}
                                onOpenFlow={openEditor}
                            />
                        ),
                    )}
                </SimpleGrid>
            )}
        </Stack>
    );
}
