// One flow: what starts it, a still picture of its graph, and how often it has run. The card and the pencil both open
// the flow in the editor.

import {ActionIcon, Badge, Card, Group, Stack, Text, Tooltip} from "@mantine/core";
import {IconPencil} from "@tabler/icons-react";
import type {FlowDoc, FlowSummary} from "../../../lib/api";
import {clickable} from "../../../lib/a11y";
import {timeSince} from "../../../lib/time";
import {FlowThumbnail} from "./FlowThumbnail";
import {GlassCard} from "../ui/GlassCard";

function triggerLabel(kind: string): string {
    switch (kind) {
        case "enroll_dep":
            return "automated enroll";
        case "enroll_profile":
            return "manual enroll";
        case "checkin":
            return "check-in";
        case "schedule":
            return "schedule";
        default:
            return kind;
    }
}

export function FlowOverviewCard({
                                     flow,
                                     stats,
                                     statsState,
                                     retentionDays,
                                     onEdit,
                                     className,
                                 }: {
    flow: FlowDoc;
    stats: FlowSummary | undefined;
    /** Whether the flows summary has answered yet, and whether it answered at all. */
    statsState: "loading" | "ready" | "unavailable";
    retentionDays: number | null;
    onEdit: () => void;
    /** For a caller that tints the card, such as the draft in a pile. */
    className?: string;
}) {
    const isDraft = Boolean(flow.draft_of);
    const isPermanent = flow.permanent === true && !isDraft;
    const disabled = flow.enabled === false && !isDraft;
    const kinds = Array.from(new Set(stats?.start_kinds ?? []));
    const nodeCount = stats?.node_count ?? flow.nodes?.length ?? 0;
    const runs = stats?.runs_in_window ?? 0;
    const failed = stats?.failed_in_window ?? 0;
    const active = stats?.active_runs ?? 0;
    const lastRun = stats?.last_run_at ? timeSince(stats.last_run_at) : null;

    const trigger = isDraft
        ? `Draft of ${flow.draft_of}`
        : kinds.length
            ? `Starts on ${kinds.map(triggerLabel).join(", ")}`
            : "No trigger, so nothing starts it";

    const windowNote = retentionDays
        ? `Runs counted over the last ${retentionDays} days.`
        : "Runs counted over the retention window.";

    return (
        <GlassCard
            material="thin"
            withBorder
            padding="md"
            h="100%"
            className={className}
            {...clickable(onEdit)}
        >
            <Group justify="space-between" align="flex-start" wrap="nowrap">
                <Stack gap={2} style={{minWidth: 0}}>
                    <Group gap="xs" wrap="nowrap">
                        <Text fw={600} truncate>
                            {flow.name || flow.id}
                        </Text>
                        {isPermanent && (
                            <Badge variant="light" color="blue" size="sm" style={{flexShrink: 0}}>
                                enrollment
                            </Badge>
                        )}
                        {isDraft && (
                            <Badge variant="outline" color="orange" size="sm" style={{flexShrink: 0}}>
                                draft
                            </Badge>
                        )}
                        {disabled && (
                            <Badge variant="light" color="gray" size="sm" style={{flexShrink: 0}}>
                                disabled
                            </Badge>
                        )}
                    </Group>
                    <Text fz="xs" c="dimmed" truncate>
                        {trigger}
                    </Text>
                </Stack>
                <Tooltip label="Open in the flow editor" withArrow>
                    <ActionIcon
                        variant="subtle"
                        color="gray"
                        onClick={(e) => {
                            // The card opens the editor too, so the pencil must not do it twice.
                            e.stopPropagation();
                            onEdit();
                        }}
                        aria-label={`Edit ${flow.name || flow.id}`}
                    >
                        <IconPencil size={16}/>
                    </ActionIcon>
                </Tooltip>
            </Group>

            <Card.Section mt="md" px="md">
                <FlowThumbnail nodes={flow.nodes ?? []} muted={disabled || isDraft}/>
            </Card.Section>

            <Group gap="xs" mt="md" wrap="wrap">
                <Badge variant="light" color="gray" size="sm">
                    {nodeCount} {nodeCount === 1 ? "block" : "blocks"}
                </Badge>
                {isDraft ? null : statsState !== "ready" ? (
                    <Text fz="xs" c="dimmed">
                        {statsState === "loading" ? "Counting runs…" : "Run counts unavailable."}
                    </Text>
                ) : (
                    <>
                        <Badge variant="light" color={runs > 0 ? "blue" : "gray"} size="sm">
                            {runs} {runs === 1 ? "run" : "runs"}
                        </Badge>
                        <Badge variant="light" color={failed > 0 ? "red" : "teal"} size="sm">
                            {failed} failed
                        </Badge>
                        {active > 0 && (
                            <Badge variant="light" color="yellow" size="sm">
                                {active} running
                            </Badge>
                        )}
                    </>
                )}
            </Group>

            {!isDraft && statsState === "ready" && (
                <Text fz="xs" c="dimmed" mt={6}>
                    {lastRun ? `Last run ${lastRun}. ` : "Never run. "}
                    {windowNote}
                </Text>
            )}
        </GlassCard>
    );
}
