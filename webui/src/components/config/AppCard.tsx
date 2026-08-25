import {ActionIcon, Badge, Code, Group, RingProgress, Stack, Text, Tooltip} from "@mantine/core";
import {IconPencil} from "@tabler/icons-react";
import {type App} from "../../../lib/config";
import {inFlight, type RolloutCounts} from "../../../lib/rollout";
import {GlassCard} from "../ui/GlassCard";

export function installedPct(counts: RolloutCounts): number {
    if (counts.total === 0) return 0;
    return Math.round((counts.installed / counts.total) * 100);
}

export function AppCard({
                            app,
                            counts,
                            hasStats,
                            onPeek,
                            onEdit,
                        }: {
    app: App;
    counts: RolloutCounts;
    hasStats: boolean;
    onPeek: () => void;
    onEdit: () => void;
}) {
    const pct = installedPct(counts);
    const in_progress_installs = inFlight(counts);
    const ringColor = counts.failed > 0 ? "red" : pct === 100 ? "teal" : "blue";

    return (
        <GlassCard
            lift="quiet"
            withBorder
            padding="md"
            h="100%"
            onClick={onPeek}
        >
            <Group justify="space-between" align="flex-start" wrap="nowrap">
                <Stack gap={2} style={{minWidth: 0}}>
                    <Group gap="xs" wrap="nowrap">
                        <Text fw={600} truncate>
                            {app.name}
                        </Text>
                        <Badge variant="light" color="gray" size="sm" style={{flexShrink: 0}}>
                            {app.versions.length} version{app.versions.length === 1 ? "" : "s"}
                        </Badge>
                    </Group>
                    <Text fz="xs" c="dimmed" truncate>
                        <Code fz="xs">{app.bundle_id}</Code>
                    </Text>
                </Stack>
                <Tooltip label="Open in the app editor" withArrow>
                    <ActionIcon
                        variant="subtle"
                        color="gray"
                        onClick={(e) => {
                            e.stopPropagation();
                            onEdit();
                        }}
                        aria-label={`Edit ${app.name}`}
                    >
                        <IconPencil size={16}/>
                    </ActionIcon>
                </Tooltip>
            </Group>

            <Group gap="md" mt="md" wrap="nowrap" align="center">
                {!hasStats ? (
                    <Text fz="sm" c="dimmed">
                        Working out rollout status…
                    </Text>
                ) : counts.total === 0 ? (
                    <Text fz="sm" c="dimmed">
                        Not installed on any devices yet.
                    </Text>
                ) : (
                    <>
                        <RingProgress
                            size={64}
                            thickness={7}
                            roundCaps
                            sections={[{value: pct, color: ringColor}]}
                            label={
                                <Text ta="center" fz="xs" fw={700}>
                                    {pct}%
                                </Text>
                            }
                        />
                        <Stack gap={2} style={{minWidth: 0}}>
                            <Text fz="sm">
                                <b>{counts.installed}</b> of {counts.total} installed
                            </Text>
                            <Group gap={6}>
                                {in_progress_installs > 0 && (
                                    <Badge variant="light" color="yellow" size="sm">
                                        {in_progress_installs} in progress
                                    </Badge>
                                )}
                                {counts.failed > 0 && (
                                    <Badge variant="light" color="red" size="sm">
                                        {counts.failed} failed
                                    </Badge>
                                )}
                                {counts.unscoped > 0 && (
                                    <Badge variant="light" color="gray" size="sm">
                                        {counts.unscoped} left scope
                                    </Badge>
                                )}
                                {in_progress_installs === 0 && counts.failed === 0 && counts.unscoped === 0 && (
                                    <Badge variant="light" color="teal" size="sm">
                                        completed
                                    </Badge>
                                )}
                            </Group>
                        </Stack>
                    </>
                )}
            </Group>
        </GlassCard>
    );
}
