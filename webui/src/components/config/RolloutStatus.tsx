// Per-item rollout counts from GET /api/v1/stats/rollout (lib/rollout.ts), so an item failing across the fleet shows
// up in the list rather than only on each device's page.

import {Alert, Badge, Group, Text, Tooltip} from "@mantine/core";
import {IconAlertTriangle} from "@tabler/icons-react";
import {type RolloutCounts} from "../../../lib/rollout";

export function RolloutCountedNote({
                                       countedAt,
                                       devicesEnrolled,
                                       error,
                                   }: {
    countedAt: string | undefined;
    devicesEnrolled: number | undefined;
    error: string | null;
}) {
    if (error) {
        return (
            <Alert color="red" variant="light" icon={<IconAlertTriangle size={16}/>}>
                Couldn&apos;t determine app rollout status: {error}
            </Alert>
        );
    }
    if (!countedAt) return null;
    return (
        <Text fz="xs" c="dimmed">
            Counted across {devicesEnrolled ?? 0} enrolled device{devicesEnrolled === 1 ? "" : "s"} at{" "}
            {new Date(countedAt).toLocaleTimeString()}.
        </Text>
    );
}

/** Per-row installed / pending / failed chips. */
export function RolloutBadges({
                                  counts,
                                  hasSummary,
                              }: {
    counts: RolloutCounts | undefined;
    hasSummary: boolean;
}) {
    if (!hasSummary) return null;
    if (!counts || counts.total === 0) {
        return (
            <Badge variant="outline" color="gray" size="sm">
                on no devices
            </Badge>
        );
    }
    const pending = counts.pending + counts.installing;
    return (
        <Group gap={4} wrap="nowrap">
            <Tooltip label="Devices that confirmed the install" withArrow>
                <Badge variant="light" color={counts.installed ? "teal" : "gray"} size="sm">
                    {counts.installed} installed
                </Badge>
            </Tooltip>
            {pending > 0 && (
                <Tooltip label="Sent, but the device hasn't replied yet" withArrow>
                    <Badge variant="light" color="yellow" size="sm">
                        {pending} pending
                    </Badge>
                </Tooltip>
            )}
            {counts.accepted > 0 && (
                <Tooltip
                    label="The device took the install command; no inventory report has confirmed the app installed yet"
                    withArrow
                    multiline
                    w={260}
                >
                    <Badge variant="light" color="cyan" size="sm">
                        {counts.accepted} accepted, waiting for confirmation
                    </Badge>
                </Tooltip>
            )}
            {counts.failed > 0 && (
                <Tooltip label="The device reported the install as failed!" withArrow>
                    <Badge variant="light" color="red" size="sm">
                        {counts.failed} failed
                    </Badge>
                </Tooltip>
            )}
            {counts.unscoped > 0 && (
                <Tooltip label="Left this app's scope after it was installed; nothing was uninstalled" withArrow>
                    <Badge variant="light" color="gray" size="sm">
                        {counts.unscoped} no longer in scope
                    </Badge>
                </Tooltip>
            )}
        </Group>
    );
}
