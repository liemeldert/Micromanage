"use client";

// Read-only breakdown of one app's rollout by state, targeted version and device model, opened
// from an app card. Version management stays in the editor. Modal styling comes from lib/theme.ts.

import {Badge, Box, Button, Code, Divider, Group, Modal, Paper, SimpleGrid, Stack, Text} from "@mantine/core";
import {BarChart, DonutChart} from "@mantine/charts";
import {IconPencil} from "@tabler/icons-react";
import {type RolloutItemStats} from "../../../lib/api";
import {type App} from "../../../lib/config";
import {toCounts} from "../../../lib/rollout";
import {installedPct} from "./AppCard";

// Order, labels and colours for deployment statuses, shared by the donut and the stacked bars.
const STATUS_SERIES: { key: string; label: string; color: string }[] = [
    {key: "installed", label: "Installed", color: "teal"},
    {key: "accepted", label: "Accepted, unconfirmed", color: "cyan"},
    {key: "installing", label: "Installing", color: "yellow"},
    {key: "pending", label: "Pending", color: "orange"},
    {key: "failed", label: "Failed", color: "red"},
    {key: "unscoped", label: "Left scope", color: "gray"},
];

function stackedRows(
    byKey: Record<string, Record<string, number>> | undefined,
    nameKey: string,
): Record<string, string | number>[] {
    return Object.entries(byKey ?? {})
        .map(([name, statuses]) => {
            const row: Record<string, string | number> = {[nameKey]: name};
            for (const s of STATUS_SERIES) row[s.label] = statuses[s.key] ?? 0;
            return row;
        })
        .sort((a, b) => String(a[nameKey]).localeCompare(String(b[nameKey])));
}

const CHART_SERIES = STATUS_SERIES.map((s) => ({name: s.label, color: s.color}));

// Recharts lists every series, so a device model sitting at one status showed five zeroes under it and the
// panel ran past the edge of the dialog. Only the states this bar actually has are worth drawing.
interface TooltipRow {
    name?: string;
    value?: number;
    color?: string;
}

function ChartTooltip({label, payload}: { label?: string; payload?: TooltipRow[] }) {
    const rows = (payload ?? []).filter((p) => (p.value ?? 0) > 0);
    if (!rows.length) return null;
    return (
        <Paper px="sm" py={6} withBorder shadow="md" radius="sm">
            <Text fz="xs" fw={600} mb={4}>
                {label}
            </Text>
            {rows.map((r) => (
                <Group key={r.name} gap={8} justify="space-between" wrap="nowrap">
                    <Group gap={6} wrap="nowrap">
                        <Box w={8} h={8} style={{borderRadius: 8, background: r.color}}/>
                        <Text fz="xs">{r.name}</Text>
                    </Group>
                    <Text fz="xs" fw={600}>
                        {r.value}
                    </Text>
                </Group>
            ))}
        </Paper>
    );
}

export function AppPeekModal({
                                 app,
                                 stats,
                                 opened,
                                 onClose,
                                 onEdit,
                             }: {
    app: App | null;
    stats: RolloutItemStats | undefined;
    opened: boolean;
    onClose: () => void;
    onEdit: (app: App) => void;
}) {
    const counts = toCounts(stats);
    const donut = STATUS_SERIES
        .map((s) => ({name: s.label, value: stats?.by_status?.[s.key] ?? 0, color: s.color}))
        .filter((d) => d.value > 0);
    const versionRows = stackedRows(stats?.by_desired_version, "version");
    const modelRows = stackedRows(stats?.by_device_model, "model");
    const reported = Object.entries(stats?.by_reported_version ?? {}).sort(
        (a, b) => b[1] - a[1],
    );

    return (
        <Modal
            opened={opened}
            onClose={onClose}
            size="lg"
            title={
                app && (
                    <Group gap="xs">
                        <Text fw={600}>{app.name}</Text>
                        <Code fz="xs">{app.bundle_id}</Code>
                    </Group>
                )
            }
        >
            {app && (
                <Stack gap="md">
                    {counts.total === 0 ? (
                        <Text c="dimmed" py="lg" ta="center">
                            Not on any device yet, so there is nothing to break down. Devices join as
                            the target groups pick them up.
                        </Text>
                    ) : (
                        <>
                            <Group gap="lg" align="center" wrap="nowrap">
                                <DonutChart
                                    size={132}
                                    thickness={20}
                                    withTooltip
                                    data={donut}
                                    chartLabel={`${installedPct(counts)}%`}
                                />
                                <Stack gap={4}>
                                    <Text fz="sm">
                                        <b>{counts.installed}</b> of {counts.total} devices confirmed the
                                        install.
                                    </Text>
                                    <Group gap={6} wrap="wrap">
                                        {donut.map((d) => (
                                            <Badge key={d.name} variant="light" color={d.color} size="sm">
                                                {d.value} {d.name.toLowerCase()}
                                            </Badge>
                                        ))}
                                    </Group>
                                </Stack>
                            </Group>

                            <SimpleGrid cols={{base: 1, sm: 2}} spacing="md">
                                {versionRows.length > 0 && (
                                    <Box>
                                        <Text fz="sm" fw={600} mb={4}>
                                            By targeted version
                                        </Text>
                                        <BarChart
                                            h={160}
                                            data={versionRows}
                                            dataKey="version"
                                            type="stacked"
                                            series={CHART_SERIES}
                                            tickLine="none"
                                            gridAxis="x"
                                            withLegend={false}
                                            tooltipProps={{
                                                content: ({label, payload}) => <ChartTooltip label={label}
                                                                                             payload={payload}/>
                                            }}
                                            yAxisProps={{allowDecimals: false}}
                                        />
                                    </Box>
                                )}
                                {modelRows.length > 0 && (
                                    <Box>
                                        <Text fz="sm" fw={600} mb={4}>
                                            By device model
                                        </Text>
                                        <BarChart
                                            h={160}
                                            data={modelRows}
                                            dataKey="model"
                                            type="stacked"
                                            series={CHART_SERIES}
                                            tickLine="none"
                                            gridAxis="x"
                                            withLegend={false}
                                            tooltipProps={{
                                                content: ({label, payload}) => <ChartTooltip label={label}
                                                                                             payload={payload}/>
                                            }}
                                            yAxisProps={{allowDecimals: false}}
                                        />
                                    </Box>
                                )}
                            </SimpleGrid>

                            {reported.length > 0 && (
                                <Box>
                                    <Text fz="sm" fw={600} mb={4}>
                                        Versions devices report
                                    </Text>
                                    <Group gap={6} wrap="wrap">
                                        {reported.map(([version, n]) => (
                                            <Badge key={version} variant="outline" color="gray" size="sm">
                                                {version} · {n}
                                            </Badge>
                                        ))}
                                    </Group>
                                    <Text fz="xs" c="dimmed" mt={4}>
                                        What each device itself calls the installed build; nothing requires
                                        it to match the version label authored here.
                                    </Text>
                                </Box>
                            )}
                        </>
                    )}

                    <Divider/>
                    <Group justify="flex-end">
                        <Button variant="default" onClick={onClose}>
                            Close
                        </Button>
                        <Button leftSection={<IconPencil size={14}/>} onClick={() => onEdit(app)}>
                            Open in editor
                        </Button>
                    </Group>
                </Stack>
            )}
        </Modal>
    );
}
