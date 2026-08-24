"use client";

import {useCallback, useEffect, useState} from "react";
import {
    Badge,
    Box,
    Grid,
    Group,
    RingProgress,
    ScrollArea,
    SimpleGrid,
    Stack,
    Text,
    ThemeIcon,
    UnstyledButton,
} from "@mantine/core";
import {IconActivityHeartbeat, IconCircleCheck, IconClock, IconDeviceLaptop, IconPackage,} from "@tabler/icons-react";
import Link from "next/link";
import {useRouter} from "next/navigation";
import {BarChart} from "@mantine/charts";
import {api, type DispatcherAlert, isBreakGlassAlert, type StatsOverview} from "../../../../lib/api";
import {useAuth} from "../../../../lib/auth-context";
import {READINESS_POLL_MS, useReadiness} from "../../../../lib/readiness";
import {notifications} from "@mantine/notifications";
import {ReadinessBanner} from "@/components/ReadinessStatus";
import {PageSkeleton} from "@/components/layout/PageSkeleton";
import {PageHeader} from "@/components/layout/PageHeader";
import {timeSince} from "../../../../lib/time";
import {GlassCard} from "@/components/ui/GlassCard";
import type {GlassTone} from "@/components/ui/glass";
import {AlertQuickRow} from "@/components/dispatcher/AlertQuickRow";
import {Interactable} from "@/components/ui/Interactable";
import {AlertPeekModal} from "@/components/dispatcher/AlertPeekModal";

function StatCard({
                      label,
                      value,
                      sub,
                      icon: Icon,
                      color,
                      tone = "neutral",
                      toneLevel = 1,
                  }: {
    label: string;
    value: number | null;
    sub?: string;
    icon: React.ElementType;
    color: string;
    /** A band of light around the card when this number is something to act on. */
    tone?: GlassTone;
    toneLevel?: number;
}) {
    return (
        <GlassCard withBorder p="lg" h="100%" interactive tone={tone} toneLevel={toneLevel}>
            <Group justify="space-between" align="flex-start" wrap="nowrap">
                <Stack gap={4}>
                    <Text fz="sm" c="dimmed" fw={500}>
                        {label}
                    </Text>
                    <Text fz={32} fw={700} lh={1}>
                        {value === null ? "--" : value.toLocaleString()}
                    </Text>
                    {sub && (
                        <Text fz="xs" c="dimmed">
                            {sub}
                        </Text>
                    )}
                </Stack>
                <ThemeIcon variant="light" color={color} size={42}>
                    <Icon size={22}/>
                </ThemeIcon>
            </Group>
        </GlassCard>
    );
}

// Triage order, worst first, matching the alert board's own colours.
const ALERT_SEVERITIES: { key: string; label: string; color: string }[] = [
    {key: "black", label: "Critical", color: "dark"},
    {key: "red", label: "High", color: "red"},
    {key: "yellow", label: "Medium", color: "yellow"},
    {key: "green", label: "Low", color: "green"},
];

function ComplianceBreakdown({
                                 alerts,
                                 failed,
                                 tone,
                                 toneLevel,
                                 onOpenSeverity,
                                 onOpenAlert,
                                 onAcknowledge,
                                 onResolve,
                                 onOpenDevice,
                                 onDismiss,
                                 onUnacknowledge,
                             }: {
    alerts: DispatcherAlert[];
    failed: boolean;
    tone: GlassTone;
    toneLevel: number;
    onOpenSeverity: (severity: string) => void;
    onOpenAlert: (id: string) => void;
    onAcknowledge: (id: string) => void;
    onResolve: (alert: DispatcherAlert) => void;
    onOpenDevice: (deviceId: string) => void;
    onDismiss: (id: string) => void;
    onUnacknowledge: (id: string) => void;
}) {
    const [peekId, setPeekId] = useState<string | null>(null);
    const [showAcked, setShowAcked] = useState(false);

    // Acknowledged means somebody has seen it, so it leaves the board the way a notification does, and the
    // counts follow the board rather than the server's total. They can be brought back to be un-acknowledged.
    const unresolved = alerts.filter((alert) => alert.status !== "resolved");
    const ackedBySeverity = unresolved
        .filter((alert) => alert.status === "acknowledged")
        .reduce<Record<string, number>>((acc, alert) => {
            acc[alert.severity] = (acc[alert.severity] ?? 0) + 1;
            return acc;
        }, {});
    const live = unresolved.filter((alert) => alert.status !== "acknowledged");
    const openAlerts = showAcked ? unresolved : live;
    const liveCounts = live.reduce<Record<string, number>>((acc, alert) => {
        acc[alert.severity] = (acc[alert.severity] ?? 0) + 1;
        return acc;
    }, {});
    const peeked = alerts.find((alert) => alert.id === peekId) ?? null;
    const peekedSeverity = ALERT_SEVERITIES.find((entry) => entry.key === peeked?.severity);

    return (
        <GlassCard
            withBorder
            p="lg"
            h="100%"
            tone={tone}
            toneLevel={toneLevel}
            toneBloom={false}
            style={{display: "flex", flexDirection: "column"}}
        >
            <Group gap="xs" align="baseline" wrap="nowrap" mb="md">
                <Text fz={32} fw={700} lh={1}>
                    {failed ? "--" : live.length.toLocaleString()}
                </Text>
                <Text fz="md" fw={600}>
                    {failed
                        ? "Alerts unavailable"
                        : `${live.length === 1 ? "Alert" : "Alerts"} open`}
                </Text>
            </Group>

            <SimpleGrid cols={{base: 1, xs: 2, xl: 4}} spacing="sm">
                {ALERT_SEVERITIES.map((severity) => {
                    const rows = openAlerts.filter((alert) => alert.severity === severity.key);
                    const count = failed ? null : (liveCounts[severity.key] ?? 0);
                    return (
                        <Stack key={severity.key} gap={6} h="100%">
                            <Interactable
                                nested
                                className={`mm-severity-cell mm-severity-${severity.color}`}
                                onActivate={() => onOpenSeverity(severity.key)}
                            >
                                <Group gap={6} wrap="nowrap">
                                    <Box
                                        w={8}
                                        h={8}
                                        style={{
                                            borderRadius: 8,
                                            flexShrink: 0,
                                            background: `var(--mantine-color-${severity.color}-6)`,
                                            // A zero is worth naming, not worth shouting.
                                            opacity: count ? 1 : 0.35,
                                        }}
                                    />
                                    <Text fz="xs" c="dimmed">
                                        {severity.label}
                                    </Text>
                                </Group>
                                <Text fz={22} fw={600} lh={1} c={count ? undefined : "dimmed"}>
                                    {count === null ? "--" : count.toLocaleString()}
                                </Text>
                            </Interactable>

                            {/* Each column scrolls on its own, so a hundred of one severity cannot bury the
                              others below it. Mantine sizes an autosize area to its widest line, which a long
                              summary turns into a sideways scrollbar, so the content is held to the column. */}
                            <ScrollArea.Autosize
                                mah={200}
                                type="auto"
                                scrollbars="y"
                                offsetScrollbars="y"
                                styles={{content: {minWidth: 0}}}
                            >
                                {/* Matches the swipe hint's reach on both sides, since the column clips
                                  anything past its padding. */}
                                <Stack gap={4} px={12}>
                                    {rows.length === 0 ? (
                                        <Text fz="xs" c="dimmed" px={8}>
                                            {failed ? "--" : "None"}
                                        </Text>
                                    ) : rows.map((alert) => (
                                        <AlertQuickRow
                                            key={alert.id}
                                            severityColor={severity.color}
                                            summary={alert.summary}
                                            detail={[
                                                alert.device?.display_name || alert.device?.serial_number,
                                                alert.opened_at ? timeSince(alert.opened_at) : null,
                                            ].filter(Boolean).join(" · ")}
                                            acknowledged={alert.status === "acknowledged"}
                                            onAcknowledge={() => (alert.status === "acknowledged"
                                                ? onUnacknowledge(alert.id)
                                                : onAcknowledge(alert.id))}
                                            onResolve={() => onResolve(alert)}
                                            onOpen={() => onOpenAlert(alert.id)}
                                            onPeek={() => setPeekId(alert.id)}
                                            onDismissed={() => onDismiss(alert.id)}
                                        />
                                    ))}
                                </Stack>
                            </ScrollArea.Autosize>

                        </Stack>
                    );
                })}
            </SimpleGrid>

            {/* Pinned to the card's bottom edge, each under the column it belongs to. */}
            <SimpleGrid cols={{base: 1, xs: 2, xl: 4}} spacing="sm" mt="auto" pt="sm">
                {ALERT_SEVERITIES.map((severity) => (
                    <Box key={severity.key}>
                        {ackedBySeverity[severity.key] > 0 && (
                            <UnstyledButton
                                className="mm-acked-toggle"
                                onClick={() => setShowAcked((on) => !on)}
                            >
                                <Text fz="xs" c="dimmed">
                                    {showAcked
                                        ? `Hide ${ackedBySeverity[severity.key]}`
                                        : `${ackedBySeverity[severity.key]} acknowledged`}
                                </Text>
                            </UnstyledButton>
                        )}
                    </Box>
                ))}
            </SimpleGrid>

            <AlertPeekModal
                alert={peeked}
                severityColor={peekedSeverity?.color ?? "gray"}
                severityLabel={peekedSeverity?.label ?? "Alert"}
                opened={peeked !== null}
                onClose={() => setPeekId(null)}
                onAcknowledge={() => {
                    if (peeked) {
                        (peeked.status === "acknowledged" ? onUnacknowledge : onAcknowledge)(peeked.id);
                    }
                    setPeekId(null);
                }}
                onResolve={() => {
                    if (peeked) onResolve(peeked);
                    setPeekId(null);
                }}
                onOpenDevice={() => {
                    if (peeked?.device_id) onOpenDevice(peeked.device_id);
                    setPeekId(null);
                }}
            />
        </GlassCard>
    );
}

export default function DashboardPage() {
    const {token} = useAuth();
    const router = useRouter();
    const {readiness, loading: readinessLoading, error: readinessError} = useReadiness(READINESS_POLL_MS);
    const [stats, setStats] = useState<StatsOverview | null>(null);
    const [byModel, setByModel] = useState<{ device_model: string; count: number }[]>([]);
    const [byOs, setByOs] = useState<{ os_version: string; count: number }[]>([]);
    const [compliance, setCompliance] = useState<{
        active: number;
        counts: Record<string, number>;
        alerts: DispatcherAlert[];
    } | null>(null);
    // A failed alert fetch is not "all clear". Held apart from compliance so the card can say it does not know
    // rather than show a green zero.
    const [complianceFailed, setComplianceFailed] = useState(false);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        if (!token) return;
        Promise.all([api.getStats(token), api.getDevicesByModel(token), api.getDevicesByOs(token)])
            .then(([s, m, o]) => {
                setStats(s);
                setByModel(m.slice(0, 8));
                setByOs(o.slice(0, 8));
            })
            .catch((e) => notifications.show({color: "red", message: e.message}))
            .finally(() => setLoading(false));
        // Compliance summary is independent (the feature may be unconfigured).
        api
            .listAlerts(token)
            .then((a) => {
                setCompliance({active: a.active, counts: a.counts, alerts: a.alerts ?? []});
                setComplianceFailed(false);
            })
            .catch(() => setComplianceFailed(true));
    }, [token]);

    const refreshAlerts = useCallback(() => {
        if (!token) return;
        api.listAlerts(token)
            .then((a) => setCompliance({active: a.active, counts: a.counts, alerts: a.alerts ?? []}))
            .catch(() => setComplianceFailed(true));
    }, [token]);

    const dismissAlert = useCallback((id: string) => {
        setCompliance((current) => (current
            ? {...current, alerts: current.alerts.filter((alert) => alert.id !== id)}
            : current));
    }, []);

    const unacknowledgeAlert = useCallback((id: string) => {
        if (!token) return;
        api.unacknowledgeAlert(token, id)
            .then(refreshAlerts)
            .catch((e) => notifications.show({color: "red", message: (e as Error).message}));
    }, [token, refreshAlerts]);

    const acknowledgeAlert = useCallback((id: string) => {
        if (!token) return;
        api.acknowledgeAlert(token, id)
            .then(refreshAlerts)
            .catch((e) => notifications.show({color: "red", message: (e as Error).message}));
    }, [token, refreshAlerts]);

    // Closing a break-glass record asks for a reason and is audited, so that one goes to the page that can
    // ask rather than being settled from a dashboard tile.
    const resolveAlert = useCallback((alert: DispatcherAlert) => {
        if (!token) return;
        if (isBreakGlassAlert(alert)) {
            router.push(`/compliance?alert=${encodeURIComponent(alert.id)}`);
            return;
        }
        api.resolveAlert(token, alert.id)
            .then(refreshAlerts)
            .catch((e) => notifications.show({color: "red", message: (e as Error).message}));
    }, [token, refreshAlerts, router]);

    if (loading) {
        return <PageSkeleton variant="dashboard"/>;
    }

    // A status with no rows is absent from by_status entirely, so every read needs its own floor. Total comes from
    // the server rather than the sum of these four, which would drop cancelled tasks.
    const byStatus: Record<string, number> = stats?.tasks?.by_status ?? {};
    const taskPending = byStatus.pending ?? 0;
    const taskRunning = byStatus.running ?? 0;
    const taskFailed = byStatus.failed ?? 0;
    const taskDone = byStatus.completed ?? 0;
    const taskTotal = stats?.tasks?.total ?? 0;

    const activeRatio = stats
        ? Math.round((stats.devices.active_7d / Math.max(stats.devices.total, 1)) * 100)
        : 0;

    // The server counts every unresolved alert, acknowledged ones included. The dashboard treats acknowledging
    // as dismissing, so both compliance tiles read from the list instead and leave those out.
    const liveAlerts = (compliance?.alerts ?? [])
        .filter((alert) => alert.status !== "resolved" && alert.status !== "acknowledged");
    const liveBySeverity = liveAlerts.reduce<Record<string, number>>((acc, alert) => {
        acc[alert.severity] = (acc[alert.severity] ?? 0) + 1;
        return acc;
    }, {});
    const ackedTotal = (compliance?.alerts ?? []).filter((alert) => alert.status === "acknowledged").length;

    // Red and black alerts want acting on; yellow is worth a quieter, warmer band. An unreachable endpoint is
    // not a fleet problem, so it says nothing rather than glowing.
    const severeAlerts = (liveBySeverity.black ?? 0) + (liveBySeverity.red ?? 0);
    const complianceTone: GlassTone = complianceFailed
        ? "neutral"
        : severeAlerts > 0
            ? "negative"
            : liveAlerts.length > 0
                ? "warning"
                : "neutral";
    const complianceLevel = severeAlerts > 0
        ? Math.min(0.4 + severeAlerts / 12, 1)
        : Math.min(0.3 + liveAlerts.length / 20, 0.7);

    return (
        <Stack gap="lg">
            <PageHeader description={null}/>

            <ReadinessBanner readiness={readiness} loading={readinessLoading} error={readinessError}/>

            <SimpleGrid cols={{base: 1, sm: 2, md: 3, lg: 5}} spacing="md">
                <Box component={Link} href="/devices"
                     style={{display: "block", height: "100%", color: "inherit", textDecoration: "none"}}>
                    <StatCard
                        label="Total devices"
                        value={stats?.devices.total ?? 0}
                        sub={`${stats?.devices.active_7d ?? 0} active in last 7 days`}
                        icon={IconDeviceLaptop}
                        color="blue"
                    />
                </Box>
                <Box component={Link} href="/apps"
                     style={{display: "block", height: "100%", color: "inherit", textDecoration: "none"}}>
                    <StatCard
                        label="App deployments"
                        value={stats?.deployments.apps ?? 0}
                        sub={
                            stats?.deployments.apps_pending
                                ? `${stats.deployments.apps_pending} are pending (sent, not yet confirmed)`
                                : undefined
                        }
                        icon={IconPackage}
                        color="grape"
                    />
                </Box>
                <Box component={Link} href="/profiles"
                     style={{display: "block", height: "100%", color: "inherit", textDecoration: "none"}}>
                    <StatCard
                        label="Profile deployments"
                        value={stats?.deployments.profiles ?? 0}
                        icon={IconCircleCheck}
                        color="teal"
                    />
                </Box>
                <Box component={Link} href="/settings/tasks"
                     style={{display: "block", height: "100%", color: "inherit", textDecoration: "none"}}>
                    <StatCard
                        label="Pending tasks"
                        value={taskPending + taskRunning}
                        sub={taskFailed > 0 ? `${taskFailed} failed` : undefined}
                        icon={IconClock}
                        color={taskFailed > 0 ? "red" : "orange"}
                        tone={taskFailed > 0 ? "negative" : "neutral"}
                        // Scales with the count, so a fleet's worth of failures glows harder than a handful.
                        toneLevel={Math.min(0.35 + taskFailed / 25, 1)}
                    />
                </Box>
                <Box component={Link} href="/compliance"
                     style={{display: "block", height: "100%", color: "inherit", textDecoration: "none"}}>
                    <StatCard
                        label="Compliance alerts"
                        value={complianceFailed ? null : liveAlerts.length}
                        sub={
                            complianceFailed
                                ? "unavailable, couldn't load alerts"
                                : [
                                    liveAlerts.length > 0
                                        ? (["black", "red", "yellow", "green"] as const)
                                            .filter((s) => (liveBySeverity[s] ?? 0) > 0)
                                            .map((s) => `${liveBySeverity[s]} ${s}`)
                                            .join(" · ")
                                        : "all clear",
                                    ackedTotal > 0 ? `${ackedTotal} acknowledged` : null,
                                ].filter(Boolean).join(" · ")
                        }
                        icon={IconActivityHeartbeat}
                        color={
                            complianceFailed
                                ? "gray"
                                : severeAlerts > 0
                                    ? "red"
                                    : liveAlerts.length > 0
                                        ? "yellow"
                                        : "teal"
                        }
                        tone={complianceTone}
                        toneLevel={complianceLevel}
                    />
                </Box>

            </SimpleGrid>

            <Grid gutter="md">
                {/* The small tile above counts the alerts; this one breaks them down by severity, so it
                  belongs with the charts rather than the single numbers. */}
                <Grid.Col span={{base: 12, md: 6}}>
                    <ComplianceBreakdown
                        alerts={compliance?.alerts ?? []}
                        failed={complianceFailed}
                        tone={complianceTone}
                        toneLevel={complianceLevel}
                        onOpenSeverity={(severity) =>
                            router.push(`/compliance?severity=${encodeURIComponent(severity)}`)}
                        onOpenAlert={(id) => router.push(`/compliance?alert=${encodeURIComponent(id)}`)}
                        onAcknowledge={acknowledgeAlert}
                        onResolve={resolveAlert}
                        onOpenDevice={(deviceId) => router.push(`/devices/${deviceId}`)}
                        onDismiss={dismissAlert}
                        onUnacknowledge={unacknowledgeAlert}
                    />
                </Grid.Col>

                <Grid.Col span={{base: 12, md: 6}}>
                    <GlassCard withBorder h="100%">
                        <Stack align="center" gap="xs">
                            <Text fw={600} fz="sm">
                                Device activity (7 days)
                            </Text>
                            <RingProgress
                                size={160}
                                thickness={16}
                                roundCaps
                                sections={[{value: activeRatio, color: "blue"}]}
                                label={
                                    <Text ta="center" fw={700} fz="xl">
                                        {activeRatio}%
                                    </Text>
                                }
                            />
                            <Text fz="xs" c="dimmed">
                                {stats?.devices.active_7d ?? 0} / {stats?.devices.total ?? 0} devices checked in
                            </Text>
                        </Stack>

                        <Stack mt="md" gap={6}>
                            {[
                                {label: "Completed", count: taskDone, color: "teal"},
                                {label: "Running", count: taskRunning, color: "blue"},
                                {label: "Pending", count: taskPending, color: "yellow"},
                                {label: "Failed", count: taskFailed, color: "red"},
                            ].map((row) => (
                                <Group key={row.label} justify="space-between">
                                    <Text fz="xs" c="dimmed">
                                        {row.label}
                                    </Text>
                                    <Badge size="sm" color={row.color} variant="light">
                                        {row.count}
                                    </Badge>
                                </Group>
                            ))}
                            <Group justify="space-between" mt={4}>
                                <Text fz="xs" fw={500}>
                                    Total tasks
                                </Text>
                                <Text fz="xs" fw={500}>
                                    {taskTotal}
                                </Text>
                            </Group>
                        </Stack>
                    </GlassCard>
                </Grid.Col>

                <Grid.Col span={{base: 12, md: 6}}>
                    <GlassCard withBorder h="100%">
                        <Text fw={600} fz="sm" mb="md">
                            Devices by model
                        </Text>
                        {byModel.length > 0 ? (
                            <BarChart
                                h={260}
                                data={byModel.map((d) => ({name: d.device_model, Devices: d.count}))}
                                dataKey="name"
                                series={[{name: "Devices", color: "blue"}]}
                                tickLine="none"
                                gridAxis="x"
                                // Recharts drops x-axis labels it thinks would collide. interval 0 keeps every
                                // bar's label, the angle stops model identifiers running into each other, and the
                                // extra axis height is the room the tilted labels need.
                                xAxisProps={{interval: 0, angle: -30, textAnchor: "end", height: 70}}
                                // Device counts are whole numbers; a small tallest bar otherwise gets 0.5 ticks.
                                yAxisProps={{allowDecimals: false}}
                            />
                        ) : (
                            <Text fz="sm" c="dimmed" ta="center" py="xl">
                                No enrolled devices yet
                            </Text>
                        )}
                    </GlassCard>
                </Grid.Col>

                {byOs.length > 0 && (
                    <Grid.Col span={{base: 12, md: 6}}>
                        <GlassCard withBorder>
                            <Text fw={600} fz="sm" mb="md">
                                Devices by OS version
                            </Text>
                            <BarChart
                                h={200}
                                // A device that has not reported its OS comes back with an empty os_version, which
                                // would draw a bar with no label at all.
                                data={byOs.map((d) => ({name: d.os_version || "unknown", Devices: d.count}))}
                                dataKey="name"
                                series={[{name: "Devices", color: "grape"}]}
                                tickLine="none"
                                gridAxis="x"
                                yAxisProps={{allowDecimals: false}}
                            />
                        </GlassCard>
                    </Grid.Col>
                )}
            </Grid>
        </Stack>
    );
}
