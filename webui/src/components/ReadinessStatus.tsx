"use client";

// GET /api/v1/readiness rendered two ways: a dashboard banner that appears only when something is wrong, and a
// settings section listing every capability. Both take what the useReadiness hook in lib/readiness.ts returns.

import {Badge, Card, Group, Loader, Stack, Text, Title, Tooltip} from "@mantine/core";
import {IconAlertTriangle, IconCircleCheck, IconInfoCircle, IconShieldCheck} from "@tabler/icons-react";
import Link from "next/link";
import type {Readiness, ReadinessCapability} from "../../lib/api";
import {GlassCard} from "./ui/GlassCard";
import {GlassAlert} from "./ui/GlassAlert";

// Stable capability ids from the readiness endpoint, given a human label. An id missing from this map still renders,
// under its raw id.
const CAPABILITY_LABELS: Record<string, string> = {
    enroll: "Enrollment",
    ade: "Automated Device Enrollment",
    app_install: "App installs",
    ddm_bridge: "DDM legacy bridge",
    ddm_sync: "DDM sync",
    mdm_enqueue: "MDM commands",
    escrow: "Secret escrow",
    webhook_ingest: "Webhook ingest",
};
const capabilityLabel = (id: string) => CAPABILITY_LABELS[id] ?? id;

/** Setting names as chips, never values. Missing is kept apart from broken (set but unusable, such as a certificate
 * path with no certificate behind it) because the fix differs. */
function SettingChips({missing, broken}: { missing: string[]; broken: string[] }) {
    if (missing.length === 0 && broken.length === 0) return null;
    return (
        <Group gap={10} wrap="wrap">
            {missing.length > 0 && (
                <Group gap={4} wrap="wrap">
                    <Text fz={10} c="dimmed" tt="uppercase" fw={600}>not set</Text>
                    {missing.map((m) => (
                        <Badge key={m} size="xs" variant="outline" color="gray" style={{fontFamily: "monospace"}}>
                            {m}
                        </Badge>
                    ))}
                </Group>
            )}
            {broken.length > 0 && (
                <Group gap={4} wrap="wrap">
                    <Text fz={10} c="orange" tt="uppercase" fw={600}>set but unusable</Text>
                    {broken.map((b) => (
                        <Badge key={b} size="xs" variant="light" color="orange" style={{fontFamily: "monospace"}}>
                            {b}
                        </Badge>
                    ))}
                </Group>
            )}
        </Group>
    );
}

/** What to do about a blocked capability: a tenant setting is editable in Settings, a deployment setting is an
 * environment variable this console cannot write. */
function ScopeHint({scope}: { scope: ReadinessCapability["scope"] }) {
    if (scope === "tenant") {
        return (
            <Text
                component={Link}
                href="/settings"
                fz="xs"
                c="blue"
                style={{textDecoration: "underline"}}
            >
                Fix in Settings
            </Text>
        );
    }
    return (
        <Text fz="xs" c="dimmed">
            Environment setting; change it and restart the controller.
        </Text>
    );
}

/** Dashboard banner. Renders nothing while loading, when the route is absent from this build, or when every
 * capability is ready with no warnings. */
export function ReadinessBanner({
                                    readiness,
                                    loading,
                                    error,
                                }: {
    readiness: Readiness | null;
    loading: boolean;
    error: string | null;
}) {
    if (loading || !readiness) {
        // A fetch failure gets one quiet line. The route being absent from this build leaves both readiness and
        // error null, and renders nothing.
        if (error) {
            return (
                <GlassAlert color="gray" variant="light" icon={<IconInfoCircle size={16}/>}>
                    Couldn&apos;t check deployment readiness: {error}
                </GlassAlert>
            );
        }
        return null;
    }

    const blocked = readiness.capabilities.filter((c) => !c.ready);
    const warned = readiness.capabilities.filter((c) => c.ready && c.warnings.length > 0);

    if (blocked.length === 0 && warned.length === 0) return null;

    if (blocked.length > 0) {
        return (
            <GlassAlert color="red" variant="light" icon={<IconAlertTriangle size={16}/>}
                        title="Some capabilities are not ready">
                <Stack gap={8}>
                    {blocked.map((c) => (
                        <Stack key={c.capability} gap={2}>
                            <Text fz="sm">
                                <b>{capabilityLabel(c.capability)}:</b> {c.reason}
                            </Text>
                            <Group gap="sm" wrap="wrap">
                                <SettingChips missing={c.missing} broken={c.broken}/>
                                <ScopeHint scope={c.scope}/>
                            </Group>
                        </Stack>
                    ))}
                </Stack>
            </GlassAlert>
        );
    }

    // Ready, with something worth knowing. Quieter than the blocked case: a warning stops nothing.
    return (
        <GlassAlert color="yellow" variant="light" icon={<IconInfoCircle size={16}/>} title="Ready, with warnings">
            <Stack gap={4}>
                {warned.flatMap((c) =>
                    c.warnings.map((w, i) => (
                        <Text key={`${c.capability}-${i}`} fz="sm">
                            <b>{capabilityLabel(c.capability)}:</b> {w}
                        </Text>
                    )),
                )}
            </Stack>
        </GlassAlert>
    );
}

/** Full listing for the settings page: every capability whatever its state, in the order the server sends them. */
export function ReadinessSection({
                                     readiness,
                                     loading,
                                     error,
                                 }: {
    readiness: Readiness | null;
    loading: boolean;
    error: string | null;
}) {
    return (
        <GlassCard withBorder p="lg">
            <Group justify="space-between" mb="xs">
                <Title order={4}>Readiness</Title>
                {readiness && (
                    <Badge
                        variant="light"
                        color={readiness.ready ? "teal" : "red"}
                        leftSection={readiness.ready ? <IconShieldCheck size={12}/> : <IconAlertTriangle size={12}/>}
                    >
                        {readiness.ready ? "All capabilities ready" : "Action needed"}
                    </Badge>
                )}
            </Group>
            <Text fz="sm" c="dimmed" mb="md">
                Whether this deployment and tenant have what each capability needs to run.
            </Text>

            {loading ? (
                <Group justify="center" py="md">
                    <Loader size="sm"/>
                </Group>
            ) : !readiness ? (
                <Text fz="sm" c="dimmed">
                    {error
                        ? `Couldn't load readiness: ${error}`
                        : "Readiness data isn't available from this controller yet."}
                </Text>
            ) : (
                <Stack gap="sm">
                    {readiness.capabilities.map((c) => (
                        <Card key={c.capability} withBorder radius="sm" p="sm" bg="var(--mantine-color-default-hover)">
                            <Group justify="space-between" align="flex-start" wrap="nowrap">
                                <Stack gap={4} style={{flex: 1, minWidth: 0}}>
                                    <Group gap={8}>
                                        <Text fw={600} fz="sm">
                                            {capabilityLabel(c.capability)}
                                        </Text>
                                        <Badge size="xs" variant="light" color="gray" tt="none">
                                            {c.scope}
                                        </Badge>
                                    </Group>
                                    {c.reason && (
                                        <Text fz="xs" c={c.ready ? "dimmed" : "red"}>
                                            {c.reason}
                                        </Text>
                                    )}
                                    <SettingChips missing={c.missing} broken={c.broken}/>
                                    {c.warnings.map((w, i) => (
                                        <Text key={i} fz="xs" c="yellow.7">
                                            {w}
                                        </Text>
                                    ))}
                                    {c.ready && !c.reason && c.warnings.length === 0 && (
                                        <Text fz="xs" c="dimmed">
                                            Nothing to report.
                                        </Text>
                                    )}
                                </Stack>
                                <Tooltip label={c.ready ? "Ready" : "Not ready"} withArrow>
                                    <Badge
                                        variant="light"
                                        color={c.ready ? "teal" : "red"}
                                        leftSection={c.ready ? <IconCircleCheck size={12}/> :
                                            <IconAlertTriangle size={12}/>}
                                        style={{flexShrink: 0}}
                                    >
                                        {c.ready ? "ready" : "blocked"}
                                    </Badge>
                                </Tooltip>
                            </Group>
                        </Card>
                    ))}
                </Stack>
            )}
        </GlassCard>
    );
}
