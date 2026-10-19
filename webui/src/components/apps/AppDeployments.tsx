import {useEffect, useMemo, useState} from "react";
import {useRouter} from "next/navigation";
import Link from "next/link";
import {Anchor, Badge, Group, Loader, Stack, Table, Text, Tooltip} from "@mantine/core";
import {clickable} from "../../../lib/a11y";
import {api, type AppDeploymentDevice} from "../../../lib/api";
import {DEPLOYMENT_STATUS_COLORS, DEPLOYMENT_STATUS_LABELS} from "../../../lib/status-labels";

// Badge words for the deployment statuses; the longer DEPLOYMENT_STATUS_LABELS text is the tooltip.
const DEPLOYMENT_STATUS_WORDS: Record<string, string> = {
    installed: "Installed",
    accepted: "Accepted",
    installing: "Installing",
    pending: "Pending",
    failed: "Failed",
    unscoped: "Left scope",
};

// Statuses of an install that has not finished or failed yet.
const WORKING_STATUSES = ["pending", "installing", "accepted"];

// The install state of this app on each device it targets.
export function AppDeployments({token, appId}: { token: string | null; appId: string }) {
    const router = useRouter();
    const [devices, setDevices] = useState<AppDeploymentDevice[] | null>(null);
    const [loading, setLoading] = useState(true);
    const [loadError, setLoadError] = useState(false);

    useEffect(() => {
        if (!token) return;
        let cancelled = false;
        setLoading(true);
        setLoadError(false);
        api.getAppDeployments(token, appId)
            .then((r) => {
                if (!cancelled) setDevices(r.devices);
            })
            .catch(() => {
                if (!cancelled) setLoadError(true);
            })
            .finally(() => {
                if (!cancelled) setLoading(false);
            });
        return () => {
            cancelled = true;
        };
    }, [token, appId]);

    const counts = useMemo(() => {
        const rows = devices ?? [];
        return {
            total: rows.length,
            installed: rows.filter((d) => d.status === "installed").length,
            working: rows.filter((d) => WORKING_STATUSES.includes(d.status)).length,
            failed: rows.filter((d) => d.status === "failed").length,
            unscoped: rows.filter((d) => d.status === "unscoped").length,
        };
    }, [devices]);

    return (
        <Stack gap="xs" mt="sm">
            <Text fw={600} fz="sm">Devices</Text>

            {loading ? (
                <Group gap="xs">
                    <Loader size="xs"/>
                    <Text fz="sm" c="dimmed">Counting devices…</Text>
                </Group>
            ) : loadError ? (
                <Text fz="sm" c="dimmed">
                    Could not read the install states for this app.
                </Text>
            ) : counts.total === 0 ? (
                <Text fz="sm" c="dimmed">
                    Not on any device yet. Devices appear here once a version above targets them.
                </Text>
            ) : (
                <>
                    <Group gap={6} wrap="wrap">
                        <Badge variant="light" color={DEPLOYMENT_STATUS_COLORS.installed} size="sm">
                            {counts.installed} installed
                        </Badge>
                        <Badge variant="light" color={DEPLOYMENT_STATUS_COLORS.installing} size="sm">
                            {counts.working} in progress
                        </Badge>
                        <Badge variant="light" color={DEPLOYMENT_STATUS_COLORS.failed} size="sm">
                            {counts.failed} failed
                        </Badge>
                        {counts.unscoped > 0 && (
                            <Badge variant="light" color={DEPLOYMENT_STATUS_COLORS.unscoped} size="sm">
                                {counts.unscoped} left scope
                            </Badge>
                        )}
                        <Text fz="xs" c="dimmed">of {counts.total} devices</Text>
                    </Group>

                    <Table.ScrollContainer minWidth={620}>
                        <Table verticalSpacing={6} fz="sm" highlightOnHover>
                            <Table.Thead>
                                <Table.Tr>
                                    <Table.Th>Device</Table.Th>
                                    <Table.Th>Model</Table.Th>
                                    <Table.Th>Status</Table.Th>
                                    <Table.Th>Target</Table.Th>
                                    <Table.Th>Reports</Table.Th>
                                    <Table.Th>Error</Table.Th>
                                </Table.Tr>
                            </Table.Thead>
                            <Table.Tbody>
                                {(devices ?? []).map((d) => (
                                    <Table.Tr
                                        key={d.device_id}
                                        style={{cursor: "pointer"}}
                                        aria-label={`Open ${d.hostname || d.serial_number}`}
                                        {...clickable(() => router.push(`/devices/${d.device_id}`), "link")}
                                    >
                                        <Table.Td>
                                            <Anchor
                                                component={Link}
                                                href={`/devices/${d.device_id}`}
                                                fz="sm"
                                                fw={500}
                                                onClick={(e) => e.stopPropagation()}
                                            >
                                                {d.hostname || d.serial_number}
                                            </Anchor>
                                            {d.hostname && (
                                                <Text fz="xs" c="dimmed">{d.serial_number}</Text>
                                            )}
                                        </Table.Td>
                                        <Table.Td>
                                            <Text fz="xs" c="dimmed">{d.device_model || "--"}</Text>
                                        </Table.Td>
                                        <Table.Td>
                                            <Tooltip
                                                label={DEPLOYMENT_STATUS_LABELS[d.status] ?? d.status}
                                                withArrow
                                                disabled={!DEPLOYMENT_STATUS_LABELS[d.status]}
                                            >
                                                <Badge
                                                    variant="light"
                                                    size="sm"
                                                    color={DEPLOYMENT_STATUS_COLORS[d.status] ?? "gray"}
                                                >
                                                    {DEPLOYMENT_STATUS_WORDS[d.status] ?? d.status}
                                                </Badge>
                                            </Tooltip>
                                            {d.status === "failed" && d.failed_attempts > 1 && (
                                                <Text fz="xs" c="red" mt={2}>
                                                    {d.failed_attempts} attempts
                                                </Text>
                                            )}
                                        </Table.Td>
                                        <Table.Td>
                                            {d.desired_version
                                                ? <Text fz="xs">v{d.desired_version}</Text>
                                                : <Text fz="xs" c="dimmed">--</Text>}
                                        </Table.Td>
                                        <Table.Td>
                                            {d.reported_version
                                                ? <Text fz="xs">{d.reported_version}</Text>
                                                : <Text fz="xs" c="dimmed">--</Text>}
                                        </Table.Td>
                                        <Table.Td>
                                            {d.last_error ? (
                                                <Tooltip label={d.last_error} withArrow multiline w={360}>
                                                    <Text fz="xs" c="red" lineClamp={2}>{d.last_error}</Text>
                                                </Tooltip>
                                            ) : (
                                                <Text fz="xs" c="dimmed">--</Text>
                                            )}
                                        </Table.Td>
                                    </Table.Tr>
                                ))}
                            </Table.Tbody>
                        </Table>
                    </Table.ScrollContainer>
                </>
            )}
        </Stack>
    );
}
