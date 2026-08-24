"use client";

import {useCallback, useEffect, useState} from "react";
import {
    ActionIcon,
    Alert,
    Badge,
    Box,
    Button,
    Code,
    CopyButton,
    Divider,
    Group,
    List,
    Loader,
    Stack,
    Table,
    Text,
    Tooltip,
} from "@mantine/core";
import {notifications} from "@mantine/notifications";
import {IconAlertTriangle, IconCheck, IconCopy, IconDownload, IconQrcode, IconRefresh,} from "@tabler/icons-react";
import QRCode from "react-qr-code";
import {api, type EnrollmentAttempt, type EnrollmentDetails} from "../../../../lib/api";
import {useAuth} from "../../../../lib/auth-context";
import {PageHeader} from "@/components/layout/PageHeader";
import {PageSkeleton} from "@/components/layout/PageSkeleton";
import {GlassCard} from "@/components/ui/GlassCard";

// Mirrors the outcomes webhook_handler writes (controller/services/webhook_handler.py).
const ATTEMPT_OUTCOME_LABELS: Record<string, string> = {
    no_tenant: "No tenant resolved",
    no_serial: "No serial number",
    bad_tenant_claim: "Untrusted tenant claim",
    unsigned_tenant_claim: "Unsigned tenant claim",
    unknown_serial: "Unprovisioned serial",
    serial_conflict: "Serial held by another device",
};

// Renewal-reminder severity for an expiry date entered in Settings. A null days_remaining shows nothing.
function expirySeverity(daysRemaining: number | null): "red" | "orange" | null {
    if (daysRemaining === null) return null;
    if (daysRemaining < 7) return "red"; // includes already-expired (negative)
    if (daysRemaining < 30) return "orange";
    return null;
}

function expiryMessage(label: string, expiresAt: string, daysRemaining: number) {
    const date = new Date(expiresAt).toLocaleDateString();
    if (daysRemaining < 0) {
        return `${label} expired ${date} (${Math.abs(daysRemaining)} day(s) ago).`;
    }
    if (daysRemaining === 0) {
        return `${label} expires today (${date}).`;
    }
    return `${label} expires ${date}, ${daysRemaining} day(s) remaining.`;
}

function RenewalAlert({
                          label,
                          expiresAt,
                          daysRemaining,
                      }: {
    label: string;
    expiresAt: string | null;
    daysRemaining: number | null;
}) {
    const severity = expirySeverity(daysRemaining);
    if (!severity || expiresAt === null || daysRemaining === null) return null;
    return (
        <Alert
            color={severity}
            variant="light"
            icon={<IconAlertTriangle size={16}/>}
            title={severity === "red" ? `${label} renewal overdue` : `${label} renewal due soon`}
        >
            <Text fz="sm">{expiryMessage(label, expiresAt, daysRemaining)} Update the date in Settings.</Text>
        </Alert>
    );
}

function DetailRow({label, value}: { label: string; value: string | null }) {
    return (
        <Group justify="space-between" wrap="nowrap" gap="md" align="flex-start">
            <Text fz="sm" c="dimmed" style={{flexShrink: 0}}>
                {label}
            </Text>
            <Group gap={4} wrap="nowrap" style={{minWidth: 0}}>
                <Code style={{whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 320}}>
                    {value ?? "--"}
                </Code>
                {value && (
                    <CopyButton value={value}>
                        {({copied, copy}) => (
                            <Tooltip label={copied ? "Copied" : "Copy"} withArrow>
                                <ActionIcon variant="subtle" color="gray" size="sm" onClick={copy}>
                                    {copied ? <IconCheck size={14}/> : <IconCopy size={14}/>}
                                </ActionIcon>
                            </Tooltip>
                        )}
                    </CopyButton>
                )}
            </Group>
        </Group>
    );
}

// The tenant-scoped list, and the admin-only list of check-ins that resolved no tenant. Two endpoints feed one
// table, since the rows carry the same fields.
const fetchTenantAttempts = (token: string) => api.getEnrollmentAttempts(token, {limit: 20});
const fetchUnattributedAttempts = (token: string) =>
    api.getUnattributedEnrollmentAttempts(token, {limit: 20});

function AttemptsCard({
                          title,
                          description,
                          emptyText,
                          fetchAttempts,
                      }: {
    title: string;
    description: string;
    emptyText: string;
    fetchAttempts: (token: string) => Promise<{ attempts: EnrollmentAttempt[] }>;
}) {
    const {token} = useAuth();
    const [attempts, setAttempts] = useState<EnrollmentAttempt[] | null>(null);
    const [loading, setLoading] = useState(true);

    const load = useCallback(async () => {
        if (!token) return;
        setLoading(true);
        try {
            const res = await fetchAttempts(token);
            setAttempts(res.attempts);
        } catch (e: unknown) {
            notifications.show({color: "red", message: (e as Error).message});
        } finally {
            setLoading(false);
        }
    }, [token, fetchAttempts]);

    useEffect(() => {
        load();
    }, [load]);

    return (
        <GlassCard withBorder padding="lg">
            <Group justify="space-between" mb="md">
                <Stack gap={0}>
                    <Text fw={600}>{title}</Text>
                    <Text fz="xs" c="dimmed">
                        {description}
                    </Text>
                </Stack>
                <ActionIcon variant="subtle" onClick={load} loading={loading}>
                    <IconRefresh size={16}/>
                </ActionIcon>
            </Group>

            {loading ? (
                <Box py="md" ta="center">
                    <Loader size="sm"/>
                </Box>
            ) : !attempts || attempts.length === 0 ? (
                <Text c="dimmed" fz="sm" ta="center" py="md">
                    {emptyText}
                </Text>
            ) : (
                <Table highlightOnHover verticalSpacing="xs" fz="sm">
                    <Table.Thead>
                        <Table.Tr>
                            <Table.Th>Outcome</Table.Th>
                            <Table.Th>UDID / Serial</Table.Th>
                            <Table.Th>Topic</Table.Th>
                            <Table.Th>When</Table.Th>
                        </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                        {attempts.map((a) => (
                            <Table.Tr key={a.id}>
                                <Table.Td>
                                    <Badge size="sm" color="red" variant="light">
                                        {ATTEMPT_OUTCOME_LABELS[a.outcome] ?? a.outcome}
                                    </Badge>
                                </Table.Td>
                                <Table.Td>
                                    <Text fz="xs" style={{fontFamily: "monospace"}}>
                                        {a.udid ?? a.serial_number ?? "--"}
                                    </Text>
                                </Table.Td>
                                <Table.Td>
                                    <Text fz="xs" c="dimmed">{a.topic ?? "--"}</Text>
                                </Table.Td>
                                <Table.Td>
                                    <Text fz="xs" c="dimmed">
                                        {a.created_at ? new Date(a.created_at).toLocaleString() : "--"}
                                    </Text>
                                </Table.Td>
                            </Table.Tr>
                        ))}
                    </Table.Tbody>
                </Table>
            )}
        </GlassCard>
    );
}

export default function EnrollmentPage() {
    const {token, isAdmin} = useAuth();
    const [details, setDetails] = useState<EnrollmentDetails | null>(null);
    const [loading, setLoading] = useState(true);

    const load = useCallback(async () => {
        if (!token) return;
        setLoading(true);
        try {
            setDetails(await api.getEnrollment(token));
        } catch (e: unknown) {
            notifications.show({color: "red", message: (e as Error).message});
        } finally {
            setLoading(false);
        }
    }, [token]);

    useEffect(() => {
        load();
    }, [load]);

    const downloadPath =
        details && details.enroll_url
            ? api.enrollmentDownloadPath(details.tenant_id, details.token)
            : null;

    return (
        <Stack gap="lg">
            <PageHeader
                description="Install this profile on a device to enroll it by hand. It is specific to your organization. The QR code opens the same link, so you do not have to type the URL into the device."
                actions={
                    <Button variant="light" leftSection={<IconRefresh size={14}/>} onClick={load}>
                        Refresh
                    </Button>
                }
            />

            <Alert variant="light" color="gray" icon={<IconAlertTriangle size={16}/>}>
                <Text fz="xs">
                    The enrollment URL embeds a secret token and the profile contains a SCEP challenge.
                    Keep these private and do not share them publicly. Anyone with access can enroll devices into your
                    organization.
                </Text>
            </Alert>

            {loading ? (
                <PageSkeleton variant="form"/>
            ) : !details ? (
                <Text c="dimmed">Could not load the enrollment details. Use Refresh to try again.</Text>
            ) : (
                <>
                    {!details.configured && (
                        <Alert
                            color="orange"
                            variant="light"
                            icon={<IconAlertTriangle size={16}/>}
                            title="Enrollment is not fully configured"
                        >
                            <Text fz="sm" mb={4}>
                                Set the following in your environment, then refresh:
                            </Text>
                            <List size="sm" spacing={2}>
                                {details.missing.map((m) => (
                                    <List.Item key={m}>
                                        <Code>{m}</Code>
                                    </List.Item>
                                ))}
                            </List>
                        </Alert>
                    )}

                    <RenewalAlert
                        label="APNs certificate"
                        expiresAt={details.apns_cert_expires_at}
                        daysRemaining={details.apns_days_remaining}
                    />
                    <RenewalAlert
                        label="ABM/ASM server token"
                        expiresAt={details.dep_token_expires_at}
                        daysRemaining={details.dep_days_remaining}
                    />

                    <Group align="stretch" gap="lg" wrap="wrap">
                        {/* Details */}
                        <GlassCard withBorder padding="lg" style={{flex: "1 1 420px", minWidth: 320}}>
                            <Group justify="space-between" mb="md">
                                <Text fw={600}>Manual enrollment</Text>
                                <Badge color={details.configured ? "teal" : "orange"} variant="light">
                                    {details.configured ? "Ready" : "Needs config"}
                                </Badge>
                            </Group>
                            <Stack gap="sm">
                                <DetailRow label="Organization" value={details.organization}/>
                                <DetailRow label="MDM server" value={details.mdm_server_url}/>
                                <DetailRow label="SCEP URL" value={details.scep_url}/>
                                <DetailRow label="APNs topic" value={details.topic}/>
                                <DetailRow label="Hostname" value={details.hostname}/>
                                <Divider my="xs"/>
                                <DetailRow label="Enrollment URL" value={details.enroll_url}/>
                                <Group mt="xs">
                                    {downloadPath && (
                                        <Button
                                            component="a"
                                            href={downloadPath}
                                            leftSection={<IconDownload size={16}/>}
                                        >
                                            Download profile
                                        </Button>
                                    )}
                                    {details.enroll_url && (
                                        <CopyButton value={details.enroll_url}>
                                            {({copied, copy}) => (
                                                <Button variant="default" leftSection={<IconCopy size={16}/>}
                                                        onClick={copy}>
                                                    {copied ? "Copied" : "Copy link"}
                                                </Button>
                                            )}
                                        </CopyButton>
                                    )}
                                </Group>
                            </Stack>
                        </GlassCard>

                        {/* QR */}
                        <GlassCard withBorder padding="lg" style={{flex: "0 1 280px", minWidth: 240}}>
                            <Stack align="center" gap="sm">
                                <Group gap={6}>
                                    <IconQrcode size={18}/>
                                    <Text fw={600}>Scan to enroll</Text>
                                </Group>
                                {details.enroll_url ? (
                                    <>
                                        <Box p="md" bg="white" style={{borderRadius: "var(--mantine-radius-sm)"}}>
                                            <QRCode value={details.enroll_url} size={180}/>
                                        </Box>
                                        <Text fz="xs" c="dimmed" ta="center">
                                            Scan with the device&apos;s camera and open the link. The profile downloads,
                                            then you install it from Settings.
                                        </Text>
                                    </>
                                ) : (
                                    <Text fz="sm" c="dimmed" ta="center" py="xl">
                                        Set <Code>PUBLIC_API_URL</Code> to generate an enrollment link.
                                    </Text>
                                )}
                            </Stack>
                        </GlassCard>
                    </Group>

                    <AttemptsCard
                        title="Recent failed attempts"
                        description={
                            "Check-ins that reached the controller but couldn't be matched to a device. " +
                            "SCEP-stage failures (before a device ever talks to the controller) aren't visible here."
                        }
                        emptyText="No failed attempts logged."
                        fetchAttempts={fetchTenantAttempts}
                    />

                    {isAdmin && (
                        <AttemptsCard
                            title="Not attributed to any tenant"
                            description={
                                "Check-ins that named no tenant this controller recognises, so they belong to no " +
                                "organization and are not in the list above. Usually a profile from another " +
                                "deployment, or one edited by hand."
                            }
                            emptyText="No unattributed check-ins logged."
                            fetchAttempts={fetchUnattributedAttempts}
                        />
                    )}
                </>
            )}
        </Stack>
    );
}
