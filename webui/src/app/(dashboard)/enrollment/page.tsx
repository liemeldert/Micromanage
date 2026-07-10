"use client";

import { useCallback, useEffect, useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Box,
  Button,
  Card,
  Code,
  CopyButton,
  Divider,
  Group,
  List,
  Loader,
  Stack,
  Table,
  Text,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconAlertTriangle,
  IconCheck,
  IconCopy,
  IconDownload,
  IconQrcode,
  IconRefresh,
} from "@tabler/icons-react";
import QRCode from "react-qr-code";
import { api, type EnrollmentAttempt, type EnrollmentDetails } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";

const ATTEMPT_OUTCOME_LABELS: Record<string, string> = {
  no_tenant: "No tenant resolved",
  no_serial: "No serial number",
};

// Renewal-reminder severity for an admin-entered expiry date. Unset (null
// days_remaining) is never shown -- there's nothing to warn about yet.
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
  return `${label} expires ${date} -- ${daysRemaining} day(s) remaining.`;
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
      icon={<IconAlertTriangle size={16} />}
      title={severity === "red" ? `${label} renewal overdue` : `${label} renewal due soon`}
    >
      <Text fz="sm">{expiryMessage(label, expiresAt, daysRemaining)} Update the date in Settings.</Text>
    </Alert>
  );
}

function DetailRow({ label, value }: { label: string; value: string | null }) {
  return (
    <Group justify="space-between" wrap="nowrap" gap="md" align="flex-start">
      <Text fz="sm" c="dimmed" style={{ flexShrink: 0 }}>
        {label}
      </Text>
      <Group gap={4} wrap="nowrap" style={{ minWidth: 0 }}>
        <Code style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 320 }}>
          {value ?? "--"}
        </Code>
        {value && (
          <CopyButton value={value}>
            {({ copied, copy }) => (
              <Tooltip label={copied ? "Copied" : "Copy"} withArrow>
                <ActionIcon variant="subtle" color="gray" size="sm" onClick={copy}>
                  {copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
                </ActionIcon>
              </Tooltip>
            )}
          </CopyButton>
        )}
      </Group>
    </Group>
  );
}

// Recent POST-SCEP webhook check-ins that never became a device -- catches
// only failures after a device reaches the controller (SCEP-stage drops,
// where the device never talks to the controller at all, are invisible).
function RecentAttemptsCard() {
  const { token } = useAuth();
  const [attempts, setAttempts] = useState<EnrollmentAttempt[] | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = await api.getEnrollmentAttempts(token, { limit: 20 });
      setAttempts(res.attempts);
    } catch (e: unknown) {
      notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <Card withBorder radius="md" padding="lg">
      <Group justify="space-between" mb="md">
        <Stack gap={0}>
          <Text fw={600}>Recent failed attempts</Text>
          <Text fz="xs" c="dimmed">
            Check-ins that reached the controller but couldn&apos;t be matched to a device. SCEP-stage
            failures (before a device ever talks to the controller) aren&apos;t visible here.
          </Text>
        </Stack>
        <ActionIcon variant="subtle" onClick={load} loading={loading}>
          <IconRefresh size={16} />
        </ActionIcon>
      </Group>

      {loading ? (
        <Box py="md" ta="center">
          <Loader size="sm" />
        </Box>
      ) : !attempts || attempts.length === 0 ? (
        <Text c="dimmed" fz="sm" ta="center" py="md">
          No failed attempts logged.
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
                  <Text fz="xs" style={{ fontFamily: "monospace" }}>
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
    </Card>
  );
}

export default function EnrollmentPage() {
  const { token } = useAuth();
  const [details, setDetails] = useState<EnrollmentDetails | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      setDetails(await api.getEnrollment(token));
    } catch (e: unknown) {
      notifications.show({ color: "red", message: (e as Error).message });
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
      <Group justify="space-between" align="flex-start">
        <Stack gap={0}>
          <Title order={2}>Enrollment</Title>
          <Text fz="sm" c="dimmed">
            This profile can be used to manually enroll a device into management. It is specific to your organization and should be kept private. The QR code below is a convenient way to enroll a device without needing to copy the URL.
          </Text>
        </Stack>
        <Button variant="light" leftSection={<IconRefresh size={14} />} onClick={load}>
          Refresh
        </Button>
      </Group>

       <Alert variant="light" color="gray" icon={<IconAlertTriangle size={16} />}>
            <Text fz="xs">
              The enrollment URL embeds a secret token and the profile contains a SCEP challenge.
              Keep these private and do not share them publicly. Anyone with access can enroll devices into your organization.
            </Text>
      </Alert>

      {loading ? (
        <Box py={80} ta="center">
          <Loader />
        </Box>
      ) : !details ? (
        <Text c="dimmed">Could not load enrollment details!</Text>
      ) : (
        <>
          {!details.configured && (
            <Alert
              color="orange"
              variant="light"
              icon={<IconAlertTriangle size={16} />}
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
            label="DEP token"
            expiresAt={details.dep_token_expires_at}
            daysRemaining={details.dep_days_remaining}
          />

          <Group align="stretch" gap="lg" wrap="wrap">
            {/* Details */}
            <Card withBorder radius="md" padding="lg" style={{ flex: "1 1 420px", minWidth: 320 }}>
              <Group justify="space-between" mb="md">
                <Text fw={600}>Manual enrollment</Text>
                <Badge color={details.configured ? "teal" : "orange"} variant="light">
                  {details.configured ? "Ready" : "Needs config"}
                </Badge>
              </Group>
              <Stack gap="sm">
                <DetailRow label="Organization" value={details.organization} />
                <DetailRow label="MDM server" value={details.mdm_server_url} />
                <DetailRow label="SCEP URL" value={details.scep_url} />
                <DetailRow label="APNs topic" value={details.topic} />
                <DetailRow label="Hostname" value={details.hostname} />
                <Divider my="xs" />
                <DetailRow label="Enrollment URL" value={details.enroll_url} />
                <Group mt="xs">
                  {downloadPath && (
                    <Button
                      component="a"
                      href={downloadPath}
                      leftSection={<IconDownload size={16} />}
                    >
                      Download profile
                    </Button>
                  )}
                  {details.enroll_url && (
                    <CopyButton value={details.enroll_url}>
                      {({ copied, copy }) => (
                        <Button variant="default" leftSection={<IconCopy size={16} />} onClick={copy}>
                          {copied ? "Copied" : "Copy link"}
                        </Button>
                      )}
                    </CopyButton>
                  )}
                </Group>
              </Stack>
            </Card>

            {/* QR */}
            <Card withBorder radius="md" padding="lg" style={{ flex: "0 1 280px", minWidth: 240 }}>
              <Stack align="center" gap="sm">
                <Group gap={6}>
                  <IconQrcode size={18} />
                  <Text fw={600}>Scan to enroll</Text>
                </Group>
                {details.enroll_url ? (
                  <>
                    <Box p="md" bg="white" style={{ borderRadius: 8 }}>
                      <QRCode value={details.enroll_url} size={180} />
                    </Box>
                    <Text fz="xs" c="dimmed" ta="center">
                      Scan with the device&apos;s camera, then install the downloaded profile in
                      Settings.
                    </Text>
                  </>
                ) : (
                  <Text fz="sm" c="dimmed" ta="center" py="xl">
                    Set <Code>PUBLIC_API_URL</Code> to generate an enrollment link.
                  </Text>
                )}
              </Stack>
            </Card>
          </Group>

          <RecentAttemptsCard />
        </>
      )}
    </Stack>
  );
}
