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
import { api, type EnrollmentDetails } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";

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
        </>
      )}
    </Stack>
  );
}
