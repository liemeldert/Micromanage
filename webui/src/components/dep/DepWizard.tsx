"use client";

import { useState } from "react";
import {
  Alert,
  Anchor,
  Button,
  Card,
  Code,
  FileButton,
  Group,
  List,
  Stack,
  Stepper,
  Text,
  TextInput,
  ThemeIcon,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconCheck,
  IconCloudDownload,
  IconExternalLink,
  IconKey,
  IconUpload,
} from "@tabler/icons-react";
import { api, ApiError, type DepServerDetail } from "../../../lib/api";
import { useAuth } from "../../../lib/auth-context";

// Guided ABM/ASM link flow. Three steps, mirroring the real Apple workflow:
//   1. name + generate a keypair here; download the PUBLIC key
//   2. upload the public key to ABM, download the encrypted server token (.p7m),
//      upload it back here (we decrypt it with the private key and verify it)
//   3. linked -> hand off to the dashboard
export function DepWizard({
  existing,
  onLinked,
}: {
  existing?: DepServerDetail | null;
  onLinked: (server: DepServerDetail) => void;
}) {
  const { token } = useAuth();
  // Resume at the token step if a keypair was already generated.
  const [active, setActive] = useState(existing?.status === "awaiting_token" ? 1 : 0);
  const [name, setName] = useState(existing?.name ?? "");
  const [server, setServer] = useState<DepServerDetail | null>(existing ?? null);
  const [busy, setBusy] = useState(false);

  async function createServer() {
    if (!token) return;
    const trimmed = name.trim();
    if (!trimmed) {
      notifications.show({ color: "red", message: "Give this connection a name." });
      return;
    }
    setBusy(true);
    try {
      const created = await api.createDepServer(token, trimmed);
      setServer(created);
      setActive(1);
    } catch (e) {
      notifications.show({
        color: "red",
        title: "Could not start linking",
        message: e instanceof ApiError ? e.message : String(e),
      });
    } finally {
      setBusy(false);
    }
  }

  async function uploadToken(file: File | null) {
    if (!token || !server || !file) return;
    setBusy(true);
    try {
      await api.uploadDepToken(token, server.id, file);
      const detail = await api.getDepServer(token, server.id);
      setServer(detail);
      setActive(2);
      notifications.show({
        color: "green",
        title: "Linked to Apple Business/School Manager",
        message: detail.account?.org_name
          ? `Connected to ${detail.account.org_name}.`
          : "Server token verified.",
      });
      onLinked(detail);
    } catch (e) {
      notifications.show({
        color: "red",
        title: "Could not link the token",
        message: e instanceof ApiError ? e.message : String(e),
        autoClose: 8000,
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card withBorder radius="md" p="lg">
      <Stepper active={active} onStepClick={setActive} allowNextStepsSelect={false} size="sm">
        {/* ── Step 1: generate + download public key ─────────────────────── */}
        <Stepper.Step
          label="Generate key"
          description="Create this server's identity"
          icon={<IconKey size={18} />}
        >
          <Stack gap="md" mt="md" maw={640}>
            <Text size="sm" c="dimmed">
              Give this connection a name (e.g. <Code>abm-corp</Code>), then generate a
              keypair. You&apos;ll upload the <b>public</b> key to Apple Business or School
              Manager; the private key never leaves this server.
            </Text>
            <TextInput
              label="Connection name"
              placeholder="abm-corp"
              value={name}
              onChange={(e) => setName(e.currentTarget.value)}
              disabled={!!server}
              maxLength={100}
              w={280}
            />
            {!server ? (
              <Group>
                <Button onClick={createServer} loading={busy} leftSection={<IconKey size={16} />}>
                  Generate keypair
                </Button>
              </Group>
            ) : (
              <Alert color="teal" icon={<IconCheck size={16} />} variant="light">
                Keypair generated for <b>{server.name}</b>. Download the public key below.
              </Alert>
            )}
            {server && (
              <Group>
                <Button
                  component="a"
                  href={api.depPublicKeyPath(server.id)}
                  leftSection={<IconCloudDownload size={16} />}
                  variant="light"
                >
                  Download public key (.pem)
                </Button>
                <Button onClick={() => setActive(1)} variant="subtle">
                  Next: upload token →
                </Button>
              </Group>
            )}
          </Stack>
        </Stepper.Step>

        {/* ── Step 2: upload the encrypted server token ──────────────────── */}
        <Stepper.Step
          label="Link token"
          description="Upload the ABM/ASM server token"
          icon={<IconUpload size={18} />}
        >
          <Stack gap="md" mt="md" maw={680}>
            <Text size="sm" fw={600}>
              In Apple Business Manager (or School Manager):
            </Text>
            <List size="sm" spacing={6} type="ordered">
              <List.Item>
                Go to <b>Settings → Your MDM Servers</b> and add (or edit) a server.
              </List.Item>
              <List.Item>
                Under <b>MDM Server Settings</b>, upload the public key you just downloaded.
              </List.Item>
              <List.Item>
                Click <b>Download Token</b> to get the encrypted server token
                (a <Code>.p7m</Code> file).
              </List.Item>
              <List.Item>Upload that token file below.</List.Item>
            </List>
            <Anchor
              href="https://business.apple.com"
              target="_blank"
              rel="noreferrer"
              size="sm"
            >
              <Group gap={4} component="span">
                Open Apple Business Manager <IconExternalLink size={13} />
              </Group>
            </Anchor>
            <Group>
              {server && (
                <Button
                  component="a"
                  href={api.depPublicKeyPath(server.id)}
                  leftSection={<IconCloudDownload size={16} />}
                  variant="subtle"
                  size="xs"
                >
                  Re-download public key
                </Button>
              )}
            </Group>
            <FileButton onChange={uploadToken} accept=".p7m,application/pkcs7-mime">
              {(props) => (
                <Button {...props} loading={busy} leftSection={<IconUpload size={16} />} w={260}>
                  Upload server token (.p7m)
                </Button>
              )}
            </FileButton>
            {server?.status === "error" && server.last_error && (
              <Alert color="red" title="Last attempt failed" variant="light">
                {server.last_error}
              </Alert>
            )}
          </Stack>
        </Stepper.Step>

        {/* ── Step 3: linked ─────────────────────────────────────────────── */}
        <Stepper.Completed>
          <Stack gap="md" mt="md" align="center" py="lg">
            <ThemeIcon size={54} radius="xl" color="teal">
              <IconCheck size={30} />
            </ThemeIcon>
            <Title order={4}>Connected to Apple Business/School Manager</Title>
            {server?.account?.org_name && (
              <Text c="dimmed">
                Organization: <b>{server.account.org_name}</b>
              </Text>
            )}
            <Text size="sm" c="dimmed" ta="center" maw={480}>
              You can now sync assigned devices and assign an enrollment profile so devices
              provision automatically out of the box.
            </Text>
            <Button onClick={() => server && onLinked(server)}>Go to the dashboard</Button>
          </Stack>
        </Stepper.Completed>
      </Stepper>
    </Card>
  );
}
