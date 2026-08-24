"use client";

import {useState} from "react";
import {
    Alert,
    Anchor,
    Button,
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
import {notifications} from "@mantine/notifications";
import {modals} from "@mantine/modals";
import {IconCheck, IconCloudDownload, IconExternalLink, IconKey, IconTrash, IconUpload,} from "@tabler/icons-react";
import {api, ApiError, type DepServerCreated, type DepServerDetail} from "../../../lib/api";
import {saveTextFile} from "../../../lib/download";
import {useAuth} from "../../../lib/auth-context";
import {GlassCard} from "../ui/GlassCard";

// Guided ABM/ASM link flow, following Apple's own: name the connection and generate a keypair here,
// take the public key to ABM and bring back the encrypted server token (.p7m), which is uploaded here
// to be decrypted with the private key and verified. The last step hands off to the dashboard.
export function DepWizard({
                              existing,
                              onLinked,
                              onRemoved,
                          }: {
    existing?: DepServerDetail | null;
    onLinked: (server: DepServerDetail) => void;
    onRemoved?: () => void;
}) {
    const {token} = useAuth();
    // Resume at the token step once a keypair exists: a failed or unfinished upload leaves the keypair
    // usable, so the retry is the token rather than the key.
    const [active, setActive] = useState(
        existing && existing.status !== "linked" && existing.has_public_cert ? 1 : 0,
    );
    const [name, setName] = useState(existing?.name ?? "");
    // DepServerCreated because POST /dep/servers returns no enroll_url or profiles, neither of which
    // the wizard uses. A DepServerDetail still fits.
    const [server, setServer] = useState<DepServerCreated | null>(existing ?? null);
    // The full detail, which exists only after GET /dep/servers/{id}. Kept apart from server so the
    // handoff cannot be given a half-populated record from the create call.
    const [linked, setLinked] = useState<DepServerDetail | null>(
        existing && existing.status === "linked" ? existing : null,
    );
    const [busy, setBusy] = useState(false);

    async function createServer() {
        if (!token) return;
        const trimmed = name.trim();
        if (!trimmed) {
            notifications.show({color: "red", message: "Give this connection a name."});
            return;
        }
        setBusy(true);
        try {
            const created = await api.createDepServer(token, trimmed);
            setServer(created);
            // Stay on step 1: it is the only place the public key download is a primary action.
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

    function downloadPublicKey() {
        // The public cert is not secret and arrives with the server detail, so save it client-side.
        // A plain link to the download endpoint would carry no auth token and be refused.
        if (!server?.public_cert_pem) {
            notifications.show({color: "red", message: "No public key available yet."});
            return;
        }
        saveTextFile(`${server.name}-public-key.pem`, server.public_cert_pem, "application/x-pem-file");
    }

    async function uploadToken(file: File | null) {
        if (!token || !server || !file) return;
        setBusy(true);
        try {
            await api.uploadDepToken(token, server.id, file);
            const detail = await api.getDepServer(token, server.id);
            setServer(detail);
            setLinked(detail);
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
            // Refresh so last_error shows inline under the upload button.
            try {
                const detail = await api.getDepServer(token, server.id);
                setServer(detail);
            } catch {
                /* keep the notification; nothing more to show */
            }
        } finally {
            setBusy(false);
        }
    }

    function confirmRemove() {
        if (!server) return;
        modals.openConfirmModal({
            title: `Remove "${server.name}"?`,
            children: (
                <Text size="sm">
                    This discards the connection and its generated keypair. Nothing is sent to Apple,
                    and no enrolled device is affected. Use this to clear out a connection you never
                    finished setting up.
                </Text>
            ),
            labels: {confirm: "Remove", cancel: "Cancel"},
            confirmProps: {color: "red"},
            onConfirm: async () => {
                if (!token) return;
                try {
                    await api.removeDepServer(token, server.id);
                    notifications.show({color: "green", message: "Connection removed."});
                    onRemoved?.();
                } catch (e) {
                    notifications.show({
                        color: "red",
                        title: "Could not remove connection",
                        message: e instanceof ApiError ? e.message : String(e),
                    });
                }
            },
        });
    }

    return (
        <GlassCard withBorder p="lg">
            <Stepper active={active} onStepClick={setActive} allowNextStepsSelect={false} size="sm">
                {/*  Step 1: generate + download public key  */}
                <Stepper.Step
                    label="Generate key"
                    description="Create this server's identity"
                    icon={<IconKey size={18}/>}
                >
                    <Stack gap="md" mt="md" maw={640}>
                        <Text size="sm" c="dimmed">
                            Give this connection a name (e.g. <Code>asm-district</Code>), then generate a
                            keypair. You&apos;ll upload the <b>public</b> key to Apple Business or School
                            Manager; the private key never leaves this server.
                        </Text>
                        <TextInput
                            label="Connection name"
                            placeholder="asm-district"
                            value={name}
                            onChange={(e) => setName(e.currentTarget.value)}
                            disabled={!!server}
                            maxLength={100}
                            w={280}
                        />
                        {!server ? (
                            <Group>
                                <Button onClick={createServer} loading={busy} leftSection={<IconKey size={16}/>}>
                                    Generate keypair
                                </Button>
                            </Group>
                        ) : (
                            <Alert color="teal" icon={<IconCheck size={16}/>} variant="light">
                                Keypair generated for <b>{server.name}</b>. Download the public key below.
                            </Alert>
                        )}
                        {server && (
                            <Group>
                                <Button
                                    onClick={() => downloadPublicKey()}
                                    disabled={!server.public_cert_pem}
                                    leftSection={<IconCloudDownload size={16}/>}
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

                {/*  Step 2: upload the encrypted server token  */}
                <Stepper.Step
                    label="Link token"
                    description="Upload the ABM/ASM server token"
                    icon={<IconUpload size={18}/>}
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
                                Open Apple Business Manager <IconExternalLink size={13}/>
                            </Group>
                        </Anchor>
                        <Group>
                            {server && (
                                <Button
                                    onClick={() => downloadPublicKey()}
                                    disabled={!server.public_cert_pem}
                                    leftSection={<IconCloudDownload size={16}/>}
                                    variant="subtle"
                                    size="xs"
                                >
                                    Re-download public key
                                </Button>
                            )}
                        </Group>
                        <FileButton onChange={uploadToken} accept=".p7m,application/pkcs7-mime">
                            {(props) => (
                                <Button {...props} loading={busy} leftSection={<IconUpload size={16}/>} w={260}>
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

                {/*  Step 3: linked  */}
                <Stepper.Completed>
                    <Stack gap="md" mt="md" align="center" py="lg">
                        <ThemeIcon size={54} radius="xl" color="teal">
                            <IconCheck size={30}/>
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
                        <Button disabled={!linked} onClick={() => linked && onLinked(linked)}>Go to the
                            dashboard</Button>
                    </Stack>
                </Stepper.Completed>
            </Stepper>

            {/* Discard a connection that was started but never linked. */}
            {server && server.status !== "linked" && onRemoved && (
                <Group justify="flex-end" mt="lg">
                    <Button
                        variant="subtle"
                        color="red"
                        size="xs"
                        leftSection={<IconTrash size={14}/>}
                        onClick={confirmRemove}
                    >
                        Remove this connection
                    </Button>
                </Group>
            )}
        </GlassCard>
    );
}
