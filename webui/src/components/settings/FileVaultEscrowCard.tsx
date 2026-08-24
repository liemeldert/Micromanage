"use client";

// Admin card for the tenant's FileVault recovery-key escrow keypair. The private key never leaves the server, so this
// card offers only the certificate; a recovery key itself is revealed by breaking the glass on a device page.

import {useEffect, useState} from "react";
import {Alert, Badge, Box, Button, Code, Group, Loader, Stack, Text, ThemeIcon,} from "@mantine/core";
import {modals} from "@mantine/modals";
import {notifications} from "@mantine/notifications";
import {IconAlertTriangle, IconCloudDownload, IconLockCog, IconRefresh} from "@tabler/icons-react";
import {api, ApiError, type FileVaultEscrowStatus} from "../../../lib/api";
import {saveTextFile} from "../../../lib/download";
import {useAuth} from "../../../lib/auth-context";
import {GlassCard} from "../ui/GlassCard";

export function FileVaultEscrowCard() {
    const {token} = useAuth();
    // null while loading, with loadError kept separate so a failed fetch never reads as not configured.
    const [status, setStatus] = useState<FileVaultEscrowStatus | null>(null);
    const [loadError, setLoadError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    const load = () => {
        if (!token) return;
        api
            .getFileVaultEscrow(token)
            .then((s) => {
                setStatus(s);
                setLoadError(null);
            })
            .catch((e) => setLoadError(e instanceof ApiError ? e.message : String(e)));
    };
    useEffect(() => {
        load();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [token]);

    // Mint or replace the keypair. replace=true is only reachable from the confirm modal below.
    const generate = async (replace: boolean) => {
        if (!token) return;
        setBusy(true);
        try {
            setStatus(await api.generateFileVaultEscrow(token, replace));
            notifications.show({
                color: "green",
                message: replace ? "Escrow keypair replaced." : "Escrow keypair generated.",
            });
        } catch (e) {
            notifications.show({
                color: "red",
                title: replace ? "Could not replace the keypair" : "Could not generate the keypair",
                message: e instanceof ApiError ? e.message : String(e),
            });
        } finally {
            setBusy(false);
        }
    };

    const confirmReplace = () => {
        modals.openConfirmModal({
            title: "Replace escrow keypair",
            children: (
                <Text size="sm">
                    A fresh keypair is minted and the reconcile re-issues the escrow profile. Recovery keys
                    already escrowed stay readable, but the old private key is discarded, so an escrow payload a
                    Mac has not yet reported cannot be read until it re-escrows against the new certificate.
                </Text>
            ),
            labels: {confirm: "Replace keypair", cancel: "Cancel"},
            confirmProps: {color: "red"},
            onConfirm: () => generate(true),
        });
    };

    const download = async () => {
        if (!token) return;
        try {
            const pem = await api.getFileVaultCertificate(token);
            saveTextFile("filevault-escrow-certificate.pem", pem, "application/x-pem-file");
        } catch (e) {
            notifications.show({color: "red", message: e instanceof ApiError ? e.message : String(e)});
        }
    };

    const configured = status?.configured === true;
    const fingerprint = status?.fingerprint_sha256 ?? null;
    // A short prefix is enough to compare by eye; the full digest is in the certificate.
    const shortFp = fingerprint ? fingerprint.replace(/:/g, "").slice(0, 16) : null;

    return (
        <GlassCard withBorder p="md">
            <Group justify="space-between" wrap="nowrap" mb="sm">
                <Group gap="sm" wrap="nowrap">
                    <ThemeIcon variant="light" color="grape" size="lg">
                        <IconLockCog size={18}/>
                    </ThemeIcon>
                    <Box>
                        <Text fz="sm" fw={600}>FileVault recovery-key escrow</Text>
                        <Text fz="xs" c="dimmed">
                            Macs encrypt their FileVault recovery key to this certificate and report it, so a locked-out
                            Mac can be recovered from Micromanage.
                        </Text>
                    </Box>
                </Group>
                {status === null && !loadError && <Loader size="xs"/>}
            </Group>

            {loadError && (
                <Alert color="red" variant="light" icon={<IconAlertTriangle size={16}/>}>
                    <Text fz="sm">Couldn&apos;t load the escrow status. {loadError}</Text>
                </Alert>
            )}

            {status !== null && (
                <Stack gap="sm">
                    {status.key_decrypts === false && (
                        <Alert color="red" variant="light" icon={<IconAlertTriangle size={16}/>}>
                            <Text fz="sm">
                                The stored private key will not decrypt, because the encryption key changed
                                underneath it, so escrowed recovery keys cannot be read. Regenerate the keypair, or
                                restore the original key from your backup.
                            </Text>
                        </Alert>
                    )}

                    {configured ? (
                        <>
                            <Group gap="xs">
                                <Badge color="teal" variant="light">Configured</Badge>
                                {status.cert_expires_at && (
                                    <Text fz="xs" c="dimmed">
                                        Certificate valid until {new Date(status.cert_expires_at).toLocaleDateString()}
                                    </Text>
                                )}
                            </Group>
                            {shortFp && (
                                <Text fz="xs" c="dimmed">
                                    Fingerprint <Code>{shortFp}&hellip;</Code>
                                </Text>
                            )}
                            <Group gap="sm">
                                <Button variant="light" leftSection={<IconCloudDownload size={16}/>} onClick={download}>
                                    Download certificate
                                </Button>
                                <Button
                                    variant="light"
                                    color="red"
                                    leftSection={<IconRefresh size={16}/>}
                                    loading={busy}
                                    onClick={confirmReplace}
                                >
                                    Replace keypair
                                </Button>
                            </Group>
                        </>
                    ) : (
                        <>
                            <Text fz="sm">
                                No escrow keypair yet. Generate one and the reconcile issues the escrow profile, so
                                Macs start reporting their recovery keys.
                            </Text>
                            <Group>
                                <Button
                                    variant="light"
                                    leftSection={<IconLockCog size={16}/>}
                                    loading={busy}
                                    onClick={() => generate(false)}
                                >
                                    Generate escrow keypair
                                </Button>
                            </Group>
                        </>
                    )}
                </Stack>
            )}
        </GlassCard>
    );
}
