// Admin card for the identity that signs enrollment profiles, uploaded as Apple hands it out: a .p12 exported from
// Keychain Access and optional .cer intermediates. The server returns only the certificate's subject, issuer, expiry
// and chain length; the key and the .p12 password never come back.

import {useEffect, useState} from "react";
import {
    Alert,
    Badge,
    Box,
    Button,
    FileInput,
    Group,
    Loader,
    PasswordInput,
    Stack,
    Text,
    ThemeIcon,
} from "@mantine/core";
import {modals} from "@mantine/modals";
import {notifications} from "@mantine/notifications";
import {IconAlertTriangle, IconCertificate, IconKey, IconRefresh, IconTrash, IconUpload} from "@tabler/icons-react";
import {api, ApiError, type ProfileSigningStatus} from "../../../lib/api";
import {useAuth} from "../../../lib/auth-context";
import {GlassCard} from "../ui/GlassCard";

// Mirrors the server's limits, so a wrong or oversized file is caught before it is uploaded.
const MAX_FILE_BYTES = 64 * 1024;
const MAX_INTERMEDIATES = 5;
const EXPIRY_WARNING_DAYS = 30;

async function fileToBase64(file: File): Promise<string> {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
        binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    }
    return btoa(binary);
}

function hasExtension(file: File, extensions: string[]): boolean {
    const name = file.name.toLowerCase();
    return extensions.some((ext) => name.endsWith(ext));
}

function p12Problem(file: File | null): string | null {
    if (!file) return null;
    if (!hasExtension(file, [".p12", ".pfx"])) return "Choose the .p12 file exported from Keychain Access.";
    if (file.size === 0) return "This file is empty.";
    if (file.size > MAX_FILE_BYTES) return "This file is larger than 64 KB, which is too big for a .p12 export.";
    return null;
}

function intermediatesProblem(files: File[]): string | null {
    if (files.length > MAX_INTERMEDIATES) return `Choose at most ${MAX_INTERMEDIATES} intermediate certificates.`;
    const wrong = files.find((f) => !hasExtension(f, [".cer"]));
    if (wrong) return `${wrong.name} is not a .cer file.`;
    const empty = files.find((f) => f.size === 0 || f.size > MAX_FILE_BYTES);
    if (empty) return `${empty.name} is empty or larger than 64 KB.`;
    return null;
}

function daysUntil(iso: string | null): number | null {
    if (!iso) return null;
    const ms = new Date(iso).getTime() - Date.now();
    return Number.isNaN(ms) ? null : Math.floor(ms / 86_400_000);
}

export function ProfileSigningCard() {
    const {token} = useAuth();
    // null while loading, with loadError kept separate so a failed fetch never reads as not configured.
    const [status, setStatus] = useState<ProfileSigningStatus | null>(null);
    const [loadError, setLoadError] = useState<string | null>(null);
    const [retrying, setRetrying] = useState(false);
    const [p12File, setP12File] = useState<File | null>(null);
    const [password, setPassword] = useState("");
    const [intermediates, setIntermediates] = useState<File[]>([]);
    const [importing, setImporting] = useState(false);
    const [removing, setRemoving] = useState(false);

    const load = () => {
        if (!token) return Promise.resolve();
        return api
            .getProfileSigning(token)
            .then((s) => {
                setStatus(s);
                setLoadError(null);
            })
            .catch((e) => setLoadError(e instanceof ApiError ? e.message : String(e)));
    };
    const retry = () => {
        setRetrying(true);
        void load().finally(() => setRetrying(false));
    };
    useEffect(() => {
        load();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [token]);

    const configured = status?.configured === true;
    const p12Error = p12Problem(p12File);
    const intermediatesError = intermediatesProblem(intermediates);
    const canImport = !!p12File && !p12Error && !intermediatesError && !importing && !removing;

    const importIdentity = async () => {
        if (!token || !p12File || !canImport) return;
        setImporting(true);
        try {
            const next = await api.importProfileSigning(token, {
                p12_b64: await fileToBase64(p12File),
                password,
                intermediates_b64: await Promise.all(intermediates.map(fileToBase64)),
            });
            setStatus(next);
            setP12File(null);
            setPassword("");
            setIntermediates([]);
            notifications.show({color: "green", message: "Signing certificate imported."});
        } catch (e) {
            notifications.show({
                color: "red",
                title: "Could not import the certificate",
                message: e instanceof ApiError ? e.message : "The files could not be read. Choose them again.",
            });
        } finally {
            setImporting(false);
        }
    };

    const confirmImport = () => {
        if (!configured) {
            void importIdentity();
            return;
        }
        modals.openConfirmModal({
            title: "Replace signing certificate",
            children: (
                <Text size="sm">
                    Enrollment profiles are signed with the new certificate from now on. The current certificate and
                    its private key are deleted.
                </Text>
            ),
            labels: {confirm: "Replace certificate", cancel: "Cancel"},
            onConfirm: () => void importIdentity(),
        });
    };

    const remove = async () => {
        if (!token) return;
        setRemoving(true);
        try {
            setStatus(await api.deleteProfileSigning(token));
            notifications.show({color: "green", message: "Signing certificate removed."});
        } catch (e) {
            notifications.show({
                color: "red",
                title: "Could not remove the certificate",
                message: e instanceof ApiError ? e.message : String(e),
            });
        } finally {
            setRemoving(false);
        }
    };

    const confirmRemove = () => {
        modals.openConfirmModal({
            title: "Remove signing certificate",
            children: (
                <Text size="sm">
                    The certificate and its private key are deleted. Enrollment profiles are served unsigned from
                    then on.
                </Text>
            ),
            labels: {confirm: "Remove certificate", cancel: "Cancel"},
            confirmProps: {color: "red"},
            onConfirm: () => void remove(),
        });
    };

    const days = daysUntil(status?.expires_at ?? null);
    const notSigning = configured && (status.expired || status.key_decrypts === false);
    const expiringSoon = configured && !status.expired && days !== null && days <= EXPIRY_WARNING_DAYS;

    return (
        <GlassCard withBorder p="md">
            <Group justify="space-between" wrap="nowrap" mb="sm">
                <Group gap="sm" wrap="nowrap">
                    <ThemeIcon variant="light" color="indigo" size="lg">
                        <IconCertificate size={18}/>
                    </ThemeIcon>
                    <Box>
                        <Text fz="sm" fw={600}>Enrollment profile signing</Text>
                        <Text fz="xs" c="dimmed">
                            A signed enrollment profile shows as verified on a device only when the certificate
                            chains to a root the device trusts. Without a certificate, profiles are served unsigned.
                        </Text>
                    </Box>
                </Group>
                {status === null && !loadError && <Loader size="xs"/>}
            </Group>

            {loadError && (
                <Alert color="red" variant="light" icon={<IconAlertTriangle size={16}/>}>
                    <Group justify="space-between" wrap="nowrap">
                        <Text fz="sm">Couldn&apos;t load the signing status. {loadError}</Text>
                        <Button
                            size="xs"
                            variant="subtle"
                            leftSection={<IconRefresh size={14}/>}
                            loading={retrying}
                            onClick={retry}
                        >
                            Retry
                        </Button>
                    </Group>
                </Alert>
            )}

            {status !== null && (
                <Stack gap="sm">
                    {configured ? (
                        <>
                            <Group gap="xs">
                                {notSigning ? (
                                    <Badge color="red" variant="light">Not signing</Badge>
                                ) : (
                                    <Badge color="teal" variant="light">Signing</Badge>
                                )}
                                {status.expires_at && (
                                    <Text fz="xs" c={status.expired ? "red" : expiringSoon ? "orange" : "dimmed"}>
                                        {status.expired ? "Certificate expired on " : "Certificate valid until "}
                                        {new Date(status.expires_at).toLocaleDateString()}
                                    </Text>
                                )}
                            </Group>
                            <Stack gap={2}>
                                {status.subject && (
                                    <Text fz="xs" style={{wordBreak: "break-word"}}>Subject: {status.subject}</Text>
                                )}
                                {status.issuer && (
                                    <Text fz="xs" style={{wordBreak: "break-word"}}>Issuer: {status.issuer}</Text>
                                )}
                                <Text fz="xs" c="dimmed">
                                    {status.chain_count === 1
                                        ? "1 intermediate certificate"
                                        : `${status.chain_count} intermediate certificates`}
                                </Text>
                            </Stack>

                            {status.expired && (
                                <Alert color="red" variant="light" icon={<IconAlertTriangle size={16}/>}>
                                    <Text fz="sm">
                                        The certificate has expired, so enrollment profiles are being served unsigned.
                                        Import a renewed certificate.
                                    </Text>
                                </Alert>
                            )}
                            {status.key_decrypts === false && (
                                <Alert color="red" variant="light" icon={<IconAlertTriangle size={16}/>}>
                                    <Text fz="sm">
                                        The stored private key can no longer be read, usually because the
                                        controller&apos;s encryption key changed. Enrollment profiles are being served
                                        unsigned. Import the .p12 again.
                                    </Text>
                                </Alert>
                            )}
                            {expiringSoon && (
                                <Alert color="orange" variant="light" icon={<IconAlertTriangle size={16}/>}>
                                    <Text fz="sm">
                                        The certificate expires in {days === 1 ? "1 day" : `${days} days`}. Import a
                                        renewed certificate before then.
                                    </Text>
                                </Alert>
                            )}
                            {status.self_signed && !notSigning && (
                                <Alert color="yellow" variant="light" icon={<IconAlertTriangle size={16}/>}>
                                    <Text fz="sm">
                                        This certificate is self-signed. Devices that do not already trust it show
                                        the enrollment profile as not verified.
                                    </Text>
                                </Alert>
                            )}

                            <Group>
                                <Button
                                    variant="light"
                                    color="red"
                                    leftSection={<IconTrash size={16}/>}
                                    loading={removing}
                                    disabled={importing}
                                    onClick={confirmRemove}
                                >
                                    Remove certificate
                                </Button>
                            </Group>
                        </>
                    ) : (
                        <Text fz="sm">No signing certificate. Enrollment profiles are served unsigned.</Text>
                    )}

                    <FileInput
                        label="Certificate and private key (.p12)"
                        description="In Keychain Access, select the certificate with its key and choose Export."
                        placeholder="Choose .p12 file"
                        leftSection={<IconKey size={16}/>}
                        accept=".p12,.pfx"
                        clearable
                        disabled={importing}
                        error={p12Error}
                        value={p12File}
                        onChange={setP12File}
                    />
                    <PasswordInput
                        label=".p12 password"
                        description="The password set during export. Leave it blank if none was set."
                        // new-password stops browsers filling in the saved sign-in password.
                        autoComplete="new-password"
                        name="p12-export-password"
                        disabled={importing}
                        value={password}
                        onChange={(e) => setPassword(e.currentTarget.value)}
                        onKeyDown={(e) => {
                            if (e.key === "Enter" && canImport) confirmImport();
                        }}
                    />
                    <FileInput
                        label="Intermediate certificates (optional)"
                        description="The issuing CA's .cer files, as downloaded from Apple, if the .p12 lacks them."
                        placeholder="Choose .cer files"
                        leftSection={<IconCertificate size={16}/>}
                        accept=".cer"
                        multiple
                        clearable
                        disabled={importing}
                        error={intermediatesError}
                        value={intermediates}
                        onChange={setIntermediates}
                    />
                    <Group>
                        <Button
                            variant="light"
                            leftSection={<IconUpload size={16}/>}
                            loading={importing}
                            disabled={!canImport}
                            onClick={confirmImport}
                        >
                            {configured ? "Replace certificate" : "Import certificate"}
                        </Button>
                    </Group>
                </Stack>
            )}
        </GlassCard>
    );
}
