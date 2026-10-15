"use client";

import {type FormEvent, useCallback, useEffect, useState} from "react";
import {
    ActionIcon,
    Box,
    Button,
    CopyButton,
    Group,
    Loader,
    Modal,
    NumberInput,
    Popover,
    Select,
    Stack,
    Table,
    Text,
    TextInput,
    Tooltip,
} from "@mantine/core";
import {modals} from "@mantine/modals";
import {notifications} from "@mantine/notifications";
import {IconCheck, IconCopy, IconPlus, IconQrcode, IconRefresh, IconTrash} from "@tabler/icons-react";
import QRCode from "react-qr-code";
import {api, ApiError, type EnrollmentLink, type EnrollmentLinkCreate} from "../../../lib/api";
import {useAuth} from "../../../lib/auth-context";
import {timeUntil} from "../../../lib/time";
import {GlassCard} from "@/components/ui/GlassCard";

const EXPIRY_OPTIONS = [
    {value: "1", label: "1 day"},
    {value: "7", label: "7 days"},
    {value: "30", label: "30 days"},
];

// Matches the max_downloads bound the API enforces.
const MAX_DOWNLOAD_LIMIT = 100000;

const NO_URL_HINT =
    "A link has no URL when PUBLIC_API_URL is unset or its token cannot be decrypted. " +
    "If PUBLIC_API_URL is set, revoke this link and create a new one.";

function expiresIn(iso: string | null): string {
    if (!iso) return "--";
    return timeUntil(iso) ?? "expired";
}

function downloadsText(link: EnrollmentLink): string {
    return link.max_downloads === null
        ? `${link.downloads} (no limit)`
        : `${link.downloads} of ${link.max_downloads}`;
}

function limitError(limit: number | string): string | null {
    if (typeof limit !== "number") return null;
    if (limit < 1) return "Must be at least 1, or empty for no limit.";
    if (limit > MAX_DOWNLOAD_LIMIT) return `Must be at most ${MAX_DOWNLOAD_LIMIT.toLocaleString()}.`;
    return null;
}

function NewLinkModal({
                          opened,
                          onClose,
                          onCreated,
                      }: {
    opened: boolean;
    onClose: () => void;
    onCreated: (link: EnrollmentLink) => void;
}) {
    const {token} = useAuth();
    const [label, setLabel] = useState("");
    const [expires, setExpires] = useState("7");
    const [limit, setLimit] = useState<number | string>("");
    const [saving, setSaving] = useState(false);
    const [wasOpened, setWasOpened] = useState(opened);

    // Fields start empty on every open.
    if (opened !== wasOpened) {
        setWasOpened(opened);
        if (opened) {
            setLabel("");
            setExpires("7");
            setLimit("");
        }
    }

    const error = limitError(limit);

    const submit = async (e: FormEvent) => {
        e.preventDefault();
        if (!token || saving || error) return;
        const body: EnrollmentLinkCreate = {expires_in_days: Number(expires) as 1 | 7 | 30};
        if (label.trim()) body.label = label.trim();
        if (typeof limit === "number") body.max_downloads = limit;
        setSaving(true);
        try {
            const link = await api.createEnrollmentLink(token, body);
            onCreated(link);
            onClose();
        } catch (e: unknown) {
            notifications.show({color: "red", message: (e as Error).message});
        } finally {
            setSaving(false);
        }
    };

    return (
        <Modal opened={opened} onClose={onClose} title="New enrollment link" size="sm">
            <form onSubmit={submit}>
                <Stack gap="sm">
                    <TextInput
                        label="Label"
                        placeholder="Optional"
                        maxLength={120}
                        value={label}
                        onChange={(e) => setLabel(e.currentTarget.value)}
                        data-autofocus
                    />
                    <Select
                        label="Expires"
                        data={EXPIRY_OPTIONS}
                        value={expires}
                        onChange={(v) => setExpires(v ?? "7")}
                        allowDeselect={false}
                    />
                    <NumberInput
                        label="Download limit"
                        placeholder="No limit"
                        min={1}
                        max={MAX_DOWNLOAD_LIMIT}
                        clampBehavior="none"
                        error={error}
                        allowDecimal={false}
                        allowNegative={false}
                        value={limit}
                        onChange={setLimit}
                    />
                    <Group justify="flex-end">
                        <Button variant="default" onClick={onClose}>
                            Cancel
                        </Button>
                        <Button type="submit" loading={saving} disabled={error !== null}>
                            Create
                        </Button>
                    </Group>
                </Stack>
            </form>
        </Modal>
    );
}

function LinkActions({link, onRevoke}: { link: EnrollmentLink; onRevoke: (link: EnrollmentLink) => void }) {
    return (
        <Group gap={4} wrap="nowrap" justify="flex-end">
            {link.url ? (
                <>
                    <CopyButton value={link.url}>
                        {({copied, copy}) => (
                            <Tooltip label={copied ? "Copied" : "Copy link"} withArrow>
                                <ActionIcon variant="subtle" color="gray" onClick={copy} aria-label="Copy link">
                                    {copied ? <IconCheck size={16}/> : <IconCopy size={16}/>}
                                </ActionIcon>
                            </Tooltip>
                        )}
                    </CopyButton>
                    <Popover position="bottom-end" withArrow shadow="md">
                        <Tooltip label="QR code" withArrow>
                            <Popover.Target>
                                <ActionIcon variant="subtle" color="gray" aria-label="Show QR code">
                                    <IconQrcode size={16}/>
                                </ActionIcon>
                            </Popover.Target>
                        </Tooltip>
                        <Popover.Dropdown>
                            <Stack align="center" gap="xs">
                                <Box p="md" bg="white" style={{borderRadius: "var(--mantine-radius-sm)"}}>
                                    <QRCode value={link.url} size={180}/>
                                </Box>
                                <Text fz="xs" c="dimmed">
                                    Scan to open the link on the device.
                                </Text>
                            </Stack>
                        </Popover.Dropdown>
                    </Popover>
                </>
            ) : (
                <Tooltip
                    label={NO_URL_HINT}
                    withArrow
                    multiline
                    w={260}
                >
                    <Text fz="xs" c="dimmed">
                        No public URL; set PUBLIC_API_URL
                    </Text>
                </Tooltip>
            )}
            <Tooltip label="Revoke" withArrow>
                <ActionIcon variant="subtle" color="red" onClick={() => onRevoke(link)} aria-label="Revoke link">
                    <IconTrash size={16}/>
                </ActionIcon>
            </Tooltip>
        </Group>
    );
}

export function EnrollmentLinksCard() {
    const {token} = useAuth();
    const [links, setLinks] = useState<EnrollmentLink[] | null>(null);
    const [loading, setLoading] = useState(true);
    const [creating, setCreating] = useState(false);

    const load = useCallback(async () => {
        if (!token) return;
        setLoading(true);
        try {
            const res = await api.listEnrollmentLinks(token);
            setLinks(res.links);
        } catch (e: unknown) {
            notifications.show({color: "red", message: (e as Error).message});
        } finally {
            setLoading(false);
        }
    }, [token]);

    useEffect(() => {
        load();
    }, [load]);

    const revoke = async (link: EnrollmentLink) => {
        if (!token) return;
        try {
            await api.revokeEnrollmentLink(token, link.id);
            setLinks((cur) => (cur ? cur.filter((l) => l.id !== link.id) : cur));
            notifications.show({color: "teal", message: "Link revoked."});
        } catch (e: unknown) {
            notifications.show({color: "red", message: (e as Error).message});
            // The link expired or was revoked elsewhere; reload so its row goes away.
            if (e instanceof ApiError && e.status === 404) load();
        }
    };

    const confirmRevoke = (link: EnrollmentLink) => {
        modals.openConfirmModal({
            title: "Revoke link",
            children: <Text size="sm">Revoke this link? Devices already enrolled stay enrolled.</Text>,
            labels: {confirm: "Revoke", cancel: "Cancel"},
            confirmProps: {color: "red"},
            onConfirm: () => revoke(link),
        });
    };

    return (
        <GlassCard withBorder padding="lg">
            <Group justify="space-between" mb="md" wrap="nowrap" align="flex-start">
                <Stack gap={0}>
                    <Text fw={600}>Enrollment links</Text>
                    <Text fz="xs" c="dimmed">
                        Each link downloads an enrollment profile. Anyone with the link can enroll a device until the
                        link expires, reaches its download limit, or is revoked.
                    </Text>
                </Stack>
                <Group gap="xs" wrap="nowrap">
                    <ActionIcon variant="subtle" onClick={load} loading={loading} aria-label="Refresh links">
                        <IconRefresh size={16}/>
                    </ActionIcon>
                    <Button size="xs" leftSection={<IconPlus size={14}/>} onClick={() => setCreating(true)}>
                        New link
                    </Button>
                </Group>
            </Group>

            {loading && links === null ? (
                <Box py="md" ta="center">
                    <Loader size="sm"/>
                </Box>
            ) : links === null ? (
                <Text c="dimmed" fz="sm" ta="center" py="md">
                    Could not load links.
                </Text>
            ) : links.length === 0 ? (
                <Text c="dimmed" fz="sm" ta="center" py="md">
                    No active links.
                </Text>
            ) : (
                <Table.ScrollContainer minWidth={560}>
                    <Table highlightOnHover verticalSpacing="xs" fz="sm">
                        <Table.Thead>
                            <Table.Tr>
                                <Table.Th>Label</Table.Th>
                                <Table.Th>Expires</Table.Th>
                                <Table.Th>Downloads</Table.Th>
                                <Table.Th>Created by</Table.Th>
                                <Table.Th/>
                            </Table.Tr>
                        </Table.Thead>
                        <Table.Tbody>
                            {links.map((link) => (
                                <Table.Tr key={link.id}>
                                    <Table.Td>{link.label ?? <Text span c="dimmed" fz="sm">--</Text>}</Table.Td>
                                    <Table.Td>
                                        <Tooltip
                                            label={link.expires_at ? new Date(link.expires_at).toLocaleString() : "--"}
                                            withArrow
                                        >
                                            <Text span fz="sm">{expiresIn(link.expires_at)}</Text>
                                        </Tooltip>
                                    </Table.Td>
                                    <Table.Td>{downloadsText(link)}</Table.Td>
                                    <Table.Td>
                                        <Text fz="xs" c="dimmed">{link.created_by}</Text>
                                    </Table.Td>
                                    <Table.Td>
                                        <LinkActions link={link} onRevoke={confirmRevoke}/>
                                    </Table.Td>
                                </Table.Tr>
                            ))}
                        </Table.Tbody>
                    </Table>
                </Table.ScrollContainer>
            )}

            <NewLinkModal
                opened={creating}
                onClose={() => setCreating(false)}
                onCreated={(link) => {
                    // Seeding a list that never loaded would hide the older links, so load it in full instead.
                    if (links === null) load();
                    else setLinks((cur) => (cur ? [link, ...cur] : cur));
                }}
            />
        </GlassCard>
    );
}
