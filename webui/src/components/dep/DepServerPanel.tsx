import {useCallback, useEffect, useMemo, useState} from "react";
import {
    ActionIcon,
    Alert,
    Badge,
    Button,
    Checkbox,
    Code,
    FileButton,
    Group,
    Loader,
    Menu,
    Pagination,
    Select,
    Stack,
    Table,
    Text,
    TextInput,
    Title,
    Tooltip,
} from "@mantine/core";
import {notifications} from "@mantine/notifications";
import {modals} from "@mantine/modals";
import {
    IconAlertTriangle,
    IconCheck,
    IconCloudDownload,
    IconDotsVertical,
    IconRefresh,
    IconSearch,
    IconStar,
    IconStarFilled,
    IconTrash,
    IconUpload,
} from "@tabler/icons-react";
import {api, ApiError, type DepDevice, type DepServerDetail} from "../../../lib/api";
import {saveTextFile} from "../../../lib/download";
import type {Profile} from "../../../lib/config";
import {useAuth} from "../../../lib/auth-context";
import {SimpleEnrollmentProfileForm} from "./SimpleEnrollmentProfileForm";
import {GlassCard} from "../ui/GlassCard";

// Renewal-reminder severity for the token expiry (mirrors the Enrollment page).
function expirySeverity(days: number | null): "red" | "orange" | null {
    if (days === null) return null;
    if (days < 14) return "red";
    if (days < 45) return "orange";
    return null;
}

function daysUntil(iso: string | null): number | null {
    if (!iso) return null;
    const ms = new Date(iso).getTime() - Date.now();
    if (Number.isNaN(ms)) return null;
    return Math.floor(ms / 86_400_000);
}

const DEVICE_PAGE_SIZE = 50;

const PROFILE_STATUS_COLOR: Record<string, string> = {
    assigned: "blue",
    pushed: "teal",
    removed: "gray",
    empty: "gray",
};

export function DepServerPanel({
                                   server: initial,
                                   onChanged,
                                   onUnlinked,
                               }: {
    server: DepServerDetail;
    onChanged: (s: DepServerDetail) => void;
    onUnlinked: () => void;
}) {
    const {token} = useAuth();
    const [server, setServer] = useState<DepServerDetail>(initial);
    const [devices, setDevices] = useState<DepDevice[]>([]);
    const [depProfiles, setDepProfiles] = useState<{ id: string; name: string }[]>([]);
    const [loading, setLoading] = useState(true);
    const [syncing, setSyncing] = useState(false);
    const [busy, setBusy] = useState(false);
    const [selected, setSelected] = useState<Set<string>>(new Set());
    const [assignProfileId, setAssignProfileId] = useState<string | null>(null);
    const [simpleFormOpen, setSimpleFormOpen] = useState(false);
    const [deviceQuery, setDeviceQuery] = useState("");
    const [page, setPage] = useState(1);

    useEffect(() => setServer(initial), [initial]);

    const reload = useCallback(async () => {
        if (!token) return;
        setLoading(true);
        try {
            const [detail, devs, cfg] = await Promise.all([
                api.getDepServer(token, initial.id),
                api.listDepDevices(token, initial.id),
                api.getConfig(token, "profiles").catch(() => ({profiles: []})),
            ]);
            setServer(detail);
            onChanged(detail);
            setDevices(devs.devices);
            const profiles = ((cfg as { profiles?: Profile[] }).profiles ?? []).filter(
                (p) => p.type === "enrollment" || p.dep_profile,
            );
            setDepProfiles(profiles.map((p) => ({id: p.id, name: p.name})));
            if (!assignProfileId && profiles[0]) setAssignProfileId(profiles[0].id);
        } catch (e) {
            notifications.show({
                color: "red",
                title: "Could not load this ABM/ASM connection",
                message: e instanceof ApiError ? e.message : String(e),
            });
        } finally {
            setLoading(false);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [token, initial.id]);

    useEffect(() => {
        reload();
    }, [reload]);

    const pushedUuidByProfile = useMemo(() => {
        const m = new Map<string, string | null>();
        for (const p of server.profiles ?? []) m.set(p.profile_id, p.profile_uuid);
        return m;
    }, [server.profiles]);

    async function sync() {
        if (!token) return;
        setSyncing(true);
        try {
            const res = await api.syncDepServer(token, server.id);
            if (res.ok) {
                notifications.show({
                    color: "green",
                    title: "Sync complete",
                    message: `${res.added ?? 0} added · ${res.modified ?? 0} updated · ${res.deleted ?? 0} removed.`,
                });
            } else {
                notifications.show({
                    color: "red",
                    title: "Sync reported a problem",
                    message: res.error ?? "See the connection status.",
                });
            }
            await reload();
        } catch (e) {
            notifications.show({
                color: "red",
                title: "Sync failed",
                message: e instanceof ApiError ? e.message : String(e),
            });
        } finally {
            setSyncing(false);
        }
    }

    async function pushProfile(profileId: string) {
        if (!token) return;
        setBusy(true);
        try {
            await api.pushDepProfile(token, server.id, profileId);
            notifications.show({color: "green", message: `Pushed "${profileId}" to Apple.`});
            await reload();
        } catch (e) {
            notifications.show({
                color: "red",
                title: "Push failed",
                message: e instanceof ApiError ? e.message : String(e),
            });
        } finally {
            setBusy(false);
        }
    }

    async function setDefault(profileId: string | null) {
        if (!token) return;
        try {
            const updated = await api.setDepDefaultProfile(token, server.id, profileId);
            setServer((s) => ({...s, default_profile_id: updated.default_profile_id}));
            onChanged({...server, default_profile_id: updated.default_profile_id});
            notifications.show({
                color: "green",
                message: profileId ? `"${profileId}" is now the default.` : "Default cleared.",
            });
        } catch (e) {
            notifications.show({
                color: "red",
                message: e instanceof ApiError ? e.message : String(e),
            });
        }
    }

    const selectedSerials = () =>
        devices.filter((d) => selected.has(d.id)).map((d) => d.serial_number);

    async function assignSelected() {
        if (!token || !assignProfileId) return;
        const serials = selectedSerials();
        if (!serials.length) return;
        setBusy(true);
        try {
            const {
                results,
                retry_after_seconds
            } = await api.assignDepProfile(token, server.id, assignProfileId, serials);
            const ok = Object.values(results).filter((r) => r === "SUCCESS").length;
            // Apple returns this only when at least one device came back THROTTLED rather than assigned. Wait the
            // stated interval before retrying those serials.
            const throttleNote = retry_after_seconds
                ? ` Apple throttled some of these; wait ${retry_after_seconds}s before retrying them.`
                : "";
            notifications.show({
                color: ok === serials.length ? "green" : "orange",
                title: "Profile assigned",
                message: `${ok}/${serials.length} succeeded.${throttleNote}`,
            });
            setSelected(new Set());
            await reload();
        } catch (e) {
            notifications.show({
                color: "red",
                title: "Assign failed",
                message: e instanceof ApiError ? e.message : String(e),
            });
        } finally {
            setBusy(false);
        }
    }

    async function unassignSelected() {
        if (!token) return;
        const serials = selectedSerials();
        if (!serials.length) return;
        setBusy(true);
        try {
            await api.unassignDepProfile(token, server.id, serials);
            notifications.show({color: "green", message: `Unassigned ${serials.length} device(s).`});
            setSelected(new Set());
            await reload();
        } catch (e) {
            notifications.show({color: "red", message: e instanceof ApiError ? e.message : String(e)});
        } finally {
            setBusy(false);
        }
    }

    function confirmDisown() {
        const serials = selectedSerials();
        if (!serials.length) return;
        modals.openConfirmModal({
            title: "Release devices from Apple Business Manager?",
            children: (
                <Stack gap="xs">
                    <Text size="sm">
                        This <b>permanently</b> removes {serials.length} device(s) from your
                        organization&apos;s Automated Device Enrollment in ABM/ASM. You cannot undo it here.
                        Apple or your reseller would have to add the device back.
                    </Text>
                    <Code block>{serials.join("\n")}</Code>
                </Stack>
            ),
            labels: {confirm: "Release (disown)", cancel: "Cancel"},
            confirmProps: {color: "red"},
            onConfirm: async () => {
                if (!token) return;
                setBusy(true);
                try {
                    await api.disownDepDevices(token, server.id, serials);
                    notifications.show({color: "green", message: `Released ${serials.length} device(s).`});
                    setSelected(new Set());
                    await reload();
                } catch (e) {
                    notifications.show({color: "red", message: e instanceof ApiError ? e.message : String(e)});
                } finally {
                    setBusy(false);
                }
            },
        });
    }

    async function uploadTokenRenewal(file: File | null) {
        if (!token || !file) return;
        setBusy(true);
        try {
            await api.uploadDepToken(token, server.id, file);
            notifications.show({color: "green", message: "Server token renewed."});
            await reload();
        } catch (e) {
            notifications.show({
                color: "red",
                title: "Renewal failed",
                message: e instanceof ApiError ? e.message : String(e),
            });
        } finally {
            setBusy(false);
        }
    }

    function confirmUnlink() {
        modals.openConfirmModal({
            title: `Unlink "${server.name}"?`,
            children: (
                <Text size="sm">
                    This wipes the stored server token and private key. Synced device records remain,
                    but syncing and profile assignment stop until you link a token again.
                </Text>
            ),
            labels: {confirm: "Unlink", cancel: "Cancel"},
            confirmProps: {color: "red"},
            onConfirm: async () => {
                if (!token) return;
                try {
                    await api.unlinkDepServer(token, server.id);
                    notifications.show({color: "green", message: "Unlinked."});
                    onUnlinked();
                } catch (e) {
                    notifications.show({color: "red", message: e instanceof ApiError ? e.message : String(e)});
                }
            },
        });
    }

    const tokenDays = daysUntil(server.token_expires_at);
    const tokenSeverity = expirySeverity(tokenDays);

    // The whole device list arrives in one response, so the filtering and paging below are client-side.
    const shown = useMemo(() => {
        const q = deviceQuery.trim().toLowerCase();
        if (!q) return devices;
        return devices.filter(
            (d) =>
                d.serial_number.toLowerCase().includes(q) ||
                (d.device_model ?? "").toLowerCase().includes(q),
        );
    }, [devices, deviceQuery]);
    const pageCount = Math.max(1, Math.ceil(shown.length / DEVICE_PAGE_SIZE));
    const currentPage = Math.min(page, pageCount);
    const pageRows = shown.slice((currentPage - 1) * DEVICE_PAGE_SIZE, currentPage * DEVICE_PAGE_SIZE);
    // The header checkbox covers the rows on this page, not devices a filter or another page is hiding.
    const allSelected = pageRows.length > 0 && pageRows.every((d) => selected.has(d.id));

    return (
        <Stack gap="lg">
            {/*  Connection status  */}
            <GlassCard withBorder p="lg">
                <Group justify="space-between" align="flex-start">
                    <Stack gap={4}>
                        <Group gap="sm">
                            <Title order={4}>{server.account?.org_name || server.name}</Title>
                            <Badge color={server.status === "linked" ? "teal" : "gray"} variant="light">
                                {server.status}
                            </Badge>
                        </Group>
                        <Text size="sm" c="dimmed">
                            Connection <Code>{server.name}</Code>
                            {server.account?.server_name && <> · MDM server {server.account.server_name}</>}
                            {server.account?.org_id && <> · Org {server.account.org_id}</>}
                        </Text>
                    </Stack>
                    <Group gap="xs">
                        <Button
                            variant="light"
                            leftSection={<IconRefresh size={16}/>}
                            loading={syncing}
                            onClick={sync}
                        >
                            Sync devices
                        </Button>
                        <Menu position="bottom-end" withinPortal>
                            <Menu.Target>
                                <ActionIcon variant="subtle" aria-label="More">
                                    <IconDotsVertical size={18}/>
                                </ActionIcon>
                            </Menu.Target>
                            <Menu.Dropdown>
                                <Menu.Item
                                    leftSection={<IconCloudDownload size={14}/>}
                                    disabled={!server.public_cert_pem}
                                    onClick={() =>
                                        server.public_cert_pem &&
                                        saveTextFile(
                                            `${server.name}-public-key.pem`,
                                            server.public_cert_pem,
                                            "application/x-pem-file",
                                        )
                                    }
                                >
                                    Download public key
                                </Menu.Item>
                                <FileButton onChange={uploadTokenRenewal} accept=".p7m,application/pkcs7-mime">
                                    {(props) => (
                                        <Menu.Item {...props} leftSection={<IconUpload size={14}/>}
                                                   closeMenuOnClick={false}>
                                            Renew server token…
                                        </Menu.Item>
                                    )}
                                </FileButton>
                                <Menu.Divider/>
                                <Menu.Item color="red" leftSection={<IconTrash size={14}/>} onClick={confirmUnlink}>
                                    Unlink connection
                                </Menu.Item>
                            </Menu.Dropdown>
                        </Menu>
                    </Group>
                </Group>

                {server.last_sync_status === "error" && server.last_sync_error && (
                    <Alert color="red" mt="md" icon={<IconAlertTriangle size={16}/>} variant="light">
                        Last sync failed: {server.last_sync_error}
                    </Alert>
                )}
                {tokenSeverity && tokenDays !== null && (
                    <Alert
                        color={tokenSeverity}
                        mt="md"
                        icon={<IconAlertTriangle size={16}/>}
                        variant="light"
                        title="Server token expiring"
                    >
                        {tokenDays < 0
                            ? `The ABM/ASM server token expired ${Math.abs(tokenDays)} day(s) ago. Sync and assignment will fail until you renew it.`
                            : `The ABM/ASM server token expires in ${tokenDays} day(s). Download a fresh token from ABM and use "Renew server token".`}
                    </Alert>
                )}
                <Text size="xs" c="dimmed" mt="sm">
                    {server.last_sync_at
                        ? `Last synced ${new Date(server.last_sync_at).toLocaleString()}`
                        : "Not synced yet"}
                    {server.token_expires_at &&
                        ` · token valid until ${new Date(server.token_expires_at).toLocaleDateString()}`}
                </Text>
            </GlassCard>

            {/*  Enrollment profiles  */}
            <GlassCard withBorder p="lg">
                <Group justify="space-between" mb="sm">
                    <Title order={5}>Enrollment profiles</Title>
                    <Group gap="xs">
                        <Button size="xs" variant="light" onClick={() => setSimpleFormOpen(true)}>
                            Create simple profile
                        </Button>
                        <Button component="a" href="/profiles" variant="subtle" size="xs">
                            Author profiles →
                        </Button>
                    </Group>
                </Group>
                {!server.enroll_url && (
                    <Alert
                        color="orange"
                        mb="sm"
                        icon={<IconAlertTriangle size={16}/>}
                        variant="light"
                        title="Enrollment URL not configured"
                    >
                        <code>PUBLIC_API_URL</code> is not set on the controller, so a DEP profile has no
                        enrollment URL to point devices at. Set it before pushing a profile to Apple.
                    </Alert>
                )}
                {depProfiles.length === 0 ? (
                    <Alert color="blue" variant="light">
                        <Stack gap="xs" align="flex-start">
                            <Text size="sm">
                                No enrollment (DEP) profiles yet. Create a simple one here to get going, or
                                author a full profile under <b>Profiles</b>. Then push it to define how devices
                                set up.
                            </Text>
                            <Button size="xs" onClick={() => setSimpleFormOpen(true)}>
                                Create a simple enrollment profile
                            </Button>
                        </Stack>
                    </Alert>
                ) : (
                    <Table verticalSpacing="sm">
                        <Table.Thead>
                            <Table.Tr>
                                <Table.Th>Profile</Table.Th>
                                <Table.Th>Apple status</Table.Th>
                                <Table.Th>Default</Table.Th>
                                <Table.Th/>
                            </Table.Tr>
                        </Table.Thead>
                        <Table.Tbody>
                            {depProfiles.map((p) => {
                                const uuid = pushedUuidByProfile.get(p.id);
                                const isDefault = server.default_profile_id === p.id;
                                return (
                                    <Table.Tr key={p.id}>
                                        <Table.Td>
                                            <Text fw={500}>{p.name}</Text>
                                            <Text size="xs" c="dimmed">
                                                <Code>{p.id}</Code>
                                            </Text>
                                        </Table.Td>
                                        <Table.Td>
                                            {uuid ? (
                                                <Tooltip label={uuid}>
                                                    <Badge color="teal" variant="light">
                                                        Pushed
                                                    </Badge>
                                                </Tooltip>
                                            ) : (
                                                <Badge color="gray" variant="light">
                                                    Not pushed
                                                </Badge>
                                            )}
                                        </Table.Td>
                                        <Table.Td>
                                            <Tooltip label={isDefault ? "Default for new devices" : "Set as default"}>
                                                <ActionIcon
                                                    variant="subtle"
                                                    color={isDefault ? "yellow" : "gray"}
                                                    onClick={() => setDefault(isDefault ? null : p.id)}
                                                    aria-label="Set default"
                                                >
                                                    {isDefault ? <IconStarFilled size={18}/> : <IconStar size={18}/>}
                                                </ActionIcon>
                                            </Tooltip>
                                        </Table.Td>
                                        <Table.Td>
                                            <Button
                                                size="xs"
                                                variant="light"
                                                loading={busy}
                                                onClick={() => pushProfile(p.id)}
                                                leftSection={<IconCheck size={14}/>}
                                            >
                                                {uuid ? "Re-push" : "Push to Apple"}
                                            </Button>
                                        </Table.Td>
                                    </Table.Tr>
                                );
                            })}
                        </Table.Tbody>
                    </Table>
                )}
                <Text size="xs" c="dimmed" mt="sm">
                    The <IconStarFilled size={11} style={{verticalAlign: "middle"}}/> default profile
                    is auto-assigned to devices as they&apos;re synced from ABM/ASM.
                </Text>
            </GlassCard>

            {/*  Assigned devices  */}
            <GlassCard withBorder p="lg">
                <Group justify="space-between" mb="sm">
                    <Title order={5}>Devices ({devices.length})</Title>
                    {selected.size > 0 && (
                        <Group gap="xs">
                            <Select
                                size="xs"
                                w={200}
                                placeholder="Profile to assign"
                                data={depProfiles.map((p) => ({value: p.id, label: p.name}))}
                                value={assignProfileId}
                                onChange={setAssignProfileId}
                                comboboxProps={{withinPortal: true}}
                            />
                            <Button size="xs" loading={busy} onClick={assignSelected} disabled={!assignProfileId}>
                                Assign ({selected.size})
                            </Button>
                            <Button size="xs" variant="light" loading={busy} onClick={unassignSelected}>
                                Unassign
                            </Button>
                            <Button size="xs" color="red" variant="light" loading={busy} onClick={confirmDisown}>
                                Disown
                            </Button>
                        </Group>
                    )}
                </Group>
                {loading ? (
                    <Group justify="center" py="lg">
                        <Loader size="sm"/>
                    </Group>
                ) : devices.length === 0 ? (
                    <Alert color="blue" variant="light">
                        No devices assigned to this MDM server in ABM/ASM yet. Assign devices to this server
                        in Apple Business Manager, then <b>Sync devices</b>.
                    </Alert>
                ) : (
                    <>
                        <Group justify="space-between" mb="sm" gap="sm">
                            <TextInput
                                size="xs"
                                w={260}
                                placeholder="Search serial or model"
                                leftSection={<IconSearch size={14}/>}
                                value={deviceQuery}
                                onChange={(e) => {
                                    setDeviceQuery(e.currentTarget.value);
                                    setPage(1);
                                }}
                            />
                            <Text fz="xs" c="dimmed">
                                {shown.length === devices.length
                                    ? `${devices.length} device${devices.length === 1 ? "" : "s"}`
                                    : `${shown.length} of ${devices.length} match`}
                            </Text>
                        </Group>
                        {shown.length === 0 ? (
                            <Text fz="sm" c="dimmed" py="sm">
                                No device matches that search.
                            </Text>
                        ) : (
                            <>
                                <Table.ScrollContainer minWidth={720}>
                                    <Table verticalSpacing="sm" highlightOnHover>
                                        <Table.Thead>
                                            <Table.Tr>
                                                <Table.Th w={36}>
                                                    <Checkbox
                                                        checked={allSelected}
                                                        indeterminate={selected.size > 0 && !allSelected}
                                                        onChange={(e) => {
                                                            const next = new Set(selected);
                                                            for (const d of pageRows) {
                                                                if (e.currentTarget.checked) next.add(d.id);
                                                                else next.delete(d.id);
                                                            }
                                                            setSelected(next);
                                                        }}
                                                        aria-label="Select all on this page"
                                                    />
                                                </Table.Th>
                                                <Table.Th>Serial</Table.Th>
                                                <Table.Th>Model</Table.Th>
                                                <Table.Th>Enrollment</Table.Th>
                                                <Table.Th>Profile status</Table.Th>
                                            </Table.Tr>
                                        </Table.Thead>
                                        <Table.Tbody>
                                            {pageRows.map((d) => (
                                                <Table.Tr key={d.id}>
                                                    <Table.Td>
                                                        <Checkbox
                                                            checked={selected.has(d.id)}
                                                            onChange={(e) => {
                                                                const next = new Set(selected);
                                                                if (e.currentTarget.checked) next.add(d.id);
                                                                else next.delete(d.id);
                                                                setSelected(next);
                                                            }}
                                                            aria-label={`Select ${d.serial_number}`}
                                                        />
                                                    </Table.Td>
                                                    <Table.Td>
                                                        <Code>{d.serial_number}</Code>
                                                    </Table.Td>
                                                    <Table.Td>{d.device_model || "--"}</Table.Td>
                                                    <Table.Td>
                                                        <Badge
                                                            variant="light"
                                                            color={d.enrolled ? "teal" : d.enrollment_state === "pending" ? "yellow" : "gray"}
                                                        >
                                                            {d.enrolled ? "enrolled" : d.enrollment_state}
                                                        </Badge>
                                                    </Table.Td>
                                                    <Table.Td>
                                                        <Badge
                                                            variant="dot"
                                                            color={PROFILE_STATUS_COLOR[d.dep_profile_status ?? "empty"] ?? "gray"}
                                                        >
                                                            {d.dep_profile_status ?? "none"}
                                                        </Badge>
                                                    </Table.Td>
                                                </Table.Tr>
                                            ))}
                                        </Table.Tbody>
                                    </Table>
                                </Table.ScrollContainer>
                                {shown.length > DEVICE_PAGE_SIZE && (
                                    <Group justify="center" mt="sm">
                                        <Pagination total={pageCount} value={currentPage} onChange={setPage} size="sm"/>
                                    </Group>
                                )}
                            </>
                        )}
                    </>
                )}
            </GlassCard>

            <SimpleEnrollmentProfileForm
                opened={simpleFormOpen}
                onClose={() => setSimpleFormOpen(false)}
                onCreated={() => reload()}
            />
        </Stack>
    );
}
