"use client";

// Every app in a sidebar, with the selected one's identity, versions and devices on the right. The Apps page links
// here with ?app=<id>.

import {Suspense, useEffect, useMemo, useState} from "react";
import {useRouter, useSearchParams} from "next/navigation";
import {
    ActionIcon,
    Alert,
    Badge,
    Box,
    Button,
    Code,
    Group,
    Loader,
    NavLink,
    ScrollArea,
    Stack,
    Switch,
    Table,
    Text,
    TextInput,
    Title,
    Tooltip,
} from "@mantine/core";
import {useMediaQuery} from "@mantine/hooks";
import {modals} from "@mantine/modals";
import {
    IconApps,
    IconArrowLeft,
    IconDeviceFloppy,
    IconInfoCircle,
    IconPencil,
    IconPlus,
    IconTrash,
} from "@tabler/icons-react";
import Link from "next/link";
import {api, type Device} from "../../../../../lib/api";
import {useAuth} from "../../../../../lib/auth-context";
import {useReadiness} from "../../../../../lib/readiness";
import {
    type App,
    type AppsConfig,
    type AppVersion,
    BUNDLE_ID_RE,
    describeCondition,
    type Group as GroupDef,
    type Rollout,
    type Scope,
    useConfigResource,
} from "../../../../../lib/config";
import {AppDeployments} from "@/components/apps/AppDeployments";
import {VersionScopeModal} from "@/components/apps/VersionScopeModal";
import {AppWizard} from "@/components/config/AppWizard";
import {SidebarLayout} from "@/components/layout/SidebarLayout";
import {GlassCard} from "@/components/ui/GlassCard";

const ADMIN_ONLY_REASON =
    "Apps install software on every device in their groups, so authoring them is admin-only.";

// Unset means the platform default, which is managed on a Mac.
const installsManaged = (app: App) => app.install_as_managed ?? true;

export default function AppEditorPage() {
    return (
        // useSearchParams requires a Suspense boundary during prerender.
        <Suspense fallback={null}>
            <AppEditorInner/>
        </Suspense>
    );
}

function AppEditorInner() {
    const {token, isAdmin} = useAuth();
    const router = useRouter();
    const searchParams = useSearchParams();
    const wide = useMediaQuery("(min-width: 62em)") ?? true;
    const {data, loading, saving, save} = useConfigResource<AppsConfig>("apps", {apps: []});
    const apps = useMemo(() => data?.apps ?? [], [data]);

    const selectedId = searchParams.get("app");
    const selected = apps.find((a) => a.id === selectedId) ?? null;

    // Identity draft for the selected app, reset whenever the selection or the saved document changes so that a
    // save or a sidebar switch shows what is stored.
    const [draft, setDraft] = useState<{ name: string; bundle_id: string; managed: boolean } | null>(null);
    useEffect(() => {
        setDraft(
            selected
                ? {name: selected.name, bundle_id: selected.bundle_id, managed: installsManaged(selected)}
                : null,
        );
    }, [selected]);

    const dirty =
        !!selected &&
        !!draft &&
        (draft.name !== selected.name ||
            draft.bundle_id !== selected.bundle_id ||
            draft.managed !== installsManaged(selected));
    const bundleBad = !!draft && !BUNDLE_ID_RE.test(draft.bundle_id);

    // Groups and devices for the wizard and the scope editor.
    const [allGroups, setAllGroups] = useState<GroupDef[]>([]);
    const [devices, setDevices] = useState<Device[]>([]);
    const {readiness} = useReadiness();
    const appInstall = readiness?.capabilities.find((c) => c.capability === "app_install");
    const uploadBlockedReason = appInstall && !appInstall.ready ? appInstall.reason : null;
    // Two wizards, told apart by their open state: one adds a version to the selected app, one creates an app.
    const [wizardOpen, setWizardOpen] = useState(false);
    const [newAppOpen, setNewAppOpen] = useState(false);

    useEffect(() => {
        if (!token) return;
        api.getConfig(token, "groups")
            .then((g) => setAllGroups((g as { groups?: GroupDef[] }).groups ?? []))
            .catch(() => {
            });
        api.listDevices(token, {state: "enrolled", limit: 500})
            .then((r) => setDevices(r.devices))
            .catch(() => {
            });
    }, [token]);

    // Selects the first app when the page opens with no ?app=, with replace so Back skips the default selection.
    useEffect(() => {
        if (!loading && !selected && apps.length > 0) {
            router.replace(`/apps/editor?app=${encodeURIComponent(apps[0].id)}`);
        }
    }, [loading, selected, apps, router]);

    const selectApp = (id: string) => router.replace(`/apps/editor?app=${encodeURIComponent(id)}`);

    async function saveIdentity() {
        if (!selected || !draft || bundleBad || !draft.name.trim()) return;
        const next = apps.map((a) =>
            a.id === selected.id
                ? {
                    ...a,
                    name: draft.name.trim(),
                    bundle_id: draft.bundle_id.trim(),
                    install_as_managed: draft.managed,
                }
                : a,
        );
        await save({apps: next});
    }

    function deleteApp(app: App) {
        modals.openConfirmModal({
            title: "Delete app",
            children: (
                <Text size="sm">
                    Delete <b>{app.name}</b> and all its versions? Devices that have it installed keep it.
                </Text>
            ),
            labels: {confirm: "Delete", cancel: "Cancel"},
            confirmProps: {color: "red"},
            onConfirm: async () => {
                const ok = await save({apps: apps.filter((a) => a.id !== app.id)});
                if (ok) router.replace("/apps/editor");
            },
        });
    }

    function deleteVersion(app: App, versionIdx: number) {
        modals.openConfirmModal({
            title: "Delete version",
            children: (
                <Text size="sm">
                    Remove version <b>{app.versions[versionIdx].version}</b> of {app.name}?
                </Text>
            ),
            labels: {confirm: "Delete", cancel: "Cancel"},
            confirmProps: {color: "red"},
            onConfirm: () => {
                const next = apps.map((a) =>
                    a.id === app.id
                        ? {...a, versions: a.versions.filter((_, vi) => vi !== versionIdx)}
                        : a,
                );
                save({apps: next});
            },
        });
    }

    // Index of the version being edited in the selected app, or null when the modal is closed.
    const [editingIdx, setEditingIdx] = useState<number | null>(null);
    const editingVersion = selected && editingIdx !== null ? selected.versions[editingIdx] ?? null : null;

    // Row indices belong to one app, so switching apps in the sidebar has to drop the pending edit.
    useEffect(() => {
        setEditingIdx(null);
    }, [selectedId]);

    // Replaces one version's targeting and keeps its package fields as stored.
    async function saveVersionScope(app: App, versionIdx: number, scope: Scope, rollout: Rollout | undefined) {
        const next = apps.map((a) =>
            a.id === app.id
                ? {
                    ...a,
                    versions: a.versions.map((v, vi) =>
                        vi === versionIdx
                            ? {
                                version: v.version,
                                s3_key: v.s3_key,
                                sha256: v.sha256,
                                ...(v.install_options ? {install_options: v.install_options} : {}),
                                groups: scope.groups ?? [],
                                ...(scope.conditions?.length ? {conditions: scope.conditions} : {}),
                                ...(scope.include_devices?.length
                                    ? {include_devices: scope.include_devices}
                                    : {}),
                                ...(scope.exclude_devices?.length
                                    ? {exclude_devices: scope.exclude_devices}
                                    : {}),
                                ...(rollout ? {rollout} : {}),
                            }
                            : v,
                    ),
                }
                : a,
        );
        return save({apps: next});
    }

    async function handleFinish(
        result:
            | { kind: "app"; app: App }
            | { kind: "version"; appId: string; version: AppVersion },
    ): Promise<boolean> {
        if (result.kind === "app") {
            const ok = await save({apps: [...apps, result.app]});
            if (ok) selectApp(result.app.id);
            return ok;
        }
        const next = apps.map((a) =>
            a.id === result.appId ? {...a, versions: [...a.versions, result.version]} : a,
        );
        return save({apps: next});
    }

    const takenIds = apps.map((a) => a.id);
    const usedKeys = apps.flatMap((a) => a.versions.map((v) => v.s3_key));

    if (loading) {
        return (
            <Box py={80} ta="center">
                <Loader/>
            </Box>
        );
    }

    return (
        <Stack gap="lg">
            <Group justify="space-between" align="flex-start">
                <Group gap="xs" align="center">
                    <Tooltip label="Back to apps" withArrow>
                        <ActionIcon variant="subtle" color="gray" component={Link} href="/apps"
                                    aria-label="Back to apps">
                            <IconArrowLeft size={18}/>
                        </ActionIcon>
                    </Tooltip>
                    <Title order={2}>App editor</Title>
                </Group>
                {selected && (
                    <Tooltip label={ADMIN_ONLY_REASON} withArrow disabled={isAdmin}>
                        <Box>
                            <Button
                                leftSection={<IconDeviceFloppy size={16}/>}
                                onClick={saveIdentity}
                                loading={saving}
                                disabled={!isAdmin || !dirty || bundleBad || !draft?.name.trim()}
                            >
                                {dirty ? "Save changes" : "Save"}
                            </Button>
                        </Box>
                    </Tooltip>
                )}
            </Group>

            {!isAdmin && (
                <Alert color="yellow" icon={<IconInfoCircle size={16}/>}>
                    {ADMIN_ONLY_REASON} You can view them here.
                </Alert>
            )}

            <SidebarLayout sidebarWidth={300} sidebar={
                <GlassCard withBorder padding="sm">
                    <Group gap={6} mb="xs" justify="space-between" wrap="nowrap">
                        <Group gap={6}>
                            <Text fw={600} fz="sm">Apps</Text>
                            <Badge size="sm" variant="light" color="gray">{apps.length}</Badge>
                        </Group>
                        <Tooltip label={isAdmin ? "Add app" : ADMIN_ONLY_REASON} withArrow>
                            <Box>
                                <ActionIcon
                                    variant="subtle"
                                    size="sm"
                                    disabled={!isAdmin}
                                    onClick={() => setNewAppOpen(true)}
                                    aria-label="Add app"
                                >
                                    <IconPlus size={16}/>
                                </ActionIcon>
                            </Box>
                        </Tooltip>
                    </Group>
                    {apps.length === 0 ? (
                        <Text fz="xs" c="dimmed" py="xs">
                            No apps defined yet. Add one with the plus above.
                        </Text>
                    ) : (
                        <ScrollArea.Autosize mah={wide ? "calc(100vh - 180px)" : 320} type="auto">
                            <Stack gap={2}>
                                {apps.map((a) => (
                                    <NavLink
                                        key={a.id}
                                        active={a.id === selected?.id}
                                        onClick={() => selectApp(a.id)}
                                        label={a.name}
                                        description={a.bundle_id}
                                        rightSection={
                                            <Badge size="sm" variant="light" color="gray">
                                                {a.versions.length}
                                            </Badge>
                                        }
                                        style={{borderRadius: "var(--mantine-radius-sm)"}}
                                    />
                                ))}
                            </Stack>
                        </ScrollArea.Autosize>
                    )}
                </GlassCard>
            }>

                {/* Right: the selected app */}
                <Box>
                    <GlassCard withBorder padding="md" mih={360}>
                        {!selected || !draft ? (
                            <Stack align="center" justify="center" mih={320} gap="xs">
                                <IconApps size={36} opacity={0.4}/>
                                <Text c="dimmed">
                                    {apps.length === 0
                                        ? "No apps to edit yet."
                                        : "Pick an app from the list."}
                                </Text>
                            </Stack>
                        ) : (
                            <Stack gap="md">
                                <Group justify="space-between" align="flex-start" wrap="nowrap">
                                    <Stack gap={2}>
                                        <Text fw={600}>{selected.name}</Text>
                                        <Text fz="xs" c="dimmed">
                                            id <Code fz="xs">{selected.id}</Code>
                                        </Text>
                                    </Stack>
                                    <Tooltip label={isAdmin ? "Delete app" : ADMIN_ONLY_REASON} withArrow>
                                        <Box>
                                            <ActionIcon
                                                variant="subtle"
                                                color="red"
                                                disabled={!isAdmin}
                                                onClick={() => deleteApp(selected)}
                                                aria-label={`Delete ${selected.name}`}
                                            >
                                                <IconTrash size={16}/>
                                            </ActionIcon>
                                        </Box>
                                    </Tooltip>
                                </Group>

                                <TextInput
                                    label="Display name"
                                    value={draft.name}
                                    onChange={(e) => setDraft({...draft, name: e.currentTarget.value})}
                                    disabled={!isAdmin}
                                    withAsterisk
                                    maw={420}
                                />
                                <TextInput
                                    label="Bundle ID"
                                    value={draft.bundle_id}
                                    onChange={(e) => setDraft({...draft, bundle_id: e.currentTarget.value})}
                                    error={draft.bundle_id && bundleBad ? "Invalid bundle identifier" : null}
                                    disabled={!isAdmin}
                                    withAsterisk
                                    maw={420}
                                />
                                <Switch
                                    label="Install as managed (macOS)"
                                    description={
                                        "Off lets macOS install packages that contain no .app, such as config or " +
                                        "script packages; on is required for the app to be removable by MDM."
                                    }
                                    checked={draft.managed}
                                    disabled={!isAdmin}
                                    onChange={(e) => setDraft({...draft, managed: e.currentTarget.checked})}
                                />

                                <Group justify="space-between" mt="sm">
                                    <Text fw={600} fz="sm">Versions</Text>
                                    <Tooltip label={ADMIN_ONLY_REASON} withArrow disabled={isAdmin}>
                                        <Box>
                                            <Button
                                                variant="light"
                                                size="xs"
                                                leftSection={<IconPlus size={14}/>}
                                                onClick={() => setWizardOpen(true)}
                                                disabled={!isAdmin}
                                            >
                                                Add version
                                            </Button>
                                        </Box>
                                    </Tooltip>
                                </Group>

                                {selected.versions.length === 0 ? (
                                    <Text fz="sm" c="dimmed">
                                        No versions yet; nothing installs until one exists.
                                    </Text>
                                ) : (
                                    <Table.ScrollContainer minWidth={520}>
                                        <Table verticalSpacing={6} fz="sm">
                                            <Table.Thead>
                                                <Table.Tr>
                                                    <Table.Th>Version</Table.Th>
                                                    <Table.Th>Groups</Table.Th>
                                                    <Table.Th>Constraints</Table.Th>
                                                    <Table.Th>Integrity</Table.Th>
                                                    <Table.Th/>
                                                </Table.Tr>
                                            </Table.Thead>
                                            <Table.Tbody>
                                                {selected.versions.map((v, vi) => (
                                                    <Table.Tr key={v.version}>
                                                        <Table.Td>
                                                            <Badge variant="light">v{v.version}</Badge>
                                                        </Table.Td>
                                                        <Table.Td>
                                                            <Group gap={4} wrap="wrap">
                                                                {v.groups.map((g) => (
                                                                    <Badge key={g} variant="dot" size="xs"
                                                                           color="blue">
                                                                        {g}
                                                                    </Badge>
                                                                ))}
                                                            </Group>
                                                        </Table.Td>
                                                        <Table.Td>
                                                            {v.conditions?.length ? (
                                                                v.conditions.map((c, ci) => (
                                                                    <Text key={ci} fz="xs" c="dimmed">
                                                                        {describeCondition(c)}
                                                                    </Text>
                                                                ))
                                                            ) : (
                                                                <Text fz="xs" c="dimmed">--</Text>
                                                            )}
                                                        </Table.Td>
                                                        <Table.Td>
                                                            <Tooltip label={v.sha256} withArrow>
                                                                <Code>{v.sha256.slice(0, 10)}…</Code>
                                                            </Tooltip>
                                                        </Table.Td>
                                                        <Table.Td>
                                                            <Group gap={4} wrap="nowrap" justify="flex-end">
                                                                <Tooltip
                                                                    label={isAdmin
                                                                        ? "Edit targeting"
                                                                        : ADMIN_ONLY_REASON}
                                                                    withArrow
                                                                >
                                                                    <Box>
                                                                        <ActionIcon
                                                                            variant="subtle"
                                                                            color="gray"
                                                                            size="sm"
                                                                            disabled={!isAdmin}
                                                                            onClick={() => setEditingIdx(vi)}
                                                                            aria-label={`Edit version ${v.version}`}
                                                                        >
                                                                            <IconPencil size={14}/>
                                                                        </ActionIcon>
                                                                    </Box>
                                                                </Tooltip>
                                                                <Tooltip label={ADMIN_ONLY_REASON} withArrow
                                                                         disabled={isAdmin}>
                                                                    <Box>
                                                                        <ActionIcon
                                                                            variant="subtle"
                                                                            color="red"
                                                                            size="sm"
                                                                            disabled={!isAdmin}
                                                                            onClick={() => deleteVersion(selected, vi)}
                                                                            aria-label={`Delete version ${v.version}`}
                                                                        >
                                                                            <IconTrash size={14}/>
                                                                        </ActionIcon>
                                                                    </Box>
                                                                </Tooltip>
                                                            </Group>
                                                        </Table.Td>
                                                    </Table.Tr>
                                                ))}
                                            </Table.Tbody>
                                        </Table>
                                    </Table.ScrollContainer>
                                )}

                                <AppDeployments key={selected.id} token={token} appId={selected.id}/>
                            </Stack>
                        )}
                    </GlassCard>
                </Box>
            </SidebarLayout>

            {/* Admin only, as the package picker and the upload call admin-only endpoints. */}
            {isAdmin && selected && (
                <AppWizard
                    opened={wizardOpen}
                    onClose={() => setWizardOpen(false)}
                    token={token ?? ""}
                    allGroups={allGroups}
                    devices={devices}
                    uploadBlockedReason={uploadBlockedReason}
                    takenIds={takenIds}
                    usedKeys={usedKeys}
                    existingApp={selected}
                    onFinish={handleFinish}
                />
            )}

            {/* Without existingApp the wizard creates a new app. */}
            {isAdmin && (
                <AppWizard
                    opened={newAppOpen}
                    onClose={() => setNewAppOpen(false)}
                    token={token ?? ""}
                    allGroups={allGroups}
                    devices={devices}
                    uploadBlockedReason={uploadBlockedReason}
                    takenIds={takenIds}
                    usedKeys={usedKeys}
                    onFinish={handleFinish}
                />
            )}

            {/* Mounted only while a row is being edited, so reopening it on another row starts from that row. */}
            {isAdmin && selected && editingVersion && editingIdx !== null && (
                <VersionScopeModal
                    key={`${selected.id}:${editingIdx}`}
                    app={selected}
                    version={editingVersion}
                    allGroups={allGroups}
                    devices={devices}
                    saving={saving}
                    onClose={() => setEditingIdx(null)}
                    onSave={async (scope, rollout) => {
                        const ok = await saveVersionScope(selected, editingIdx, scope, rollout);
                        if (ok) setEditingIdx(null);
                    }}
                />
            )}
        </Stack>
    );
}
