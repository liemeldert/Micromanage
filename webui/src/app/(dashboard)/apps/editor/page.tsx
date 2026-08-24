"use client";

// The full app editor: every app in a sidebar, the selected one's identity, versions and delete actions on the
// right. Laid out like the Dispatcher rule editor so the list stays in reach while a long form scrolls. The Apps
// page cards link here with ?app=<id>.

import {Suspense, useEffect, useMemo, useState} from "react";
import {useRouter, useSearchParams} from "next/navigation";
import {
    ActionIcon,
    Alert,
    Anchor,
    Badge,
    Box,
    Button,
    Code,
    Group,
    Loader,
    Modal,
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
import {clickable} from "../../../../../lib/a11y";
import {api, type AppDeploymentDevice, type Device} from "../../../../../lib/api";
import {useAuth} from "../../../../../lib/auth-context";
import {DEPLOYMENT_STATUS_COLORS, DEPLOYMENT_STATUS_LABELS} from "../../../../../lib/status-labels";
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
import {confirmDiscard} from "../../../../../lib/use-unsaved-changes";
import {AppWizard} from "@/components/config/AppWizard";
import {RolloutEditor} from "@/components/config/RolloutEditor";
import {ScopeEditor} from "@/components/config/ScopeEditor";
import {SidebarLayout} from "@/components/layout/SidebarLayout";
import {GlassCard} from "@/components/ui/GlassCard";

const ADMIN_ONLY_REASON =
    "Apps install software on every device in their groups, so authoring them is admin-only.";

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
                ? {
                    name: selected.name,
                    bundle_id: selected.bundle_id,
                    // Unset means the platform default, which is managed on a Mac. The toggle needs a definite state.
                    managed: selected.install_as_managed ?? true,
                }
                : null,
        );
    }, [selected]);

    const dirty =
        !!selected &&
        !!draft &&
        (draft.name !== selected.name ||
            draft.bundle_id !== selected.bundle_id ||
            draft.managed !== (selected.install_as_managed ?? true));
    const bundleBad = !!draft && !BUNDLE_ID_RE.test(draft.bundle_id);

    // The wizard needs the same context the Apps page gives it.
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

    // Select the first app when the page opens with no ?app=. replace rather than push, so Back does not step
    // through the default selection.
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
                    Delete <b>{app.name}</b> and all its versions? Devices will not be told to remove it
                    automatically.
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

    // Index of the version being edited in the selected app, or null when the modal is closed. The modal mounts
    // only while this is set, so reopening it on another row starts from that row's stored scope.
    const [editingIdx, setEditingIdx] = useState<number | null>(null);
    const editingVersion = selected && editingIdx !== null ? selected.versions[editingIdx] ?? null : null;

    // Row indices belong to one app, so switching apps in the sidebar has to drop the pending edit.
    useEffect(() => {
        setEditingIdx(null);
    }, [selectedId]);

    // Writes the edited scope back over one version, through the same save path deleteVersion uses.
    async function saveVersionScope(app: App, versionIdx: number, scope: Scope, rollout: Rollout | undefined) {
        const next = apps.map((a) =>
            a.id === app.id
                ? {
                    ...a,
                    versions: a.versions.map((v, vi) =>
                        vi === versionIdx
                            ? {
                                // Package identity stays exactly as stored: only the targeting fields are replaced.
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
            // Show the new app straight away rather than leaving the old selection in the form.
            if (ok) selectApp(result.app.id);
            return ok;
        }
        const next = apps.map((a) =>
            a.id === result.appId ? {...a, versions: [...a.versions, result.version]} : a,
        );
        return save({apps: next});
    }

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

                {/*  Right: the selected app  */}
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

            {/* Members never mount it: the package picker and the upload both use admin-only endpoints. */}
            {isAdmin && selected && (
                <AppWizard
                    opened={wizardOpen}
                    onClose={() => setWizardOpen(false)}
                    token={token ?? ""}
                    allGroups={allGroups}
                    devices={devices}
                    uploadBlockedReason={uploadBlockedReason}
                    takenIds={apps.map((a) => a.id)}
                    usedKeys={apps.flatMap((a) => a.versions.map((v) => v.s3_key))}
                    existingApp={selected}
                    onFinish={handleFinish}
                />
            )}

            {/* No existingApp, so this one runs the new-app flow the Apps page uses. */}
            {isAdmin && (
                <AppWizard
                    opened={newAppOpen}
                    onClose={() => setNewAppOpen(false)}
                    token={token ?? ""}
                    allGroups={allGroups}
                    devices={devices}
                    uploadBlockedReason={uploadBlockedReason}
                    takenIds={apps.map((a) => a.id)}
                    usedKeys={apps.flatMap((a) => a.versions.map((v) => v.s3_key))}
                    onFinish={handleFinish}
                />
            )}

            {/* Mounted only while a row is being edited, which keeps the form free of the previous row's state. */}
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

// Edits one stored version's targeting: groups, conditions, device overrides and the gradual rollout, in the
// same shape the wizard's Target step uses. The version string, key and digest name the package, so they are
// read-only here; pointing a deployed version at other bytes has to go through a new version instead.
function VersionScopeModal({
                               app,
                               version,
                               allGroups,
                               devices,
                               saving,
                               onClose,
                               onSave,
                           }: {
    app: App;
    version: AppVersion;
    allGroups: GroupDef[];
    devices: Device[];
    saving: boolean;
    onClose: () => void;
    onSave: (scope: Scope, rollout: Rollout | undefined) => Promise<void>;
}) {
    const stored: Scope = useMemo(
        () => ({
            groups: version.groups ?? [],
            conditions: version.conditions ?? [],
            ...(version.include_devices ? {include_devices: version.include_devices} : {}),
            ...(version.exclude_devices ? {exclude_devices: version.exclude_devices} : {}),
        }),
        [version],
    );
    const [scope, setScope] = useState<Scope>(stored);
    const [rollout, setRollout] = useState<Rollout | undefined>(version.rollout);

    const dirty =
        JSON.stringify(scope) !== JSON.stringify(stored) ||
        JSON.stringify(rollout ?? null) !== JSON.stringify(version.rollout ?? null);

    // Same rule as the wizard: a version has to name at least one group, condition or included device.
    const valid =
        (scope.groups?.length ?? 0) > 0 ||
        (scope.conditions?.length ?? 0) > 0 ||
        (scope.include_devices?.length ?? 0) > 0;

    function requestClose() {
        confirmDiscard({dirty, what: `version ${version.version}`, onConfirm: onClose});
    }

    return (
        <Modal opened onClose={requestClose} size="lg" title={`Edit v${version.version} of ${app.name}`}>
            <Stack gap="md">
                <Stack gap={4}>
                    <Text fz="xs" c="dimmed">
                        Key: <Code fz="xs">{version.s3_key}</Code>
                    </Text>
                    <Text fz="xs" c="dimmed">
                        SHA-256: <Code fz="xs">{version.sha256}</Code>
                    </Text>
                </Stack>
                <ScopeEditor
                    scope={scope}
                    onChange={setScope}
                    devices={devices}
                    allGroups={allGroups}
                    previous={stored}
                    groupsLabel="Install on groups"
                    groupsDescription="Devices in any of these groups receive this version."
                />
                <RolloutEditor rollout={rollout} onChange={setRollout}/>
                <Group justify="space-between" mt="sm">
                    <Button variant="default" onClick={requestClose}>Cancel</Button>
                    <Button
                        leftSection={<IconDeviceFloppy size={16}/>}
                        onClick={() => onSave(scope, rollout)}
                        loading={saving}
                        disabled={!dirty || !valid}
                    >
                        Save version
                    </Button>
                </Group>
            </Stack>
        </Modal>
    );
}

// Short badge words for the six deployment statuses. The shared labels map spells two of them out at length,
// which suits a detail line rather than a table cell, so it is used as the tooltip instead.
const DEPLOYMENT_STATUS_WORDS: Record<string, string> = {
    installed: "Installed",
    accepted: "Accepted",
    installing: "Installing",
    pending: "Pending",
    failed: "Failed",
    unscoped: "Left scope",
};

// Statuses that mean the install is under way rather than settled either direction.
const WORKING_STATUSES = ["pending", "installing", "accepted"];

// Which devices actually carry this app, device by device, under the app's versions. The grouped rollout stats
// answer how many; this answers which ones, and which of them are stuck.
function AppDeployments({token, appId}: { token: string | null; appId: string }) {
    const router = useRouter();
    const [devices, setDevices] = useState<AppDeploymentDevice[] | null>(null);
    const [loading, setLoading] = useState(true);
    const [loadError, setLoadError] = useState(false);

    useEffect(() => {
        if (!token) return;
        let cancelled = false;
        setLoading(true);
        setLoadError(false);
        api.getAppDeployments(token, appId)
            .then((r) => {
                if (cancelled) return;
                setDevices(r.devices);
            })
            .catch(() => {
                if (!cancelled) setLoadError(true);
            })
            .finally(() => {
                if (!cancelled) setLoading(false);
            });
        return () => {
            cancelled = true;
        };
    }, [token, appId]);

    const counts = useMemo(() => {
        const rows = devices ?? [];
        return {
            total: rows.length,
            installed: rows.filter((d) => d.status === "installed").length,
            working: rows.filter((d) => WORKING_STATUSES.includes(d.status)).length,
            failed: rows.filter((d) => d.status === "failed").length,
            unscoped: rows.filter((d) => d.status === "unscoped").length,
        };
    }, [devices]);

    return (
        <Stack gap="xs" mt="sm">
            <Text fw={600} fz="sm">Devices</Text>

            {loading ? (
                <Group gap="xs">
                    <Loader size="xs"/>
                    <Text fz="sm" c="dimmed">Counting devices…</Text>
                </Group>
            ) : loadError ? (
                <Text fz="sm" c="dimmed">
                    Could not read the install states for this app.
                </Text>
            ) : counts.total === 0 ? (
                <Text fz="sm" c="dimmed">
                    Not on any device yet. Devices join as the versions above pick up their groups.
                </Text>
            ) : (
                <>
                    <Group gap={6} wrap="wrap">
                        <Badge variant="light" color={DEPLOYMENT_STATUS_COLORS.installed} size="sm">
                            {counts.installed} installed
                        </Badge>
                        <Badge variant="light" color={DEPLOYMENT_STATUS_COLORS.installing} size="sm">
                            {counts.working} still working
                        </Badge>
                        <Badge variant="light" color={DEPLOYMENT_STATUS_COLORS.failed} size="sm">
                            {counts.failed} failed
                        </Badge>
                        {counts.unscoped > 0 && (
                            <Badge variant="light" color={DEPLOYMENT_STATUS_COLORS.unscoped} size="sm">
                                {counts.unscoped} left scope
                            </Badge>
                        )}
                        <Text fz="xs" c="dimmed">of {counts.total} devices</Text>
                    </Group>

                    <Table.ScrollContainer minWidth={620}>
                        <Table verticalSpacing={6} fz="sm" highlightOnHover>
                            <Table.Thead>
                                <Table.Tr>
                                    <Table.Th>Device</Table.Th>
                                    <Table.Th>Model</Table.Th>
                                    <Table.Th>Status</Table.Th>
                                    <Table.Th>Target</Table.Th>
                                    <Table.Th>Reports</Table.Th>
                                    <Table.Th>Error</Table.Th>
                                </Table.Tr>
                            </Table.Thead>
                            <Table.Tbody>
                                {(devices ?? []).map((d) => (
                                    <Table.Tr
                                        key={d.device_id}
                                        style={{cursor: "pointer"}}
                                        aria-label={`Open ${d.hostname || d.serial_number}`}
                                        {...clickable(() => router.push(`/devices/${d.device_id}`), "link")}
                                    >
                                        <Table.Td>
                                            <Anchor
                                                component={Link}
                                                href={`/devices/${d.device_id}`}
                                                fz="sm"
                                                fw={500}
                                                onClick={(e) => e.stopPropagation()}
                                            >
                                                {d.hostname || d.serial_number}
                                            </Anchor>
                                            {d.hostname && (
                                                <Text fz="xs" c="dimmed">{d.serial_number}</Text>
                                            )}
                                        </Table.Td>
                                        <Table.Td>
                                            <Text fz="xs" c="dimmed">{d.device_model || "--"}</Text>
                                        </Table.Td>
                                        <Table.Td>
                                            <Tooltip
                                                label={DEPLOYMENT_STATUS_LABELS[d.status] ?? d.status}
                                                withArrow
                                                disabled={!DEPLOYMENT_STATUS_LABELS[d.status]}
                                            >
                                                <Badge
                                                    variant="light"
                                                    size="sm"
                                                    color={DEPLOYMENT_STATUS_COLORS[d.status] ?? "gray"}
                                                >
                                                    {DEPLOYMENT_STATUS_WORDS[d.status] ?? d.status}
                                                </Badge>
                                            </Tooltip>
                                            {d.status === "failed" && d.failed_attempts > 1 && (
                                                <Text fz="xs" c="red" mt={2}>
                                                    {d.failed_attempts} attempts
                                                </Text>
                                            )}
                                        </Table.Td>
                                        <Table.Td>
                                            {d.desired_version
                                                ? <Text fz="xs">v{d.desired_version}</Text>
                                                : <Text fz="xs" c="dimmed">--</Text>}
                                        </Table.Td>
                                        <Table.Td>
                                            {d.reported_version
                                                ? <Text fz="xs">{d.reported_version}</Text>
                                                : <Text fz="xs" c="dimmed">--</Text>}
                                        </Table.Td>
                                        <Table.Td>
                                            {d.last_error ? (
                                                <Tooltip label={d.last_error} withArrow multiline w={360}>
                                                    <Text fz="xs" c="red" lineClamp={2}>{d.last_error}</Text>
                                                </Tooltip>
                                            ) : (
                                                <Text fz="xs" c="dimmed">--</Text>
                                            )}
                                        </Table.Td>
                                    </Table.Tr>
                                ))}
                            </Table.Tbody>
                        </Table>
                    </Table.ScrollContainer>
                </>
            )}
        </Stack>
    );
}
