"use client";

import {useState} from "react";
import {useRouter} from "next/navigation";
import {ActionIcon, Alert, Badge, Box, Button, Code, FileButton, Group, Stack, Text, Tooltip,} from "@mantine/core";
import {modals} from "@mantine/modals";
import {notifications} from "@mantine/notifications";
import {
    IconDownload,
    IconFileCertificate,
    IconHistory,
    IconInfoCircle,
    IconPencil,
    IconPlus,
    IconTrash,
    IconUpload,
} from "@tabler/icons-react";
import {useAuth} from "../../../../lib/auth-context";
import {type Profile, profilePayloads, type ProfilesConfig, useConfigResource,} from "../../../../lib/config";
import {getManifest} from "../../../../lib/profile-manifests";
import {saveTextFile} from "../../../../lib/download";
import {
    dateTypes,
    parseMobileconfig,
    type PlistTypes,
    profileToMobileconfig,
    undeclaredDataKeys,
    untypedDataPayloadTypes,
} from "../../../../lib/plist";
import {ConfigHistoryDrawer} from "@/components/config/ConfigHistoryDrawer";
import {IMPORT_KEY, IMPORT_TYPES_KEY, readDateTypes} from "@/components/config/ProfileEditor";
import {RolloutBadges, RolloutCountedNote} from "@/components/config/RolloutStatus";
import {toCounts, useRolloutStats} from "../../../../lib/rollout";
import {PageHeader} from "@/components/layout/PageHeader";
import {PageSkeleton} from "@/components/layout/PageSkeleton";
import {GlassCard} from "@/components/ui/GlassCard";

function slugify(s: string): string {
    return (
        s
            .toLowerCase()
            .replace(/[^a-z0-9._-]+/g, "-")
            .replace(/^-+|-+$/g, "")
            .slice(0, 60) || "profile"
    );
}

// Saving profiles.yaml is admin-only, and a member's reads come back with payload secrets redacted, so export is
// off for them too: the file would look real while carrying placeholders where the PSK and challenges belong.
const ADMIN_ONLY_REASON =
    "A profile changes settings on every device it targets, so authoring one is admin-only.";

export default function ProfilesPage() {
    const router = useRouter();
    const {isAdmin} = useAuth();
    const {data, loading, save, reload, currentDocText, version} =
        useConfigResource<ProfilesConfig>("profiles", {profiles: []});
    const [importing, setImporting] = useState(false);
    const [historyOpen, setHistoryOpen] = useState(false);
    // How far each profile has got across the fleet.
    const rollout = useRolloutStats("profile");

    const profiles = data?.profiles ?? [];

    async function handleImport(file: File | null) {
        if (!file) return;
        setImporting(true);
        try {
            const imp = parseMobileconfig(await file.text());
            if (!imp.payloads.length) {
                notifications.show({color: "orange", message: "No payloads found in that profile."});
                return;
            }
            // Data keys the manifests do not already cover go on the profile itself, so the controller types them as
            // data too.
            const dataKeys = undeclaredDataKeys(imp.payloads, imp.plistTypes);
            const profile: Profile = {
                id: slugify(imp.identifier || imp.name || "imported"),
                name: imp.name || "Imported profile",
                description: imp.description || "",
                type: "configuration",
                groups: [],
                payloads: imp.payloads,
                ...(dataKeys.length ? {data_keys: dataKeys} : {}),
            };
            sessionStorage.setItem(IMPORT_KEY, JSON.stringify(profile));
            // Dates are kept beside the draft because profiles.yaml has no way to record them. Clearing first keeps
            // an earlier import's dates off this profile.
            const dates = dateTypes(imp.plistTypes);
            if (Object.keys(dates).length) {
                sessionStorage.setItem(IMPORT_TYPES_KEY, JSON.stringify(dates));
            } else {
                sessionStorage.removeItem(IMPORT_TYPES_KEY);
            }
            notifications.show({
                color: "teal",
                message: `Imported ${imp.payloads.length} payload${imp.payloads.length === 1 ? "" : "s"}. Review and save.`,
            });
            router.push("/profiles/new");
        } catch (e: unknown) {
            notifications.show({
                color: "red",
                title: "Could not import",
                message: (e as Error).message,
                autoClose: 8000,
            });
        } finally {
            setImporting(false);
        }
    }

    function downloadProfile(p: Profile) {
        const payloads = profilePayloads(p);
        // Data types come from the profile's own data_keys, which the controller reads too, so the export matches
        // the profile devices receive. The tab-scoped record holds only dates.
        const plistTypes: PlistTypes = {...dateTypes(readDateTypes(p.id) ?? {})};
        for (const key of p.data_keys ?? []) plistTypes[key] = "data";
        const xml = profileToMobileconfig({
            id: p.id,
            name: p.name,
            description: p.description,
            payloads,
            plistTypes,
        });
        saveTextFile(`${p.id || "profile"}.mobileconfig`, xml, "application/x-apple-aspen-config");
        // Keys on a payload type no manifest describes and data_keys does not name. The server types from the same
        // two sources, so the device receives the same.
        const untyped = untypedDataPayloadTypes(payloads, plistTypes);
        if (untyped.length) {
            notifications.show({
                color: "orange",
                title: "Some values could not be typed",
                message: `Micromanage has no payload manifest for ${untyped.join(", ")}. Any certificate or other binary key in ${untyped.length === 1 ? "it" : "them"} is written as a string, here and in the profile devices receive, unless the profile lists it under "Keys sent as binary data". Set that in the editor, or re-import the original .mobileconfig.`,
                autoClose: 12000,
            });
        }
    }

    function handleDelete(p: Profile) {
        modals.openConfirmModal({
            title: "Delete profile",
            children: (
                <Text size="sm">
                    Delete profile <b>{p.name}</b>? It will be removed from devices in its groups on the
                    next sync. Unlike apps, profile removal is automatic.
                </Text>
            ),
            labels: {confirm: "Delete", cancel: "Cancel"},
            confirmProps: {color: "red"},
            onConfirm: () => save({profiles: profiles.filter((x) => x.id !== p.id)}),
        });
    }

    return (
        <Stack gap="lg">
            <PageHeader
                description="Configuration profiles set settings and restrictions on managed devices. Create one here, or import a .mobileconfig built in another tool. Enrollment profiles enroll devices into management; Micromanage generates those automatically."
                actions={
                    <>
                        <Button
                            variant="light"
                            leftSection={<IconHistory size={14}/>}
                            onClick={() => setHistoryOpen(true)}
                            disabled={loading}
                        >
                            History
                        </Button>
                        <FileButton onChange={handleImport}
                                    accept=".mobileconfig,.plist,application/x-apple-aspen-config">
                            {(props) => (
                                <Tooltip label={ADMIN_ONLY_REASON} withArrow disabled={isAdmin}>
                                    <Box>
                                        <Button
                                            variant="default"
                                            leftSection={<IconUpload size={16}/>}
                                            loading={importing}
                                            {...props}
                                            disabled={!isAdmin}
                                        >
                                            Import .mobileconfig
                                        </Button>
                                    </Box>
                                </Tooltip>
                            )}
                        </FileButton>
                        <Tooltip label={ADMIN_ONLY_REASON} withArrow disabled={isAdmin}>
                            <Box>
                                <Button
                                    leftSection={<IconPlus size={16}/>}
                                    onClick={() => router.push("/profiles/new")}
                                    disabled={loading || !isAdmin}
                                >
                                    New profile
                                </Button>
                            </Box>
                        </Tooltip>
                    </>
                }
            />

            {!isAdmin && (
                <Alert color="yellow" icon={<IconInfoCircle size={16}/>}>
                    {ADMIN_ONLY_REASON} You can view them here, with payload secrets redacted.
                </Alert>
            )}

            <RolloutCountedNote
                countedAt={rollout.stats?.counted_at}
                devicesEnrolled={rollout.stats?.devices_enrolled}
                error={rollout.error}
            />

            {loading ? (
                <PageSkeleton variant="grid"/>
            ) : profiles.length === 0 ? (
                <GlassCard withBorder py={48}>
                    <Stack align="center" gap="xs">
                        <IconFileCertificate size={36} opacity={0.4}/>
                        <Text c="dimmed">No profiles defined yet.</Text>
                        <Button
                            variant="light"
                            leftSection={<IconPlus size={16}/>}
                            onClick={() => router.push("/profiles/new")}
                        >
                            Create your first profile
                        </Button>
                    </Stack>
                </GlassCard>
            ) : (
                <Stack gap="sm">
                    {profiles.map((p) => {
                        const isDep = p.type === "enrollment" || p.dep_profile;
                        const payloads = profilePayloads(p);
                        return (
                            <GlassCard key={p.id} withBorder padding="md">
                                <Group justify="space-between" align="flex-start" wrap="nowrap">
                                    <Stack gap={6} style={{flex: 1, minWidth: 0}}>
                                        <Group gap="xs">
                                            <Text fw={600}>{p.name}</Text>
                                            <Badge color={isDep ? "grape" : "blue"} variant="light" size="sm">
                                                {isDep ? "Enrollment" : "Configuration"}
                                            </Badge>
                                            {!isDep && (
                                                <Badge color="gray" variant="light" size="sm">
                                                    {payloads.length} payload{payloads.length === 1 ? "" : "s"}
                                                </Badge>
                                            )}
                                        </Group>
                                        {p.description && (
                                            <Text fz="sm" c="dimmed">
                                                {p.description}
                                            </Text>
                                        )}
                                        <Group gap={6} wrap="wrap">
                                            <Text fz="xs" c="dimmed">
                                                id <Code>{p.id}</Code>
                                            </Text>
                                            {!isDep &&
                                                payloads.slice(0, 5).map((pl, i) => {
                                                    const m = getManifest(pl.PayloadType as string);
                                                    return (
                                                        <Badge key={i} variant="outline" size="xs" color="gray">
                                                            {m ? m.title : ((pl.PayloadType as string) ?? "custom")}
                                                        </Badge>
                                                    );
                                                })}
                                            {(p.groups ?? []).length === 0 ? (
                                                <Badge variant="outline" color="orange" size="sm">
                                                    no groups
                                                </Badge>
                                            ) : (
                                                (p.groups ?? []).map((g) => (
                                                    <Badge key={g} variant="dot" size="sm" color="blue">
                                                        {g}
                                                    </Badge>
                                                ))
                                            )}
                                        </Group>
                                        <RolloutBadges
                                            counts={toCounts(rollout.stats?.items[p.id])}
                                            hasSummary={rollout.stats !== null}
                                        />
                                    </Stack>
                                    <Group gap={4}>
                                        {!isDep && payloads.length > 0 && (
                                            <Tooltip
                                                label={
                                                    isAdmin
                                                        ? "Download .mobileconfig"
                                                        : "Your copy of this profile has its secrets redacted, so the export would not be the real thing."
                                                }
                                                withArrow
                                            >
                                                <Box>
                                                    <ActionIcon
                                                        variant="subtle"
                                                        color="gray"
                                                        onClick={() => downloadProfile(p)}
                                                        disabled={!isAdmin}
                                                    >
                                                        <IconDownload size={16}/>
                                                    </ActionIcon>
                                                </Box>
                                            </Tooltip>
                                        )}
                                        <Button
                                            variant="subtle"
                                            size="xs"
                                            leftSection={<IconPencil size={14}/>}
                                            onClick={() => router.push(`/profiles/${encodeURIComponent(p.id)}`)}
                                        >
                                            {isAdmin ? "Edit" : "View"}
                                        </Button>
                                        <Tooltip label={ADMIN_ONLY_REASON} withArrow disabled={isAdmin}>
                                            <Box>
                                                <Button
                                                    variant="subtle"
                                                    color="red"
                                                    size="xs"
                                                    leftSection={<IconTrash size={14}/>}
                                                    onClick={() => handleDelete(p)}
                                                    disabled={!isAdmin}
                                                >
                                                    Delete
                                                </Button>
                                            </Box>
                                        </Tooltip>
                                    </Group>
                                </Group>
                            </GlassCard>
                        );
                    })}
                </Stack>
            )}

            <ConfigHistoryDrawer
                opened={historyOpen}
                onClose={() => setHistoryOpen(false)}
                type="profiles"
                currentDoc={currentDocText}
                currentVersion={version}
                onRestored={reload}
            />
        </Stack>
    );
}
