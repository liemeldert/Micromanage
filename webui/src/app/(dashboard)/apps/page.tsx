"use client";

import {useEffect, useMemo, useState} from "react";
import {useRouter} from "next/navigation";
import {Alert, Box, Button, SimpleGrid, Stack, Text, Tooltip,} from "@mantine/core";
import {IconApps, IconHistory, IconInfoCircle, IconPlus} from "@tabler/icons-react";
import {api, type Device} from "../../../../lib/api";
import {useAuth} from "../../../../lib/auth-context";
import {useReadiness} from "../../../../lib/readiness";
import {
    type App,
    type AppsConfig,
    type AppVersion,
    type Group as GroupDef,
    useConfigResource,
} from "../../../../lib/config";
import {PageSkeleton} from "@/components/layout/PageSkeleton";
import {PageHeader} from "@/components/layout/PageHeader";
import {AppWizard} from "@/components/config/AppWizard";
import {AppCard} from "@/components/config/AppCard";
import {AppPeekModal} from "@/components/config/AppPeekModal";
import {ConfigHistoryDrawer} from "@/components/config/ConfigHistoryDrawer";
import {RolloutCountedNote} from "@/components/config/RolloutStatus";
import {toCounts, useRolloutStats} from "../../../../lib/rollout";
import {GlassCard} from "@/components/ui/GlassCard";

const ADMIN_ONLY_REASON =
    "Editing apps is restricted to administrators.";

export default function AppsPage() {
    const {token, isAdmin} = useAuth();
    const router = useRouter();
    const {data, loading, save, reload, currentDocText, version} =
        useConfigResource<AppsConfig>("apps", {apps: []});
    const [historyOpen, setHistoryOpen] = useState(false);
    const rollout = useRolloutStats("app");

    const [allGroups, setAllGroups] = useState<GroupDef[]>([]);
    const [devices, setDevices] = useState<Device[]>([]);

    const {readiness} = useReadiness();
    const appInstall = readiness?.capabilities.find((c) => c.capability === "app_install");
    const uploadBlockedReason = appInstall && !appInstall.ready ? appInstall.reason : null;

    const [wizardOpen, setWizardOpen] = useState(false);
    const [peekAppId, setPeekAppId] = useState<string | null>(null);

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

    const apps = useMemo(() => data?.apps ?? [], [data]);
    const peekApp = apps.find((a) => a.id === peekAppId) ?? null;
    const openEditor = (app: App) => router.push(`/apps/editor?app=${encodeURIComponent(app.id)}`);

    async function handleFinish(
        result:
            | { kind: "app"; app: App }
            | { kind: "version"; appId: string; version: AppVersion },
    ): Promise<boolean> {
        // Only the new-app path runs from this page; versions are added in the editor. The wizard reports both
        // results, so both are handled.
        if (result.kind === "app") {
            return save({apps: [...apps, result.app]});
        }
        const next = apps.map((a) =>
            a.id === result.appId ? {...a, versions: [...a.versions, result.version]} : a,
        );
        return save({apps: next});
    }

    return (
        <Stack gap="lg">
            <PageHeader
                description="" // I see no need for a description here.
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
                        <Tooltip label={ADMIN_ONLY_REASON} withArrow disabled={isAdmin}>
                            <Box>
                                <Button
                                    leftSection={<IconPlus size={16}/>}
                                    onClick={() => setWizardOpen(true)}
                                    disabled={loading || !isAdmin}
                                >
                                    Add app
                                </Button>
                            </Box>
                        </Tooltip>
                    </>
                }
            />

            {!isAdmin && (
                <Alert color="yellow" icon={<IconInfoCircle size={16}/>}>
                    {ADMIN_ONLY_REASON} You can view them here.
                </Alert>
            )}

            <RolloutCountedNote
                countedAt={rollout.stats?.counted_at}
                devicesEnrolled={rollout.stats?.devices_enrolled}
                error={rollout.error}
            />

            {loading ? (
                <PageSkeleton variant="grid"/>
            ) : apps.length === 0 ? (
                <GlassCard withBorder py={48}>
                    <Stack align="center" gap="xs">
                        <IconApps size={36} opacity={0.4}/>
                        <Text c="dimmed">No apps defined yet.</Text>
                        <Tooltip label={ADMIN_ONLY_REASON} withArrow disabled={isAdmin}>
                            <Box>
                                <Button
                                    variant="light"
                                    leftSection={<IconPlus size={16}/>}
                                    onClick={() => setWizardOpen(true)}
                                    disabled={!isAdmin}
                                >
                                    Add your first app
                                </Button>
                            </Box>
                        </Tooltip>
                    </Stack>
                </GlassCard>
            ) : (
                <SimpleGrid cols={{base: 1, sm: 2, lg: 3}} spacing="md">
                    {apps.map((app) => (
                        <AppCard
                            key={app.id}
                            app={app}
                            counts={toCounts(rollout.stats?.items[app.id])}
                            hasStats={rollout.stats !== null}
                            onPeek={() => setPeekAppId(app.id)}
                            onEdit={() => openEditor(app)}
                        />
                    ))}
                </SimpleGrid>
            )}

            <AppPeekModal
                app={peekApp}
                stats={peekApp ? rollout.stats?.items[peekApp.id] : undefined}
                opened={peekApp !== null}
                onClose={() => setPeekAppId(null)}
                onEdit={openEditor}
            />

            {isAdmin && (
                <AppWizard
                    opened={wizardOpen}
                    onClose={() => setWizardOpen(false)}
                    token={token ?? ""}
                    allGroups={allGroups}
                    devices={devices}
                    uploadBlockedReason={uploadBlockedReason}
                    takenIds={apps.map((a) => a.id)}
                    usedKeys={apps.flatMap((a) => a.versions.map((v) => v.s3_key))}
                    onFinish={handleFinish}
                />
            )}

            <ConfigHistoryDrawer
                opened={historyOpen}
                onClose={() => setHistoryOpen(false)}
                type="apps"
                currentDoc={currentDocText}
                currentVersion={version}
                onRestored={reload}
            />
        </Stack>
    );
}
