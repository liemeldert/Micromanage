"use client";

import {useCallback, useEffect, useState} from "react";
import {Alert, Box, Button, Group, SegmentedControl, Stack,} from "@mantine/core";
import {IconInfoCircle, IconPlus} from "@tabler/icons-react";
import {api, ApiError, type DepServer, type DepServerDetail} from "../../../../lib/api";
import {useAuth} from "../../../../lib/auth-context";
import {DepWizard} from "@/components/dep/DepWizard";
import {DepServerPanel} from "@/components/dep/DepServerPanel";
import {PageSkeleton} from "@/components/layout/PageSkeleton";
import {PageHeader} from "@/components/layout/PageHeader";

export default function DepPage() {
    const {token, isAdmin} = useAuth();
    const [servers, setServers] = useState<DepServer[]>([]);
    const [detail, setDetail] = useState<DepServerDetail | null>(null);
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [addingNew, setAddingNew] = useState(false);

    const load = useCallback(async () => {
        if (!token) return;
        setLoading(true);
        setError(null);
        try {
            const {servers: list} = await api.listDepServers(token);
            setServers(list);
            // Prefer a linked server; else fall back to whatever exists (to resume linking).
            const linked = list.find((s) => s.status === "linked");
            const pick = linked ?? list[0] ?? null;
            setSelectedId((prev) => prev ?? pick?.id ?? null);
        } catch (e) {
            setError(e instanceof ApiError ? e.message : String(e));
        } finally {
            setLoading(false);
        }
    }, [token]);

    useEffect(() => {
        if (isAdmin) load();
        else setLoading(false);
    }, [isAdmin, load]);

    // Load the full detail for the selected server, clearing the old detail first so the panel never
    // shows the previous server's data and the wizard remounts with the right resume state.
    useEffect(() => {
        if (!token || !selectedId) {
            setDetail(null);
            return;
        }
        let alive = true;
        setDetail(null);
        api
            .getDepServer(token, selectedId)
            .then((d) => alive && setDetail(d))
            .catch(() => alive && setDetail(null));
        return () => {
            alive = false;
        };
    }, [token, selectedId]);

    if (!isAdmin) {
        return (
            <Box>
                <PageHeader/>
                <Alert color="gray" icon={<IconInfoCircle size={16}/>} mt="md">
                    Automated Device Enrollment is managed by tenant administrators.
                </Alert>
            </Box>
        );
    }

    if (loading) {
        return <PageSkeleton variant="table"/>;
    }

    const selected = servers.find((s) => s.id === selectedId) ?? null;
    const linkedSelected = selected?.status === "linked";
    const showWizard = addingNew || !selected || !linkedSelected;

    return (
        <Box>
            <PageHeader/>

            {error && (
                <Alert color="red" mt="md" title="Could not load your ABM/ASM connections">
                    {error}
                </Alert>
            )}

            {/* Connection switcher (only once there's more than one). */}
            {servers.length > 1 && !addingNew && (
                <Group mt="md" justify="space-between">
                    <SegmentedControl
                        value={selectedId ?? ""}
                        onChange={(v) => {
                            setSelectedId(v);
                            setAddingNew(false);
                        }}
                        data={servers.map((s) => ({
                            value: s.id,
                            label: s.account?.org_name || s.name,
                        }))}
                    />
                </Group>
            )}

            <Box mt="md">
                {showWizard ? (
                    <Stack gap="md">
                        {servers.length > 0 && addingNew && (
                            <Button variant="subtle" w="fit-content" onClick={() => setAddingNew(false)}>
                                ← Back to {selected?.account?.org_name || selected?.name || "connections"}
                            </Button>
                        )}
                        <DepWizard
                            key={addingNew ? "new" : detail?.id ?? "loading"}
                            existing={
                                !addingNew && detail && detail.status !== "linked" && detail.has_public_cert
                                    ? detail
                                    : null
                            }
                            onLinked={async (s) => {
                                setAddingNew(false);
                                setSelectedId(s.id);
                                setDetail(s);
                                await load();
                            }}
                            onRemoved={async () => {
                                setSelectedId(null);
                                setDetail(null);
                                setAddingNew(false);
                                await load();
                            }}
                        />
                    </Stack>
                ) : (
                    detail && (
                        <Stack gap="md">
                            <Group justify="flex-end">
                                <Button
                                    variant="subtle"
                                    size="xs"
                                    leftSection={<IconPlus size={14}/>}
                                    onClick={() => setAddingNew(true)}
                                >
                                    Add another connection
                                </Button>
                            </Group>
                            <DepServerPanel
                                key={detail.id}
                                server={detail}
                                onChanged={(s) => {
                                    setDetail(s);
                                    setServers((prev) => prev.map((x) => (x.id === s.id ? {...x, ...s} : x)));
                                }}
                                onUnlinked={async () => {
                                    setSelectedId(null);
                                    setDetail(null);
                                    setAddingNew(false);
                                    await load();
                                }}
                            />
                        </Stack>
                    )
                )}
            </Box>
        </Box>
    );
}
