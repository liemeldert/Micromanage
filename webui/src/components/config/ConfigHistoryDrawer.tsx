"use client";

import {useCallback, useEffect, useState} from "react";
import {Badge, Box, Button, Drawer, Group, Loader, ScrollArea, Stack, Text,} from "@mantine/core";
import {modals} from "@mantine/modals";
import {notifications} from "@mantine/notifications";
import {IconArrowBackUp, IconHistory} from "@tabler/icons-react";
import {api, configConflict, type ConfigVersion} from "../../../lib/api";
import {useAuth} from "../../../lib/auth-context";
import {showConfigConflict} from "../../../lib/config";

type EditableType = "groups" | "apps" | "profiles" | "declarations";

/**
 * History drawer for a config document: prior versions newest first, a line diff against the live
 * file, and a restore. Restoring replaces the whole file, so currentVersion goes out as If-Match and
 * is refused if someone else has saved since; the server snapshots first, so a restore is undoable.
 * The diff base is the live file's own text, since re-serializing the editors' parsed JSON reformats
 * the YAML and marks every line changed.
 */
export function ConfigHistoryDrawer({
                                        opened,
                                        onClose,
                                        type,
                                        currentDoc,
                                        currentVersion,
                                        onRestored,
                                    }: {
    opened: boolean;
    onClose: () => void;
    type: EditableType;
    currentDoc: string;
    currentVersion?: string;
    onRestored: () => void;
}) {
    const {token} = useAuth();
    const [versions, setVersions] = useState<ConfigVersion[]>([]);
    const [loading, setLoading] = useState(false);
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [selectedContent, setSelectedContent] = useState<string>("");
    const [loadingContent, setLoadingContent] = useState(false);
    const [restoring, setRestoring] = useState(false);
    // The diff base. Null until it arrives, and if the fetch fails the diff uses currentDoc.
    const [liveDoc, setLiveDoc] = useState<string | null>(null);

    const loadList = useCallback(async () => {
        if (!token) return;
        setLoading(true);
        try {
            const res = await api.listConfigHistory(token, type);
            setVersions(res.versions);
        } catch (e) {
            notifications.show({color: "red", message: (e as Error).message});
        } finally {
            setLoading(false);
        }
    }, [token, type]);

    useEffect(() => {
        if (opened) {
            setSelectedId(null);
            setSelectedContent("");
            setLiveDoc(null);
            loadList();
        }
    }, [opened, loadList]);

    useEffect(() => {
        if (!opened || !token) return;
        let stale = false;
        api
            .getConfigRaw(token, type)
            .then((r) => {
                if (!stale) setLiveDoc(r.text);
            })
            .catch(() => {
            });
        return () => {
            stale = true;
        };
    }, [opened, token, type]);

    const selectVersion = async (id: string) => {
        if (!token) return;
        setSelectedId(id);
        setLoadingContent(true);
        try {
            const res = await api.getConfigVersion(token, type, id);
            setSelectedContent(res.content);
        } catch (e) {
            notifications.show({color: "red", message: (e as Error).message});
            setSelectedContent("");
        } finally {
            setLoadingContent(false);
        }
    };

    const confirmRestore = (id: string) => {
        modals.openConfirmModal({
            title: "Restore this version?",
            children: (
                <Text size="sm">
                    This replaces the live <b>{type}.yaml</b> with version <b>{id}</b>, then validates and
                    reconciles devices. The current version is saved to history first, so you can undo it.
                </Text>
            ),
            labels: {confirm: "Restore & apply", cancel: "Cancel"},
            confirmProps: {color: "orange"},
            onConfirm: () => doRestore(id),
        });
    };

    const doRestore = async (id: string) => {
        if (!token) return;
        setRestoring(true);
        try {
            const res = await api.restoreConfigVersion(token, type, id, {ifMatch: currentVersion});
            notifications.show({
                color: "teal",
                title: "Restored",
                message: res.warnings?.length ? `Warnings: ${res.warnings.join("; ")}` : res.message,
            });
            onRestored();
            onClose();
        } catch (e) {
            const conflict = configConflict(e);
            if (conflict) {
                // The diff on screen was computed against a document that is no longer live, so
                // reload rather than restore over it.
                showConfigConflict(conflict.message, () => {
                    onRestored();
                    onClose();
                });
                return;
            }
            notifications.show({
                color: "red",
                title: "Restore failed",
                message: (e as Error).message,
                autoClose: 8000,
            });
        } finally {
            setRestoring(false);
        }
    };

    const diff = selectedContent ? computeLineDiff(liveDoc ?? currentDoc, selectedContent) : [];

    return (
        <Drawer
            opened={opened}
            onClose={onClose}
            position="right"
            size="xl"
            title={
                <Group gap="xs">
                    <IconHistory size={18}/>
                    <Text fw={600}>{type}.yaml history</Text>
                </Group>
            }
        >
            <Box style={{display: "flex", gap: 16, height: "calc(100vh - 100px)"}}>
                {/* version list */}
                <Box style={{
                    flex: "0 0 240px",
                    borderRight: "1px solid var(--mantine-color-default-border)",
                    paddingRight: 12
                }}>
                    {loading ? (
                        <Box ta="center" py="xl"><Loader size="sm"/></Box>
                    ) : versions.length === 0 ? (
                        <Text fz="sm" c="dimmed" py="md">
                            No previous versions yet. They accumulate each time you save this config.
                        </Text>
                    ) : (
                        <ScrollArea.Autosize mah="100%">
                            <Stack gap={4}>
                                {versions.map((v) => (
                                    <Box
                                        key={v.id}
                                        p="xs"
                                        style={{
                                            borderRadius: "var(--mantine-radius-sm)",
                                            cursor: "pointer",
                                            background: v.id === selectedId ? "var(--mantine-color-blue-light)" : undefined,
                                        }}
                                        onClick={() => selectVersion(v.id)}
                                    >
                                        <Text fz="xs" fw={500}>{formatTime(v.saved_at)}</Text>
                                        <Text fz={10} c="dimmed" truncate>
                                            {v.user ?? "unknown"}
                                        </Text>
                                    </Box>
                                ))}
                            </Stack>
                        </ScrollArea.Autosize>
                    )}
                </Box>

                {/* diff view */}
                <Box style={{flex: 1, minWidth: 0, display: "flex", flexDirection: "column"}}>
                    {!selectedId ? (
                        <Text fz="sm" c="dimmed" py="md">
                            Select a version to see what changed versus the current file.
                        </Text>
                    ) : loadingContent ? (
                        <Box ta="center" py="xl"><Loader size="sm"/></Box>
                    ) : (
                        <>
                            <Group justify="space-between" mb="xs">
                                <Group gap={6}>
                                    <Badge size="sm" variant="light" color="red">− current</Badge>
                                    <Badge size="sm" variant="light" color="teal">+ this version</Badge>
                                </Group>
                                <Button
                                    size="xs"
                                    color="orange"
                                    variant="light"
                                    leftSection={<IconArrowBackUp size={14}/>}
                                    loading={restoring}
                                    onClick={() => confirmRestore(selectedId)}
                                >
                                    Restore this version
                                </Button>
                            </Group>
                            <ScrollArea.Autosize mah="100%" type="auto">
                                <Box
                                    style={{
                                        fontFamily: "var(--mantine-font-family-monospace)",
                                        fontSize: 12,
                                        lineHeight: 1.5,
                                        border: "1px solid var(--mantine-color-default-border)",
                                        borderRadius: "var(--mantine-radius-sm)",
                                        overflow: "hidden",
                                    }}
                                >
                                    {diff.length === 0 ? (
                                        <Text fz="xs" c="dimmed" p="sm">Identical to the current file.</Text>
                                    ) : (
                                        diff.map((line, i) => (
                                            <Box
                                                key={i}
                                                px="sm"
                                                style={{
                                                    whiteSpace: "pre-wrap",
                                                    wordBreak: "break-word",
                                                    background:
                                                        line.kind === "add"
                                                            ? "var(--mantine-color-teal-light)"
                                                            : line.kind === "del"
                                                                ? "var(--mantine-color-red-light)"
                                                                : undefined,
                                                    color: line.kind === "ctx" ? "var(--mantine-color-dimmed)" : undefined,
                                                }}
                                            >
                                                {line.kind === "add" ? "+ " : line.kind === "del" ? "− " : "  "}
                                                {line.text || " "}
                                            </Box>
                                        ))
                                    )}
                                </Box>
                            </ScrollArea.Autosize>
                        </>
                    )}
                </Box>
            </Box>
        </Drawer>
    );
}

function formatTime(iso: string | null): string {
    if (!iso) return "unknown time";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString();
}

interface DiffLine {
    kind: "ctx" | "add" | "del";
    text: string;
}

// Minimal LCS line diff, base being the live file and target the historical version. Configs are
// small enough for O(n*m).
function computeLineDiff(base: string, target: string): DiffLine[] {
    const a = base.replace(/\n$/, "").split("\n");
    const b = target.replace(/\n$/, "").split("\n");
    const n = a.length;
    const m = b.length;
    const lcs: number[][] = Array.from({length: n + 1}, () => new Array(m + 1).fill(0));
    for (let i = n - 1; i >= 0; i--) {
        for (let j = m - 1; j >= 0; j--) {
            lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
        }
    }
    const out: DiffLine[] = [];
    let i = 0;
    let j = 0;
    while (i < n && j < m) {
        if (a[i] === b[j]) {
            out.push({kind: "ctx", text: a[i]});
            i++;
            j++;
        } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
            out.push({kind: "del", text: a[i]});
            i++;
        } else {
            out.push({kind: "add", text: b[j]});
            j++;
        }
    }
    while (i < n) out.push({kind: "del", text: a[i++]});
    while (j < m) out.push({kind: "add", text: b[j++]});
    return out;
}
