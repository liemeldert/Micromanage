"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Badge,
  Box,
  Button,
  Drawer,
  Group,
  Loader,
  ScrollArea,
  Stack,
  Text,
} from "@mantine/core";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconArrowBackUp, IconHistory } from "@tabler/icons-react";
import { api, type ConfigVersion } from "../../../lib/api";
import { useAuth } from "../../../lib/auth-context";

type EditableType = "groups" | "apps" | "profiles";

/**
 * History drawer for a config document: lists prior versions (newest first),
 * shows a line-level diff of the selected version against what's live now, and
 * restores it (validated + re-snapshotted server-side, so a restore is itself
 * undoable). `currentDoc` is the live YAML text for the diff base.
 */
export function ConfigHistoryDrawer({
  opened,
  onClose,
  type,
  currentDoc,
  onRestored,
}: {
  opened: boolean;
  onClose: () => void;
  type: EditableType;
  currentDoc: string;
  onRestored: () => void;
}) {
  const { token } = useAuth();
  const [versions, setVersions] = useState<ConfigVersion[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedContent, setSelectedContent] = useState<string>("");
  const [loadingContent, setLoadingContent] = useState(false);
  const [restoring, setRestoring] = useState(false);

  const loadList = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = await api.listConfigHistory(token, type);
      setVersions(res.versions);
    } catch (e) {
      notifications.show({ color: "red", message: (e as Error).message });
    } finally {
      setLoading(false);
    }
  }, [token, type]);

  useEffect(() => {
    if (opened) {
      setSelectedId(null);
      setSelectedContent("");
      loadList();
    }
  }, [opened, loadList]);

  const selectVersion = async (id: string) => {
    if (!token) return;
    setSelectedId(id);
    setLoadingContent(true);
    try {
      const res = await api.getConfigVersion(token, type, id);
      setSelectedContent(res.content);
    } catch (e) {
      notifications.show({ color: "red", message: (e as Error).message });
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
      labels: { confirm: "Restore & apply", cancel: "Cancel" },
      confirmProps: { color: "orange" },
      onConfirm: () => doRestore(id),
    });
  };

  const doRestore = async (id: string) => {
    if (!token) return;
    setRestoring(true);
    try {
      const res = await api.restoreConfigVersion(token, type, id);
      notifications.show({
        color: "teal",
        title: "Restored",
        message: res.warnings?.length ? `Warnings: ${res.warnings.join("; ")}` : res.message,
      });
      onRestored();
      onClose();
    } catch (e) {
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

  const diff = selectedContent ? computeLineDiff(currentDoc, selectedContent) : [];

  return (
    <Drawer
      opened={opened}
      onClose={onClose}
      position="right"
      size="xl"
      title={
        <Group gap="xs">
          <IconHistory size={18} />
          <Text fw={600}>{type}.yaml history</Text>
        </Group>
      }
    >
      <Box style={{ display: "flex", gap: 16, height: "calc(100vh - 100px)" }}>
        {/* version list */}
        <Box style={{ flex: "0 0 240px", borderRight: "1px solid var(--mantine-color-default-border)", paddingRight: 12 }}>
          {loading ? (
            <Box ta="center" py="xl"><Loader size="sm" /></Box>
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
                      borderRadius: 6,
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
        <Box style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
          {!selectedId ? (
            <Text fz="sm" c="dimmed" py="md">
              Select a version to see what changed versus the current file.
            </Text>
          ) : loadingContent ? (
            <Box ta="center" py="xl"><Loader size="sm" /></Box>
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
                  leftSection={<IconArrowBackUp size={14} />}
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
                    borderRadius: 6,
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

// Minimal LCS line diff (base = current, target = the historical version).
// "+ this version" lines exist only in the old version; "− current" lines exist
// only in the live file. Small configs, so O(n·m) is fine.
function computeLineDiff(base: string, target: string): DiffLine[] {
  const a = base.replace(/\n$/, "").split("\n");
  const b = target.replace(/\n$/, "").split("\n");
  const n = a.length;
  const m = b.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
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
      out.push({ kind: "ctx", text: a[i] });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      out.push({ kind: "del", text: a[i] });
      i++;
    } else {
      out.push({ kind: "add", text: b[j] });
      j++;
    }
  }
  while (i < n) out.push({ kind: "del", text: a[i++] });
  while (j < m) out.push({ kind: "add", text: b[j++] });
  return out;
}
