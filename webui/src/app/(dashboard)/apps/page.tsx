"use client";

import { useEffect, useState } from "react";
import {
  ActionIcon,
  Badge,
  Box,
  Button,
  Card,
  Code,
  Group,
  Loader,
  Modal,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { modals } from "@mantine/modals";
import {
  IconApps,
  IconHistory,
  IconPencil,
  IconPlus,
  IconTrash,
} from "@tabler/icons-react";
import { api, type Device } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";
import {
  BUNDLE_ID_RE,
  useConfigResource,
  type App,
  type AppsConfig,
  type AppVersion,
  type Group as GroupDef,
} from "../../../../lib/config";
import { AppWizard } from "../../../components/config/AppWizard";
import { ConfigHistoryDrawer } from "../../../components/config/ConfigHistoryDrawer";

export default function AppsPage() {
  const { token } = useAuth();
  const { data, loading, saving, save, reload, currentDocText } = useConfigResource<AppsConfig>(
    "apps",
    { apps: [] },
  );
  const [historyOpen, setHistoryOpen] = useState(false);

  const [groupNames, setGroupNames] = useState<string[]>([]);
  const [allGroups, setAllGroups] = useState<GroupDef[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [s3Configured, setS3Configured] = useState(false);

  const [wizardOpen, setWizardOpen] = useState(false);
  const [wizardApp, setWizardApp] = useState<App | undefined>(undefined);

  const [editApp, setEditApp] = useState<{ index: number; name: string; bundle_id: string } | null>(
    null,
  );

  useEffect(() => {
    if (!token) return;
    api
      .getConfig(token, "groups")
      .then((g) => {
        const gs = (g as { groups?: GroupDef[] }).groups ?? [];
        setAllGroups(gs);
        setGroupNames(gs.map((x) => x.name));
      })
      .catch(() => {});
    api
      .listDevices(token, { state: "enrolled", limit: 500 })
      .then((r) => setDevices(r.devices))
      .catch(() => {});
    api
      .getTenant(token)
      .then((t) => setS3Configured(!!(t.s3_config && (t.s3_config as { bucket?: string }).bucket)))
      .catch(() => {});
  }, [token]);

  const apps = data?.apps ?? [];

  async function handleFinish(
    result:
      | { kind: "app"; app: App }
      | { kind: "version"; appId: string; version: AppVersion },
  ): Promise<boolean> {
    if (result.kind === "app") {
      return save({ apps: [...apps, result.app] });
    }
    const next = apps.map((a) =>
      a.id === result.appId ? { ...a, versions: [...a.versions, result.version] } : a,
    );
    return save({ apps: next });
  }

  function openNewApp() {
    setWizardApp(undefined);
    setWizardOpen(true);
  }
  function openAddVersion(app: App) {
    setWizardApp(app);
    setWizardOpen(true);
  }

  function deleteApp(i: number) {
    modals.openConfirmModal({
      title: "Delete app",
      children: (
        <Text size="sm">
          Delete <b>{apps[i].name}</b> and all its versions? Devices will not be told to remove it
          automatically.
        </Text>
      ),
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () => save({ apps: apps.filter((_, idx) => idx !== i) }),
    });
  }

  function deleteVersion(appIdx: number, versionIdx: number) {
    const app = apps[appIdx];
    modals.openConfirmModal({
      title: "Delete version",
      children: (
        <Text size="sm">
          Remove version <b>{app.versions[versionIdx].version}</b> of {app.name}?
        </Text>
      ),
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () => {
        const next = apps.map((a, i) =>
          i === appIdx ? { ...a, versions: a.versions.filter((_, vi) => vi !== versionIdx) } : a,
        );
        save({ apps: next });
      },
    });
  }

  async function saveEdit() {
    if (!editApp) return;
    if (!BUNDLE_ID_RE.test(editApp.bundle_id) || !editApp.name.trim()) return;
    const next = apps.map((a, i) =>
      i === editApp.index ? { ...a, name: editApp.name.trim(), bundle_id: editApp.bundle_id.trim() } : a,
    );
    const ok = await save({ apps: next });
    if (ok) setEditApp(null);
  }

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-start">
        <Stack gap={0}>
          <Title order={2}>Apps</Title>
          <Text fz="sm" c="dimmed">
            Managed app packages and the device groups each version installs on.
          </Text>
        </Stack>
        <Group gap="xs">
          <Button
            variant="light"
            leftSection={<IconHistory size={14} />}
            onClick={() => setHistoryOpen(true)}
            disabled={loading}
          >
            History
          </Button>
          <Button leftSection={<IconPlus size={16} />} onClick={openNewApp} disabled={loading}>
            Add app
          </Button>
        </Group>
      </Group>

      {loading ? (
        <Box py={80} ta="center">
          <Loader />
        </Box>
      ) : apps.length === 0 ? (
        <Card withBorder radius="md" py={48}>
          <Stack align="center" gap="xs">
            <IconApps size={36} opacity={0.4} />
            <Text c="dimmed">No apps defined yet.</Text>
            <Button variant="light" leftSection={<IconPlus size={16} />} onClick={openNewApp}>
              Add your first app
            </Button>
          </Stack>
        </Card>
      ) : (
        <Stack gap="sm">
          {apps.map((app, i) => (
            <Card key={app.id} withBorder radius="md" padding="md">
              <Group justify="space-between" align="flex-start" wrap="nowrap" mb="sm">
                <Stack gap={2}>
                  <Group gap="xs">
                    <Text fw={600}>{app.name}</Text>
                    <Badge variant="light" color="gray" size="sm">
                      {app.versions.length} version{app.versions.length === 1 ? "" : "s"}
                    </Badge>
                  </Group>
                  <Text fz="xs" c="dimmed">
                    <Code>{app.bundle_id}</Code> · id <Code>{app.id}</Code>
                  </Text>
                </Stack>
                <Group gap={4}>
                  <Button
                    variant="subtle"
                    size="xs"
                    leftSection={<IconPlus size={14} />}
                    onClick={() => openAddVersion(app)}
                  >
                    Add version
                  </Button>
                  <Tooltip label="Edit name / bundle id" withArrow>
                    <ActionIcon variant="subtle" color="gray" onClick={() =>
                      setEditApp({ index: i, name: app.name, bundle_id: app.bundle_id })
                    }>
                      <IconPencil size={16} />
                    </ActionIcon>
                  </Tooltip>
                  <Tooltip label="Delete app" withArrow>
                    <ActionIcon variant="subtle" color="red" onClick={() => deleteApp(i)}>
                      <IconTrash size={16} />
                    </ActionIcon>
                  </Tooltip>
                </Group>
              </Group>

              {app.versions.length > 0 && (
                <Table verticalSpacing={6} fz="sm">
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Version</Table.Th>
                      <Table.Th>Groups</Table.Th>
                      <Table.Th>Constraints</Table.Th>
                      <Table.Th>Integrity</Table.Th>
                      <Table.Th />
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {app.versions.map((v, vi) => (
                      <Table.Tr key={v.version}>
                        <Table.Td>
                          <Badge variant="light">v{v.version}</Badge>
                        </Table.Td>
                        <Table.Td>
                          <Group gap={4} wrap="wrap">
                            {v.groups.map((g) => (
                              <Badge key={g} variant="dot" size="xs" color="blue">
                                {g}
                              </Badge>
                            ))}
                          </Group>
                        </Table.Td>
                        <Table.Td>
                          {v.conditions?.length ? (
                            v.conditions.map((c, ci) => (
                              <Text key={ci} fz="xs" c="dimmed">
                                OS {c.operator} {String(c.value)}
                              </Text>
                            ))
                          ) : (
                            <Text fz="xs" c="dimmed">
                              --
                            </Text>
                          )}
                        </Table.Td>
                        <Table.Td>
                          <Tooltip label={v.sha256} withArrow>
                            <Code>{v.sha256.slice(0, 10)}…</Code>
                          </Tooltip>
                        </Table.Td>
                        <Table.Td>
                          <ActionIcon
                            variant="subtle"
                            color="red"
                            size="sm"
                            onClick={() => deleteVersion(i, vi)}
                          >
                            <IconTrash size={14} />
                          </ActionIcon>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              )}
            </Card>
          ))}
        </Stack>
      )}

      <AppWizard
        opened={wizardOpen}
        onClose={() => setWizardOpen(false)}
        token={token ?? ""}
        groupNames={groupNames}
        allGroups={allGroups}
        devices={devices}
        s3Configured={s3Configured}
        takenIds={apps.map((a) => a.id)}
        existingApp={wizardApp}
        onFinish={handleFinish}
      />

      <Modal opened={!!editApp} onClose={() => setEditApp(null)} title="Edit app" size="md">
        {editApp && (
          <Stack gap="md">
            <TextInput
              label="Display name"
              value={editApp.name}
              onChange={(e) => setEditApp({ ...editApp, name: e.currentTarget.value })}
              withAsterisk
            />
            <TextInput
              label="Bundle ID"
              value={editApp.bundle_id}
              onChange={(e) => setEditApp({ ...editApp, bundle_id: e.currentTarget.value })}
              error={
                editApp.bundle_id && !BUNDLE_ID_RE.test(editApp.bundle_id)
                  ? "Invalid bundle identifier"
                  : null
              }
              withAsterisk
            />
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setEditApp(null)}>
                Cancel
              </Button>
              <Button onClick={saveEdit} loading={saving}>
                Save
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>

      <ConfigHistoryDrawer
        opened={historyOpen}
        onClose={() => setHistoryOpen(false)}
        type="apps"
        currentDoc={currentDocText}
        onRestored={reload}
      />
    </Stack>
  );
}
