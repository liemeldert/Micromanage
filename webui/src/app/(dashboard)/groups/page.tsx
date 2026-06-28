"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Badge,
  Box,
  Button,
  Card,
  Group,
  Loader,
  Modal,
  Stack,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { modals } from "@mantine/modals";
import {
  IconAlertTriangle,
  IconDevices2,
  IconPencil,
  IconPlus,
  IconStack2,
  IconTrash,
} from "@tabler/icons-react";
import { api, type Device } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";
import {
  deviceMatchesGroup,
  describeCondition,
  GROUP_NAME_RE,
  useConfigResource,
  type Condition,
  type Group as GroupT,
  type GroupsConfig,
} from "../../../../lib/config";
import { ConditionBuilder } from "../../../components/config/ConditionBuilder";

export default function GroupsPage() {
  const { token } = useAuth();
  const { data, loading, saving, save } = useConfigResource<GroupsConfig>("groups", {
    groups: [],
  });
  const [devices, setDevices] = useState<Device[]>([]);

  const [modalOpen, setModalOpen] = useState(false);
  const [editIndex, setEditIndex] = useState<number | null>(null);
  const [draft, setDraft] = useState<GroupT>({ name: "", description: "", conditions: [] });
  const [nameError, setNameError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    api
      .listDevices(token, { limit: 500 })
      .then((r) => setDevices(r.devices))
      .catch(() => {});
  }, [token]);

  const groups = useMemo(() => data?.groups ?? [], [data]);

  const matchCounts = useMemo(
    () => groups.map((g) => devices.filter((d) => deviceMatchesGroup(d, g.conditions)).length),
    [groups, devices],
  );

  const draftMatches = useMemo(
    () => devices.filter((d) => deviceMatchesGroup(d, draft.conditions)),
    [devices, draft.conditions],
  );

  function openNew() {
    setDraft({ name: "", description: "", conditions: [] });
    setEditIndex(null);
    setNameError(null);
    setModalOpen(true);
  }

  function openEdit(i: number) {
    setDraft(structuredClone(groups[i]));
    setEditIndex(i);
    setNameError(null);
    setModalOpen(true);
  }

  function validateName(name: string): string | null {
    if (!name.trim()) return "Name is required";
    if (!GROUP_NAME_RE.test(name)) return "Only letters, numbers, hyphens and underscores";
    const clash = groups.some((g, i) => g.name === name && i !== editIndex);
    if (clash) return "A group with this name already exists";
    return null;
  }

  async function handleSave() {
    const err = validateName(draft.name);
    setNameError(err);
    if (err) return;
    const cleaned: GroupT = {
      name: draft.name.trim(),
      ...(draft.description?.trim() ? { description: draft.description.trim() } : {}),
      conditions: draft.conditions,
    };
    const next = [...groups];
    if (editIndex === null) next.push(cleaned);
    else next[editIndex] = cleaned;
    const ok = await save({ groups: next });
    if (ok) setModalOpen(false);
  }

  function handleDelete(i: number) {
    modals.openConfirmModal({
      title: "Delete group",
      children: (
        <Text size="sm">
          Delete group <b>{groups[i].name}</b>? Apps and profiles that target it will no longer
          match these devices.
        </Text>
      ),
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () => {
        save({ groups: groups.filter((_, idx) => idx !== i) });
      },
    });
  }

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-start">
        <Stack gap={0}>
          <Title order={2}>Groups</Title>
          <Text fz="sm" c="dimmed">
            Dynamically segment enrolled devices with conditions. Apps and profiles target these
            groups by name.
          </Text>
        </Stack>
        <Button leftSection={<IconPlus size={16} />} onClick={openNew} disabled={loading}>
          New group
        </Button>
      </Group>

      {loading ? (
        <Box py={80} ta="center">
          <Loader />
        </Box>
      ) : groups.length === 0 ? (
        <Card withBorder radius="md" py={48}>
          <Stack align="center" gap="xs">
            <IconStack2 size={36} opacity={0.4} />
            <Text c="dimmed">No groups yet.</Text>
            <Button variant="light" leftSection={<IconPlus size={16} />} onClick={openNew}>
              Create your first group
            </Button>
          </Stack>
        </Card>
      ) : (
        <Stack gap="sm">
          {groups.map((g, i) => (
            <Card key={g.name} withBorder radius="md" padding="md">
              <Group justify="space-between" align="flex-start" wrap="nowrap">
                <Stack gap={6} style={{ flex: 1, minWidth: 0 }}>
                  <Group gap="xs">
                    <Text fw={600}>{g.name}</Text>
                    <Tooltip label="Estimated from currently-loaded devices" withArrow>
                      <Badge
                        variant="light"
                        color={matchCounts[i] ? "teal" : "gray"}
                        leftSection={<IconDevices2 size={12} />}
                      >
                        ≈ {matchCounts[i]} device{matchCounts[i] === 1 ? "" : "s"}
                      </Badge>
                    </Tooltip>
                  </Group>
                  {g.description && (
                    <Text fz="sm" c="dimmed">
                      {g.description}
                    </Text>
                  )}
                  <Group gap={6} wrap="wrap">
                    {g.conditions.length === 0 ? (
                      <Badge variant="outline" color="orange" size="sm">
                        no conditions — matches nothing
                      </Badge>
                    ) : (
                      g.conditions.map((c: Condition, ci: number) => (
                        <Badge key={ci} variant="light" size="sm" color="blue">
                          {describeCondition(c)}
                        </Badge>
                      ))
                    )}
                  </Group>
                </Stack>
                <Group gap={4}>
                  <Button
                    variant="subtle"
                    size="xs"
                    leftSection={<IconPencil size={14} />}
                    onClick={() => openEdit(i)}
                  >
                    Edit
                  </Button>
                  <Button
                    variant="subtle"
                    color="red"
                    size="xs"
                    leftSection={<IconTrash size={14} />}
                    onClick={() => handleDelete(i)}
                  >
                    Delete
                  </Button>
                </Group>
              </Group>
            </Card>
          ))}
        </Stack>
      )}

      <Modal
        opened={modalOpen}
        onClose={() => setModalOpen(false)}
        title={editIndex === null ? "New group" : `Edit group`}
        size="lg"
      >
        <Stack gap="md">
          <TextInput
            label="Name"
            description="Referenced by apps and profiles. Letters, numbers, hyphens, underscores."
            placeholder="e.g. macbooks-engineering"
            value={draft.name}
            error={nameError}
            onChange={(e) => {
              setDraft({ ...draft, name: e.currentTarget.value });
              if (nameError) setNameError(validateName(e.currentTarget.value));
            }}
            withAsterisk
          />
          <TextInput
            label="Description"
            placeholder="Optional, human-readable"
            value={draft.description ?? ""}
            onChange={(e) => setDraft({ ...draft, description: e.currentTarget.value })}
          />

          <Box>
            <Text fz="sm" fw={500} mb={4}>
              Conditions
            </Text>
            <ConditionBuilder
              conditions={draft.conditions}
              onChange={(conditions) => setDraft({ ...draft, conditions })}
            />
          </Box>

          <Alert
            variant="light"
            color={draftMatches.length ? "teal" : "gray"}
            icon={<IconDevices2 size={16} />}
          >
            <Text fz="sm">
              Matches <b>≈ {draftMatches.length}</b> of {devices.length} loaded device
              {devices.length === 1 ? "" : "s"}.
              {draftMatches.length > 0 && (
                <Text span c="dimmed" fz="xs">
                  {" "}
                  ({draftMatches.slice(0, 4).map((d) => d.serial_number).join(", ")}
                  {draftMatches.length > 4 ? "…" : ""})
                </Text>
              )}
            </Text>
          </Alert>

          {draft.conditions.length === 0 && (
            <Group gap={6}>
              <IconAlertTriangle size={14} color="var(--mantine-color-orange-6)" />
              <Text fz="xs" c="orange.7">
                A group with no conditions matches no devices.
              </Text>
            </Group>
          )}

          <Group justify="flex-end">
            <Button variant="default" onClick={() => setModalOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleSave} loading={saving}>
              {editIndex === null ? "Create group" : "Save changes"}
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
}
