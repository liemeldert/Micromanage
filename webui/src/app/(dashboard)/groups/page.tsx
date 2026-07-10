"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Badge,
  Box,
  Button,
  Card,
  Code,
  Collapse,
  Divider,
  Group,
  Loader,
  Modal,
  Stack,
  Switch,
  Text,
  TextInput,
  Title,
  Tooltip,
  UnstyledButton,
} from "@mantine/core";
import { modals } from "@mantine/modals";
import {
  IconAlertTriangle,
  IconChevronRight,
  IconDevices2,
  IconHistory,
  IconPencil,
  IconPlus,
  IconStack2,
  IconTag,
  IconTrash,
  IconUserCheck,
  IconUserX,
} from "@tabler/icons-react";
import { api, type Device } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";
import {
  deviceInGroup,
  describeCondition,
  GROUP_NAME_RE,
  isSelfReferentialTemplate,
  renderNameTemplate,
  unknownNameVariables,
  useConfigResource,
  useTagRegistry,
  type Condition,
  type Group as GroupT,
  type GroupsConfig,
} from "../../../../lib/config";
import { ConditionBuilder } from "../../../components/config/ConditionBuilder";
import { ConfigHistoryDrawer } from "../../../components/config/ConfigHistoryDrawer";
import { DevicePicker } from "../../../components/config/DevicePicker";
import { NameTemplateInput } from "../../../components/config/NameTemplateInput";

export default function GroupsPage() {
  const { token } = useAuth();
  const { data, loading, saving, save, reload, currentDocText } = useConfigResource<GroupsConfig>(
    "groups",
    { groups: [] },
  );
  const [devices, setDevices] = useState<Device[]>([]);
  const [historyOpen, setHistoryOpen] = useState(false);

  const [modalOpen, setModalOpen] = useState(false);
  const [editIndex, setEditIndex] = useState<number | null>(null);
  const [draft, setDraft] = useState<GroupT>({ name: "", description: "", conditions: [] });
  const [nameError, setNameError] = useState<string | null>(null);
  const [cherryOpen, setCherryOpen] = useState(false);

  useEffect(() => {
    if (!token) return;
    api
      .listDevices(token, { state: "enrolled", limit: 500 })
      .then((r) => setDevices(r.devices))
      .catch(() => {});
  }, [token]);

  const groups = useMemo(() => data?.groups ?? [], [data]);

  // Membership-aware counts: honor group-refs, NOT, and include/exclude.
  const matchCounts = useMemo(
    () => groups.map((g) => devices.filter((d) => deviceInGroup(d, g, groups)).length),
    [groups, devices],
  );

  // Evaluate the draft against a group set where the draft replaces the group
  // being edited (so self-consistent group-refs resolve to the live edits).
  const draftGroupSet = useMemo(() => {
    if (editIndex === null) return [...groups, draft];
    return groups.map((g, i) => (i === editIndex ? draft : g));
  }, [groups, draft, editIndex]);

  const draftMatches = useMemo(
    () => devices.filter((d) => deviceInGroup(d, draft, draftGroupSet)),
    [devices, draft, draftGroupSet],
  );

  // Other groups' names, for the group-membership condition (exclude self).
  const otherGroupNames = useMemo(
    () => groups.filter((_, i) => i !== editIndex).map((g) => g.name),
    [groups, editIndex],
  );
  const { tagNames } = useTagRegistry();

  const conditionSuggestions = useMemo(
    () => ({
      device_model: uniqStrings(devices.map((d) => d.device_model)),
      hostname: uniqStrings(devices.map((d) => d.hostname)),
      serial_number: uniqStrings(devices.map((d) => d.serial_number)),
      os_version: uniqStrings(devices.map((d) => d.os_version)),
    }),
    [devices],
  );

  // ── Naming template (optional per-group) ──
  const namingTemplate = draft.device_naming?.template ?? "";
  const applyOnEnroll = draft.device_naming?.apply_on_enroll ?? false;
  const setNaming = (patch: Partial<{ template: string; apply_on_enroll: boolean }>) =>
    setDraft((d) => ({
      ...d,
      device_naming: {
        template: patch.template ?? d.device_naming?.template ?? "",
        apply_on_enroll: patch.apply_on_enroll ?? d.device_naming?.apply_on_enroll ?? false,
      },
    }));
  // Preview against a device that matches this group, else any loaded device.
  const namingSample = draftMatches[0] ?? devices[0] ?? null;
  const namingPreview =
    namingTemplate && namingSample ? renderNameTemplate(namingTemplate, namingSample) : "";
  const unknownVars = unknownNameVariables(namingTemplate);
  const selfReferential = isSelfReferentialTemplate(namingTemplate);

  function openNew() {
    setDraft({ name: "", description: "", conditions: [] });
    setEditIndex(null);
    setNameError(null);
    setCherryOpen(false);
    setModalOpen(true);
  }

  function openEdit(i: number) {
    const g = structuredClone(groups[i]);
    setDraft(g);
    setEditIndex(i);
    setNameError(null);
    setCherryOpen((g.include_devices?.length ?? 0) + (g.exclude_devices?.length ?? 0) > 0);
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
    if (selfReferential) return;
    const tpl = draft.device_naming?.template?.trim() ?? "";
    const cleaned: GroupT = {
      name: draft.name.trim(),
      ...(draft.description?.trim() ? { description: draft.description.trim() } : {}),
      conditions: draft.conditions,
      ...(draft.include_devices?.length ? { include_devices: draft.include_devices } : {}),
      ...(draft.exclude_devices?.length ? { exclude_devices: draft.exclude_devices } : {}),
      // Only persist a naming block when a template is actually set.
      ...(tpl
        ? {
            device_naming: {
              template: tpl,
              ...(draft.device_naming?.apply_on_enroll ? { apply_on_enroll: true } : {}),
            },
          }
        : {}),
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
            Automatically segment enrolled devices with conditions.
            You can then target these groups in apps and profiles.
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
          <Button leftSection={<IconPlus size={16} />} onClick={openNew} disabled={loading}>
            New group
          </Button>
        </Group>
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
              Create your first group!
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
                    {g.device_naming?.template && (
                      <Tooltip
                        label={
                          g.device_naming.apply_on_enroll
                            ? "Names devices automatically on enrollment"
                            : "Offered as a rename suggestion"
                        }
                        withArrow
                      >
                        <Badge
                          variant="light"
                          color="grape"
                          leftSection={<IconTag size={12} />}
                          style={{ textTransform: "none" }}
                        >
                          {g.device_naming.template}
                        </Badge>
                      </Tooltip>
                    )}
                  </Group>
                  {g.description && (
                    <Text fz="sm" c="dimmed">
                      {g.description}
                    </Text>
                  )}
                  <Group gap={6} wrap="wrap">
                    {g.conditions.length === 0 && !g.include_devices?.length ? (
                      <Badge variant="outline" color="orange" size="sm">
                        no conditions -- matches nothing
                      </Badge>
                    ) : (
                      g.conditions.map((c: Condition, ci: number) => (
                        <Badge key={ci} variant="light" size="sm" color="blue">
                          {describeCondition(c)}
                        </Badge>
                      ))
                    )}
                    {(g.include_devices?.length ?? 0) > 0 && (
                      <Badge variant="light" size="sm" color="teal" leftSection={<IconUserCheck size={12} />}>
                        +{g.include_devices!.length} included
                      </Badge>
                    )}
                    {(g.exclude_devices?.length ?? 0) > 0 && (
                      <Badge variant="light" size="sm" color="red" leftSection={<IconUserX size={12} />}>
                        −{g.exclude_devices!.length} excluded
                      </Badge>
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
              groupNames={otherGroupNames}
              tagNames={tagNames}
              suggestions={conditionSuggestions}
            />
          </Box>

          <Box>
            <UnstyledButton onClick={() => setCherryOpen((o) => !o)}>
              <Group gap={4}>
                <IconChevronRight
                  size={14}
                  style={{ transform: cherryOpen ? "rotate(90deg)" : "none", transition: "transform 120ms" }}
                />
                <Text fz="xs" fw={500} c="dimmed">
                  Add/remove specific devices
                  {(draft.include_devices?.length ?? 0) + (draft.exclude_devices?.length ?? 0) > 0 &&
                    ` (${draft.include_devices?.length ?? 0} in, ${draft.exclude_devices?.length ?? 0} out)`}
                </Text>
              </Group>
            </UnstyledButton>
            <Collapse in={cherryOpen}>
              <Group grow align="flex-start" gap="md" mt="xs">
                <Box>
                  <Text fz="xs" fw={600} c="teal" mb={4}>Always include</Text>
                  <DevicePicker
                    devices={devices}
                    value={draft.include_devices ?? []}
                    onChange={(v) => setDraft({ ...draft, include_devices: v.length ? v : undefined })}
                    color="teal"
                  />
                </Box>
                <Box>
                  <Text fz="xs" fw={600} c="red" mb={4}>Always exclude</Text>
                  <DevicePicker
                    devices={devices}
                    value={draft.exclude_devices ?? []}
                    onChange={(v) => setDraft({ ...draft, exclude_devices: v.length ? v : undefined })}
                    color="red"
                  />
                </Box>
              </Group>
              <Text fz="xs" c="dimmed" mt={4}>
                Excluded devices are forced to be excluded from this group, even if they match the conditions.
              </Text>
              <Text fz="xs" c="dimmed">
                Included devices are always included, even if they do not match the conditions.
              </Text>
            </Collapse>
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

          {draft.conditions.length === 0 && !draft.include_devices?.length && (
            <Group gap={6}>
              <IconAlertTriangle size={14} color="var(--mantine-color-orange-6)" />
              <Text fz="xs" c="orange.7">
                A group with no conditions or included devices matches nothing.
              </Text>
            </Group>
          )}

          <Divider label="Device naming (optional)" labelPosition="left" />
          <Stack gap="xs">
            <Text fz="xs" c="dimmed">
              Sets a managed name for devices in this group from a template. Type{" "}
              <Code>{"{"}</Code> to insert a device variable. When a device matches several
              groups, the first group (top-down) that defines a template is chosen over lower groups.
            </Text>
            <NameTemplateInput
              label="Name template"
              placeholder="e.g. US-DC-{serial}"
              value={namingTemplate}
              onChange={(template) => setNaming({ template })}
            />
            {unknownVars.length > 0 && (
              <Group gap={6}>
                <IconAlertTriangle size={14} color="var(--mantine-color-orange-6)" />
                <Text fz="xs" c="orange.7">
                  Unknown variable{unknownVars.length > 1 ? "s" : ""}:{" "}
                  {unknownVars.map((v) => `{${v}}`).join(", ")} will render empty.
                </Text>
              </Group>
            )}
            {selfReferential && (
              <Group gap={6} wrap="nowrap" align="flex-start">
                <IconAlertTriangle
                  size={14}
                  color="var(--mantine-color-orange-6)"
                  style={{ marginTop: 2, flexShrink: 0 }}
                />
                <Text fz="xs" c="orange.7">
                  {"{hostname}"} is the device&apos;s own name. You have created hostname inception.
                  This will create a self-referential loop, and will leave the device with an existential crisis.
                  Use a different variable like {"{serial}"}.
                </Text>
              </Group>
            )}
            {namingTemplate && (
              <Group gap={8} align="center">
                <Text fz="xs" c="dimmed">
                  Preview:
                </Text>
                {namingPreview ? (
                  <>
                    <Code>{namingPreview}</Code>
                    {namingSample && (
                      <Text fz="xs" c="dimmed">
                        from {namingSample.serial_number}
                      </Text>
                    )}
                  </>
                ) : (
                  <Text fz="xs" c="dimmed">
                    {namingSample ? "(renders empty)" : "no devices loaded to preview"}
                  </Text>
                )}
              </Group>
            )}
            <Switch
              checked={applyOnEnroll}
              onChange={(e) => setNaming({ apply_on_enroll: e.currentTarget.checked })}
              label="Apply automatically on enrollment"
              description="Name matching devices as they enroll (only if they have no name yet). Otherwise the template is just a suggestion in the rename box for now. Future additions to compliance manager will be able to enforce this automatically."
            />
          </Stack>

          <Group justify="flex-end">
            <Button variant="default" onClick={() => setModalOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleSave} loading={saving} disabled={saving || selfReferential}>
              {editIndex === null ? "Create group" : "Save changes"}
            </Button>
          </Group>
        </Stack>
      </Modal>

      <ConfigHistoryDrawer
        opened={historyOpen}
        onClose={() => setHistoryOpen(false)}
        type="groups"
        currentDoc={currentDocText}
        onRestored={reload}
      />
    </Stack>
  );
}

function uniqStrings(values: (string | null | undefined)[]): string[] {
  return Array.from(new Set(values.filter((v): v is string => !!v))).sort();
}
