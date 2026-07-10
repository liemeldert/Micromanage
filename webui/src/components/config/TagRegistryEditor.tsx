"use client";

// Editor for the advisory tag registry (tags.yaml). Optional: free-form tags
// work without it, but registered entries drive pickers, chip colours and
// typo warnings. Saves through the standard validated PUT (history + restore
// for free).

import { useEffect, useMemo, useState } from "react";
import {
  ActionIcon,
  Alert,
  Button,
  Card,
  ColorSwatch,
  Group,
  Loader,
  Select,
  Table,
  Text,
  TextInput,
  ThemeIcon,
} from "@mantine/core";
import { IconDeviceFloppy, IconInfoCircle, IconPlus, IconTag, IconTrash } from "@tabler/icons-react";
import { useConfigResource, type TagDef, type TagsConfig } from "../../../lib/config";

// Mantine's default palette -- the colour a chip renders in.
const TAG_COLORS = [
  "gray", "red", "pink", "grape", "violet", "indigo",
  "blue", "cyan", "teal", "green", "lime", "yellow", "orange",
];
const TAG_NAME_RE = /^[a-zA-Z0-9-_]+$/;

export function TagRegistryEditor() {
  const { data, loading, saving, save } = useConfigResource<TagsConfig>("tags", { tags: [] });
  const [tags, setTags] = useState<TagDef[]>([]);
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    // Don't clobber in-progress edits if the resource refetches under us.
    if (data && !dirty) setTags(data.tags ?? []);
  }, [data, dirty]);

  const update = (i: number, patch: Partial<TagDef>) => {
    setTags((ts) => ts.map((t, idx) => (idx === i ? { ...t, ...patch } : t)));
    setDirty(true);
  };
  const remove = (i: number) => {
    setTags((ts) => ts.filter((_, idx) => idx !== i));
    setDirty(true);
  };
  const add = () => {
    setTags((ts) => [...ts, { name: "" }]);
    setDirty(true);
  };

  const errors = useMemo(() => {
    const seen = new Set<string>();
    return tags.map((t) => {
      const name = (t.name || "").trim();
      if (!name) return "Name is required";
      if (!TAG_NAME_RE.test(name)) return "Letters, digits, - and _ only";
      if (seen.has(name)) return "Duplicate name";
      seen.add(name);
      return null;
    });
  }, [tags]);
  const hasError = errors.some(Boolean);

  const onSave = async () => {
    const cleaned = tags.map((t) => ({
      name: (t.name || "").trim(),
      ...(t.label?.trim() ? { label: t.label.trim() } : {}),
      ...(t.description?.trim() ? { description: t.description.trim() } : {}),
      ...(t.color ? { color: t.color } : {}),
    }));
    const ok = await save({ tags: cleaned });
    if (ok) setDirty(false);
  };

  return (
    <Card withBorder radius="md" p="md">
      <Group justify="space-between" mb="xs">
        <Group gap="xs">
          <ThemeIcon variant="light" color="grape" size="sm">
            <IconTag size={14} />
          </ThemeIcon>
          <Text fz="sm" fw={600}>
            Tags
          </Text>
        </Group>
        <Button
          size="xs"
          variant="light"
          leftSection={<IconDeviceFloppy size={14} />}
          onClick={onSave}
          loading={saving}
          disabled={!dirty || hasError}
        >
          Save
        </Button>
      </Group>

      <Text fz="xs" c="dimmed" mb="sm">
        An advisory registry of tags. Free-form tags are always allowed; entries here
        add a label, a chip colour, and typo warnings when a config references an
        unknown tag.
      </Text>

      {loading ? (
        <Group justify="center" py="md">
          <Loader size="sm" />
        </Group>
      ) : tags.length === 0 ? (
        <Alert variant="light" color="gray" icon={<IconInfoCircle size={16} />}>
          No registered tags. Tags still work as free-form labels; add entries to get a
          picker and chip colours.
        </Alert>
      ) : (
        <Table verticalSpacing="xs" withRowBorders={false}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Label</Table.Th>
              <Table.Th>Colour</Table.Th>
              <Table.Th>Description</Table.Th>
              <Table.Th w={40} />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {tags.map((t, i) => (
              <Table.Tr key={i}>
                <Table.Td>
                  <TextInput
                    size="xs"
                    placeholder="kiosk"
                    value={t.name}
                    error={errors[i] || undefined}
                    onChange={(e) => update(i, { name: e.currentTarget.value })}
                  />
                </Table.Td>
                <Table.Td>
                  <TextInput
                    size="xs"
                    placeholder="Kiosk"
                    value={t.label ?? ""}
                    onChange={(e) => update(i, { label: e.currentTarget.value })}
                  />
                </Table.Td>
                <Table.Td>
                  <Select
                    size="xs"
                    w={130}
                    placeholder="colour"
                    clearable
                    data={TAG_COLORS}
                    value={t.color ?? null}
                    onChange={(v) => update(i, { color: v ?? undefined })}
                    leftSection={
                      t.color ? <ColorSwatch color={`var(--mantine-color-${t.color}-6)`} size={12} /> : undefined
                    }
                    comboboxProps={{ withinPortal: true }}
                  />
                </Table.Td>
                <Table.Td>
                  <TextInput
                    size="xs"
                    placeholder="Company-owned kiosk"
                    value={t.description ?? ""}
                    onChange={(e) => update(i, { description: e.currentTarget.value })}
                  />
                </Table.Td>
                <Table.Td>
                  <ActionIcon variant="subtle" color="red" onClick={() => remove(i)} aria-label="Remove tag">
                    <IconTrash size={16} />
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      <Group mt="sm">
        <Button size="xs" variant="subtle" leftSection={<IconPlus size={14} />} onClick={add}>
          Add tag
        </Button>
      </Group>
    </Card>
  );
}
