"use client";

// Editor for the advisory tag registry (tags.yaml). Free-form tags work without it; registered entries feed the
// pickers, chip colors and typo warnings. Saves through the standard validated PUT, so history and restore apply.

import {useEffect, useMemo, useState} from "react";
import {
    ActionIcon,
    Alert,
    Button,
    ColorSwatch,
    Group,
    Loader,
    Select,
    Table,
    Text,
    TextInput,
    ThemeIcon,
} from "@mantine/core";
import {modals} from "@mantine/modals";
import {IconDeviceFloppy, IconInfoCircle, IconPlus, IconTag, IconTrash} from "@tabler/icons-react";
import {type TagDef, type TagsConfig, useConfigResource} from "../../../lib/config";
import {useBeforeUnload} from "../../../lib/use-unsaved-changes";
import {GlassCard} from "../ui/GlassCard";

const TAG_COLORS = [
    "gray", "red", "pink", "grape", "violet", "indigo",
    "blue", "cyan", "teal", "green", "lime", "yellow", "orange",
];
const TAG_NAME_RE = /^[a-zA-Z0-9-_]+$/;

export function TagRegistryEditor() {
    const {data, loading, saving, save} = useConfigResource<TagsConfig>("tags", {tags: []});
    const [tags, setTags] = useState<TagDef[]>([]);
    const [dirty, setDirty] = useState(false);

    useEffect(() => {
        if (data && !dirty) setTags(data.tags ?? []);
    }, [data, dirty]);

    useBeforeUnload(dirty);

    const update = (i: number, patch: Partial<TagDef>) => {
        setTags((ts) => ts.map((t, idx) => (idx === i ? {...t, ...patch} : t)));
        setDirty(true);
    };
    const remove = (i: number) => {
        setTags((ts) => ts.filter((_, idx) => idx !== i));
        setDirty(true);
    };
    const confirmRemove = (i: number) => {
        const name = (tags[i]?.name || "").trim();
        // An empty row has nothing to lose.
        if (!name) {
            remove(i);
            return;
        }
        modals.openConfirmModal({
            title: "Remove tag",
            children: (
                <Text size="sm">
                    Remove <b>{name}</b> from the registry? Devices keep the tag itself, but it loses its
                    color and drops out of the pickers. Nothing changes until you save.
                </Text>
            ),
            labels: {confirm: "Remove", cancel: "Cancel"},
            confirmProps: {color: "red"},
            onConfirm: () => remove(i),
        });
    };
    const add = () => {
        setTags((ts) => [...ts, {name: ""}]);
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
            ...(t.label?.trim() ? {label: t.label.trim()} : {}),
            ...(t.description?.trim() ? {description: t.description.trim()} : {}),
            ...(t.color ? {color: t.color} : {}),
        }));
        const ok = await save({tags: cleaned});
        if (ok) setDirty(false);
    };

    return (
        <GlassCard withBorder p="md">
            <Group justify="space-between" mb="xs">
                <Group gap="xs">
                    <ThemeIcon variant="light" color="grape" size="sm">
                        <IconTag size={14}/>
                    </ThemeIcon>
                    <Text fz="sm" fw={600}>
                        Tags
                    </Text>
                </Group>
                <Button
                    size="xs"
                    variant="light"
                    leftSection={<IconDeviceFloppy size={14}/>}
                    onClick={onSave}
                    loading={saving}
                    disabled={!dirty || hasError}
                >
                    Save
                </Button>
            </Group>

            <Text fz="xs" c="dimmed" mb="sm">
                Tags are labels you put on a device by hand, or that an automation sets from a flow or a
                compliance rule. Registering one here puts it in the device picker and lets you give it a chip
                color; tags still work unregistered.
            </Text>

            {loading ? (
                <Group justify="center" py="md">
                    <Loader size="sm"/>
                </Group>
            ) : tags.length === 0 ? (
                <Alert variant="light" color="gray" icon={<IconInfoCircle size={16}/>}>
                    No tags registered.
                </Alert>
            ) : (
                <Table verticalSpacing="xs" withRowBorders={false}>
                    <Table.Thead>
                        <Table.Tr>
                            <Table.Th>Name</Table.Th>
                            <Table.Th>Label</Table.Th>
                            <Table.Th>Color</Table.Th>
                            <Table.Th>Description</Table.Th>
                            <Table.Th w={40}/>
                        </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                        {tags.map((t, i) => (
                            <Table.Tr key={i}>
                                <Table.Td>
                                    <TextInput
                                        size="xs"
                                        placeholder="cart-a"
                                        value={t.name}
                                        error={errors[i] || undefined}
                                        onChange={(e) => update(i, {name: e.currentTarget.value})}
                                    />
                                </Table.Td>
                                <Table.Td>
                                    <TextInput
                                        size="xs"
                                        placeholder="Cart A"
                                        value={t.label ?? ""}
                                        onChange={(e) => update(i, {label: e.currentTarget.value})}
                                    />
                                </Table.Td>
                                <Table.Td>
                                    <Select
                                        size="xs"
                                        w={130}
                                        placeholder="color"
                                        clearable
                                        data={TAG_COLORS}
                                        value={t.color ?? null}
                                        onChange={(v) => update(i, {color: v ?? undefined})}
                                        leftSection={
                                            t.color ? <ColorSwatch color={`var(--mantine-color-${t.color}-6)`}
                                                                   size={12}/> : undefined
                                        }
                                        comboboxProps={{withinPortal: true}}
                                    />
                                </Table.Td>
                                <Table.Td>
                                    <TextInput
                                        size="xs"
                                        placeholder="Shared classroom iPad, Cart A"
                                        value={t.description ?? ""}
                                        onChange={(e) => update(i, {description: e.currentTarget.value})}
                                    />
                                </Table.Td>
                                <Table.Td>
                                    <ActionIcon variant="subtle" color="red" onClick={() => confirmRemove(i)}
                                                aria-label="Remove tag">
                                        <IconTrash size={16}/>
                                    </ActionIcon>
                                </Table.Td>
                            </Table.Tr>
                        ))}
                    </Table.Tbody>
                </Table>
            )}

            <Group mt="sm">
                <Button size="xs" variant="subtle" leftSection={<IconPlus size={14}/>} onClick={add}>
                    Add tag
                </Button>
            </Group>
        </GlassCard>
    );
}
