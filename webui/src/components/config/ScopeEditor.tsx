import {useMemo, useState} from "react";
import {Alert, Badge, Box, Collapse, Group, MultiSelect, Stack, Text, UnstyledButton,} from "@mantine/core";
import {IconChevronRight, IconDevices2, IconTargetArrow} from "@tabler/icons-react";
import type {Device} from "../../../lib/api";
import {
    deviceGroupNames,
    evaluateScope,
    type Group as GroupDef,
    type Scope,
    useTagRegistry,
} from "../../../lib/config";
import {ConditionBuilder, type ConditionSuggestions} from "./ConditionBuilder";
import {DevicePicker} from "./DevicePicker";

/**
 * Scope editor for profiles, app versions, flow triggers and dispatcher rules: target groups (any match) AND
 * conditions (all match), plus include/exclude device overrides. Shows a live match count and, when a previous
 * scope is given, the added/removed diff.
 */
export function ScopeEditor({
                                scope,
                                onChange,
                                devices,
                                allGroups,
                                previous,
                                groupsLabel = "Target groups",
                                groupsDescription = "Devices in any of these groups are in scope.",
                                emptyMatchesAll = false,
                                emptyAllLabel = "every device",
                            }: {
    scope: Scope;
    onChange: (next: Scope) => void;
    devices: Device[];
    allGroups: GroupDef[];
    previous?: Scope;
    groupsLabel?: string;
    groupsDescription?: string;
    // Flow triggers and dispatcher rules treat an empty scope as matching every device; profiles and apps treat it
    // as matching nothing, which is the default here.
    emptyMatchesAll?: boolean;
    // What "everyone" means for this caller, read only when emptyMatchesAll is set. The sentence below supplies a
    // singular verb, so this has to be a singular noun phrase: "every device" works, "all devices" does not.
    emptyAllLabel?: string;
}) {
    const [advancedOpen, setAdvancedOpen] = useState(
        (scope.include_devices?.length ?? 0) > 0 || (scope.exclude_devices?.length ?? 0) > 0,
    );

    const groupOptions = allGroups.map((g) => g.name);
    const {tagNames} = useTagRegistry();
    const suggestions: ConditionSuggestions = useMemo(
        () => ({
            device_model: uniq(devices.map((d) => d.device_model)),
            hostname: uniq(devices.map((d) => d.hostname)),
            serial_number: uniq(devices.map((d) => d.serial_number)),
            os_version: uniq(devices.map((d) => d.os_version)),
        }),
        [devices],
    );

    const matched = useMemo(() => {
        const loaded = devices.filter((d) => d.serial_number);
        if (emptyMatchesAll && isEmptyScope(scope)) return loaded;
        return loaded.filter((d) => evaluateScope(d, deviceGroupNames(d, allGroups), scope, allGroups));
    }, [devices, allGroups, scope, emptyMatchesAll]);

    const diff = useMemo(() => {
        if (!previous) return null;
        const loaded = devices.filter((d) => d.serial_number);
        const prevMatched =
            emptyMatchesAll && isEmptyScope(previous)
                ? loaded
                : loaded.filter((d) => evaluateScope(d, deviceGroupNames(d, allGroups), previous, allGroups));
        const prev = new Set(prevMatched.map((d) => d.serial_number));
        const now = new Set(matched.map((d) => d.serial_number));
        const added = [...now].filter((s) => !prev.has(s));
        const removed = [...prev].filter((s) => !now.has(s));
        return {added, removed};
    }, [previous, devices, allGroups, matched, emptyMatchesAll]);

    const patch = (p: Partial<Scope>) => onChange({...scope, ...p});

    const scopeIsEmpty = isEmptyScope(scope);

    return (
        <Stack gap="sm">
            <MultiSelect
                label={groupsLabel}
                description={groupsDescription}
                placeholder={groupOptions.length ? "Select groups" : "No groups defined yet"}
                data={groupOptions}
                value={scope.groups ?? []}
                onChange={(g) => patch({groups: g})}
                searchable
                clearable
                nothingFoundMessage="No matching groups"
            />

            <Box>
                <Text fz="sm" fw={500} mb={4}>
                    Additional conditions
                </Text>
                <ConditionBuilder
                    conditions={scope.conditions ?? []}
                    onChange={(conditions) => patch({conditions})}
                    groupNames={groupOptions}
                    tagNames={tagNames}
                    suggestions={suggestions}
                    emptyHint="No extra conditions. Add one to further narrow the target (all must match)."
                />
            </Box>

            <UnstyledButton onClick={() => setAdvancedOpen((o) => !o)}>
                <Group gap={4}>
                    <IconChevronRight
                        size={14}
                        style={{transform: advancedOpen ? "rotate(90deg)" : "none", transition: "transform 120ms"}}
                    />
                    <Text fz="xs" fw={500} c="dimmed">
                        Cherry-pick specific devices
                        {((scope.include_devices?.length ?? 0) + (scope.exclude_devices?.length ?? 0)) > 0 &&
                            ` (${(scope.include_devices?.length ?? 0)} in, ${(scope.exclude_devices?.length ?? 0)} out)`}
                    </Text>
                </Group>
            </UnstyledButton>
            <Collapse expanded={advancedOpen}>
                <Group grow align="flex-start" gap="md">
                    <Box>
                        <Text fz="xs" fw={600} c="teal" mb={4}>
                            Always include
                        </Text>
                        <DevicePicker
                            devices={devices}
                            value={scope.include_devices ?? []}
                            onChange={(v) => patch({include_devices: v.length ? v : undefined})}
                            color="teal"
                        />
                    </Box>
                    <Box>
                        <Text fz="xs" fw={600} c="red" mb={4}>
                            Always exclude
                        </Text>
                        <DevicePicker
                            devices={devices}
                            value={scope.exclude_devices ?? []}
                            onChange={(v) => patch({exclude_devices: v.length ? v : undefined})}
                            color="red"
                        />
                    </Box>
                </Group>
                <Text fz="xs" c="dimmed" mt={4}>
                    Exclude always wins; include forces a device in regardless of groups/conditions.
                </Text>
            </Collapse>

            <Alert
                variant="light"
                color={matched.length ? "teal" : "gray"}
                icon={<IconTargetArrow size={16}/>}
                p="xs"
            >
                <Group gap="sm" wrap="wrap">
                    <Group gap={6}>
                        <IconDevices2 size={14}/>
                        <Text fz="sm">
                            Matches <b>≈ {matched.length}</b> of {devices.filter((d) => d.serial_number).length}{" "}
                            loaded device{devices.length === 1 ? "" : "s"}
                        </Text>
                    </Group>
                    {diff && (diff.added.length > 0 || diff.removed.length > 0) && (
                        <Group gap={6}>
                            {diff.added.length > 0 && (
                                <Badge size="sm" variant="light" color="teal">
                                    +{diff.added.length} added
                                </Badge>
                            )}
                            {diff.removed.length > 0 && (
                                <Badge size="sm" variant="light" color="red">
                                    −{diff.removed.length} removed
                                </Badge>
                            )}
                        </Group>
                    )}
                </Group>
                {scopeIsEmpty && (
                    <Text fz="xs" fw={500} mt={4}>
                        {emptyMatchesAll
                            ? `The scope is empty, so ${emptyAllLabel} matches. Add a group or condition to narrow it.`
                            : "The scope is empty, so no devices match yet. Add a group or condition to choose which ones."}
                    </Text>
                )}
                {matched.length > 0 && (
                    <Text span c="dimmed" fz="xs">
                        {matched.slice(0, 5).map((d) => d.serial_number).join(", ")}
                        {matched.length > 5 ? "…" : ""}
                    </Text>
                )}
            </Alert>
        </Stack>
    );
}

function uniq(values: (string | null | undefined)[]): string[] {
    return Array.from(new Set(values.filter((v): v is string => !!v))).sort();
}

// Must agree with the controller's own empty-scope check: empty means none of the four fields has an entry.
function isEmptyScope(s: Scope): boolean {
    return (
        (s.groups?.length ?? 0) === 0 &&
        (s.conditions?.length ?? 0) === 0 &&
        (s.include_devices?.length ?? 0) === 0 &&
        (s.exclude_devices?.length ?? 0) === 0
    );
}
