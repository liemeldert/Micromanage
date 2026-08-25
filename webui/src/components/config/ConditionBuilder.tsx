import {
    ActionIcon,
    Autocomplete,
    Button,
    Group,
    MultiSelect,
    Select,
    Stack,
    TagsInput,
    Text,
    TextInput,
} from "@mantine/core";
import {IconPlus, IconTrash} from "@tabler/icons-react";
import {
    type Condition,
    CONDITION_TYPES,
    type ConditionType,
    conditionTypeMeta,
    ENROLLMENT_SOURCE_OPTIONS,
    OPERATOR_LABELS,
    PLATFORM_OPTIONS,
} from "../../../lib/config";

function defaultValueForKind(kind: string): string | string[] {
    return kind === "list" || kind === "group" || kind === "platform" ||
    kind === "tag" || kind === "enrollment_source"
        ? []
        : "";
}

function newCondition(type: ConditionType = "platform"): Condition {
    const meta = conditionTypeMeta(type);
    const operator = meta.operators[0];
    return {type, operator, value: defaultValueForKind(meta.valueKindFor(operator))};
}

// Suggestions per condition type, so the value field autocompletes from what the loaded devices report.
export interface ConditionSuggestions {
    device_model?: string[];
    hostname?: string[];
    serial_number?: string[];
    os_version?: string[];
}

export function ConditionBuilder({
                                     conditions,
                                     onChange,
                                     allowedTypes,
                                     groupNames = [],
                                     tagNames = [],
                                     suggestions = {},
                                     emptyHint = "No conditions yet. This group matches no devices until you add one.",
                                 }: {
    conditions: Condition[];
    onChange: (next: Condition[]) => void;
    allowedTypes?: ConditionType[];
    groupNames?: string[];
    // Known tag names offered as autocomplete for the tag condition; free-form tags are still allowed.
    tagNames?: string[];
    suggestions?: ConditionSuggestions;
    emptyHint?: string;
}) {
    const types = allowedTypes
        ? CONDITION_TYPES.filter((t) => allowedTypes.includes(t.value))
        : CONDITION_TYPES;

    const update = (idx: number, patch: Partial<Condition>) => {
        onChange(conditions.map((c, i) => (i === idx ? {...c, ...patch} : c)));
    };

    const setType = (idx: number, type: ConditionType) => {
        const meta = conditionTypeMeta(type);
        const operator = meta.operators[0];
        update(idx, {type, operator, value: defaultValueForKind(meta.valueKindFor(operator))});
    };

    const setOperator = (idx: number, operator: string) => {
        const meta = conditionTypeMeta(conditions[idx].type);
        const prevKind = meta.valueKindFor(conditions[idx].operator);
        const nextKind = meta.valueKindFor(operator);
        const value =
            prevKind === nextKind ? conditions[idx].value : defaultValueForKind(nextKind);
        update(idx, {operator, value});
    };

    const suggestFor = (type: ConditionType): string[] => {
        switch (type) {
            case "device_model":
                return suggestions.device_model ?? [];
            case "hostname":
                return suggestions.hostname ?? [];
            case "serial_number":
                return suggestions.serial_number ?? [];
            case "os_version":
                return suggestions.os_version ?? [];
            default:
                return [];
        }
    };

    const asList = (v: string | string[]): string[] =>
        Array.isArray(v) ? v : v ? [String(v)] : [];

    return (
        <Stack gap="xs">
            {conditions.length === 0 && (
                <Text fz="xs" c="dimmed">
                    {emptyHint}
                </Text>
            )}

            {conditions.map((c, idx) => {
                const meta = conditionTypeMeta(c.type);
                const kind = meta.valueKindFor(c.operator);
                // For group, platform, tag and enrollment source the operator is always "in" and the label says so,
                // so the dropdown is hidden.
                const showOperator =
                    c.type !== "group" && c.type !== "platform" && c.type !== "tag" &&
                    c.type !== "enrollment_source";
                // The row wraps on purpose: its fixed-width selects, value field and remove button come to roughly
                // 550px, which overflows the 320px flow inspector panel. Wider surfaces never reach the wrap point.
                return (
                    <Group key={idx} gap="xs" align="flex-start">
                        <Select
                            data={types.map((t) => ({value: t.value, label: t.label}))}
                            value={c.type}
                            onChange={(v) => v && setType(idx, v as ConditionType)}
                            w={150}
                            allowDeselect={false}
                            comboboxProps={{withinPortal: true}}
                        />
                        <Select
                            data={[
                                {value: "is", label: "is"},
                                {value: "is-not", label: "is not"},
                            ]}
                            value={c.negate ? "is-not" : "is"}
                            onChange={(v) => update(idx, {negate: v === "is-not"})}
                            w={92}
                            allowDeselect={false}
                            comboboxProps={{withinPortal: true}}
                        />
                        {showOperator && (
                            <Select
                                data={meta.operators.map((op) => ({
                                    value: op,
                                    label: OPERATOR_LABELS[op] ?? op,
                                }))}
                                value={c.operator}
                                onChange={(v) => v && setOperator(idx, v)}
                                w={140}
                                allowDeselect={false}
                                comboboxProps={{withinPortal: true}}
                            />
                        )}
                        {kind === "platform" ? (
                            <MultiSelect
                                style={{flex: 1}}
                                placeholder="Select platform(s)"
                                data={PLATFORM_OPTIONS}
                                value={asList(c.value)}
                                onChange={(v) => update(idx, {value: v})}
                                clearable
                                comboboxProps={{withinPortal: true}}
                            />
                        ) : kind === "enrollment_source" ? (
                            <MultiSelect
                                style={{flex: 1}}
                                placeholder="Select enrollment source(s)"
                                data={ENROLLMENT_SOURCE_OPTIONS}
                                value={asList(c.value)}
                                onChange={(v) => update(idx, {value: v})}
                                clearable
                                comboboxProps={{withinPortal: true}}
                            />
                        ) : kind === "group" ? (
                            <TagsInput
                                style={{flex: 1}}
                                placeholder={groupNames.length ? "Select group(s)" : "No other groups"}
                                data={groupNames}
                                value={asList(c.value)}
                                onChange={(v) => update(idx, {value: v})}
                                clearable
                                comboboxProps={{withinPortal: true}}
                            />
                        ) : kind === "tag" ? (
                            <TagsInput
                                style={{flex: 1}}
                                placeholder="Add tag(s), press Enter"
                                data={tagNames}
                                value={asList(c.value)}
                                onChange={(v) => update(idx, {value: v})}
                                clearable
                                comboboxProps={{withinPortal: true}}
                            />
                        ) : kind === "list" ? (
                            <TagsInput
                                style={{flex: 1}}
                                placeholder="Add value(s), press Enter"
                                data={suggestFor(c.type)}
                                value={asList(c.value)}
                                onChange={(v) => update(idx, {value: v})}
                                comboboxProps={{withinPortal: true}}
                            />
                        ) : kind === "date" ? (
                            <TextInput
                                style={{flex: 1}}
                                type="date"
                                value={Array.isArray(c.value) ? "" : c.value}
                                onChange={(e) => update(idx, {value: e.currentTarget.value})}
                            />
                        ) : (
                            <Autocomplete
                                style={{flex: 1}}
                                data={c.operator === "regex" ? [] : suggestFor(c.type)}
                                placeholder={
                                    kind === "version"
                                        ? "e.g. 17.0"
                                        : c.operator === "regex"
                                            ? "regular expression, e.g. ^MacBook"
                                            : "value"
                                }
                                value={Array.isArray(c.value) ? "" : c.value}
                                onChange={(v) => update(idx, {value: v})}
                                comboboxProps={{withinPortal: true}}
                            />
                        )}
                        <ActionIcon
                            variant="subtle"
                            color="red"
                            mt={4}
                            onClick={() => onChange(conditions.filter((_, i) => i !== idx))}
                            aria-label="Remove condition"
                        >
                            <IconTrash size={16}/>
                        </ActionIcon>
                    </Group>
                );
            })}

            <Group justify="space-between" mt={4}>
                <Button
                    variant="subtle"
                    size="xs"
                    leftSection={<IconPlus size={14}/>}
                    onClick={() => onChange([...conditions, newCondition(types[0].value)])}
                >
                    Add condition
                </Button>
                {conditions.length > 1 && (
                    <Text fz="xs" c="dimmed">
                        All conditions must match (AND)
                    </Text>
                )}
            </Group>
        </Stack>
    );
}
