"use client";

import {
  ActionIcon,
  Button,
  Group,
  Select,
  Stack,
  TagsInput,
  Text,
  TextInput,
} from "@mantine/core";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import {
  CONDITION_TYPES,
  conditionTypeMeta,
  OPERATOR_LABELS,
  type Condition,
  type ConditionType,
} from "../../../lib/config";

function defaultValueForKind(kind: string): string | string[] {
  return kind === "list" ? [] : "";
}

function newCondition(type: ConditionType = "device_model"): Condition {
  const meta = conditionTypeMeta(type);
  const operator = meta.operators[0];
  return { type, operator, value: defaultValueForKind(meta.valueKindFor(operator)) };
}

export function ConditionBuilder({
  conditions,
  onChange,
  allowedTypes,
  emptyHint = "No conditions yet — this group will match no devices until you add one.",
}: {
  conditions: Condition[];
  onChange: (next: Condition[]) => void;
  allowedTypes?: ConditionType[];
  emptyHint?: string;
}) {
  const types = allowedTypes
    ? CONDITION_TYPES.filter((t) => allowedTypes.includes(t.value))
    : CONDITION_TYPES;

  const update = (idx: number, patch: Partial<Condition>) => {
    onChange(conditions.map((c, i) => (i === idx ? { ...c, ...patch } : c)));
  };

  const setType = (idx: number, type: ConditionType) => {
    const meta = conditionTypeMeta(type);
    const operator = meta.operators[0];
    update(idx, { type, operator, value: defaultValueForKind(meta.valueKindFor(operator)) });
  };

  const setOperator = (idx: number, operator: string) => {
    const meta = conditionTypeMeta(conditions[idx].type);
    const prevKind = meta.valueKindFor(conditions[idx].operator);
    const nextKind = meta.valueKindFor(operator);
    const value =
      prevKind === nextKind ? conditions[idx].value : defaultValueForKind(nextKind);
    update(idx, { operator, value });
  };

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
        return (
          <Group key={idx} gap="xs" align="flex-start" wrap="nowrap">
            <Select
              data={types.map((t) => ({ value: t.value, label: t.label }))}
              value={c.type}
              onChange={(v) => v && setType(idx, v as ConditionType)}
              w={150}
              allowDeselect={false}
              comboboxProps={{ withinPortal: true }}
            />
            <Select
              data={meta.operators.map((op) => ({
                value: op,
                label: OPERATOR_LABELS[op] ?? op,
              }))}
              value={c.operator}
              onChange={(v) => v && setOperator(idx, v)}
              w={140}
              allowDeselect={false}
              comboboxProps={{ withinPortal: true }}
            />
            {kind === "list" ? (
              <TagsInput
                style={{ flex: 1 }}
                placeholder="Add values, press Enter"
                value={Array.isArray(c.value) ? c.value : []}
                onChange={(v) => update(idx, { value: v })}
              />
            ) : (
              <TextInput
                style={{ flex: 1 }}
                type={kind === "date" ? "date" : "text"}
                placeholder={
                  kind === "version"
                    ? "e.g. 17.0"
                    : kind === "date"
                      ? ""
                      : c.operator === "regex"
                        ? "regular expression, e.g. ^MacBook"
                        : "value"
                }
                value={Array.isArray(c.value) ? "" : c.value}
                onChange={(e) => update(idx, { value: e.currentTarget.value })}
              />
            )}
            <ActionIcon
              variant="subtle"
              color="red"
              mt={4}
              onClick={() => onChange(conditions.filter((_, i) => i !== idx))}
              aria-label="Remove condition"
            >
              <IconTrash size={16} />
            </ActionIcon>
          </Group>
        );
      })}

      <Group justify="space-between" mt={4}>
        <Button
          variant="subtle"
          size="xs"
          leftSection={<IconPlus size={14} />}
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
