import {Badge, Box, Group, Text, UnstyledButton} from "@mantine/core";
import {type DispatcherRule} from "../../../lib/api";
import {plural, scopeSummary} from "./rule-summary";

export function RuleListItem({rule, checkLabel, active, onSelect}: {
    rule: DispatcherRule;
    checkLabel: string;
    active: boolean;
    onSelect: () => void;
}) {
    const off = rule.enabled === false;
    const actions = rule.actions?.length ?? 0;
    return (
        <UnstyledButton
            onClick={onSelect}
            p="xs"
            style={{
                borderRadius: "var(--mantine-radius-sm)",
                background: active ? "var(--mantine-color-blue-light)" : undefined,
            }}
        >
            <Box style={{minWidth: 0}}>
                <Text fz="sm" fw={active ? 600 : 500} truncate c={off ? "dimmed" : undefined}>
                    {rule.name.trim() || rule.id}
                </Text>
                <Text fz="xs" c="dimmed" truncate>
                    {checkLabel}
                </Text>
                <Group gap={6} wrap="nowrap" mt={4}>
                    {off && <Badge size="xs" variant="light" color="gray">off</Badge>}
                    <Text fz="xs" c="dimmed" truncate>
                        {scopeSummary(rule.scope)} · {actions ? plural(actions, "action") : "no actions"}
                    </Text>
                </Group>
            </Box>
        </UnstyledButton>
    );
}
