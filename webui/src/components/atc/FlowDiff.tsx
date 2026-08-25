import {Alert, Badge, Card, Code, Divider, Drawer, Group, Paper, Stack, Table, Text,} from "@mantine/core";
import {IconAlertTriangle, IconGitCompare, IconMinus, IconPlus, IconReplace,} from "@tabler/icons-react";
import type {DraftDiff} from "../../../lib/api";

interface FlowDiffProps {
    opened: boolean;
    onClose: () => void;
    diff: DraftDiff | null;
}

export function FlowDiff({opened, onClose, diff}: FlowDiffProps) {
    if (!diff) return null;

    const summary = diff.summary;

    return (
        <Drawer
            opened={opened}
            onClose={onClose}
            title={
                <Group gap="xs">
                    <IconGitCompare size={20}/>
                    <Text fw={600}>Review Changes: {diff.draft_id}</Text>
                </Group>
            }
            position="right"
            size="xl"
            styles={{body: {paddingBottom: 24}}}
        >
            <Stack gap="md">
                {diff.base_drifted ? (
                    <Alert
                        color="red"
                        title="Base Flow Modified"
                        icon={<IconAlertTriangle size={18}/>}
                    >
                        The live target flow &ldquo;{diff.flow_id}&rdquo; was modified after this draft was created.
                        Promoting will overwrite those live changes.
                    </Alert>
                ) : null}

                {diff.note ? (
                    <Card withBorder p="xs" radius="sm" bg="var(--mantine-color-gray-0)">
                        <Text size="xs" fw={600} c="dimmed">
                            Draft Note:
                        </Text>
                        <Text size="sm">{diff.note}</Text>
                        {diff.created_by ? (
                            <Text size="xs" c="dimmed" mt={4}>
                                Created
                                by {diff.created_by} {diff.created_at ? `on ${new Date(diff.created_at).toLocaleString()}` : ""}
                            </Text>
                        ) : null}
                    </Card>
                ) : null}

                <Group gap="xs">
                    <Badge color="green" variant="filled" leftSection={<IconPlus size={12}/>}>
                        {summary.added} added
                    </Badge>
                    <Badge color="red" variant="filled" leftSection={<IconMinus size={12}/>}>
                        {summary.removed} removed
                    </Badge>
                    <Badge color="orange" variant="filled" leftSection={<IconReplace size={12}/>}>
                        {summary.changed} changed
                    </Badge>
                    <Badge color="gray" variant="light">
                        {summary.unchanged} unchanged
                    </Badge>
                </Group>

                <Divider label="Node Changes" labelPosition="left"/>

                <Stack gap="xs">
                    {diff.nodes.map((node) => {
                        const isAdded = node.change === "added";
                        const isRemoved = node.change === "removed";

                        return (
                            <Card
                                key={node.id}
                                withBorder
                                p="xs"
                                radius="sm"
                                style={{
                                    borderLeftWidth: 4,
                                    borderLeftColor: isAdded
                                        ? "var(--mantine-color-green-filled)"
                                        : isRemoved
                                            ? "var(--mantine-color-red-filled)"
                                            : "var(--mantine-color-orange-filled)",
                                }}
                            >
                                <Group justify="space-between" mb={node.params_diff ? 6 : 0}>
                                    <Group gap="xs">
                                        <Badge
                                            size="xs"
                                            color={isAdded ? "green" : isRemoved ? "red" : "orange"}
                                            variant="light"
                                        >
                                            {node.change}
                                        </Badge>
                                        <Text fw={600} size="sm">
                                            {node.id}
                                        </Text>
                                        {node.type ? (
                                            <Badge size="xs" variant="default">
                                                {node.type}
                                            </Badge>
                                        ) : null}
                                    </Group>
                                </Group>

                                {node.params_diff ? (
                                    <Paper withBorder radius="sm" mt="xs" style={{overflow: "hidden"}}>
                                        <Table withColumnBorders>
                                            <Table.Thead>
                                                <Table.Tr>
                                                    <Table.Th style={{width: "30%"}}>Parameter</Table.Th>
                                                    <Table.Th style={{width: "35%"}}>Live (From)</Table.Th>
                                                    <Table.Th style={{width: "35%"}}>Draft (To)</Table.Th>
                                                </Table.Tr>
                                            </Table.Thead>
                                            <Table.Tbody>
                                                {Object.entries(node.params_diff).map(([key, d]) => (
                                                    <Table.Tr key={key}>
                                                        <Table.Td fw={500}>{key}</Table.Td>
                                                        <Table.Td c="red.7">
                                                            <Code block>{JSON.stringify(d.from, null, 2)}</Code>
                                                        </Table.Td>
                                                        <Table.Td c="green.7">
                                                            <Code block>{JSON.stringify(d.to, null, 2)}</Code>
                                                        </Table.Td>
                                                    </Table.Tr>
                                                ))}
                                            </Table.Tbody>
                                        </Table>
                                    </Paper>
                                ) : null}
                            </Card>
                        );
                    })}

                    {diff.nodes.length === 0 ? (
                        <Text size="sm" c="dimmed">
                            No node changes.
                        </Text>
                    ) : null}
                </Stack>

                {diff.edges.length > 0 ? (
                    <>
                        <Divider label="Edge / Connection Changes" labelPosition="left"/>
                        <Stack gap="xs">
                            {diff.edges.map((e, i) => (
                                <Card key={i} withBorder p="xs" radius="sm">
                                    <Group gap="xs">
                                        <Badge
                                            size="xs"
                                            color={e.change === "added" ? "green" : e.change === "removed" ? "red" : "orange"}
                                        >
                                            {e.change}
                                        </Badge>
                                        <Text size="sm">
                                            <strong>{e.from}</strong> [{e.handle}] &rarr;{" "}
                                            {e.change === "changed" ? (
                                                <span>
                                                    <s style={{color: "var(--mantine-color-red-filled)"}}>{e.to_from}</s> &rarr;{" "}
                                                    <strong
                                                        style={{color: "var(--mantine-color-green-filled)"}}>{e.to_to}</strong>
                                                </span>
                                            ) : (
                                                <strong>{e.to_to || e.to_from}</strong>
                                            )}
                                        </Text>
                                    </Group>
                                </Card>
                            ))}
                        </Stack>
                    </>
                ) : null}
            </Stack>
        </Drawer>
    );
}
