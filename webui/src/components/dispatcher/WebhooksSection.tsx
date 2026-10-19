import {useRef} from "react";
import {ActionIcon, Box, Button, Divider, Group, Paper, Stack, Text, TextInput} from "@mantine/core";
import {modals} from "@mantine/modals";
import {IconPlus, IconTrash} from "@tabler/icons-react";
import {type DispatcherWebhook} from "../../../lib/api";
import {RedactedInput} from "../config/RedactedInput";

let webhookRowSeq = 0;
const nextRowId = () => `webhook-row-${++webhookRowSeq}`;

export function WebhooksSection({webhooks, onChange, disabled}: {
    webhooks: DispatcherWebhook[];
    onChange: (w: DispatcherWebhook[]) => void;
    disabled: boolean;
}) {
    // Row keys, since the name is editable and an index key would hand a removed row's credential editing state to
    // the row below it, which then shows the redaction sentinel as a value.
    const rowIds = useRef<string[]>([]);
    if (rowIds.current.length !== webhooks.length) {
        // A load or reload replaced the list; add and remove below keep rowIds in step themselves.
        rowIds.current = webhooks.map((_, i) => rowIds.current[i] ?? nextRowId());
    }

    const patch = (i: number, p: Partial<DispatcherWebhook>) =>
        onChange(webhooks.map((w, j) => (i === j ? {...w, ...p} : w)));
    return (
        <Stack gap="sm">
            <Group justify="space-between" align="flex-start" wrap="nowrap">
                <Box style={{minWidth: 0}}>
                    <Text fw={600}>Webhook targets</Text>
                    <Text fz="xs" c="dimmed">
                        Endpoints any rule can post to through a webhook action.
                    </Text>
                </Box>
                <Button variant="light" size="xs" leftSection={<IconPlus size={14}/>} disabled={disabled}
                        onClick={() => {
                            rowIds.current = [...rowIds.current, nextRowId()];
                            onChange([...webhooks, {name: `hook-${webhooks.length + 1}`, url: ""}]);
                        }}>
                    Add target
                </Button>
            </Group>
            <Divider my="xs"/>
            {webhooks.length === 0 ? (
                <Text fz="xs" c="dimmed">
                    No webhook targets. Add one to notify Slack, Teams, Discord or any endpoint when a rule
                    raises an alert.
                </Text>
            ) : (
                <Stack gap="xs">
                    {webhooks.map((w, i) => (
                        <Paper key={rowIds.current[i] ?? i} withBorder radius="sm" p="xs">
                            <Group gap="xs" wrap="nowrap" align="flex-start">
                                <TextInput placeholder="name" value={w.name}
                                           onChange={(e) => patch(i, {name: e.currentTarget.value})} w={160}
                                           disabled={disabled}/>
                                <RedactedInput
                                    placeholder="https://hooks.slack.com/…"
                                    value={w.url ?? ""}
                                    onChange={(v) => patch(i, {url: v})}
                                    style={{flex: 1}}
                                    disabled={disabled}
                                />
                                <RedactedInput
                                    password
                                    placeholder="HMAC secret (optional)"
                                    value={w.secret ?? ""}
                                    onChange={(v) => patch(i, {secret: v})}
                                    w={200}
                                    disabled={disabled}
                                />
                                <ActionIcon
                                    variant="subtle"
                                    color="red"
                                    disabled={disabled}
                                    aria-label="Remove webhook target"
                                    onClick={() =>
                                        modals.openConfirmModal({
                                            title: "Remove webhook target",
                                            children: (
                                                <Text size="sm">
                                                    Remove <b>{w.name || "this target"}</b>? Any rule pointing at it
                                                    stops notifying once you save, and the stored URL and secret are
                                                    deleted.
                                                </Text>
                                            ),
                                            labels: {confirm: "Remove", cancel: "Cancel"},
                                            confirmProps: {color: "red"},
                                            onConfirm: () => {
                                                rowIds.current = rowIds.current.filter((_, j) => j !== i);
                                                onChange(webhooks.filter((_, j) => j !== i));
                                            },
                                        })
                                    }
                                >
                                    <IconTrash size={16}/>
                                </ActionIcon>
                            </Group>
                        </Paper>
                    ))}
                    <Text fz="xs" c="dimmed">
                        The URL and secret are stored on the server and never sent back to this page once
                        saved. A field marked &quot;set, leave blank to keep&quot; already holds a value;
                        typing a new one replaces it.
                    </Text>
                </Stack>
            )}
        </Stack>
    );
}
