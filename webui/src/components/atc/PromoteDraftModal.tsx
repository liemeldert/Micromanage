"use client";

import {useState} from "react";
import {Alert, Badge, Button, Card, Checkbox, Divider, Group, Modal, Stack, Text,} from "@mantine/core";
import {IconAlertTriangle, IconGitMerge,} from "@tabler/icons-react";
import type {DraftDiff, GateFinding} from "../../../lib/api";

interface PromoteDraftModalProps {
    opened: boolean;
    onClose: () => void;
    onPromote: (options: { acknowledge: string[]; force: boolean }) => Promise<void>;
    diff: DraftDiff | null;
    gateFindings?: GateFinding[];
    promoting: boolean;
    // Display name of the live flow this draft targets; the modal falls back to diff.flow_id when it is absent.
    liveFlowName?: string;
}

export function PromoteDraftModal({
                                      opened,
                                      onClose,
                                      onPromote,
                                      diff,
                                      gateFindings = [],
                                      promoting,
                                      liveFlowName,
                                  }: PromoteDraftModalProps) {
    const [acknowledgedCodes, setAcknowledgedCodes] = useState<string[]>([]);
    const [force, setForce] = useState(false);

    if (!diff) return null;

    const targetName = liveFlowName || diff.flow_id;

    const blockingFindings = gateFindings.filter(
        (f) => !f.advisory && (!f.acknowledgeable || !acknowledgedCodes.includes(f.code)),
    );
    const hasUnacknowledgedBlocking = blockingFindings.length > 0;

    const handlePublish = async () => {
        await onPromote({
            acknowledge: acknowledgedCodes,
            force: Boolean(diff.base_drifted && force),
        });
    };

    return (
        <Modal
            opened={opened}
            onClose={onClose}
            title={
                <Group gap="xs">
                    <IconGitMerge size={20} color="var(--mantine-color-green-filled)"/>
                    <Text fw={600}>Publish draft: {targetName}</Text>
                </Group>
            }
            size="md"
        >
            <Stack gap="md">
                <Text size="sm">
                    Publishing replaces the live flow &ldquo;{targetName}&rdquo; with the contents of this draft, and
                    takes effect on live device executions immediately.
                </Text>

                <Group gap="xs">
                    <Badge color="green" variant="light">
                        +{diff.summary.added} added
                    </Badge>
                    <Badge color="red" variant="light">
                        -{diff.summary.removed} removed
                    </Badge>
                    <Badge color="orange" variant="light">
                        ~{diff.summary.changed} changed
                    </Badge>
                </Group>

                {diff.base_drifted ? (
                    <Alert color="red" title="Concurrent edits detected" icon={<IconAlertTriangle size={18}/>}>
                        <Stack gap="xs">
                            <Text size="xs">
                                The live target flow was modified since this draft was created. You must force the
                                publish to overwrite those live changes.
                            </Text>
                            <Checkbox
                                label="I understand and wish to overwrite the live changes"
                                checked={force}
                                onChange={(e) => setForce(e.currentTarget.checked)}
                                color="red"
                            />
                        </Stack>
                    </Alert>
                ) : null}

                {gateFindings.length > 0 ? (
                    <>
                        <Divider label="Save gate warnings" labelPosition="left"/>
                        <Stack gap="xs">
                            {gateFindings.map((f) => (
                                <Card key={f.code} withBorder p="xs" radius="sm">
                                    <Group justify="space-between" align="flex-start" wrap="nowrap">
                                        <Stack gap={2}>
                                            <Group gap={6}>
                                                <Badge size="xs" color={f.acknowledgeable ? "orange" : "red"}>
                                                    {f.code}
                                                </Badge>
                                                {f.node_id ? (
                                                    <Text size="xs" c="dimmed">
                                                        node: {f.node_id}
                                                    </Text>
                                                ) : null}
                                            </Group>
                                            <Text size="xs">{f.message}</Text>
                                        </Stack>

                                        {f.acknowledgeable ? (
                                            <Checkbox
                                                size="xs"
                                                label="Acknowledge"
                                                checked={acknowledgedCodes.includes(f.code)}
                                                onChange={(e) => {
                                                    if (e.currentTarget.checked) {
                                                        setAcknowledgedCodes((prev) => [...prev, f.code]);
                                                    } else {
                                                        setAcknowledgedCodes((prev) => prev.filter((c) => c !== f.code));
                                                    }
                                                }}
                                            />
                                        ) : null}
                                    </Group>
                                </Card>
                            ))}
                        </Stack>
                    </>
                ) : null}

                <Group justify="flex-end" mt="md">
                    <Button variant="default" onClick={onClose} disabled={promoting}>
                        Cancel
                    </Button>
                    <Button
                        color="green"
                        onClick={handlePublish}
                        loading={promoting}
                        disabled={(diff.base_drifted && !force) || hasUnacknowledgedBlocking}
                    >
                        Publish to live flow
                    </Button>
                </Group>
            </Stack>
        </Modal>
    );
}
