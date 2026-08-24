"use client";

import {Alert, Badge, Button, Group, Modal, Paper, ScrollArea, Stack, Text, UnstyledButton} from "@mantine/core";
import {IconAlertTriangle, IconCircleCheck, IconExclamationCircle} from "@tabler/icons-react";
import type {FlowWarning} from "../../../lib/api";
import type {FlowIssue} from "./flow-utils";

/** The flow's issues and warnings as a list, opened from the toolbar or by a blocked Save. The canvas shows the same
 * things on the blocks themselves. Neither belongs in a panel above the canvas, where one line per unfinished block
 * pushes the editor down the page mid-edit.
 *
 * Issues mirror the server's structural checks (flow-utils.validateFlowClient), so a save the server would refuse is
 * caught here. Warnings come from the server and never block. An issue naming a node is a button that selects and
 * centres it; flow-level issues, such as no start node, read as plain text. */
export function FlowIssuesModal({
                                    opened,
                                    blocking,
                                    flowName,
                                    issues,
                                    warnings,
                                    onGoToNode,
                                    onClose,
                                }: {
    opened: boolean;
    /** Opened by Save rather than by the toolbar: the modal says the save stopped. */
    blocking: boolean;
    flowName: string;
    issues: FlowIssue[];
    warnings: FlowWarning[];
    onGoToNode: (nodeId: string) => void;
    onClose: () => void;
}) {
    const firstNode = issues.find((i) => i.nodeId)?.nodeId;
    const goTo = (nodeId: string) => {
        onGoToNode(nodeId);
        onClose();
    };

    return (
        <Modal
            opened={opened}
            onClose={onClose}
            size="lg"
            title={
                <Group gap="xs">
                    {issues.length > 0 ? (
                        <IconExclamationCircle size={18} color="var(--mantine-color-red-6)"/>
                    ) : warnings.length > 0 ? (
                        <IconAlertTriangle size={18} color="var(--mantine-color-yellow-6)"/>
                    ) : (
                        <IconCircleCheck size={18} color="var(--mantine-color-teal-6)"/>
                    )}
                    <Text fw={600}>
                        {blocking ? "Not saved" : "This flow"} &middot; {flowName}
                    </Text>
                </Group>
            }
        >
            <Stack gap="md">
                {blocking && (
                    <Alert color="red" variant="light">
                        <Text fz="sm">
                            The server refuses a flow that cannot run end to end, so nothing was saved. Fix
                            the {issues.length === 1 ? "issue" : "issues"} below and save again.
                        </Text>
                    </Alert>
                )}

                {issues.length === 0 && warnings.length === 0 && (
                    <Text fz="sm">Nothing to fix. This flow is ready to save.</Text>
                )}

                {issues.length > 0 && (
                    <div>
                        <Text fz="sm" fw={600} mb={6}>
                            {issues.length === 1 ? "1 issue" : `${issues.length} issues`}
                        </Text>
                        <ScrollArea.Autosize mah={280}>
                            <Stack gap={6}>
                                {issues.map((issue, i) => (
                                    <IssueRow
                                        key={`${issue.nodeId ?? "flow"}::${i}`}
                                        issue={issue}
                                        onGoToNode={goTo}
                                    />
                                ))}
                            </Stack>
                        </ScrollArea.Autosize>
                    </div>
                )}

                {warnings.length > 0 && (
                    <div>
                        <Text fz="sm" fw={600} mb={6}>
                            {warnings.length === 1 ? "1 warning" : `${warnings.length} warnings`}
                        </Text>
                        <ScrollArea.Autosize mah={220}>
                            <Stack gap={6}>
                                {warnings.map((w, i) => (
                                    <IssueRow
                                        key={`${w.code}::${i}`}
                                        issue={{nodeId: w.node_id ?? undefined, message: w.message}}
                                        color="yellow"
                                        onGoToNode={goTo}
                                    />
                                ))}
                            </Stack>
                        </ScrollArea.Autosize>
                        <Text fz="xs" c="dimmed" mt={6}>
                            Warnings never block a save. They come from the server and refresh when you save.
                        </Text>
                    </div>
                )}

                <Group justify="flex-end" gap="sm">
                    {firstNode && (
                        <Button variant="light" onClick={() => goTo(firstNode)}>
                            Go to first issue
                        </Button>
                    )}
                    <Button variant={firstNode ? "subtle" : "filled"} color={firstNode ? "gray" : undefined}
                            onClick={onClose}>
                        {blocking ? "Back to the editor" : "Close"}
                    </Button>
                </Group>
            </Stack>
        </Modal>
    );
}

function IssueRow({
                      issue,
                      color = "red",
                      onGoToNode,
                  }: {
    issue: FlowIssue;
    color?: string;
    onGoToNode: (nodeId: string) => void;
}) {
    const body = (
        <Group gap="xs" align="flex-start" wrap="nowrap">
            {/* tt="none": a node id is a typed slug, and Mantine's badge would otherwise show it in capitals. */}
            <Badge
                size="sm"
                variant="light"
                tt="none"
                color={issue.nodeId ? color : "gray"}
                style={{flexShrink: 0}}
            >
                {issue.nodeId ?? "flow"}
            </Badge>
            <Text fz="sm">{issue.message}</Text>
        </Group>
    );

    if (!issue.nodeId) {
        return (
            <Paper withBorder radius="sm" p="xs">
                {body}
            </Paper>
        );
    }
    return (
        <UnstyledButton onClick={() => onGoToNode(issue.nodeId!)}>
            <Paper withBorder radius="sm" p="xs" style={{cursor: "pointer"}}>
                {body}
                <Text fz={10} c="dimmed" mt={4} ml={2}>
                    Show this block
                </Text>
            </Paper>
        </UnstyledButton>
    );
}
