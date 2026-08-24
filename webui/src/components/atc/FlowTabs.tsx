"use client";

import {ActionIcon, Badge, Box, Divider, Group, Paper, ScrollArea, Text, Tooltip,} from "@mantine/core";
import {IconCircleFilled, IconFilePlus, IconGitBranch, IconLock, IconSearch, IconX,} from "@tabler/icons-react";
import type {FlowDoc} from "../../../lib/api";
import {glassClassName} from "../ui/glass";

const SAVE_FIRST_REASON = "Save this flow first; a draft copies the saved flow.";

// The editor's single toolbar: open flow tabs on the left, and on the right whatever actions the
// page supplies for the active flow. One row, so the canvas keeps the rest of the window.
interface FlowTabsProps {
    flows: FlowDoc[];
    openFlowIds: string[];
    activeFlowId: string;
    onSelectFlow: (flowId: string) => void;
    onCloseTab: (flowId: string) => void;
    onNewFlow: () => void;
    onOpenSwitcher: () => void;
    dirtyFlowIds?: Set<string>;
    issuesByFlowId?: Record<string, number>;
    /** Opens the create-draft modal for the active flow. */
    onCreateDraft?: () => void;
    /** Flows the saved document holds; a draft copies the saved flow, so an unsaved one cannot have one. */
    savedFlowIds?: Set<string>;
    isAdmin?: boolean;
    adminOnlyReason?: string;
    /** Flow-scoped actions (issues, publish, enable, save). */
    actions?: React.ReactNode;
}

export function FlowTabs({
                             flows,
                             openFlowIds,
                             activeFlowId,
                             onSelectFlow,
                             onCloseTab,
                             onNewFlow,
                             onOpenSwitcher,
                             dirtyFlowIds = new Set(),
                             issuesByFlowId = {},
                             onCreateDraft,
                             savedFlowIds = new Set(),
                             isAdmin = false,
                             adminOnlyReason,
                             actions,
                         }: FlowTabsProps) {
    const flowsById = new Map(flows.map((f) => [f.id, f]));
    const openFlows = openFlowIds
        .map((id) => flowsById.get(id))
        .filter((f): f is FlowDoc => Boolean(f));

    // Which live flows a draft already covers, so a tab can say so without the page measuring anything.
    const draftByTarget = new Map<string, FlowDoc>();
    for (const f of flows) {
        if (!f.draft_of) continue;
        if (!draftByTarget.has(f.draft_of)) draftByTarget.set(f.draft_of, f);
    }

    const flowLabel = (flow: FlowDoc | undefined, fallback: string) => flow?.name || flow?.id || fallback;

    const activeFlow = flowsById.get(activeFlowId);
    const activeIsDraft = Boolean(activeFlow?.draft_of);
    const draftOfActive = activeFlow ? draftByTarget.get(activeFlow.id) : undefined;
    const activeName = flowLabel(activeFlow, activeFlowId);
    const activeSaved = activeFlow ? savedFlowIds.has(activeFlow.id) : false;
    const canOfferCreateDraft = Boolean(activeFlow) && !activeIsDraft && !draftOfActive;

    const draftLabel = draftOfActive
        ? `Open the draft of ${activeName}. The live flow is read-only while it exists.`
        : !isAdmin
            ? (adminOnlyReason ?? "Only an admin can create a draft.")
            : !activeSaved
                ? SAVE_FIRST_REASON
                : `Create a draft of ${activeName}`;

    return (
        // Glass over the canvas, so nodes scrolling underneath stay faintly visible through the bar. The
        // stacking context keeps it above them.
        <Paper
            className={glassClassName({material: "thin", reactive: false})}
            p="xs"
            radius={0}
            style={{position: "relative", zIndex: 5}}
        >
            <Group justify="space-between" wrap="nowrap" gap="xs">
                <ScrollArea type="never" offsetScrollbars={false} style={{flex: 1}}>
                    <Group gap={6} wrap="nowrap">
                        {openFlows.map((flow) => {
                            const isPermanent = flow.permanent === true && !flow.draft_of;
                            const isDraft = Boolean(flow.draft_of);
                            const isActive = flow.id === activeFlowId;
                            const isDirty = dirtyFlowIds.has(flow.id);
                            const issueCount = issuesByFlowId[flow.id] || 0;
                            const draftTargetName = flow.draft_of
                                ? flowLabel(flowsById.get(flow.draft_of), flow.draft_of)
                                : null;
                            // A live flow whose draft exists is read-only, and the tab is where that is said.
                            const hasOpenDraft = !isDraft && draftByTarget.has(flow.id);

                            return (
                                <Group
                                    key={flow.id}
                                    gap={6}
                                    wrap="nowrap"
                                    role="button"
                                    aria-label={flow.name || flow.id}
                                    onClick={() => onSelectFlow(flow.id)}
                                    style={{
                                        cursor: "pointer",
                                        padding: "4px 10px",
                                        borderRadius: "var(--mantine-radius-xs)",
                                        backgroundColor: isActive ? "var(--mantine-color-blue-light)" : "var(--mantine-color-default)",
                                        border: isActive
                                            ? "1px solid var(--mantine-color-blue-filled)"
                                            : isDraft
                                                ? "1px dashed var(--mantine-color-orange-filled)"
                                                : "1px solid var(--mantine-color-default-border)",
                                        userSelect: "none",
                                    }}
                                >
                                    {isPermanent ? (
                                        <Tooltip label="Permanent enrollment flow (pinned)" withArrow position="top">
                                            <IconLock size={14} style={{color: "var(--mantine-color-dimmed)"}}/>
                                        </Tooltip>
                                    ) : isDraft ? (
                                        <Tooltip label={`Draft of ${draftTargetName}`} withArrow position="top">
                                            <IconGitBranch size={14}
                                                           style={{color: "var(--mantine-color-orange-filled)"}}/>
                                        </Tooltip>
                                    ) : null}

                                    <Text size="sm" fw={isActive ? 600 : 400} c={isActive ? "blue" : undefined}>
                                        {flow.name || flow.id}
                                    </Text>

                                    {isDraft ? (
                                        <Tooltip
                                            label={`Draft of ${draftTargetName}. It saves itself. Publish to make it live.`}
                                            withArrow
                                            position="top"
                                            multiline
                                            w={240}
                                        >
                                            <Badge size="xs" variant="outline" color="orange">
                                                draft
                                            </Badge>
                                        </Tooltip>
                                    ) : null}

                                    {hasOpenDraft ? (
                                        <Tooltip
                                            label="This flow has a draft, so it is read-only here. Changes belong in the draft."
                                            withArrow
                                            position="top"
                                            multiline
                                            w={240}
                                        >
                                            <Badge size="xs" variant="outline" color="gray">
                                                draft open
                                            </Badge>
                                        </Tooltip>
                                    ) : null}

                                    {issueCount > 0 ? (
                                        <Badge size="xs" color="red" variant="filled">
                                            {issueCount}
                                        </Badge>
                                    ) : null}

                                    {isDirty ? (
                                        <Tooltip label="Unsaved edits" withArrow position="top">
                                            <IconCircleFilled size={8}
                                                              style={{color: "var(--mantine-color-orange-filled)"}}/>
                                        </Tooltip>
                                    ) : null}

                                    {!isPermanent ? (
                                        <ActionIcon
                                            size="xs"
                                            variant="subtle"
                                            color="gray"
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                onCloseTab(flow.id);
                                            }}
                                        >
                                            <IconX size={12}/>
                                        </ActionIcon>
                                    ) : null}
                                </Group>
                            );
                        })}
                    </Group>
                </ScrollArea>

                <Group gap={6} wrap="nowrap">
                    {/* Both controls are always here, enabled or not, so the toolbar keeps one width as a
                        draft comes and goes. */}
                    <Tooltip label="New flow" withArrow position="top">
                        <ActionIcon size="md" variant="default" onClick={onNewFlow} aria-label="New flow">
                            <IconFilePlus size={16}/>
                        </ActionIcon>
                    </Tooltip>

                    <Tooltip
                        label={draftLabel}
                        withArrow
                        position="top"
                        multiline
                        w={draftLabel.length > 40 ? 240 : undefined}
                    >
                        <Box style={{display: "flex"}}>
                            <ActionIcon
                                size="md"
                                variant={draftOfActive ? "light" : "default"}
                                color={draftOfActive ? "orange" : undefined}
                                onClick={draftOfActive ? () => onSelectFlow(draftOfActive.id) : onCreateDraft}
                                disabled={!draftOfActive && (!isAdmin || !activeSaved || !canOfferCreateDraft)}
                                aria-label={draftOfActive ? "Open draft" : "Create draft"}
                            >
                                <IconGitBranch size={16}/>
                            </ActionIcon>
                        </Box>
                    </Tooltip>
                    <Tooltip label="All flows (mod+P)" withArrow position="top">
                        <ActionIcon size="md" variant="default" onClick={onOpenSwitcher}>
                            <IconSearch size={16}/>
                        </ActionIcon>
                    </Tooltip>
                    {actions ? (
                        <>
                            <Divider orientation="vertical" mx={4}/>
                            {actions}
                        </>
                    ) : null}
                </Group>
            </Group>
        </Paper>
    );
}
