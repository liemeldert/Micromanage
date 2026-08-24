"use client";

// The flow switcher: mod+P, or the "All flows" control on the editor toolbar. Tabs are the working
// set, this is the whole list. Built on the same Spotlight primitive and classes as the command
// palette (mod+K), which also keeps every row at one height and one hit area. Badges point at dead
// weight: an enabled flow with a trigger and no runs in the retention window, or a draft left open.

import {useEffect, useMemo, useState} from "react";
import {ActionIcon, Badge, Group, Text, Tooltip} from "@mantine/core";
import {createSpotlight, Spotlight} from "@mantine/spotlight";
import {IconGitBranch, IconLock, IconPlus, IconSearch, IconSitemap, IconTrash,} from "@tabler/icons-react";
import type {FlowDoc, FlowsSummaryResponse, FlowSummary} from "../../../lib/api";

// Its own store, not the package singleton: the command palette owns that one.
const [switcherStore, switcherActions] = createSpotlight();

export const flowSwitcher = switcherActions;

// A draft left unpromoted for this long gets a badge. Nothing discards it.
const STALE_DRAFT_DAYS = 30;

interface FlowSwitcherProps {
    opened: boolean;
    onClose: () => void;
    flows: FlowDoc[];
    summary: FlowsSummaryResponse | null;
    onSelectFlow: (flowId: string) => void;
    onNewFlow: () => void;
    /** Absent for a member, who may not change flows. */
    onDeleteFlow?: (flow: FlowDoc) => void;
}

function daysSince(iso: string | null | undefined): number | null {
    if (!iso) return null;
    const then = Date.parse(iso);
    if (Number.isNaN(then)) return null;
    return Math.floor((Date.now() - then) / 86_400_000);
}

function triggerLabel(kind: string): string {
    switch (kind) {
        case "enroll_dep":
            return "automated enroll";
        case "enroll_profile":
            return "manual enroll";
        case "checkin":
            return "check-in";
        case "schedule":
            return "schedule";
        default:
            return kind;
    }
}

export function FlowSwitcher({
                                 opened,
                                 onClose,
                                 flows,
                                 summary,
                                 onSelectFlow,
                                 onNewFlow,
                                 onDeleteFlow,
                             }: FlowSwitcherProps) {
    // The page owns the open flag, so keep the store in step with it in both directions.
    useEffect(() => {
        if (opened) switcherActions.open();
        else switcherActions.close();
    }, [opened]);

    useEffect(() => {
        const onKeyDown = (e: KeyboardEvent) => {
            if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "p") {
                e.preventDefault();
                if (opened) onClose();
                else switcherActions.open();
            }
        };
        window.addEventListener("keydown", onKeyDown);
        return () => window.removeEventListener("keydown", onKeyDown);
    }, [opened, onClose]);

    const [query, setQuery] = useState("");
    useEffect(() => {
        if (!opened) setQuery("");
    }, [opened]);

    const summaryById = useMemo(() => {
        const map = new Map<string, FlowSummary>();
        for (const s of summary?.flows ?? []) map.set(s.id, s);
        return map;
    }, [summary]);

    // Live flows first, each followed by its own draft, so a draft reads as belonging to the flow above.
    const ordered = useMemo(() => {
        const live = flows.filter((f) => !f.draft_of);
        live.sort((a, b) => {
            if (Boolean(a.permanent) !== Boolean(b.permanent)) return a.permanent ? -1 : 1;
            return (a.name || a.id).localeCompare(b.name || b.id);
        });
        const draftsByParent = new Map<string, FlowDoc[]>();
        for (const f of flows) {
            if (!f.draft_of) continue;
            const group = draftsByParent.get(f.draft_of) ?? [];
            group.push(f);
            draftsByParent.set(f.draft_of, group);
        }
        const out: FlowDoc[] = [];
        for (const flow of live) {
            out.push(flow);
            for (const draft of draftsByParent.get(flow.id) ?? []) out.push(draft);
            draftsByParent.delete(flow.id);
        }
        // Whatever is left drafts a flow this list does not hold. Keep it visible, at the end.
        for (const group of draftsByParent.values()) out.push(...group);
        return out;
    }, [flows]);

    const matches = useMemo(() => {
        const q = query.trim().toLowerCase();
        if (!q) return ordered;
        return ordered.filter((f) =>
            [f.name, f.id, f.description, f.draft_of]
                .some((field) => (field ?? "").toLowerCase().includes(q)),
        );
    }, [ordered, query]);

    // Only a draft sitting under the flow it drafts is indented. A draft whose flow the search
    // filtered out has nothing to hang from, so it reads as a plain row.
    const shownIds = useMemo(() => new Set(matches.map((f) => f.id)), [matches]);

    const deleteControl = (flow: FlowDoc, isPermanent: boolean) => {
        if (!onDeleteFlow || isPermanent) return null;
        return (
            <Tooltip label="Delete this flow" withArrow position="left">
                <ActionIcon
                    className="mm-flow-delete"
                    variant="subtle"
                    color="red"
                    size="sm"
                    aria-label={`Delete ${flow.name || flow.id}`}
                    onClick={(e) => {
                        // The row itself opens the flow, so the button must not.
                        e.stopPropagation();
                        onClose();
                        onDeleteFlow(flow);
                    }}
                >
                    <IconTrash size={14}/>
                </ActionIcon>
            </Tooltip>
        );
    };

    const renderFlow = (flow: FlowDoc) => {
        const stats = summaryById.get(flow.id);
        const isDraft = Boolean(flow.draft_of);
        const isPermanent = flow.permanent === true && !isDraft;
        const kinds = Array.from(new Set(stats?.start_kinds ?? []));
        const runs = stats?.runs_in_window ?? 0;
        const nodeCount = stats?.node_count ?? flow.nodes?.length ?? 0;
        const draftAge = isDraft ? daysSince(flow.draft_created_at) : null;
        const indented = isDraft && shownIds.has(flow.draft_of ?? "");

        const bits: string[] = [];
        if (isDraft) {
            bits.push(`draft of ${flow.draft_of}`);
        } else if (kinds.length) {
            bits.push(`on ${kinds.map(triggerLabel).join(", ")}`);
        } else {
            bits.push("no trigger");
        }
        bits.push(`${nodeCount} ${nodeCount === 1 ? "block" : "blocks"}`);
        if (!isDraft) {
            bits.push(runs === 0
                ? "no runs in the retention window"
                : `${runs} ${runs === 1 ? "run" : "runs"}`);
        }
        if (flow.description) bits.push(flow.description);

        // State badges in one column, so a row with something to say stays as wide
        // as the one above it.
        const badges: React.ReactNode[] = [];
        if (isPermanent) {
            badges.push(
                <Badge key="perm" size="xs" variant="light" color="blue"
                       leftSection={<IconLock size={10}/>}>
                    enrollment
                </Badge>);
        }
        if (isDraft) {
            badges.push(
                <Badge key="draft" size="xs" variant="outline" color="orange">
                    draft
                </Badge>);
            if (draftAge !== null && draftAge >= STALE_DRAFT_DAYS) {
                badges.push(
                    <Badge key="stale" size="xs" variant="light" color="orange">
                        {draftAge}d old
                    </Badge>);
            }
        }
        if (flow.enabled === false && !isDraft) {
            badges.push(
                <Badge key="off" size="xs" variant="light" color="gray">
                    disabled
                </Badge>);
        } else if (!isDraft && runs === 0 && kinds.length > 0) {
            badges.push(
                <Badge key="never" size="xs" variant="light" color="yellow">
                    never fired
                </Badge>);
        }
        if ((stats?.gate_findings?.length ?? 0) > 0) {
            badges.push(
                <Badge key="issues" size="xs" variant="light" color="red">
                    {stats?.gate_findings?.length} to fix
                </Badge>);
        }

        return (
            <Spotlight.Action
                key={flow.id}
                className={indented ? "mm-flow-child" : undefined}
                // Searched against, so the id and description are findable behind the name.
                keywords={[flow.id, flow.description ?? "", flow.draft_of ?? ""]}
                label={flow.name || flow.id}
                description={bits.join(" · ")}
                leftSection={
                    isDraft
                        ? <IconGitBranch size={18} stroke={1.5}/>
                        : <IconSitemap size={18} stroke={1.5}/>
                }
                rightSection={
                    <Group gap={4} wrap="nowrap">
                        {badges}
                        {deleteControl(flow, isPermanent)}
                    </Group>
                }
                onClick={() => {
                    onSelectFlow(flow.id);
                    onClose();
                }}
            />
        );
    };

    return (
        <Spotlight.Root
            store={switcherStore}
            scrollable
            maxHeight={440}
            onSpotlightClose={onClose}
            classNames={{
                inner: "mm-palette-inner",
                overlay: "mm-palette-overlay",
                content: "mm-palette-content mm-glass-surface",
                search: "mm-palette-search mm-glass-input",
                action: "mm-palette-row",
            }}
            transitionProps={{
                transition: "pop",
                duration: 220,
                timingFunction: "cubic-bezier(0.16, 1, 0.3, 1)",
            }}
        >
            {/* Controlled, because the rows are children rather than the actions prop: Spotlight cannot
                filter what it was not handed, so the query, the filtering and the empty state are ours. */}
            <Spotlight.Search
                placeholder="Search flows by name, id or description"
                leftSection={<IconSearch size={18} stroke={1.5}/>}
                value={query}
                onChange={(event) => setQuery(event.currentTarget.value)}
            />

            <Spotlight.ActionsList>
                <Spotlight.ActionsGroup label="Flows">
                    {matches.map((flow) => renderFlow(flow))}
                    {matches.length === 0 ? (
                        <Text size="sm" c="dimmed" px="md" py="sm">
                            No flow matches that.
                        </Text>
                    ) : null}
                </Spotlight.ActionsGroup>

                <Spotlight.ActionsGroup label="Create">
                    <Spotlight.Action
                        label="New flow"
                        description="An empty flow you can wire up from the palette"
                        leftSection={<IconPlus size={18} stroke={1.5}/>}
                        onClick={() => {
                            onClose();
                            onNewFlow();
                        }}
                    />
                </Spotlight.ActionsGroup>
            </Spotlight.ActionsList>
        </Spotlight.Root>
    );
}
