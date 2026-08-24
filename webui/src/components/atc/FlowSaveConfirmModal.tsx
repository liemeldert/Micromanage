"use client";

import {useEffect, useState} from "react";
import {Alert, Button, Checkbox, Group, List, Modal, Stack, Text} from "@mantine/core";
import {IconAlertTriangle} from "@tabler/icons-react";
import {api, type ScopePreview, type ScopePreviewTriggerKind} from "../../../lib/api";
import {useAuth} from "../../../lib/auth-context";
import type {SaveGuardReason} from "./flow-utils";

/** Blocking save-time confirmation on the flow editor: nothing is written until the acknowledgement is ticked and
 * confirmed, and closing returns to the editor unsaved. Renders whatever reasons it is handed, mixing the
 * structural check in flow-utils.saveGuardReasons with the server's release-ordering warnings, which arrive with
 * kind "server". A non-empty serverErrors is a fresh dry-run refusal and holds the confirm button down; an empty
 * one leaves the modal as it was. Device counts from /api/v1/scope/preview only ever add a line under a reason.
 */

// Trigger kinds the count endpoint understands. Server reasons carry no scope and are skipped.
const PREVIEW_KINDS = new Set<string>([
    "enroll_dep",
    "enroll_profile",
    "checkin",
    "schedule",
]);

// Same ceiling the ATC page puts on its warnings fetch; past it the count is not coming.
const PREVIEW_TIMEOUT_MS = 4000;

// How many devices are named under a count.
const SAMPLE_SHOWN = 3;

/** Dedupe key for a count request: starts of the same kind with the same scope are one question. */
function previewKey(r: SaveGuardReason): string {
    return `${r.kind}::${JSON.stringify(r.match ?? {})}`;
}

async function fetchPreview(
    token: string,
    reason: SaveGuardReason,
): Promise<ScopePreview | null> {
    try {
        const res = await Promise.race([
            api.previewScope(token, {
                scope: reason.match ?? {},
                // A flow start reads an empty scope as every device of this trigger kind, so say so rather than
                // leave the server to guess. Profiles and app versions would send "none".
                empty_scope: "all",
                trigger_kind: reason.kind as ScopePreviewTriggerKind,
                sample_limit: SAMPLE_SHOWN,
            }),
            new Promise<null>((resolve) => setTimeout(() => resolve(null), PREVIEW_TIMEOUT_MS)),
        ]);
        return res && typeof res.matched === "number" ? res : null;
    } catch {
        return null;
    }
}

function plural(n: number, one: string, many: string): string {
    return n === 1 ? one : many;
}

function count(n: number, truncated: boolean): string {
    return `${truncated ? "at least " : ""}${n.toLocaleString()}`;
}

/** The sentence carrying the number, one per trigger kind. It sits under the reason's own sentence rather than
 * replacing it. */
function countSentence(reason: SaveGuardReason, p: ScopePreview): string {
    const matched = count(p.matched, p.truncated);
    const devices = plural(p.matched, "device", "devices");
    if (!p.scope_is_empty) {
        return `This scope matches ${matched} of the ${p.eligible.toLocaleString()} ${plural(
            p.eligible,
            "device",
            "devices",
        )} it can reach right now.`;
    }
    if (p.total === 0) return "No devices are enrolled right now.";
    switch (reason.kind) {
        case "enroll_dep":
        case "enroll_profile": {
            const how =
                reason.kind === "enroll_dep"
                    ? "came in through Automated Device Enrollment"
                    : "enrolled manually or over the air";
            return (
                `${matched} of the ${p.total.toLocaleString()} ${plural(p.total, "device", "devices")} ` +
                `enrolled right now ${how}. This start fires as devices enroll, so it will also reach ` +
                `devices that are not in that count.`
            );
        }
        // checkin and schedule both reach the whole enrolled fleet.
        default:
            return `That is ${matched} ${devices} right now.`;
    }
}

/** Up to three matched devices by name, so the number can be sanity checked. */
function sampleSentence(p: ScopePreview): string | null {
    const names = p.sample.slice(0, SAMPLE_SHOWN).map((d) => d.display_name);
    if (!names.length) return null;
    const rest = p.matched - names.length;
    // matched is a floor when the walk stopped early, so the remainder is too.
    const more = rest > 0 ? ` and ${p.truncated ? "at least " : ""}${rest.toLocaleString()} more` : "";
    return `For example ${names.join(", ")}${more}.`;
}

export function FlowSaveConfirmModal({
                                         flowName,
                                         reasons,
                                         serverErrors = [],
                                         opened,
                                         saving,
                                         onCancel,
                                         onConfirm,
                                     }: {
    flowName: string;
    reasons: SaveGuardReason[];
    /** Errors from the dry-run this save attempt just ran, and only from that.
     * Non-empty means the server has already refused this document. */
    serverErrors?: string[];
    opened: boolean;
    saving: boolean;
    onCancel: () => void;
    onConfirm: () => void;
}) {
    const {token} = useAuth();
    const [acked, setAcked] = useState(false);
    // Counts by previewKey, filled in as replies arrive. Never blocks a render.
    const [previews, setPreviews] = useState<Record<string, ScopePreview>>({});

    // Never carry the tick over from the previous open.
    useEffect(() => {
        if (opened) setAcked(false);
    }, [opened]);

    // One count request per distinct (kind, scope) when the modal opens. Replies are dropped if the modal closed
    // meanwhile, and the previous open's numbers are cleared first so no stale count sits under a new reason.
    useEffect(() => {
        if (!opened) return;
        setPreviews({});
        if (!token) return;
        let stale = false;
        const asked = new Map<string, SaveGuardReason>();
        for (const r of reasons) {
            if (!PREVIEW_KINDS.has(r.kind)) continue;
            const key = previewKey(r);
            if (!asked.has(key)) asked.set(key, r);
        }
        for (const [key, reason] of asked) {
            fetchPreview(token, reason).then((p) => {
                if (!stale && p) setPreviews((prev) => ({...prev, [key]: p}));
            });
        }
        return () => {
            stale = true;
        };
    }, [opened, token, reasons]);

    // The confirm label names the consequence, broadest reason winning: a check-in or schedule start reaches the
    // whole fleet, an enrollment start reaches devices as they enroll, and server-only reasons ask just for the
    // acknowledgement. A document the server has already refused gets no offer.
    const blocked = serverErrors.length > 0;
    const fleetNow = reasons.some((r) => r.kind === "checkin" || r.kind === "schedule");
    const anyEnroll = reasons.some((r) => r.kind === "enroll_dep" || r.kind === "enroll_profile");
    const confirmLabel = blocked
        ? "Cannot save yet"
        : fleetNow
            ? "Save and run on every device"
            : anyEnroll
                ? "Save and run on every device that enrolls"
                : reasons.length === 1
                    ? "Save with this warning"
                    : "Save with these warnings";

    return (
        <Modal
            opened={opened}
            // Once confirm is clicked the save is under way, so every way out stays shut until it settles.
            onClose={() => {
                if (!saving) onCancel();
            }}
            withCloseButton={!saving}
            closeOnEscape={!saving}
            closeOnClickOutside={!saving}
            title={
                <Group gap="xs">
                    <IconAlertTriangle size={18} color="var(--mantine-color-yellow-6)"/>
                    <Text fw={600}>Before you save &middot; {flowName}</Text>
                </Group>
            }
        >
            <Stack gap="md">
                {blocked && (
                    <Alert
                        color="red"
                        variant="light"
                        title={`The server will reject this save (${serverErrors.length} ${
                            serverErrors.length === 1 ? "error" : "errors"
                        })`}
                    >
                        <Text fz="sm" mb={6}>
                            This flow was checked against the server just now and came back invalid, so
                            saving it would be turned down. Fix these first, then save.
                        </Text>
                        <List size="sm">
                            {serverErrors.map((e, i) => (
                                <List.Item key={`server-error-${i}`}>{e}</List.Item>
                            ))}
                        </List>
                    </Alert>
                )}
                {reasons.map((r, i) => {
                    const p = previews[previewKey(r)];
                    const examples = p ? sampleSentence(p) : null;
                    return (
                        <Alert key={`${r.nodeId ?? "server"}::${i}`} color="yellow" variant="light">
                            <Text fz="sm">{r.message}</Text>
                            {p && (
                                <Text fz="sm" fw={600} mt={4}>
                                    {countSentence(r, p)}
                                </Text>
                            )}
                            {examples && (
                                <Text fz="xs" c="dimmed" mt={2}>
                                    {examples}
                                </Text>
                            )}
                        </Alert>
                    );
                })}
                <Text fz="xs" c="dimmed">
                    Nothing is saved yet.
                </Text>
                {/* Nothing to acknowledge while the save cannot go through. */}
                {!blocked && (
                    <Checkbox
                        checked={acked}
                        onChange={(e) => {
                            // Read the value before the state updater runs. React recycles the
                            // synthetic event, so e.currentTarget is null inside it.
                            const on = e.currentTarget.checked;
                            setAcked(on);
                        }}
                        label="I understand what this flow will do after I save."
                    />
                )}
                <Group justify="flex-end" gap="sm">
                    <Button variant="subtle" color="gray" disabled={saving} onClick={onCancel}>
                        Keep editing
                    </Button>
                    <Button disabled={blocked || !acked} loading={saving} onClick={onConfirm}>
                        {confirmLabel}
                    </Button>
                </Group>
            </Stack>
        </Modal>
    );
}
