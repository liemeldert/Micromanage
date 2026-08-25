import {useCallback, useEffect, useMemo, useState} from "react";
import Link from "next/link";
import {useRouter, useSearchParams} from "next/navigation";
import {
    ActionIcon,
    Alert,
    Anchor,
    Badge,
    Box,
    Button,
    Chip,
    Code,
    Collapse,
    Group,
    Loader,
    Modal,
    Paper,
    ScrollArea,
    Stack,
    Text,
    Textarea,
    Tooltip,
} from "@mantine/core";
import {notifications} from "@mantine/notifications";
import {
    IconAlertTriangle,
    IconCheck,
    IconChevronRight,
    IconExternalLink,
    IconRefresh,
    IconShieldCheck,
} from "@tabler/icons-react";
import {
    api,
    type AtcRunFailedDetail,
    type BreakGlassAlertDetail,
    type DispatcherAlert,
    type FlowGap,
    isBreakGlassAlert,
} from "../../../lib/api";
import {useAuth} from "../../../lib/auth-context";
import {GlassCard} from "../ui/GlassCard";

// Triage colours (black > red > yellow > green).
const SEVERITY_COLOR: Record<string, string> = {
    black: "dark",
    red: "red",
    yellow: "yellow",
    green: "green",
};

const ACTIVE_STATUSES = ["pending", "open", "acknowledged"];

export function AlertBoard() {
    const {token, isAdmin} = useAuth();
    const router = useRouter();
    const [alerts, setAlerts] = useState<DispatcherAlert[]>([]);
    const [counts, setCounts] = useState<Record<string, number>>({});
    const [loading, setLoading] = useState(true);
    // Why the last fetch failed, so a failed load does not render as a clean board.
    const [loadError, setLoadError] = useState<string | null>(null);
    const [sevFilter, setSevFilter] = useState<string | null>(null);
    const [showResolved, setShowResolved] = useState(false);
    const [expanded, setExpanded] = useState<string | null>(null);
    // ?alert= names one to open and ?severity= narrows to one column, which is how the dashboard board hands
    // either of them over.
    const params = useSearchParams();
    const wantedAlert = params.get("alert");
    const wantedSeverity = params.get("severity");
    useEffect(() => {
        if (wantedAlert) setExpanded(wantedAlert);
    }, [wantedAlert]);
    useEffect(() => {
        if (wantedSeverity) setSevFilter(wantedSeverity);
    }, [wantedSeverity]);
    const [busy, setBusy] = useState<string | null>(null);
    // The break-glass alert waiting on a reason before it closes, so dismissing one is never a single click.
    const [dismissing, setDismissing] = useState<DispatcherAlert | null>(null);
    const [reason, setReason] = useState("");
    // The pending remediation waiting on a veto reason. The reason is optional and goes on the audit row.
    const [rejecting, setRejecting] = useState<{
        alert: DispatcherAlert;
        actionKey: string;
        command: string
    } | null>(null);
    const [rejectReason, setRejectReason] = useState("");

    const load = useCallback(
        async (background = false) => {
            if (!token) return;
            if (!background) setLoading(true);
            try {
                const res = await api.listAlerts(token, sevFilter ? {severity: sevFilter} : {});
                setAlerts(res.alerts);
                setCounts(res.counts);
                setLoadError(null);
            } catch (e) {
                setLoadError((e as Error).message);
                if (!background) notifications.show({color: "red", message: (e as Error).message});
            } finally {
                if (!background) setLoading(false);
            }
        },
        [token, sevFilter],
    );

    useEffect(() => {
        load();
        const t = setInterval(() => load(true), 15000);
        return () => clearInterval(t);
    }, [load]);

    const visible = useMemo(
        () => alerts.filter((a) => (showResolved ? true : ACTIVE_STATUSES.includes(a.status))),
        [alerts, showResolved],
    );

    const act = async (fn: () => Promise<unknown>, id: string) => {
        setBusy(id);
        try {
            await fn();
            await load(true);
        } catch (e) {
            notifications.show({color: "red", message: (e as Error).message});
        } finally {
            setBusy(null);
        }
    };

    const evaluateNow = () =>
        act(async () => {
            const r = await api.dispatcherEvaluate(token!);
            notifications.show({
                color: "teal",
                message: `Evaluated ${r.devices_evaluated} device${r.devices_evaluated === 1 ? "" : "s"}`,
            });
        }, "__eval");

    if (loading) return <Loader/>;

    return (
        <Stack gap="md">
            <Group justify="space-between">
                <Group gap="xs">
                    {(["black", "red", "yellow", "green"] as const).map((s) => (
                        <Chip
                            key={s}
                            checked={sevFilter === s}
                            onChange={() => setSevFilter(sevFilter === s ? null : s)}
                            color={SEVERITY_COLOR[s]}
                            variant="light"
                            size="sm"
                        >
                            {s} · {counts[s] ?? 0}
                        </Chip>
                    ))}
                </Group>
                <Group gap="xs">
                    <Chip checked={showResolved} onChange={() => setShowResolved((v) => !v)} size="sm" variant="light">
                        Show resolved
                    </Chip>
                    <Button
                        size="compact-sm"
                        variant="light"
                        leftSection={<IconRefresh size={14}/>}
                        onClick={evaluateNow}
                        loading={busy === "__eval"}
                    >
                        Evaluate now
                    </Button>
                </Group>
            </Group>

            {loadError && (
                <Alert
                    color="red"
                    variant="light"
                    icon={<IconAlertTriangle size={16}/>}
                    title="Couldn't load alerts"
                >
                    <Stack gap="xs" align="flex-start">
                        <Text fz="sm">
                            {loadError}
                            {alerts.length > 0 ? " Anything below is from the last fetch that worked." : ""}
                        </Text>
                        <Button
                            size="compact-sm"
                            variant="light"
                            color="red"
                            leftSection={<IconRefresh size={14}/>}
                            onClick={() => load()}
                        >
                            Retry
                        </Button>
                    </Stack>
                </Alert>
            )}

            {visible.length === 0 && !loadError ? (
                <Paper withBorder p="xl">
                    <Group justify="center" gap="xs">
                        <IconShieldCheck size={20} color="var(--mantine-color-teal-6)"/>
                        {/* Name the severity: with a filter on, a bare "no active alerts" contradicts the chip
                beside it still counting some. */}
                        <Text c="dimmed">
                            No {showResolved ? "" : "active "}
                            {sevFilter ? `${sevFilter} ` : ""}alerts.
                        </Text>
                    </Group>
                </Paper>
            ) : (
                <Stack gap={6}>
                    {visible.map((a) => (
                        <AlertRow
                            key={a.id}
                            alert={a}
                            isAdmin={isAdmin}
                            busy={busy === a.id}
                            expanded={expanded === a.id}
                            onToggle={() => setExpanded(expanded === a.id ? null : a.id)}
                            onOpenDevice={() => a.device_id && router.push(`/devices/${a.device_id}`)}
                            ruleHref={`/compliance/rules?rule=${encodeURIComponent(a.rule_id)}`}
                            onOpenRun={(runId) => router.push(`/atc/runs/${runId}`)}
                            onAck={() => act(() => api.acknowledgeAlert(token!, a.id), a.id)}
                            onResolve={() => {
                                // A break-glass alert asks for a reason first; everything else closes on
                                // the click.
                                if (isBreakGlassAlert(a)) {
                                    setReason("");
                                    setDismissing(a);
                                    return;
                                }
                                act(() => api.resolveAlert(token!, a.id), a.id);
                            }}
                            onApprove={(key) =>
                                act(async () => {
                                    const r = await api.approveRemediation(token!, a.id, key);
                                    notifications.show({color: "teal", message: r.outcome});
                                }, a.id)
                            }
                            onReject={(key, command) => {
                                setRejectReason("");
                                setRejecting({alert: a, actionKey: key, command});
                            }}
                            onAction={(key) => act(() => api.alertAction(token!, a.id, key), a.id)}
                        />
                    ))}
                </Stack>
            )}

            <Modal
                opened={dismissing !== null}
                onClose={() => setDismissing(null)}
                title="Dismiss this break-glass alert?"
                centered
            >
                <Stack gap="sm">
                    <Text fz="sm">
                        This alert records that somebody was handed a device password. It closes on its own once
                        that password is rotated, so dismissing it says you have decided no rotation is needed.
                        Your name and your reason go into the audit log.
                    </Text>
                    <Textarea
                        label="Reason"
                        description="Optional. It is the only explanation the audit log will carry."
                        placeholder="Recovered the cart after the power cut; passwords unchanged on purpose."
                        autosize
                        minRows={2}
                        value={reason}
                        onChange={(e) => setReason(e.currentTarget.value)}
                    />
                    <Group justify="flex-end">
                        <Button variant="default" onClick={() => setDismissing(null)}>
                            Cancel
                        </Button>
                        <Button
                            color="orange"
                            loading={busy === dismissing?.id}
                            onClick={() => {
                                const target = dismissing;
                                if (!target) return;
                                setDismissing(null);
                                act(() => api.resolveAlert(token!, target.id, reason.trim() || undefined), target.id);
                            }}
                        >
                            Dismiss alert
                        </Button>
                    </Group>
                </Stack>
            </Modal>

            <Modal
                opened={rejecting !== null}
                onClose={() => setRejecting(null)}
                title="Reject this queued command?"
                centered
            >
                <Stack gap="sm">
                    <Text fz="sm">
                        <Code>{rejecting?.command}</Code> never runs. It stops waiting for a decision, even if
                        the alert is later resolved without anybody approving it.
                    </Text>
                    <Textarea
                        label="Reason"
                        description="Optional. It is the only explanation the audit log will carry."
                        placeholder="Device came back into compliance on its own; no need to wipe it."
                        autosize
                        minRows={2}
                        value={rejectReason}
                        onChange={(e) => setRejectReason(e.currentTarget.value)}
                    />
                    <Group justify="flex-end">
                        <Button variant="default" onClick={() => setRejecting(null)}>
                            Cancel
                        </Button>
                        <Button
                            color="orange"
                            loading={busy === rejecting?.alert.id}
                            onClick={() => {
                                const target = rejecting;
                                if (!target) return;
                                setRejecting(null);
                                act(async () => {
                                    const r = await api.rejectRemediation(
                                        token!, target.alert.id, target.actionKey, rejectReason.trim() || undefined,
                                    );
                                    notifications.show({color: "teal", message: r.message});
                                }, target.alert.id);
                            }}
                        >
                            Reject
                        </Button>
                    </Group>
                </Stack>
            </Modal>
        </Stack>
    );
}

const when = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : "");

/** The expanded body of a break-glass alert: who revealed the credential, how many times it has been revealed,
 * and whether this reveal was part of a burst. */
function BreakGlassDetail({detail}: { detail: BreakGlassAlertDetail }) {
    const revealed = detail.reveal_count ?? 0;
    return (
        <Stack gap={4}>
            {detail.burst && (
                <Alert variant="light" color="red" p="xs" title="Revealed during a burst">
                    <Text fz="xs">
                        {detail.reveals_in_window
                            ? `This was one of ${detail.reveals_in_window} passwords revealed in quick succession.`
                            : "This was one of several passwords revealed in quick succession."}{" "}
                        A burst looks the same whether one person is working through a cart or a session has been
                        stolen, so confirm who did it before you close this.
                    </Text>
                </Alert>
            )}
            <Text fz="xs">
                {detail.last_revealed_by ? (
                    <>
                        Last taken by <b>{detail.last_revealed_by}</b>
                        {detail.last_revealed_at ? ` on ${when(detail.last_revealed_at)}` : ""}.
                    </>
                ) : (
                    "No record of who took it."
                )}
            </Text>
            {detail.first_revealed_by && detail.first_revealed_by !== detail.last_revealed_by && (
                <Text fz="xs" c="dimmed">
                    First taken by {detail.first_revealed_by}.
                </Text>
            )}
            {revealed > 1 && (
                <Text fz="xs" c="dimmed">
                    Handed out {revealed} times in total.
                </Text>
            )}
            <Text fz="xs" c="dimmed">
                This closes by itself when the password is rotated.
            </Text>
        </Stack>
    );
}

/** One gap-ledger line as a sentence naming the wait step that came up short. An unrecognised kind falls back to
 * the raw value rather than disappearing. */
function gapHeadline(gap: FlowGap): string {
    const node = gap.node || "an earlier step";
    switch (gap.kind) {
        case "not_queued":
            return `${node} did not queue everything it named`;
        case "barrier_empty":
            return `the wait at ${node} had nothing to hold`;
        case "never_arrived":
            return `${node} gave up waiting for these`;
        default:
            return `${node} recorded a ${gap.kind} gap`;
    }
}

/** The ledger the release guard snapshotted onto the alert: which ids the device did not get and why.
 *
 * A broken grade means the flow named something the engine could not deliver, so there is an id to look up. A
 * policy grade means the device was not entitled to it yet, usually a rollout wave. */
function GapLedger({gaps}: { gaps: FlowGap[] }) {
    const worst = gaps.some(
        (g) => g.grade === "broken" || (g.items ?? []).some((i) => i.grade === "broken"),
    )
        ? "broken"
        : "policy";
    // A ledger of nothing but empty barriers has no ids to name, so the copy points at the flow instead.
    const named = gaps.some((g) => (g.items ?? []).length > 0);

    return (
        <Stack gap="xs">
            <Alert
                variant="light"
                color={worst === "broken" ? "red" : "yellow"}
                p="xs"
                title={
                    worst === "broken"
                        ? "The device went out without something the flow asked for"
                        : "The device went out early, but nothing it was owed is missing"
                }
            >
                <Text fz="xs">
                    {worst === "broken" && named
                        ? "It left Setup Assistant and is in use now. The ids below were named by the " +
                        "flow and never reached the device, so check each one against this tenant's " +
                        "config before another device runs this flow."
                        : worst === "broken"
                            ? "It left Setup Assistant and is in use now. Nothing above the wait step " +
                            "below ever queued anything for it, so the flow is holding for something " +
                            "it never asks for. Fix the flow before another device runs it."
                            : named
                                ? "It left Setup Assistant before the wait step had anything to hold, " +
                                "because this device was not entitled to the items below yet. If the " +
                                "step is not meant to hold a device up, switch its gate off in the " +
                                "flow editor."
                                : "It left Setup Assistant before the wait step had anything to hold, and " +
                                "nothing this device was owed is missing. If the step is not meant to " +
                                "hold a device up, switch its gate off in the flow editor."}
                </Text>
            </Alert>

            {gaps.map((gap, gi) => {
                const items = gap.items ?? [];
                return (
                    <Box key={gi}>
                        <Group gap={6} align="center">
                            <Badge
                                size="xs"
                                variant="light"
                                color={gap.grade === "broken" ? "red" : "yellow"}
                            >
                                {gap.grade}
                            </Badge>
                            <Text fz="xs" fw={600}>
                                {gapHeadline(gap)}
                            </Text>
                            {gap.signal && (
                                <Text fz={10} c="dimmed">
                                    {gap.signal}
                                </Text>
                            )}
                        </Group>
                        {items.length > 0 && (
                            <Stack gap={2} pl={12} mt={2}>
                                {items.map((item, ii) => (
                                    <Text key={ii} fz="xs">
                                        <Code>{item.id}</Code>{" "}
                                        <Text span c="dimmed">
                                            {item.why}
                                        </Text>
                                    </Text>
                                ))}
                            </Stack>
                        )}
                        {gap.note && (
                            <Text fz="xs" c="dimmed" pl={12}>
                                {gap.note}
                            </Text>
                        )}
                    </Box>
                );
            })}
        </Stack>
    );
}

/** Everything a failed ATC run put on the board: the node it stopped at, the error, how often it has come back,
 * and the way through to the run itself. Failures coalesce into one row per device and flow, so this panel is the
 * only place the repeat count is visible. */
function AtcFailureDetail({
                              detail,
                              onOpenRun,
                          }: {
    detail: AtcRunFailedDetail;
    onOpenRun: (runId: string) => void;
}) {
    const gaps = detail.gaps ?? [];
    const count = detail.failure_count ?? 1;

    return (
        <Stack gap="xs">
            {detail.flow_run_id && (
                <Button
                    size="compact-sm"
                    variant="light"
                    w="fit-content"
                    leftSection={<IconExternalLink size={14}/>}
                    onClick={() => onOpenRun(detail.flow_run_id)}
                >
                    Open the run that failed
                </Button>
            )}

            <Box>
                <Text fz="xs">
                    Flow <Code>{detail.flow_id}</Code>
                    {detail.node_id ? (
                        <>
                            {" "}
                            stopped at <Code>{detail.node_id}</Code>
                        </>
                    ) : (
                        " stopped before it reached a step"
                    )}
                    {detail.event_kind ? (
                        <Text span c="dimmed">
                            {" "}
                            (started by {detail.event_kind})
                        </Text>
                    ) : null}
                </Text>
                {/* Always shown, even when the ledger below repeats it: one row covers every failure of this flow
            on this device, so the ledger may be from an older one. */}
                {detail.error && (
                    <Text fz="xs" mt={2}>
                        {detail.error}
                    </Text>
                )}
            </Box>

            {detail.held_in_setup && !detail.released_unverified && (
                <Alert variant="light" color="red" p="xs" title="Still in Setup Assistant">
                    <Text fz="xs">
                        The run stopped before it could release this device, so it is sitting on the
                        Remote Management screen and nobody can use it until you release it or fix the
                        flow.
                    </Text>
                </Alert>
            )}

            {gaps.length > 0 && <GapLedger gaps={gaps}/>}

            <Text fz={10} c="dimmed">
                {count > 1
                    ? `${count} failures, first ${when(detail.first_failed_at)}, most recent ${when(
                        detail.last_failed_at,
                    )}.`
                    : `Failed ${when(detail.last_failed_at || detail.first_failed_at)}.`}
            </Text>
        </Stack>
    );
}

function AlertRow({
                      alert,
                      isAdmin,
                      busy,
                      expanded,
                      onToggle,
                      onOpenDevice,
                      ruleHref,
                      onOpenRun,
                      onAck,
                      onResolve,
                      onApprove,
                      onReject,
                      onAction,
                  }: {
    alert: DispatcherAlert;
    isAdmin: boolean;
    busy: boolean;
    expanded: boolean;
    onToggle: () => void;
    onOpenDevice: () => void;
    ruleHref: string;
    onOpenRun: (runId: string) => void;
    onAck: () => void;
    onResolve: () => void;
    onApprove: (actionKey: string) => void;
    onReject: (actionKey: string, command: string) => void;
    onAction: (actionKey: string) => void;
}) {
    const detail = alert.detail || {};
    const pending = (detail.pending_approvals as { action_key: string; command: string }[]) || [];
    const remediations = (detail.remediations as {
        action: string;
        at: string;
        outcome: string;
        dry_run?: boolean
    }[]) || [];
    // Some rules record no failing state and leave a truthy empty object behind, so check for keys before putting
    // the heading over a literal {}.
    const checkState = detail.check as Record<string, unknown> | undefined;
    const hasCheckState = !!checkState && Object.keys(checkState).length > 0;
    const color = SEVERITY_COLOR[alert.severity] ?? "gray";
    // ATC alerts carry typed actions in detail: an in-setup release, or a set of
    // manual_gate decision options (each resumes the run down its edge).
    const kind = detail.kind as string | undefined;
    const gateOptions = (detail.options as { label: string; edge: string }[]) || [];
    const runFailure = kind === "atc_run_failed" ? (detail as unknown as AtcRunFailedDetail) : null;
    // A break-glass alert records that a recovery credential was revealed. Only an admin may close one, and the
    // burst flag is what turns some of them red.
    const breakGlass = isBreakGlassAlert(alert);
    const bgDetail = breakGlass ? (detail as BreakGlassAlertDetail) : null;
    const burstCount = bgDetail?.burst ? bgDetail.reveals_in_window : undefined;
    // Namespaced ids (atc:*, breakglass:*) belong to no rule in the dispatcher config,
    // so only a real rule id is worth linking to the rule editor.
    const authoredRule = !!alert.rule_id && !alert.rule_id.includes(":");

    return (
        <GlassCard withBorder p="sm" style={{borderLeft: `4px solid var(--mantine-color-${color}-6)`}}>
            {/* Wraps rather than squeezes: on a phone the buttons and the summary do not fit on one line, and
          nowrap spends the width on the buttons and truncates the summary. */}
            <Group justify="space-between" wrap="wrap">
                <Group gap="sm" wrap="nowrap" style={{minWidth: 0, flex: "1 1 260px"}}>
                    <ActionIcon variant="subtle" color="gray" onClick={onToggle}
                                aria-label={expanded ? "Hide details" : "Show details"}>
                        <IconChevronRight
                            size={16}
                            style={{transform: expanded ? "rotate(90deg)" : "none", transition: "transform 120ms"}}
                        />
                    </ActionIcon>
                    {/* ATC summaries run long, and without flexShrink the Group squeezes this badge down to
              "R...". */}
                    <Badge color={color} variant="filled" tt="uppercase" style={{flexShrink: 0}}>
                        {alert.severity}
                    </Badge>
                    <Box style={{minWidth: 0}}>
                        <Text fw={600} fz="sm" truncate>
                            {alert.summary}
                        </Text>
                        <Group gap={6}>
                            {authoredRule ? (
                                // A real anchor: keyboard focus, middle-click and
                                // open-in-new-tab all work, unlike a click handler.
                                <Anchor
                                    component={Link}
                                    href={ruleHref}
                                    fz="xs"
                                    onClick={(e) => e.stopPropagation()}
                                >
                                    {alert.rule_id}
                                </Anchor>
                            ) : (
                                <Text fz="xs" c="dimmed">
                                    {alert.rule_id}
                                </Text>
                            )}
                            {alert.device && (
                                <Text
                                    fz="xs"
                                    c="blue"
                                    style={{cursor: "pointer"}}
                                    onClick={onOpenDevice}
                                >
                                    {alert.device.display_name || alert.device.serial_number}
                                </Text>
                            )}
                            <Badge size="xs" variant="light" color={alert.status === "open" ? color : "gray"}>
                                {alert.status}
                            </Badge>
                            {pending.length > 0 && (
                                <Badge size="xs" variant="outline" color="orange">
                                    approval required
                                </Badge>
                            )}
                            {runFailure?.released_unverified && (
                                <Badge size="xs" variant="outline" color={color}>
                                    released unverified
                                </Badge>
                            )}
                            {runFailure && !runFailure.released_unverified && runFailure.held_in_setup && (
                                <Badge size="xs" variant="outline" color={color}>
                                    held in setup
                                </Badge>
                            )}
                            {bgDetail?.burst && (
                                <Badge size="xs" variant="outline" color="red">
                                    {burstCount
                                        ? `revealed during a burst of ${burstCount}`
                                        : "revealed during a burst"}
                                </Badge>
                            )}
                        </Group>
                    </Box>
                </Group>
                {alert.status !== "resolved" && (
                    <Group gap={4} wrap="nowrap">
                        {kind === "atc_in_setup" && (
                            <Button size="compact-xs" variant="light" color="green" loading={busy}
                                    onClick={() => onAction("release")}>
                                Release from setup
                            </Button>
                        )}
                        {kind === "atc_gate" &&
                            gateOptions.map((o) => (
                                <Button
                                    key={o.edge}
                                    size="compact-xs"
                                    variant="light"
                                    color={o.edge === "on_release" ? "green" : o.edge === "on_cancel" ? "red" : "blue"}
                                    loading={busy}
                                    onClick={() => onAction(o.edge)}
                                >
                                    {o.label}
                                </Button>
                            ))}
                        {alert.status !== "acknowledged" && (
                            <Tooltip label="Acknowledge">
                                <ActionIcon variant="light" color="blue" loading={busy} onClick={onAck}>
                                    <IconCheck size={16}/>
                                </ActionIcon>
                            </Tooltip>
                        )}
                        {/* The server returns 403 for a member closing a break-glass alert,
                so the button says why instead of offering a click that fails. */}
                        {breakGlass && !isAdmin ? (
                            <Tooltip
                                label={"Only an admin can dismiss this. It closes on its own once the "
                                    + "password is rotated."}
                                withinPortal
                                multiline
                                w={260}
                            >
                                <Text fz="xs" c="dimmed">
                                    admin only
                                </Text>
                            </Tooltip>
                        ) : (
                            <Button
                                size="compact-xs"
                                variant="light"
                                color={breakGlass ? "orange" : "teal"}
                                loading={busy}
                                onClick={onResolve}
                            >
                                {breakGlass ? "Dismiss" : "Resolve"}
                            </Button>
                        )}
                    </Group>
                )}
            </Group>

            <Collapse in={expanded}>
                <Stack gap="xs" mt="sm" pl={40}>
                    {runFailure && <AtcFailureDetail detail={runFailure} onOpenRun={onOpenRun}/>}
                    {bgDetail && <BreakGlassDetail detail={bgDetail}/>}
                    {pending.length > 0 && (
                        <Paper withBorder p="xs" radius="sm" bg="var(--mantine-color-orange-light)">
                            <Text fz="xs" fw={700} mb={4}>
                                Pending admin approval (destructive)
                            </Text>
                            {pending.map((pa) => (
                                <Group key={pa.action_key} justify="space-between" mb={4}>
                                    <Text fz="xs">
                                        <Code>{pa.command}</Code>, which never runs until approved
                                    </Text>
                                    {isAdmin ? (
                                        <Group gap={6}>
                                            <Button
                                                size="compact-xs"
                                                variant="default"
                                                loading={busy}
                                                onClick={() => onReject(pa.action_key, pa.command)}
                                            >
                                                Reject
                                            </Button>
                                            <Button size="compact-xs" color="red" loading={busy}
                                                    onClick={() => onApprove(pa.action_key)}>
                                                Approve &amp; run
                                            </Button>
                                        </Group>
                                    ) : (
                                        <Text fz="xs" c="dimmed">
                                            admin only
                                        </Text>
                                    )}
                                </Group>
                            ))}
                        </Paper>
                    )}
                    {remediations.length > 0 && (
                        <Box>
                            <Text fz="xs" fw={700} mb={2}>
                                Remediation ledger
                            </Text>
                            <ScrollArea.Autosize mah={160}>
                                {remediations.slice().reverse().map((r, i) => (
                                    <Text key={i} fz="xs" c="dimmed">
                                        {r.at ? new Date(r.at).toLocaleString() : ""} · {r.action}
                                        {r.dry_run ? " (dry-run)" : ""} → {r.outcome}
                                    </Text>
                                ))}
                            </ScrollArea.Autosize>
                        </Box>
                    )}
                    {hasCheckState ? (
                        <Box>
                            <Text fz="xs" fw={700} mb={2}>
                                Failing state
                            </Text>
                            <Code block fz={10}>
                                {JSON.stringify(checkState, null, 2)}
                            </Code>
                        </Box>
                    ) : null}
                </Stack>
            </Collapse>
        </GlassCard>
    );
}
