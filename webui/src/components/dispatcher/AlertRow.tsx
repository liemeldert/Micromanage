import Link from "next/link";
import {
    ActionIcon,
    Anchor,
    Badge,
    Box,
    Button,
    Code,
    Collapse,
    Group,
    Paper,
    ScrollArea,
    Stack,
    Text,
    Tooltip,
} from "@mantine/core";
import {IconCheck, IconChevronRight} from "@tabler/icons-react";
import {
    type AtcRunFailedDetail,
    type CredentialRevealAlertDetail,
    type DispatcherAlert,
    isCredentialRevealAlert,
} from "../../../lib/api";
import {
    ALERT_BOARD_STRINGS,
    ATC_ALERT_STRINGS,
    CREDENTIAL_REVEAL_STRINGS,
    REMEDIATION_STRINGS,
} from "../../../lib/strings/alerts";
import {SEVERITY_COLORS} from "../../../lib/status-labels";
import {GlassCard} from "../ui/GlassCard";
import {AtcFailureDetail, CredentialRevealDetail, when} from "./alert-details";

type PendingApproval = { action_key: string; command: string };
type RemediationEntry = { action: string; at: string; outcome: string; dry_run?: boolean };

export function AlertRow({
                             alert,
                             isAdmin,
                             busy,
                             expanded,
                             onToggle,
                             deviceHref,
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
    deviceHref: string | null;
    ruleHref: string;
    onOpenRun: (runId: string) => void;
    onAck: () => void;
    onResolve: () => void;
    onApprove: (actionKey: string) => void;
    onReject: (actionKey: string, command: string) => void;
    onAction: (actionKey: string) => void;
}) {
    const detail = alert.detail || {};
    const pending = (detail.pending_approvals as PendingApproval[]) || [];
    const remediations = (detail.remediations as RemediationEntry[]) || [];
    // Some rules store an empty object as the failing state, which gets no section.
    const checkState = detail.check as Record<string, unknown> | undefined;
    const hasCheckState = !!checkState && Object.keys(checkState).length > 0;
    const color = SEVERITY_COLORS[alert.severity] ?? "gray";
    // ATC alerts carry their actions in detail, either a release from setup or the decision options of a manual_gate
    // node, each of which resumes the run down its edge.
    const kind = detail.kind as string | undefined;
    const gateOptions = (detail.options as { label: string; edge: string }[]) || [];
    const runFailure = kind === "atc_run_failed" ? (detail as unknown as AtcRunFailedDetail) : null;
    // Only an admin may close a credential reveal alert, and the burst flag marks a rapid run of reveals.
    const credentialReveal = isCredentialRevealAlert(alert);
    const revealDetail = credentialReveal ? (detail as CredentialRevealAlertDetail) : null;
    const burstCount = revealDetail?.burst ? revealDetail.reveals_in_window : undefined;
    // Namespaced ids (atc:*, breakglass:*) have no rule in the dispatcher config to link to.
    const authoredRule = !!alert.rule_id && !alert.rule_id.includes(":");

    return (
        <GlassCard withBorder p="sm" style={{borderLeft: `4px solid var(--mantine-color-${color}-6)`}}>
            <Group justify="space-between" wrap="wrap">
                <Group gap="sm" wrap="nowrap" style={{minWidth: 0, flex: "1 1 260px"}}>
                    <ActionIcon variant="subtle" color="gray" onClick={onToggle}
                                aria-label={expanded ? "Hide details" : "Show details"}>
                        <IconChevronRight
                            size={16}
                            style={{transform: expanded ? "rotate(90deg)" : "none", transition: "transform 120ms"}}
                        />
                    </ActionIcon>
                    {/* Keeps a long summary from truncating the badge. */}
                    <Badge color={color} variant="filled" tt="uppercase" style={{flexShrink: 0}}>
                        {alert.severity}
                    </Badge>
                    <Box style={{minWidth: 0}}>
                        <Text fw={600} fz="sm" truncate>
                            {alert.summary}
                        </Text>
                        <Group gap={6}>
                            {authoredRule ? (
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
                            {alert.device && deviceHref && (
                                <Anchor component={Link} href={deviceHref} fz="xs" c="blue">
                                    {alert.device.display_name || alert.device.serial_number}
                                </Anchor>
                            )}
                            <Badge size="xs" variant="light" color={alert.status === "open" ? color : "gray"}>
                                {alert.status}
                            </Badge>
                            {pending.length > 0 && (
                                <Badge size="xs" variant="outline" color="orange">
                                    {REMEDIATION_STRINGS.approvalBadge}
                                </Badge>
                            )}
                            {runFailure?.released_unverified && (
                                <Badge size="xs" variant="outline" color={color}>
                                    {ATC_ALERT_STRINGS.releasedBadge}
                                </Badge>
                            )}
                            {runFailure && !runFailure.released_unverified && runFailure.held_in_setup && (
                                <Badge size="xs" variant="outline" color={color}>
                                    {ATC_ALERT_STRINGS.heldBadge}
                                </Badge>
                            )}
                            {revealDetail?.burst && (
                                <Badge size="xs" variant="outline" color="red">
                                    {CREDENTIAL_REVEAL_STRINGS.burstBadge(burstCount)}
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
                                {ATC_ALERT_STRINGS.releaseFromSetup}
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
                                <ActionIcon variant="light" color="blue" loading={busy} onClick={onAck}
                                            aria-label="Acknowledge">
                                    <IconCheck size={16}/>
                                </ActionIcon>
                            </Tooltip>
                        )}
                        {/* A member closing a credential reveal alert gets a 403. */}
                        {credentialReveal && !isAdmin ? (
                            <Tooltip
                                label={CREDENTIAL_REVEAL_STRINGS.adminOnlyTooltip}
                                withinPortal
                                multiline
                                w={260}
                            >
                                <Text fz="xs" c="dimmed">
                                    {ALERT_BOARD_STRINGS.adminOnly}
                                </Text>
                            </Tooltip>
                        ) : (
                            <Button
                                size="compact-xs"
                                variant="light"
                                color={credentialReveal ? "orange" : "teal"}
                                loading={busy}
                                onClick={onResolve}
                            >
                                {credentialReveal ? CREDENTIAL_REVEAL_STRINGS.dismissButton : "Resolve"}
                            </Button>
                        )}
                    </Group>
                )}
            </Group>

            <Collapse expanded={expanded}>
                <Stack gap="xs" mt="sm" pl={40}>
                    {runFailure && <AtcFailureDetail detail={runFailure} onOpenRun={onOpenRun}/>}
                    {revealDetail && <CredentialRevealDetail detail={revealDetail}/>}
                    {pending.length > 0 && (
                        <Paper withBorder p="xs" radius="sm" bg="var(--mantine-color-orange-light)">
                            <Text fz="xs" fw={700} mb={4}>
                                {REMEDIATION_STRINGS.pendingHeading}
                            </Text>
                            {pending.map((pa) => (
                                <Group key={pa.action_key} justify="space-between" mb={4}>
                                    <Text fz="xs">
                                        <Code>{pa.command}</Code>
                                        {REMEDIATION_STRINGS.untilApproved}
                                    </Text>
                                    {isAdmin ? (
                                        <Group gap={6}>
                                            <Button
                                                size="compact-xs"
                                                variant="default"
                                                loading={busy}
                                                onClick={() => onReject(pa.action_key, pa.command)}
                                            >
                                                {REMEDIATION_STRINGS.reject}
                                            </Button>
                                            <Button size="compact-xs" color="red" loading={busy}
                                                    onClick={() => onApprove(pa.action_key)}>
                                                {REMEDIATION_STRINGS.approve}
                                            </Button>
                                        </Group>
                                    ) : (
                                        <Text fz="xs" c="dimmed">
                                            {ALERT_BOARD_STRINGS.adminOnly}
                                        </Text>
                                    )}
                                </Group>
                            ))}
                        </Paper>
                    )}
                    {remediations.length > 0 && (
                        <Box>
                            <Text fz="xs" fw={700} mb={2}>
                                {REMEDIATION_STRINGS.ledgerHeading}
                            </Text>
                            <ScrollArea.Autosize mah={160}>
                                {remediations.slice().reverse().map((r, i) => (
                                    <Text key={i} fz="xs" c="dimmed">
                                        {REMEDIATION_STRINGS.ledgerLine(when(r.at), r.action, !!r.dry_run, r.outcome)}
                                    </Text>
                                ))}
                            </ScrollArea.Autosize>
                        </Box>
                    )}
                    {hasCheckState ? (
                        <Box>
                            <Text fz="xs" fw={700} mb={2}>
                                {ALERT_BOARD_STRINGS.failingState}
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
