import {Alert, Badge, Box, Button, Code, Group, Stack, Text} from "@mantine/core";
import {IconExternalLink} from "@tabler/icons-react";
import {type AtcRunFailedDetail, type CredentialRevealAlertDetail, type FlowGap} from "../../../lib/api";
import {
    ATC_ALERT_STRINGS,
    CREDENTIAL_REVEAL_STRINGS,
    GAP_LEDGER_STRINGS,
    gapHeadline,
} from "../../../lib/strings/alerts";

export const when = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : "");

export function CredentialRevealDetail({detail}: { detail: CredentialRevealAlertDetail }) {
    const revealed = detail.reveal_count ?? 0;
    return (
        <Stack gap={4}>
            {detail.burst && (
                <Alert variant="light" color="red" p="xs" title={CREDENTIAL_REVEAL_STRINGS.burstTitle}>
                    <Text fz="xs">{CREDENTIAL_REVEAL_STRINGS.burstBody(detail.reveals_in_window)}</Text>
                </Alert>
            )}
            <Text fz="xs">
                {detail.last_revealed_by ? (
                    <>
                        {CREDENTIAL_REVEAL_STRINGS.lastRevealedBy} <b>{detail.last_revealed_by}</b>
                        {detail.last_revealed_at
                            ? CREDENTIAL_REVEAL_STRINGS.revealedOn(when(detail.last_revealed_at))
                            : ""}.
                    </>
                ) : (
                    CREDENTIAL_REVEAL_STRINGS.noRevealer
                )}
            </Text>
            {detail.first_revealed_by && detail.first_revealed_by !== detail.last_revealed_by && (
                <Text fz="xs" c="dimmed">
                    {CREDENTIAL_REVEAL_STRINGS.firstRevealedBy(detail.first_revealed_by)}
                </Text>
            )}
            {revealed > 1 && (
                <Text fz="xs" c="dimmed">
                    {CREDENTIAL_REVEAL_STRINGS.revealCount(revealed)}
                </Text>
            )}
            <Text fz="xs" c="dimmed">
                {CREDENTIAL_REVEAL_STRINGS.closesOnRotation}
            </Text>
        </Stack>
    );
}

function GapLedger({gaps}: { gaps: FlowGap[] }) {
    const broken = gaps.some((g) => g.grade === "broken" || (g.items ?? []).some((i) => i.grade === "broken"));
    const worst = broken ? "broken" : "policy";
    // A ledger of nothing but empty barriers has no ids to name, so the text points at the flow instead.
    const named = gaps.some((g) => (g.items ?? []).length > 0);
    const strings = GAP_LEDGER_STRINGS[worst];

    return (
        <Stack gap="xs">
            <Alert
                variant="light"
                color={broken ? "red" : "yellow"}
                p="xs"
                title={strings.title}
            >
                <Text fz="xs">{named ? strings.named : strings.unnamed}</Text>
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

export function AtcFailureDetail({
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
                    {ATC_ALERT_STRINGS.openRun}
                </Button>
            )}

            <Box>
                <Text fz="xs">
                    {ATC_ALERT_STRINGS.flow} <Code>{detail.flow_id}</Code>
                    {detail.node_id ? (
                        <>
                            {" "}
                            {ATC_ALERT_STRINGS.stoppedAt} <Code>{detail.node_id}</Code>
                        </>
                    ) : (
                        ` ${ATC_ALERT_STRINGS.stoppedBeforeStep}`
                    )}
                    {detail.event_kind ? (
                        <Text span c="dimmed">
                            {" "}
                            {ATC_ALERT_STRINGS.startedBy(detail.event_kind)}
                        </Text>
                    ) : null}
                </Text>
                {/* The alert covers every failure of this flow on this device, so the ledger below may be from an
                    older run. */}
                {detail.error && (
                    <Text fz="xs" mt={2}>
                        {detail.error}
                    </Text>
                )}
            </Box>

            {detail.held_in_setup && !detail.released_unverified && (
                <Alert variant="light" color="red" p="xs" title={ATC_ALERT_STRINGS.heldTitle}>
                    <Text fz="xs">{ATC_ALERT_STRINGS.heldBody}</Text>
                </Alert>
            )}

            {gaps.length > 0 && <GapLedger gaps={gaps}/>}

            <Text fz={10} c="dimmed">
                {count > 1
                    ? ATC_ALERT_STRINGS.failures(count, when(detail.first_failed_at), when(detail.last_failed_at))
                    : ATC_ALERT_STRINGS.failedOnce(when(detail.last_failed_at || detail.first_failed_at))}
            </Text>
        </Stack>
    );
}
