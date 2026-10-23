import {type ReactNode, useCallback, useEffect, useMemo, useState} from "react";
import {useRouter, useSearchParams} from "next/navigation";
import {Alert, Button, Chip, Code, Group, Loader, Modal, Paper, Stack, Text, Textarea} from "@mantine/core";
import {notifications} from "@mantine/notifications";
import {IconAlertTriangle, IconRefresh, IconShieldCheck} from "@tabler/icons-react";
import {api, type DispatcherAlert, isCredentialRevealAlert} from "../../../lib/api";
import {ALERT_BOARD_STRINGS, CREDENTIAL_REVEAL_STRINGS, REMEDIATION_STRINGS} from "../../../lib/strings/alerts";
import {useAuth} from "../../../lib/auth-context";
import {SEVERITIES, SEVERITY_COLORS} from "../../../lib/status-labels";
import {AlertRow} from "./AlertRow";

const ACTIVE_STATUSES = ["pending", "open", "acknowledged"];

type PendingReject = { alert: DispatcherAlert; actionKey: string; command: string };

export function AlertBoard() {
    const {isAdmin} = useAuth();
    const router = useRouter();
    const [alerts, setAlerts] = useState<DispatcherAlert[]>([]);
    const [counts, setCounts] = useState<Record<string, number>>({});
    const [loading, setLoading] = useState(true);
    // Why the last fetch failed, so a failed load does not render as a clean board.
    const [loadError, setLoadError] = useState<string | null>(null);
    const [sevFilter, setSevFilter] = useState<string | null>(null);
    const [showResolved, setShowResolved] = useState(false);
    const [expanded, setExpanded] = useState<string | null>(null);
    const [busy, setBusy] = useState<string | null>(null);
    // The credential reveal alert whose dismiss dialog is open.
    const [dismissing, setDismissing] = useState<DispatcherAlert | null>(null);
    const [reason, setReason] = useState("");
    // The pending remediation whose reject dialog is open.
    const [rejecting, setRejecting] = useState<PendingReject | null>(null);
    const [rejectReason, setRejectReason] = useState("");

    // The dashboard links here with ?alert= to open one alert and ?severity= to filter.
    const params = useSearchParams();
    const wantedAlert = params.get("alert");
    const wantedSeverity = params.get("severity");
    useEffect(() => {
        if (wantedAlert) setExpanded(wantedAlert);
    }, [wantedAlert]);
    useEffect(() => {
        if (wantedSeverity) setSevFilter(wantedSeverity);
    }, [wantedSeverity]);

    const load = useCallback(
        async (background = false) => {
            if (!background) setLoading(true);
            try {
                const res = await api.listAlerts(sevFilter ? {severity: sevFilter} : {});
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
        [sevFilter],
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
            const r = await api.dispatcherEvaluate();
            notifications.show({
                color: "teal",
                message: ALERT_BOARD_STRINGS.evaluated(r.devices_evaluated),
            });
        }, "__eval");

    if (loading) return <Loader/>;

    return (
        <Stack gap="md">
            <Group justify="space-between">
                <Group gap="xs">
                    {SEVERITIES.map((s) => (
                        <Chip
                            key={s}
                            checked={sevFilter === s}
                            onChange={() => setSevFilter(sevFilter === s ? null : s)}
                            color={SEVERITY_COLORS[s]}
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
                    title={ALERT_BOARD_STRINGS.loadErrorTitle}
                >
                    <Stack gap="xs" align="flex-start">
                        <Text fz="sm">
                            {loadError}
                            {alerts.length > 0 ? ` ${ALERT_BOARD_STRINGS.staleData}` : ""}
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
                        <Text c="dimmed">{ALERT_BOARD_STRINGS.empty(showResolved, sevFilter)}</Text>
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
                            deviceHref={a.device_id ? `/devices/${a.device_id}` : null}
                            ruleHref={`/compliance/rules?rule=${encodeURIComponent(a.rule_id)}`}
                            onOpenRun={(runId) => router.push(`/atc/runs/${runId}`)}
                            onAck={() => act(() => api.acknowledgeAlert(a.id), a.id)}
                            onResolve={() => {
                                // A credential reveal alert asks for a reason first.
                                if (isCredentialRevealAlert(a)) {
                                    setReason("");
                                    setDismissing(a);
                                    return;
                                }
                                act(() => api.resolveAlert(a.id), a.id);
                            }}
                            onApprove={(key) =>
                                act(async () => {
                                    const r = await api.approveRemediation(a.id, key);
                                    notifications.show({color: "teal", message: r.outcome});
                                }, a.id)
                            }
                            onReject={(key, command) => {
                                setRejectReason("");
                                setRejecting({alert: a, actionKey: key, command});
                            }}
                            onAction={(key) => act(() => api.alertAction(a.id, key), a.id)}
                        />
                    ))}
                </Stack>
            )}

            <ReasonModal
                opened={dismissing !== null}
                onClose={() => setDismissing(null)}
                title={CREDENTIAL_REVEAL_STRINGS.dismissTitle}
                body={CREDENTIAL_REVEAL_STRINGS.dismissBody}
                placeholder={CREDENTIAL_REVEAL_STRINGS.dismissPlaceholder}
                confirmLabel={CREDENTIAL_REVEAL_STRINGS.dismissConfirm}
                reason={reason}
                onReasonChange={setReason}
                loading={busy === dismissing?.id}
                onConfirm={() => {
                    const target = dismissing;
                    if (!target) return;
                    setDismissing(null);
                    act(() => api.resolveAlert(target.id, reason.trim() || undefined), target.id);
                }}
            />

            <ReasonModal
                opened={rejecting !== null}
                onClose={() => setRejecting(null)}
                title={REMEDIATION_STRINGS.rejectTitle}
                body={
                    <>
                        <Code>{rejecting?.command}</Code>
                        {REMEDIATION_STRINGS.rejectBody}
                    </>
                }
                placeholder={REMEDIATION_STRINGS.rejectPlaceholder}
                confirmLabel={REMEDIATION_STRINGS.reject}
                reason={rejectReason}
                onReasonChange={setRejectReason}
                loading={busy === rejecting?.alert.id}
                onConfirm={() => {
                    const target = rejecting;
                    if (!target) return;
                    setRejecting(null);
                    act(async () => {
                        const r = await api.rejectRemediation(
                            target.alert.id, target.actionKey, rejectReason.trim() || undefined,
                        );
                        notifications.show({color: "teal", message: r.message});
                    }, target.alert.id);
                }}
            />
        </Stack>
    );
}

// A confirmation that takes an optional reason for the audit log.
function ReasonModal({
                         opened,
                         onClose,
                         title,
                         body,
                         placeholder,
                         confirmLabel,
                         reason,
                         onReasonChange,
                         loading,
                         onConfirm,
                     }: {
    opened: boolean;
    onClose: () => void;
    title: string;
    body: ReactNode;
    placeholder: string;
    confirmLabel: string;
    reason: string;
    onReasonChange: (reason: string) => void;
    loading: boolean;
    onConfirm: () => void;
}) {
    return (
        <Modal opened={opened} onClose={onClose} title={title} centered>
            <Stack gap="sm">
                <Text fz="sm">{body}</Text>
                <Textarea
                    label={ALERT_BOARD_STRINGS.reasonLabel}
                    description={ALERT_BOARD_STRINGS.reasonDescription}
                    placeholder={placeholder}
                    autosize
                    minRows={2}
                    value={reason}
                    onChange={(e) => onReasonChange(e.currentTarget.value)}
                />
                <Group justify="flex-end">
                    <Button variant="default" onClick={onClose}>
                        Cancel
                    </Button>
                    <Button color="orange" loading={loading} onClick={onConfirm}>
                        {confirmLabel}
                    </Button>
                </Group>
            </Stack>
        </Modal>
    );
}
