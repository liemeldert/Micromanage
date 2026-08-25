// Yes I stole the name from EPIC.

import {useEffect, useState} from "react";
import Link from "next/link";
import {Alert, Anchor, Badge, Button, CopyButton, Group, Loader, Modal, Stack, Text,} from "@mantine/core";
import {IconAlertTriangle, IconCheck, IconCopy, IconLockOpen, IconShieldLock,} from "@tabler/icons-react";
import {api, type DeviceSecret, type RevealedSecret, secretLifecycle} from "../../lib/api";
import {useAuth} from "../../lib/auth-context";
import {GlassShatter} from "./GlassShatter";
import {GlassCard} from "./ui/GlassCard";

function fmt(ts: string | null | undefined): string {
    if (!ts) return "";
    try {
        return new Date(ts).toLocaleString();
    } catch {
        return ts;
    }
}

// What the device has done with a stored password. A value the device never acknowledged opens nothing, and while a
// rotation is still unconfirmed this card hands back the older password.
function SecretState({secret}: { secret: DeviceSecret }) {
    const life = secretLifecycle(secret);
    return (
        <Stack gap={2} mt={2}>
            {life.unconfirmed_task_id && (
                <Text fz="xs" c="red" fw={500}>
                    The device has never acknowledged this password, so it may open nothing.
                    {life.unconfirmed_reason ? ` ${life.unconfirmed_reason}.` : ""}
                </Text>
            )}
            {life.pending_task_id && (
                <Text fz="xs" c="orange" fw={500}>
                    A newer password was sent{life.pending_set_by ? ` by ${life.pending_set_by}` : ""}
                    {life.pending_since ? ` on ${fmt(life.pending_since)}` : ""}. Until the device confirms
                    the change, this card still hands back the one it answers to now.
                </Text>
            )}
            {life.confirmed_at && !life.unconfirmed_task_id && (
                <Text fz="xs" c="dimmed">Confirmed by the device on {fmt(life.confirmed_at)}.</Text>
            )}
            {life.verified_at && (
                <Text fz="xs" c="teal">Last verified against the device on {fmt(life.verified_at)}.</Text>
            )}
            {life.verify_failed_at && (
                <Text fz="xs" c="red" fw={500}>
                    Failed verification on {fmt(life.verify_failed_at)}: it does not open this device.
                </Text>
            )}
        </Stack>
    );
}

// The badge beside the kind, shown when the stored password is not both current and confirmed.
function stateBadge(secret: DeviceSecret) {
    const life = secretLifecycle(secret);
    if (life.unconfirmed_task_id) {
        return <Badge size="xs" variant="light" color="red">never confirmed</Badge>;
    }
    if (life.pending_task_id) {
        return <Badge size="xs" variant="light" color="orange">rotation pending</Badge>;
    }
    return null;
}

export function BreakTheGlassCard({deviceId}: { deviceId: string }) {
    const {token} = useAuth();
    const [secrets, setSecrets] = useState<DeviceSecret[] | null>(null);
    const [loadError, setLoadError] = useState<string | null>(null);
    const [target, setTarget] = useState<DeviceSecret | null>(null); // confirm modal
    const [revealing, setRevealing] = useState(false);
    const [revealed, setRevealed] = useState<RevealedSecret | null>(null);
    // Held between the controller answering and the glass finishing, so the password only appears once
    // the pane it was behind is gone.
    const [pending, setPending] = useState<RevealedSecret | null>(null);
    const [broken, setBroken] = useState(false);
    // Why the last reveal was refused. It stays in the confirm modal rather than a toast, because a refusal runs to
    // several sentences of instructions that a toast would take away after four seconds.
    const [revealError, setRevealError] = useState<string | null>(null);

    const load = () => {
        if (!token) return;
        api
            .getDeviceSecrets(token, deviceId)
            .then((r) => {
                setSecrets(r.secrets);
                setLoadError(null);
            })
            // A failed fetch must not read as an empty list: the error is what separates no recovery credentials
            // from no answer.
            .catch((e) => {
                setSecrets([]);
                setLoadError((e as Error).message);
            });
    };

    useEffect(() => {
        load();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [token, deviceId]);

    const breakGlass = async () => {
        if (!token || !target) return;
        setRevealing(true);
        setRevealError(null);
        try {
            const res = await api.revealDeviceSecret(token, deviceId, target.kind);
            // The password waits here while the glass breaks. A refusal leaves the pane intact.
            setPending(res);
            setBroken(true);
            load(); // refresh the sealed state and reveal count
        } catch (e) {
            // Shown verbatim, because the controller's message carries the instructions.
            setRevealError((e as Error).message);
        } finally {
            setRevealing(false);
        }
    };

    const finishReveal = () => {
        setRevealed(pending);
        setPending(null);
        setTarget(null);
        setBroken(false);
    };

    // A device with no recovery credentials gets an explicit empty state, so the card cannot be mistaken for one
    // that has not loaded.
    const empty = secrets !== null && secrets.length === 0;

    return (
        <GlassCard withBorder p="md">
            <Group justify="space-between" mb="xs">
                <Group gap="xs">
                    <IconShieldLock size={16}/>
                    <Text fz="sm" fw={600}>
                        Recovery credentials
                    </Text>
                    {empty && !loadError && (
                        <Badge size="xs" variant="light" color="gray">
                            none stored
                        </Badge>
                    )}
                </Group>
                {secrets === null && <Loader size="xs"/>}
            </Group>

            {loadError && (
                <Alert color="red" variant="light" icon={<IconAlertTriangle size={16}/>} mb="sm">
                    <Text fz="sm">
                        Couldn&apos;t check whether this device has recovery credentials, so this list may be
                        incomplete. Reload the page to try again.
                    </Text>
                    <Text fz="xs" c="dimmed" mt={4}>
                        {loadError}
                    </Text>
                </Alert>
            )}

            {empty && !loadError && (
                <Stack gap={6}>
                    <Text fz="sm">
                        No recovery credentials are stored for this device. There is nothing to reveal here.
                    </Text>
                    <Text fz="xs" c="dimmed">
                        A recovery credential is stored whenever something sets a password: a{" "}
                        <b>Configure accounts</b> step with a managed admin account, a <b>Set firmware lock</b>{" "}
                        step (Recovery Lock on Apple silicon, firmware password on Intel), or{" "}
                        <b>Set Recovery Lock</b> / <b>Set firmware password</b> run by hand from this device&apos;s{" "}
                        <b>Commands</b> tab. A FileVault recovery key appears here when a Mac reports it after the
                        escrow profile installs, or from <b>Rotate FileVault recovery key</b> on the{" "}
                        <b>Commands</b> tab.
                    </Text>
                    <Anchor component={Link} href="/atc" fz="xs">
                        Open Flows to add one of those steps
                    </Anchor>
                </Stack>
            )}

            <Stack gap="sm">
                {(secrets ?? []).map((s) => (
                    <Group key={s.id} justify="space-between" wrap="nowrap" align="flex-start">
                        <div style={{minWidth: 0}}>
                            <Group gap={6}>
                                <Text fz="sm" fw={500}>
                                    {s.kind_label}
                                </Text>
                                {s.sealed ? (
                                    <Badge size="xs" variant="light" color="gray">
                                        sealed
                                    </Badge>
                                ) : (
                                    <Badge size="xs" variant="light" color="orange">
                                        revealed &times;{s.reveal_count}
                                    </Badge>
                                )}
                                {stateBadge(s)}
                            </Group>
                            {/* The account name or key label, unless it repeats the kind line above. */}
                            {s.label && s.label !== s.kind_label && (
                                <Text fz="xs" c="dimmed">
                                    {s.label}
                                </Text>
                            )}
                            {!s.sealed && (
                                <Text fz="xs" c="dimmed">
                                    Last by {s.revealed_by} at {fmt(s.revealed_at)}
                                </Text>
                            )}
                            <SecretState secret={s}/>
                        </div>
                        <Button
                            size="xs"
                            variant="light"
                            color="orange"
                            leftSection={<IconLockOpen size={14}/>}
                            onClick={() => setTarget(s)}
                        >
                            Reveal
                        </Button>
                    </Group>
                ))}
            </Stack>

            {!empty && (
                <Text fz="xs" c="dimmed" mt="sm">
                    Retrieving a password is logged to the audit trail and raises an alert.
                </Text>
            )}

            {/* Step 1: confirm, spelling out what the reveal costs. */}
            <Modal
                opened={target !== null}
                onClose={() => {
                    setTarget(null);
                    setRevealError(null);
                    setBroken(false);
                    setPending(null);
                }}
                title="Break the glass?"
                centered
            >
                <Stack gap="sm">
                    <GlassShatter broken={broken} onBroken={finishReveal}/>
                    <Alert
                        color="orange"
                        variant="light"
                        icon={<IconAlertTriangle size={16}/>}
                    >
                        You are about to reveal the <b>{target?.kind_label.toLowerCase()}</b>
                        {target?.label ? ` (${target.label})` : ""}. This is recorded against your
                        account and raises an alert on the device. Being on the device may expose you to
                        privileged or classified information. Make sure you are authorized to access it.
                    </Alert>
                    {revealError && (
                        <Alert color="red" variant="light" icon={<IconAlertTriangle size={16}/>}>
                            <Text fz="sm" style={{whiteSpace: "pre-wrap"}}>
                                {revealError}
                            </Text>
                        </Alert>
                    )}
                    <Group justify="flex-end">
                        <Button
                            variant="default"
                            onClick={() => {
                                setTarget(null);
                                setRevealError(null);
                            }}
                            disabled={revealing}
                        >
                            Cancel
                        </Button>
                        <Button color="orange" onClick={breakGlass} loading={revealing}>
                            {revealError ? "Try again" : "Reveal password"}
                        </Button>
                    </Group>
                </Stack>
            </Modal>

            {/* Step 2: the plaintext, shown once. */}
            <Modal
                opened={revealed !== null}
                onClose={() => setRevealed(null)}
                title={revealed?.kind_label ?? "Password"}
                centered
            >
                <Stack gap="sm">
                    <Alert color="orange" variant="light" icon={<IconAlertTriangle size={16}/>}>
                        Shown once. You will raise another alert if you retrieve it again.
                    </Alert>
                    {revealed?.label && (
                        <Text fz="sm">
                            Account / label: <b>{revealed.label}</b>
                        </Text>
                    )}
                    <Group
                        justify="space-between"
                        wrap="nowrap"
                        p="xs"
                        style={{
                            border: "1px solid var(--mantine-color-default-border)",
                            borderRadius: "var(--mantine-radius-sm)",
                            fontFamily: "var(--mantine-font-family-monospace)",
                        }}
                    >
                        <Text fz="sm" style={{wordBreak: "break-all"}}>
                            {revealed?.value}
                        </Text>
                        <CopyButton value={revealed?.value ?? ""}>
                            {({copied, copy}) => (
                                <Button
                                    size="xs"
                                    variant="light"
                                    color={copied ? "teal" : "gray"}
                                    leftSection={
                                        copied ? <IconCheck size={14}/> : <IconCopy size={14}/>
                                    }
                                    onClick={copy}
                                >
                                    {copied ? "Copied" : "Copy"}
                                </Button>
                            )}
                        </CopyButton>
                    </Group>
                    <Group justify="flex-end">
                        <Button variant="default" onClick={() => setRevealed(null)}>
                            Done
                        </Button>
                    </Group>
                </Stack>
            </Modal>
        </GlassCard>
    );
}
