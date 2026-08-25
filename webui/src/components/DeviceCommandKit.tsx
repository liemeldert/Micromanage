// Device command UI driven by the server's command catalog (GET /api/v1/commands/catalog) rather than a hardcoded
// list. QuickActionsCard renders the catalog's common commands on the device page's left rail, and CommandsPanel
// renders every command grouped by category with the role requirement and device constraints from the catalog.
// Commands named in KNOWN_FLOWS get a tailored confirmation; anything else falls back to a generic modal that
// warns it is a passthrough and renders the fields from params. Descriptive text comes from the catalog entry.

import {useEffect, useState} from "react";
import {
    ActionIcon,
    Alert,
    Badge,
    Box,
    Button,
    Checkbox,
    Divider,
    Group,
    Modal,
    PasswordInput,
    PinInput,
    Stack,
    Switch,
    Text,
    Textarea,
    TextInput,
    Tooltip,
} from "@mantine/core";
import {notifications} from "@mantine/notifications";
import {
    IconAlertTriangle,
    IconArrowRight,
    IconEraser,
    IconLock,
    IconLockOpen2,
    IconMapPin,
    IconPower,
    IconRefresh,
    IconShieldLock,
    IconTerminal2,
    IconUsers,
    IconVolume,
    IconVolumeOff,
} from "@tabler/icons-react";
import {
    api,
    ApiError,
    type CatalogCommand,
    type CommandConfirmation,
    type Device,
    type DeviceSecret,
    secretLifecycle,
} from "../../lib/api";
import {devicePlatformCategory} from "../../lib/config";
import {describeTaskType} from "../../lib/task-errors";
import {useAuth} from "../../lib/auth-context";
import {GlassCard} from "./ui/GlassCard";

// The server reports whether the push reached the device separately from whether the command was stored. A push
// failure only means the device acts at its next check-in, so say that instead of a flat "Command sent".
function withPushStatus(res: { message?: string; result?: { push_failed?: boolean } }, message: string): string {
    return res.result?.push_failed
        ? "Queued; the push failed, the device acts on its next check-in."
        : message;
}

// Commands whose confirmation needs more than a parameter form. The description text comes from the catalog;
// these are the extra behaviours the modal layers on top.
//
//  danger           red alert and red confirm button, for a command that destroys data
//  serialConfirm    the serial number has to be typed before the command can be sent
//  returnToService  the erase modal's re-enroll section
//  escrowKind       the DeviceSecret this command writes or reads, so the modal can name the recovery credential
//                   already stored for this Mac
//  ackRestart       an explicit acknowledgement that the Mac restarts
const KNOWN_FLOWS: Record<
    string,
    {
        danger?: boolean;
        serialConfirm?: boolean;
        returnToService?: boolean;
        escrowKind?: string;
        ackRestart?: boolean;
    }
> = {
    restart: {},
    shutdown: {},
    // Clearing an iOS passcode hands the device back unlocked, so it gets the same red confirm and typed serial
    // as erase.
    clear_passcode: {danger: true, serialConfirm: true},
    clear_restrictions_password: {},
    lock: {},
    enable_lost_mode: {},
    disable_lost_mode: {},
    delete_user: {danger: true},
    erase: {danger: true, serialConfirm: true, returnToService: true},
    rotate_filevault_key: {escrowKind: "filevault_prk"},
    set_recovery_lock: {escrowKind: "recovery_lock"},
    verify_recovery_lock: {escrowKind: "recovery_lock"},
    set_firmware_password: {escrowKind: "firmware_password", danger: true, ackRestart: true},
    verify_firmware_password: {escrowKind: "firmware_password"},
};

// Erase params handled by the tailored Return to Service section, so the generic param loop skips them.
const RTS_PARAMS = new Set(["return_to_service", "wifi_ssid", "wifi_password", "wifi_hidden"]);

// First OS major with Return to Service, per platform, mirroring the server's floors. Mac and Apple Watch never
// get it, so they have no entry here, same as an unrecognized model.
const RTS_OS_FLOORS: Record<string, number> = {
    "iPhone": 17,
    "iPad": 17,
    "iPod": 17,
    "Apple TV": 18,
    "Apple Vision Pro": 26,
};

const CATEGORY_ICONS: Record<string, React.FC<{ size?: number }>> = {
    Queries: IconRefresh,
    Power: IconPower,
    Security: IconShieldLock,
    "Lost Mode": IconMapPin,
    Users: IconUsers,
};

function isMac(device: Device) {
    return (device.device_model || "").toLowerCase().includes("mac");
}

// Why Apple will not run this command on this device, or null if it will. Mirrors the server's own check, down to
// its rule that unknowns pass: a device that has not reported IsSupervised or IsAppleSilicon yet is let through.
// The server enforces this regardless; here it only saves filling in a form for a 400.
function unsupportedReason(entry: CatalogCommand, device: Device): string | null {
    const attrs = (device.attributes ?? {}) as Record<string, unknown>;
    const platform = devicePlatformCategory(device.device_model);
    const platforms = entry.platforms;
    if (platforms?.length && platform !== "Other" && !platforms.includes(platform)) {
        return `Not supported by platform. This device reports as ${platform}.`;
    }
    if (attrs.IsSupervised === false) {
        if (entry.supervised) {
            return `${entry.label} only works on a supervised device.`;
        }
        // Supervision is required per platform for the same command (Restart on iOS and tvOS but not macOS), so
        // the refusal names the platform it applies to.
        if (entry.supervised_platforms?.includes(platform)) {
            return `${entry.label} only works on a supervised ${platform}.`;
        }
    }
    // Both sides have to be a real boolean: an unconstrained catalog entry and a device that never reported its
    // architecture are both silence, not grounds for refusing.
    const wants = entry.apple_silicon;
    const has = attrs.IsAppleSilicon;
    if (typeof wants === "boolean" && typeof has === "boolean" && wants !== has) {
        return (
            `${entry.label} is an ${wants ? "Apple silicon" : "Intel"} command. ` +
            `This Mac reports as ${has ? "Apple silicon" : "Intel"}.`
        );
    }
    return null;
}

// One-word verdict beside a command's label; the full sentence is the catalog description.
function reversalBadge(entry: CatalogCommand) {
    if (entry.reversible === false) {
        return <Badge size="xs" color="red" variant="light">permanent</Badge>;
    }
    if (entry.reversible === true) {
        return <Badge size="xs" color="gray" variant="light">reversible</Badge>;
    }
    return null;
}

// A small "Refresh" button for a specific contextual command, shown on the tab it populates
// (and in the header) so it isn't buried in the commands menu.
export function RefreshButton({
                                  device,
                                  catalog,
                                  commandType,
                                  label,
                                  size = "xs",
                                  variant = "light",
                                  disabled = false,
                                  onDispatched,
                              }: {
    device: Device;
    catalog: CatalogCommand[];
    commandType: string;
    label?: string;
    size?: string;
    variant?: string;
    disabled?: boolean;
    onDispatched: () => void;
}) {
    const {token} = useAuth();
    const [busy, setBusy] = useState(false);
    const entry = catalog.find((c) => c.type === commandType);
    if (!entry) return null;

    const run = async () => {
        if (!token) return;
        setBusy(true);
        try {
            const res = await api.sendCommand(token, device.id, commandType, {});
            notifications.show({
                color: "teal",
                message: withPushStatus(res, `${entry.label} requested. Updates when the device responds.`),
            });
            onDispatched();
        } catch (e) {
            notifications.show({color: "red", title: "Command failed", message: (e as Error).message});
        } finally {
            setBusy(false);
        }
    };

    return (
        <Button size={size} variant={variant} leftSection={<IconRefresh size={14}/>}
                loading={busy} disabled={disabled} onClick={run}>
            {label ?? "Refresh"}
        </Button>
    );
}

// created_by is an actor slug (mdm:<command type>, admin:<email>, atc:<flow>). The machine actors that write
// escrows get a display name and anything else is shown as stored. mdm:security_info means the escrow profile:
// the Mac reports the key in a SecurityInfo answer once that profile installs.
function escrowActorText(createdBy: string, entry: CatalogCommand): string {
    if (createdBy === "mdm:security_info") return "the escrow profile";
    if (createdBy.startsWith("mdm:")) {
        const type = createdBy.slice("mdm:".length);
        return `the ${type === entry.type ? entry.label : describeTaskType(type)} command`;
    }
    return createdBy;
}

// Which recovery credential is already escrowed for this Mac, shown inside the lock-command modals so the form
// can say whether leaving "Current password" blank will work. Best-effort: a failed lookup stays quiet.
function EscrowNote({entry, secret}: { entry: CatalogCommand; secret: DeviceSecret | null }) {
    const setting = entry.type.startsWith("set_");
    // FileVault rotation is neither a set_ nor a verify_ command: the field holds the Mac's CURRENT personal
    // recovery key (a user password fails over MDM), and a fresh key is minted and escrowed.
    const rotating = entry.type === "rotate_filevault_key";
    if (secret === null) {
        return (
            <Alert color="blue" variant="light">
                <Text fz="xs">
                    {rotating
                        ? "No FileVault recovery key is escrowed for this Mac yet. Enter its current " +
                        "recovery key below if somebody holds it; the new key is escrowed and read " +
                        "back through break-glass. If nobody holds the current key, rotate once on " +
                        "the Mac itself (sudo fdesetup changerecovery -personal) and the escrow " +
                        "profile reports the new key here on the next security refresh."
                        : setting
                            ? "Nothing is escrowed for this Mac yet. The password you set below becomes the " +
                            "escrowed copy, and you read it back by breaking the glass on the Summary " +
                            "or Security tab. " +
                            "Leave Current password blank unless somebody set a lock on this Mac outside " +
                            "Micromanage."
                            : "Nothing is escrowed for this Mac, so a blank field has nothing to check. " +
                            "Type the password you want to verify."}
                </Text>
            </Alert>
        );
    }
    const life = secretLifecycle(secret);
    const when = (ts?: string) => (ts ? new Date(ts).toLocaleString() : "");
    return (
        <Alert color={life.pending_task_id || life.unconfirmed_task_id ? "orange" : "blue"} variant="light">
            <Stack gap={4}>
                <Text fz="xs">
                    {/* Lowercased mid-sentence, except FileVault, which is a brand name. */}
                    Micromanage holds a {secret.kind_label.startsWith("FileVault")
                    ? secret.kind_label
                    : secret.kind_label.toLowerCase()} for this Mac
                    {secret.created_by ? `, set by ${escrowActorText(secret.created_by, entry)}` : ""}
                    {secret.updated_at ? ` on ${when(secret.updated_at)}` : ""}.{" "}
                    {rotating
                        ? "Leave the field blank to unlock the rotation with it; the new key replaces " +
                        "it in escrow."
                        : setting ? "Leave Current password blank to use it." : "Leave the field blank to check it."}
                </Text>
                {life.pending_task_id && (
                    <Text fz="xs" fw={500}>
                        A change is already in progress. A device rejects subsequent commands until it responds to the
                        first one.
                    </Text>
                )}
                {life.unconfirmed_task_id && (
                    <Text fz="xs" fw={500}>
                        The Mac has never acknowledged that password, so it may open nothing.
                        {life.unconfirmed_reason ? ` ${life.unconfirmed_reason}.` : ""}
                    </Text>
                )}
                {life.verified_at &&
                    <Text fz="xs" c="dimmed">Last verified against the Mac on {when(life.verified_at)}.</Text>}
                {life.verify_failed_at && (
                    <Text fz="xs" fw={500}>
                        It failed verification on {when(life.verify_failed_at)}, so it does not open this Mac.
                    </Text>
                )}
            </Stack>
        </Alert>
    );
}

//  The modal (custom or generic, decided by the catalog entry)
function CommandModal({
                          device, entry, opened, onClose, onDone,
                      }: {
    device: Device;
    entry: CatalogCommand | null;
    opened: boolean;
    onClose: () => void;
    onDone: () => void;
}) {
    const {token} = useAuth();
    const [values, setValues] = useState<Record<string, string>>({});
    const [serialText, setSerialText] = useState("");
    const [acked, setAcked] = useState(false);
    const [busy, setBusy] = useState(false);
    // undefined = not looked up (or the lookup failed); null = nothing escrowed.
    const [escrow, setEscrow] = useState<DeviceSecret | null | undefined>(undefined);
    // Set when a send came back refused but confirmable (Return to Service with no Wi-Fi network, or a device
    // reporting Activation Lock). Non-null swaps the form for a plain confirm step.
    const [confirmDetail, setConfirmDetail] = useState<CommandConfirmation | null>(null);

    const escrowKind = entry ? KNOWN_FLOWS[entry.type]?.escrowKind : undefined;
    useEffect(() => {
        setEscrow(undefined);
        if (!opened || !escrowKind || !token) return;
        let live = true;
        api
            .getDeviceSecrets(token, device.id)
            .then((r) => {
                if (live) setEscrow(r.secrets.find((s) => s.kind === escrowKind) ?? null);
            })
            .catch(() => { /* best-effort: the form still works without it */
            });
        return () => {
            live = false;
        };
    }, [opened, escrowKind, token, device.id]);

    if (!entry) return null;
    const flow = KNOWN_FLOWS[entry.type];
    const mac = isMac(device);

    const attrs = (device.attributes ?? {}) as Record<string, unknown>;
    const osMajor = parseInt((device.os_version || "").split(".")[0], 10) || 0;
    // Return to Service eligibility: no supervision requirement, just the platform's OS floor. Keyed by
    // devicePlatformCategory rather than a second model-prefix table.
    const platformCategory = devicePlatformCategory(device.device_model);
    const rtsFloor = RTS_OS_FLOORS[platformCategory];
    const rtsEligible = !!flow?.returnToService && rtsFloor !== undefined && osMajor >= rtsFloor;
    const rtsOn = values.return_to_service === "true";
    // A wiped device stops at the activation screen if Activation Lock is still on, since Return to Service
    // cannot get past it to re-enroll.
    const activationLockOn = attrs.IsActivationLockEnabled === true;

    const requiredMissing = entry.params.some((p) => {
        if (RTS_PARAMS.has(p.name)) return false; // validated separately below
        const need = p.required === true || (p.required === "mac" && mac);
        return need && !(values[p.name] ?? "").trim();
    });
    const pinParam = entry.params.find((p) => p.type === "pin");
    const pinInvalid = !!pinParam && !!values[pinParam.name] && !/^\d{6}$/.test(values[pinParam.name]);
    const serialBlocked = !!flow?.serialConfirm && serialText.trim() !== device.serial_number;
    const ackMissing = !!flow?.ackRestart && !acked;
    // A missing Wi-Fi network warns and never blocks: Apple only requires it when the device has no Ethernet or
    // cellular after the wipe. The server returns it as a confirmable warning, same as Activation Lock.
    const canSubmit = !requiredMissing && !pinInvalid && !serialBlocked && !ackMissing;

    const close = () => {
        setValues({});
        setSerialText("");
        setAcked(false);
        setConfirmDetail(null);
        onClose();
    };

    // acknowledge re-sends the same parameters plus acknowledge_warnings, after the confirm step.
    const submit = async (acknowledge = false) => {
        if (!token) return;
        setBusy(true);
        try {
            const parameters: Record<string, unknown> = {};
            for (const p of entry.params) {
                const v = (values[p.name] ?? "").trim();
                if (v) parameters[p.name] = v;
            }
            if (acknowledge) parameters.acknowledge_warnings = "true";
            const res = await api.sendCommand(token, device.id, entry.type, parameters);
            // The server is the only side that knows what happened to the escrow, so its own message is shown
            // rather than one guessed at here.
            notifications.show({
                color: "teal",
                title: `${entry.label} sent to ${device.serial_number}`,
                message: withPushStatus(res, res.message),
            });
            close();
            onDone();
        } catch (e) {
            // A confirmable refusal swaps the form for a confirm step instead of a red toast. A hard refusal
            // carries no requires_confirmation and falls through to the ordinary error.
            const detail = e instanceof ApiError ? e.detail : undefined;
            if (detail && typeof detail === "object" && (detail as CommandConfirmation).requires_confirmation) {
                setConfirmDetail(detail as CommandConfirmation);
                return;
            }
            notifications.show({color: "red", title: "Command failed", message: (e as Error).message});
        } finally {
            setBusy(false);
        }
    };

    return (
        <Modal
            opened={opened}
            onClose={close}
            title={
                <Group gap="xs">
                    {(flow?.danger || entry.destructive) && (
                        <IconAlertTriangle size={18}
                                           color={`var(--mantine-color-${flow?.danger ? "red" : "yellow"}-6)`}/>
                    )}
                    <Text fw={600}>{entry.label} &middot; {device.serial_number}</Text>
                </Group>
            }
        >
            <Stack gap="md">
                {confirmDetail ? (
                    // The server refused this send but will take a repeat with the warnings acknowledged.
                    <>
                        <Alert color="orange" variant="light" icon={<IconAlertTriangle size={16}/>}
                               title="Confirm before sending">
                            <Stack gap={6}>
                                {confirmDetail.warnings.map((w, i) => (
                                    <Text key={confirmDetail.warning_codes[i] ?? i} fz="sm">{w}</Text>
                                ))}
                            </Stack>
                        </Alert>
                        <Group justify="flex-end" gap="sm">
                            <Button variant="subtle" color="gray" onClick={() => setConfirmDetail(null)}>
                                Go back
                            </Button>
                            <Button color="orange" loading={busy} onClick={() => submit(true)}>
                                Proceed anyway
                            </Button>
                        </Group>
                    </>
                ) : (
                    <>
                        {/* The description text comes from the catalog entry. */}
                        {flow ? (
                            <Alert color={flow.danger ? "red" : "yellow"} variant="light">
                                <Text fz="sm">{entry.description}</Text>
                            </Alert>
                        ) : (
                            // No tailored flow for this command yet, so be explicit that the
                            // fields below go to the device untouched.
                            <Alert color="orange" variant="light" icon={<IconAlertTriangle size={16}/>}>
                                <Text fz="sm" fw={500}>No guided flow exists for this command yet.</Text>
                                <Text fz="xs" mt={4}>
                                    {entry.description} The fields below are sent to the device exactly as
                                    entered, so double-check them before running.
                                </Text>
                            </Alert>
                        )}

                        {escrowKind && escrow !== undefined && <EscrowNote entry={entry} secret={escrow}/>}

                        {entry.params.filter((p) => !RTS_PARAMS.has(p.name)).map((p) => {
                            const need = p.required === true || (p.required === "mac" && mac);
                            if (p.type === "pin") {
                                // Macs require the PIN; skip the field entirely on non-Macs unless required.
                                if (!need && !mac) return null;
                                return (
                                    <Stack key={p.name} gap={4}>
                                        <Text fz="sm" fw={500}>{p.label}{need ? "" : " (optional)"}</Text>
                                        {p.help && <Text fz="xs" c="dimmed">{p.help}</Text>}
                                        <PinInput
                                            length={6}
                                            type="number"
                                            value={values[p.name] ?? ""}
                                            onChange={(v) => setValues((s) => ({...s, [p.name]: v}))}
                                            oneTimeCode={false}
                                        />
                                    </Stack>
                                );
                            }
                            // Secret params (passwords) render masked; free text as textarea; else input.
                            const Field = p.secret ? PasswordInput : p.type === "text" ? Textarea : TextInput;
                            return (
                                <Field
                                    key={p.name}
                                    label={`${p.label}${need ? "" : " (optional)"}`}
                                    description={p.help}
                                    required={need}
                                    autoComplete={p.secret ? "new-password" : undefined}
                                    value={values[p.name] ?? ""}
                                    onChange={(e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
                                        // Read the value before the state updater runs. React recycles
                                        // the synthetic event, so e.currentTarget is null inside it.
                                        const v = e.currentTarget.value;
                                        setValues((s) => ({...s, [p.name]: v}));
                                    }}
                                />
                            );
                        })}

                        {flow?.returnToService && rtsEligible && (
                            <Box style={{borderTop: "1px solid var(--mantine-color-default-border)", paddingTop: 12}}>
                                <Switch
                                    checked={rtsOn}
                                    onChange={(e) => {
                                        // Read before the updater; React recycles the synthetic event.
                                        const on = e.currentTarget.checked;
                                        setValues((s) => ({...s, return_to_service: on ? "true" : ""}));
                                    }}
                                    label="Re-enroll automatically after wipe (Return to Service)"
                                    description="The device wipes, rejoins the Wi-Fi below and comes back enrolled, so nobody sets it up by hand. Activation Lock has to be off, or it stops at the activation screen."
                                />
                                {rtsOn && activationLockOn && (
                                    <Alert color="orange" variant="light" icon={<IconAlertTriangle size={16}/>} mt="sm">
                                        <Text fz="sm">
                                            Activation Lock is on for this device. Apple requires it to be off for
                                            Return to Service to re-enroll automatically after the wipe; otherwise the
                                            device stops at the activation screen and needs to be unlocked by hand.
                                        </Text>
                                    </Alert>
                                )}
                                {rtsOn && (
                                    <Stack gap="xs" mt="sm" pl="md"
                                           style={{borderLeft: "2px solid var(--mantine-color-blue-3)"}}>
                                        <TextInput
                                            label="Wi-Fi network (SSID)"
                                            description="Needed unless the device can reach the server over Ethernet or cellular after the wipe. Leaving it blank asks you to confirm before sending."
                                            value={values.wifi_ssid ?? ""}
                                            onChange={(e) => {
                                                const v = e.currentTarget.value;
                                                setValues((s) => ({...s, wifi_ssid: v}));
                                            }}
                                        />
                                        <PasswordInput
                                            label="Wi-Fi password"
                                            description="Leave blank for an open network."
                                            autoComplete="new-password"
                                            value={values.wifi_password ?? ""}
                                            onChange={(e) => {
                                                const v = e.currentTarget.value;
                                                setValues((s) => ({...s, wifi_password: v}));
                                            }}
                                        />
                                        <Switch
                                            checked={values.wifi_hidden === "true"}
                                            onChange={(e) => {
                                                const on = e.currentTarget.checked;
                                                setValues((s) => ({...s, wifi_hidden: on ? "true" : ""}));
                                            }}
                                            label="Hidden network"
                                        />
                                    </Stack>
                                )}
                            </Box>
                        )}
                        {flow?.returnToService && !rtsEligible && rtsFloor !== undefined && osMajor > 0 && osMajor < rtsFloor && (
                            <Text fz="xs" c="dimmed">
                                Automatic re-enroll after wipe (Return to Service) needs a newer OS version on this
                                device.
                            </Text>
                        )}

                        {/* A firmware password restarts the Mac immediately, and only AppleCare can recover a
            lost one, so it gets its own acknowledgement. */}
                        {flow?.ackRestart && (
                            <Checkbox
                                checked={acked}
                                onChange={(e) => {
                                    const on = e.currentTarget.checked;
                                    setAcked(on);
                                }}
                                label="I understand this Mac restarts now, and that only AppleCare can recover a lost firmware password."
                            />
                        )}

                        {flow?.serialConfirm && (
                            <TextInput
                                label={`Type the serial number to confirm: ${device.serial_number}`}
                                placeholder={device.serial_number}
                                value={serialText}
                                onChange={(e) => setSerialText(e.currentTarget.value)}
                                error={serialText && serialBlocked ? "Doesn't match" : null}
                            />
                        )}

                        <Group justify="flex-end" gap="sm">
                            <Button variant="subtle" color="gray" onClick={close}>Cancel</Button>
                            <Button
                                color={flow?.danger ? "red" : "blue"}
                                disabled={!canSubmit}
                                loading={busy}
                                onClick={() => submit()}
                            >
                                {entry.label}
                            </Button>
                        </Group>
                    </>
                )}
            </Stack>
        </Modal>
    );
}

//  Shared runner hook: sends simple commands directly, opens a modal for the rest
function useCommandRunner(device: Device, onDispatched: () => void) {
    const {token} = useAuth();
    const [modalEntry, setModalEntry] = useState<CatalogCommand | null>(null);
    const [busyType, setBusyType] = useState<string | null>(null);

    const runOrOpen = async (entry: CatalogCommand) => {
        // Plain refreshes go straight out; anything destructive or parameterized goes through a modal.
        if (!entry.destructive && entry.params.length === 0) {
            if (!token) return;
            setBusyType(entry.type);
            try {
                const res = await api.sendCommand(token, device.id, entry.type, {});
                notifications.show({
                    color: "teal",
                    message: withPushStatus(res, `${entry.label} sent to ${device.serial_number}`),
                });
                onDispatched();
            } catch (e) {
                notifications.show({color: "red", title: "Command failed", message: (e as Error).message});
            } finally {
                setBusyType(null);
            }
            return;
        }
        setModalEntry(entry);
    };

    const modal = (
        <CommandModal
            device={device}
            entry={modalEntry}
            opened={modalEntry !== null}
            onClose={() => setModalEntry(null)}
            onDone={onDispatched}
        />
    );

    return {runOrOpen, busyType, modal};
}

//  Quick actions (left rail)
export function QuickActionsCard({
                                     device, catalog, onDispatched, onShowAll,
                                 }: {
    device: Device;
    catalog: CatalogCommand[];
    onDispatched: () => void;
    onShowAll: () => void;
}) {
    const {runOrOpen, busyType, modal} = useCommandRunner(device, onDispatched);

    // Lost Mode state comes from the device's own IsMDMLostModeEnabled. It is supervised iOS only, so Macs and
    // unsupervised devices never get the toggle and the ring stays disabled.
    const attrs = (device.attributes ?? {}) as Record<string, unknown>;
    const locked = attrs.IsMDMLostModeEnabled === true;
    const supervised = attrs.IsSupervised === true;
    const isMac = (device.device_model || "").toLowerCase().includes("mac");
    const lostCapable = supervised && !isMac;

    const byType = (t: string) => catalog.find((c) => c.type === t);
    const ringCmd = byType("play_lost_mode_sound");

    // Quick actions are the catalog's common commands, and the block below is only a layout for a few of them.
    // Lock and erase appear here because the catalog marks them common, and both keep their full confirmation.
    const EMERGENCY_TYPES = new Set(["lock", "erase", "enable_lost_mode", "disable_lost_mode", "play_lost_mode_sound"]);
    const common = catalog.filter((c) => c.common && !c.contextual);
    const emergency = (t: string) => common.find((c) => c.type === t) ?? null;
    const lockCmd = emergency("lock");
    const eraseCmd = emergency("erase");
    // The Lost Mode toggle runs whichever command the reported state calls for. It stays separate from Lock so a
    // device already in Lost Mode can still be locked.
    const lostToggle = lostCapable ? byType(locked ? "disable_lost_mode" : "enable_lost_mode") : null;
    const ringDisabled = !lostCapable || !locked || !ringCmd?.allowed;

    const quick = common.filter((c) => c.allowed && !EMERGENCY_TYPES.has(c.type));

    // Why a command's button is off, or null if it isn't. The role check comes before the device check.
    const unavailable = (c: CatalogCommand) =>
        (!c.allowed ? "Requires the admin role" : unsupportedReason(c, device));
    const lockWhy = lockCmd && unavailable(lockCmd);
    const eraseWhy = eraseCmd && unavailable(eraseCmd);

    return (
        <GlassCard withBorder p="md">
            <Text fz="sm" fw={600} mb="sm">Quick actions</Text>
            <Stack gap={6}>
                {/*{(lockCmd || eraseCmd || lostToggle) && (*/}
                {/*    <Text fz={10} fw={700} c="dimmed" tt="uppercase" mb={2} style={{letterSpacing: 0.5}}>*/}
                {/*        If the device is lost or stolen*/}
                {/*    </Text>*/}
                {/*)}*/}
                {lockCmd && (
                    <Group gap={6} wrap="nowrap">
                        <Tooltip label={lockWhy ?? ""} disabled={!lockWhy} withinPortal>
                            <Box style={{flex: 1, display: "flex"}}>
                                <Button
                                    variant="light"
                                    color="orange"
                                    justify="flex-start"
                                    leftSection={<IconLock size={14}/>}
                                    disabled={!!lockWhy}
                                    loading={busyType === "lock"}
                                    onClick={() => runOrOpen(lockCmd)}
                                    fullWidth
                                >
                                    {lockCmd.label}
                                </Button>
                            </Box>
                        </Tooltip>
                        <Tooltip
                            label={
                                !lostCapable ? "Ring device requires Lost Mode (supervised iPhone or iPad)"
                                    : !locked ? "Ring device is available once the device is in Lost Mode"
                                        : !ringCmd?.allowed ? "Ring device requires the admin role"
                                            : "Play a sound on the device"
                            }
                            withinPortal
                        >
                            <Box style={{display: "flex"}}>
                                <ActionIcon
                                    variant="light"
                                    color="blue"
                                    size={36}
                                    disabled={ringDisabled}
                                    loading={busyType === "play_lost_mode_sound"}
                                    onClick={() => ringCmd && runOrOpen(ringCmd)}
                                    aria-label="Ring device"
                                >
                                    {ringDisabled ? <IconVolumeOff size={17}/> : <IconVolume size={17}/>}
                                </ActionIcon>
                            </Box>
                        </Tooltip>
                    </Group>
                )}
                {lostToggle && (
                    <Tooltip label="Requires the admin role" disabled={lostToggle.allowed} withinPortal>
                        <Box style={{display: "flex"}}>
                            <Button
                                variant="light"
                                color={locked ? "blue" : "orange"}
                                justify="flex-start"
                                leftSection={locked ? <IconLockOpen2 size={14}/> : <IconMapPin size={14}/>}
                                disabled={!lostToggle.allowed}
                                onClick={() => runOrOpen(lostToggle)}
                                fullWidth
                            >
                                {locked ? "Disable Lost Mode" : "Enable Lost Mode"}
                            </Button>
                        </Box>
                    </Tooltip>
                )}
                {eraseCmd && (
                    <Tooltip label={eraseWhy ?? ""} disabled={!eraseWhy} withinPortal>
                        <Box style={{display: "flex"}}>
                            <Button
                                variant="light"
                                color="red"
                                justify="flex-start"
                                leftSection={<IconEraser size={14}/>}
                                disabled={!!eraseWhy}
                                onClick={() => runOrOpen(eraseCmd)}
                                fullWidth
                            >
                                {eraseCmd.label}
                            </Button>
                        </Box>
                    </Tooltip>
                )}
                {quick.length > 0 && (lockCmd || eraseCmd || lostToggle) && <Divider my={4}/>}
                {quick.map((c) => {
                    const Icon = CATEGORY_ICONS[c.category] ?? IconTerminal2;
                    const why = unsupportedReason(c, device);
                    return (
                        <Tooltip key={c.type} label={why ?? ""} disabled={!why} withinPortal multiline w={260}>
                            <Box style={{display: "flex"}}>
                                <Button
                                    variant="light"
                                    color={c.destructive ? "orange" : "blue"}
                                    justify="flex-start"
                                    leftSection={<Icon size={14}/>}
                                    disabled={!!why}
                                    loading={busyType === c.type}
                                    onClick={() => runOrOpen(c)}
                                    fullWidth
                                >
                                    {c.label}
                                </Button>
                            </Box>
                        </Tooltip>
                    );
                })}
                <Button
                    variant="subtle"
                    color="gray"
                    justify="flex-start"
                    rightSection={<IconArrowRight size={14}/>}
                    onClick={onShowAll}
                    fullWidth
                >
                    All commands
                </Button>
            </Stack>
            {modal}
        </GlassCard>
    );
}

//  Full catalog, grouped by category
export function CommandsPanel({
                                  device, catalog, onDispatched,
                              }: {
    device: Device;
    catalog: CatalogCommand[];
    onDispatched: () => void;
}) {
    const {runOrOpen, busyType, modal} = useCommandRunner(device, onDispatched);
    // Contextual refreshes (device info, profile/app inventory) belong on their own tabs, so
    // the command menu leaves them out.
    const menu = catalog.filter((c) => !c.contextual);
    const categories = Array.from(new Set(menu.map((c) => c.category)));

    return (
        <Stack gap="lg">
            {categories.map((cat) => {
                const Icon = CATEGORY_ICONS[cat] ?? IconTerminal2;
                return (
                    <GlassCard key={cat} withBorder p="md">
                        <Group gap="xs" mb="sm">
                            <Icon size={16}/>
                            <Text fz="sm" fw={600}>{cat}</Text>
                        </Group>
                        <Stack gap="xs">
                            {menu.filter((c) => c.category === cat).map((c) => {
                                // Role first, then what this device can run. A command Apple would reject is
                                // greyed out with the reason.
                                const roleWhy = c.allowed ? null : "Requires the admin role";
                                const deviceWhy = unsupportedReason(c, device);
                                const why = roleWhy ?? deviceWhy;
                                return (
                                    <Group
                                        key={c.type}
                                        justify="space-between"
                                        wrap="nowrap"
                                        p="sm"
                                        style={{
                                            border: "1px solid var(--mantine-color-default-border)",
                                            borderRadius: "var(--mantine-radius-sm)",
                                            opacity: deviceWhy ? 0.55 : 1,
                                        }}
                                    >
                                        <div style={{minWidth: 0}}>
                                            <Group gap={8}>
                                                <Text fz="sm" fw={500}>{c.label}</Text>
                                                {c.destructive &&
                                                    <Badge size="xs" color="red" variant="light">admin</Badge>}
                                                {reversalBadge(c)}
                                                {!KNOWN_FLOWS[c.type] && (c.destructive || c.params.length > 0) && (
                                                    <Badge size="xs" color="orange" variant="light">generic form</Badge>
                                                )}
                                            </Group>
                                            <Text fz="xs" c="dimmed">{c.description}</Text>
                                            {deviceWhy && (
                                                <Text fz="xs" c="orange" fw={500} mt={2}>{deviceWhy}</Text>
                                            )}
                                        </div>
                                        <Tooltip label={why ?? ""} disabled={!why} multiline w={260}>
                                            <Box style={{display: "flex"}}>
                                                <Button
                                                    size="xs"
                                                    variant="light"
                                                    color={c.destructive ? "red" : "blue"}
                                                    disabled={!!why}
                                                    loading={busyType === c.type}
                                                    onClick={() => runOrOpen(c)}
                                                >
                                                    Run
                                                </Button>
                                            </Box>
                                        </Tooltip>
                                    </Group>
                                );
                            })}
                        </Stack>
                    </GlassCard>
                );
            })}
            {modal}
        </Stack>
    );
}
