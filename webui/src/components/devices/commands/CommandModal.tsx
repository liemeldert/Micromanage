import {useEffect, useState} from "react";
import {
    Alert,
    Box,
    Button,
    Checkbox,
    Group,
    Modal,
    PasswordInput,
    PinInput,
    Stack,
    Switch,
    Text,
    Textarea,
    TextInput,
} from "@mantine/core";
import {notifications} from "@mantine/notifications";
import {IconAlertTriangle} from "@tabler/icons-react";
import {
    api,
    ApiError,
    type CatalogCommand,
    type CommandConfirmation,
    type Device,
    type DeviceSecret,
} from "../../../../lib/api";
import {devicePlatformCategory} from "../../../../lib/config";
import {commandWarning, isMac, KNOWN_FLOWS, withPushStatus} from "./command-support";
import {EscrowNote} from "./EscrowNote";

// Erase params handled by the tailored Return to Service section, so the generic param loop skips them.
const RTS_PARAMS = new Set(["return_to_service", "wifi_ssid", "wifi_password", "wifi_hidden"]);

// First OS major with Return to Service per platform, mirroring the server. Mac, Apple Watch and unrecognized models
// have no entry.
const RTS_OS_FLOORS: Record<string, number> = {
    "iPhone": 17,
    "iPad": 17,
    "iPod": 17,
    "Apple TV": 18,
    "Apple Vision Pro": 26,
};

// Confirmation for one catalog command, either a tailored flow from KNOWN_FLOWS or a generic parameter form.
export function CommandModal({
                                 device, entry, opened, onClose, onDone,
                             }: {
    device: Device;
    entry: CatalogCommand | null;
    opened: boolean;
    onClose: () => void;
    onDone: () => void;
}) {
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
        if (!opened || !escrowKind) return;
        let live = true;
        api
            .getDeviceSecrets(device.id)
            .then((r) => {
                if (live) setEscrow(r.secrets.find((s) => s.kind === escrowKind) ?? null);
            })
            .catch(() => {
            });
        return () => {
            live = false;
        };
    }, [opened, escrowKind, device.id]);

    if (!entry) return null;
    const flow = KNOWN_FLOWS[entry.type];
    const mac = isMac(device);
    const isRequired = (p: CatalogCommand["params"][number]) => p.required === true || (p.required === "mac" && mac);

    const attrs = (device.attributes ?? {}) as Record<string, unknown>;
    const osMajor = parseInt((device.os_version || "").split(".")[0], 10) || 0;
    // Return to Service needs only the platform's OS floor, not supervision.
    const rtsFloor = RTS_OS_FLOORS[devicePlatformCategory(device.device_model)];
    const rtsEligible = !!flow?.returnToService && rtsFloor !== undefined && osMajor >= rtsFloor;
    const rtsNeedsNewerOs = !!flow?.returnToService && rtsFloor !== undefined && osMajor > 0 && osMajor < rtsFloor;
    const rtsOn = values.return_to_service === "true";
    // Return to Service cannot get past Activation Lock, so a wiped device stops at the activation screen.
    const activationLockOn = attrs.IsActivationLockEnabled === true;
    const warning = commandWarning(entry, device);

    const requiredMissing = entry.params.some(
        (p) => !RTS_PARAMS.has(p.name) && isRequired(p) && !(values[p.name] ?? "").trim(),
    );
    const pinParam = entry.params.find((p) => p.type === "pin");
    const pinInvalid = !!pinParam && !!values[pinParam.name] && !/^\d{6}$/.test(values[pinParam.name]);
    const serialBlocked = !!flow?.serialConfirm && serialText.trim() !== device.serial_number;
    const ackMissing = !!flow?.ackRestart && !acked;
    // A missing Wi-Fi network does not block the send; the server returns it as a confirmable warning.
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
        setBusy(true);
        try {
            const parameters: Record<string, unknown> = {};
            for (const p of entry.params) {
                const v = (values[p.name] ?? "").trim();
                if (v) parameters[p.name] = v;
            }
            if (acknowledge) parameters.acknowledge_warnings = "true";
            const res = await api.sendCommand(device.id, entry.type, parameters);
            // The server's message reports what happened to the escrow.
            notifications.show({
                color: "teal",
                title: `${entry.label} sent to ${device.serial_number}`,
                message: withPushStatus(res, res.message),
            });
            close();
            onDone();
        } catch (e) {
            // A refusal with requires_confirmation becomes the confirm step; anything else is a toast.
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
                        {flow ? (
                            <Alert color={flow.danger ? "red" : "yellow"} variant="light">
                                <Text fz="sm">{entry.description}</Text>
                            </Alert>
                        ) : (
                            <Alert color="orange" variant="light" icon={<IconAlertTriangle size={16}/>}>
                                <Text fz="sm" fw={500}>No guided flow exists for this command yet.</Text>
                                <Text fz="xs" mt={4}>
                                    {entry.description} The fields below are sent to the device exactly as
                                    entered, so double-check them before running.
                                </Text>
                            </Alert>
                        )}

                        {escrowKind && escrow !== undefined && <EscrowNote entry={entry} secret={escrow}/>}

                        {warning && (
                            <Alert color="orange" variant="light" icon={<IconAlertTriangle size={16}/>}>
                                <Text fz="sm">{warning}</Text>
                            </Alert>
                        )}

                        {entry.params.filter((p) => !RTS_PARAMS.has(p.name)).map((p) => {
                            const need = isRequired(p);
                            if (p.type === "pin") {
                                // Only a Mac uses the PIN.
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
                                            mt={4}
                                            style={{justifyContent: "center"}}
                                        />
                                    </Stack>
                                );
                            }
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
                                        // currentTarget is null by the time the state updater runs.
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
                                        const on = e.currentTarget.checked;
                                        setValues((s) => ({...s, return_to_service: on ? "true" : ""}));
                                    }}
                                    label="Re-enroll automatically after wipe (Return to Service)"
                                    description={
                                        "The device wipes, rejoins the Wi-Fi below and comes back enrolled, so " +
                                        "nobody sets it up by hand. Activation Lock has to be off, or it stops at " +
                                        "the activation screen."
                                    }
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
                                            description={
                                                "Needed unless the device can reach the server over Ethernet or " +
                                                "cellular after the wipe. Leaving it blank asks you to confirm " +
                                                "before sending."
                                            }
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
                        {rtsNeedsNewerOs && (
                            <Text fz="xs" c="dimmed">
                                Automatic re-enroll after wipe (Return to Service) needs a newer OS version on this
                                device.
                            </Text>
                        )}

                        {flow?.ackRestart && (
                            <Checkbox
                                checked={acked}
                                onChange={(e) => setAcked(e.currentTarget.checked)}
                                label={
                                    "I understand this Mac restarts now, and that only AppleCare can recover a lost " +
                                    "firmware password."
                                }
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
