import {Badge, Button, Divider, Group, Modal, Stack, Text} from "@mantine/core";
import {IconArrowBackUp, IconArrowRight, IconCheck, IconDeviceLaptop} from "@tabler/icons-react";
import {ALERT_BOARD_STRINGS, CREDENTIAL_REVEAL_STRINGS} from "../../../lib/strings/alerts";
import {type DispatcherAlert, isCredentialRevealAlert} from "../../../lib/api";
import {timeSince} from "../../../lib/time";

export function AlertPeekModal({
                                   alert,
                                   severityColor,
                                   severityLabel,
                                   opened,
                                   onClose,
                                   onAcknowledge,
                                   onResolve,
                                   onOpenDevice,
                               }: {
    alert: DispatcherAlert | null;
    severityColor: string;
    severityLabel: string;
    opened: boolean;
    onClose: () => void;
    onAcknowledge: () => void;
    onResolve: () => void;
    onOpenDevice: () => void;
}) {
    if (!alert) return null;

    const device = alert.device?.display_name || alert.device?.serial_number;
    const needsFullPage = isCredentialRevealAlert(alert);
    const acknowledged = alert.status === "acknowledged";

    return (
        <Modal
            opened={opened}
            onClose={onClose}
            size="md"
            title={
                <Group gap="xs" wrap="nowrap">
                    <Badge size="sm" variant="light" color={severityColor}>
                        {severityLabel}
                    </Badge>
                    <Text fw={600}>{alert.summary}</Text>
                </Group>
            }
        >
            <Stack gap="md">
                <Stack gap={4}>
                    <Text fz="sm">
                        {device ?? ALERT_BOARD_STRINGS.noDevice}
                    </Text>
                    <Text fz="xs" c="dimmed">
                        {[
                            alert.status,
                            alert.opened_at ? `opened ${timeSince(alert.opened_at)}` : null,
                        ].filter(Boolean).join(" · ")}
                    </Text>
                </Stack>

                <Divider/>

                <Group gap="xs" justify="flex-end">
                    <Button
                        variant="default"
                        leftSection={<IconDeviceLaptop size={14}/>}
                        disabled={!alert.device_id}
                        onClick={onOpenDevice}
                    >
                        Open device
                    </Button>
                    <Button
                        variant="light"
                        leftSection={acknowledged ? <IconArrowBackUp size={14}/> : <IconCheck size={14}/>}
                        onClick={onAcknowledge}
                    >
                        {acknowledged ? "Restore" : "Acknowledge"}
                    </Button>
                    <Button
                        color="teal"
                        rightSection={needsFullPage ? <IconArrowRight size={14}/> : undefined}
                        onClick={onResolve}
                    >
                        {needsFullPage ? CREDENTIAL_REVEAL_STRINGS.peekResolve : "Resolve"}
                    </Button>
                </Group>
            </Stack>
        </Modal>
    );
}
