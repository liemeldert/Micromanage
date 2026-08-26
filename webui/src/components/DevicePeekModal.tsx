// Read-only summary of one device, opened by holding or force clicking its row in the list. Everything shown
// comes from the row the list already has, so the modal opens without a request.

import {Badge, Button, Divider, Group, type MantineTransition, Modal, SimpleGrid, Stack, Text} from "@mantine/core";
import {IconArrowRight, IconBrandApple} from "@tabler/icons-react";
import type {Device} from "../../lib/api";
import {timeSince} from "../../lib/time";
import {CopyValue} from "./CopyValue";

function Fact({label, value}: { label: string; value: React.ReactNode }) {
    return (
        <Stack gap={2} style={{minWidth: 0}}>
            <Text fz="xs" c="dimmed" fw={500}>
                {label}
            </Text>
            {typeof value === "string" ? <Text fz="sm" truncate>{value}</Text> : value}
        </Stack>
    );
}

const PEEK_TRANSITION: MantineTransition = {
    common: {transformOrigin: "center"},
    in: {opacity: 1, transform: "scale(1)"},
    out: {opacity: 0, transform: "scale(0.82)"},
    transitionProperty: "transform, opacity",
};

export function DevicePeekModal({
                                    device,
                                    opened,
                                    onClose,
                                    onOpenDevice,
                                    stateLabel,
                                    stateColor,
                                    tagLabel,
                                    tagColor,
                                }: {
    device: Device | null;
    opened: boolean;
    onClose: () => void;
    onOpenDevice: () => void;
    stateLabel: string;
    stateColor: string;
    /** The list owns the tag registry, so labels and colours come from it. */
    tagLabel: (tag: string) => string;
    tagColor: (tag: string) => string | undefined;
}) {
    if (!device) return null;

    const enrolled = device.enrollment_state === "enrolled";
    const polling = device.poll_interval_minutes
        ? `every ${device.poll_interval_minutes} min`
        : "not scheduled";

    return (
        <Modal
            opened={opened}
            onClose={onClose}
            size="lg"
            // A peek should feel like it sprang out of the row that was held. Mantine's own pop starts at 0.9,
            // which on a dialog this size barely moves; this starts it much smaller and the overshoot in the
            // timing function carries it past 1 on the way in.
            transitionProps={{
                transition: PEEK_TRANSITION,
                duration: 260,
                exitDuration: 140,
                timingFunction: "cubic-bezier(0.2, 1.5, 0.35, 1)",
            }}
            classNames={{content: "mm-peek-content"}}
            title={
            <Group gap="xs" wrap="nowrap">
                {device.management_type === "apple_mdm" && <IconBrandApple size={16} style={{opacity: 0.6}}/>}
                <Text fw={600}>{device.display_name || device.serial_number || "Device"}</Text>
                <Badge size="sm" variant="light" color={stateColor}>
                    {stateLabel}
                </Badge>
            </Group>
        }>
            <Stack gap="md">
                <SimpleGrid cols={{base: 2, sm: 3}} spacing="md">
                    <Fact label="Model" value={device.device_model || "--"}/>
                    <Fact label="OS version" value={device.os_version || "--"}/>
                    <Fact
                        label="Last seen"
                        value={enrolled ? timeSince(device.last_seen)
                            : device.unenrolled_at ? `left ${timeSince(device.unenrolled_at)}` : "--"}
                    />
                    <Fact label="Serial" value={<CopyValue value={device.serial_number || "--"} align="start"/>}/>
                    <Fact label="Hostname" value={device.hostname || "--"}/>
                    <Fact label="Enrolled" value={device.enrollment_date ? timeSince(device.enrollment_date) : "--"}/>
                    <Fact label="Check-in" value={polling}/>
                    <Fact
                        label="Last polled"
                        value={device.last_polled_at ? timeSince(device.last_polled_at) : "never"}
                    />
                    <Fact
                        label="UDID"
                        value={device.udid ? <CopyValue value={device.udid} align="start" mono/> : "--"}
                    />
                </SimpleGrid>

                <Divider/>

                <Stack gap={6}>
                    <Text fz="xs" c="dimmed" fw={500}>
                        Groups
                    </Text>
                    <Group gap={4} wrap="wrap">
                        {device.groups.length === 0 ? (
                            <Text fz="sm" c="dimmed">None</Text>
                        ) : device.groups.map((g) => (
                            <Badge key={g} variant="dot" size="sm" color="blue">
                                {g}
                            </Badge>
                        ))}
                    </Group>
                </Stack>

                <Stack gap={6}>
                    <Text fz="xs" c="dimmed" fw={500}>
                        Tags
                    </Text>
                    <Group gap={4} wrap="wrap">
                        {(device.tags ?? []).length === 0 ? (
                            <Text fz="sm" c="dimmed">None</Text>
                        ) : (device.tags ?? []).map((t) => (
                            <Badge key={t} variant="light" size="sm" color={tagColor(t) || "gray"}>
                                {tagLabel(t)}
                            </Badge>
                        ))}
                    </Group>
                </Stack>

                <Group justify="flex-end" gap="xs">
                    <Button variant="default" onClick={onClose}>
                        Close
                    </Button>
                    <Button rightSection={<IconArrowRight size={14}/>} onClick={onOpenDevice}>
                        Open device
                    </Button>
                </Group>
            </Stack>
        </Modal>
    );
}
