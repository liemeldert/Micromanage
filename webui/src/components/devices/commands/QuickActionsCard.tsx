import {ActionIcon, Box, Button, Divider, Group, Stack, Text, Tooltip} from "@mantine/core";
import {
    IconArrowRight,
    IconEraser,
    IconLock,
    IconLockOpen2,
    IconMapPin,
    IconTerminal2,
    IconVolume,
    IconVolumeOff,
} from "@tabler/icons-react";
import {type CatalogCommand, type Device} from "../../../../lib/api";
import {GlassCard} from "../../ui/GlassCard";
import {ADMIN_ROLE_REASON, CATEGORY_ICONS, isMac, unsupportedReason} from "./command-support";
import {useCommandRunner} from "./use-command-runner";

// Common commands laid out at the top of the card instead of as plain buttons.
const EMERGENCY_TYPES = new Set(["lock", "erase", "enable_lost_mode", "disable_lost_mode", "play_lost_mode_sound"]);

// The catalog's common commands, for the device page's left rail.
export function QuickActionsCard({
                                     device, catalog, onDispatched, onShowAll,
                                 }: {
    device: Device;
    catalog: CatalogCommand[];
    onDispatched: () => void;
    onShowAll: () => void;
}) {
    const {runOrOpen, busyType, modal} = useCommandRunner(device, onDispatched);

    // Lost Mode is supervised iOS only, so Macs and unsupervised devices get no toggle and Ring device stays off.
    const attrs = (device.attributes ?? {}) as Record<string, unknown>;
    const locked = attrs.IsMDMLostModeEnabled === true;
    const lostCapable = attrs.IsSupervised === true && !isMac(device);

    const byType = (t: string) => catalog.find((c) => c.type === t);
    const ringCmd = byType("play_lost_mode_sound");

    const common = catalog.filter((c) => c.common && !c.contextual);
    const emergency = (t: string) => common.find((c) => c.type === t) ?? null;
    const lockCmd = emergency("lock");
    const eraseCmd = emergency("erase");
    // Separate from Lock, so a device already in Lost Mode can still be locked.
    const lostToggle = lostCapable ? byType(locked ? "disable_lost_mode" : "enable_lost_mode") : null;
    const ringDisabled = !lostCapable || !locked || !ringCmd?.allowed;
    const ringLabel = !lostCapable ? "Ring device requires Lost Mode (supervised iPhone or iPad)"
        : !locked ? "Ring device is available once the device is in Lost Mode"
            : !ringCmd?.allowed ? "Ring device requires the admin role"
                : "Play a sound on the device";

    const quick = common.filter((c) => c.allowed && !EMERGENCY_TYPES.has(c.type));

    // Why a command's button is off, or null if it isn't.
    const unavailable = (c: CatalogCommand) => (c.allowed ? unsupportedReason(c, device) : ADMIN_ROLE_REASON);
    const lockWhy = lockCmd && unavailable(lockCmd);
    const eraseWhy = eraseCmd && unavailable(eraseCmd);

    return (
        <GlassCard withBorder p="md" lift="quiet">
            <Text fz="sm" fw={600} mb="sm">Quick actions</Text>
            <Stack gap={6}>
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
                        <Tooltip label={ringLabel} withinPortal>
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
                    <Tooltip label={ADMIN_ROLE_REASON} disabled={lostToggle.allowed} withinPortal>
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
