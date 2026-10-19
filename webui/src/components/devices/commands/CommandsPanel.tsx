import {Badge, Box, Button, Group, Stack, Text, Tooltip} from "@mantine/core";
import {IconTerminal2} from "@tabler/icons-react";
import {type CatalogCommand, type Device} from "../../../../lib/api";
import {GlassCard} from "../../ui/GlassCard";
import {ADMIN_ROLE_REASON, CATEGORY_ICONS, KNOWN_FLOWS, reversalBadge, unsupportedReason} from "./command-support";
import {useCommandRunner} from "./use-command-runner";

// The whole command catalog, grouped by category.
export function CommandsPanel({
                                  device, catalog, onDispatched,
                              }: {
    device: Device;
    catalog: CatalogCommand[];
    onDispatched: () => void;
}) {
    const {runOrOpen, busyType, modal} = useCommandRunner(device, onDispatched);
    // Contextual refreshes (device info, profile and app inventory) run from their own tabs instead.
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
                                // A command Apple would reject is greyed out with the reason.
                                const deviceWhy = unsupportedReason(c, device);
                                const why = c.allowed ? deviceWhy : ADMIN_ROLE_REASON;
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
                                        <Box style={{minWidth: 0}}>
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
                                        </Box>
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
