import {useMemo, useState} from "react";
import {Badge, Box, Checkbox, Group, ScrollArea, Text, TextInput,} from "@mantine/core";
import {IconSearch} from "@tabler/icons-react";
import type {Device} from "../../../lib/api";

/**
 * Multi-select device list for picking include and exclude cohorts. Searches serial, hostname, managed name and
 * model, and shows the managed name under each serial so a person can recognise the device. The color prop tints the
 * selection: teal for include, red for exclude.
 */
export function DevicePicker({
                                 devices,
                                 value,
                                 onChange,
                                 color = "teal",
                                 emptyHint = "No enrolled devices loaded.",
                             }: {
    devices: Device[];
    value: string[];
    onChange: (serials: string[]) => void;
    color?: string;
    emptyHint?: string;
}) {
    const [q, setQ] = useState("");
    const selected = useMemo(() => new Set(value), [value]);

    const filtered = useMemo(() => {
        const term = q.trim().toLowerCase();
        const list = devices.filter((d) => d.serial_number);
        if (!term) return list;
        return list.filter((d) =>
            `${d.serial_number} ${d.hostname ?? ""} ${d.display_name ?? ""} ${d.device_model ?? ""}`
                .toLowerCase()
                .includes(term),
        );
    }, [devices, q]);

    const toggle = (serial: string) => {
        const next = new Set(selected);
        if (next.has(serial)) next.delete(serial);
        else next.add(serial);
        onChange(Array.from(next));
    };

    // Selected serials with no loaded device, such as a pre-provisioned one. Shown so an edit does not drop them.
    const orphanSerials = value.filter((s) => !devices.some((d) => d.serial_number === s));

    return (
        <Box>
            <TextInput
                size="xs"
                mb={6}
                placeholder="Search serial, hostname, model…"
                leftSection={<IconSearch size={13}/>}
                value={q}
                onChange={(e) => setQ(e.currentTarget.value)}
            />
            <ScrollArea.Autosize mah={200} type="auto">
                <Box style={{
                    border: "1px solid var(--mantine-color-default-border)",
                    borderRadius: "var(--mantine-radius-sm)"
                }}>
                    {filtered.length === 0 && orphanSerials.length === 0 ? (
                        <Text fz="xs" c="dimmed" p="sm">
                            {q ? "No devices match." : emptyHint}
                        </Text>
                    ) : (
                        <>
                            {orphanSerials.map((s) => (
                                <Group key={s} gap="xs" wrap="nowrap" px="sm" py={5} justify="space-between">
                                    <Checkbox
                                        size="xs"
                                        color={color}
                                        checked
                                        onChange={() => toggle(s)}
                                        label={<Text fz="xs" ff="monospace">{s}</Text>}
                                    />
                                    <Badge size="xs" variant="light" color="gray">not loaded</Badge>
                                </Group>
                            ))}
                            {filtered.map((d) => {
                                const on = selected.has(d.serial_number);
                                return (
                                    <Group
                                        key={d.id}
                                        gap="xs"
                                        wrap="nowrap"
                                        px="sm"
                                        py={5}
                                        justify="space-between"
                                        style={{
                                            cursor: "pointer",
                                            background: on ? `var(--mantine-color-${color}-light)` : undefined
                                        }}
                                        onClick={() => toggle(d.serial_number)}
                                    >
                                        <Checkbox
                                            size="xs"
                                            color={color}
                                            checked={on}
                                            readOnly
                                            label={
                                                <Box>
                                                    <Text fz="xs" ff="monospace">{d.serial_number}</Text>
                                                    <Text fz={10} c="dimmed">
                                                        {d.display_name || d.hostname || d.device_model || "--"}
                                                    </Text>
                                                </Box>
                                            }
                                        />
                                    </Group>
                                );
                            })}
                        </>
                    )}
                </Box>
            </ScrollArea.Autosize>
            {value.length > 0 && (
                <Text fz="xs" c="dimmed" mt={4}>
                    {value.length} device{value.length === 1 ? "" : "s"} selected
                </Text>
            )}
        </Box>
    );
}
