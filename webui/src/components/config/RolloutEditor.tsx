import {useState} from "react";
import {Alert, Group, NumberInput, Progress, SegmentedControl, Stack, Switch, Text,} from "@mantine/core";
import {IconInfoCircle} from "@tabler/icons-react";
import {type Rollout} from "../../../lib/config";

/**
 * Editor for a wave-based rollout: every interval another percentage of scoped devices becomes
 * eligible, with an option to skip weekends. Shows the projected schedule.
 */
export function RolloutEditor({
                                  rollout,
                                  onChange,
                              }: {
    rollout: Rollout | undefined;
    onChange: (next: Rollout | undefined) => void;
}) {
    const enabled = !!rollout;
    const r: Rollout = rollout ?? {percent: 25, interval_hours: 24, skip_weekends: false};

    // Custom is sticky: at 24h or 168h the value alone reads as Day or Week, so the hours field
    // would never stay open.
    const [customChosen, setCustomChosen] = useState(false);
    const intervalPreset = customChosen
        ? "custom"
        : r.interval_hours === 24
            ? "day"
            : r.interval_hours === 168
                ? "week"
                : "custom";

    // Projected from a fresh start; the server stamps the real one on save. Stops at the first
    // wave that reaches 100%.
    const waves: { pct: number; hoursFromStart: number }[] = [];
    {
        const step = Math.max(1, Math.trunc(r.percent || 1));
        let pct = 0;
        let wave = 0;
        while (pct < 100 && wave < 40) {
            pct = Math.min(100, step * (wave + 1));
            waves.push({pct, hoursFromStart: wave * (r.interval_hours || 24)});
            wave += 1;
        }
    }

    return (
        <Stack gap="sm">
            <Switch
                checked={enabled}
                onChange={(e) =>
                    onChange(e.currentTarget.checked ? r : undefined)
                }
                label="Roll out gradually"
                description="Release to a fraction of scoped devices at a time instead of all at once."
            />

            {enabled && (
                <Stack gap="sm" pl="md" style={{borderLeft: "2px solid var(--mantine-color-blue-3)"}}>
                    <Group gap="md" align="flex-end" wrap="wrap">
                        <NumberInput
                            label="Wave size"
                            description="% of devices per step"
                            w={140}
                            min={1}
                            max={100}
                            suffix="%"
                            value={r.percent}
                            onChange={(v) => onChange({...r, percent: clampPct(v)})}
                        />
                        <Stack gap={2}>
                            <Text fz="sm" fw={500}>Every</Text>
                            <SegmentedControl
                                size="xs"
                                value={intervalPreset}
                                onChange={(v) => {
                                    setCustomChosen(v === "custom");
                                    // Custom keeps the current value and reveals the field.
                                    if (v === "day") onChange({...r, interval_hours: 24});
                                    else if (v === "week") onChange({...r, interval_hours: 168});
                                }}
                                data={[
                                    {label: "Day", value: "day"},
                                    {label: "Week", value: "week"},
                                    {label: "Custom", value: "custom"},
                                ]}
                            />
                        </Stack>
                        {intervalPreset === "custom" && (
                            <NumberInput
                                label="Interval (hours)"
                                w={150}
                                min={1}
                                value={r.interval_hours}
                                onChange={(v) => onChange({...r, interval_hours: Math.max(1, Number(v) || 24)})}
                            />
                        )}
                    </Group>

                    <Switch
                        checked={!!r.skip_weekends}
                        onChange={(e) => onChange({...r, skip_weekends: e.currentTarget.checked})}
                        label="Skip weekends"
                        description="Don't advance to a new wave on Saturday or Sunday (UTC)."
                    />

                    <Stack gap={4}>
                        <Text fz="xs" fw={600} c="dimmed">
                            Wave schedule (from the moment you save)
                        </Text>
                        {waves.map((w, i) => (
                            <Group key={i} gap="sm" wrap="nowrap">
                                <Text fz="xs" c="dimmed" w={110}>
                                    {w.hoursFromStart === 0 ? "immediately" : `+${humanHours(w.hoursFromStart, !!r.skip_weekends)}`}
                                </Text>
                                <Progress value={w.pct} color="blue" size="sm" style={{flex: 1}} radius="xl"/>
                                <Text fz="xs" w={40} ta="right">{w.pct}%</Text>
                            </Group>
                        ))}
                    </Stack>

                    <Alert variant="light" color="blue" icon={<IconInfoCircle size={14}/>} p="xs">
                        <Text fz="xs">
                            Devices are assigned to waves by a stable hash, so a device never moves between
                            waves. Changing the wave size / restarting reshuffles the order. Devices not yet
                            in a wave keep their current version (they aren&apos;t downgraded).
                        </Text>
                    </Alert>
                </Stack>
            )}
        </Stack>
    );
}

function clampPct(v: number | string): number {
    const n = Math.trunc(Number(v) || 0);
    return Math.min(100, Math.max(1, n));
}

// Rough duration label. With weekends skipped, day intervals are labelled in business days.
function humanHours(hours: number, skipWeekends: boolean): string {
    if (hours % 168 === 0) return `${hours / 168}w`;
    if (hours % 24 === 0) {
        const days = hours / 24;
        return skipWeekends ? `${days} business day${days === 1 ? "" : "s"}` : `${days}d`;
    }
    return `${hours}h`;
}
