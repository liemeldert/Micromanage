// One label-and-value line in a fact table. Shared so the device pages, the peek modals and anything else showing
// inventory all lay a fact out the same way and a change to the layout lands in one place.
//
// Pass `value` for a plain value and it renders through Value, which makes it copyable. Pass children for anything
// that is not text: a badge, a progress bar, a link, several values in a row.

import {Box, Group, Text} from "@mantine/core";
import type {ReactNode} from "react";
import {Value} from "./Value";

export function FactRow({
                            label,
                            value,
                            mono,
                            copyable,
                            children,
                            details,
                        }: {
    label: string;
    /** Plain text value, rendered copyable. Ignored when children are given. */
    value?: string | number | null;
    mono?: boolean;
    /** Off for a value nobody retypes: timestamps, booleans, counts, relative times. */
    copyable?: boolean;
    children?: ReactNode;
    /** Renders under the label and value line at the row's full width, for expanded JSON. */
    details?: ReactNode;
}) {
    return (
        <Box style={{borderBottom: "1px solid var(--mantine-color-default-border)", padding: "7px 0"}}>
            <Group justify="space-between" wrap="nowrap" gap="lg" align="flex-start">
                {/* Inventory keys run past 60 characters with no spaces, so the label wraps and breaks
                    mid-token rather than overflowing into the next column. */}
                <Text fz="sm" c="dimmed" style={{minWidth: 0, overflowWrap: "anywhere"}}>{label}</Text>
                {/* Never shrinks, since a squeezed column truncated a Yes/No badge to "Y...". The cap is
                    wide enough for a 36 character UDID on one line. */}
                <div style={{textAlign: "right", flexShrink: 0, maxWidth: "75%", overflowWrap: "anywhere"}}>
                    {children ?? <Value mono={mono} copyable={copyable} label={label}>{value}</Value>}
                </div>
            </Group>
            {details}
        </Box>
    );
}
