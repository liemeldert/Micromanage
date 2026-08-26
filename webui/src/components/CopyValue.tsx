// An identifier people retype (UDID, serial, bundle id). Kept as its own name because call sites read better for
// it, but the behaviour is Value's: the text is the button, so nothing sits beside it pushing it out of line.

import {Group} from "@mantine/core";
import {Value} from "./ui/Value";

export function CopyValue({
                              value,
                              mono = false,
                              fz = "sm",
                              label,
                              align = "end",
                          }: {
    value: string;
    /** Monospace suits identifiers where character shape matters. */
    mono?: boolean;
    fz?: string;
    /** Names the value in the accessible label. Defaults to the value itself. */
    label?: string;
    /** Fact rows put the value against the right edge; a grid or a stack wants it against the left. */
    align?: "start" | "end";
}) {
    return (
        <Group
            gap={4}
            wrap="nowrap"
            justify={align === "start" ? "flex-start" : "flex-end"}
            style={{minWidth: 0}}
        >
            <Value mono={mono} fz={fz} label={label}>{value}</Value>
        </Group>
    );
}
