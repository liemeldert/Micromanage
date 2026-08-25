// A value with a copy button that appears on hover or keyboard focus, for identifiers people retype (UDID, serial,
// bundle id) where a button on every row would clutter a dense table. Touch has no hover, so it stays visible there.

import {ActionIcon, CopyButton, Group, Text, Tooltip} from "@mantine/core";
import {IconCheck, IconCopy} from "@tabler/icons-react";

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
    /** Names the value in the button's accessible label. Defaults to the value itself. */
    label?: string;
    /** Fact rows put the value against the right edge; a grid or a stack wants it against the left. */
    align?: "start" | "end";
}) {
    return (
        <Group
            className="mm-copy-value"
            gap={4}
            wrap="nowrap"
            justify={align === "start" ? "flex-start" : "flex-end"}
            style={{minWidth: 0}}
        >
            <Text
                fz={fz}
                style={{
                    minWidth: 0,
                    overflowWrap: "anywhere",
                    fontFamily: mono ? "var(--mantine-font-family-monospace)" : undefined,
                }}
            >
                {value}
            </Text>
            <CopyButton value={value} timeout={1400}>
                {({copied, copy}) => (
                    <Tooltip label={copied ? "Copied" : "Copy"} withArrow openDelay={300}>
                        <ActionIcon
                            className="mm-copy-value-button"
                            size="sm"
                            variant="subtle"
                            color={copied ? "teal" : "gray"}
                            onClick={copy}
                            aria-label={`Copy ${label ?? value}`}
                            style={{flexShrink: 0}}
                        >
                            {copied ? <IconCheck size={14}/> : <IconCopy size={14}/>}
                        </ActionIcon>
                    </Tooltip>
                )}
            </CopyButton>
        </Group>
    );
}
