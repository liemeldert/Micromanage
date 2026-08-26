// A displayed value. Copyable is the default across the app, because almost everything on a device or config page
// is an identifier somebody is about to retype: serials, UDIDs, hostnames, bundle ids, paths, error codes.
//
// The value itself is what you click. Nothing is added beside it, so a copyable value occupies exactly the space
// the text does and a table of them stays aligned. A button in the flow shifted the text sideways on every row
// that had one, which is what this replaces.
//
// Opt out with copyable={false} for anything retyping makes no sense for: a timestamp, a yes/no, a duration, a
// count, a relative time like "3d ago".

import {Text, type TextProps, Tooltip} from "@mantine/core";
import {useClipboard} from "@mantine/hooks";
import {useEffect} from "react";
import {notifications} from "@mantine/notifications";

export interface ValueProps extends Omit<TextProps, "children"> {
    children: string | number | null | undefined;
    /** Monospace suits identifiers where character shape matters. */
    mono?: boolean;
    /** Off for a value nobody would paste anywhere: timestamps, booleans, counts, relative times. */
    copyable?: boolean;
    /** Names the value in the accessible label. Defaults to the value itself. */
    label?: string;
}

// A placeholder is not a value, so it never offers to copy itself.
const PLACEHOLDERS = new Set(["", "--", "-", "n/a", "N/A", "unknown"]);

export function Value({
                          children,
                          mono = false,
                          copyable = true,
                          label,
                          fz = "sm",
                          style,
                          className,
                          ...rest
                      }: ValueProps) {
    const clipboard = useClipboard({timeout: 1400});
    const text = children === null || children === undefined ? "" : String(children);

    // A refused write leaves the value looking like it ignored the click, so say so rather than letting someone
    // paste whatever they had before and not notice. useClipboard reports both ways this fails: no clipboard
    // api at all, and a write the browser turned down.
    useEffect(() => {
        if (!clipboard.error) return;
        notifications.show({color: "red", message: "This browser would not let the page use the clipboard."});
    }, [clipboard.error]);

    const base = {
        fz,
        style: {
            overflowWrap: "anywhere" as const,
            fontFamily: mono ? "var(--mantine-font-family-monospace)" : undefined,
            ...style,
        },
        ...rest,
    };

    if (!copyable || PLACEHOLDERS.has(text.trim())) {
        return <Text className={className} {...base}>{text}</Text>;
    }

    return (
        <Tooltip label={clipboard.copied ? "Copied" : "Click to copy"} withArrow openDelay={450} position="top">
            <Text
                component="span"
                role="button"
                tabIndex={0}
                aria-label={`Copy ${label ?? text}`}
                data-copied={clipboard.copied || undefined}
                className={`mm-copy-text ${className ?? ""}`}
                onClick={() => clipboard.copy(text)}
                onKeyDown={(event) => {
                    if (event.key !== "Enter" && event.key !== " ") return;
                    event.preventDefault();
                    clipboard.copy(text);
                }}
                {...base}
            >
                {text}
            </Text>
        </Tooltip>
    );
}
