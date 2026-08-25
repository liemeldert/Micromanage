import {Box, ScrollArea} from "@mantine/core";
import {useMediaQuery} from "@mantine/hooks";
import type {ReactNode} from "react";

export function SidebarLayout({
                                  sidebar,
                                  children,
                                  sidebarWidth = 340,
                                  breakpoint = "(min-width: 1100px)",
                                  top = 16,
                              }: {
    sidebar: ReactNode;
    children: ReactNode;
    /** Fixed width of the sidebar column while the layout is side by side. */
    sidebarWidth?: number;
    /** Below this the columns stack. */
    breakpoint?: string;
    /** Gap between the top of the viewport and the pinned sidebar. */
    top?: number;
}) {
    // Defaults to the wide layout so the server render matches the common case and does not flash a
    // stacked column before the query
    const wide = useMediaQuery(breakpoint, true);

    return (
        <Box
            style={{
                display: "flex",
                gap: "var(--mantine-spacing-lg)",
                alignItems: "flex-start",
                flexWrap: wide ? "nowrap" : "wrap",
            }}
        >
            <Box
                style={
                    wide
                        ? {position: "sticky", top, alignSelf: "flex-start", flex: `0 0 ${sidebarWidth}px`}
                        : {width: "100%"}
                }
            >
                {wide ? (
                    <ScrollArea.Autosize
                        mah={`calc(100vh - ${top * 2}px)`}
                        type="auto"
                        scrollbars="y"
                        offsetScrollbars
                    >
                        {sidebar}
                    </ScrollArea.Autosize>
                ) : (
                    sidebar
                )}
            </Box>

            {/* minWidth 0 keeps wide children (tables, code blocks) from pushing the column past the page. */}
            <Box style={{flex: "1 1 0", minWidth: 0, width: wide ? undefined : "100%"}}>{children}</Box>
        </Box>
    );
}
