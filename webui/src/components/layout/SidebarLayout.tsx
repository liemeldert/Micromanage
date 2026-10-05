import {Box, ScrollArea} from "@mantine/core";
import {useMediaQuery} from "@mantine/hooks";
import type {ReactNode} from "react";

// Room left around a scrolling column for the cards' drop shadows, which the scroll viewport would otherwise clip.
// Sideways this is the page gutter and the column gap, both spacing lg, so the widened scroll box reaches to the
// edge of each and covers nothing that takes a click.
const SHADOW_ROOM_X = 20;

// Below the last card the room is padding inside the viewport, not a taller box. A box reaching above its own top would
// draw its scrolling cards over the page content up there, so the first card's top shadow stays clipped.
const SHADOW_ROOM_BOTTOM = 40;

/** A column that scrolls on its own, with room left for the shadows of the cards inside it. */
function ScrollingColumn({
                             children,
                             maxHeight,
                             insetTop = 0,
                         }: {
    children: ReactNode;
    /** Omit to fill the height the parent gives it. */
    maxHeight?: string;
    /** Empty space at the top of the scrolled content, for anything floating over the column. */
    insetTop?: number;
}) {
    return (
        // Widening the box also moves the scrollbar, which rides its edge, so it is inset by the same amount and
        // stays beside the cards it scrolls rather than out in the gap.
        <ScrollArea.Autosize
            h={maxHeight ? undefined : "100%"}
            mah={maxHeight}
            type="auto"
            scrollbars="y"
            offsetScrollbars
            style={{marginInline: `-${SHADOW_ROOM_X}px`}}
            styles={{
                scrollbar: {
                    insetBlockEnd: SHADOW_ROOM_BOTTOM,
                    insetInlineEnd: SHADOW_ROOM_X,
                },
            }}
        >
            <Box px={SHADOW_ROOM_X} pb={SHADOW_ROOM_BOTTOM} pt={insetTop}>{children}</Box>
        </ScrollArea.Autosize>
    );
}

export function SidebarLayout({
                                  sidebar,
                                  children,
                                  sidebarWidth = 340,
                                  breakpoint = "(min-width: 1100px)",
                                  top = 16,
                                  fill = false,
                                  insetTop = 0,
                              }: {
    sidebar: ReactNode;
    children: ReactNode;
    /** Fixed width of the sidebar column while the layout is side by side. */
    sidebarWidth?: number;
    /** Below this the columns stack. */
    breakpoint?: string;
    /** Gap between the top of the viewport and the pinned sidebar. Ignored when filling. */
    top?: number;
    /**
     * Fill the height the parent gives this layout and scroll each column inside it instead of the page, so what is
     * above the layout stays in view. The parent must have a height of its own.
     */
    fill?: boolean;
    /**
     * Empty space at the top of both scrolled columns. For something floating over the layout, so the columns
     * start below it rather than under it, while still scrolling up behind it.
     */
    insetTop?: number;
}) {
    // Defaults to the wide layout so the server render matches the common case and does not flash a
    // stacked column before the query
    const wide = useMediaQuery(breakpoint, true);
    const filling = fill && wide;

    return (
        <Box
            style={{
                display: "flex",
                gap: "var(--mantine-spacing-lg)",
                alignItems: filling ? "stretch" : "flex-start",
                flexWrap: wide ? "nowrap" : "wrap",
                ...(filling ? {height: "100%", minHeight: 0} : {}),
            }}
        >
            <Box
                style={
                    !wide
                        ? {width: "100%"}
                        : filling
                            ? {flex: `0 0 ${sidebarWidth}px`, minHeight: 0}
                            : {position: "sticky", top, alignSelf: "flex-start", flex: `0 0 ${sidebarWidth}px`}
                }
            >
                {wide ? (
                    <ScrollingColumn
                        maxHeight={filling ? undefined : `calc(100vh - ${top * 2}px)`}
                        insetTop={insetTop}
                    >
                        {sidebar}
                    </ScrollingColumn>
                ) : (
                    sidebar
                )}
            </Box>

            {/* minWidth 0 keeps wide children (tables, code blocks) from pushing the column past the page. */}
            <Box
                style={{
                    flex: "1 1 0",
                    minWidth: 0,
                    width: wide ? undefined : "100%",
                    ...(filling ? {minHeight: 0} : {}),
                }}
            >
                {filling ? <ScrollingColumn insetTop={insetTop}>{children}</ScrollingColumn> : children}
            </Box>
        </Box>
    );
}
