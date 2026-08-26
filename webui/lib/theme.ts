import {createTheme, rem} from "@mantine/core";
import {glassClassName} from "@/components/ui/glass";

// App-wide corner rounding and the material floating surfaces are drawn on.
export const theme = createTheme({
    defaultRadius: "md",
    // Rounder than Mantine stock: md is the working surface (cards, inputs, buttons), sm a surface nested inside one
    // of those, lg a floating overlay, xl a pill.
    radius: {
        xs: rem(4),
        sm: rem(8),
        md: rem(12),
        lg: rem(18),
        xl: rem(28),
    },
    components: {
        // Overlays take the translucent material from globals.css (.mm-glass-*), the fuller variant rather than the
        // softened one the cards use, so a modal reads over whatever the page is showing. One that wants the plain
        // surface overrides classNames itself.
        Modal: {
            defaultProps: {
                centered: true,
                radius: "lg",
                overlayProps: {backgroundOpacity: 0.14, blur: 4},
                transitionProps: {
                    transition: "pop",
                    duration: 200,
                    timingFunction: "cubic-bezier(0.16, 1, 0.3, 1)",
                },
            },
            classNames: {
                content: glassClassName({material: "overlay", className: "mm-overlay-content"}),
                header: "mm-overlay-header",
            },
        },
        // Buttons and icon buttons sit on the same material as everything else: they take the highlight that
        // follows the cursor, the press glow, and a small rise toward the reader. material "none" is the point,
        // since the variant already paints the button and this only adds how it answers the pointer. Colour
        // therefore survives untouched, which matters where colour is the warning (red erase, orange lock).
        //
        // Doing it here rather than at each call site is what makes it one edit: every Button in the app,
        // including the ones inside modals and drawers, picks this up.
        Button: {
            defaultProps: {radius: "md"},
            classNames: {
                root: glassClassName({
                    material: "none",
                    interactive: true,
                    lift: "quiet",
                    className: "mm-glass-control",
                }),
            },
        },
        ActionIcon: {
            classNames: {
                root: glassClassName({
                    material: "none",
                    interactive: true,
                    lift: "quiet",
                    className: "mm-glass-control",
                }),
            },
        },
        // Text fields answer the pointer the same way, with the highlight that follows the cursor but not the
        // press feedback or the pointer cursor: a field is typed into, not clicked. Set on Input, which is the
        // element every text-entry component in Mantine builds on, so TextInput, Textarea, Select, Autocomplete
        // and PillsInput all take it from here.
        Input: {
            classNames: {
                input: glassClassName({
                    material: "none",
                    interactive: false,
                    className: "mm-glass-field",
                }),
            },
        },
        Drawer: {
            defaultProps: {
                overlayProps: {backgroundOpacity: 0.14, blur: 4},
            },
            classNames: {
                content: glassClassName({material: "overlay"}),
                header: "mm-overlay-header",
            },
        },
    },
});
