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
