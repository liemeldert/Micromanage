// An element that answers the pointer the way the rest of the app does, with the hover wash, the press glow,
// the lean toward the cursor, and press-and-hold or force click to peek.

import type {ComponentPropsWithoutRef, ElementType} from "react";
import {forwardRef} from "react";
import {useMergedRef} from "@mantine/hooks";
import {glassClassName, type GlassLift, type GlassMaterial, type GlassTone, glassToneStyle} from "./glass";
import {usePeek} from "./use-peek";

interface OwnProps {
    /** Defaults to a div. Pass "tr", "button", or a component that forwards className and ref. */
    component?: ElementType;
    material?: GlassMaterial;
    /** Turns off the highlight that follows the cursor. */
    reactive?: boolean;
    lift?: GlassLift;
    /** Something interactive inside something else interactive. */
    nested?: boolean;
    tone?: GlassTone;
    /** How brightly the tone burns, 0 to 1. Ignored when the tone is neutral. */
    toneLevel?: number;
    className?: string;
    /** What activating it does. Held or force clicked, it peeks instead, and this does not also run. */
    onActivate?: () => void;
    /** What a press and hold or a force click does. Without it the element takes no peek gesture. */
    onPeek?: () => void;
    style?: React.CSSProperties;
}

type InteractableProps<C extends ElementType> = OwnProps & Omit<ComponentPropsWithoutRef<C>, keyof OwnProps>;

export const Interactable = forwardRef<HTMLElement, InteractableProps<ElementType>>(
    function Interactable(
        {
            component: Component = "div",
            material = "none",
            reactive = true,
            lift = "normal",
            nested = false,
            tone = "neutral",
            toneLevel = 1,
            className,
            style,
            onActivate,
            onPeek,
            ...rest
        },
        ref,
    ) {
        const peek = usePeek(onPeek ?? (() => {
        }), Boolean(onPeek));
        const merged = useMergedRef(ref, peek.ref);
        const activate = onActivate ? peek.guard(onActivate) : undefined;

        return (
            <Component
                ref={merged}
                role={onActivate ? "button" : undefined}
                tabIndex={onActivate ? 0 : undefined}
                className={glassClassName({
                    material,
                    reactive,
                    interactive: true,
                    lift,
                    nested,
                    tone,
                    className,
                })}
                style={tone === "neutral" ? style : {...glassToneStyle(toneLevel), ...style}}
                onClick={activate}
                onKeyDown={activate
                    ? (event: React.KeyboardEvent) => {
                        if (event.target !== event.currentTarget) return;
                        if (event.key !== "Enter" && event.key !== " ") return;
                        event.preventDefault();
                        activate();
                    }
                    : undefined}
                {...peek.handlers}
                {...rest}
            />
        );
    },
);
