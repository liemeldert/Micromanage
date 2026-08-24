"use client";

// Card on the app's glass material. The behaviour comes from glass.ts, so this is only the Mantine binding.

import {Card, type CardProps, type ElementProps} from "@mantine/core";
import {forwardRef} from "react";
import {glassClassName, type GlassLift, type GlassMaterial, type GlassTone, glassToneStyle,} from "./glass";

type GlassCardProps = CardProps & ElementProps<"div", keyof CardProps> & {
    /** Thin for a card sitting over the flow canvas, none for one that brings a background of its own. */
    material?: GlassMaterial;
    /** Turns off the highlight that follows the cursor. */
    reactive?: boolean;
    /** Hover and press feedback. Defaults to on for a card that handles a click. */
    interactive?: boolean;
    /** Rises and leans toward the cursor. Defaults to on wherever the card is interactive. */
    lift?: GlassLift;
    /** A band of light around the edge saying how this is doing. Neutral draws nothing. */
    tone?: GlassTone;
    /** How brightly the tone burns, 0 to 1. Ignored when the tone is neutral. */
    toneLevel?: number;
    /** Off where the card holds controls with colours of their own. */
    toneBloom?: boolean;
};

export const GlassCard = forwardRef<HTMLDivElement, GlassCardProps>(function GlassCard(
    {
        material = "surface",
        reactive = true,
        interactive,
        lift,
        tone = "neutral",
        toneLevel = 1,
        toneBloom = true,
        className,
        style,
        ...rest
    },
    ref,
) {
    // A card wired to a click is interactive whether or not the caller says so.
    const reacts = interactive ?? (rest.onClick !== undefined || rest.role === "button");

    return (
        <Card
            ref={ref}
            className={glassClassName({
                material,
                reactive,
                interactive: reacts,
                lift: lift ?? (reacts ? "normal" : "none"),
                tone,
                toneBloom,
                className,
            })}
            style={tone === "neutral" ? style : {...glassToneStyle(toneLevel), ...style}}
            {...rest}
        />
    );
});
