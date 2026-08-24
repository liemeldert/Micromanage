// The class names that put an element on the app's glass material. A surface opts in by name rather than by
// wiring up styles of its own.
//
// Deliberately not a client module. lib/theme.ts calls it at module scope and is imported by the root layout,
// which is a Server Component.

/** Which fill a surface gets. Overlay is the fuller variant, for something floating over the page it has to
 * stay readable against. Thin is for anything laid over the flow canvas, where the standard fill would hide
 * the graph, and none is for an element that already has a background and only wants the highlight. */
export type GlassMaterial = "surface" | "overlay" | "thin" | "none";

/** What a surface says about its own state. Neutral draws nothing and is the right answer for most things. */
export type GlassTone = "neutral" | "positive" | "warning" | "negative";

/** How far a surface rises and leans toward the cursor. Quiet is for a large surface, where the full movement
 * would fight the text on it. */
export type GlassLift = "none" | "quiet" | "normal";

const MATERIAL: Record<GlassMaterial, string> = {
    surface: "mm-glass-surface mm-glass-surface-soft",
    overlay: "mm-glass-surface",
    thin: "mm-glass-surface mm-glass-surface-soft mm-glass-thin",
    none: "",
};

export interface GlassOptions {
    material?: GlassMaterial;
    /** The highlight that follows the cursor, which glass-pointer drives for every element carrying it. */
    reactive?: boolean;
    /** Hover and press feedback, for something that does anything when clicked. */
    interactive?: boolean;
    lift?: GlassLift;
    /** Something interactive inside something else interactive, which answers more quietly. */
    nested?: boolean;
    tone?: GlassTone;
    /** Whether the tone also colours the cursor highlight. Off for a surface whose contents carry their own
     * colours, where the state colour would drown out whichever of them the pointer is over. */
    toneBloom?: boolean;
    className?: string;
}

export function glassClassName({
                                   material = "surface",
                                   reactive = true,
                                   interactive = false,
                                   lift = "none",
                                   nested = false,
                                   tone = "neutral",
                                   toneBloom = true,
                                   className,
                               }: GlassOptions = {}): string {
    return [
        MATERIAL[material],
        reactive ? "mm-glass-reactive" : "",
        interactive ? "mm-glass-interactive" : "",
        lift === "none" ? "" : lift === "quiet" ? "mm-glass-lift mm-glass-lift-quiet" : "mm-glass-lift",
        nested ? "mm-glass-nested" : "",
        tone === "neutral" ? "" : `mm-glass-tone mm-glass-tone-${tone}`,
        tone !== "neutral" && !toneBloom ? "mm-glass-tone-plain" : "",
        className,
    ].filter(Boolean).join(" ");
}

/** Inline style setting how brightly the tone burns, 0 to 1. Levels outside that range are clamped. */
export function glassToneStyle(level = 1): React.CSSProperties {
    return {"--mm-tone-level": Math.min(Math.max(level, 0), 1)} as React.CSSProperties;
}
