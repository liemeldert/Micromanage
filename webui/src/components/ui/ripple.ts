// The glow a press leaves on the surface, growing with hold time and with trackpad force where there is any. It is a
// background layer centred on the pointer position glass-pointer tracks, since a table row cannot carry a child node.

const REDUCED_MOTION = "(prefers-reduced-motion: reduce)";

// How long a press with no pressure behind it takes to reach full size.
const GROW_MS = 620;
// What the time and the pressure are each worth. Time alone gets most of the way there.
const TIME_SHARE = 0.72;
const FORCE_SHARE = 0.4;

let pressed: { element: HTMLElement; start: number; frame: number } | null = null;
let force = 0;

export function setPressForce(value: number) {
    force = value;
}

function paint() {
    if (!pressed) return;
    const held = Math.min((performance.now() - pressed.start) / GROW_MS, 1);
    const level = Math.min(held * TIME_SHARE + force * FORCE_SHARE, 1);
    pressed.element.style.setProperty("--mm-glass-press", level.toFixed(3));
    pressed.frame = requestAnimationFrame(paint);
}

/** Starts the glow on a surface and drives it frame by frame until the press ends. */
export function beginPress(target: Element | null | undefined) {
    if (typeof window === "undefined") return;
    if (!(target instanceof HTMLElement)) return;
    if (window.matchMedia(REDUCED_MOTION).matches) return;

    endPress();
    // No transition while the press drives the value directly, or every frame would chase the last one.
    target.classList.add("mm-glass-pressing");
    target.style.setProperty("--mm-glass-press-glow", "1");
    pressed = {element: target, start: performance.now(), frame: 0};
    paint();
}

/** Stops driving the glow and lets it fade out at the size it reached. */
export function endPress() {
    if (!pressed) return;
    const {element, frame} = pressed;
    pressed = null;
    force = 0;
    cancelAnimationFrame(frame);

    element.classList.remove("mm-glass-pressing");
    element.style.setProperty("--mm-glass-press-glow", "0");
    window.setTimeout(() => {
        element.style.removeProperty("--mm-glass-press");
        element.style.removeProperty("--mm-glass-press-glow");
    }, 640);
}
