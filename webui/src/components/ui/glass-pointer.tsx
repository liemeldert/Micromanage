"use client";

// One set of window listeners drives the cursor highlight, the lean, and the press glow for every glass
// surface on the page.

import {useEffect} from "react";
import {beginPress, endPress, setPressForce} from "./ripple";

// How far outside a surface the highlight still reaches.
const FALLOFF_PX = 260;
// How far a lifting surface leans after the cursor at its outer edge. A large panel leans less, since the
// movement plays against text being read.
const LEAN_PX = 3.5;
const LEAN_QUIET_PX = 1.75;

interface ForceEvent extends MouseEvent {
    webkitForce?: number;
}

let pointer: { x: number; y: number } | null = null;
// The surface currently wearing a tint borrowed from something inside it.
let borrower: HTMLElement | null = null;
let frame = 0;
let listening = false;

function paint() {
    frame = 0;
    const at = pointer;
    const surfaces = document.querySelectorAll<HTMLElement>(".mm-glass-reactive");
    // All the reads before all the writes, so a page full of surfaces does not thrash layout.
    const rects: Array<[HTMLElement, DOMRect]> = [];
    for (const el of surfaces) rects.push([el, el.getBoundingClientRect()]);

    for (const [el, rect] of rects) {
        if (!at) {
            el.style.setProperty("--mm-glass-near", "0");
            el.style.setProperty("--mm-glass-lean-x", "0px");
            el.style.setProperty("--mm-glass-lean-y", "0px");
            continue;
        }
        const dx = Math.max(rect.left - at.x, 0, at.x - rect.right);
        const dy = Math.max(rect.top - at.y, 0, at.y - rect.bottom);
        const distance = Math.hypot(dx, dy);
        const near = distance >= FALLOFF_PX ? 0 : (1 - distance / FALLOFF_PX) ** 2;
        el.style.setProperty("--mm-glass-px", `${at.x - rect.left}px`);
        el.style.setProperty("--mm-glass-py", `${at.y - rect.top}px`);
        el.style.setProperty("--mm-glass-near", near.toFixed(3));

        // A surface that lifts also leans after the pointer while it is over it, the way a focused target does
        // on iPadOS. Only while the pointer is actually inside, or a card would drift at a cursor passing by.
        if (!el.classList.contains("mm-glass-lift")) continue;
        const over = distance === 0;
        // Pressing harder leans the card further. The press level already folds in trackpad force and pen
        // pressure where they exist, and grows on hold time where they do not.
        const press = Number(el.style.getPropertyValue("--mm-glass-press")) || 0;
        const span = el.classList.contains("mm-glass-lift-quiet") ? LEAN_QUIET_PX : LEAN_PX;
        const reach = over ? span * (1 + press * 0.9) : 0;
        const leanX = ((at.x - (rect.left + rect.width / 2)) / (rect.width / 2)) * reach;
        const leanY = ((at.y - (rect.top + rect.height / 2)) / (rect.height / 2)) * reach;
        el.style.setProperty("--mm-glass-lean-x", `${leanX.toFixed(2)}px`);
        el.style.setProperty("--mm-glass-lean-y", `${leanY.toFixed(2)}px`);
    }
}

function schedule() {
    // One paint per frame, however many events arrived during it.
    if (frame) return;
    frame = requestAnimationFrame(paint);
}

function handleMove(event: PointerEvent) {
    pointer = {x: event.clientX, y: event.clientY};
    // A pen carries its pressure on the move event, so the press glow reads it here instead of from Force Touch.
    if (event.pointerType === "pen") setPressForce(event.pressure);
    schedule();
}

// A coloured control lends its colour to the surface around it while the pointer is on it, so hovering a red
// severity does not leave the card blooming in the app accent. Read on the way in rather than per frame.
function handleOver(event: PointerEvent) {
    const target = (event.target as HTMLElement | null)?.closest<HTMLElement>(".mm-glass-reactive");
    // The surface that would borrow, null when the pointer is on the outermost one. Working it out first drops
    // the loan as soon as the pointer leaves the child, instead of holding the colour until another is hovered.
    const host = target?.parentElement?.closest<HTMLElement>(".mm-glass-reactive") ?? null;

    if (borrower && borrower !== host) {
        borrower.style.removeProperty("--mm-glass-glow-tint");
        borrower = null;
    }
    if (!target || !host) return;

    const tint = getComputedStyle(target).getPropertyValue("--mm-glass-glow-tint").trim();
    if (!tint) return;
    host.style.setProperty("--mm-glass-glow-tint", tint);
    borrower = host;
}

function handleOut(event: PointerEvent) {
    // A null relatedTarget means the cursor left the window rather than moving onto another element.
    if (event.relatedTarget) return;
    pointer = null;
    if (borrower) {
        borrower.style.removeProperty("--mm-glass-glow-tint");
        borrower = null;
    }
    schedule();
}

// Force Touch is WebKit only. Everywhere else this never runs and the press glow grows on hold time alone.
function handleForce(event: Event) {
    const raw = (event as ForceEvent).webkitForce;
    // 1 is the click threshold and 3 is about as hard as the trackpad reports.
    setPressForce(typeof raw === "number" ? Math.min(Math.max(raw / 3, 0), 1) : 0);
}

function handlePress(event: PointerEvent) {
    if (event.button !== 0) return;
    // Any glass surface answers a press, not only the ones that do something when clicked. The stylesheet
    // gives a surface that is only being read a quieter response.
    beginPress((event.target as HTMLElement | null)?.closest(".mm-glass-reactive"));
}

/** Renders nothing. Mounted once in the root layout, it drives every mm-glass-reactive surface in the app. */
export function GlassPointer() {
    useEffect(() => {
        if (listening) return;
        if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
        listening = true;
        window.addEventListener("pointermove", handleMove, {passive: true});
        // Capture, because a nested control stops the event bubbling to keep its parent's gesture out of the
        // way, and the glow still belongs to whatever was pressed.
        window.addEventListener("pointerdown", handlePress, {capture: true, passive: true});
        window.addEventListener("pointerover", handleOver, {passive: true});
        window.addEventListener("pointerout", handleOut, {passive: true});
        window.addEventListener("webkitmouseforcechanged", handleForce, {passive: true});
        window.addEventListener("pointerup", endPress, {passive: true});
        window.addEventListener("pointercancel", endPress, {passive: true});
        window.addEventListener("scroll", schedule, {passive: true, capture: true});
        window.addEventListener("resize", schedule, {passive: true});
        // No frames run while the tab is hidden, so a paint owed from then is taken on the way back.
        document.addEventListener("visibilitychange", schedule);
    }, []);

    return null;
}
