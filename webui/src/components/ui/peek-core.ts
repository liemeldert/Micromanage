// Timer, drift and click-swallowing behind usePeek and usePeekGesture. Internal to those two hooks; nothing
// else imports it.

import type {PointerEvent as ReactPointerEvent} from "react";
import {useCallback, useEffect, useRef} from "react";

// Matches --mm-hold-duration in globals.css, which runs the press animation for the same window.
const HOLD_MS = 450;
// How far the pointer may drift before the hold is a drag instead.
const DRIFT_PX = 8;

/** Safari's own force-click action (Look Up) has to be refused before it starts, or it takes the gesture. */
export function bindForceClick(
    element: HTMLElement,
    willBegin: (event: Event) => void,
    forceDown: (event: Event) => void,
) {
    element.addEventListener("webkitmouseforcewillbegin", willBegin);
    element.addEventListener("webkitmouseforcedown", forceDown);
    return () => {
        element.removeEventListener("webkitmouseforcewillbegin", willBegin);
        element.removeEventListener("webkitmouseforcedown", forceDown);
    };
}

/** The hold itself: what it counts, what cancels it, and the click after it that has to be swallowed. */
export function usePeekTimer() {
    const timer = useRef<number | null>(null);
    const origin = useRef<{ x: number; y: number } | null>(null);
    const fired = useRef(false);

    const cancel = useCallback(() => {
        if (timer.current !== null) window.clearTimeout(timer.current);
        timer.current = null;
        origin.current = null;
    }, []);

    useEffect(() => () => cancel(), [cancel]);

    const start = useCallback((event: ReactPointerEvent, peek: () => void) => {
        if (event.button !== 0) return;
        // Clearing first, since cancel drops the origin the drift check measures against.
        cancel();
        // A hold released off the element leaves nothing to swallow, and a stale flag would eat the next
        // honest click.
        fired.current = false;
        origin.current = {x: event.clientX, y: event.clientY};
        timer.current = window.setTimeout(() => {
            fired.current = true;
            peek();
        }, HOLD_MS);
    }, [cancel]);

    const drift = useCallback((event: ReactPointerEvent) => {
        const from = origin.current;
        if (!from) return;
        if (Math.abs(event.clientX - from.x) > DRIFT_PX || Math.abs(event.clientY - from.y) > DRIFT_PX) cancel();
    }, [cancel]);

    /** Trackpad pressure reaches the callback without waiting out the timer. */
    const forcePeek = useCallback((peek: () => void) => {
        cancel();
        fired.current = true;
        peek();
    }, [cancel]);

    /** Wrap an activate handler so the click ending a hold does not also open the thing. */
    const guard = useCallback((activate: () => void) => () => {
        if (fired.current) {
            fired.current = false;
            return;
        }
        activate();
    }, []);

    return {cancel, start, drift, forcePeek, guard};
}
