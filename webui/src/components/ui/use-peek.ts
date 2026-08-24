"use client";

// Press and hold, or force click on a Mac trackpad, to peek at one thing. Attached per element rather than
// per container, so anything can take the gesture by spreading what this returns.
//
// Force Touch is WebKit only, so Safari gets the pressure path and everything else gets the hold. Both end in
// the same callback, and the click that follows either is swallowed or the element would also open.

import type {PointerEvent as ReactPointerEvent} from "react";
import {useEffect, useRef} from "react";
import {bindForceClick, usePeekTimer} from "./peek-core";

/** The peek gesture on a single element. Attach the returned ref to it and spread the returned handlers. */
export function usePeek(onPeek: () => void, enabled = true) {
    const ref = useRef<HTMLElement | null>(null);
    const {cancel, start, drift, forcePeek, guard} = usePeekTimer();

    useEffect(() => {
        const element = ref.current;
        if (!element || !enabled) return;

        return bindForceClick(
            element,
            (event) => event.preventDefault(),
            (event) => {
                event.preventDefault();
                forcePeek(onPeek);
            },
        );
    }, [forcePeek, onPeek, enabled]);

    const handlers = {
        onPointerDown: (event: ReactPointerEvent) => {
            if (enabled) start(event, onPeek);
        },
        onPointerMove: drift,
        onPointerUp: cancel,
        onPointerCancel: cancel,
        onPointerLeave: cancel,
    };

    return {ref, handlers, guard, cancel};
}
