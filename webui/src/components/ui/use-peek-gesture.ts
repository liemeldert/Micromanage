// Press and hold a row, or force click it on a Mac trackpad, to peek at it without leaving the list.

// I cannot believe that I am making a web app with first class Safari support of all things.

import type {PointerEvent as ReactPointerEvent} from "react";
import {useCallback, useEffect, useRef} from "react";
import {glassClassName} from "./glass";
import {bindForceClick, usePeekTimer} from "./peek-core";

/** The same gesture for a whole list, delegated from the container to any row marked with data-peek-id. */
export function usePeekGesture(
    onPeek: (id: string) => void,
    /** Held or force clicked on a [data-peek-filter] element inside the container, rather than on a row. */
    onPeekFilter?: (filter: string) => void,
) {
    const containerRef = useRef<HTMLElement | null>(null);
    const {cancel, start, drift, forcePeek, guard} = usePeekTimer();

    useEffect(() => {
        const root = containerRef.current;
        if (!root) return;

        return bindForceClick(
            root,
            (event) => {
                const target = event.target as HTMLElement | null;
                if (target?.closest("[data-peek-filter]") || target?.closest("[data-peek-id]")) event.preventDefault();
            },
            (event) => {
                const target = event.target as HTMLElement | null;
                // A value inside a row is more specific than the row, so it answers first.
                const filter = target?.closest("[data-peek-filter]")?.getAttribute("data-peek-filter");
                if (filter && onPeekFilter) {
                    event.preventDefault();
                    forcePeek(() => onPeekFilter(filter));
                    return;
                }
                const id = target?.closest("[data-peek-id]")?.getAttribute("data-peek-id");
                if (!id) return;
                event.preventDefault();
                forcePeek(() => onPeek(id));
            },
        );
    }, [forcePeek, onPeek, onPeekFilter]);

    /** Everything a row needs to take the gesture, the interactive glass classes included. */
    const rowProps = useCallback((id: string) => ({
        "data-peek-id": id,
        className: glassClassName({material: "none", interactive: true}),
        onPointerDown: (event: ReactPointerEvent) => start(event, () => onPeek(id)),
        onPointerMove: drift,
        onPointerUp: cancel,
        onPointerCancel: cancel,
        onPointerLeave: cancel,
    }), [start, drift, cancel, onPeek]);

    return {containerRef, rowProps, guardActivate: guard};
}
