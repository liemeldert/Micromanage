"use client";

// A surface with an action behind each edge, reached by dragging it aside. The drag tracks the pointer the
// whole way rather than snapping once a threshold is crossed.
//
// A touch swipe, a mouse press and drag, and a trackpad's two-finger horizontal scroll all reach it. The
// wheel listener is attached by hand, since a passive one cannot refuse the browser's back-and-forward swipe.

import type {PointerEvent as ReactPointerEvent, ReactNode} from "react";
import {useCallback, useEffect, useRef, useState} from "react";
import {Box, UnstyledButton} from "@mantine/core";

export interface SwipeAction {
    label: string;
    icon: ReactNode;
    /** A Mantine colour name. Also tints the edge hint on that side. */
    color: string;
    onAction: () => void;
    /** Runs as soon as the drag passes the threshold, rather than waiting for a press on the revealed action. */
    immediate?: boolean;
    /** Sends the surface all the way across and collapses it, the way a notification is cleared. */
    dismiss?: boolean;
}

// How far the surface has to travel before an action is armed, and how far it rests when one is held open.
const TRIGGER_PX = 56;
const REST_PX = 96;
// Far enough to clear any row, and the window the collapse runs in before the row is taken out of the list.
const CLEAR_PX = 2000;
const CLEAR_MS = 260;
// A wheel gesture has no release, so it settles once the deltas stop arriving.
const WHEEL_SETTLE_MS = 140;

export function SwipeActions({
                                 left,
                                 right,
                                 disabled = false,
                                 onDismissed,
                                 children,
                             }: {
    /** Revealed by dragging the surface to the right. */
    left?: SwipeAction;
    /** Revealed by dragging the surface to the left. */
    right?: SwipeAction;
    disabled?: boolean;
    /** Called once a dismissing action has finished clearing, so the caller can drop the row. */
    onDismissed?: () => void;
    children: ReactNode;
}) {
    const [offset, setOffset] = useState(0);
    const [dragging, setDragging] = useState(false);
    const [clearing, setClearing] = useState(false);
    const surface = useRef<HTMLDivElement | null>(null);
    const origin = useRef<number | null>(null);
    const settleTimer = useRef<number | null>(null);
    const moved = useRef(false);

    const limit = useCallback((next: number) => {
        const min = right ? -REST_PX : 0;
        const max = left ? REST_PX : 0;
        return Math.max(min, Math.min(max, next));
    }, [left, right]);

    // Past the threshold the action is armed. An immediate one runs now and the surface stays open so the
    // second action behind it can be reached; otherwise the surface just rests open.
    const settle = useCallback((at: number) => {
        const action = at <= -TRIGGER_PX ? right : at >= TRIGGER_PX ? left : undefined;
        if (!action) {
            setOffset(0);
            return;
        }
        if (action.immediate) action.onAction();
        if (action.dismiss) {
            // Straight off the edge and out of the list, the way a notification is cleared.
            setDragging(false);
            setClearing(true);
            setOffset(at < 0 ? -CLEAR_PX : CLEAR_PX);
            window.setTimeout(() => onDismissed?.(), CLEAR_MS);
            return;
        }
        setOffset(at < 0 ? -REST_PX : REST_PX);
    }, [left, right, onDismissed]);

    const endDrag = useCallback(() => {
        origin.current = null;
        setDragging(false);
        setOffset((current) => {
            settle(current);
            return current;
        });
    }, [settle]);

    useEffect(() => {
        const element = surface.current;
        if (!element || disabled) return;

        const onWheel = (event: WheelEvent) => {
            if (Math.abs(event.deltaX) <= Math.abs(event.deltaY)) return;
            // Without this the browser reads the same gesture as back or forward.
            event.preventDefault();
            setDragging(true);
            setOffset((current) => limit(current - event.deltaX));

            if (settleTimer.current !== null) window.clearTimeout(settleTimer.current);
            settleTimer.current = window.setTimeout(endDrag, WHEEL_SETTLE_MS);
        };

        element.addEventListener("wheel", onWheel, {passive: false});
        return () => {
            element.removeEventListener("wheel", onWheel);
            if (settleTimer.current !== null) window.clearTimeout(settleTimer.current);
        };
    }, [disabled, limit, endDrag]);

    const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
        if (disabled || event.button !== 0) return;
        origin.current = event.clientX - offset;
        moved.current = false;
    };

    const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
        if (origin.current === null) return;
        const next = limit(event.clientX - origin.current);
        if (Math.abs(next - offset) > 2) {
            moved.current = true;
            setDragging(true);
        }
        setOffset(next);
    };

    const onPointerUp = () => {
        if (origin.current === null) return;
        endDrag();
    };

    const held = Math.abs(offset) >= REST_PX && !clearing;

    useEffect(() => {
        if (!held) return;
        const close = (event: Event) => {
            if (surface.current?.parentElement?.contains(event.target as Node)) return;
            setOffset(0);
        };
        document.addEventListener("pointerdown", close);
        return () => document.removeEventListener("pointerdown", close);
    }, [held]);

    return (
        <Box
            className="mm-swipe"
            data-open={held || undefined}
            data-dragging={dragging || undefined}
            data-clearing={clearing || undefined}
            // Left alone, an opened surface closes itself rather than sitting there waiting.
            onPointerLeave={() => {
                if (origin.current === null && held) setOffset(0);
            }}
            style={{
                "--mm-swipe-hint-left": left ? `var(--mantine-color-${left.color}-5)` : "transparent",
                "--mm-swipe-hint-right": right ? `var(--mantine-color-${right.color}-5)` : "transparent",
            } as React.CSSProperties}
        >
            <Box className="mm-swipe-clip">
                {left && (
                    <UnstyledButton
                        className="mm-swipe-action mm-swipe-action-left"
                        style={{"--mm-swipe-tint": `var(--mantine-color-${left.color}-5)`} as React.CSSProperties}
                        aria-label={left.label}
                        tabIndex={offset > 0 ? 0 : -1}
                        onClick={(event) => {
                            event.stopPropagation();
                            left.onAction();
                            setOffset(0);
                        }}
                    >
                        {left.icon}
                    </UnstyledButton>
                )}
                {right && (
                    <UnstyledButton
                        className="mm-swipe-action mm-swipe-action-right"
                        style={{"--mm-swipe-tint": `var(--mantine-color-${right.color}-5)`} as React.CSSProperties}
                        aria-label={right.label}
                        tabIndex={offset < 0 ? 0 : -1}
                        onClick={(event) => {
                            event.stopPropagation();
                            right.onAction();
                            setOffset(0);
                        }}
                    >
                        {right.icon}
                    </UnstyledButton>
                )}

                <Box
                    ref={surface}
                    className="mm-swipe-surface"
                    style={{
                        transform: `translate3d(${offset}px, 0, 0)`,
                        transition: dragging ? "none" : undefined,
                    }}
                    onPointerDown={onPointerDown}
                    onPointerMove={onPointerMove}
                    onPointerUp={onPointerUp}
                    onPointerCancel={onPointerUp}
                    onPointerLeave={onPointerUp}
                    // A drag that moved is not a click, and an open surface closes rather than activating.
                    onClickCapture={(event) => {
                        if (!moved.current && !held) return;
                        event.stopPropagation();
                        event.preventDefault();
                        moved.current = false;
                        if (held) setOffset(0);
                    }}
                >
                    {children}
                </Box>
            </Box>
        </Box>
    );
}
