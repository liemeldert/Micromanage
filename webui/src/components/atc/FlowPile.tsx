// A flow and its drafts, as one pile in the overview grid. The drafts lie across the lower part of the
// flow they draft; hovering spreads them, and clicking takes the pile to the centre of the page and
// unstacks it into a column of readable cards.

import {useCallback, useEffect, useRef, useState} from "react";
import {Badge, Portal} from "@mantine/core";
import {useIsomorphicEffect} from "@mantine/hooks";
import type {FlowDoc, FlowSummary} from "../../../lib/api";
import {FlowOverviewCard} from "./FlowOverviewCard";

// Unstacking timings, matching .atc-inspector-flyout and the palette entrance.
const UNSTACK_MS = 240;
const UNSTACK_STAGGER_MS = 50;

interface FlowPileProps {
    /** The flow first, then its drafts. */
    stack: FlowDoc[];
    statsFor: (flow: FlowDoc) => FlowSummary | undefined;
    statsState: "loading" | "ready" | "unavailable";
    retentionDays: number | null;
    onOpenFlow: (flow: FlowDoc) => void;
}

function motionOff(): boolean {
    if (typeof window === "undefined") return false;
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export function FlowPile({stack, statsFor, statsState, retentionDays, onOpenFlow}: FlowPileProps) {
    // Where the pile sat when it was opened, as an offset from the centre of the viewport. Phase drives
    // the CSS transition, "closing" being the pile state again with the stagger reversed.
    const [origin, setOrigin] = useState<{ dx: number; dy: number } | null>(null);
    const [phase, setPhase] = useState<"pile" | "open" | "closing">("pile");
    const [shifts, setShifts] = useState<number[]>([]);
    const pileRef = useRef<HTMLDivElement | null>(null);
    const layerRef = useRef<HTMLDivElement | null>(null);
    const closeTimer = useRef<number | null>(null);

    const drafts = stack.length - 1;

    const drop = useCallback(() => {
        if (closeTimer.current !== null) {
            window.clearTimeout(closeTimer.current);
            closeTimer.current = null;
        }
        setOrigin(null);
        setPhase("pile");
        setShifts([]);
    }, []);

    const close = useCallback(() => {
        if (!origin) return;
        if (motionOff()) {
            drop();
            return;
        }
        setPhase("closing");
        closeTimer.current = window.setTimeout(drop, UNSTACK_MS + UNSTACK_STAGGER_MS * stack.length + 40);
    }, [origin, drop, stack.length]);

    const open = () => {
        const box = pileRef.current?.getBoundingClientRect();
        setShifts([]);
        setPhase("pile");
        setOrigin({
            dx: box ? box.left + box.width / 2 - window.innerWidth / 2 : 0,
            dy: box ? box.top + box.height / 2 - window.innerHeight / 2 : 0,
        });
    };

    // The cards land in a column, so each one's gather offset is the distance back to the top card.
    // Measured before the first paint, plus a few pixels of cascade so the pile keeps its edges.
    useIsomorphicEffect(() => {
        if (!origin || !layerRef.current) return;
        const cards = Array.from(layerRef.current.querySelectorAll<HTMLElement>(".mm-flow-unstack-card"));
        if (cards.length === 0) return;
        const base = cards[0].offsetTop;
        setShifts(cards.map((card, i) => base - card.offsetTop + i * 8));
    }, [origin]);

    // One frame in the pile position, then release the transition.
    useEffect(() => {
        if (!origin || phase !== "pile") return;
        if (motionOff()) {
            setPhase("open");
            return;
        }
        const id = requestAnimationFrame(() => requestAnimationFrame(() => setPhase("open")));
        return () => cancelAnimationFrame(id);
    }, [origin, phase]);

    useEffect(() => {
        if (!origin) return;
        const onKeyDown = (e: KeyboardEvent) => {
            if (e.key !== "Escape") return;
            e.preventDefault();
            close();
        };
        window.addEventListener("keydown", onKeyDown, true);
        return () => window.removeEventListener("keydown", onKeyDown, true);
    }, [origin, close]);

    useEffect(() => () => {
        if (closeTimer.current !== null) window.clearTimeout(closeTimer.current);
    }, []);

    const openFlow = (flow: FlowDoc) => {
        drop();
        onOpenFlow(flow);
    };

    const card = (flow: FlowDoc, onEdit: () => void) => (
        <FlowOverviewCard
            flow={flow}
            stats={statsFor(flow)}
            statsState={statsState}
            retentionDays={retentionDays}
            onEdit={onEdit}
            className={flow.draft_of ? "mm-flow-card-draft" : undefined}
        />
    );

    return (
        <>
            {/* The click is taken on the way down, so a card in the pile opens the pile rather than its own
                flow. Each card keeps its own keyboard path, and focusing one spreads the pile. */}
            <div
                ref={pileRef}
                className="mm-flow-pile"
                style={{"--mm-pile-drafts": drafts} as React.CSSProperties}
                onClickCapture={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    open();
                }}
            >
                {stack.map((flow, i) => (
                    <div
                        key={flow.id}
                        className="mm-flow-pile-card"
                        style={{"--mm-pile-i": i, zIndex: i + 1} as React.CSSProperties}
                    >
                        {card(flow, () => onOpenFlow(flow))}
                    </div>
                ))}
                {drafts > 1 ? (
                    <Badge className="mm-flow-pile-count" size="sm" variant="filled" color="orange">
                        {drafts} drafts
                    </Badge>
                ) : null}
            </div>

            {origin ? (
                <Portal>
                    <div
                        ref={layerRef}
                        className="mm-flow-unstack-layer"
                        data-state={phase === "open" ? "open" : "pile"}
                        style={{
                            "--mm-unstack-dx": `${origin.dx}px`,
                            "--mm-unstack-dy": `${origin.dy}px`,
                        } as React.CSSProperties}
                    >
                        {/* A native button so dismissing the pile has a keyboard path without making the
                            backdrop a tab stop that swallows focus. */}
                        <button
                            type="button"
                            className="mm-flow-unstack-scrim"
                            aria-label="Close the flow stack"
                            onClick={close}
                        />
                        <div className="mm-flow-unstack-column">
                            {stack.map((flow, i) => (
                                <div
                                    key={flow.id}
                                    className="mm-flow-unstack-card"
                                    style={{
                                        "--mm-unstack-shift": `${shifts[i] ?? 0}px`,
                                        // Closing reverses the order, so the top card is the last one back.
                                        "--mm-unstack-delay": motionOff()
                                            ? "0ms"
                                            : `${(phase === "closing" ? stack.length - 1 - i : i) * UNSTACK_STAGGER_MS}ms`,
                                    } as React.CSSProperties}
                                >
                                    {card(flow, () => openFlow(flow))}
                                </div>
                            ))}
                        </div>
                    </div>
                </Portal>
            ) : null}
        </>
    );
}
