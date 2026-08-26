// A pane of glass over a key, broken to get at what is behind it. Decorative only, and it never holds up
// the reveal, since prefers-reduced-motion skips straight to the broken state and onBroken still runs.

import {useEffect, useRef, useState} from "react";
import {Box} from "@mantine/core";
import {IconKey} from "@tabler/icons-react";

const W = 220;
const H = 150;
const CX = W / 2;
const CY = H / 2;

// Outer edge of the pane, clockwise from the top left. Wedges run from the impact point out to each
// neighbouring pair, so the pane comes apart along the seams drawn on the intact glass.
const RIM: [number, number][] = [
    [0, 0], [46, 0], [88, 0], [132, 0], [180, 0], [W, 0],
    [W, 40], [W, 78], [W, 112], [W, H],
    [176, H], [130, H], [84, H], [40, H], [0, H],
    [0, 110], [0, 72], [0, 34],
];

// Deterministic scatter. Real randomness would change between the server and client renders.
function shard(i: number) {
    const [x1, y1] = RIM[i];
    const [x2, y2] = RIM[(i + 1) % RIM.length];
    const mx = (CX + x1 + x2) / 3;
    const my = (CY + y1 + y2) / 3;
    const dx = mx - CX;
    const dy = my - CY;
    const len = Math.hypot(dx, dy) || 1;
    const throwBy = 96 + ((i * 53) % 64);
    return {
        points: `${CX},${CY} ${x1},${y1} ${x2},${y2}`,
        tx: `${((dx / len) * throwBy).toFixed(1)}px`,
        ty: `${((dy / len) * throwBy - 12).toFixed(1)}px`,
        rot: `${(((i * 37) % 13) - 6) * 9}deg`,
        delay: `${(i % 5) * 22}ms`,
    };
}

const SHARDS = RIM.map((_, i) => shard(i));

export function GlassShatter({
                                 broken,
                                 onBroken,
                             }: {
    broken: boolean;
    /** Runs once the last shard has cleared, or immediately when motion is reduced. */
    onBroken?: () => void;
}) {
    const [gone, setGone] = useState(false);
    const fired = useRef(false);

    // Held in a ref because the caller rebuilds this callback every render. As a dependency it would cancel the
    // timer below on the next render the parent happens to do, and the fired guard then refuses to set another,
    // so the animation would end with nothing revealed.
    const onBrokenRef = useRef(onBroken);
    useEffect(() => {
        onBrokenRef.current = onBroken;
    }, [onBroken]);

    useEffect(() => {
        if (!broken || fired.current) return;
        fired.current = true;
        const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        const t = setTimeout(() => {
            setGone(true);
            onBrokenRef.current?.();
        }, reduced ? 0 : 820);
        return () => clearTimeout(t);
    }, [broken]);

    // A pane put back together is one the caller is reusing for another key, so the next break animates again.
    useEffect(() => {
        if (broken) return;
        fired.current = false;
        setGone(false);
    }, [broken]);

    return (
        <Box className="mm-shatter" aria-hidden>
            <div className={`mm-shatter-key${broken ? " mm-shatter-key-lit" : ""}`}>
                <IconKey size={54} stroke={1.4}/>
            </div>

            {!gone && (
                <svg className="mm-shatter-pane" viewBox={`0 0 ${W} ${H}`} width={W} height={H}>
                    <defs>
                        <linearGradient id="mm-shatter-fill" x1="0" y1="0" x2="1" y2="1">
                            <stop offset="0%" stopColor="rgba(255,255,255,0.62)"/>
                            <stop offset="45%" stopColor="rgba(214,232,255,0.34)"/>
                            <stop offset="100%" stopColor="rgba(255,255,255,0.52)"/>
                        </linearGradient>
                    </defs>
                    {SHARDS.map((s, i) => (
                        <polygon
                            key={i}
                            className={`mm-shatter-shard${broken ? " mm-shatter-shard-flying" : ""}`}
                            points={s.points}
                            fill="url(#mm-shatter-fill)"
                            stroke="rgba(255,255,255,0.85)"
                            strokeWidth={0.8}
                            style={
                                {
                                    "--mm-tx": s.tx,
                                    "--mm-ty": s.ty,
                                    "--mm-rot": s.rot,
                                    "--mm-delay": s.delay,
                                } as React.CSSProperties
                            }
                        />
                    ))}
                </svg>
            )}

            {broken && <div className="mm-shatter-flash"/>}
        </Box>
    );
}
