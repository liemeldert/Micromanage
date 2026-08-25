// A still picture of a flow's graph: one small rectangle per block at its stored position, thin lines
// for the edges. Plain SVG, so a page can carry one per card where a real canvas could not.

import {Box, Text} from "@mantine/core";
import type {FlowNode} from "../../../lib/api";

const WIDTH = 280;
const HEIGHT = 96;
const PAD = 8;
const NODE_W = 16;
const NODE_H = 8;

// Every handle a block can wire from. Whatever one points at becomes a line.
const HANDLES = ["next", "on_true", "on_false", "on_timeout", "on_release", "on_cancel", "on_wait"] as const;

interface Placed {
    id: string;
    x: number;
    y: number;
    start: boolean;
}

/** Stored canvas positions, scaled and centred to fit the box. One scale for both axes, so the
 * picture keeps the proportions the author laid out. */
function place(nodes: FlowNode[]): Placed[] {
    const raw = nodes.map((node, i) => ({
        id: node.id,
        // A block the canvas never laid out has no position, so it takes a slot in a row.
        x: node.ui?.x ?? i * 240,
        y: node.ui?.y ?? 0,
        start: node.type === "start",
    }));
    const xs = raw.map((n) => n.x);
    const ys = raw.map((n) => n.y);
    const minX = Math.min(...xs);
    const minY = Math.min(...ys);
    const spanX = Math.max(...xs) - minX;
    const spanY = Math.max(...ys) - minY;
    const innerW = WIDTH - PAD * 2 - NODE_W;
    const innerH = HEIGHT - PAD * 2 - NODE_H;
    const scale = Math.min(spanX > 0 ? innerW / spanX : innerW, spanY > 0 ? innerH / spanY : innerH);
    const offX = (WIDTH - NODE_W - spanX * scale) / 2;
    const offY = (HEIGHT - NODE_H - spanY * scale) / 2;
    return raw.map((n) => ({
        ...n,
        x: offX + (n.x - minX) * scale,
        y: offY + (n.y - minY) * scale,
    }));
}

export function FlowThumbnail({nodes, muted}: { nodes: FlowNode[]; muted?: boolean }) {
    if (nodes.length === 0) {
        return (
            <Box
                h={HEIGHT}
                style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    borderRadius: "var(--mantine-radius-sm)",
                    background: "var(--mantine-color-default-hover)",
                }}
            >
                <Text fz="xs" c="dimmed">No blocks yet</Text>
            </Box>
        );
    }

    const placed = place(nodes);
    const byId = new Map(placed.map((n) => [n.id, n]));
    const lines: { key: string; x1: number; y1: number; x2: number; y2: number }[] = [];
    for (const node of nodes) {
        const from = byId.get(node.id);
        if (!from) continue;
        for (const handle of HANDLES) {
            const targetId = node[handle];
            if (!targetId) continue;
            const to = byId.get(targetId);
            if (!to) continue;
            lines.push({
                key: `${node.id}:${handle}`,
                x1: from.x + NODE_W,
                y1: from.y + NODE_H / 2,
                x2: to.x,
                y2: to.y + NODE_H / 2,
            });
        }
    }

    const accent = muted ? "gray" : "blue";
    const nodeFill = `var(--mantine-color-${accent}-light)`;
    const nodeStroke = `var(--mantine-color-${accent}-light-color)`;
    const startFill = muted ? "var(--mantine-color-gray-light)" : "var(--mantine-color-teal-light)";
    const startStroke = muted
        ? "var(--mantine-color-gray-light-color)"
        : "var(--mantine-color-teal-light-color)";

    return (
        <Box
            style={{
                borderRadius: "var(--mantine-radius-sm)",
                background: "var(--mantine-color-default-hover)",
                overflow: "hidden",
            }}
        >
            <svg
                viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
                width="100%"
                height={HEIGHT}
                role="img"
                aria-label={`${nodes.length} blocks`}
                preserveAspectRatio="xMidYMid meet"
            >
                {lines.map((l) => (
                    <line
                        key={l.key}
                        x1={l.x1}
                        y1={l.y1}
                        x2={l.x2}
                        y2={l.y2}
                        stroke="var(--mantine-color-dimmed)"
                        strokeWidth={1}
                        strokeOpacity={0.55}
                    />
                ))}
                {placed.map((n) => (
                    <rect
                        key={n.id}
                        x={n.x}
                        y={n.y}
                        width={NODE_W}
                        height={NODE_H}
                        rx={2.5}
                        fill={n.start ? startFill : nodeFill}
                        stroke={n.start ? startStroke : nodeStroke}
                        strokeWidth={1}
                    />
                ))}
            </svg>
        </Box>
    );
}
