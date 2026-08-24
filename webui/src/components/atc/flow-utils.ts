// Canvas and flows.yaml conversion for the ATC visual editor. Node positions live in each node's ui:{x,y}, which
// keeps the rest of the YAML readable in a diff. The YAML is the source of truth, versioned through config history.

import type {Edge, Node} from "@xyflow/react";
import type {FlowDoc, FlowNode, FlowNodeSpec, FlowsConfig, StartKind} from "../../../lib/api";

export type EdgeHandle =
    | "next"
    | "on_true"
    | "on_false"
    | "on_timeout"
    | "on_release"
    | "on_cancel"
    | "on_wait";
export const EDGE_HANDLES: EdgeHandle[] = [
    "next",
    "on_true",
    "on_false",
    "on_timeout",
    "on_release",
    "on_cancel",
    "on_wait",
];

export const EDGE_LABEL: Record<EdgeHandle, string> = {
    next: "",
    on_true: "true",
    on_false: "false",
    on_timeout: "timeout",
    on_release: "release",
    on_cancel: "cancel",
    on_wait: "wait",
};

export const EDGE_COLOR: Record<EdgeHandle, string> = {
    next: "#868e96",
    on_true: "#2f9e44",
    on_false: "#e03131",
    on_timeout: "#f08c00",
    on_release: "#2f9e44",
    on_cancel: "#e03131",
    on_wait: "#4c6ef5",
};

// Mantine colour per palette category (chip / node accent).
export const CATEGORY_COLOR: Record<string, string> = {
    Tags: "grape",
    Naming: "blue",
    Deploy: "teal",
    Command: "orange",
    Flow: "indigo",
};

export interface FlowNodeData extends Record<string, unknown> {
    node: FlowNode;
    spec?: FlowNodeSpec;
}

export type RFNode = Node<FlowNodeData>;

function specByType(catalog: FlowNodeSpec[]): Record<string, FlowNodeSpec> {
    return Object.fromEntries(catalog.map((s) => [s.type, s]));
}

// The edge handles a node exposes. Without a catalog spec they are inferred from the fields the node has set, so the
// run viewer works without loading the catalog.
export function nodeEdges(node: FlowNode, spec?: FlowNodeSpec): EdgeHandle[] {
    if (spec) return spec.edges;
    return EDGE_HANDLES.filter((h) => node[h] != null);
}

// Roughly what FlowNodeCard renders at. Only ever a pre-measure hint.
const NODE_CARD_WIDTH = 180;
const NODE_CARD_HEIGHT = 78;

// Build React Flow nodes + edges from a flow document.
export function flowToGraph(
    flow: FlowDoc,
    catalog: FlowNodeSpec[],
): { nodes: RFNode[]; edges: Edge[] } {
    const specs = specByType(catalog);
    const nodes: RFNode[] = (flow.nodes ?? []).map((n, i) => ({
        id: n.id,
        type: "atc",
        position: n.ui ?? {x: (i % 4) * 240, y: Math.floor(i / 4) * 160},
        // Hints, not sizes: React Flow prefers its measured box wherever it has one. The run viewer holds its own
        // nodes and never feeds dimension changes back, so without these its MiniMap draws an empty frame.
        initialWidth: NODE_CARD_WIDTH,
        initialHeight: NODE_CARD_HEIGHT,
        data: {node: n, spec: specs[n.type]},
    }));

    const ids = new Set(nodes.map((n) => n.id));
    const edges: Edge[] = [];
    for (const n of flow.nodes ?? []) {
        for (const h of EDGE_HANDLES) {
            const target = n[h];
            if (typeof target === "string" && ids.has(target)) {
                edges.push({
                    id: `${n.id}::${h}::${target}`,
                    source: n.id,
                    target,
                    sourceHandle: h,
                    label: EDGE_LABEL[h] || undefined,
                    style: {stroke: EDGE_COLOR[h]},
                    labelStyle: {fill: EDGE_COLOR[h], fontWeight: 600, fontSize: 11},
                });
            }
        }
    }
    return {nodes, edges};
}

// Rebuild a flow document's nodes from the canvas positions and wiring, keeping each node's type and params.
export function graphToNodes(rfNodes: RFNode[], rfEdges: Edge[]): FlowNode[] {
    return rfNodes.map((rf) => {
        const base = rf.data.node;
        const node: FlowNode = {
            id: rf.id,
            type: base.type,
            params: base.params ?? {},
            ui: {x: Math.round(rf.position.x), y: Math.round(rf.position.y)},
        };
        for (const h of EDGE_HANDLES) {
            const e = rfEdges.find((ed) => ed.source === rf.id && ed.sourceHandle === h);
            if (e) node[h] = e.target;
        }
        return node;
    });
}

let _counter = 0;

export function newNodeId(type: string, existing: Set<string>): string {
    let id = `${type}-${(_counter += 1)}`;
    while (existing.has(id)) id = `${type}-${(_counter += 1)}`;
    return id;
}

export function emptyFlow(id: string, name?: string, description?: string): FlowDoc {
    return {
        id,
        name: name || id,
        description: description || "",
        enabled: true,
        nodes: [],
    };
}

export function defaultEnrollmentFlow(): FlowDoc {
    return {
        id: "enrollment",
        name: "Device enrollment",
        description: "Runs when a device enrolls. Provisions it and releases it from Setup Assistant.",
        enabled: true,
        permanent: true,
        nodes: [
            {
                id: "start-dep",
                type: "start",
                params: {kind: "enroll_dep"},
                next: "await-info",
                ui: {x: -240, y: 0},
            },
            {
                id: "start-ota",
                type: "start",
                params: {kind: "enroll_profile"},
                next: "await-info",
                ui: {x: -240, y: 120},
            },
            {
                id: "await-info",
                type: "wait_for",
                params: {signal: "device_info", timeout_minutes: 30, gate: false},
                next: "release",
                on_timeout: "gate-stuck",
                ui: {x: 0, y: 60},
            },
            {
                id: "gate-stuck",
                type: "manual_gate",
                params: {
                    severity: "yellow",
                    summary: "Device has not reported in after enrollment",
                    options: [
                        {label: "Release device", edge: "on_release"},
                        {label: "Cancel onboarding", edge: "on_cancel"},
                        {label: "Keep waiting", edge: "on_wait"},
                    ],
                },
                on_release: "release",
                on_cancel: "done",
                on_wait: "release",
                ui: {x: 240, y: 140},
            },
            {
                id: "release",
                type: "release_device",
                next: "done",
                ui: {x: 240, y: 0},
            },
            {
                id: "done",
                type: "end",
                ui: {x: 480, y: 60},
            },
        ],
    };
}

// The server validates a flow id against ^[a-z0-9-_]+$ (yaml_validator.Flow); checking it here catches a bad id
// before the create dialog submits.
export const ADMIN_ONLY_REASON =
    "A flow acts on devices on its own, so authoring one is admin-only.";

export const FLOW_ID_RE = /^[a-z0-9_-]+$/;

/** A flow id derived from a display name, filled in by the create dialog as you type. Lowercased, with runs of
 * anything else collapsed to single hyphens, so the result always passes the server's check. */
export function slugifyFlowId(name: string): string {
    return name
        .toLowerCase()
        .normalize("NFKD")
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 60);
}

/** Why this id cannot be used, or null when it can. */
export function flowIdError(id: string, takenIds: string[] = []): string | null {
    const value = id.trim();
    if (!value) return "An id is required.";
    if (!FLOW_ID_RE.test(value)) {
        return "Use lowercase letters, digits, hyphens and underscores only.";
    }
    if (value.endsWith(DRAFT_SUFFIX)) {
        return `Ids ending in "${DRAFT_SUFFIX}" are reserved for drafts.`;
    }
    if (takenIds.includes(value)) return "Another flow already has this id.";
    return null;
}

export const DRAFT_SUFFIX = "--draft";

/** The flow list of a config document. Handles legacy single-flow format and server normalization. */
export function flowsFromConfig(cfg: FlowsConfig | null | undefined): FlowDoc[] {
    if (!cfg) return [];
    if (Array.isArray(cfg.flows)) return cfg.flows;
    const legacy = (cfg as { flow?: FlowDoc }).flow;
    if (legacy) return [{...legacy, permanent: true}];
    return [];
}

export function isDraftFlow(flow: FlowDoc): boolean {
    return Boolean(flow.draft_of);
}

export function isEnrollmentFlow(flow: FlowDoc, doc?: FlowsConfig | null): boolean {
    if (flow.permanent === true && !flow.draft_of) return true;
    if (flow.draft_of && doc?.flows) {
        const target = doc.flows.find((f) => f.id === flow.draft_of);
        if (target && target.permanent === true) return true;
    }
    return false;
}

export function paletteForFlow(
    catalog: FlowNodeSpec[],
    flow: FlowDoc,
    doc?: FlowsConfig | null,
): FlowNodeSpec[] {
    if (isEnrollmentFlow(flow, doc)) return catalog;
    return catalog.filter((spec) => spec.scope !== "enrollment" && spec.type !== "release_device" && spec.type !== "configure_accounts");
}

export function startKindsForFlow(
    kinds: StartKind[],
    flow: FlowDoc,
    doc?: FlowsConfig | null,
): StartKind[] {
    if (isEnrollmentFlow(flow, doc)) return kinds;
    return kinds.filter((k) => k.scope !== "enrollment" && k.value !== "enroll_dep" && k.value !== "enroll_profile");
}

// True when a start node's match scope narrows which devices it applies to.
function scopeIsSet(match: unknown): boolean {
    if (!match || typeof match !== "object") return false;
    const m = match as Record<string, unknown>;
    return ["conditions", "groups", "include_devices", "exclude_devices"].some(
        (k) => Array.isArray(m[k]) && (m[k] as unknown[]).length > 0,
    );
}

// Short summary of a node's params, shown on the canvas card.
const START_KIND_LABEL: Record<string, string> = {
    enroll_dep: "on automated enroll",
    enroll_profile: "on manual enroll",
    checkin: "on check-in",
    schedule: "on schedule",
};

export function nodeSummary(node: FlowNode): string {
    const p = node.params ?? {};
    switch (node.type) {
        case "start": {
            const kind = String(p.kind ?? "");
            const label = START_KIND_LABEL[kind] ?? kind ?? "?";
            const iv = kind === "schedule" && p.interval_minutes ? ` every ${p.interval_minutes}m` : "";
            return `${label}${iv}${scopeIsSet(p.match) ? " · scoped" : ""}`;
        }
        case "manual_gate":
            return String(p.summary ?? "");
        case "assign_tag":
        case "remove_tag":
            return arr(p.tags).join(", ");
        case "set_name":
            return String(p.template ?? "");
        case "install_profiles":
            return arr(p.profile_ids).join(", ");
        case "install_apps":
            return arr(p.app_ids).join(", ");
        case "send_command":
            return String(p.command ?? "");
        case "branch": {
            const c = p.condition as { type?: string } | undefined;
            return c?.type ? `if ${c.type}…` : "condition";
        }
        case "wait_for":
            return `${p.signal ?? "?"} (${p.timeout_minutes ?? "?"}m)`;
        case "release_device":
            return "DeviceConfigured";
        default:
            return "";
    }
}

function arr(v: unknown): string[] {
    return Array.isArray(v) ? v.map(String) : v ? [String(v)] : [];
}

// Structural validation on the client, for feedback before the save. Mirrors the important flows.yaml checks, but
// the server is authoritative.
const START_KINDS = new Set(["enroll_dep", "enroll_profile", "checkin", "schedule"]);
const GATE_EDGES = new Set(["on_release", "on_cancel", "on_wait"]);

/** One problem with the document, carrying the node it is about. Flow-level issues have no nodeId. */
export interface FlowIssue {
    nodeId?: string;
    message: string;
}

/** Issue messages grouped by the node they belong to, for the canvas decoration pass.
 * Flow-level issues have no node to hang on and are dropped here. */
export function issuesByNode(issues: FlowIssue[]): Record<string, string[]> {
    const byNode: Record<string, string[]> = {};
    for (const issue of issues) {
        if (issue.nodeId) (byNode[issue.nodeId] ??= []).push(issue.message);
    }
    return byNode;
}

// What an edge handle is called in a sentence. The canvas leaves "next" unlabelled, but prose needs a word for it.
function handleName(h: EdgeHandle): string {
    return EDGE_LABEL[h] || "next";
}

export function validateFlowClient(flow: FlowDoc, catalog: FlowNodeSpec[]): FlowIssue[] {
    const errors: FlowIssue[] = [];
    const specs = specByType(catalog);
    const byId = new Map(flow.nodes.map((n) => [n.id, n]));
    if (!flow.id || !/^[a-z0-9-_]+$/.test(flow.id))
        errors.push({message: "Flow id must be a slug (lowercase letters, digits, - and _)."});
    if (!flow.nodes.length) {
        errors.push({message: "Add at least one node."});
        return errors;
    }

    const starts = flow.nodes.filter((n) => n.type === "start");
    if (!starts.length)
        errors.push({message: "Add at least one start node (an entry point: enrollment, check-in or schedule)."});

    for (const n of flow.nodes) {
        const spec = specs[n.type];
        const p = n.params ?? {};

        // Required edges. A manual_gate only requires the handles its options name.
        let required: EdgeHandle[];
        if (n.type === "manual_gate") {
            const opts = Array.isArray(p.options) ? (p.options as { edge?: string }[]) : [];
            required = opts
                .map((o) => o?.edge)
                .filter((e): e is EdgeHandle => typeof e === "string" && GATE_EDGES.has(e));
        } else {
            required = (spec?.edges ?? []).filter((h) => h !== "on_timeout") as EdgeHandle[];
        }
        for (const h of required) {
            const t = n[h];
            if (!t)
                errors.push({
                    nodeId: n.id,
                    message: `The "${handleName(h)}" output is not wired, so the flow stops here.`,
                });
            else if (!byId.has(String(t)))
                errors.push({
                    nodeId: n.id,
                    message: `The "${handleName(h)}" output points to a node that is no longer on the canvas.`,
                });
        }

        // per-type required params
        const at = (message: string) => errors.push({nodeId: n.id, message});
        if (n.type === "start") {
            if (!START_KINDS.has(String(p.kind))) at("Pick what triggers this start.");
            if (p.kind === "schedule") {
                const iv = p.interval_minutes;
                if (typeof iv !== "number" || iv <= 0)
                    at("Set how often this runs, as a positive number of minutes.");
            }
        }
        if (n.type === "manual_gate") {
            if (!String(p.summary ?? "").trim()) at("Write the alert summary an operator will see.");
            const opts = Array.isArray(p.options) ? (p.options as { label?: string; edge?: string }[]) : [];
            if (!opts.some((o) => o?.label && GATE_EDGES.has(String(o?.edge))))
                at("Add at least one decision option.");
        }
        if ((n.type === "assign_tag" || n.type === "remove_tag") && !arr(p.tags).length)
            at("Choose at least one tag.");
        if (n.type === "set_name" && !String(p.template ?? "").trim()) at("Write a name template.");
        if (n.type === "install_profiles" && !arr(p.profile_ids).length) at("Choose at least one profile.");
        if (n.type === "install_apps" && !arr(p.app_ids).length) at("Choose at least one app.");
        if (n.type === "send_command" && !p.command) at("Choose a command to send.");
        if (n.type === "wait_for" && !p.signal) at("Choose a signal to wait for.");
    }

    // Reachable end and cycle check, mirroring _check_flow_graph and _find_cycle_edges in
    // controller/utils/yaml_validator.py.
    if (starts.length) {
        const adjacency = new Map<string, string[]>();
        for (const n of flow.nodes) {
            const targets: string[] = [];
            for (const h of EDGE_HANDLES) {
                const t = n[h];
                if (typeof t === "string" && byId.has(t)) targets.push(t);
            }
            adjacency.set(n.id, targets);
        }
        const reach = (from: string[]): Set<string> => {
            const seen = new Set<string>();
            const stack = [...from];
            while (stack.length) {
                const id = stack.pop()!;
                if (seen.has(id)) continue;
                seen.add(id);
                for (const t of adjacency.get(id) ?? []) if (!seen.has(t)) stack.push(t);
            }
            return seen;
        };

        const reachable = reach(starts.map((s) => s.id));
        const reachableEdges = new Map<string, string[]>();
        for (const id of reachable) {
            reachableEdges.set(id, (adjacency.get(id) ?? []).filter((t) => reachable.has(t)));
        }

        const cycles = findCycleEdges(reachableEdges);
        for (const [node, ref] of cycles) {
            errors.push({
                nodeId: node,
                message: `This node loops back to "${ref}", so the flow can never finish. Flows must be acyclic.`,
            });
        }
        if (cycles.length === 0) {
            for (const s of starts) {
                const endsHere = [...reach([s.id])].some((id) => byId.get(id)?.type === "end");
                if (!endsHere)
                    errors.push({
                        nodeId: s.id,
                        message: "Nothing this start reaches is an End block, so a run from here never finishes.",
                    });
            }
        }
    }
    return errors;
}

// == Save-time confirmation triggers ==

/** One reason the save has to be confirmed rather than going through on one click. kind is the start kind that
 * produced it, or "server" for a warning from the dry-run validate; the modal renders both sources as one list. */
export interface SaveGuardReason {
    nodeId?: string;
    kind: string;
    message: string;
    /** The start's match scope, so the modal can ask the server how many devices it matches. Server reasons are
     * about the graph and carry none. */
    match?: Record<string, unknown>;
}

/** Broad-scope starts that need confirmation before save. This is a client-side approximation only. */
export function saveGuardReasons(flow: FlowDoc): SaveGuardReason[] {
    // A disabled flow has no live trigger, so saving it changes nothing on any device.
    if (flow.enabled === false) return [];
    const reasons: SaveGuardReason[] = [];
    for (const n of flow.nodes ?? []) {
        if (n.type !== "start") continue;
        const p = n.params ?? {};
        const kind = String(p.kind ?? "");
        // A start without a valid kind never runs, and fails validation on save.
        if (!START_KINDS.has(kind)) continue;
        if (scopeIsSet(p.match)) continue;
        reasons.push({
            nodeId: n.id,
            kind,
            message: broadStartMessage(n.id, kind, p),
            // Sent to the count endpoint as authored. Empty by definition here, and passed through anyway so the
            // count stays right if this check ever reaches a scoped start.
            match:
                p.match && typeof p.match === "object" && !Array.isArray(p.match)
                    ? (p.match as Record<string, unknown>)
                    : {},
        });
    }
    return reasons;
}

// One sentence per trigger kind, carrying no count so the modal can show it without waiting on anything.
// FlowSaveConfirmModal adds the device count from the preview endpoint underneath when it arrives.
function broadStartMessage(id: string, kind: string, p: Record<string, unknown>): string {
    const head = `Start "${id}" has no scope.`;
    switch (kind) {
        case "enroll_dep":
            return `${head} After you save, this flow runs on every device that enrolls through Automated Device Enrollment.`;
        case "enroll_profile":
            return `${head} After you save, this flow runs on every device that enrolls manually or over the air.`;
        case "checkin":
            return `${head} After you save, this flow runs on every device in the fleet at every check-in.`;
        case "schedule": {
            const iv = p.interval_minutes;
            const every =
                typeof iv === "number" && iv > 0
                    ? iv === 1
                        ? "every minute"
                        : `every ${iv} minutes`
                    : "on its schedule";
            return `${head} After you save, this flow runs on every device in the fleet ${every}.`;
        }
        default:
            return `${head} After you save, this flow runs on every device its trigger sees.`;
    }
}

// Find cycles via iterative 3-color DFS, mirroring _find_cycle_edges in controller/utils/yaml_validator.py.
function findCycleEdges(edges: Map<string, string[]>): [string, string][] {
    const WHITE = 0, GRAY = 1, BLACK = 2;
    const color = new Map<string, number>();
    for (const n of edges.keys()) color.set(n, WHITE);
    const back: [string, string][] = [];

    for (const root of edges.keys()) {
        if (color.get(root) !== WHITE) continue;
        const stack: { node: string; idx: number }[] = [{node: root, idx: 0}];
        color.set(root, GRAY);
        while (stack.length) {
            const frame = stack[stack.length - 1];
            const targets = edges.get(frame.node) ?? [];
            let advanced = false;
            while (frame.idx < targets.length) {
                const ref = targets[frame.idx];
                frame.idx += 1;
                if (!color.has(ref)) continue; // dangling ref, reported elsewhere
                const refColor = color.get(ref);
                if (refColor === GRAY) {
                    back.push([frame.node, ref]);
                    continue;
                }
                if (refColor === WHITE) {
                    color.set(ref, GRAY);
                    stack.push({node: ref, idx: 0});
                    advanced = true;
                    break;
                }
            }
            // Loop exhausted with no WHITE ref pushed, which the advanced flag stands in for (Python's for...else):
            // this node is fully explored, so BLACK and pop.
            if (!advanced) {
                color.set(frame.node, BLACK);
                stack.pop();
            }
        }
    }
    return back;
}
