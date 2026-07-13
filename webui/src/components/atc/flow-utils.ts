// Canvas <-> flows.yaml helpers for the ATC visual editor. Node positions live
// in each node's ui:{x,y} so the *logic* stays diff-friendly / human-readable
// (the YAML is the source of truth, versioned via config history).

import type { Edge, Node } from "@xyflow/react";
import type { FlowDoc, FlowNode, FlowNodeSpec } from "../../../lib/api";

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

// The edge handles a node actually exposes (from its catalog spec, falling back
// to inference from the fields it has set so the run viewer works without it).
export function nodeEdges(node: FlowNode, spec?: FlowNodeSpec): EdgeHandle[] {
  if (spec) return spec.edges;
  return EDGE_HANDLES.filter((h) => node[h] != null);
}

// Build React Flow nodes + edges from a flow document.
export function flowToGraph(
  flow: FlowDoc,
  catalog: FlowNodeSpec[],
): { nodes: RFNode[]; edges: Edge[] } {
  const specs = specByType(catalog);
  const nodes: RFNode[] = (flow.nodes ?? []).map((n, i) => ({
    id: n.id,
    type: "atc",
    position: n.ui ?? { x: (i % 4) * 240, y: Math.floor(i / 4) * 160 },
    data: { node: n, spec: specs[n.type] },
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
          style: { stroke: EDGE_COLOR[h] },
          labelStyle: { fill: EDGE_COLOR[h], fontWeight: 600, fontSize: 11 },
        });
      }
    }
  }
  return { nodes, edges };
}

// Reconstruct a flow document's nodes from the canvas (positions + wiring),
// preserving each node's type/params from its data.
export function graphToNodes(rfNodes: RFNode[], rfEdges: Edge[]): FlowNode[] {
  return rfNodes.map((rf) => {
    const base = rf.data.node;
    const node: FlowNode = {
      id: rf.id,
      type: base.type,
      params: base.params ?? {},
      ui: { x: Math.round(rf.position.x), y: Math.round(rf.position.y) },
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

export function emptyFlow(id: string): FlowDoc {
  return {
    id,
    name: id,
    enabled: true,
    nodes: [],
  };
}

// True when a start node's match scope narrows which devices it applies to.
function scopeIsSet(match: unknown): boolean {
  if (!match || typeof match !== "object") return false;
  const m = match as Record<string, unknown>;
  return ["conditions", "groups", "include_devices", "exclude_devices"].some(
    (k) => Array.isArray(m[k]) && (m[k] as unknown[]).length > 0,
  );
}

// A short human summary of a node's params, shown on the canvas card.
const START_KIND_LABEL: Record<string, string> = {
  enroll_dep: "on DEP/ADE enroll",
  enroll_profile: "on OTA/manual enroll",
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

// Client-side structural validation (fast feedback before the server validates
// on save). Mirrors the important flows.yaml checks; the server is authoritative.
const START_KINDS = new Set(["enroll_dep", "enroll_profile", "checkin", "schedule"]);
const GATE_EDGES = new Set(["on_release", "on_cancel", "on_wait"]);

export function validateFlowClient(flow: FlowDoc, catalog: FlowNodeSpec[]): string[] {
  const errors: string[] = [];
  const specs = specByType(catalog);
  const byId = new Map(flow.nodes.map((n) => [n.id, n]));
  if (!flow.id || !/^[a-z0-9-_]+$/.test(flow.id))
    errors.push("Flow id must be a slug (lowercase letters, digits, - and _).");
  if (!flow.nodes.length) {
    errors.push("Add at least one node.");
    return errors;
  }

  const starts = flow.nodes.filter((n) => n.type === "start");
  if (!starts.length)
    errors.push("Add at least one start node (an entry point: enrollment, check-in or schedule).");

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
      if (!t) errors.push(`Node "${n.id}" (${n.type}) needs its "${h}" edge wired.`);
      else if (!byId.has(String(t)))
        errors.push(`Node "${n.id}" "${h}" points to a missing node.`);
    }

    // per-type required params (light -- the server is authoritative)
    if (n.type === "start") {
      if (!START_KINDS.has(String(p.kind)))
        errors.push(`Start node "${n.id}" needs a trigger kind.`);
      if (p.kind === "schedule") {
        const iv = p.interval_minutes;
        if (typeof iv !== "number" || iv <= 0)
          errors.push(`Scheduled start "${n.id}" needs a positive interval (minutes).`);
      }
    }
    if (n.type === "manual_gate") {
      if (!String(p.summary ?? "").trim())
        errors.push(`Gate "${n.id}" needs an alert summary.`);
      const opts = Array.isArray(p.options) ? (p.options as { label?: string; edge?: string }[]) : [];
      if (!opts.some((o) => o?.label && GATE_EDGES.has(String(o?.edge))))
        errors.push(`Gate "${n.id}" needs at least one decision option.`);
    }
    if ((n.type === "assign_tag" || n.type === "remove_tag") && !arr(p.tags).length)
      errors.push(`Node "${n.id}" needs at least one tag.`);
    if (n.type === "set_name" && !String(p.template ?? "").trim())
      errors.push(`Node "${n.id}" needs a name template.`);
    if (n.type === "install_profiles" && !arr(p.profile_ids).length)
      errors.push(`Node "${n.id}" needs at least one profile.`);
    if (n.type === "install_apps" && !arr(p.app_ids).length)
      errors.push(`Node "${n.id}" needs at least one app.`);
    if (n.type === "send_command" && !p.command)
      errors.push(`Node "${n.id}" needs a command.`);
    if (n.type === "wait_for" && !p.signal)
      errors.push(`Node "${n.id}" needs a signal to wait for.`);
  }

  // reachable end + cycle check (best-effort; mirrors the server's
  // controller/utils/yaml_validator.py _check_flow_graph / _find_cycle_edges:
  // union reachability from ALL start nodes is computed first, then cycle
  // detection runs ONLY over the reachable subgraph, and "no reachable end" is
  // suppressed when a cycle is found -- a cycle explains the missing end).
  if (starts.length) {
    const edges = new Map<string, string[]>();
    const seen = new Set<string>();
    const stack = starts.map((s) => s.id);
    let reachedEnd = false;
    while (stack.length) {
      const id = stack.pop()!;
      if (seen.has(id)) continue;
      seen.add(id);
      const n = byId.get(id)!;
      if (n.type === "end") reachedEnd = true;
      const targets: string[] = [];
      for (const h of EDGE_HANDLES) {
        const t = n[h];
        if (typeof t === "string" && byId.has(t)) {
          targets.push(t);
          if (!seen.has(t)) stack.push(t);
        }
      }
      edges.set(id, targets);
    }

    const cycles = findCycleEdges(edges);
    for (const [node, ref] of cycles) {
      errors.push(`Flow has a cycle involving '${node}' and '${ref}' — flows must be acyclic.`);
    }
    if (!reachedEnd && cycles.length === 0) errors.push("No reachable end node from a start.");
  }
  return errors;
}

// Back-edges (node, ref) that make `edges` cyclic, via an iterative 3-color DFS
// (WHITE/GRAY/BLACK). Mirrors controller/utils/yaml_validator.py
// _find_cycle_edges exactly so the client can't drift from the server: a
// GRAY->GRAY edge (a ref still on the current DFS stack) is a back-edge/cycle;
// refs not present as keys in `edges` are ignored (dangling refs are reported
// elsewhere).
function findCycleEdges(edges: Map<string, string[]>): [string, string][] {
  const WHITE = 0, GRAY = 1, BLACK = 2;
  const color = new Map<string, number>();
  for (const n of edges.keys()) color.set(n, WHITE);
  const back: [string, string][] = [];

  for (const root of edges.keys()) {
    if (color.get(root) !== WHITE) continue;
    const stack: { node: string; idx: number }[] = [{ node: root, idx: 0 }];
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
          stack.push({ node: ref, idx: 0 });
          advanced = true;
          break;
        }
      }
      // Loop exhausted with no WHITE ref pushed (mirrors Python's `for...else`
      // via the `advanced` flag): this node is fully explored -> BLACK, pop.
      if (!advanced) {
        color.set(frame.node, BLACK);
        stack.pop();
      }
    }
  }
  return back;
}
