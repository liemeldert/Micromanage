// Canvas <-> flows.yaml helpers for the ATC visual editor. Node positions live
// in each node's ui:{x,y} so the *logic* stays diff-friendly / human-readable
// (the YAML is the source of truth, versioned via config history).

import type { Edge, Node } from "@xyflow/react";
import type { FlowDoc, FlowNode, FlowNodeSpec } from "../../../lib/api";

export type EdgeHandle = "next" | "on_true" | "on_false" | "on_timeout";
export const EDGE_HANDLES: EdgeHandle[] = ["next", "on_true", "on_false", "on_timeout"];

export const EDGE_LABEL: Record<EdgeHandle, string> = {
  next: "",
  on_true: "true",
  on_false: "false",
  on_timeout: "timeout",
};

export const EDGE_COLOR: Record<EdgeHandle, string> = {
  next: "#868e96",
  on_true: "#2f9e44",
  on_false: "#e03131",
  on_timeout: "#f08c00",
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
    priority: 100,
    trigger: { on: "enroll", match: {} },
    start: "",
    nodes: [],
  };
}

// A short human summary of a node's params, shown on the canvas card.
export function nodeSummary(node: FlowNode): string {
  const p = node.params ?? {};
  switch (node.type) {
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
    default:
      return "";
  }
}

function arr(v: unknown): string[] {
  return Array.isArray(v) ? v.map(String) : v ? [String(v)] : [];
}

// Client-side structural validation (fast feedback before the server validates
// on save). Mirrors the important flows.yaml checks; the server is authoritative.
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
  if (!flow.start || !byId.has(flow.start))
    errors.push("Set a start node (right-click a node → Set as start).");

  for (const n of flow.nodes) {
    const spec = specs[n.type];
    const handles = spec?.edges ?? [];
    for (const h of handles) {
      if (h === "on_timeout") continue; // optional
      const t = n[h];
      if (!t) errors.push(`Node "${n.id}" (${n.type}) needs its "${h}" edge wired.`);
      else if (!byId.has(String(t)))
        errors.push(`Node "${n.id}" "${h}" points to a missing node.`);
    }
    // per-type required params (light -- the server is authoritative)
    const p = n.params ?? {};
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
  // reachability is computed first, then cycle detection runs ONLY over the
  // reachable subgraph, and "no reachable end" is suppressed when a cycle is
  // found -- a cycle explains the missing end on its own).
  if (flow.start && byId.has(flow.start)) {
    const edges = new Map<string, string[]>();
    const seen = new Set<string>();
    const stack = [flow.start];
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
    if (!reachedEnd && cycles.length === 0) errors.push("No reachable end node from the start.");
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
