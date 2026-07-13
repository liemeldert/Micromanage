"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  addEdge,
  Background,
  Controls,
  Handle,
  MiniMap,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  type Connection,
  type Edge,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  ActionIcon,
  Badge,
  Box,
  Button,
  Group,
  Paper,
  ScrollArea,
  Stack,
  Text,
  Tooltip,
} from "@mantine/core";
import { IconTrash, IconX } from "@tabler/icons-react";
import type {
  CatalogCommand,
  Device,
  FlowNode as FlowNodeT,
  FlowNodeSpec,
  StartKind,
} from "../../../lib/api";
import type { Group as GroupDef } from "../../../lib/config";
import { NodeInspector } from "./NodeInspector";
import {
  CATEGORY_COLOR,
  EDGE_COLOR,
  EDGE_LABEL,
  flowToGraph,
  graphToNodes,
  newNodeId,
  nodeEdges,
  nodeSummary,
  type EdgeHandle,
  type FlowNodeData,
  type RFNode,
} from "./flow-utils";

const MANTINE_HEX: Record<string, string> = {
  grape: "#ae3ec9",
  blue: "#1971c2",
  teal: "#0ca678",
  orange: "#e8590c",
  indigo: "#3b5bdb",
};

// ── Custom canvas node ───────────────────────────────────────────────────────
export function FlowNodeCard({ data, selected }: NodeProps) {
  const d = data as FlowNodeData;
  const node = d.node;
  const spec = d.spec;
  const isStart = node.type === "start";
  const highlight = d.highlight as "visited" | "current" | undefined;
  const color = MANTINE_HEX[CATEGORY_COLOR[spec?.category ?? "Flow"] ?? "indigo"] ?? "#3b5bdb";
  const handles = nodeEdges(node, spec);
  const summary = nodeSummary(node);

  const border = selected
    ? `2px solid ${color}`
    : highlight === "current"
      ? "2px solid #f08c00"
      : highlight === "visited"
        ? "2px solid #2f9e44"
        : "1px solid var(--mantine-color-dark-4)";

  return (
    <div
      style={{
        borderRadius: 8,
        border,
        background: "var(--mantine-color-dark-7, #25262b)",
        minWidth: 150,
        opacity: highlight === undefined && d.dim ? 0.5 : 1,
        boxShadow: highlight === "current" ? "0 0 0 4px rgba(240,140,0,0.2)" : undefined,
      }}
    >
      {/* every node has a target (entry) handle except a start node, which is
          itself an entry point and is only ever wired FROM */}
      {!isStart && <Handle type="target" position={Position.Top} style={{ background: color }} />}
      <Box px="sm" py={6} style={{ borderBottom: "1px solid var(--mantine-color-dark-4)" }}>
        <Group gap={6} justify="space-between" wrap="nowrap">
          <Group gap={6} wrap="nowrap">
            <Box style={{ width: 8, height: 8, borderRadius: 8, background: color }} />
            <Text fz="xs" fw={700} truncate>
              {spec?.label ?? node.type}
            </Text>
          </Group>
          {isStart && (
            <Badge size="xs" color="yellow" variant="light">
              start
            </Badge>
          )}
        </Group>
      </Box>
      <Box px="sm" py={4}>
        <Text fz={10} c="dimmed">
          {node.id}
        </Text>
        {summary && (
          <Text fz={11} lineClamp={2}>
            {summary}
          </Text>
        )}
      </Box>

      {/* one source handle per outgoing edge type, spread along the bottom */}
      {handles.map((h, i) => {
        const left = handles.length === 1 ? 50 : (100 / (handles.length + 1)) * (i + 1);
        return (
          <Handle
            key={h}
            id={h}
            type="source"
            position={Position.Bottom}
            style={{ left: `${left}%`, background: EDGE_COLOR[h] }}
          >
            {h !== "next" && (
              <span
                style={{
                  position: "absolute",
                  top: 6,
                  left: -6,
                  fontSize: 9,
                  color: EDGE_COLOR[h],
                  pointerEvents: "none",
                }}
              >
                {EDGE_LABEL[h]}
              </span>
            )}
          </Handle>
        );
      })}
    </div>
  );
}

const nodeTypes = { atc: FlowNodeCard };

// ── Editor ───────────────────────────────────────────────────────────────────
export interface FlowEditorOptions {
  tagNames: string[];
  profileIds: string[];
  appIds: string[];
  commands: CatalogCommand[];
  groupNames: string[];
  devices: Device[];
  allGroups: GroupDef[];
  startKinds: StartKind[];
}

export function FlowEditor(props: {
  flowId: string; // re-init the canvas when the flow id changes
  initialNodes: FlowNodeT[];
  catalog: FlowNodeSpec[];
  options: FlowEditorOptions;
  onChange: (patch: { nodes: FlowNodeT[] }) => void;
}) {
  return (
    <ReactFlowProvider>
      <FlowEditorInner {...props} />
    </ReactFlowProvider>
  );
}

function FlowEditorInner({
  flowId,
  initialNodes,
  catalog,
  options,
  onChange,
}: {
  flowId: string;
  initialNodes: FlowNodeT[];
  catalog: FlowNodeSpec[];
  options: FlowEditorOptions;
  onChange: (patch: { nodes: FlowNodeT[] }) => void;
}) {
  const initial = useMemo(
    () => flowToGraph({ id: flowId, name: flowId, nodes: initialNodes }, catalog),
    // rebuild only when the flow id changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [flowId],
  );

  const [nodes, setNodes, onNodesChange] = useNodesState<RFNode>(initial.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>(initial.edges);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Re-initialise when the flow id changes.
  const lastFlow = useRef(flowId);
  useEffect(() => {
    if (lastFlow.current === flowId) return;
    lastFlow.current = flowId;
    const g = flowToGraph({ id: flowId, name: flowId, nodes: initialNodes }, catalog);
    setNodes(g.nodes);
    setEdges(g.edges);
    setSelectedId(null);
  }, [flowId, initialNodes, catalog, setNodes, setEdges]);

  // Emit changes upward (positions, wiring, params).
  useEffect(() => {
    onChange({ nodes: graphToNodes(nodes, edges) });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, edges]);

  const decorated = nodes;

  const onConnect = useCallback(
    (c: Connection) => {
      const handle = (c.sourceHandle ?? "next") as EdgeHandle;
      setEdges((eds) => {
        // Each source handle wires to exactly one target: replace any existing.
        const pruned = eds.filter((e) => !(e.source === c.source && e.sourceHandle === handle));
        return addEdge(
          {
            ...c,
            id: `${c.source}::${handle}::${c.target}`,
            sourceHandle: handle,
            label: EDGE_LABEL[handle] || undefined,
            style: { stroke: EDGE_COLOR[handle] },
            labelStyle: { fill: EDGE_COLOR[handle], fontWeight: 600, fontSize: 11 },
          },
          pruned,
        );
      });
    },
    [setEdges],
  );

  const addNode = useCallback(
    (spec: FlowNodeSpec) => {
      const existing = new Set(nodes.map((n) => n.id));
      const id = newNodeId(spec.type, existing);
      const node: FlowNodeT = { id, type: spec.type, params: defaultParams(spec.type) };
      const pos = { x: 80 + (nodes.length % 5) * 60, y: 80 + nodes.length * 30 };
      const rf: RFNode = { id, type: "atc", position: pos, data: { node, spec } };
      setNodes((ns) => [...ns, rf]);
      setSelectedId(id);
    },
    [nodes, setNodes],
  );

  const updateNodeParams = useCallback(
    (id: string, params: Record<string, unknown>) => {
      setNodes((ns) =>
        ns.map((n) =>
          n.id === id ? { ...n, data: { ...n.data, node: { ...n.data.node, params } } } : n,
        ),
      );
    },
    [setNodes],
  );

  const deleteNode = useCallback(
    (id: string) => {
      setNodes((ns) => ns.filter((n) => n.id !== id));
      setEdges((es) => es.filter((e) => e.source !== id && e.target !== id));
      setSelectedId(null);
    },
    [setNodes, setEdges],
  );

  const selected = decorated.find((n) => n.id === selectedId);
  const paletteGroups = useMemo(() => groupBy(catalog, (s) => s.category), [catalog]);

  return (
    <Group align="stretch" gap={0} style={{ height: "100%", minHeight: 520 }} wrap="nowrap">
      <Box style={{ flex: 1, position: "relative", border: "1px solid var(--mantine-color-dark-4)", borderRadius: 8 }}>
        <ReactFlow
          nodes={decorated}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          nodeTypes={nodeTypes}
          onNodeClick={(_, n) => setSelectedId(n.id)}
          onPaneClick={() => setSelectedId(null)}
          fitView
          deleteKeyCode={["Backspace", "Delete"]}
          proOptions={{ hideAttribution: true }}
        >
          <Background gap={16} />
          <Controls />
          <MiniMap pannable zoomable style={{ background: "var(--mantine-color-dark-8)" }} />
          <Panel position="top-left">
            <Paper withBorder p="xs" radius="md" style={{ maxWidth: 200 }}>
              <Text fz="xs" fw={700} mb={4}>
                Palette
              </Text>
              <ScrollArea.Autosize mah={280}>
                <Stack gap={8}>
                  {Object.entries(paletteGroups).map(([cat, specs]) => (
                    <Box key={cat}>
                      <Text fz={10} c="dimmed" tt="uppercase" mb={2}>
                        {cat}
                      </Text>
                      <Group gap={4}>
                        {specs.map((s) => (
                          <Tooltip key={s.type} label={s.description} multiline w={220} withArrow>
                            <Button
                              size="compact-xs"
                              variant="light"
                              color={CATEGORY_COLOR[cat] ?? "indigo"}
                              onClick={() => addNode(s)}
                            >
                              {s.label}
                            </Button>
                          </Tooltip>
                        ))}
                      </Group>
                    </Box>
                  ))}
                </Stack>
              </ScrollArea.Autosize>
            </Paper>
          </Panel>
        </ReactFlow>
      </Box>

      {selected && (
        <Paper
          withBorder
          radius="md"
          ml="sm"
          p="md"
          style={{ width: 320, flexShrink: 0, overflow: "hidden", display: "flex", flexDirection: "column" }}
        >
          <Group justify="space-between" mb="xs">
            <Text fw={700} fz="sm">
              {selected.data.spec?.label ?? selected.data.node.type}
            </Text>
            <Group gap={4}>
              <Tooltip label="Delete node">
                <ActionIcon variant="subtle" color="red" onClick={() => deleteNode(selected.id)}>
                  <IconTrash size={16} />
                </ActionIcon>
              </Tooltip>
              <ActionIcon variant="subtle" color="gray" onClick={() => setSelectedId(null)}>
                <IconX size={16} />
              </ActionIcon>
            </Group>
          </Group>
          <ScrollArea.Autosize mah={460}>
            <NodeInspector
              node={selected.data.node}
              spec={selected.data.spec}
              onChange={(params) => updateNodeParams(selected.id, params)}
              tagNames={options.tagNames}
              profileIds={options.profileIds}
              appIds={options.appIds}
              commands={options.commands}
              groupNames={options.groupNames}
              devices={options.devices}
              allGroups={options.allGroups}
              startKinds={options.startKinds}
            />
          </ScrollArea.Autosize>
        </Paper>
      )}
    </Group>
  );
}

function defaultParams(type: string): Record<string, unknown> {
  switch (type) {
    case "start":
      return { kind: "enroll_dep", match: {} };
    case "manual_gate":
      return {
        summary: "",
        severity: "yellow",
        options: [{ label: "Release device from setup", edge: "on_release" }],
      };
    case "assign_tag":
    case "remove_tag":
      return { tags: [] };
    case "set_name":
      return { template: "" };
    case "install_profiles":
      return { profile_ids: [] };
    case "install_apps":
      return { app_ids: [] };
    case "send_command":
      return { command: undefined, params: {} };
    case "branch":
      return { condition: undefined };
    case "wait_for":
      return { signal: undefined, timeout_minutes: 60 };
    default:
      return {};
  }
}

function groupBy<T>(items: T[], key: (t: T) => string): Record<string, T[]> {
  const out: Record<string, T[]> = {};
  for (const it of items) (out[key(it)] ??= []).push(it);
  return out;
}
