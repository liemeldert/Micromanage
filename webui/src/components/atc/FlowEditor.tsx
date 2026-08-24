"use client";

import {type DragEvent, useCallback, useEffect, useMemo, useRef, useState} from "react";
import {
    addEdge,
    Background,
    type Connection,
    Controls,
    type Edge,
    Handle,
    MiniMap,
    type NodeProps,
    PanOnScrollMode,
    Position,
    ReactFlow,
    ReactFlowProvider,
    SelectionMode,
    useEdgesState,
    useNodesState,
    useReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
    ActionIcon,
    Alert,
    Badge,
    Box,
    Button,
    Group,
    List,
    Modal,
    Paper,
    ScrollArea,
    Stack,
    Text,
    Tooltip,
    useComputedColorScheme,
} from "@mantine/core";
import {
    IconAlertTriangle,
    IconChevronLeft,
    IconChevronRight,
    IconExclamationCircle,
    IconGrid4x4,
    IconHandStop,
    IconSquareDashed,
    IconTrash,
    IconWand,
    IconX,
} from "@tabler/icons-react";
import type {CatalogCommand, Device, FlowNode as FlowNodeT, FlowNodeSpec, StartKind,} from "../../../lib/api";
import type {Group as GroupDef} from "../../../lib/config";
import {NodeInspector} from "./NodeInspector";
import {
    CATEGORY_COLOR,
    EDGE_COLOR,
    EDGE_LABEL,
    type EdgeHandle,
    type FlowNodeData,
    flowToGraph,
    graphToNodes,
    newNodeId,
    nodeEdges,
    nodeSummary,
    type RFNode,
} from "./flow-utils";
import {glassClassName} from "../ui/glass";

const MANTINE_HEX: Record<string, string> = {
    grape: "#ae3ec9",
    blue: "#1971c2",
    teal: "#0ca678",
    orange: "#e8590c",
    indigo: "#3b5bdb",
};

const PALETTE_DRAG_MIME = "application/x-micromanage-flow-node";

// Edge-peek states for the palette, closed through to click-pinned.
type PaletteMode = "closed" | "peek" | "open" | "pinned";

// Hover intent delays. The leave grace is long enough to cross a gap without the palette snapping shut.
const PALETTE_PEEK_DELAY = 90;
const PALETTE_CLOSE_DELAY = 300;

// Canvas grid pitch, shared by the Background dots, the snap setting and the tidy pass so all three agree.
const GRID = 16;

// Pointer tools. Pan drags the canvas; select drags a marquee over it.
type CanvasTool = "pan" | "select";

//  Custom canvas node
export function FlowNodeCard({data, selected, isConnectable}: NodeProps) {
    const d = data as FlowNodeData;
    const node = d.node;
    const spec = d.spec;
    const isStart = node.type === "start";
    const highlight = d.highlight as "visited" | "current" | undefined;
    // Server flow warnings for this node, from the editor's decoration pass. Advisory: the badge blocks nothing.
    const warnings = (d.warnings as string[] | undefined) ?? [];
    // Validation issues for this node, from the same pass. Unlike the warnings these stop the save, so they own the
    // card's outline and its tooltip.
    const issues = (d.issues as string[] | undefined) ?? [];
    const color = MANTINE_HEX[CATEGORY_COLOR[spec?.category ?? "Flow"] ?? "indigo"] ?? "#3b5bdb";
    const handles = nodeEdges(node, spec);
    const summary = nodeSummary(node);

    const border = selected
        ? `2px solid ${color}`
        : highlight === "current"
            ? "2px solid #f08c00"
            : highlight === "visited"
                ? "2px solid #2f9e44"
                : issues.length
                    ? "2px solid var(--mantine-color-red-6)"
                    : "1px solid var(--mantine-color-default-border)";

    // A selected node keeps its category border, so the halo is what marks it unfinished while it is selected.
    const glow = highlight === "current"
        ? "0 0 0 4px rgba(240,140,0,0.2)"
        : issues.length
            ? "0 0 0 4px rgba(224,49,49,0.18)"
            : undefined;

    const card = (
        <div
            style={{
                borderRadius: 14,
                border,
                background: "var(--mantine-color-default)",
                minWidth: 150,
                opacity: highlight === undefined && d.dim ? 0.5 : 1,
                boxShadow: glow,
            }}
        >
            {/* every node has a target (entry) handle except a start node, which is only ever wired FROM */}
            {!isStart && (
                <Handle
                    type="target"
                    position={Position.Top}
                    isConnectable={isConnectable}
                    style={{background: color}}
                />
            )}
            <Box px="sm" py={6} style={{borderBottom: "1px solid var(--mantine-color-default-border)"}}>
                <Group gap={6} justify="space-between" wrap="nowrap">
                    <Group gap={6} wrap="nowrap">
                        <Box style={{width: 8, height: 8, borderRadius: 8, background: color}}/>
                        <Text fz="xs" fw={700} truncate>
                            {spec?.label ?? node.type}
                        </Text>
                    </Group>
                    <Group gap={4} wrap="nowrap">
                        {issues.length > 0 && (
                            <Badge
                                size="xs"
                                color="red"
                                variant="filled"
                                leftSection={<IconExclamationCircle size={10}/>}
                            >
                                {issues.length}
                            </Badge>
                        )}
                        {warnings.length > 0 && (
                            <Tooltip
                                label={<span style={{whiteSpace: "pre-line"}}>{warnings.join("\n\n")}</span>}
                                multiline
                                w={280}
                                withArrow
                            >
                                <Badge
                                    size="xs"
                                    color="yellow"
                                    variant="filled"
                                    leftSection={<IconAlertTriangle size={10}/>}
                                >
                                    {warnings.length}
                                </Badge>
                            </Tooltip>
                        )}
                        {isStart && (
                            <Badge size="xs" color="yellow" variant="light">
                                start
                            </Badge>
                        )}
                    </Group>
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
                        isConnectable={isConnectable}
                        style={{left: `${left}%`, background: EDGE_COLOR[h]}}
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

    if (!issues.length) return card;
    // The outline marks which block is unfinished; the tooltip on hover says what is wrong with it.
    return (
        <Tooltip
            label={<span style={{whiteSpace: "pre-line"}}>{issues.join("\n\n")}</span>}
            multiline
            w={280}
            color="red"
            position="top"
            openDelay={120}
            withArrow
            // Pointer only: a node is not focusable, and a tooltip opened on touch would sit over the block being
            // dragged.
            events={{hover: true, focus: false, touch: false}}
        >
            {card}
        </Tooltip>
    );
}

const nodeTypes = {atc: FlowNodeCard};

// React Flow's default off-screen minimap mask, rgba(240,240,240,.6), is a near-white slab on a dark canvas. The dark
// value inverts it and stays translucent so the nodes underneath remain visible.
export const MINIMAP_MASK: Record<"light" | "dark", string> = {
    light: "rgba(240, 240, 240, 0.6)",
    dark: "rgba(0, 0, 0, 0.5)",
};

//  Editor
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

export interface FlowEditorProps {
    // Identity of the loaded document on screen: it must change when a different document loads (new id, or a
    // re-fetch) and must not change while the canvas is edited, because the canvas is rebuilt from initialNodes
    // whenever it does. Mounting before the document and the node catalog have loaded emits an empty node list upward
    // and overwrites the saved flow on the next save.
    docKey: string;
    flowId: string;
    initialNodes: FlowNodeT[];
    catalog: FlowNodeSpec[];
    options: FlowEditorOptions;
    // Server flow warnings keyed by node id, drawn as a yellow badge on that node's card. Ids no longer on the
    // canvas decorate nothing.
    nodeWarnings?: Record<string, string[]>;
    // Validation issues keyed by node id, treated the same but in red: outline, badge, hover text, and a note in the
    // inspector.
    nodeIssues?: Record<string, string[]>;
    // A node the page is asking to show, from the issues list in the toolbar. The nonce lets the same node be
    // requested twice.
    focusNode?: { id: string; nonce: number } | null;
    // Read-only canvas: drags, wiring, deletes, palette adds and inspector edits are all off. The page sets it on a
    // live flow that has a draft, where every change belongs in the draft instead.
    readOnly?: boolean;
    // The draft that holds this live flow read-only, and the page's own flow-opening handler. The page passes them
    // only in that state, so the canvas never carries the notice on a draft.
    draftFlowId?: string | null;
    onOpenDraft?: (flowId: string) => void;
    // The emitted flowId names the flow the graph was built from, which is not always the flowId prop: switching
    // flows changes the prop a render before docKey rebuilds the graph, and a drag still in progress emits during that
    // window. The parent needs to know whose graph it is handed, or it writes one flow's canvas onto another.
    onChange: (patch: { nodes: FlowNodeT[]; flowId: string }) => void;
}

export function FlowEditor(props: FlowEditorProps) {
    return (
        <ReactFlowProvider>
            <FlowEditorInner {...props} />
        </ReactFlowProvider>
    );
}

function FlowEditorInner({
                             docKey,
                             flowId,
                             initialNodes,
                             catalog,
                             options,
                             nodeWarnings,
                             nodeIssues,
                             focusNode,
                             readOnly = false,
                             draftFlowId,
                             onOpenDraft,
                             onChange,
                         }: FlowEditorProps) {
    const {fitView, screenToFlowPosition} = useReactFlow();
    const initial = useMemo(
        // Build once per loaded document. Keyed on docKey rather than flowId, so a flow that keeps its id across
        // loads still re-initialises and nothing that changes mid-edit can throw the canvas away.
        () => flowToGraph({id: flowId, name: flowId, nodes: initialNodes}, catalog),
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [docKey],
    );

    // The flow the graph in state was built from. Only the rebuild below moves it.
    const graphFlowId = useRef(flowId);

    const [nodes, setNodes, onNodesChange] = useNodesState<RFNode>(initial.nodes);
    const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>(initial.edges);
    const [selectedId, setSelectedId] = useState<string | null>(null);
    // Palette visibility. "peek" and "open" are hover states that close themselves; "pinned" is a click-open
    // palette that ignores hover-out.
    const [paletteMode, setPaletteMode] = useState<PaletteMode>("pinned");
    const [detailsSpec, setDetailsSpec] = useState<FlowNodeSpec | null>(null);
    const [tool, setTool] = useState<CanvasTool>("pan");
    const [snap, setSnap] = useState(true);

    // The graph as it was (re)initialised from the loaded document. While state still holds these arrays nothing has
    // been edited, so nothing is sent upward: echoing the document back would round-trip it through graphToNodes,
    // dropping node keys the canvas does not model, and mark a pristine document dirty. Compared by reference.
    const pristine = useRef({nodes: initial.nodes, edges: initial.edges});

    // Re-initialise when a different document is loaded.
    const lastDoc = useRef(docKey);
    useEffect(() => {
        if (lastDoc.current === docKey) return;
        lastDoc.current = docKey;
        const g = flowToGraph({id: flowId, name: flowId, nodes: initialNodes}, catalog);
        pristine.current = {nodes: g.nodes, edges: g.edges};
        graphFlowId.current = flowId;
        setNodes(g.nodes);
        setEdges(g.edges);
        setSelectedId(null);
    }, [docKey, flowId, initialNodes, catalog, setNodes, setEdges]);

    // Emit changes upward (positions, wiring, params).
    useEffect(() => {
        if (nodes === pristine.current.nodes && edges === pristine.current.edges) return;
        onChange({nodes: graphToNodes(nodes, edges), flowId: graphFlowId.current});
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [nodes, edges]);

    // Carry the server warnings and the validation issues in as node decorations so FlowNodeCard can mark the named
    // node. Derived, never written back: graphToNodes ignores both keys.
    const decorated = useMemo(() => {
        const anyWarnings = nodeWarnings && Object.keys(nodeWarnings).length > 0;
        const anyIssues = nodeIssues && Object.keys(nodeIssues).length > 0;
        if (!anyWarnings && !anyIssues) return nodes;
        return nodes.map((n) => {
            const w = nodeWarnings?.[n.id];
            const e = nodeIssues?.[n.id];
            if (!w?.length && !e?.length) return n;
            return {
                ...n,
                data: {
                    ...n.data,
                    ...(w?.length ? {warnings: w} : {}),
                    ...(e?.length ? {issues: e} : {}),
                },
            };
        });
    }, [nodes, nodeWarnings, nodeIssues]);

    // Select and centre the node the page asked for, so an entry in the issues list reaches an off-screen block.
    useEffect(() => {
        if (!focusNode) return;
        setSelectedId(focusNode.id);
        fitView({nodes: [{id: focusNode.id}], maxZoom: 1.2, duration: 350});
    }, [focusNode, fitView]);

    const onConnect = useCallback(
        (c: Connection) => {
            if (readOnly) return;
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
                        style: {stroke: EDGE_COLOR[handle]},
                        labelStyle: {fill: EDGE_COLOR[handle], fontWeight: 600, fontSize: 11},
                    },
                    pruned,
                );
            });
        },
        [setEdges, readOnly],
    );

    const addNodeAt = useCallback(
        (spec: FlowNodeSpec, position?: { x: number; y: number }) => {
            if (readOnly) return;
            setNodes((ns) => {
                const existing = new Set(ns.map((n) => n.id));
                const id = newNodeId(spec.type, existing);
                const node: FlowNodeT = {
                    id, type: spec.type,
                    params: defaultParams(spec.type, options.startKinds),
                };
                const fallback = {x: 80 + (ns.length % 5) * 60, y: 80 + ns.length * 30};
                const rf: RFNode = {id, type: "atc", position: position ?? fallback, data: {node, spec}};
                setSelectedId(id);
                return [...ns, rf];
            });
        },
        [setNodes, options.startKinds, readOnly],
    );

    const addNode = useCallback((spec: FlowNodeSpec) => addNodeAt(spec), [addNodeAt]);

    // Pending hover-intent timers, and whether a block is currently being dragged out of the palette.
    const paletteTimers = useRef<{ enter?: number; leave?: number }>({});
    const paletteDragging = useRef(false);

    const clearPaletteTimers = useCallback(() => {
        window.clearTimeout(paletteTimers.current.enter);
        window.clearTimeout(paletteTimers.current.leave);
        paletteTimers.current = {};
    }, []);

    useEffect(() => clearPaletteTimers, [clearPaletteTimers]);

    // A pointer that only clips the corner of the strip should not peek the palette, so the peek waits.
    const onPaletteEdgeEnter = useCallback(() => {
        window.clearTimeout(paletteTimers.current.leave);
        paletteTimers.current.enter = window.setTimeout(
            () => setPaletteMode((m) => (m === "closed" ? "peek" : m)),
            PALETTE_PEEK_DELAY,
        );
    }, []);

    // Both the strip and the panel close through this, so leaving either takes the same grace period and a
    // pointer crossing from one to the other never starts a close it cannot cancel.
    const schedulePaletteClose = useCallback(() => {
        window.clearTimeout(paletteTimers.current.leave);
        paletteTimers.current.leave = window.setTimeout(
            () => setPaletteMode((m) => (m === "pinned" ? m : "closed")),
            PALETTE_CLOSE_DELAY,
        );
    }, []);

    const onPaletteEdgeLeave = useCallback(() => {
        window.clearTimeout(paletteTimers.current.enter);
        schedulePaletteClose();
    }, [schedulePaletteClose]);

    // Reaching the peeked edge pulls the whole panel out, unless the user already pinned it open.
    const onPaletteEnter = useCallback(() => {
        window.clearTimeout(paletteTimers.current.leave);
        setPaletteMode((m) => (m === "pinned" ? m : "open"));
    }, []);

    const onPaletteLeave = useCallback(() => {
        // A drag pulls the pointer off the panel straight away; that close is handled on drag end instead.
        if (paletteDragging.current) return;
        window.clearTimeout(paletteTimers.current.enter);
        schedulePaletteClose();
    }, [schedulePaletteClose]);

    const pinPalette = useCallback(() => {
        clearPaletteTimers();
        setPaletteMode("pinned");
    }, [clearPaletteTimers]);

    const closePalette = useCallback(() => {
        clearPaletteTimers();
        setPaletteMode("closed");
    }, [clearPaletteTimers]);

    const onPaletteDragStart = useCallback((ev: DragEvent, spec: FlowNodeSpec) => {
        ev.dataTransfer.effectAllowed = "copy";
        ev.dataTransfer.setData(PALETTE_DRAG_MIME, spec.type);
        paletteDragging.current = true;
        window.clearTimeout(paletteTimers.current.leave);
    }, []);

    // A hover-opened palette gets out of the way once the block has been dropped. A pinned one stays.
    const onPaletteDragEnd = useCallback(() => {
        paletteDragging.current = false;
        setPaletteMode((m) => (m === "pinned" ? m : "closed"));
    }, []);

    const onDragOver = useCallback((ev: DragEvent) => {
        ev.preventDefault();
        ev.dataTransfer.dropEffect = "copy";
    }, []);

    const onDrop = useCallback((ev: DragEvent) => {
        ev.preventDefault();
        const type = ev.dataTransfer.getData(PALETTE_DRAG_MIME);
        if (!type) return;
        const spec = catalog.find((s) => s.type === type);
        if (!spec) return;
        addNodeAt(spec, screenToFlowPosition({x: ev.clientX, y: ev.clientY}));
    }, [addNodeAt, catalog, screenToFlowPosition]);

    const updateNodeParams = useCallback(
        (id: string, params: Record<string, unknown>) => {
            if (readOnly) return;
            setNodes((ns) =>
                ns.map((n) =>
                    n.id === id ? {...n, data: {...n.data, node: {...n.data.node, params}}} : n,
                ),
            );
        },
        [setNodes, readOnly],
    );

    const deleteNode = useCallback(
        (id: string) => {
            if (readOnly) return;
            setNodes((ns) => ns.filter((n) => n.id !== id));
            setEdges((es) => es.filter((e) => e.source !== id && e.target !== id));
            setSelectedId(null);
        },
        [setNodes, setEdges, readOnly],
    );

    // Snap every node to the grid in one pass, so the whole layout moves as a single change rather than node by
    // node. Unchanged positions keep their array, leaving a tidy layout pristine.
    const tidy = useCallback(() => {
        if (readOnly) return;
        setNodes((ns) => {
            let moved = false;
            const next = ns.map((n) => {
                const x = Math.round(n.position.x / GRID) * GRID;
                const y = Math.round(n.position.y / GRID) * GRID;
                if (x === n.position.x && y === n.position.y) return n;
                moved = true;
                return {...n, position: {x, y}};
            });
            return moved ? next : ns;
        });
    }, [setNodes, readOnly]);

    const selected = decorated.find((n) => n.id === selectedId);
    const selectedIssues = (selected?.data.issues as string[] | undefined) ?? [];
    const paletteGroups = useMemo(() => groupBy(catalog, (s) => s.category), [catalog]);
    const scheme = useComputedColorScheme("light");
    const inspectorOpen = !!selected;
    const detailsOutputs = detailsSpec
        ? nodeEdges({id: "preview", type: detailsSpec.type, params: {}}, detailsSpec)
        : [];

    return (
        <Group align="stretch" gap={0} style={{height: "100%", minHeight: 0}} wrap="nowrap">
            <Box style={{
                flex: 1,
                position: "relative",
                borderRadius: 10,
                overflow: "hidden",
            }}>
                <ReactFlow
                    nodes={decorated}
                    edges={edges}
                    onNodesChange={onNodesChange}
                    onEdgesChange={onEdgesChange}
                    onConnect={onConnect}
                    nodeTypes={nodeTypes}
                    onNodeClick={(_, n) => setSelectedId(n.id)}
                    onPaneClick={() => setSelectedId(null)}
                    onDragOver={onDragOver}
                    onDrop={onDrop}
                    fitView
                    // Keep a little room around the graph so nodes are not flush against the edges after fit-view.
                    fitViewOptions={{padding: {left: "24px", top: "24px", right: "24px", bottom: "24px"}}}
                    // Mac trackpad feel: two-finger scroll pans both axes, pinch zooms, and Cmd plus wheel
                    // zooms. preventScrolling keeps the page still while the pointer is over the canvas.
                    panOnScroll
                    // Default is 0.5, which moves the canvas half as far as the fingers and reads as drag.
                    panOnScrollSpeed={1}
                    panOnScrollMode={PanOnScrollMode.Free}
                    zoomOnScroll={false}
                    zoomOnPinch
                    zoomOnDoubleClick
                    zoomActivationKeyCode="Meta"
                    preventScrolling
                    // The pan tool drags the canvas; the select tool drags a marquee instead. Two-finger scroll
                    // keeps panning in both.
                    panOnDrag={tool === "pan"}
                    selectionOnDrag={tool === "select"}
                    // A box that only touches a node still takes it.
                    selectionMode={SelectionMode.Partial}
                    // Shift is the transient marquee while the pan tool is active, and the same key adds a clicked
                    // node to the selection.
                    selectionKeyCode="Shift"
                    multiSelectionKeyCode="Shift"
                    snapToGrid={snap}
                    snapGrid={[GRID, GRID]}
                    nodesDraggable={!readOnly}
                    nodesConnectable={!readOnly}
                    deleteKeyCode={readOnly ? null : ["Backspace", "Delete"]}
                    proOptions={{hideAttribution: true}}
                >
                    <Background gap={GRID}/>
                    {/* The interactivity lock would re-enable dragging over the readOnly prop, so it is withheld
                        when the editor is locked. */}
                    <Controls showInteractive={!readOnly}/>
                    <MiniMap
                        pannable
                        zoomable
                        maskColor={MINIMAP_MASK[scheme]}
                        style={{
                            background: "var(--mantine-color-body)",
                            transform: inspectorOpen ? "translateX(-336px)" : "translateX(0)",
                            transition: "transform 170ms cubic-bezier(0.16, 1, 0.3, 1)",
                        }}
                    />
                </ReactFlow>
                {/* Faint orange edge glow while a live flow is held read-only. Overlaid and inert, so it tints
                    nothing and moves nothing. */}
                {readOnly && draftFlowId && (
                    <Box
                        className="atc-readonly-vignette"
                        aria-hidden
                        style={{position: "absolute", inset: 0, zIndex: 4, pointerEvents: "none"}}
                    />
                )}
                {/* Invisible hover strip down the left edge. It takes pointer events only over its own few
                    pixels, so canvas clicks elsewhere are untouched. It sits above the panel and stays armed
                    through the peek: resting in the strip holds the peek, and only moving right off it onto the
                    panel commits to open. */}
                <Box
                    className="atc-palette-edge"
                    data-armed={paletteMode === "closed" || paletteMode === "peek"}
                    onMouseEnter={onPaletteEdgeEnter}
                    onMouseLeave={onPaletteEdgeLeave}
                    style={{position: "absolute", left: 0, top: 0, bottom: 0, width: 12, zIndex: 6}}
                />
                <Paper
                    className={glassClassName({material: "thin", reactive: false, className: "atc-palette-panel"})}
                    data-state={paletteMode}
                    onMouseEnter={onPaletteEnter}
                    onMouseLeave={onPaletteLeave}
                    p="xs"
                    radius="xl"
                    style={{
                        position: "absolute",
                        // Clears the toolbar floating over the canvas.
                        top: 56,
                        bottom: 8,
                        left: 8,
                        width: 320,
                        zIndex: 5,
                        display: "flex",
                        flexDirection: "column",
                        padding: 14,
                    }}
                >
                    <Group justify="center" mb={8} style={{position: "relative"}}>
                        <Text fz="lg" fw={800} ta="center">
                            Palette
                        </Text>
                        {/* Glass, so the button reads as a control resting on the soft panel. */}
                        <ActionIcon
                            className={glassClassName({material: "overlay", reactive: false})}
                            variant="subtle"
                            color="gray"
                            onClick={closePalette}
                            style={{position: "absolute", right: 0, top: "50%", transform: "translateY(-50%)"}}
                        >
                            <IconChevronLeft size={16}/>
                        </ActionIcon>
                    </Group>
                    <Text fz="sm" c="dimmed" ta="center" mb="md">
                        Drag a block onto the canvas, or click Add.
                    </Text>
                    <Box style={{flex: 1, minHeight: 0}}>
                        <ScrollArea h="100%" offsetScrollbars>
                            <Stack gap="sm">
                                {Object.entries(paletteGroups).map(([cat, specs]) => (
                                    <Box key={cat}>
                                        <Text fz={10} c="dimmed" tt="uppercase" mb={6}>
                                            {cat}
                                        </Text>
                                        <Stack gap={8}>
                                            {specs.map((s) => (
                                                <Paper
                                                    key={s.type}
                                                    className={glassClassName({material: "thin", reactive: false})}
                                                    p="xs"
                                                    radius="lg"
                                                    draggable={!readOnly}
                                                    onDragStart={(ev) => onPaletteDragStart(ev, s)}
                                                    onDragEnd={onPaletteDragEnd}
                                                    style={{cursor: readOnly ? "default" : "grab"}}
                                                >
                                                    <Group justify="space-between" align="flex-start" wrap="nowrap">
                                                        <Box style={{minWidth: 0}}>
                                                            <Text fz="sm" fw={700} truncate>
                                                                {s.label}
                                                            </Text>
                                                            <Text fz={10} c="dimmed">
                                                                {s.type}
                                                            </Text>
                                                        </Box>
                                                        <Badge variant="light" color={CATEGORY_COLOR[cat] ?? "indigo"}>
                                                            {cat}
                                                        </Badge>
                                                    </Group>
                                                    <Text fz="xs" c="dimmed" lineClamp={2} mt={6}>
                                                        {shortDescription(s.description)}
                                                    </Text>
                                                    <Group gap={6} mt="xs">
                                                        <Button
                                                            size="compact-xs"
                                                            color={CATEGORY_COLOR[cat] ?? "indigo"}
                                                            onClick={() => addNode(s)}
                                                            disabled={readOnly}
                                                        >
                                                            Add
                                                        </Button>
                                                        <Button
                                                            size="compact-xs"
                                                            variant="subtle"
                                                            onClick={() => setDetailsSpec(s)}
                                                        >
                                                            Details
                                                        </Button>
                                                    </Group>
                                                </Paper>
                                            ))}
                                        </Stack>
                                    </Box>
                                ))}
                            </Stack>
                        </ScrollArea>
                    </Box>
                </Paper>
                {/* The reveal button stays mounted next to the panel so both sides of the toggle animate. It is
                    also the keyboard route in, and it pins the palette open. */}
                <ActionIcon
                    className="atc-palette-reveal"
                    data-shown={paletteMode === "closed"}
                    variant="filled"
                    size="lg"
                    radius="xl"
                    aria-label="Open palette"
                    onClick={pinPalette}
                    style={{
                        position: "absolute",
                        left: 8,
                        top: "50%",
                        transform: "translateY(-50%)",
                        zIndex: 5,
                    }}
                >
                    <IconChevronRight size={18}/>
                </ActionIcon>
                {/* Canvas tools. Bottom centre keeps them clear of React Flow's own zoom controls at the bottom
                    left and the minimap at the bottom right. Annotation blocks would belong here once the server
                    accepts them. */}
                <Paper
                    className={glassClassName({material: "thin", reactive: false})}
                    radius="xl"
                    p={6}
                    style={{
                        position: "absolute",
                        bottom: 8,
                        left: "50%",
                        transform: "translateX(-50%)",
                        zIndex: 6,
                    }}
                >
                    <Group gap={4} wrap="nowrap">
                        <Tooltip label="Pan (drag the canvas)" withArrow position="top">
                            <ActionIcon
                                size="md"
                                radius="xl"
                                variant={tool === "pan" ? "filled" : "subtle"}
                                color={tool === "pan" ? "blue" : "gray"}
                                aria-label="Pan tool"
                                aria-pressed={tool === "pan"}
                                onClick={() => setTool("pan")}
                            >
                                <IconHandStop size={16}/>
                            </ActionIcon>
                        </Tooltip>
                        <Tooltip label="Select (drag a box, or hold Shift while panning)" withArrow position="top">
                            <ActionIcon
                                size="md"
                                radius="xl"
                                variant={tool === "select" ? "filled" : "subtle"}
                                color={tool === "select" ? "blue" : "gray"}
                                aria-label="Select tool"
                                aria-pressed={tool === "select"}
                                onClick={() => setTool("select")}
                            >
                                <IconSquareDashed size={16}/>
                            </ActionIcon>
                        </Tooltip>
                        <Box style={{
                            width: 1,
                            alignSelf: "stretch",
                            margin: "2px 4px",
                            background: "var(--mantine-color-default-border)",
                        }}/>
                        <Tooltip label={snap ? "Snapping on" : "Snapping off"} withArrow position="top">
                            <ActionIcon
                                size="md"
                                radius="xl"
                                variant={snap ? "light" : "subtle"}
                                color={snap ? "blue" : "gray"}
                                aria-label="Snap to grid"
                                aria-pressed={snap}
                                onClick={() => setSnap((s) => !s)}
                            >
                                <IconGrid4x4 size={16}/>
                            </ActionIcon>
                        </Tooltip>
                        <Tooltip label="Tidy up (snap every block to the grid)" withArrow position="top">
                            {/* A disabled ActionIcon drops its pointer events, so the tooltip needs a wrapper. */}
                            <Box style={{display: "flex"}}>
                                <ActionIcon
                                    size="md"
                                    radius="xl"
                                    variant="subtle"
                                    color="gray"
                                    aria-label="Tidy up"
                                    onClick={tidy}
                                    disabled={readOnly}
                                >
                                    <IconWand size={16}/>
                                </ActionIcon>
                            </Box>
                        </Tooltip>
                    </Group>
                </Paper>
                {/* Stacked just above the tools rather than beside them, so neither one displaces the canvas. */}
                {readOnly && draftFlowId && (
                    <Paper
                        className={glassClassName({material: "thin", reactive: false})}
                        radius="xl"
                        px="sm"
                        py={6}
                        style={{
                            position: "absolute",
                            bottom: 60,
                            left: "50%",
                            transform: "translateX(-50%)",
                            zIndex: 6,
                            maxWidth: "min(520px, calc(100% - 32px))",
                        }}
                    >
                        <Group gap="sm" wrap="nowrap">
                            <IconAlertTriangle size={16} color="var(--mantine-color-orange-6)"/>
                            <Text fz="xs">
                                This version is in use and read only.
                            </Text>
                            <Button
                                size="compact-xs"
                                color="orange"
                                variant="light"
                                onClick={() => onOpenDraft?.(draftFlowId)}
                            >
                                Open draft
                            </Button>
                        </Group>
                    </Paper>
                )}
                <Modal
                    opened={detailsSpec !== null}
                    onClose={() => setDetailsSpec(null)}
                    title={detailsSpec?.label ?? "Block details"}
                    size="lg"
                >
                    {detailsSpec && (
                        <Stack gap="sm">
                            <FlowNodePreview spec={detailsSpec} startKinds={options.startKinds}/>
                            <Text fz="sm">{detailsSpec.description}</Text>
                            <Paper withBorder p="sm">
                                <Text fz="xs" c="dimmed" mb={4}>
                                    Inputs
                                </Text>
                                <Text fz="sm">
                                    {detailsSpec.type === "start" ? "No input (entry node)." : "One upstream step."}
                                </Text>
                                <Text fz="xs" c="dimmed" mt="sm" mb={4}>
                                    Outputs
                                </Text>
                                {detailsOutputs.length > 0 ? (
                                    <Group gap={6}>
                                        {detailsOutputs.map((h) => (
                                            <Badge key={h} variant="light" color="gray">
                                                {EDGE_LABEL[h] || "next"}
                                            </Badge>
                                        ))}
                                    </Group>
                                ) : (
                                    <Text fz="sm">No outgoing edges.</Text>
                                )}
                            </Paper>
                        </Stack>
                    )}
                </Modal>

                {selected && (
                    <Paper
                        className={glassClassName({
                            material: "surface", reactive: false, className: "atc-inspector-flyout",
                        })}
                        withBorder
                        radius="xl"
                        p="md"
                        style={{
                            position: "absolute",
                            top: 56,
                            bottom: 8,
                            right: 8,
                            width: 320,
                            zIndex: 6,
                            overflow: "hidden",
                            display: "flex",
                            flexDirection: "column",
                        }}
                    >
                        <Group justify="space-between" mb="xs">
                            <Text fw={700} fz="sm">
                                {selected.data.spec?.label ?? selected.data.node.type}
                            </Text>
                            <Group gap={4}>
                                {!readOnly && (
                                    <Tooltip label="Delete node">
                                        <ActionIcon variant="subtle" color="red"
                                                    onClick={() => deleteNode(selected.id)}>
                                            <IconTrash size={16}/>
                                        </ActionIcon>
                                    </Tooltip>
                                )}
                                <ActionIcon variant="subtle" color="gray" onClick={() => setSelectedId(null)}>
                                    <IconX size={16}/>
                                </ActionIcon>
                            </Group>
                        </Group>
                        <ScrollArea style={{flex: 1, minHeight: 0}}>
                            {selectedIssues.length > 0 && (
                                <Alert
                                    color="red"
                                    variant="light"
                                    p="xs"
                                    mb="sm"
                                    icon={<IconExclamationCircle size={16}/>}
                                    title={selectedIssues.length === 1 ? "1 issue" : `${selectedIssues.length} issues`}
                                >
                                    {/* The alert body is already indented past its icon, so the list only needs
                                        enough room to hang its bullets. */}
                                    <List size="xs" spacing={4} styles={{root: {paddingInlineStart: "1.05rem"}}}>
                                        {selectedIssues.map((message, i) => (
                                            <List.Item key={i}>{message}</List.Item>
                                        ))}
                                    </List>
                                </Alert>
                            )}
                            {/* When read-only, the disabled fieldset keeps keyboard input out of every control;
                                pointer-events covers whatever is not a form element. */}
                            <fieldset
                                disabled={readOnly}
                                style={{
                                    border: 0,
                                    margin: 0,
                                    padding: 0,
                                    minInlineSize: 0,
                                    ...(readOnly ? {pointerEvents: "none" as const, opacity: 0.7} : {}),
                                }}
                            >
                                <NodeInspector
                                    // Per node: the inspector's password fields hold local replacing-the-saved-value
                                    // state, and carrying that to the next node unseals its redaction sentinel.
                                    key={selected.id}
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
                            </fieldset>
                        </ScrollArea>
                    </Paper>
                )}
            </Box>
        </Group>
    );
}

function FlowNodePreview({spec, startKinds}: { spec: FlowNodeSpec; startKinds: StartKind[] }) {
    const color = MANTINE_HEX[CATEGORY_COLOR[spec.category ?? "Flow"] ?? "indigo"] ?? "#3b5bdb";
    // Same defaults the drop uses, so the sample card matches the block you get.
    const node: FlowNodeT = {
        id: `${spec.type}-device`, type: spec.type,
        params: defaultParams(spec.type, startKinds),
    };
    const summary = nodeSummary(node);

    return (
        <Box style={{width: 300, position: "relative", paddingTop: spec.type === "start" ? 0 : 8, paddingBottom: 16}}>
            {spec.type !== "start" && (
                <Box
                    style={{
                        position: "absolute",
                        top: 0,
                        left: "50%",
                        transform: "translateX(-50%)",
                        width: 10,
                        height: 10,
                        borderRadius: 999,
                        background: color,
                        border: "2px solid var(--mantine-color-body)",
                    }}
                />
            )}
            <Paper withBorder radius="xl" style={{overflow: "hidden"}}>
                <Box px="sm" py={8} style={{borderBottom: "1px solid var(--mantine-color-default-border)"}}>
                    <Group gap={8} wrap="nowrap">
                        <Box style={{width: 10, height: 10, borderRadius: 999, background: color}}/>
                        <Text fw={700}>{spec.label}</Text>
                    </Group>
                </Box>
                <Box px="sm" py="xs">
                    <Text fz={11} c="dimmed">{node.id}</Text>
                    {summary && <Text fz="sm">{summary}</Text>}
                </Box>
            </Paper>
            <Box
                style={{
                    position: "absolute",
                    bottom: 0,
                    left: "50%",
                    transform: "translateX(-50%)",
                    width: 10,
                    height: 10,
                    borderRadius: 999,
                    background: "#adb5bd",
                    border: "2px solid var(--mantine-color-body)",
                }}
            />
        </Box>
    );
}

// Params a freshly dropped node starts with. startKinds is the set of triggers this flow may use, already scoped by
// the caller, so a start node on a compliance flow does not default to a trigger that flow cannot hold. Without it the
// node carries a kind missing from its own Select, the field renders empty, and the node is invalid on arrival.
function defaultParams(type: string,
                       startKinds: StartKind[] = []): Record<string, unknown> {
    switch (type) {
        case "start":
            return {kind: startKinds[0]?.value ?? "checkin", match: {}};
        case "manual_gate":
            return {
                summary: "",
                severity: "yellow",
                options: [{label: "Release device from setup", edge: "on_release"}],
            };
        case "assign_tag":
        case "remove_tag":
            return {tags: []};
        case "set_name":
            return {template: ""};
        case "install_profiles":
            return {profile_ids: []};
        case "install_apps":
            return {app_ids: []};
        case "send_command":
            return {command: undefined, params: {}};
        case "branch":
            return {condition: undefined};
        case "wait_for":
            return {signal: undefined, timeout_minutes: 60};
        default:
            return {};
    }
}

function groupBy<T>(items: T[], key: (t: T) => string): Record<string, T[]> {
    const out: Record<string, T[]> = {};
    for (const it of items) (out[key(it)] ??= []).push(it);
    return out;
}

function shortDescription(text: string): string {
    const clean = text.trim();
    if (!clean) return "No description provided.";
    const [sentence] = clean.split(/(?<=[.!?])\s+/);
    if (!sentence) return clean;
    return sentence.length > 140 ? `${sentence.slice(0, 137).trimEnd()}...` : sentence;
}

