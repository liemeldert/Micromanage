"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Alert,
  Badge,
  Button,
  Group,
  Loader,
  Paper,
  ScrollArea,
  Stack,
  Text,
  Timeline,
  Title,
} from "@mantine/core";
import { IconArrowLeft, IconSitemap } from "@tabler/icons-react";
import { api, type FlowNodeSpec, type FlowRunDetail } from "../../../../../../lib/api";
import { useAuth } from "../../../../../../lib/auth-context";
import { FlowNodeCard } from "../../../../../components/atc/FlowEditor";
import { flowToGraph, type RFNode } from "../../../../../components/atc/flow-utils";

const nodeTypes = { atc: FlowNodeCard };

const STATUS_COLOR: Record<string, string> = {
  running: "blue",
  waiting: "yellow",
  completed: "teal",
  failed: "red",
  cancelled: "gray",
};

const TERMINAL_STATUSES = new Set(["completed", "failed", "cancelled"]);

export default function FlowRunViewer() {
  const { token } = useAuth();
  const router = useRouter();
  const params = useParams();
  const id = String(params.id);
  const [run, setRun] = useState<FlowRunDetail | null>(null);
  const [catalog, setCatalog] = useState<FlowNodeSpec[]>([]);
  const [loading, setLoading] = useState(true);
  // Mirrors `run?.status` without being a dependency: the polling interval
  // below reads this instead of closing over `run`, so status updates don't
  // need to tear down/recreate the interval (and can't read a stale value).
  const statusRef = useRef<string | undefined>(undefined);
  useEffect(() => {
    statusRef.current = run?.status;
  }, [run?.status]);

  useEffect(() => {
    if (!token) return;
    api.getFlowStepCatalog(token).then((c) => setCatalog(c.nodes)).catch(() => {});
  }, [token]);

  useEffect(() => {
    if (!token) return;
    let live = true;
    const load = () =>
      api
        .getFlowRun(token, id)
        .then((r) => live && setRun(r))
        .catch(() => {})
        .finally(() => live && setLoading(false));
    load();
    // Poll every 5s until the run reaches a terminal state, then stop.
    const t = setInterval(() => {
      if (statusRef.current && TERMINAL_STATUSES.has(statusRef.current)) {
        clearInterval(t);
        return;
      }
      load();
    }, 5000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [token, id]);

  const graph = useMemo(() => {
    if (!run?.flow) return { nodes: [] as RFNode[], edges: [] as Edge[] };
    const g = flowToGraph(run.flow, catalog);
    const visited = new Set(run.visited ?? []);
    const nodes = g.nodes.map((n) => ({
      ...n,
      draggable: false,
      connectable: false,
      selectable: false,
      data: {
        ...n.data,
        highlight:
          n.id === run.current_node ? "current" : visited.has(n.id) ? "visited" : undefined,
        dim: !(n.id === run.current_node || visited.has(n.id)),
      },
    }));
    return { nodes, edges: g.edges };
  }, [run, catalog]);

  if (loading) return <Loader />;
  if (!run) return <Alert color="red">Flow run not found.</Alert>;

  return (
    <Stack gap="md">
      <Group justify="space-between" align="flex-start">
        <div>
          <Button
            variant="subtle"
            size="compact-sm"
            leftSection={<IconArrowLeft size={14} />}
            onClick={() => router.back()}
            mb={4}
          >
            Back
          </Button>
          <Title order={3}>
            <Group gap={8}>
              <IconSitemap size={22} /> {run.flow_id}
            </Group>
          </Title>
        </div>
        <Group gap={8}>
          {run.event_kind && (
            <Badge size="lg" variant="light" color="grape">
              {run.event_kind}
            </Badge>
          )}
          <Badge size="lg" color={STATUS_COLOR[run.status] ?? "gray"} variant="light">
            {run.status}
          </Badge>
          {run.status === "waiting" && run.waiting_signal && (
            <Badge size="lg" variant="outline" color="yellow">
              waiting: {run.waiting_signal}
            </Badge>
          )}
        </Group>
      </Group>

      {run.error && <Alert color="red" title="Run error">{run.error}</Alert>}

      <Group align="stretch" gap="md" wrap="nowrap" style={{ minHeight: 520 }}>
        <Paper withBorder radius="md" p="xs" style={{ flex: 1, height: 560 }}>
          <ReactFlowProvider>
            <ReactFlow
              nodes={graph.nodes}
              edges={graph.edges}
              nodeTypes={nodeTypes}
              fitView
              nodesDraggable={false}
              nodesConnectable={false}
              elementsSelectable={false}
              proOptions={{ hideAttribution: true }}
            >
              <Background gap={16} />
              <Controls showInteractive={false} />
              <MiniMap pannable style={{ background: "var(--mantine-color-dark-8)" }} />
            </ReactFlow>
          </ReactFlowProvider>
        </Paper>

        <Paper withBorder radius="md" p="md" style={{ width: 340, flexShrink: 0 }}>
          <Text fw={700} fz="sm" mb="sm">
            Timeline
          </Text>
          <ScrollArea.Autosize mah={480}>
            <Timeline active={(run.timeline?.length ?? 1) - 1} bulletSize={14} lineWidth={2}>
              {(run.timeline ?? []).map((t, i) => (
                <Timeline.Item key={i} title={t.node ?? "flow"}>
                  <Text fz="xs">{t.message}</Text>
                  <Text fz={10} c="dimmed">
                    {t.at ? new Date(t.at).toLocaleString() : ""}
                  </Text>
                </Timeline.Item>
              ))}
            </Timeline>
            {!run.timeline?.length && (
              <Text fz="xs" c="dimmed">
                No timeline entries yet.
              </Text>
            )}
          </ScrollArea.Autosize>
        </Paper>
      </Group>
    </Stack>
  );
}
