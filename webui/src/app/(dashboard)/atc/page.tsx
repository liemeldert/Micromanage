"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Divider,
  Group,
  List,
  Modal,
  NumberInput,
  Paper,
  ScrollArea,
  Select,
  Stack,
  Switch,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import {
  IconCopy,
  IconDeviceFloppy,
  IconInfoCircle,
  IconPlus,
  IconSitemap,
  IconTrash,
} from "@tabler/icons-react";
import {
  api,
  type CatalogCommand,
  type Device,
  type FlowDoc,
  type FlowNode,
  type FlowNodeSpec,
  type FlowsConfig,
} from "../../../../lib/api";
import { useConfigResource, useTagRegistry, type Group as GroupDef, type Scope } from "../../../../lib/config";
import { useAuth } from "../../../../lib/auth-context";
import { ScopeEditor } from "../../../components/config/ScopeEditor";
import { FlowEditor } from "../../../components/atc/FlowEditor";
import { validateFlowClient } from "../../../components/atc/flow-utils";

export default function ATCPage() {
  const { token } = useAuth();
  const { data, setData, loading, saving, save } = useConfigResource<FlowsConfig>("flows", {
    flows: [],
  });
  const { tagNames } = useTagRegistry();

  const [catalog, setCatalog] = useState<FlowNodeSpec[]>([]);
  const [commands, setCommands] = useState<CatalogCommand[]>([]);
  const [profileIds, setProfileIds] = useState<string[]>([]);
  const [appIds, setAppIds] = useState<string[]>([]);
  const [groups, setGroups] = useState<GroupDef[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [newOpen, newHandlers] = useDisclosure(false);

  // Load the palette + the option lists the inspector / scope editor need.
  useEffect(() => {
    if (!token) return;
    api.getFlowStepCatalog(token).then((c) => setCatalog(c.nodes)).catch(() => {});
    api.getCommandCatalog(token).then((c) => setCommands(c.commands)).catch(() => {});
    api.getConfig(token, "profiles").then((p) => setProfileIds(((p?.profiles as { id: string }[]) ?? []).map((x) => x.id))).catch(() => {});
    api.getConfig(token, "apps").then((a) => setAppIds(((a?.apps as { id: string }[]) ?? []).map((x) => x.id))).catch(() => {});
    api.getConfig(token, "groups").then((g) => setGroups(((g?.groups as GroupDef[]) ?? []))).catch(() => {});
    api.listDevices(token, { limit: 500 }).then((r) => setDevices(r.devices)).catch(() => {});
  }, [token]);

  const flows = useMemo(() => data?.flows ?? [], [data]);
  useEffect(() => {
    if (!selectedId && flows.length) setSelectedId(flows[0].id);
  }, [flows, selectedId]);

  const flow = flows.find((f) => f.id === selectedId) ?? null;
  const flowIndex = flows.findIndex((f) => f.id === selectedId);

  const patchFlow = useCallback(
    (patch: Partial<FlowDoc>) => {
      setData((prev) => {
        const next = { flows: [...(prev?.flows ?? [])] };
        if (flowIndex >= 0) next.flows[flowIndex] = { ...next.flows[flowIndex], ...patch };
        return next;
      });
    },
    [setData, flowIndex],
  );

  // Canvas emits node/start changes; merge into the selected flow.
  const onCanvasChange = useCallback(
    (p: { nodes: FlowNode[]; start: string }) => patchFlow({ nodes: p.nodes, start: p.start }),
    [patchFlow],
  );

  const createFlow = (id: string, name: string) => {
    const clean = id.trim().toLowerCase();
    if (!/^[a-z0-9-_]+$/.test(clean)) {
      notifications.show({ color: "red", message: "Id must be a slug ([a-z0-9-_])." });
      return;
    }
    if (flows.some((f) => f.id === clean)) {
      notifications.show({ color: "red", message: "A flow with that id already exists." });
      return;
    }
    const doc: FlowDoc = {
      id: clean,
      name: name.trim() || clean,
      enabled: true,
      priority: 100,
      trigger: { on: "enroll", match: {} },
      start: "",
      nodes: [],
    };
    setData((prev) => ({ flows: [...(prev?.flows ?? []), doc] }));
    setSelectedId(clean);
    newHandlers.close();
  };

  const duplicateFlow = () => {
    if (!flow) return;
    let id = `${flow.id}-copy`;
    let n = 1;
    while (flows.some((f) => f.id === id)) id = `${flow.id}-copy-${++n}`;
    const copy: FlowDoc = { ...structuredClone(flow), id, name: `${flow.name} (copy)`, enabled: false };
    setData((prev) => ({ flows: [...(prev?.flows ?? []), copy] }));
    setSelectedId(id);
  };

  const deleteFlow = () => {
    if (!flow) return;
    setData((prev) => ({ flows: (prev?.flows ?? []).filter((f) => f.id !== flow.id) }));
    setSelectedId(null);
  };

  const clientErrors = useMemo(
    () => (flow && catalog.length ? validateFlowClient(flow, catalog) : []),
    [flow, catalog],
  );

  const onSave = async () => {
    // Save the whole document; the server validates every flow and returns
    // errors/warnings (surfaced as toasts by useConfigResource).
    await save(data ?? { flows: [] });
  };

  return (
    <Stack gap="md">
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>
            <Group gap={8}>
              <IconSitemap size={26} /> ATC — Air Traffic Control
            </Group>
          </Title>
          <Text c="dimmed" fz="sm">
            Visual enrollment flows. On (re)enroll, the highest-priority matching flow runs per
            device as it answers MDM commands. The canvas serializes to a readable flows.yaml.
          </Text>
        </div>
        <Group>
          <Select
            placeholder="Select a flow"
            data={flows.map((f) => ({ value: f.id, label: `${f.name}${f.enabled === false ? " (disabled)" : ""}` }))}
            value={selectedId}
            onChange={setSelectedId}
            w={240}
            searchable
            nothingFoundMessage="No flows yet"
          />
          <Tooltip label="New flow">
            <ActionIcon variant="light" size="lg" onClick={newHandlers.open}>
              <IconPlus size={18} />
            </ActionIcon>
          </Tooltip>
          {flow && (
            <>
              <Tooltip label="Duplicate">
                <ActionIcon variant="light" size="lg" color="gray" onClick={duplicateFlow}>
                  <IconCopy size={18} />
                </ActionIcon>
              </Tooltip>
              <Tooltip label="Delete flow">
                <ActionIcon variant="light" size="lg" color="red" onClick={deleteFlow}>
                  <IconTrash size={18} />
                </ActionIcon>
              </Tooltip>
            </>
          )}
          <Button
            leftSection={<IconDeviceFloppy size={16} />}
            onClick={onSave}
            loading={saving}
            disabled={loading || !data}
          >
            Save
          </Button>
        </Group>
      </Group>

      {!loading && !flows.length && (
        <Alert color="blue" icon={<IconInfoCircle size={18} />} title="No flows yet">
          <Text fz="sm">
            Create a flow to automate onboarding. A flow assigns tags, names the device, installs
            profiles/apps and branches on device facts as the device answers.
          </Text>
          <Text fz="sm" mt={6}>
            There is deliberately no “add to group” step: group membership is computed from state.
            To put a device in a group, <b>assign a tag</b> here and define the group in groups.yaml
            with a <b>tag</b> condition.
          </Text>
        </Alert>
      )}

      {flow && (
        <>
          <Paper withBorder radius="md" p="md">
            <Group align="flex-end" gap="md" wrap="wrap">
              <TextInput
                label="Name"
                value={flow.name}
                onChange={(e) => patchFlow({ name: e.currentTarget.value })}
                w={240}
              />
              <TextInput label="Id" value={flow.id} disabled w={200} />
              <NumberInput
                label="Priority"
                description="Higher wins when several match"
                value={flow.priority ?? 100}
                onChange={(v) => patchFlow({ priority: typeof v === "number" ? v : 100 })}
                w={140}
                min={0}
              />
              <Switch
                label="Enabled"
                checked={flow.enabled !== false}
                onChange={(e) => patchFlow({ enabled: e.currentTarget.checked })}
                mb={6}
              />
            </Group>
            <Divider my="sm" label="Trigger — fires on enroll for devices matching" labelPosition="left" />
            <ScopeEditor
              scope={(flow.trigger.match ?? {}) as Scope}
              onChange={(match) => patchFlow({ trigger: { on: "enroll", match: match as Record<string, unknown> } })}
              devices={devices}
              allGroups={groups}
              groupsLabel="Target groups"
              groupsDescription="Empty trigger matches every enrolling device."
            />
          </Paper>

          {clientErrors.length > 0 && (
            <Alert color="orange" title={`${clientErrors.length} issue${clientErrors.length === 1 ? "" : "s"} to fix before this flow runs`}>
              <ScrollArea.Autosize mah={140}>
                <List size="sm">
                  {clientErrors.map((e, i) => (
                    <List.Item key={i}>{e}</List.Item>
                  ))}
                </List>
              </ScrollArea.Autosize>
            </Alert>
          )}

          <Paper withBorder radius="md" p="xs" style={{ height: 620 }}>
            <FlowEditor
              flowId={flow.id}
              initialNodes={flow.nodes}
              initialStart={flow.start}
              catalog={catalog}
              options={{ tagNames, profileIds, appIds, commands, groupNames: groups.map((g) => g.name) }}
              onChange={onCanvasChange}
            />
          </Paper>

          <Group gap={6}>
            <Badge variant="light" color="gray">
              {flow.nodes.length} node{flow.nodes.length === 1 ? "" : "s"}
            </Badge>
            <Text fz="xs" c="dimmed">
              Drag from a node’s bottom handle to wire the next step. Select a node to edit it; use
              the star to set the start node.
            </Text>
          </Group>
        </>
      )}

      <NewFlowModal opened={newOpen} onClose={newHandlers.close} onCreate={createFlow} />
    </Stack>
  );
}

function NewFlowModal({
  opened,
  onClose,
  onCreate,
}: {
  opened: boolean;
  onClose: () => void;
  onCreate: (id: string, name: string) => void;
}) {
  const [name, setName] = useState("");
  const [id, setId] = useState("");
  useEffect(() => {
    if (opened) {
      setName("");
      setId("");
    }
  }, [opened]);
  const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9-_]+/g, "-").replace(/^-+|-+$/g, "");
  return (
    <Modal opened={opened} onClose={onClose} title="New flow" centered>
      <Stack>
        <TextInput
          label="Name"
          placeholder="Standard Mac Onboarding"
          value={name}
          onChange={(e) => {
            setName(e.currentTarget.value);
            if (!id) setId(slug(e.currentTarget.value));
          }}
        />
        <TextInput
          label="Id (slug)"
          placeholder="standard-mac-onboarding"
          value={id}
          onChange={(e) => setId(slug(e.currentTarget.value))}
        />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={() => onCreate(id, name)} disabled={!id}>
            Create
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
