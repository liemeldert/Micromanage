"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Group,
  List,
  Paper,
  ScrollArea,
  Stack,
  Switch,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { IconDeviceFloppy, IconInfoCircle, IconSitemap } from "@tabler/icons-react";
import {
  api,
  type CatalogCommand,
  type Device,
  type FlowNode,
  type FlowNodeSpec,
  type FlowsConfig,
  type StartKind,
} from "../../../../lib/api";
import { useConfigResource, useTagRegistry, type Group as GroupDef } from "../../../../lib/config";
import { useAuth } from "../../../../lib/auth-context";
import { FlowEditor } from "../../../components/atc/FlowEditor";
import { emptyFlow, validateFlowClient } from "../../../components/atc/flow-utils";

export default function ATCPage() {
  const { token } = useAuth();
  const { data, setData, loading, saving, save } = useConfigResource<FlowsConfig>("flows", {
    flow: emptyFlow("main"),
  });
  const { tagNames } = useTagRegistry();

  const [catalog, setCatalog] = useState<FlowNodeSpec[]>([]);
  const [startKinds, setStartKinds] = useState<StartKind[]>([]);
  const [commands, setCommands] = useState<CatalogCommand[]>([]);
  const [profileIds, setProfileIds] = useState<string[]>([]);
  const [appIds, setAppIds] = useState<string[]>([]);
  const [groups, setGroups] = useState<GroupDef[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);

  // Load the palette + the option lists the inspector / scope editor need.
  useEffect(() => {
    if (!token) return;
    api
      .getFlowStepCatalog(token)
      .then((c) => {
        setCatalog(c.nodes);
        setStartKinds(c.start_kinds ?? []);
      })
      .catch(() => {});
    api.getCommandCatalog(token).then((c) => setCommands(c.commands)).catch(() => {});
    api.getConfig(token, "profiles").then((p) => setProfileIds(((p?.profiles as { id: string }[]) ?? []).map((x) => x.id))).catch(() => {});
    api.getConfig(token, "apps").then((a) => setAppIds(((a?.apps as { id: string }[]) ?? []).map((x) => x.id))).catch(() => {});
    api.getConfig(token, "groups").then((g) => setGroups(((g?.groups as GroupDef[]) ?? []))).catch(() => {});
    api.listDevices(token, { limit: 500 }).then((r) => setDevices(r.devices)).catch(() => {});
  }, [token]);

  const flow = useMemo(() => data?.flow ?? emptyFlow("main"), [data]);

  const patchFlow = useCallback(
    (patch: Partial<typeof flow>) => {
      setData((prev) => ({ flow: { ...(prev?.flow ?? emptyFlow("main")), ...patch } }));
    },
    [setData],
  );

  // Canvas emits node changes; merge into the flow.
  const onCanvasChange = useCallback(
    (p: { nodes: FlowNode[] }) => patchFlow({ nodes: p.nodes }),
    [patchFlow],
  );

  const clientErrors = useMemo(
    () => (catalog.length ? validateFlowClient(flow, catalog) : []),
    [flow, catalog],
  );

  const onSave = async () => {
    // Save the whole document; the server validates the flow and returns
    // errors/warnings (surfaced as toasts by useConfigResource).
    await save(data ?? { flow: emptyFlow("main") });
  };

  return (
    <Stack gap="md">
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>
            <Group gap={8}>
              <IconSitemap size={26} /> Air Traffic Control
            </Group>
          </Title>
          <Text c="dimmed" fz="sm">
            ATC is a single visual flow that automates what happens to devices in your fleet. Add{" "}
            <b>start blocks</b> as entry points — on enrollment (DEP/ADE or OTA), on check-in, or on a
            schedule — then scope them down and assign tags, set the device name, install
            profiles/apps, wait for the device, escalate to a human, and release from Setup Assistant.
          </Text>
        </div>
        <Group align="flex-end">
          <Switch
            label="Enabled"
            checked={flow.enabled !== false}
            onChange={(e) => patchFlow({ enabled: e.currentTarget.checked })}
            mb={6}
          />
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

      <Paper withBorder radius="md" p="md">
        <Group align="flex-end" gap="md" wrap="wrap">
          <TextInput
            label="Flow name"
            value={flow.name}
            onChange={(e) => patchFlow({ name: e.currentTarget.value })}
            w={280}
          />
          <TextInput label="Id" value={flow.id} disabled w={200} />
        </Group>
        <Text fz="xs" c="dimmed" mt="sm">
          To put a device in a group, assign a tag here and define the group by that tag in the{" "}
          <b>Groups</b> section — membership stays computed from device state.
        </Text>
      </Paper>

      {clientErrors.length > 0 && (
        <Alert
          color="orange"
          title={`${clientErrors.length} issue${clientErrors.length === 1 ? "" : "s"} to fix before this flow runs`}
        >
          <ScrollArea.Autosize mah={140}>
            <List size="sm">
              {clientErrors.map((e, i) => (
                <List.Item key={i}>{e}</List.Item>
              ))}
            </List>
          </ScrollArea.Autosize>
        </Alert>
      )}

      {!catalog.length && !loading && (
        <Alert color="blue" icon={<IconInfoCircle size={18} />} title="Loading palette…" />
      )}

      <Paper withBorder radius="md" p="xs" style={{ height: 640 }}>
        <FlowEditor
          flowId={flow.id}
          initialNodes={flow.nodes}
          catalog={catalog}
          options={{
            tagNames,
            profileIds,
            appIds,
            commands,
            groupNames: groups.map((g) => g.name),
            devices,
            allGroups: groups,
            startKinds,
          }}
          onChange={onCanvasChange}
        />
      </Paper>

      <Group gap={6}>
        <Badge variant="light" color="gray">
          {flow.nodes.length} node{flow.nodes.length === 1 ? "" : "s"}
        </Badge>
        <Text fz="xs" c="dimmed">
          Drag from a node’s bottom handle to wire the next step. Add <b>Start</b> nodes from the
          palette as entry points; select any node to edit it.
        </Text>
      </Group>
    </Stack>
  );
}
