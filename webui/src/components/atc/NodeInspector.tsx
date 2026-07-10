"use client";

import {
  Alert,
  Badge,
  Divider,
  Group,
  MultiSelect,
  NumberInput,
  Select,
  Stack,
  TagsInput,
  Text,
  TextInput,
} from "@mantine/core";
import { IconInfoCircle } from "@tabler/icons-react";
import type { CatalogCommand, FlowNode, FlowNodeSpec, WaitSignal } from "../../../lib/api";
import type { Condition, Group as GroupDef } from "../../../lib/config";
import { ConditionBuilder } from "../config/ConditionBuilder";
import { NameTemplateInput } from "../config/NameTemplateInput";

/** Per-node parameter editor for the ATC flow canvas. Reuses the existing
 * condition / naming builders and renders type-appropriate controls, so a node's
 * params are edited the same way the rest of the console edits scope/naming. */
export function NodeInspector({
  node,
  spec,
  onChange,
  tagNames,
  profileIds,
  appIds,
  commands,
  groupNames,
}: {
  node: FlowNode;
  spec?: FlowNodeSpec;
  onChange: (params: Record<string, unknown>) => void;
  tagNames: string[];
  profileIds: string[];
  appIds: string[];
  commands: CatalogCommand[];
  groupNames: string[];
}) {
  const p = node.params ?? {};
  const patch = (next: Record<string, unknown>) => onChange({ ...p, ...next });
  const asList = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : []);

  const waitSignals: WaitSignal[] = (spec?.params.find((x) => x.type === "signal")?.options ??
    []) as WaitSignal[];

  // Only non-destructive commands may be used as a flow step (server enforces it too).
  const commandOptions = commands
    .filter((c) => !c.destructive)
    .map((c) => ({ value: c.type, label: c.label }));
  const selectedCommand = commands.find((c) => c.type === p.command);

  return (
    <Stack gap="sm">
      {spec && (
        <Text fz="xs" c="dimmed">
          {spec.description}
        </Text>
      )}

      {(node.type === "assign_tag" || node.type === "remove_tag") && (
        <TagsInput
          label={node.type === "assign_tag" ? "Tags to add" : "Tags to remove"}
          description="Registry tags are suggested; free-form tags are allowed."
          placeholder="Type a tag and press Enter"
          data={tagNames}
          value={asList(p.tags)}
          onChange={(v) => patch({ tags: v })}
          clearable
        />
      )}

      {node.type === "set_name" && (
        <NameTemplateInput
          value={String(p.template ?? "")}
          onChange={(t) => patch({ template: t })}
          label="Name template"
          placeholder="IT-{serial}"
        />
      )}

      {node.type === "install_profiles" && (
        <MultiSelect
          label="Profiles"
          description="Installed now (imperative). Scope the profile to keep it maintained."
          placeholder={profileIds.length ? "Select profiles" : "No profiles defined"}
          data={profileIds}
          value={asList(p.profile_ids)}
          onChange={(v) => patch({ profile_ids: v })}
          searchable
        />
      )}

      {node.type === "install_apps" && (
        <MultiSelect
          label="Apps"
          description="Installs the version the device is entitled to (apps.yaml scoping)."
          placeholder={appIds.length ? "Select apps" : "No apps defined"}
          data={appIds}
          value={asList(p.app_ids)}
          onChange={(v) => patch({ app_ids: v })}
          searchable
        />
      )}

      {node.type === "send_command" && (
        <Stack gap="xs">
          <Select
            label="Command"
            placeholder="Select a command"
            data={commandOptions}
            value={typeof p.command === "string" ? p.command : null}
            onChange={(v) => patch({ command: v ?? undefined, params: {} })}
            searchable
          />
          {selectedCommand && selectedCommand.params.length > 0 && (
            <CommandParamsForm
              command={selectedCommand}
              value={(p.params as Record<string, unknown>) ?? {}}
              onChange={(cp) => patch({ params: cp })}
            />
          )}
          <Alert variant="light" color="gray" p="xs" icon={<IconInfoCircle size={14} />}>
            Destructive commands (erase, lock, …) can never run from an automated flow.
          </Alert>
        </Stack>
      )}

      {node.type === "branch" && (
        <div>
          <Text fz="sm" fw={500} mb={4}>
            Condition (takes the <b>true</b> edge when it matches, else <b>false</b>)
          </Text>
          <ConditionBuilder
            conditions={p.condition ? [p.condition as Condition] : []}
            onChange={(list) => patch({ condition: list[0] ?? undefined })}
            groupNames={groupNames}
            tagNames={tagNames}
            emptyHint="Add the condition to branch on."
          />
        </div>
      )}

      {node.type === "wait_for" && (
        <Stack gap="xs">
          <Select
            label="Wait for signal"
            data={waitSignals.map((s) => ({ value: s.value, label: s.label }))}
            value={typeof p.signal === "string" ? p.signal : null}
            onChange={(v) => patch({ signal: v ?? undefined })}
          />
          {typeof p.signal === "string" && p.signal ? (
            <Text fz="xs" c="dimmed">
              {waitSignals.find((s) => s.value === p.signal)?.description}
            </Text>
          ) : null}
          <NumberInput
            label="Timeout (minutes)"
            description="After this, the timeout edge is taken (or the run fails)."
            min={1}
            value={typeof p.timeout_minutes === "number" ? p.timeout_minutes : 60}
            onChange={(v) => patch({ timeout_minutes: typeof v === "number" ? v : 60 })}
          />
        </Stack>
      )}

      {node.type === "end" && (
        <Text fz="sm" c="dimmed">
          Terminal node. The run completes when it reaches an end.
        </Text>
      )}

      <Divider my={4} />
      <Group gap={6}>
        <Text fz="xs" c="dimmed">
          Node id
        </Text>
        <Badge variant="light" size="sm">
          {node.id}
        </Badge>
      </Group>
    </Stack>
  );
}

function CommandParamsForm({
  command,
  value,
  onChange,
}: {
  command: CatalogCommand;
  value: Record<string, unknown>;
  onChange: (v: Record<string, unknown>) => void;
}) {
  return (
    <Stack gap={6}>
      {command.params.map((param) => (
        <TextInput
          key={param.name}
          size="xs"
          label={param.label}
          required={param.required === true}
          description={
            param.secret
              ? "Avoid secrets here -- flows.yaml is stored in plain text and versioned."
              : param.help
          }
          value={String(value[param.name] ?? "")}
          onChange={(e) => onChange({ ...value, [param.name]: e.currentTarget.value })}
        />
      ))}
    </Stack>
  );
}
