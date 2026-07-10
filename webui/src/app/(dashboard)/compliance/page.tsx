"use client";

import { useState } from "react";
import { Group, Stack, Tabs, Text, Title } from "@mantine/core";
import { IconActivityHeartbeat, IconAlertTriangle, IconListDetails } from "@tabler/icons-react";
import { AlertBoard } from "../../../components/dispatcher/AlertBoard";
import { RuleEditor } from "../../../components/dispatcher/RuleEditor";

// The Dispatcher (compliance) console: a triage alert board + the rule editor.
export default function DispatcherPage() {
  const [tab, setTab] = useState<string | null>("alerts");
  return (
    <Stack gap="md">
      <div>
        <Title order={2}>
          <Group gap={8}>
            <IconActivityHeartbeat size={26} /> Dispatcher — Compliance
          </Group>
        </Title>
        <Text c="dimmed" fz="sm">
          Rules watch observed device state and raise severity-ranked alerts (Black → Green) that
          auto-resolve when the device becomes compliant, with optional signed webhooks and guarded
          auto-remediation.
        </Text>
      </div>

      <Tabs value={tab} onChange={setTab}>
        <Tabs.List>
          <Tabs.Tab value="alerts" leftSection={<IconAlertTriangle size={16} />}>
            Alert board
          </Tabs.Tab>
          <Tabs.Tab value="rules" leftSection={<IconListDetails size={16} />}>
            Rules
          </Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="alerts" pt="md">
          <AlertBoard />
        </Tabs.Panel>
        <Tabs.Panel value="rules" pt="md">
          <RuleEditor />
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
