"use client";

// Apple Declarative Device Management (DDM): the tenant's authored
// declarations.yaml, summarized read-only here (mirrors the Profiles page
// layout). Editing happens through the raw YAML editor -- declarations are
// authored as structured payloads (Apple's declaration JSON), which doesn't
// have a friendly visual builder the way profiles/groups do yet.

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Alert,
  Badge,
  Box,
  Button,
  Card,
  Code,
  Group,
  Loader,
  Stack,
  Text,
  Title,
} from "@mantine/core";
import { IconFileDescription, IconInfoCircle, IconPencil } from "@tabler/icons-react";
import Link from "next/link";
import { api, ApiError, type DeclarationSummary, type TenantInfo } from "../../../../lib/api";
import { useAuth } from "../../../../lib/auth-context";

// "com.apple.configuration.legacy" -> "legacy". Keeps the badge readable --
// every native declaration type shares this prefix (yaml_validator.py enforces it).
const TYPE_PREFIX = "com.apple.configuration.";
function shortType(type: string): string {
  return type.startsWith(TYPE_PREFIX) ? type.slice(TYPE_PREFIX.length) : type;
}

export default function DeclarationsPage() {
  const router = useRouter();
  const { token } = useAuth();
  const [declarations, setDeclarations] = useState<DeclarationSummary[]>([]);
  const [tenant, setTenant] = useState<TenantInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    setLoading(true);
    Promise.all([api.listDeclarations(token), api.getTenant(token)])
      .then(([d, t]) => {
        setDeclarations(d.declarations);
        setTenant(t);
        setError(null);
      })
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : (e as Error).message))
      .finally(() => setLoading(false));
  }, [token]);

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-start">
        <Stack gap={0}>
          <Title order={2}>Declarations</Title>
          <Text fz="sm" c="dimmed">
            Declarative configurations applied natively by devices -- Apple&apos;s DDM evaluates
            and reports on these on-device, so they stay enforced even offline and self-heal
            without waiting for a check-in.
          </Text>
        </Stack>
        <Button
          variant="light"
          leftSection={<IconPencil size={14} />}
          onClick={() => router.push("/yaml?type=declarations")}
        >
          Edit YAML
        </Button>
      </Group>

      {tenant && !tenant.ddm_enabled && (
        <Alert color="orange" variant="light" icon={<IconInfoCircle size={16} />}>
          Declarative Device Management is turned off for this tenant, so nothing below is being
          sent to devices yet. Turn it on in{" "}
          <Text component={Link} href="/settings" fw={600} c="orange" style={{ textDecoration: "underline" }}>
            Settings
          </Text>{" "}
          to start enforcing declarations.
        </Alert>
      )}

      {error && (
        <Alert color="red" variant="light" icon={<IconInfoCircle size={16} />}>
          {error}
        </Alert>
      )}

      {loading ? (
        <Box py={80} ta="center">
          <Loader />
        </Box>
      ) : declarations.length === 0 ? (
        <Card withBorder radius="md" py={48}>
          <Stack align="center" gap="xs">
            <IconFileDescription size={36} opacity={0.4} />
            <Text c="dimmed">No declarations defined yet.</Text>
            <Button
              variant="light"
              leftSection={<IconPencil size={16} />}
              onClick={() => router.push("/yaml?type=declarations")}
            >
              Add one in the YAML editor
            </Button>
          </Stack>
        </Card>
      ) : (
        <Stack gap="sm">
          {declarations.map((d) => (
            <Card key={d.id} withBorder radius="md" padding="md">
              <Group justify="space-between" align="flex-start" wrap="nowrap">
                <Stack gap={6} style={{ flex: 1, minWidth: 0 }}>
                  <Group gap="xs">
                    <Text fw={600}>{d.name || d.id}</Text>
                    <Badge color="grape" variant="light" size="sm">
                      {shortType(d.type)}
                    </Badge>
                    {typeof d.scoped_count === "number" && (
                      <Badge color="gray" variant="light" size="sm">
                        {d.scoped_count} device{d.scoped_count === 1 ? "" : "s"}
                      </Badge>
                    )}
                  </Group>
                  {d.description && (
                    <Text fz="sm" c="dimmed">
                      {d.description}
                    </Text>
                  )}
                  <Group gap={6} wrap="wrap">
                    <Text fz="xs" c="dimmed">
                      id <Code>{d.id}</Code>
                    </Text>
                    {(d.scope?.groups ?? []).length === 0 ? (
                      <Badge variant="outline" color="orange" size="sm">
                        no groups
                      </Badge>
                    ) : (
                      (d.scope?.groups ?? []).map((g) => (
                        <Badge key={g} variant="dot" size="sm" color="blue">
                          {g}
                        </Badge>
                      ))
                    )}
                    {(d.scope?.platforms ?? []).map((p) => (
                      <Badge key={p} variant="outline" size="sm" color="teal">
                        {p}
                      </Badge>
                    ))}
                    {(d.scope?.conditions ?? 0) > 0 && (
                      <Badge variant="outline" size="sm" color="gray">
                        {d.scope!.conditions} condition{d.scope!.conditions === 1 ? "" : "s"}
                      </Badge>
                    )}
                    {d.scope?.rollout && (
                      <Badge variant="outline" size="sm" color="yellow">
                        gradual rollout
                      </Badge>
                    )}
                  </Group>
                </Stack>
              </Group>
            </Card>
          ))}
        </Stack>
      )}
    </Stack>
  );
}
