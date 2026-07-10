"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  ActionIcon,
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
  Tooltip,
} from "@mantine/core";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { FileButton } from "@mantine/core";
import {
  IconDownload,
  IconFileCertificate,
  IconHistory,
  IconPencil,
  IconPlus,
  IconTrash,
  IconUpload,
} from "@tabler/icons-react";
import {
  profilePayloads,
  useConfigResource,
  type Profile,
  type ProfilesConfig,
} from "../../../../lib/config";
import { getManifest } from "../../../../lib/profile-manifests";
import { parseMobileconfig, profileToMobileconfig } from "../../../../lib/plist";
import { ConfigHistoryDrawer } from "../../../components/config/ConfigHistoryDrawer";
import { IMPORT_KEY } from "../../../components/config/ProfileEditor";

function slugify(s: string): string {
  return (
    s
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 60) || "profile"
  );
}

export default function ProfilesPage() {
  const router = useRouter();
  const { data, loading, save, reload, currentDocText } = useConfigResource<ProfilesConfig>(
    "profiles",
    { profiles: [] },
  );
  const [importing, setImporting] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);

  const profiles = data?.profiles ?? [];

  async function handleImport(file: File | null) {
    if (!file) return;
    setImporting(true);
    try {
      const imp = parseMobileconfig(await file.text());
      if (!imp.payloads.length) {
        notifications.show({ color: "orange", message: "No payloads found in that profile." });
        return;
      }
      const profile: Profile = {
        id: slugify(imp.identifier || imp.name || "imported"),
        name: imp.name || "Imported profile",
        description: imp.description || "",
        type: "configuration",
        groups: [],
        payloads: imp.payloads,
      };
      sessionStorage.setItem(IMPORT_KEY, JSON.stringify(profile));
      notifications.show({
        color: "teal",
        message: `Imported ${imp.payloads.length} payload${imp.payloads.length === 1 ? "" : "s"} -- review and save.`,
      });
      router.push("/profiles/new");
    } catch (e: unknown) {
      notifications.show({
        color: "red",
        title: "Could not import",
        message: (e as Error).message,
        autoClose: 8000,
      });
    } finally {
      setImporting(false);
    }
  }

  function downloadProfile(p: Profile) {
    const xml = profileToMobileconfig({
      id: p.id,
      name: p.name,
      description: p.description,
      payloads: profilePayloads(p),
    });
    const blob = new Blob([xml], { type: "application/x-apple-aspen-config" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${p.id || "profile"}.mobileconfig`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function handleDelete(p: Profile) {
    modals.openConfirmModal({
      title: "Delete profile",
      children: (
        <Text size="sm">
          Delete profile <b>{p.name}</b>? It will be removed from devices in its groups on the
          next sync -- unlike apps, profile removal is automatic.
        </Text>
      ),
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () => save({ profiles: profiles.filter((x) => x.id !== p.id) }),
    });
  }

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-start">
        <Stack gap={0}>
          <Title order={2}>Profiles</Title>
          <Text fz="sm" c="dimmed">
            Device configuration profiles define settings and restrictions for managed devices. You can create configuration profiles or import existing .mobileconfig files created in other tools.
            Enrollment profiles are used to enroll devices into management and are generated automatically.
          </Text>
        </Stack>
        <Group gap="xs">
          <Button
            variant="light"
            leftSection={<IconHistory size={14} />}
            onClick={() => setHistoryOpen(true)}
            disabled={loading}
          >
            History
          </Button>
          <FileButton onChange={handleImport} accept=".mobileconfig,.plist,application/x-apple-aspen-config">
            {(props) => (
              <Button
                variant="default"
                leftSection={<IconUpload size={16} />}
                loading={importing}
                {...props}
              >
                Import .mobileconfig
              </Button>
            )}
          </FileButton>
          <Button
            leftSection={<IconPlus size={16} />}
            onClick={() => router.push("/profiles/new")}
            disabled={loading}
          >
            New profile
          </Button>
        </Group>
      </Group>

      {loading ? (
        <Box py={80} ta="center">
          <Loader />
        </Box>
      ) : profiles.length === 0 ? (
        <Card withBorder radius="md" py={48}>
          <Stack align="center" gap="xs">
            <IconFileCertificate size={36} opacity={0.4} />
            <Text c="dimmed">No profiles defined yet.</Text>
            <Button
              variant="light"
              leftSection={<IconPlus size={16} />}
              onClick={() => router.push("/profiles/new")}
            >
              Create your first profile
            </Button>
          </Stack>
        </Card>
      ) : (
        <Stack gap="sm">
          {profiles.map((p) => {
            const isDep = p.type === "enrollment" || p.dep_profile;
            const payloads = profilePayloads(p);
            return (
              <Card key={p.id} withBorder radius="md" padding="md">
                <Group justify="space-between" align="flex-start" wrap="nowrap">
                  <Stack gap={6} style={{ flex: 1, minWidth: 0 }}>
                    <Group gap="xs">
                      <Text fw={600}>{p.name}</Text>
                      <Badge color={isDep ? "grape" : "blue"} variant="light" size="sm">
                        {isDep ? "Enrollment (DEP)" : "Configuration"}
                      </Badge>
                      {!isDep && (
                        <Badge color="gray" variant="light" size="sm">
                          {payloads.length} payload{payloads.length === 1 ? "" : "s"}
                        </Badge>
                      )}
                    </Group>
                    {p.description && (
                      <Text fz="sm" c="dimmed">
                        {p.description}
                      </Text>
                    )}
                    <Group gap={6} wrap="wrap">
                      <Text fz="xs" c="dimmed">
                        id <Code>{p.id}</Code>
                      </Text>
                      {!isDep &&
                        payloads.slice(0, 5).map((pl, i) => {
                          const m = getManifest(pl.PayloadType as string);
                          return (
                            <Badge key={i} variant="outline" size="xs" color="gray">
                              {m ? m.title : ((pl.PayloadType as string) ?? "custom")}
                            </Badge>
                          );
                        })}
                      {(p.groups ?? []).length === 0 ? (
                        <Badge variant="outline" color="orange" size="sm">
                          no groups
                        </Badge>
                      ) : (
                        (p.groups ?? []).map((g) => (
                          <Badge key={g} variant="dot" size="sm" color="blue">
                            {g}
                          </Badge>
                        ))
                      )}
                    </Group>
                  </Stack>
                  <Group gap={4}>
                    {!isDep && payloads.length > 0 && (
                      <Tooltip label="Download .mobileconfig" withArrow>
                        <ActionIcon variant="subtle" color="gray" onClick={() => downloadProfile(p)}>
                          <IconDownload size={16} />
                        </ActionIcon>
                      </Tooltip>
                    )}
                    <Button
                      variant="subtle"
                      size="xs"
                      leftSection={<IconPencil size={14} />}
                      onClick={() => router.push(`/profiles/${encodeURIComponent(p.id)}`)}
                    >
                      Edit
                    </Button>
                    <Button
                      variant="subtle"
                      color="red"
                      size="xs"
                      leftSection={<IconTrash size={14} />}
                      onClick={() => handleDelete(p)}
                    >
                      Delete
                    </Button>
                  </Group>
                </Group>
              </Card>
            );
          })}
        </Stack>
      )}

      <ConfigHistoryDrawer
        opened={historyOpen}
        onClose={() => setHistoryOpen(false)}
        type="profiles"
        currentDoc={currentDocText}
        onRestored={reload}
      />
    </Stack>
  );
}
