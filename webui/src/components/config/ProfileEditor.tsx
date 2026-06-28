"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  ActionIcon,
  Badge,
  Box,
  Button,
  Card,
  Chip,
  Divider,
  Group,
  JsonInput,
  Loader,
  Modal,
  MultiSelect,
  NavLink,
  ScrollArea,
  SegmentedControl,
  Stack,
  Text,
  Textarea,
  TextInput,
  Title,
  UnstyledButton,
} from "@mantine/core";
import { useMediaQuery } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import {
  IconArrowLeft,
  IconDeviceFloppy,
  IconLayoutGrid,
  IconPlus,
  IconSearch,
  IconTrash,
} from "@tabler/icons-react";
import { api, type Device } from "../../../lib/api";
import { useAuth } from "../../../lib/auth-context";
import {
  deviceMatchesGroup,
  devicePlatform,
  profilePayloads,
  SLUG_RE,
  useConfigResource,
  type Group as GroupDef,
  type Profile,
  type ProfileKind,
  type ProfilesConfig,
} from "../../../lib/config";
import {
  ALL_PLATFORMS,
  blankPayload,
  ENROLLMENT_MANIFEST,
  getManifest,
  manifestsByCategory,
  type Platform,
} from "../../../lib/profile-manifests";
import { PayloadForm } from "./PayloadForm";

export const IMPORT_KEY = "mm_profile_import";

interface DraftState {
  id: string;
  name: string;
  description: string;
  kind: ProfileKind;
  platforms: Platform[];
  groups: string[];
  payloads: Record<string, unknown>[];
  enrollment: Record<string, unknown>;
}

function fromProfile(p: Profile): DraftState {
  const kind: ProfileKind = p.type === "enrollment" || p.dep_profile ? "enrollment" : "configuration";
  const platforms = (p.platforms as Platform[] | undefined)?.filter((x) =>
    ALL_PLATFORMS.includes(x),
  );
  return {
    id: p.id,
    name: p.name,
    description: p.description ?? "",
    kind,
    platforms: platforms && platforms.length ? platforms : ["iOS", "macOS"],
    groups: p.groups ?? [],
    payloads: kind === "configuration" ? profilePayloads(p) : [],
    enrollment: kind === "enrollment" ? (p.payload ?? {}) : {},
  };
}

function payloadLabel(pl: Record<string, unknown>): { title: string; subtitle?: string } {
  const m = getManifest(pl.PayloadType as string);
  const sub =
    (pl.SSID_STR as string) ||
    (pl.Label as string) ||
    (pl.UserDefinedName as string) ||
    (pl.EmailAddress as string) ||
    (pl.CalDAVHostName as string) ||
    (pl.CardDAVHostName as string) ||
    undefined;
  return { title: m ? m.title : (pl.PayloadType as string) || "Custom payload", subtitle: sub };
}

export function ProfileEditor({ profileId }: { profileId?: string }) {
  const router = useRouter();
  const { token } = useAuth();
  const { data, loading, saving, save } = useConfigResource<ProfilesConfig>("profiles", {
    profiles: [],
  });

  const [groups, setGroups] = useState<GroupDef[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [draft, setDraft] = useState<DraftState | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [mode, setMode] = useState<"form" | "json">("form");
  const [payloadText, setPayloadText] = useState("{}");
  const [idError, setIdError] = useState<string | null>(null);
  const [initialized, setInitialized] = useState(false);
  const [notFound, setNotFound] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [addQuery, setAddQuery] = useState("");
  // Side-by-side with a sticky sidebar on wide screens; stacked on narrow ones.
  const wide = useMediaQuery("(min-width: 1100px)", true);

  useEffect(() => {
    if (!token) return;
    api
      .getConfig(token, "groups")
      .then((g) => setGroups((g as { groups?: GroupDef[] }).groups ?? []))
      .catch(() => {});
    api
      .listDevices(token, { limit: 500 })
      .then((r) => setDevices(r.devices))
      .catch(() => {});
  }, [token]);

  // Device groups eligible for the selected platforms: a group is eligible if it
  // has no determinable members, or any of its members run a selected platform.
  const eligibleGroupNames = useMemo(() => {
    const sel = draft?.platforms ?? [];
    const names = groups
      .filter((g) => {
        const members = devices.filter((d) => deviceMatchesGroup(d, g.conditions));
        if (members.length === 0) return true;
        const plats = new Set(members.map((d) => devicePlatform(d.device_model)));
        return sel.some((p) => plats.has(p));
      })
      .map((g) => g.name);
    // Keep already-selected groups visible even if they became ineligible.
    return Array.from(new Set([...names, ...(draft?.groups ?? [])]));
  }, [groups, devices, draft?.platforms, draft?.groups]);

  // Initialise the draft once the config load settles (even if it came back
  // empty or errored — treat a missing config as an empty profile list).
  useEffect(() => {
    if (initialized || loading) return;
    const profiles = data?.profiles ?? [];

    let seed: Profile | null = null;
    if (!profileId && typeof window !== "undefined") {
      const raw = sessionStorage.getItem(IMPORT_KEY);
      if (raw) {
        try {
          seed = JSON.parse(raw) as Profile;
        } catch {
          /* ignore */
        }
        sessionStorage.removeItem(IMPORT_KEY);
      }
    }

    if (profileId) {
      const p = profiles.find((x) => x.id === profileId);
      if (!p) {
        setNotFound(true);
        setInitialized(true);
        return;
      }
      const d = fromProfile(p);
      setDraft(d);
      setSelected(d.payloads.length ? 0 : null);
    } else if (seed) {
      const d = fromProfile(seed);
      setDraft(d);
      setSelected(d.payloads.length ? 0 : null);
    } else {
      setDraft({
        id: "",
        name: "",
        description: "",
        kind: "configuration",
        platforms: ["iOS", "macOS"],
        groups: [],
        payloads: [],
        enrollment: {},
      });
    }
    setInitialized(true);
  }, [loading, data, initialized, profileId]);

  // Sync the JSON view + form/json mode when the selected payload changes.
  useEffect(() => {
    if (!draft || selected === null || !draft.payloads[selected]) return;
    const pl = draft.payloads[selected];
    setMode(getManifest(pl.PayloadType as string) ? "form" : "json");
    setPayloadText(JSON.stringify(pl, null, 2));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  function update(patch: Partial<DraftState>) {
    setDraft((d) => (d ? { ...d, ...patch } : d));
  }

  function updateSelectedPayload(next: Record<string, unknown>) {
    if (!draft || selected === null) return;
    update({ payloads: draft.payloads.map((p, i) => (i === selected ? next : p)) });
  }

  function addPayload(domain: string) {
    if (!draft) return;
    const m = getManifest(domain);
    const pl = m ? blankPayload(m) : { PayloadType: domain };
    const payloads = [...draft.payloads, pl];
    update({ payloads });
    setSelected(payloads.length - 1);
    setAddOpen(false);
    setAddQuery("");
  }

  function removePayload(i: number) {
    if (!draft) return;
    const payloads = draft.payloads.filter((_, idx) => idx !== i);
    update({ payloads });
    setSelected(payloads.length ? Math.min(i, payloads.length - 1) : null);
  }

  function switchMode(m: "form" | "json") {
    if (selected === null || !draft) return;
    if (m === "json") {
      setPayloadText(JSON.stringify(draft.payloads[selected] ?? {}, null, 2));
    } else {
      try {
        updateSelectedPayload(JSON.parse(payloadText || "{}"));
      } catch {
        notifications.show({ color: "red", message: "Fix the JSON before switching to the form." });
        return;
      }
    }
    setMode(m);
  }

  function validateId(id: string): string | null {
    if (!id.trim()) return "ID is required";
    if (!SLUG_RE.test(id)) return "Letters, numbers, '.', '_', '-' only";
    if (data?.profiles.some((p) => p.id === id && p.id !== profileId))
      return "A profile with this ID already exists";
    return null;
  }

  async function handleSave() {
    if (!draft) return;
    const idErr = validateId(draft.id);
    setIdError(idErr);
    if (idErr) return;
    if (!draft.name.trim()) {
      notifications.show({ color: "red", message: "Name is required." });
      return;
    }
    if (draft.kind === "configuration" && draft.payloads.length === 0) {
      notifications.show({ color: "orange", message: "Add at least one payload." });
      return;
    }

    const common = {
      id: draft.id.trim(),
      name: draft.name.trim(),
      ...(draft.description.trim() ? { description: draft.description.trim() } : {}),
      groups: draft.groups,
    };
    const withPlatforms = { ...common, platforms: draft.platforms };
    const profile: Profile =
      draft.kind === "enrollment"
        ? { ...withPlatforms, type: "enrollment", dep_profile: true, payload: draft.enrollment }
        : { ...withPlatforms, type: "configuration", payloads: draft.payloads };

    const profiles = [...(data?.profiles ?? [])];
    const idx = profiles.findIndex((p) => p.id === (profileId ?? draft.id));
    if (idx >= 0) profiles[idx] = profile;
    else profiles.push(profile);

    const ok = await save({ profiles });
    if (ok) router.push("/profiles");
  }

  // ── render ──────────────────────────────────────────────────────────────────
  if (loading || !initialized) {
    return (
      <Box py={80} ta="center">
        <Loader />
      </Box>
    );
  }

  if (notFound || !draft) {
    return (
      <Stack align="center" py={80} gap="sm">
        <Text c="dimmed">Profile not found.</Text>
        <Button variant="light" onClick={() => router.push("/profiles")}>
          Back to profiles
        </Button>
      </Stack>
    );
  }

  const selectedPayload = selected !== null ? draft.payloads[selected] : null;
  const selectedManifest = selectedPayload
    ? getManifest(selectedPayload.PayloadType as string)
    : undefined;

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Group gap="sm">
          <ActionIcon variant="subtle" color="gray" onClick={() => router.push("/profiles")}>
            <IconArrowLeft size={18} />
          </ActionIcon>
          <Title order={2}>{draft.name.trim() || (profileId ? "Edit profile" : "New profile")}</Title>
          <Badge variant="light" color={draft.kind === "enrollment" ? "grape" : "blue"}>
            {draft.kind === "enrollment" ? "Enrollment (DEP)" : "Configuration"}
          </Badge>
        </Group>
        <Button leftSection={<IconDeviceFloppy size={16} />} loading={saving} onClick={handleSave}>
          Save profile
        </Button>
      </Group>

      <Box style={{ display: "flex", gap: "var(--mantine-spacing-lg)", alignItems: "flex-start", flexWrap: wide ? "nowrap" : "wrap" }}>
        {/* ── Left: metadata + payload list (sticky while keys scroll) ──── */}
        <Box
          style={
            wide
              ? {
                  position: "sticky",
                  top: 16,
                  alignSelf: "flex-start",
                  flex: "0 0 340px",
                  maxHeight: "calc(100vh - 32px)",
                  overflowY: "auto",
                }
              : { width: "100%" }
          }
        >
          <Stack gap="md">
            <Card withBorder radius="md" padding="md">
              <Stack gap="sm">
                <TextInput
                  label="Profile ID"
                  placeholder="corp-baseline"
                  value={draft.id}
                  error={idError}
                  disabled={!!profileId}
                  onChange={(e) => {
                    update({ id: e.currentTarget.value });
                    if (idError) setIdError(validateId(e.currentTarget.value));
                  }}
                  withAsterisk
                />
                <TextInput
                  label="Name"
                  placeholder="Corporate Baseline"
                  value={draft.name}
                  onChange={(e) => update({ name: e.currentTarget.value })}
                  withAsterisk
                />
                <Textarea
                  label="Description"
                  placeholder="Optional"
                  autosize
                  minRows={1}
                  value={draft.description}
                  onChange={(e) => update({ description: e.currentTarget.value })}
                />
                <Box>
                  <Text fz="sm" fw={500} mb={4}>
                    Profile type
                  </Text>
                  <SegmentedControl
                    fullWidth
                    value={draft.kind}
                    onChange={(v) => {
                      update({ kind: v as ProfileKind });
                      if (v === "enrollment") setSelected(null);
                    }}
                    data={[
                      { label: "Configuration", value: "configuration" },
                      { label: "Enrollment (DEP)", value: "enrollment" },
                    ]}
                  />
                  <Text fz="xs" c="dimmed" mt={4}>
                    {draft.kind === "enrollment"
                      ? "Applied during Automated Device Enrollment via ABM/ASM."
                      : "Managed configuration pushed to devices in the target groups."}
                  </Text>
                </Box>
                <Box>
                  <Text fz="sm" fw={500} mb={4}>
                    Target platforms
                  </Text>
                  <Chip.Group
                    multiple
                    value={draft.platforms}
                    onChange={(v) => {
                      const next = (v as Platform[]).length ? (v as Platform[]) : draft.platforms;
                      update({ platforms: next });
                    }}
                  >
                    <Group gap="xs">
                      {ALL_PLATFORMS.map((p) => (
                        <Chip key={p} value={p} size="xs" variant="outline">
                          {p}
                        </Chip>
                      ))}
                    </Group>
                  </Chip.Group>
                  <Text fz="xs" c="dimmed" mt={4}>
                    Filters the payload types and keys to those the selected platforms support.
                  </Text>
                </Box>
                <MultiSelect
                  label="Target groups"
                  description="Only groups containing devices on the selected platforms are shown."
                  placeholder={eligibleGroupNames.length ? "Select groups" : "No eligible groups"}
                  data={eligibleGroupNames}
                  value={draft.groups}
                  onChange={(g) => update({ groups: g })}
                  searchable
                  nothingFoundMessage="No groups match the selected platforms"
                />
              </Stack>
            </Card>

            {draft.kind === "configuration" && (
              <Card withBorder radius="md" padding="md">
                <Group justify="space-between" mb="sm">
                  <Text fw={600} fz="sm">
                    Payloads
                  </Text>
                  <Button
                    variant="light"
                    size="xs"
                    leftSection={<IconPlus size={14} />}
                    onClick={() => {
                      setAddQuery("");
                      setAddOpen(true);
                    }}
                  >
                    Add payload
                  </Button>
                </Group>

                {draft.payloads.length === 0 ? (
                  <Text fz="xs" c="dimmed">
                    No payloads yet. Add one — a profile can bundle several (e.g. multiple Wi-Fi
                    networks plus restrictions).
                  </Text>
                ) : (
                  <Stack gap={4}>
                    {draft.payloads.map((pl, i) => {
                      const { title, subtitle } = payloadLabel(pl);
                      const active = i === selected;
                      return (
                        <UnstyledButton
                          key={i}
                          onClick={() => setSelected(i)}
                          p="xs"
                          style={{
                            borderRadius: 6,
                            background: active ? "var(--mantine-color-blue-light)" : undefined,
                          }}
                        >
                          <Group justify="space-between" wrap="nowrap">
                            <Box style={{ minWidth: 0 }}>
                              <Text fz="sm" fw={active ? 600 : 400} truncate>
                                {title}
                              </Text>
                              {subtitle && (
                                <Text fz="xs" c="dimmed" truncate>
                                  {subtitle}
                                </Text>
                              )}
                            </Box>
                            <ActionIcon
                              component="div"
                              variant="subtle"
                              color="red"
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                removePayload(i);
                              }}
                            >
                              <IconTrash size={14} />
                            </ActionIcon>
                          </Group>
                        </UnstyledButton>
                      );
                    })}
                  </Stack>
                )}
              </Card>
            )}
          </Stack>
        </Box>

        {/* ── Right: payload editor ────────────────────────────────────── */}
        <Box style={{ flex: "1 1 auto", minWidth: 0, width: wide ? undefined : "100%" }}>
          <Card withBorder radius="md" padding="md" mih={360}>
            {draft.kind === "enrollment" ? (
              <Stack gap="sm">
                <Text fw={600}>{ENROLLMENT_MANIFEST.title}</Text>
                <Text fz="xs" c="dimmed">
                  {ENROLLMENT_MANIFEST.description}
                </Text>
                <Divider my="xs" />
                <PayloadForm
                  manifest={ENROLLMENT_MANIFEST}
                  value={draft.enrollment}
                  onChange={(enrollment) => update({ enrollment })}
                  platforms={draft.platforms}
                />
              </Stack>
            ) : selectedPayload === null ? (
              <Stack align="center" justify="center" mih={320} gap="xs">
                <IconLayoutGrid size={32} opacity={0.4} />
                <Text c="dimmed" fz="sm">
                  {draft.payloads.length === 0
                    ? "Add a payload to start building this profile."
                    : "Select a payload to edit."}
                </Text>
              </Stack>
            ) : (
              <Stack gap="sm">
                <Group justify="space-between">
                  <Box>
                    <Text fw={600}>{payloadLabel(selectedPayload).title}</Text>
                    <Text fz="xs" c="dimmed">
                      {(selectedPayload.PayloadType as string) || "custom"}
                    </Text>
                  </Box>
                  {selectedManifest && (
                    <SegmentedControl
                      size="xs"
                      value={mode}
                      onChange={(v) => switchMode(v as "form" | "json")}
                      data={[
                        { label: "Form", value: "form" },
                        { label: "JSON", value: "json" },
                      ]}
                    />
                  )}
                </Group>
                <Divider my="xs" />
                {selectedManifest && mode === "form" ? (
                  <PayloadForm
                    manifest={selectedManifest}
                    value={selectedPayload}
                    onChange={updateSelectedPayload}
                    platforms={draft.platforms}
                  />
                ) : (
                  <JsonInput
                    value={payloadText}
                    onChange={(t) => {
                      setPayloadText(t);
                      try {
                        updateSelectedPayload(JSON.parse(t || "{}"));
                      } catch {
                        /* keep typing */
                      }
                    }}
                    validationError="Invalid JSON"
                    formatOnBlur
                    autosize
                    minRows={10}
                    styles={{ input: { fontFamily: "var(--mantine-font-family-monospace)", fontSize: 13 } }}
                  />
                )}
              </Stack>
            )}
          </Card>
        </Box>
      </Box>

      {/* ── Searchable "Add payload" picker ──────────────────────────────── */}
      <Modal opened={addOpen} onClose={() => setAddOpen(false)} title="Add payload" size="md">
        <Stack gap="sm">
          <TextInput
            placeholder="Search payload types…"
            leftSection={<IconSearch size={14} />}
            value={addQuery}
            onChange={(e) => setAddQuery(e.currentTarget.value)}
            data-autofocus
          />
          <ScrollArea.Autosize mah={440}>
            {(() => {
              const q = addQuery.trim().toLowerCase();
              const cats = manifestsByCategory(draft.platforms)
                .map((g) => ({
                  category: g.category,
                  items: g.items.filter((m) => `${m.title} ${m.domain}`.toLowerCase().includes(q)),
                }))
                .filter((g) => g.items.length > 0);
              const showCustom = "custom raw json".includes(q);
              if (cats.length === 0 && !showCustom) {
                return (
                  <Text fz="sm" c="dimmed" ta="center" py="md">
                    No payload types match.
                  </Text>
                );
              }
              return (
                <Stack gap="xs">
                  {cats.map((g) => (
                    <Box key={g.category}>
                      <Text fz="xs" fw={700} c="dimmed" tt="uppercase" mb={2}>
                        {g.category}
                      </Text>
                      {g.items.map((m) => (
                        <NavLink
                          key={m.domain}
                          label={m.title}
                          description={m.description}
                          onClick={() => addPayload(m.domain)}
                          rightSection={
                            <Group gap={4} wrap="nowrap">
                              {m.platforms.map((p) => (
                                <Badge key={p} size="xs" variant="outline" color="gray">
                                  {p}
                                </Badge>
                              ))}
                            </Group>
                          }
                        />
                      ))}
                    </Box>
                  ))}
                  {showCustom && (
                    <Box>
                      <Text fz="xs" fw={700} c="dimmed" tt="uppercase" mb={2}>
                        Other
                      </Text>
                      <NavLink
                        label="Custom (raw JSON)"
                        description="Any payload type — edit the raw JSON."
                        onClick={() => addPayload("com.apple.custom")}
                      />
                    </Box>
                  )}
                </Stack>
              );
            })()}
          </ScrollArea.Autosize>
        </Stack>
      </Modal>
    </Stack>
  );
}
