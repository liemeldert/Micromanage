"use client";

import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Collapse,
  Divider,
  Group,
  Loader,
  Modal,
  MultiSelect,
  Stack,
  Switch,
  Text,
  TextInput,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconChevronDown, IconChevronRight, IconInfoCircle } from "@tabler/icons-react";
import { api, ApiError, type DepSkipKey } from "../../../lib/api";
import type { Device } from "../../../lib/api";
import type { Profile, ProfilesConfig } from "../../../lib/config";
import { renderNameTemplate, unknownNameVariables } from "../../../lib/config";
import { useAuth } from "../../../lib/auth-context";
import { NameTemplateInput } from "../config/NameTemplateInput";

const PLATFORMS = ["iOS", "macOS", "tvOS"];

// A modest default that trims the noisiest Setup Assistant panes without blocking
// the essentials (Apple ID, passcode, biometrics stay on). Admins can adjust.
const DEFAULT_SKIP = [
  "Diagnostics",
  "Appearance",
  "Privacy",
  "TOS",
  "Restore",
  "Welcome",
  "iCloudStorage",
];

// A stand-in device for the live name preview.
const SAMPLE_DEVICE = {
  serial_number: "C02X1234ABCD",
  device_model: "MacBookPro18,3",
  hostname: "sample",
  os_version: "15.5",
  udid: "1234ABCD-5678-90EF-1234-567890ABCDEF",
  management_type: "apple_mdm",
} as unknown as Device;

function slugify(s: string): string {
  return (
    s
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "enrollment"
  );
}

function uniqueId(base: string, taken: Set<string>): string {
  if (!taken.has(base)) return base;
  let i = 2;
  while (taken.has(`${base}-${i}`)) i += 1;
  return `${base}-${i}`;
}

// A guided, low-ceremony builder for a DEP enrollment profile. Writes a valid
// enrollment profile into profiles.yaml (reusing the normal save + push path) so
// it shows up ready to push to Apple, and optionally sets the tenant-default
// device-name template applied at enrollment.
export function SimpleEnrollmentProfileForm({
  opened,
  onClose,
  onCreated,
}: {
  opened: boolean;
  onClose: () => void;
  onCreated: (profileId: string) => void;
}) {
  const { token } = useAuth();
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [existing, setExisting] = useState<Profile[]>([]);
  const [skipCatalog, setSkipCatalog] = useState<DepSkipKey[]>([]);
  const [busy, setBusy] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // ── form state ──────────────────────────────────────────────────────────
  const [name, setName] = useState("");
  const [platforms, setPlatforms] = useState<string[]>([...PLATFORMS]);
  const [removable, setRemovable] = useState(false);
  const [supervised, setSupervised] = useState(true);
  const [mandatory, setMandatory] = useState(true);
  const [skipItems, setSkipItems] = useState<string[]>([...DEFAULT_SKIP]);
  // Naming (tenant default).
  const [nameTemplate, setNameTemplate] = useState("");
  const [applyOnEnroll, setApplyOnEnroll] = useState(true);
  const [initialNaming, setInitialNaming] = useState<{ template: string; apply: boolean }>({
    template: "",
    apply: false,
  });
  // Advanced.
  const [awaitConfigured, setAwaitConfigured] = useState(false);
  const [allowPairing, setAllowPairing] = useState(true);
  const [autoAdvance, setAutoAdvance] = useState(false);
  const [supportPhone, setSupportPhone] = useState("");
  const [supportEmail, setSupportEmail] = useState("");
  const [department, setDepartment] = useState("");

  useEffect(() => {
    if (!opened || !token) return;
    let alive = true;
    setLoading(true);
    setLoadError(null);
    Promise.all([
      api.getConfig(token, "profiles"),
      api.getDepSkipKeys(token).catch(() => ({ skip_keys: [] as DepSkipKey[] })),
      api.getTenant(token).catch(() => null),
    ])
      .then(([cfg, skip, tenant]) => {
        if (!alive) return;
        setExisting(((cfg as unknown as ProfilesConfig).profiles ?? []) as Profile[]);
        setSkipCatalog(skip.skip_keys ?? []);
        const dn = tenant?.device_naming ?? {};
        const tpl = typeof dn.template === "string" ? dn.template : "";
        setNameTemplate(tpl);
        setApplyOnEnroll(tpl ? dn.apply_on_enroll !== false : true);
        setInitialNaming({ template: tpl, apply: !!dn.apply_on_enroll });
      })
      .catch((e) => alive && setLoadError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [opened, token]);

  const skipOptions =
    skipCatalog.length > 0
      ? skipCatalog.map((k) => ({
          value: k.name,
          label: k.deprecated ? `${k.label} (deprecated)` : `${k.label} · ${k.platforms}`,
        }))
      : DEFAULT_SKIP.map((k) => ({ value: k, label: k }));

  const namePreview = renderNameTemplate(nameTemplate, SAMPLE_DEVICE);
  const unknownVars = unknownNameVariables(nameTemplate);
  const namingChanged =
    nameTemplate.trim() !== initialNaming.template || applyOnEnroll !== initialNaming.apply;

  async function create() {
    if (!token) return;
    const trimmed = name.trim();
    if (!trimmed) {
      notifications.show({ color: "red", message: "Give the profile a name." });
      return;
    }
    if (platforms.length === 0) {
      notifications.show({ color: "red", message: "Pick at least one platform." });
      return;
    }
    setBusy(true);
    try {
      const taken = new Set(existing.map((p) => p.id));
      const id = uniqueId(slugify(trimmed), taken);

      const payload: Record<string, unknown> = {
        is_supervised: supervised,
        is_mandatory: mandatory,
        is_mdm_removable: removable,
        await_device_configured: awaitConfigured,
        allow_pairing: allowPairing,
        auto_advance_setup: autoAdvance,
      };
      if (skipItems.length) payload.skip_setup_items = skipItems;
      if (supportPhone.trim()) payload.support_phone_number = supportPhone.trim();
      if (supportEmail.trim()) payload.support_email_address = supportEmail.trim();
      if (department.trim()) payload.department = department.trim();

      const profile: Profile = {
        id,
        name: trimmed,
        type: "enrollment",
        dep_profile: true,
        platforms,
        payload,
      };

      await api.updateConfig(token, "profiles", { profiles: [...existing, profile] });

      // Tenant-default naming template (applies to all devices at enrollment). Only
      // touch it when the admin actually set or changed it here.
      if (namingChanged && nameTemplate.trim()) {
        await api.updateTenant(token, {
          device_naming: { template: nameTemplate.trim(), apply_on_enroll: applyOnEnroll },
        });
      }

      notifications.show({ color: "green", message: `Created enrollment profile "${trimmed}".` });
      onCreated(id);
      onClose();
    } catch (e) {
      notifications.show({
        color: "red",
        title: "Could not create profile",
        message: e instanceof ApiError ? e.message : String(e),
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title="Create a simple enrollment profile"
      size="lg"
      centered
    >
      {loading ? (
        <Group justify="center" py="xl">
          <Loader />
        </Group>
      ) : loadError ? (
        <Alert color="red" title="Could not load configuration">
          {loadError}
        </Alert>
      ) : (
        <Stack gap="md">
          <Text size="sm" c="dimmed">
            The basics for how devices set up out of the box. You can fine-tune everything later
            in the full profile editor.
          </Text>

          <TextInput
            label="Profile name"
            placeholder="Standard enrollment"
            value={name}
            onChange={(e) => setName(e.currentTarget.value)}
            required
            maxLength={125}
          />

          <MultiSelect
            label="Platforms"
            data={PLATFORMS}
            value={platforms}
            onChange={setPlatforms}
            comboboxProps={{ withinPortal: false }}
          />

          <Switch
            label="Allow users to remove management"
            description="Off (recommended) keeps the MDM profile locked on the device."
            checked={removable}
            onChange={(e) => setRemovable(e.currentTarget.checked)}
          />
          <Switch
            label="Supervised"
            description="Enables the full set of management controls. Recommended for company-owned devices."
            checked={supervised}
            onChange={(e) => setSupervised(e.currentTarget.checked)}
          />
          <Switch
            label="Mandatory enrollment"
            description="The user cannot skip MDM enrollment during setup."
            checked={mandatory}
            onChange={(e) => setMandatory(e.currentTarget.checked)}
          />

          <MultiSelect
            label="Skip these Setup Assistant panes"
            placeholder="Search panes…"
            data={skipOptions}
            value={skipItems}
            onChange={setSkipItems}
            searchable
            clearable
            comboboxProps={{ withinPortal: false }}
            description="Hidden during setup so users reach the home screen faster."
          />

          <Divider label="Device naming" labelPosition="left" />
          <Text size="xs" c="dimmed" mt={-8}>
            Sets the tenant-wide default name applied to devices as they enroll. A group-specific
            naming rule (Groups → device naming) overrides this for its members.
          </Text>
          <NameTemplateInput
            label="Device name template"
            placeholder="IT-{serial}"
            value={nameTemplate}
            onChange={setNameTemplate}
          />
          {nameTemplate.trim() && (
            <>
              <Text size="xs" c="dimmed">
                Preview: <b>{namePreview || "(empty)"}</b>
              </Text>
              {unknownVars.length > 0 && (
                <Alert color="orange" variant="light" icon={<IconInfoCircle size={16} />}>
                  Unknown variable(s): {unknownVars.map((v) => `{${v}}`).join(", ")}. These render
                  as empty.
                </Alert>
              )}
              <Switch
                label="Apply automatically on enrollment"
                description="When off, the template is only offered as a suggested name in the rename dialog."
                checked={applyOnEnroll}
                onChange={(e) => setApplyOnEnroll(e.currentTarget.checked)}
              />
            </>
          )}

          <Divider />
          <Button
            variant="subtle"
            size="xs"
            w="fit-content"
            leftSection={
              showAdvanced ? <IconChevronDown size={14} /> : <IconChevronRight size={14} />
            }
            onClick={() => setShowAdvanced((v) => !v)}
          >
            Advanced options
          </Button>
          <Collapse in={showAdvanced}>
            <Stack gap="md">
              <Switch
                label="Await final configuration"
                description="Hold the device in Setup Assistant until released — pair with an ATC flow ending in “Release from Setup Assistant” for true zero-touch."
                checked={awaitConfigured}
                onChange={(e) => setAwaitConfigured(e.currentTarget.checked)}
              />
              <Switch
                label="Allow host pairing"
                checked={allowPairing}
                onChange={(e) => setAllowPairing(e.currentTarget.checked)}
              />
              <Switch
                label="Auto-advance setup (tvOS)"
                checked={autoAdvance}
                onChange={(e) => setAutoAdvance(e.currentTarget.checked)}
              />
              <TextInput
                label="Support phone number"
                value={supportPhone}
                onChange={(e) => setSupportPhone(e.currentTarget.value)}
              />
              <TextInput
                label="Support email"
                value={supportEmail}
                onChange={(e) => setSupportEmail(e.currentTarget.value)}
              />
              <TextInput
                label="Department / location"
                value={department}
                onChange={(e) => setDepartment(e.currentTarget.value)}
              />
            </Stack>
          </Collapse>

          <Group justify="flex-end" mt="sm">
            <Button variant="subtle" onClick={onClose}>
              Cancel
            </Button>
            <Button onClick={create} loading={busy} disabled={!name.trim() || platforms.length === 0}>
              Create profile
            </Button>
          </Group>
        </Stack>
      )}
    </Modal>
  );
}
