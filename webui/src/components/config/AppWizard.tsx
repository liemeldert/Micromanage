"use client";

import { useMemo, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Code,
  FileInput,
  Group,
  Loader,
  Modal,
  MultiSelect,
  SegmentedControl,
  Stack,
  Stepper,
  Text,
  TextInput,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconCheck, IconFileZip, IconUpload } from "@tabler/icons-react";
import { api } from "../../../lib/api";
import {
  BUNDLE_ID_RE,
  SHA256_RE,
  SLUG_RE,
  sha256Hex,
  type App,
  type AppVersion,
} from "../../../lib/config";

export interface AppWizardProps {
  opened: boolean;
  onClose: () => void;
  token: string;
  groupNames: string[];
  s3Configured: boolean;
  takenIds: string[];
  existingApp?: App; // present => "add version" mode (identity locked)
  // Returns true on a successful persist; the wizard then closes itself.
  onFinish: (result:
    | { kind: "app"; app: App }
    | { kind: "version"; appId: string; version: AppVersion }) => Promise<boolean>;
}

export function AppWizard({
  opened,
  onClose,
  token,
  groupNames,
  s3Configured,
  takenIds,
  existingApp,
  onFinish,
}: AppWizardProps) {
  const addVersion = !!existingApp;

  const [active, setActive] = useState(0);
  const [submitting, setSubmitting] = useState(false);

  // identity
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [bundleId, setBundleId] = useState("");

  // package
  const [version, setVersion] = useState("");
  const [source, setSource] = useState<"upload" | "manual">(s3Configured ? "upload" : "manual");
  const [file, setFile] = useState<File | null>(null);
  const [s3Key, setS3Key] = useState("");
  const [sha256, setSha256] = useState("");
  const [hashing, setHashing] = useState(false);
  const [uploading, setUploading] = useState(false);

  // target
  const [groups, setGroups] = useState<string[]>([]);
  const [minOs, setMinOs] = useState("");

  function reset() {
    setActive(0);
    setId("");
    setName("");
    setBundleId("");
    setVersion("");
    setSource(s3Configured ? "upload" : "manual");
    setFile(null);
    setS3Key("");
    setSha256("");
    setGroups([]);
    setMinOs("");
  }

  function close() {
    reset();
    onClose();
  }

  const effectiveAppId = addVersion ? existingApp!.id : id;

  // ── per-step validity ──────────────────────────────────────────────────────
  const identityValid =
    SLUG_RE.test(id) && !takenIds.includes(id) && name.trim().length > 0 && BUNDLE_ID_RE.test(bundleId);
  const packageValid = version.trim().length > 0 && s3Key.trim().length > 0 && SHA256_RE.test(sha256);
  const targetValid = groups.length > 0;

  const versionClash = useMemo(
    () => addVersion && existingApp!.versions.some((v) => v.version === version.trim()),
    [addVersion, existingApp, version],
  );

  // step indices differ between the two modes
  const steps = addVersion
    ? (["package", "target", "review"] as const)
    : (["identity", "package", "target", "review"] as const);
  const current = steps[active];

  async function onPickFile(f: File | null) {
    setFile(f);
    setSha256("");
    setS3Key("");
    if (!f) return;
    setHashing(true);
    try {
      setSha256(await sha256Hex(f));
    } catch {
      notifications.show({ color: "red", message: "Could not hash file in the browser" });
    } finally {
      setHashing(false);
    }
  }

  async function doUpload() {
    if (!file || !effectiveAppId || !version.trim()) return;
    setUploading(true);
    try {
      const res = await api.uploadApp(token, file, effectiveAppId, version.trim());
      setS3Key(res.s3_key);
      notifications.show({ color: "teal", message: "Package uploaded to S3" });
    } catch (e: unknown) {
      notifications.show({ color: "red", title: "Upload failed", message: (e as Error).message });
    } finally {
      setUploading(false);
    }
  }

  function canAdvance(): boolean {
    if (current === "identity") return identityValid;
    if (current === "package") return packageValid && !versionClash;
    if (current === "target") return targetValid;
    return true;
  }

  async function finish() {
    setSubmitting(true);
    try {
      const conditions =
        minOs.trim().length > 0
          ? [{ type: "os_version" as const, operator: "gte", value: minOs.trim() }]
          : undefined;
      const v: AppVersion = {
        version: version.trim(),
        s3_key: s3Key.trim(),
        sha256: sha256.trim().toLowerCase(),
        groups,
        ...(conditions ? { conditions } : {}),
      };
      const ok = addVersion
        ? await onFinish({ kind: "version", appId: existingApp!.id, version: v })
        : await onFinish({
            kind: "app",
            app: { id: id.trim(), name: name.trim(), bundle_id: bundleId.trim(), versions: [v] },
          });
      if (ok) close();
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal
      opened={opened}
      onClose={close}
      size="lg"
      title={addVersion ? `Add version to ${existingApp!.name}` : "Add app"}
    >
      <Stepper active={active} onStepClick={setActive} size="sm" mb="lg">
        {!addVersion && <Stepper.Step label="Identity" description="Name & bundle" />}
        <Stepper.Step label="Package" description="Version & file" />
        <Stepper.Step label="Target" description="Groups & OS" />
        <Stepper.Step label="Review" />
      </Stepper>

      {current === "identity" && (
        <Stack gap="md">
          <TextInput
            label="App ID"
            description="Internal identifier. Letters, numbers, '.', '_', '-'."
            placeholder="company-app"
            value={id}
            onChange={(e) => setId(e.currentTarget.value)}
            error={
              id && !SLUG_RE.test(id)
                ? "Invalid characters"
                : takenIds.includes(id)
                  ? "An app with this ID already exists"
                  : null
            }
            withAsterisk
          />
          <TextInput
            label="Display name"
            placeholder="Company App"
            value={name}
            onChange={(e) => setName(e.currentTarget.value)}
            withAsterisk
          />
          <TextInput
            label="Bundle ID"
            description="Reverse-domain notation."
            placeholder="com.example.companyapp"
            value={bundleId}
            onChange={(e) => setBundleId(e.currentTarget.value)}
            error={bundleId && !BUNDLE_ID_RE.test(bundleId) ? "Invalid bundle identifier" : null}
            withAsterisk
          />
        </Stack>
      )}

      {current === "package" && (
        <Stack gap="md">
          <TextInput
            label="Version"
            placeholder="1.0.0"
            value={version}
            onChange={(e) => setVersion(e.currentTarget.value)}
            error={versionClash ? "This version already exists for this app" : null}
            withAsterisk
          />
          <SegmentedControl
            value={source}
            onChange={(v) => setSource(v as "upload" | "manual")}
            data={[
              { label: "Upload package", value: "upload" },
              { label: "Already in storage", value: "manual" },
            ]}
          />

          {source === "upload" ? (
            <Stack gap="sm">
              {!s3Configured && (
                <Alert color="orange" variant="light">
                  S3 isn&apos;t configured for this tenant, so upload is unavailable. Configure it in
                  Settings, or switch to &quot;Already in storage&quot;.
                </Alert>
              )}
              <FileInput
                label="Package file"
                description="Hashed locally (SHA-256) before upload."
                placeholder="Choose .ipa / .pkg"
                leftSection={<IconFileZip size={16} />}
                accept=".ipa,.pkg,.app,.zip,.mobileconfig"
                value={file}
                onChange={onPickFile}
                disabled={!s3Configured}
                clearable
              />
              {hashing && (
                <Group gap={6}>
                  <Loader size={14} />
                  <Text fz="xs" c="dimmed">
                    Hashing…
                  </Text>
                </Group>
              )}
              {sha256 && (
                <Text fz="xs" c="dimmed">
                  SHA-256: <Code>{sha256.slice(0, 16)}…</Code>
                </Text>
              )}
              <Group>
                <Button
                  variant="light"
                  leftSection={<IconUpload size={16} />}
                  loading={uploading}
                  disabled={!file || !sha256 || !version.trim() || !effectiveAppId}
                  onClick={doUpload}
                >
                  Upload to storage
                </Button>
                {s3Key && (
                  <Badge color="teal" variant="light" leftSection={<IconCheck size={12} />}>
                    Stored
                  </Badge>
                )}
              </Group>
              {s3Key && (
                <Text fz="xs" c="dimmed">
                  Key: <Code>{s3Key}</Code>
                </Text>
              )}
            </Stack>
          ) : (
            <Stack gap="sm">
              <TextInput
                label="S3 key"
                description="Path of the package within the configured bucket/prefix."
                placeholder="company-app/company-app-1.0.0.ipa"
                value={s3Key}
                onChange={(e) => setS3Key(e.currentTarget.value)}
                withAsterisk
              />
              <TextInput
                label="SHA-256"
                description="64-character hex digest the device verifies the download against."
                placeholder="a1b2c3…"
                value={sha256}
                onChange={(e) => setSha256(e.currentTarget.value)}
                error={sha256 && !SHA256_RE.test(sha256) ? "Must be 64 hex characters" : null}
                withAsterisk
              />
            </Stack>
          )}
        </Stack>
      )}

      {current === "target" && (
        <Stack gap="md">
          <MultiSelect
            label="Install on groups"
            description="Devices in any of these groups receive this version."
            placeholder={groupNames.length ? "Select groups" : "No groups defined yet"}
            data={groupNames}
            value={groups}
            onChange={setGroups}
            searchable
            withAsterisk
            nothingFoundMessage="Create groups first on the Groups page"
          />
          <TextInput
            label="Minimum OS version"
            description="Optional. Only devices at or above this version are eligible."
            placeholder="e.g. 17.0"
            value={minOs}
            onChange={(e) => setMinOs(e.currentTarget.value)}
          />
        </Stack>
      )}

      {current === "review" && (
        <Stack gap="xs">
          <Text fz="sm">
            <b>{addVersion ? existingApp!.name : name}</b>{" "}
            <Text span c="dimmed">
              ({addVersion ? existingApp!.bundle_id : bundleId})
            </Text>
          </Text>
          <Group gap="xs">
            <Badge variant="light">v{version}</Badge>
            {minOs && <Badge variant="light" color="grape">OS ≥ {minOs}</Badge>}
            {groups.map((g) => (
              <Badge key={g} variant="dot" color="blue">
                {g}
              </Badge>
            ))}
          </Group>
          <Text fz="xs" c="dimmed">
            Key: <Code>{s3Key}</Code>
          </Text>
          <Text fz="xs" c="dimmed">
            SHA-256: <Code>{sha256.slice(0, 24)}…</Code>
          </Text>
        </Stack>
      )}

      <Group justify="space-between" mt="lg">
        <Button variant="default" onClick={() => (active === 0 ? close() : setActive(active - 1))}>
          {active === 0 ? "Cancel" : "Back"}
        </Button>
        {current === "review" ? (
          <Button onClick={finish} loading={submitting} leftSection={<IconCheck size={16} />}>
            {addVersion ? "Add version" : "Create app"}
          </Button>
        ) : (
          <Button onClick={() => setActive(active + 1)} disabled={!canAdvance()}>
            Next
          </Button>
        )}
      </Group>
    </Modal>
  );
}
