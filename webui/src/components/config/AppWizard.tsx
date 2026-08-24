"use client";

import {useCallback, useEffect, useMemo, useState} from "react";
import {
    Alert,
    Badge,
    Button,
    Code,
    FileInput,
    Group,
    Loader,
    Modal,
    Progress,
    Radio,
    ScrollArea,
    SegmentedControl,
    Stack,
    Stepper,
    Switch,
    Text,
    TextInput,
} from "@mantine/core";
import {notifications} from "@mantine/notifications";
import {IconAlertTriangle, IconCheck, IconFileZip, IconSearch, IconUpload,} from "@tabler/icons-react";
import {api, type AppPackage, type Device} from "../../../lib/api";
import {
    type App,
    type AppVersion,
    BUNDLE_ID_RE,
    type Group as GroupDef,
    type Rollout,
    type Scope,
    SHA256_RE,
    SLUG_RE,
} from "../../../lib/config";
import {timeSince} from "../../../lib/time";
import {confirmDiscard} from "../../../lib/use-unsaved-changes";
import {RolloutEditor} from "./RolloutEditor";
import {ScopeEditor} from "./ScopeEditor";

// Where the package comes from. "storage" means the file is already in the bucket and only needs
// pointing at.
type PackageSource = "storage" | "upload" | "manual";

// Binary units, matching the controller's own quota message.
function humanBytes(n: number): string {
    if (!Number.isFinite(n) || n < 0) return "--";
    if (n < 1024) return `${n} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let value = n / 1024;
    let i = 0;
    while (value >= 1024 && i < units.length - 1) {
        value /= 1024;
        i += 1;
    }
    return `${value.toFixed(1)} ${units[i]}`;
}

export interface AppWizardProps {
    opened: boolean;
    onClose: () => void;
    token: string;
    allGroups: GroupDef[];
    devices: Device[];
    // Why uploading is unavailable, from GET /api/v1/readiness, or null when it is not blocked.
    // Shown verbatim, since the reason names the setting to change.
    uploadBlockedReason: string | null;
    takenIds: string[];
    // Every s3_key apps.yaml already points at, so the picker can mark those rows. Never blocks:
    // two app versions pointing at one object is legal.
    usedKeys?: string[];
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
                              allGroups,
                              devices,
                              uploadBlockedReason,
                              takenIds,
                              usedKeys = [],
                              existingApp,
                              onFinish,
                          }: AppWizardProps) {
    const addVersion = !!existingApp;
    const canUpload = !uploadBlockedReason;

    const [active, setActive] = useState(0);
    const [submitting, setSubmitting] = useState(false);

    // identity
    const [id, setId] = useState("");
    const [name, setName] = useState("");
    const [bundleId, setBundleId] = useState("");
    // Apple's InstallAsManaged, macOS only. On by default, which makes the app removable with the
    // MDM profile and matches how apps that never set it per app are deployed.
    const [installAsManaged, setInstallAsManaged] = useState(true);

    // package
    const [version, setVersion] = useState("");
    // Null until something is chosen, so until then the default follows the listing and readiness,
    // both of which are fetched asynchronously.
    const [source, setSource] = useState<PackageSource | null>(null);
    // True once the dialog's open animation has finished. SegmentedControl measures its own width to
    // place the active indicator, and measuring mid-animation leaves the indicator off to one side, so
    // it is remounted on this flag. Reset on close, since the dialog remounts its body each time.
    const [settled, setSettled] = useState(false);
    const [file, setFile] = useState<File | null>(null);
    const [s3Key, setS3Key] = useState("");
    const [sha256, setSha256] = useState("");
    const [uploading, setUploading] = useState(false);
    // What the controller read out of the uploaded .pkg. A component or unsigned package stores fine
    // and then fails on the device, so these stay on screen until another file is chosen.
    const [uploadWarnings, setUploadWarnings] = useState<string[]>([]);
    // The server's own words on a refused upload (a quota 413 above all), which outlive a toast.
    const [uploadError, setUploadError] = useState<string | null>(null);

    // what is already in the bucket (GET /apps/packages), loaded when the package
    // step opens. null = not read yet.
    const [packages, setPackages] = useState<AppPackage[] | null>(null);
    const [packagesLoading, setPackagesLoading] = useState(false);
    const [packagesError, setPackagesError] = useState<string | null>(null);
    const [usage, setUsage] = useState<{ used: number; quota: number | null } | null>(null);
    const [filter, setFilter] = useState("");
    const [checksumming, setChecksumming] = useState(false);

    // target (unified scope + optional gradual rollout)
    const [scope, setScope] = useState<Scope>({groups: [], conditions: []});
    const [rollout, setRollout] = useState<Rollout | undefined>(undefined);

    function reset() {
        setActive(0);
        setSettled(false);
        setId("");
        setName("");
        setBundleId("");
        setInstallAsManaged(true);
        setVersion("");
        setSource(null);
        setFile(null);
        setS3Key("");
        setSha256("");
        setUploadWarnings([]);
        setUploadError(null);
        setPackages(null);
        setPackagesError(null);
        setUsage(null);
        setFilter("");
        setScope({groups: [], conditions: []});
        setRollout(undefined);
    }

    function close() {
        reset();
        onClose();
    }

    // Anything typed or picked so far. Closing on an overlay click or Escape confirms first, since
    // an uploaded package's key and hash cost a full upload to get back.
    const hasInput =
        !!id ||
        !!name.trim() ||
        !!bundleId ||
        !!version.trim() ||
        !!s3Key ||
        !!sha256 ||
        !!file ||
        (scope.groups?.length ?? 0) > 0 ||
        (scope.conditions?.length ?? 0) > 0 ||
        (scope.include_devices?.length ?? 0) > 0 ||
        (scope.exclude_devices?.length ?? 0) > 0 ||
        !!rollout;

    function requestClose() {
        confirmDiscard({
            dirty: hasInput,
            what: addVersion ? "this version" : "this app",
            onConfirm: close,
        });
    }

    const effectiveAppId = addVersion ? existingApp!.id : id;

    //  per-step validity
    const identityValid =
        SLUG_RE.test(id) && !takenIds.includes(id) && name.trim().length > 0 && BUNDLE_ID_RE.test(bundleId);
    const packageValid = version.trim().length > 0 && s3Key.trim().length > 0 && SHA256_RE.test(sha256);
    // A version must target at least one group, condition, or included device.
    const targetValid =
        (scope.groups?.length ?? 0) > 0 ||
        (scope.conditions?.length ?? 0) > 0 ||
        (scope.include_devices?.length ?? 0) > 0;

    const versionClash = useMemo(
        () => addVersion && existingApp!.versions.some((v) => v.version === version.trim()),
        [addVersion, existingApp, version],
    );

    // step indices differ between the two modes
    const steps = addVersion
        ? (["package", "target", "review"] as const)
        : (["identity", "package", "target", "review"] as const);
    const current = steps[active];

    const loadPackages = useCallback(async () => {
        if (!token) return;
        setPackagesLoading(true);
        setPackagesError(null);
        try {
            const res = await api.listAppPackages(token);
            setPackages(res.packages);
            setUsage({used: res.usage_bytes, quota: res.quota_bytes});
        } catch (e: unknown) {
            // A 400 here is the same missing bucket that blocks uploads, in the server's own words.
            setPackagesError((e as Error).message);
            setPackages([]);
        } finally {
            setPackagesLoading(false);
        }
    }, [token]);

    // Read the bucket when the package step comes up, not when the wizard opens.
    useEffect(() => {
        if (!opened || current !== "package") return;
        if (packages !== null || packagesLoading || packagesError) return;
        loadPackages();
    }, [opened, current, packages, packagesLoading, packagesError, loadPackages]);

    // Storage is the default as soon as there is anything to pick, including while the listing is
    // still loading. An empty or unreadable bucket falls back to uploading, then to typing the key.
    const defaultSource: PackageSource =
        packagesLoading || (packages?.length ?? 0) > 0
            ? "storage"
            : canUpload
                ? "upload"
                : "manual";
    const effectiveSource: PackageSource = source ?? defaultSource;

    // The chosen file has been through the upload endpoint: picking a file clears the key, so the
    // two together can only mean this file was stored.
    const uploaded = !!file && !!s3Key;

    const visiblePackages = useMemo(() => {
        const needle = filter.trim().toLowerCase();
        const all = packages ?? [];
        return needle ? all.filter((p) => p.key.toLowerCase().includes(needle)) : all;
    }, [packages, filter]);

    function pickPackage(key: string) {
        const pkg = (packages ?? []).find((p) => p.key === key);
        setS3Key(key);
        // An unknown digest clears the field, so Next stays disabled until the checksum call fills it.
        setSha256(pkg?.sha256 ?? "");
    }

    async function computeChecksum() {
        if (!s3Key) return;
        setChecksumming(true);
        try {
            const res = await api.checksumAppPackage(token, s3Key);
            setSha256(res.sha256);
            setPackages((prev) =>
                prev ? prev.map((p) => (p.key === res.s3_key ? {...p, sha256: res.sha256} : p)) : prev,
            );
        } catch (e: unknown) {
            notifications.show({color: "red", title: "Checksum failed", message: (e as Error).message});
        } finally {
            setChecksumming(false);
        }
    }

    function onPickFile(f: File | null) {
        setFile(f);
        setSha256("");
        setS3Key("");
        setUploadWarnings([]);
        setUploadError(null);
    }

    async function doUpload() {
        if (!file || !effectiveAppId || !version.trim()) return;
        setUploading(true);
        setUploadError(null);
        try {
            const res = await api.uploadApp(token, file, effectiveAppId, version.trim());
            setS3Key(res.s3_key);
            // The digest is the server's, taken from the bytes it stored.
            setSha256(res.sha256);
            setUploadWarnings(res.warnings ?? []);
            notifications.show({color: "teal", message: "Package uploaded to S3"});
            // The new object changes both the listing and the usage line.
            loadPackages();
        } catch (e: unknown) {
            const message = (e as Error).message;
            setUploadError(message);
            notifications.show({color: "red", title: "Upload failed", message});
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
            const v: AppVersion = {
                version: version.trim(),
                s3_key: s3Key.trim(),
                sha256: sha256.trim().toLowerCase(),
                groups: scope.groups ?? [],
                ...(scope.conditions?.length ? {conditions: scope.conditions} : {}),
                ...(scope.include_devices?.length ? {include_devices: scope.include_devices} : {}),
                ...(scope.exclude_devices?.length ? {exclude_devices: scope.exclude_devices} : {}),
                ...(rollout ? {rollout} : {}),
            };
            const ok = addVersion
                ? await onFinish({kind: "version", appId: existingApp!.id, version: v})
                : await onFinish({
                    kind: "app",
                    app: {
                        id: id.trim(),
                        name: name.trim(),
                        bundle_id: bundleId.trim(),
                        install_as_managed: installAsManaged,
                        versions: [v],
                    },
                });
            if (ok) close();
        } finally {
            setSubmitting(false);
        }
    }

    return (
        <Modal
            opened={opened}
            onClose={requestClose}
            size="lg"
            title={addVersion ? `Add version to ${existingApp!.name}` : "Add app"}
            transitionProps={{onEntered: () => setSettled(true)}}
        >
            {/* Steps can be revisited but not skipped: jumping ahead would bypass canAdvance() and
          let Review submit an empty s3_key and sha256. */}
            <Stepper
                active={active}
                onStepClick={setActive}
                allowNextStepsSelect={false}
                size="sm"
                mb="lg"
            >
                {!addVersion && <Stepper.Step label="Identity" description="Name & bundle"/>}
                <Stepper.Step label="Package" description="Version & file"/>
                <Stepper.Step label="Target" description="Groups & OS"/>
                <Stepper.Step label="Review"/>
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
                                    ? "An app with this ID already exists."
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
                        description="Reverse-domain notation is expected."
                        placeholder="com.example.companyapp"
                        value={bundleId}
                        onChange={(e) => setBundleId(e.currentTarget.value)}
                        error={bundleId && !BUNDLE_ID_RE.test(bundleId) ? "Not a valid bundle identifier." : null}
                        withAsterisk
                    />
                    <Switch
                        label="Install as managed (macOS)"
                        description={
                            'Off lets macOS install packages that contain no .app, such as config or script ' +
                            "packages; on is required for the app to be removable by MDM."
                        }
                        checked={installAsManaged}
                        onChange={(e) => setInstallAsManaged(e.currentTarget.checked)}
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
                        error={versionClash ? "This version already exists for this app." : null}
                        withAsterisk
                    />
                    <SegmentedControl
                        key={settled ? "settled" : "opening"}
                        value={effectiveSource}
                        onChange={(v) => setSource(v as PackageSource)}
                        data={[
                            {label: "Upload a file", value: "upload"},
                            {label: "Choose from storage", value: "storage"},
                            {label: "Enter manually", value: "manual"},
                        ]}
                    />

                    {effectiveSource === "storage" && (
                        <Stack gap="sm">
                            {packagesLoading ? (
                                <Group gap={6}>
                                    <Loader size={14}/>
                                    <Text fz="xs" c="dimmed">
                                        Reading storage…
                                    </Text>
                                </Group>
                            ) : packagesError ? (
                                <Alert color="orange" variant="light" title="Could not list storage">
                                    <Stack gap="xs" align="flex-start">
                                        <Text fz="sm">{packagesError}</Text>
                                        <Text fz="sm">Enter the key manually if you know it.</Text>
                                        <Button size="xs" variant="light" onClick={loadPackages}>
                                            Retry
                                        </Button>
                                    </Stack>
                                </Alert>
                            ) : (packages ?? []).length === 0 ? (
                                <Alert color="gray" variant="light">
                                    Nothing in storage yet. Upload a file first; it then shows up here for every
                                    later version.
                                </Alert>
                            ) : (
                                <>
                                    <TextInput
                                        placeholder="Filter by key"
                                        leftSection={<IconSearch size={14}/>}
                                        value={filter}
                                        onChange={(e) => setFilter(e.currentTarget.value)}
                                    />
                                    <Radio.Group value={s3Key} onChange={pickPackage}>
                                        <ScrollArea.Autosize mah={240} type="auto" offsetScrollbars>
                                            <Stack gap={6}>
                                                {visiblePackages.map((p) => (
                                                    <Radio.Card key={p.key} value={p.key} p="xs">
                                                        <Group wrap="nowrap" align="center" gap="sm">
                                                            <Radio.Indicator/>
                                                            <Stack gap={2} style={{minWidth: 0}}>
                                                                <Group gap={6} wrap="nowrap">
                                                                    <Code>{p.key}</Code>
                                                                    {usedKeys.includes(p.key) && (
                                                                        <Badge size="xs" variant="light" color="gray">
                                                                            in use
                                                                        </Badge>
                                                                    )}
                                                                </Group>
                                                                <Group gap={6}>
                                                                    <Text fz="xs" c="dimmed">
                                                                        {humanBytes(p.size)} · {timeSince(p.last_modified)}
                                                                    </Text>
                                                                    <Badge
                                                                        size="xs"
                                                                        variant="light"
                                                                        color={p.sha256 ? "teal" : "gray"}
                                                                    >
                                                                        {p.sha256 ? "checksum known" : "no checksum yet"}
                                                                    </Badge>
                                                                </Group>
                                                            </Stack>
                                                        </Group>
                                                    </Radio.Card>
                                                ))}
                                                {visiblePackages.length === 0 && (
                                                    <Text fz="xs" c="dimmed">
                                                        Nothing matches that filter.
                                                    </Text>
                                                )}
                                            </Stack>
                                        </ScrollArea.Autosize>
                                    </Radio.Group>
                                    {/* Named here too: a filter can hide the row that is selected. */}
                                    {s3Key && (
                                        <Text fz="xs" c="dimmed">
                                            Selected: <Code>{s3Key}</Code>
                                        </Text>
                                    )}
                                    {s3Key && !sha256 && (
                                        <Group gap="sm">
                                            <Button variant="light" loading={checksumming} onClick={computeChecksum}>
                                                Compute checksum
                                            </Button>
                                            <Text fz="xs" c="dimmed">
                                                Reads the package once. A large one takes a few seconds.
                                            </Text>
                                        </Group>
                                    )}
                                    {s3Key && sha256 && (
                                        <Text fz="xs" c="dimmed">
                                            SHA-256: <Code>{sha256.slice(0, 16)}…</Code>
                                        </Text>
                                    )}
                                </>
                            )}
                        </Stack>
                    )}

                    {effectiveSource === "upload" && (
                        <Stack gap="sm">
                            {uploadBlockedReason && (
                                <Alert color="orange" variant="light">
                                    {uploadBlockedReason} Use &quot;Choose from storage&quot; if the package is
                                    already there.
                                </Alert>
                            )}
                            <FileInput
                                label="Package file"
                                description="Stored in this tenant's bucket, then hashed by the server."
                                placeholder="Choose .ipa / .pkg"
                                leftSection={<IconFileZip size={16}/>}
                                accept=".ipa,.pkg,.app,.zip,.mobileconfig"
                                value={file}
                                onChange={onPickFile}
                                disabled={!canUpload}
                                clearable
                            />
                            {uploadWarnings.length > 0 && (
                                <Alert
                                    color="yellow"
                                    variant="light"
                                    icon={<IconAlertTriangle size={16}/>}
                                    title="The package uploaded, but the device may refuse it"
                                >
                                    <Stack gap={6}>
                                        {uploadWarnings.map((w) => (
                                            <Text key={w} fz="sm">{w}</Text>
                                        ))}
                                    </Stack>
                                </Alert>
                            )}
                            {uploadError && (
                                <Alert color="red" variant="light" title="Upload failed">
                                    {uploadError}
                                </Alert>
                            )}
                            {/* Only what this upload produced: choosing a file clears both, so a key
                  carried over from the picker cannot read as stored. */}
                            {uploaded && (
                                <Text fz="xs" c="dimmed">
                                    SHA-256: <Code>{sha256.slice(0, 16)}…</Code>
                                </Text>
                            )}
                            <Group>
                                <Button
                                    variant="light"
                                    leftSection={<IconUpload size={16}/>}
                                    loading={uploading}
                                    disabled={!file || !version.trim() || !effectiveAppId}
                                    onClick={doUpload}
                                >
                                    Upload to storage
                                </Button>
                                {uploaded && (
                                    <Badge color="teal" variant="light" leftSection={<IconCheck size={12}/>}>
                                        Stored
                                    </Badge>
                                )}
                            </Group>
                            {uploaded && (
                                <Text fz="xs" c="dimmed">
                                    Key: <Code>{s3Key}</Code>
                                </Text>
                            )}
                        </Stack>
                    )}

                    {effectiveSource === "manual" && (
                        <Stack gap="sm">
                            <Text fz="xs" c="dimmed">
                                For a package this console cannot list, such as one in a bucket it has no
                                permission to read.
                            </Text>
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

                    {usage && (
                        <Stack gap={4}>
                            <Text fz="xs" c="dimmed">
                                {usage.quota === null
                                    ? `${humanBytes(usage.used)} used`
                                    : `${humanBytes(usage.used)} of ${humanBytes(usage.quota)} used`}
                            </Text>
                            {usage.quota !== null && usage.quota > 0 && (
                                <Progress
                                    size="xs"
                                    value={Math.min(100, (usage.used / usage.quota) * 100)}
                                    color={usage.used / usage.quota > 0.9 ? "red" : "blue"}
                                />
                            )}
                        </Stack>
                    )}
                </Stack>
            )}

            {current === "target" && (
                <Stack gap="md">
                    <ScopeEditor
                        scope={scope}
                        onChange={setScope}
                        devices={devices}
                        allGroups={allGroups}
                        groupsLabel="Install on groups"
                        groupsDescription="Devices in any of these groups receive this version."
                    />
                    <RolloutEditor rollout={rollout} onChange={setRollout}/>
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
                        {!addVersion && !installAsManaged && (
                            <Badge variant="light" color="gray">not managed on macOS</Badge>
                        )}
                        {rollout && (
                            <Badge variant="light" color="orange">
                                rollout {rollout.percent}%/{rollout.interval_hours === 24 ? "day" : rollout.interval_hours === 168 ? "week" : `${rollout.interval_hours}h`}
                            </Badge>
                        )}
                        {(scope.groups ?? []).map((g) => (
                            <Badge key={g} variant="dot" color="blue">
                                {g}
                            </Badge>
                        ))}
                        {(scope.conditions?.length ?? 0) > 0 && (
                            <Badge variant="light" color="grape">+{scope.conditions!.length} condition(s)</Badge>
                        )}
                        {(scope.include_devices?.length ?? 0) > 0 && (
                            <Badge variant="light" color="teal">+{scope.include_devices!.length} incl</Badge>
                        )}
                        {(scope.exclude_devices?.length ?? 0) > 0 && (
                            <Badge variant="light" color="red">−{scope.exclude_devices!.length} excl</Badge>
                        )}
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
                <Button variant="default" onClick={() => (active === 0 ? requestClose() : setActive(active - 1))}>
                    {active === 0 ? "Cancel" : "Back"}
                </Button>
                {current === "review" ? (
                    <Button onClick={finish} loading={submitting} leftSection={<IconCheck size={16}/>}>
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
