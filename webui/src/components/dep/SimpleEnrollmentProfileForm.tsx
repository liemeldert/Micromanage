import {useEffect, useRef, useState} from "react";
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
import {notifications} from "@mantine/notifications";
import {IconChevronDown, IconChevronRight, IconInfoCircle} from "@tabler/icons-react";
import type {Device} from "../../../lib/api";
import {api, ApiError, configConflict, type DepSkipKey} from "../../../lib/api";
import type {Profile, ProfilesConfig} from "../../../lib/config";
import {renderNameTemplate, showConfigConflict, unknownNameVariables} from "../../../lib/config";
import {useAuth} from "../../../lib/auth-context";
import {NameTemplateInput} from "../config/NameTemplateInput";
// Target platforms come from the shared vocabulary the full profile editor and
// the controller's validator use, so both editors offer the same list.
import {ALL_PLATFORMS} from "../../../lib/profile-manifests";

// Apple Watch has no Automated Device Enrollment, so DEP cannot target it. Filtering ALL_PLATFORMS keeps this in
// step with the shared list.
const DEP_PLATFORMS = ALL_PLATFORMS.filter((p) => p !== "watchOS");

// The noisiest Setup Assistant panes, skipped by default. Apple ID, passcode and biometrics stay on.
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

// A guided builder for a DEP enrollment profile. It writes the profile into profiles.yaml through the normal save
// path, ready to push to Apple, and can set the tenant-default device-name template applied at enrollment.
export function SimpleEnrollmentProfileForm({
                                                opened,
                                                onClose,
                                                onCreated,
                                            }: {
    opened: boolean;
    onClose: () => void;
    onCreated: (profileId: string) => void;
}) {
    const {token} = useAuth();
    const [loading, setLoading] = useState(true);
    const [loadError, setLoadError] = useState<string | null>(null);
    const [existing, setExisting] = useState<Profile[]>([]);
    // Version of profiles.yaml as read, sent back on the save. Creating a profile rewrites the whole document, so
    // without it a profile saved elsewhere since this modal opened would be dropped.
    const [version, setVersion] = useState<string | undefined>(undefined);
    const [skipCatalog, setSkipCatalog] = useState<DepSkipKey[]>([]);
    const [busy, setBusy] = useState(false);
    const [showAdvanced, setShowAdvanced] = useState(false);

    //  form state
    const [name, setName] = useState("");
    const [platforms, setPlatforms] = useState<string[]>([...DEP_PLATFORMS]);
    const [removable, setRemovable] = useState(false);
    const [supervised, setSupervised] = useState(true);
    // What removable was before turning Supervised off forced it on.
    const removableBeforeForce = useRef(false);
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
            api.getConfigWithVersion(token, "profiles"),
            api.getDepSkipKeys(token).catch(() => ({skip_keys: [] as DepSkipKey[]})),
            api.getTenant(token).catch(() => null),
        ])
            .then(([cfg, skip, tenant]) => {
                if (!alive) return;
                setExisting(((cfg.data as unknown as ProfilesConfig).profiles ?? []) as Profile[]);
                setVersion(cfg.version);
                setSkipCatalog(skip.skip_keys ?? []);
                const dn = tenant?.device_naming ?? {};
                const tpl = typeof dn.template === "string" ? dn.template : "";
                setNameTemplate(tpl);
                // The server reads a missing apply_on_enroll as false, so a stored template with the flag absent
                // shows as off here too. Otherwise creating a profile would switch naming on unasked.
                setApplyOnEnroll(tpl ? dn.apply_on_enroll === true : true);
                setInitialNaming({template: tpl, apply: !!dn.apply_on_enroll});
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
            : DEFAULT_SKIP.map((k) => ({value: k, label: k}));

    const namePreview = renderNameTemplate(nameTemplate, SAMPLE_DEVICE);
    const unknownVars = unknownNameVariables(nameTemplate);
    const namingChanged =
        nameTemplate.trim() !== initialNaming.template || applyOnEnroll !== initialNaming.apply;

    // Re-read profiles.yaml without touching the form, which is what the conflict modal's Reload does: the
    // filled-in fields stay, and the next attempt is written on top of the other profile rather than over it.
    async function reloadExisting() {
        if (!token) return;
        try {
            const res = await api.getConfigWithVersion(token, "profiles");
            setExisting(((res.data as unknown as ProfilesConfig).profiles ?? []) as Profile[]);
            setVersion(res.version);
        } catch (e) {
            notifications.show({
                color: "red",
                message: e instanceof ApiError ? e.message : String(e),
            });
        }
    }

    async function create() {
        if (!token) return;
        const trimmed = name.trim();
        if (!trimmed) {
            notifications.show({color: "red", message: "Give the profile a name."});
            return;
        }
        if (platforms.length === 0) {
            notifications.show({color: "red", message: "Pick at least one platform."});
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

            await api.updateConfig(token, "profiles", {profiles: [...existing, profile]},
                undefined, {ifMatch: version});

            // Tenant-default naming template, applied to all devices at enrollment. Written only when it was set or
            // changed here.
            if (namingChanged && nameTemplate.trim()) {
                await api.updateTenant(token, {
                    device_naming: {template: nameTemplate.trim(), apply_on_enroll: applyOnEnroll},
                });
            }

            notifications.show({color: "green", message: `Created enrollment profile "${trimmed}".`});
            onCreated(id);
            onClose();
        } catch (e) {
            const conflict = configConflict(e);
            if (conflict) {
                showConfigConflict(
                    "Profiles changed while this was open. Reload, then create again. Nothing you typed is lost.",
                    reloadExisting,
                );
                return;
            }
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
                    <Loader/>
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
                        data={[...DEP_PLATFORMS]}
                        value={platforms}
                        onChange={setPlatforms}
                        comboboxProps={{withinPortal: false}}
                    />

                    <Switch
                        label="Allow users to remove management"
                        description={
                            supervised
                                ? "Off (recommended) keeps the MDM profile locked on the device."
                                : "Apple only allows a locked MDM profile on a supervised device, so this stays on while Supervised is off."
                        }
                        checked={removable}
                        disabled={!supervised}
                        onChange={(e) => setRemovable(e.currentTarget.checked)}
                    />
                    <Switch
                        label="Supervised"
                        description="Enables the full set of management controls. Recommended for company-owned devices."
                        checked={supervised}
                        onChange={(e) => {
                            const on = e.currentTarget.checked;
                            setSupervised(on);
                            if (!on) {
                                // A non-removable profile is only valid on a supervised device, so leaving it off
                                // here would build a combination the server rejects.
                                removableBeforeForce.current = removable;
                                setRemovable(true);
                            } else {
                                setRemovable(removableBeforeForce.current);
                            }
                        }}
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
                        comboboxProps={{withinPortal: false}}
                        description="Hidden during setup so users reach the home screen faster."
                    />

                    <Divider label="Device naming" labelPosition="left"/>
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
                                <Alert color="orange" variant="light" icon={<IconInfoCircle size={16}/>}>
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

                    <Divider/>
                    <Button
                        variant="subtle"
                        size="xs"
                        w="fit-content"
                        leftSection={
                            showAdvanced ? <IconChevronDown size={14}/> : <IconChevronRight size={14}/>
                        }
                        onClick={() => setShowAdvanced((v) => !v)}
                    >
                        Advanced options
                    </Button>
                    <Collapse in={showAdvanced}>
                        <Stack gap="md">
                            <Switch
                                label="Await final configuration"
                                description={'Holds the device in Setup Assistant until something releases it. Pair this with a flow ending in a "Release from Setup Assistant" step, or the device sits on the Remote Management screen.'}
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
