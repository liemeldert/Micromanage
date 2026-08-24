"use client";

import {useEffect, useMemo, useRef, useState} from "react";
import {useRouter} from "next/navigation";
import {
    ActionIcon,
    Alert,
    Badge,
    Box,
    Button,
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
    Tooltip,
    UnstyledButton,
} from "@mantine/core";
import {notifications} from "@mantine/notifications";
import {
    IconArrowLeft,
    IconDeviceFloppy,
    IconInfoCircle,
    IconLayoutGrid,
    IconPlus,
    IconSearch,
    IconTrash,
} from "@tabler/icons-react";
import {api, type Device} from "../../../lib/api";
import {useAuth} from "../../../lib/auth-context";
import {
    type Condition,
    type Group as GroupDef,
    type Profile,
    type ProfileKind,
    profilePayloads,
    type ProfilesConfig,
    type Rollout,
    type Scope,
    SLUG_RE,
    slugifyConfigId,
    useConfigResource,
} from "../../../lib/config";
import {
    ALL_PLATFORMS,
    blankPayload,
    ENROLLMENT_MANIFEST,
    getManifest,
    manifestsByCategory,
    type Platform,
} from "../../../lib/profile-manifests";
import {dateTypes, type PlistTypes} from "../../../lib/plist";
import {confirmDiscard, useBeforeUnload} from "../../../lib/use-unsaved-changes";
import {PayloadForm} from "./PayloadForm";
import {RolloutEditor} from "./RolloutEditor";
import {ScopeEditor} from "./ScopeEditor";
import {SidebarLayout} from "../layout/SidebarLayout";
import {GlassCard} from "../ui/GlassCard";

export const IMPORT_KEY = "mm_profile_import";
// The <date> keys an import recovered (lib/plist parseMobileconfig). Data keys live in the profile's
// own data_keys; dates have nowhere to live, since profiles.yaml holds JSON values with no plist
// type, so they sit beside the draft in sessionStorage. That store is tab-scoped: a download in a
// later session types what the manifests and data_keys know, and warns about the rest.
export const IMPORT_TYPES_KEY = "mm_profile_import_types";
const PLIST_TYPES_KEY = "mm_profile_plist_types";

function readTypeStore(): Record<string, PlistTypes> {
    if (typeof window === "undefined") return {};
    try {
        const raw = sessionStorage.getItem(PLIST_TYPES_KEY);
        const all = raw ? JSON.parse(raw) : null;
        return all && typeof all === "object" ? (all as Record<string, PlistTypes>) : {};
    } catch {
        return {};
    }
}

// The date types recorded for a saved profile, for export. Filtered on the way out as well as in, so
// a stale entry cannot type a data key behind data_keys' back.
export function readDateTypes(id: string): PlistTypes | undefined {
    const t = dateTypes(readTypeStore()[id] ?? {});
    return Object.keys(t).length ? t : undefined;
}

function writeDateTypes(id: string, types: PlistTypes) {
    if (typeof window === "undefined" || !Object.keys(types).length) return;
    try {
        sessionStorage.setItem(PLIST_TYPES_KEY, JSON.stringify({...readTypeStore(), [id]: types}));
    } catch {
        // A full or disabled sessionStorage costs the hints, nothing else.
    }
}

// Meta keys every payload carries. None is ever binary, so keep them out of the
// data_keys picker.
const PAYLOAD_META_KEYS = new Set([
    "PayloadType",
    "PayloadVersion",
    "PayloadIdentifier",
    "PayloadUUID",
    "PayloadDisplayName",
    "PayloadDescription",
    "PayloadOrganization",
    "PayloadEnabled",
]);

// Key names in a payload that hold a string somewhere. Only string leaves are decoded
// (see profile_manager._decode_data_values), so declaring anything else does nothing.
function stringKeyNames(value: unknown, out: Set<string>, key?: string) {
    if (typeof value === "string") {
        if (key && !PAYLOAD_META_KEYS.has(key)) out.add(key);
    } else if (Array.isArray(value)) {
        for (const v of value) stringKeyNames(v, out, key);
    } else if (value && typeof value === "object") {
        for (const [k, v] of Object.entries(value)) stringKeyNames(v, out, k);
    }
}

interface DraftState {
    id: string;
    name: string;
    description: string;
    kind: ProfileKind;
    platforms: Platform[];
    groups: string[];
    conditions: Condition[];
    include_devices: string[];
    exclude_devices: string[];
    rollout?: Rollout;
    payloads: Record<string, unknown>[];
    enrollment: Record<string, unknown>;
    // Key names whose base64 values must reach the device as plist <data>. Saved as
    // the profile's data_keys.
    dataKeys: string[];
    // Keys of the saved profile this form doesn't model (payload_type, and
    // anything a YAML author wrote by hand). Carried through the round-trip so
    // opening a profile and saving it can't silently delete parts of it.
    extra: Record<string, unknown>;
    // What an import said each date key was. Stripped from what gets saved;
    // see PLIST_TYPES_KEY above.
    dates: PlistTypes;
}

// Everything the form writes back. Any other key on a loaded profile goes to draft.extra untouched.
const FORM_OWNED_KEYS = new Set([
    "id",
    "name",
    "description",
    "type",
    "dep_profile",
    "platforms",
    "groups",
    "conditions",
    "include_devices",
    "exclude_devices",
    "rollout",
    "payload",
    // dep_manager reads payload before enrollment, so the form owns both keys and writes exactly one
    // of them; carrying the other through would leave a stale copy under the settings on screen.
    "enrollment",
    "payloads",
    "data_keys",
]);

function fromProfile(p: Profile, dates: PlistTypes = {}): DraftState {
    const kind: ProfileKind = p.type === "enrollment" || p.dep_profile ? "enrollment" : "configuration";
    const platforms = (p.platforms as Platform[] | undefined)?.filter((x) =>
        ALL_PLATFORMS.includes(x),
    );
    const extra: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(p)) {
        if (!FORM_OWNED_KEYS.has(k) && v !== undefined) extra[k] = v;
    }
    return {
        id: p.id,
        name: p.name,
        description: p.description ?? "",
        kind,
        platforms: platforms && platforms.length ? platforms : ["iOS", "macOS"],
        groups: p.groups ?? [],
        conditions: p.conditions ?? [],
        include_devices: p.include_devices ?? [],
        exclude_devices: p.exclude_devices ?? [],
        rollout: p.rollout,
        payloads: kind === "configuration" ? profilePayloads(p) : [],
        // Read in the same order dep_manager does.
        enrollment: kind === "enrollment" ? (p.payload ?? p.enrollment ?? {}) : {},
        dataKeys: p.data_keys ?? [],
        extra,
        dates,
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
    return {title: m ? m.title : (pl.PayloadType as string) || "Custom payload", subtitle: sub};
}

// profiles.yaml is outside MEMBER_WRITABLE_CONFIG_TYPES (controller/auth), so a member's save is
// refused with 403. The form still renders; payload secrets come back redacted.
const ADMIN_ONLY_REASON =
    "A profile changes settings on every device it targets, so authoring one is admin-only.";

export function ProfileEditor({profileId}: { profileId?: string }) {
    const router = useRouter();
    const {token, isAdmin} = useAuth();
    const {data, loading, saving, save} = useConfigResource<ProfilesConfig>("profiles", {
        profiles: [],
    });

    const [groups, setGroups] = useState<GroupDef[]>([]);
    const [devices, setDevices] = useState<Device[]>([]);
    const [draft, setDraft] = useState<DraftState | null>(null);
    const [selected, setSelected] = useState<number | null>(null);
    const [mode, setMode] = useState<"form" | "json">("form");
    const [payloadText, setPayloadText] = useState("{}");
    // Non-null while the raw JSON on screen does not match the draft. Saving waits for it to parse,
    // otherwise the last text that happened to parse would be saved instead of what is on screen.
    const [payloadTextError, setPayloadTextError] = useState<string | null>(null);
    // Bumped on every delete. PayloadForm holds per-field local text, so it is
    // keyed on the selected index plus this, and a delete that keeps the index
    // still remounts it onto the payload that moved into the slot.
    const [payloadEpoch, setPayloadEpoch] = useState(0);
    const [idError, setIdError] = useState<string | null>(null);
    // The id follows the name until the id itself is edited, after which the name no longer rewrites
    // it. Only creation derives an id; an existing profile's is immutable and the field is disabled.
    const [idTouched, setIdTouched] = useState(false);
    const [initialized, setInitialized] = useState(false);
    const [notFound, setNotFound] = useState(false);
    const [addOpen, setAddOpen] = useState(false);
    const [addQuery, setAddQuery] = useState("");
    // The draft as the editor opened on, so the guards below can tell a touched
    // form from an untouched one.
    const baseline = useRef("");

    useEffect(() => {
        if (!token) return;
        api
            .getConfig(token, "groups")
            .then((g) => setGroups((g as { groups?: GroupDef[] }).groups ?? []))
            .catch(() => {
            });
        api
            .listDevices(token, {state: "enrolled", limit: 500})
            .then((r) => setDevices(r.devices))
            .catch(() => {
            });
    }, [token]);

    // Live scope from the draft, and the on-disk scope (for the change diff).
    const draftScope: Scope = useMemo(
        () => ({
            groups: draft?.groups ?? [],
            conditions: draft?.conditions ?? [],
            include_devices: draft?.include_devices ?? [],
            exclude_devices: draft?.exclude_devices ?? [],
        }),
        [draft?.groups, draft?.conditions, draft?.include_devices, draft?.exclude_devices],
    );

    const savedScope: Scope | undefined = useMemo(() => {
        if (!profileId) return undefined;
        const p = data?.profiles?.find((x) => x.id === profileId);
        if (!p) return undefined;
        return {
            groups: p.groups ?? [],
            conditions: p.conditions ?? [],
            include_devices: p.include_devices ?? [],
            exclude_devices: p.exclude_devices ?? [],
        };
    }, [data?.profiles, profileId]);

    // Initialise the draft once the config load settles, even if it came back
    // empty or errored. A missing config is just an empty profile list.
    useEffect(() => {
        if (initialized || loading) return;
        const profiles = data?.profiles ?? [];

        const startDraft = (d: DraftState) => {
            baseline.current = JSON.stringify(d);
            setDraft(d);
            setSelected(d.payloads.length ? 0 : null);
        };

        let seed: Profile | null = null;
        let seedDates: PlistTypes = {};
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
            const rawTypes = sessionStorage.getItem(IMPORT_TYPES_KEY);
            if (rawTypes) {
                try {
                    seedDates = dateTypes(JSON.parse(rawTypes) as PlistTypes);
                } catch {
                    /* ignore */
                }
                sessionStorage.removeItem(IMPORT_TYPES_KEY);
            }
        }

        if (profileId) {
            const p = profiles.find((x) => x.id === profileId);
            if (!p) {
                setNotFound(true);
                setInitialized(true);
                return;
            }
            // Editing keeps whatever the import recorded, so re-saving doesn't drop it.
            startDraft(fromProfile(p, readDateTypes(profileId) ?? {}));
        } else if (seed) {
            startDraft(fromProfile(seed, seedDates));
        } else {
            startDraft({
                id: "",
                name: "",
                description: "",
                kind: "configuration",
                platforms: ["iOS", "macOS"],
                groups: [],
                conditions: [],
                include_devices: [],
                exclude_devices: [],
                payloads: [],
                enrollment: {},
                dataKeys: [],
                extra: {},
                dates: {},
            });
        }
        setInitialized(true);
    }, [loading, data, initialized, profileId]);

    // Every field on this form lives in draft, so comparing it against what the editor opened on is
    // enough to know whether anything would be lost.
    const dirty = !!draft && JSON.stringify(draft) !== baseline.current;
    useBeforeUnload(dirty);
    const leaveEditor = () =>
        confirmDiscard({dirty, what: "this profile", onConfirm: () => router.push("/profiles")});

    // The JSON view and the form/json toggle belong to whichever payload is on
    // screen, so they move together with it.
    function syncPayloadView(pl?: Record<string, unknown>) {
        setMode(pl && getManifest(pl.PayloadType as string) ? "form" : "json");
        setPayloadText(pl ? JSON.stringify(pl, null, 2) : "{}");
        setPayloadTextError(null);
    }

    useEffect(() => {
        if (!draft || selected === null || !draft.payloads[selected]) return;
        syncPayloadView(draft.payloads[selected]);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [selected]);

    function update(patch: Partial<DraftState>) {
        setDraft((d) => (d ? {...d, ...patch} : d));
    }

    function updateSelectedPayload(next: Record<string, unknown>) {
        if (!draft || selected === null) return;
        update({payloads: draft.payloads.map((p, i) => (i === selected ? next : p))});
    }

    function addPayload(domain: string) {
        if (!draft) return;
        const m = getManifest(domain);
        const pl = m ? blankPayload(m) : {PayloadType: domain};
        const payloads = [...draft.payloads, pl];
        update({payloads});
        setSelected(payloads.length - 1);
        setAddOpen(false);
        setAddQuery("");
    }

    function removePayload(i: number) {
        if (!draft) return;
        const payloads = draft.payloads.filter((_, idx) => idx !== i);
        const next = payloads.length ? Math.min(i, payloads.length - 1) : null;
        update({payloads});
        setSelected(next);
        // Deleting #0 of 2 leaves index 0 selected on a different payload, and the effect above only
        // runs on an index change, so resync the JSON text and the form's own field state here.
        setPayloadEpoch((n) => n + 1);
        syncPayloadView(next === null ? undefined : payloads[next]);
    }

    // Parse the raw JSON editor's text into the draft. Anything that is not a usable payload object
    // leaves the draft alone and records an error, so a blank or invalid box cannot save as an empty
    // object and lose PayloadType.
    function commitPayloadText(text: string): boolean {
        const trimmed = text.trim();
        if (!trimmed) {
            setPayloadTextError("A payload can't be empty.");
            return false;
        }
        let parsed: unknown;
        try {
            parsed = JSON.parse(trimmed);
        } catch {
            setPayloadTextError("Invalid JSON.");
            return false;
        }
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
            setPayloadTextError("A payload must be a JSON object.");
            return false;
        }
        setPayloadTextError(null);
        updateSelectedPayload(parsed as Record<string, unknown>);
        return true;
    }

    function switchMode(m: "form" | "json") {
        if (selected === null || !draft) return;
        if (m === "json") {
            setPayloadText(JSON.stringify(draft.payloads[selected] ?? {}, null, 2));
            setPayloadTextError(null);
        } else if (!commitPayloadText(payloadText)) {
            notifications.show({color: "red", message: "Fix the JSON before switching to the form."});
            return;
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
            notifications.show({color: "red", message: "Name is required."});
            return;
        }
        if (draft.kind === "configuration" && draft.payloads.length === 0) {
            notifications.show({color: "orange", message: "Add at least one payload."});
            return;
        }
        if (payloadTextError) {
            notifications.show({color: "red", message: `Fix the payload JSON first: ${payloadTextError}`});
            return;
        }

        const common = {
            id: draft.id.trim(),
            name: draft.name.trim(),
            ...(draft.description.trim() ? {description: draft.description.trim()} : {}),
            groups: draft.groups,
            // Written for both kinds so switching an imported profile to enrollment and
            // back cannot drop the declaration.
            ...(draft.dataKeys.length ? {data_keys: draft.dataKeys} : {}),
        };
        // Scope + rollout only apply to managed configuration profiles.
        const scoping =
            draft.kind === "configuration"
                ? {
                    ...(draft.conditions.length ? {conditions: draft.conditions} : {}),
                    ...(draft.include_devices.length ? {include_devices: draft.include_devices} : {}),
                    ...(draft.exclude_devices.length ? {exclude_devices: draft.exclude_devices} : {}),
                    ...(draft.rollout ? {rollout: draft.rollout} : {}),
                }
                : {};
        // extra first, so anything the form owns wins over the loaded copy.
        const withPlatforms = {...draft.extra, ...common, ...scoping, platforms: draft.platforms};
        const profile: Profile =
            draft.kind === "enrollment"
                ? {...withPlatforms, type: "enrollment", dep_profile: true, payload: draft.enrollment}
                : {...withPlatforms, type: "configuration", payloads: draft.payloads};

        const profiles = [...(data?.profiles ?? [])];
        const idx = profiles.findIndex((p) => p.id === (profileId ?? draft.id));
        if (idx >= 0) profiles[idx] = profile;
        else profiles.push(profile);

        const ok = await save({profiles});
        if (!ok) return;
        writeDateTypes(profile.id, draft.dates);
        router.push("/profiles");
    }

    //  render
    if (loading || !initialized) {
        return (
            <Box py={80} ta="center">
                <Loader/>
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
    // Keys this payload could send as binary. Only offered where no manifest says which they are; a
    // manifest-backed payload already types its own keys.
    const dataKeyOptions: string[] = [];
    if (selectedPayload && !selectedManifest) {
        const names = new Set<string>();
        stringKeyNames(selectedPayload, names);
        dataKeyOptions.push(...Array.from(names).sort());
    }

    return (
        <Stack gap="lg">
            <Group justify="space-between">
                <Group gap="sm">
                    <ActionIcon variant="subtle" color="gray" onClick={leaveEditor} aria-label="Back to profiles">
                        <IconArrowLeft size={18}/>
                    </ActionIcon>
                    <Title order={2}>{draft.name.trim() || (profileId ? "Edit profile" : "New profile")}</Title>
                    <Badge variant="light" color={draft.kind === "enrollment" ? "grape" : "blue"}>
                        {draft.kind === "enrollment" ? "Enrollment" : "Configuration"}
                    </Badge>
                </Group>
                <Tooltip label={ADMIN_ONLY_REASON} withArrow disabled={isAdmin}>
                    <Box>
                        <Button
                            leftSection={<IconDeviceFloppy size={16}/>}
                            loading={saving}
                            onClick={handleSave}
                            disabled={!!payloadTextError || !isAdmin}
                        >
                            Save profile
                        </Button>
                    </Box>
                </Tooltip>
            </Group>

            {!isAdmin && (
                <Alert color="yellow" icon={<IconInfoCircle size={16}/>}>
                    {ADMIN_ONLY_REASON} You can read this one here; payload secrets are redacted.
                </Alert>
            )}

            <SidebarLayout sidebarWidth={340} sidebar={
                <Stack gap="md">
                    <GlassCard withBorder padding="md">
                        <Stack gap="sm">
                            <TextInput
                                label="Name"
                                placeholder="Campus Wi-Fi"
                                value={draft.name}
                                onChange={(e) => {
                                    const name = e.currentTarget.value;
                                    if (!profileId && !idTouched) {
                                        const id = slugifyConfigId(name);
                                        update({name, id});
                                        setIdError(id ? validateId(id) : null);
                                    } else {
                                        update({name});
                                    }
                                }}
                                withAsterisk
                            />
                            <TextInput
                                label="Profile ID"
                                placeholder="campus-wifi"
                                description="Also names the profile on devices: appended to the tenant's payload identifier prefix (Settings)."
                                value={draft.id}
                                error={idError}
                                disabled={!!profileId}
                                onChange={(e) => {
                                    const id = e.currentTarget.value;
                                    setIdTouched(true);
                                    update({id});
                                    setIdError(id ? validateId(id) : null);
                                }}
                                withAsterisk
                            />
                            <Textarea
                                label="Description"
                                placeholder="Optional"
                                autosize
                                minRows={1}
                                value={draft.description}
                                onChange={(e) => update({description: e.currentTarget.value})}
                            />
                            <Box>
                                <Text fz="sm" fw={500} mb={4}>
                                    Profile type
                                </Text>
                                <SegmentedControl
                                    fullWidth
                                    value={draft.kind}
                                    onChange={(v) => {
                                        update({kind: v as ProfileKind});
                                        if (v === "enrollment") setSelected(null);
                                    }}
                                    data={[
                                        {label: "Configuration", value: "configuration"},
                                        {label: "Enrollment", value: "enrollment"},
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
                                        update({platforms: next});
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
                        </Stack>
                    </GlassCard>

                    {draft.kind === "configuration" && (
                        <GlassCard withBorder padding="md">
                            <Text fw={600} fz="sm" mb="sm">
                                Scope
                            </Text>
                            <ScopeEditor
                                scope={draftScope}
                                onChange={(s) =>
                                    update({
                                        groups: s.groups ?? [],
                                        conditions: s.conditions ?? [],
                                        include_devices: s.include_devices ?? [],
                                        exclude_devices: s.exclude_devices ?? [],
                                    })
                                }
                                devices={devices}
                                allGroups={groups}
                                previous={savedScope}
                                groupsDescription="Devices in any of these groups receive this profile."
                            />
                        </GlassCard>
                    )}

                    {draft.kind === "configuration" && (
                        <GlassCard withBorder padding="md">
                            <Text fw={600} fz="sm" mb="sm">
                                Gradual rollout
                            </Text>
                            <RolloutEditor
                                rollout={draft.rollout}
                                onChange={(rollout) => update({rollout})}
                            />
                        </GlassCard>
                    )}

                    {draft.kind === "configuration" && (
                        <GlassCard withBorder padding="md">
                            <Group justify="space-between" mb="sm">
                                <Text fw={600} fz="sm">
                                    Payloads
                                </Text>
                                <Button
                                    variant="light"
                                    size="xs"
                                    leftSection={<IconPlus size={14}/>}
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
                                    No payloads yet. Add one; a profile can bundle several, like a few Wi-Fi
                                    networks plus restrictions.
                                </Text>
                            ) : (
                                <Stack gap={4}>
                                    {draft.payloads.map((pl, i) => {
                                        const {title, subtitle} = payloadLabel(pl);
                                        const active = i === selected;
                                        return (
                                            <UnstyledButton
                                                key={i}
                                                onClick={() => setSelected(i)}
                                                p="xs"
                                                style={{
                                                    borderRadius: "var(--mantine-radius-sm)",
                                                    background: active ? "var(--mantine-color-blue-light)" : undefined,
                                                }}
                                            >
                                                <Group justify="space-between" wrap="nowrap">
                                                    <Box style={{minWidth: 0}}>
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
                                                        <IconTrash size={14}/>
                                                    </ActionIcon>
                                                </Group>
                                            </UnstyledButton>
                                        );
                                    })}
                                </Stack>
                            )}
                        </GlassCard>
                    )}
                </Stack>
            }>
                {/*  Right: payload editor  */}
                <Box>
                    <GlassCard withBorder padding="md" mih={360}>
                        {draft.kind === "enrollment" ? (
                            <Stack gap="sm">
                                <Text fw={600}>{ENROLLMENT_MANIFEST.title}</Text>
                                <Text fz="xs" c="dimmed">
                                    {ENROLLMENT_MANIFEST.description}
                                </Text>
                                <Divider my="xs"/>
                                <PayloadForm
                                    manifest={ENROLLMENT_MANIFEST}
                                    value={draft.enrollment}
                                    onChange={(enrollment) => update({enrollment})}
                                    platforms={draft.platforms}
                                />
                            </Stack>
                        ) : selectedPayload === null ? (
                            <Stack align="center" justify="center" mih={320} gap="xs">
                                <IconLayoutGrid size={32} opacity={0.4}/>
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
                                                {label: "Form", value: "form"},
                                                {label: "JSON", value: "json"},
                                            ]}
                                        />
                                    )}
                                </Group>
                                <Divider my="xs"/>
                                {selectedManifest && mode === "form" ? (
                                    <PayloadForm
                                        key={`${selected}:${payloadEpoch}`}
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
                                            commitPayloadText(t);
                                        }}
                                        error={payloadTextError}
                                        validationError="Invalid JSON"
                                        formatOnBlur
                                        autosize
                                        minRows={10}
                                        styles={{
                                            input: {
                                                fontFamily: "var(--mantine-font-family-monospace)",
                                                fontSize: 13
                                            }
                                        }}
                                    />
                                )}
                                {!selectedManifest && (
                                    <>
                                        <Divider my="xs"/>
                                        <MultiSelect
                                            label="Keys sent as binary data"
                                            description="Micromanage has no manifest for this payload type, so it cannot tell which base64 values the device expects as binary rather than text. Named keys are decoded on the way to the device and exported as <data>."
                                            placeholder={
                                                dataKeyOptions.length
                                                    ? "None"
                                                    : "This payload has no text values"
                                            }
                                            data={dataKeyOptions}
                                            value={draft.dataKeys.filter((k) => dataKeyOptions.includes(k))}
                                            onChange={(v) => {
                                                // Keys belonging to the profile's other payloads are not on
                                                // offer here, so carry them through untouched.
                                                const others = draft.dataKeys.filter(
                                                    (k) => !dataKeyOptions.includes(k),
                                                );
                                                update({
                                                    dataKeys: Array.from(new Set([...others, ...v])).sort(),
                                                });
                                            }}
                                            disabled={!isAdmin || dataKeyOptions.length === 0}
                                            searchable
                                            clearable
                                        />
                                    </>
                                )}
                            </Stack>
                        )}
                    </GlassCard>
                </Box>
            </SidebarLayout>

            {/*  Searchable "Add payload" picker  */}
            <Modal opened={addOpen} onClose={() => setAddOpen(false)} title="Add payload" size="md">
                <Stack gap="sm">
                    <TextInput
                        placeholder="Search payload types…"
                        leftSection={<IconSearch size={14}/>}
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
                                    // Keywords carry the section titles a merged
                                    // domain absorbed, so searching Energy Saver still
                                    // reaches the payload that now holds those keys.
                                    items: g.items.filter((m) =>
                                        `${m.title} ${m.domain} ${(m.keywords ?? []).join(" ")} ${m.fields.map(f => f.name).join(" ")}`
                                            .toLowerCase()
                                            .includes(q),
                                    ),
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
                                                    // One entry per domain: the catalog merges the
                                                    // manifests that share one (see mergeByDomain).
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
                                                description="Any payload type. Edit the raw JSON."
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
