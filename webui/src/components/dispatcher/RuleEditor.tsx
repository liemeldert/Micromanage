"use client";

import {useCallback, useEffect, useMemo, useRef, useState} from "react";
import {
    ActionIcon,
    Alert,
    Badge,
    Box,
    Button,
    Divider,
    Group,
    MultiSelect,
    NavLink,
    NumberInput,
    Paper,
    ScrollArea,
    Select,
    Stack,
    Switch,
    TagsInput,
    Text,
    TextInput,
    Tooltip,
    UnstyledButton,
} from "@mantine/core";
import {useMediaQuery} from "@mantine/hooks";
import {modals} from "@mantine/modals";
import {notifications} from "@mantine/notifications";
import {
    IconAlertTriangle,
    IconDeviceFloppy,
    IconInfoCircle,
    IconListDetails,
    IconPlus,
    IconSearch,
    IconTrash,
    IconWebhook,
} from "@tabler/icons-react";
import {
    api,
    type CatalogCommand,
    type Device,
    type DispatcherAction,
    type DispatcherCheckSpec,
    type DispatcherConfig,
    type DispatcherRule,
    type DispatcherWebhook,
    type Severity,
} from "../../../lib/api";
import {type Group as GroupDef, type Scope, useConfigResource, useTagRegistry,} from "../../../lib/config";
import {useAuth} from "../../../lib/auth-context";
import {confirmDiscard, useBeforeUnload} from "../../../lib/use-unsaved-changes";
import {RedactedInput} from "../config/RedactedInput";
import {ScopeEditor} from "../config/ScopeEditor";
import {SidebarLayout} from "../layout/SidebarLayout";
import {GlassCard} from "../ui/GlassCard";

const SEVERITIES: Severity[] = ["black", "red", "yellow", "green"];
// Same triage colours the alert board uses, so a rule reads the same in both places.
const SEVERITY_COLOR: Record<string, string> = {
    black: "dark",
    red: "red",
    yellow: "yellow",
    green: "green",
};
const REMEDIATION_TYPES = new Set(["install_profiles", "install_apps", "send_command"]);
const ACTION_TYPES = ["webhook", "assign_tag", "remove_tag", "install_profiles", "install_apps", "send_command"];

// The sidebar selects either one rule or the shared webhook targets, which are
// config on the same document but not part of any single rule.
type Selection = { kind: "rule"; id: string } | { kind: "webhooks" };

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

// Worst first, and anything the catalog does not know about last.
const severityRank = (s: string) => {
    const i = SEVERITIES.indexOf(s as Severity);
    return i < 0 ? SEVERITIES.length : i;
};

// One line of at-a-glance scope for the sidebar. An empty scope means every
// device here (ScopeEditor is given emptyMatchesAll below).
function scopeSummary(scope: Record<string, unknown> | undefined): string {
    const count = (key: string) => (Array.isArray(scope?.[key]) ? (scope![key] as unknown[]).length : 0);
    const parts: string[] = [];
    const groups = count("groups");
    const conditions = count("conditions");
    const included = count("include_devices");
    const excluded = count("exclude_devices");
    if (groups) parts.push(plural(groups, "group"));
    if (conditions) parts.push(plural(conditions, "condition"));
    if (included) parts.push(`${included} pinned`);
    if (excluded) parts.push(`${excluded} excluded`);
    return parts.length ? parts.join(" · ") : "All devices";
}

export function RuleEditor({initialRuleId}: { initialRuleId?: string | null }) {
    const {token, isAdmin} = useAuth();
    const {data, setData, loading, saving, save, reload} = useConfigResource<DispatcherConfig>("dispatcher", {
        rules: [],
        webhooks: [],
    });
    // Edited in memory until Save, so the editor keeps what it loaded to know what is unsaved. Null
    // until the first non-loading render takes a snapshot.
    const [baseline, setBaseline] = useState<string | null>(null);
    const {tagNames} = useTagRegistry();
    const [checks, setChecks] = useState<DispatcherCheckSpec[]>([]);
    const [commands, setCommands] = useState<CatalogCommand[]>([]);
    const [profileIds, setProfileIds] = useState<string[]>([]);
    const [appIds, setAppIds] = useState<string[]>([]);
    const [groups, setGroups] = useState<GroupDef[]>([]);
    const [devices, setDevices] = useState<Device[]>([]);
    const [selection, setSelection] = useState<Selection | null>(null);
    const [query, setQuery] = useState("");
    // Sidebar beside the form on wide screens, stacked above it on narrow ones.
    const wide = useMediaQuery("(min-width: 1100px)", true);

    useEffect(() => {
        if (!token) return;
        api.getDispatcherCheckCatalog(token).then((c) => setChecks(c.checks)).catch(() => {
        });
        api.getCommandCatalog(token).then((c) => setCommands(c.commands)).catch(() => {
        });
        api.getConfig(token, "profiles").then((p) => setProfileIds(((p?.profiles as {
            id: string
        }[]) ?? []).map((x) => x.id))).catch(() => {
        });
        api.getConfig(token, "apps").then((a) => setAppIds(((a?.apps as {
            id: string
        }[]) ?? []).map((x) => x.id))).catch(() => {
        });
        api.getConfig(token, "groups").then((g) => setGroups((g?.groups as GroupDef[]) ?? [])).catch(() => {
        });
        // Enrolled only, matching the flow editor and the scope-preview endpoint's total. The
        // dispatcher evaluates enrolled devices, so this scope counter must not quote a wider fleet.
        api.listDevices(token, {state: "enrolled", limit: 500}).then((r) => setDevices(r.devices)).catch(() => {
        });
    }, [token]);

    const rules = useMemo(() => data?.rules ?? [], [data]);
    const webhooks = useMemo(() => data?.webhooks ?? [], [data]);
    // The order the sidebar shows: worst tier first, config order within a tier
    // (sort is stable). Selection follows this order, not the file's.
    const ordered = useMemo(
        () => [...rules].sort((a, b) => severityRank(a.severity) - severityRank(b.severity)),
        [rules],
    );

    // A selected rule that a reload or a discard took away leaves the selection dangling; drop it and
    // let the effect below fall back to the first rule.
    useEffect(() => {
        if (selection?.kind === "rule" && !rules.some((r) => r.id === selection.id)) setSelection(null);
    }, [rules, selection]);
    // The ?rule= deep link only gets the first pick. Marked once a selection is
    // committed, so a discard later falls to the top of the list instead of back
    // onto the linked rule.
    const picked = useRef(false);
    useEffect(() => {
        if (selection) picked.current = true;
    }, [selection]);
    useEffect(() => {
        if (selection || !ordered.length) return;
        const wanted = picked.current ? null : initialRuleId;
        const hit = wanted && ordered.some((r) => r.id === wanted) ? wanted : ordered[0].id;
        // A link to a rule that no longer exists selects the top of the list, so name the one it
        // could not find.
        if (wanted && hit !== wanted) {
            notifications.show({
                color: "yellow",
                message: `Rule "${wanted}" was not found. It may have been renamed or deleted.`,
            });
        }
        setSelection({kind: "rule", id: hit});
    }, [ordered, selection, initialRuleId]);

    const selectedRuleId = selection?.kind === "rule" ? selection.id : null;
    const rule = rules.find((r) => r.id === selectedRuleId) ?? null;
    const ruleIdx = rules.findIndex((r) => r.id === selectedRuleId);
    const checkLabel = useCallback(
        (r: DispatcherRule) => {
            const type = typeof r.check?.type === "string" ? (r.check.type as string) : "";
            return checks.find((c) => c.type === type)?.label ?? type ?? "No check";
        },
        [checks],
    );

    const patchRule = useCallback(
        (patch: Partial<DispatcherRule>) => {
            setData((prev) => {
                const next: DispatcherConfig = {
                    ...prev,
                    rules: [...(prev?.rules ?? [])],
                    webhooks: prev?.webhooks ?? []
                };
                if (ruleIdx >= 0) next.rules![ruleIdx] = {...next.rules![ruleIdx], ...patch};
                return next;
            });
        },
        [setData, ruleIdx],
    );

    const setWebhooks = (next: DispatcherWebhook[]) =>
        setData((prev) => ({...prev, rules: prev?.rules ?? [], webhooks: next}));

    const createRule = () => {
        const base = "rule";
        let id = base;
        let n = 1;
        while (rules.some((r) => r.id === id)) id = `${base}-${++n}`;
        const doc: DispatcherRule = {
            id,
            name: "New rule",
            enabled: true,
            severity: "yellow",
            scope: {},
            check: {type: "filevault_disabled"},
            grace_minutes: 60,
            actions: [],
            auto_resolve: true,
        };
        setData((prev) => ({...prev, webhooks: prev?.webhooks ?? [], rules: [...(prev?.rules ?? []), doc]}));
        setQuery("");
        setSelection({kind: "rule", id});
    };

    const deleteRule = () => {
        if (!rule) return;
        const doomed = rule;
        const idx = ordered.findIndex((r) => r.id === doomed.id);
        modals.openConfirmModal({
            title: "Delete rule",
            children: (
                <Text size="sm">
                    Delete <b>{doomed.name}</b>? Alerts it raised stay, but the rule stops evaluating once you
                    save.
                </Text>
            ),
            labels: {confirm: "Delete", cancel: "Cancel"},
            confirmProps: {color: "red"},
            onConfirm: () => {
                setData((prev) => ({
                    ...prev,
                    webhooks: prev?.webhooks ?? [],
                    rules: (prev?.rules ?? []).filter((r) => r.id !== doomed.id)
                }));
                // Select the neighbour that takes the deleted rule's place, so the form does not
                // empty out mid-edit.
                const rest = ordered.filter((r) => r.id !== doomed.id);
                const next = rest[Math.min(idx, rest.length - 1)];
                setSelection(next ? {kind: "rule", id: next.id} : null);
            },
        });
    };

    const serialized = data === null ? null : JSON.stringify(data);
    useEffect(() => {
        if (!loading && serialized !== null && baseline === null) setBaseline(serialized);
    }, [loading, serialized, baseline]);
    const dirty = baseline !== null && serialized !== null && serialized !== baseline;
    useBeforeUnload(dirty);

    const onSave = async () => {
        if (!isAdmin) {
            notifications.show({color: "red", message: "Editing dispatcher rules requires the admin role."});
            return;
        }
        const doc = data ?? {rules: [], webhooks: []};
        if (await save(doc)) setBaseline(JSON.stringify(doc));
    };

    const onDiscard = () =>
        confirmDiscard({
            dirty,
            what: "these compliance rules",
            onConfirm: () => {
                setBaseline(null);
                setSelection(null);
                reload();
            },
        });

    const needle = query.trim().toLowerCase();
    const visible = needle
        ? ordered.filter((r) =>
            [r.name, r.id, checkLabel(r)].some((s) => (s ?? "").toLowerCase().includes(needle)),
        )
        : ordered;
    const enabledCount = rules.filter((r) => r.enabled !== false).length;
    // A severity the catalog does not know about still gets a section, so no rule is hidden.
    const tiers: { severity: string; rules: DispatcherRule[] }[] = [
        ...SEVERITIES.map((s) => ({severity: s as string, rules: visible.filter((r) => r.severity === s)})),
        {severity: "other", rules: visible.filter((r) => !SEVERITIES.includes(r.severity))},
    ].filter((t) => t.rules.length > 0);

    if (loading) return <Text c="dimmed">Loading…</Text>;

    return (
        <Stack gap="md">
            {!isAdmin && (
                <Alert color="yellow" icon={<IconInfoCircle size={16}/>}>
                    Compliance rules can act on devices and reach external webhooks, so authoring them is
                    admin-only. You can view them here.
                </Alert>
            )}

            <Group justify="space-between" align="center">
                <Text fz="sm" c="dimmed">
                    {rules.length ? `${enabledCount} of ${plural(rules.length, "rule")} enabled` : "No rules yet"}
                    {webhooks.length ? ` · ${plural(webhooks.length, "webhook target")}` : ""}
                </Text>
                <Group gap="xs">
                    {dirty && (
                        <>
                            <Badge color="yellow" variant="light">Unsaved changes</Badge>
                            <Button variant="default" onClick={onDiscard} disabled={saving}>
                                Discard
                            </Button>
                        </>
                    )}
                    <Button leftSection={<IconDeviceFloppy size={16}/>} onClick={onSave} loading={saving}
                            disabled={!isAdmin}>
                        {dirty ? "Save changes" : "Save"}
                    </Button>
                </Group>
            </Group>

            <SidebarLayout sidebarWidth={320} sidebar={
                <Stack gap="md">
                    <GlassCard withBorder padding="sm">
                        <Group gap={6} mb="xs">
                            <Text fw={600} fz="sm">Rules</Text>
                            <Badge size="sm" variant="light" color="gray">{rules.length}</Badge>
                        </Group>

                        {rules.length > 6 && (
                            <TextInput
                                size="xs"
                                mb="xs"
                                placeholder="Filter rules"
                                leftSection={<IconSearch size={14}/>}
                                value={query}
                                onChange={(e) => setQuery(e.currentTarget.value)}
                            />
                        )}

                        {rules.length === 0 ? (
                            <Text fz="xs" c="dimmed" py="xs">
                                No rules yet. Add one to start watching the fleet.
                            </Text>
                        ) : visible.length === 0 ? (
                            <Text fz="xs" c="dimmed" py="xs">
                                No rule matches “{query.trim()}”.
                            </Text>
                        ) : (
                            <ScrollArea.Autosize mah={wide ? "calc(100vh - 340px)" : 400} type="auto">
                                <Stack gap="xs">
                                    {tiers.map((tier) => (
                                        <Box key={tier.severity}>
                                            <Group gap={6} px={4} mb={4} wrap="nowrap">
                                                <Box
                                                    style={{
                                                        width: 8,
                                                        height: 8,
                                                        borderRadius: "var(--mantine-radius-sm)",
                                                        flexShrink: 0,
                                                        background: `var(--mantine-color-${SEVERITY_COLOR[tier.severity] ?? "gray"}-6)`,
                                                        // The black tier's swatch is the page colour in dark
                                                        // mode, so every dot carries a ring to stay visible.
                                                        boxShadow: "0 0 0 1px var(--mantine-color-dimmed)",
                                                    }}
                                                />
                                                <Text fz={10} fw={700} tt="uppercase" c="dimmed">
                                                    {tier.severity}
                                                </Text>
                                                <Text fz={10} c="dimmed">{tier.rules.length}</Text>
                                            </Group>
                                            <Stack gap={2}>
                                                {tier.rules.map((r) => (
                                                    <RuleListItem
                                                        key={r.id}
                                                        rule={r}
                                                        checkLabel={checkLabel(r)}
                                                        active={r.id === selectedRuleId}
                                                        onSelect={() => setSelection({kind: "rule", id: r.id})}
                                                    />
                                                ))}
                                            </Stack>
                                        </Box>
                                    ))}
                                </Stack>
                            </ScrollArea.Autosize>
                        )}

                        <Divider my="xs"/>
                        <Button
                            fullWidth
                            size="xs"
                            variant="light"
                            leftSection={<IconPlus size={14}/>}
                            onClick={createRule}
                            disabled={!isAdmin}
                        >
                            New rule
                        </Button>
                    </GlassCard>

                    <GlassCard withBorder padding={4}>
                        <NavLink
                            active={selection?.kind === "webhooks"}
                            onClick={() => setSelection({kind: "webhooks"})}
                            leftSection={<IconWebhook size={16}/>}
                            label="Webhook targets"
                            description={
                                webhooks.length
                                    ? webhooks.map((w) => w.name || "unnamed").join(", ")
                                    : "None configured"
                            }
                            rightSection={
                                <Badge size="sm" variant="light" color="gray">{webhooks.length}</Badge>
                            }
                            style={{borderRadius: "var(--mantine-radius-sm)"}}
                        />
                    </GlassCard>
                </Stack>
            }>

                {/*  Right: the selected rule, or the shared webhook targets  */}
                <Box>
                    <GlassCard withBorder padding="md" mih={360}>
                        {selection?.kind === "webhooks" ? (
                            <WebhooksSection webhooks={webhooks} onChange={setWebhooks} disabled={!isAdmin}/>
                        ) : rule === null ? (
                            <Stack align="center" justify="center" mih={320} gap="xs">
                                <IconListDetails size={32} opacity={0.4}/>
                                <Text c="dimmed" fz="sm">
                                    {rules.length === 0
                                        ? "Add a rule to start watching the fleet."
                                        : "Select a rule to edit."}
                                </Text>
                            </Stack>
                        ) : (
                            <Stack gap="sm">
                                <Group justify="space-between" align="flex-start" wrap="nowrap">
                                    <Box style={{minWidth: 0}}>
                                        <Text fw={600} truncate>{rule.name.trim() || "Untitled rule"}</Text>
                                        <Tooltip label="Rule id, fixed once created. Alerts reference it." withArrow>
                                            <Text fz="xs" c="dimmed" truncate style={{width: "fit-content"}}>
                                                {rule.id}
                                            </Text>
                                        </Tooltip>
                                    </Box>
                                    <Group gap="md" wrap="nowrap">
                                        <Switch
                                            label="Enabled"
                                            checked={rule.enabled !== false}
                                            onChange={(e) => patchRule({enabled: e.currentTarget.checked})}
                                            disabled={!isAdmin}
                                        />
                                        <Tooltip
                                            label="Close the alert on its own once the device passes the check again."
                                            withArrow multiline w={240}>
                                            <Box>
                                                <Switch
                                                    label="Auto-resolve"
                                                    checked={rule.auto_resolve !== false}
                                                    onChange={(e) => patchRule({auto_resolve: e.currentTarget.checked})}
                                                    disabled={!isAdmin}
                                                />
                                            </Box>
                                        </Tooltip>
                                        <Tooltip label="Delete rule" withArrow>
                                            <ActionIcon variant="light" color="red" onClick={deleteRule}
                                                        disabled={!isAdmin} aria-label="Delete rule">
                                                <IconTrash size={16}/>
                                            </ActionIcon>
                                        </Tooltip>
                                    </Group>
                                </Group>

                                <Divider my="xs"/>

                                <Group align="flex-end" gap="md" wrap="wrap">
                                    <TextInput label="Name" value={rule.name}
                                               onChange={(e) => patchRule({name: e.currentTarget.value})} w={280}
                                               disabled={!isAdmin}/>
                                    <Select
                                        label="Severity"
                                        data={SEVERITIES.map((s) => ({value: s, label: s}))}
                                        value={rule.severity}
                                        onChange={(v) => patchRule({severity: (v as Severity) ?? "yellow"})}
                                        w={140}
                                        disabled={!isAdmin}
                                    />
                                    <NumberInput
                                        label="Grace (minutes)"
                                        description="Anti-flap: alert only after this long"
                                        value={rule.grace_minutes ?? 0}
                                        onChange={(v) => patchRule({grace_minutes: typeof v === "number" ? v : 0})}
                                        min={0}
                                        w={150}
                                        disabled={!isAdmin}
                                    />
                                </Group>

                                <Divider my="sm" label="Applies to" labelPosition="left"/>
                                <ScopeEditor
                                    scope={(rule.scope ?? {}) as Scope}
                                    onChange={(scope) => patchRule({scope: scope as Record<string, unknown>})}
                                    devices={devices}
                                    allGroups={groups}
                                    groupsLabel="Target groups"
                                    groupsDescription="Empty scope applies the rule to every device."
                                    emptyMatchesAll
                                />

                                <Divider my="sm" label="Compliance state (creates alert when true)"
                                         labelPosition="left"/>
                                <CheckPicker checks={checks} value={rule.check ?? {}}
                                             onChange={(check) => patchRule({check})}
                                             profileIds={profileIds} tagNames={tagNames} disabled={!isAdmin}/>

                                <Divider my="sm" label="Actions" labelPosition="left"/>
                                <ActionsEditor
                                    actions={rule.actions ?? []}
                                    onChange={(actions) => patchRule({actions})}
                                    webhooks={webhooks}
                                    tagNames={tagNames}
                                    profileIds={profileIds}
                                    appIds={appIds}
                                    commands={commands}
                                    disabled={!isAdmin}
                                    onEditWebhooks={() => setSelection({kind: "webhooks"})}
                                />
                            </Stack>
                        )}
                    </GlassCard>
                </Box>
            </SidebarLayout>
        </Stack>
    );
}

function RuleListItem({rule, checkLabel, active, onSelect}: {
    rule: DispatcherRule;
    checkLabel: string;
    active: boolean;
    onSelect: () => void;
}) {
    const off = rule.enabled === false;
    const actions = rule.actions?.length ?? 0;
    return (
        <UnstyledButton
            onClick={onSelect}
            p="xs"
            style={{
                borderRadius: "var(--mantine-radius-sm)",
                background: active ? "var(--mantine-color-blue-light)" : undefined,
            }}
        >
            <Box style={{minWidth: 0}}>
                <Text fz="sm" fw={active ? 600 : 500} truncate c={off ? "dimmed" : undefined}>
                    {rule.name.trim() || rule.id}
                </Text>
                <Text fz="xs" c="dimmed" truncate>
                    {checkLabel}
                </Text>
                <Group gap={6} wrap="nowrap" mt={4}>
                    {off && <Badge size="xs" variant="light" color="gray">off</Badge>}
                    <Text fz="xs" c="dimmed" truncate>
                        {scopeSummary(rule.scope)} · {actions ? plural(actions, "action") : "no actions"}
                    </Text>
                </Group>
            </Box>
        </UnstyledButton>
    );
}

let webhookRowSeq = 0;
const nextRowId = () => `webhook-row-${++webhookRowSeq}`;

function WebhooksSection({webhooks, onChange, disabled}: {
    webhooks: DispatcherWebhook[];
    onChange: (w: DispatcherWebhook[]) => void;
    disabled: boolean
}) {
    // A stable row identity: the name is editable and the position is not. Keyed by index, removing a
    // row would hand its credential fields' local editing state to the row that slides up into it,
    // which then shows the redaction sentinel as an editable value.
    const rowIds = useRef<string[]>([]);
    if (rowIds.current.length !== webhooks.length) {
        // The list changed underneath this component (first load, or a reload);
        // add and remove below keep the two in step themselves.
        rowIds.current = webhooks.map((_, i) => rowIds.current[i] ?? nextRowId());
    }

    const patch = (i: number, p: Partial<DispatcherWebhook>) => onChange(webhooks.map((w, j) => (i === j ? {...w, ...p} : w)));
    return (
        <Stack gap="sm">
            <Group justify="space-between" align="flex-start" wrap="nowrap">
                <Box style={{minWidth: 0}}>
                    <Text fw={600}>Webhook targets</Text>
                    <Text fz="xs" c="dimmed">
                        Endpoints any rule can post to through a webhook action. Shared by every rule.
                    </Text>
                </Box>
                <Button variant="light" size="xs" leftSection={<IconPlus size={14}/>} disabled={disabled}
                        onClick={() => {
                            rowIds.current = [...rowIds.current, nextRowId()];
                            onChange([...webhooks, {name: `hook-${webhooks.length + 1}`, url: ""}]);
                        }}>
                    Add target
                </Button>
            </Group>
            <Divider my="xs"/>
            {webhooks.length === 0 ? (
                <Text fz="xs" c="dimmed">
                    No webhook targets. Add one to notify Slack, Teams, Discord or any endpoint when a rule
                    raises an alert.
                </Text>
            ) : (
                <Stack gap="xs">
                    {webhooks.map((w, i) => (
                        <Paper key={rowIds.current[i] ?? i} withBorder radius="sm" p="xs">
                            <Group gap="xs" wrap="nowrap" align="flex-start">
                                <TextInput placeholder="name" value={w.name}
                                           onChange={(e) => patch(i, {name: e.currentTarget.value})} w={160}
                                           disabled={disabled}/>
                                <RedactedInput
                                    placeholder="https://hooks.slack.com/…"
                                    value={w.url ?? ""}
                                    onChange={(v) => patch(i, {url: v})}
                                    style={{flex: 1}}
                                    disabled={disabled}
                                />
                                <RedactedInput
                                    password
                                    placeholder="HMAC secret (optional)"
                                    value={w.secret ?? ""}
                                    onChange={(v) => patch(i, {secret: v})}
                                    w={200}
                                    disabled={disabled}
                                />
                                <ActionIcon
                                    variant="subtle"
                                    color="red"
                                    disabled={disabled}
                                    aria-label="Remove webhook target"
                                    onClick={() =>
                                        modals.openConfirmModal({
                                            title: "Remove webhook target",
                                            children: (
                                                <Text size="sm">
                                                    Remove <b>{w.name || "this target"}</b>? Any rule pointing at it
                                                    stops notifying once you save, and the stored URL and secret are
                                                    gone.
                                                </Text>
                                            ),
                                            labels: {confirm: "Remove", cancel: "Cancel"},
                                            confirmProps: {color: "red"},
                                            onConfirm: () => {
                                                rowIds.current = rowIds.current.filter((_, j) => j !== i);
                                                onChange(webhooks.filter((_, j) => j !== i));
                                            },
                                        })
                                    }
                                >
                                    <IconTrash size={16}/>
                                </ActionIcon>
                            </Group>
                        </Paper>
                    ))}
                    <Text fz="xs" c="dimmed">
                        The URL and secret are stored on the server and never sent back to this page once
                        saved. A field marked &quot;set, leave blank to keep&quot; already holds a value;
                        typing a new one replaces it.
                    </Text>
                </Stack>
            )}
        </Stack>
    );
}

function CheckPicker({checks, value, onChange, profileIds, tagNames, disabled}: {
    checks: DispatcherCheckSpec[];
    value: Record<string, unknown>;
    onChange: (c: Record<string, unknown>) => void;
    profileIds: string[];
    tagNames: string[];
    disabled: boolean
}) {
    const spec = checks.find((c) => c.type === value.type);
    const patch = (p: Record<string, unknown>) => onChange({...value, ...p});
    return (
        <Stack gap="xs">
            <Select
                label="Check"
                data={checks.map((c) => ({value: c.type, label: c.label}))}
                value={typeof value.type === "string" ? value.type : null}
                onChange={(v) => onChange({type: v ?? undefined})}
                description={spec?.description}
                searchable
                disabled={disabled}
            />
            {(spec?.params ?? []).map((p) => {
                if (p.type === "tags") {
                    return <TagsInput key={p.name} label={p.label} data={tagNames}
                                      value={Array.isArray(value[p.name]) ? (value[p.name] as string[]) : []}
                                      onChange={(v) => patch({[p.name]: v})} disabled={disabled}/>;
                }
                if (p.name === "profile_id") {
                    return <Select key={p.name} label={p.label} data={profileIds}
                                   value={typeof value[p.name] === "string" ? (value[p.name] as string) : null}
                                   onChange={(v) => patch({[p.name]: v ?? undefined})} searchable disabled={disabled}/>;
                }
                if (p.type === "select") {
                    return <Select key={p.name} label={p.label} data={p.options ?? []}
                                   value={typeof value[p.name] === "string" ? (value[p.name] as string) : null}
                                   onChange={(v) => patch({[p.name]: v ?? undefined})} disabled={disabled}/>;
                }
                if (p.type === "int") {
                    return <NumberInput key={p.name} label={p.label}
                                        value={typeof value[p.name] === "number" ? (value[p.name] as number) : undefined}
                                        onChange={(v) => patch({[p.name]: v})} disabled={disabled}/>;
                }
                return <TextInput key={p.name} label={p.label} description={p.help} value={String(value[p.name] ?? "")}
                                  onChange={(e) => patch({[p.name]: e.currentTarget.value})} disabled={disabled}/>;
            })}
        </Stack>
    );
}

function ActionsEditor({
                           actions,
                           onChange,
                           webhooks,
                           tagNames,
                           profileIds,
                           appIds,
                           commands,
                           disabled,
                           onEditWebhooks
                       }: {
    actions: DispatcherAction[];
    onChange: (a: DispatcherAction[]) => void;
    webhooks: DispatcherWebhook[];
    tagNames: string[];
    profileIds: string[];
    appIds: string[];
    commands: CatalogCommand[];
    disabled: boolean;
    onEditWebhooks: () => void;
}) {
    const patch = (i: number, p: Partial<DispatcherAction>) => onChange(actions.map((a, j) => (i === j ? {...a, ...p} : a)));
    const setParams = (i: number, params: Record<string, unknown>) => patch(i, {params});
    return (
        <Stack gap="xs">
            {actions.map((a, i) => {
                const p = a.params ?? {};
                const cmd = commands.find((c) => c.type === p.command);
                const isDestructive = a.type === "send_command" && cmd?.destructive;
                return (
                    <Paper key={i} withBorder radius="sm" p="xs">
                        <Group justify="space-between" mb={6}>
                            <Group gap="xs">
                                <Select
                                    size="xs"
                                    data={ACTION_TYPES}
                                    value={a.type}
                                    onChange={(v) => {
                                        const type = v ?? "webhook";
                                        // A remediation acts on real devices, so it starts in dry
                                        // run. A missing dry_run reads as false on the server, so
                                        // write it explicitly.
                                        patch(i, {
                                            type,
                                            params: {},
                                            dry_run: REMEDIATION_TYPES.has(type) ? true : undefined,
                                        });
                                    }}
                                    w={160}
                                    disabled={disabled}
                                />
                                {REMEDIATION_TYPES.has(a.type) && (
                                    <Switch size="xs" label="Dry run" checked={Boolean(a.dry_run)}
                                            onChange={(e) => patch(i, {dry_run: e.currentTarget.checked})}
                                            disabled={disabled}/>
                                )}
                                {isDestructive && (
                                    <Tooltip
                                        label="Destructive commands never run on their own; they require admin approval on the alert."
                                        multiline w={240}>
                                        <Badge color="orange" variant="light"
                                               leftSection={<IconAlertTriangle size={12}/>}>
                                            approval required
                                        </Badge>
                                    </Tooltip>
                                )}
                            </Group>
                            <ActionIcon
                                variant="subtle"
                                color="red"
                                disabled={disabled}
                                aria-label="Remove action"
                                onClick={() =>
                                    modals.openConfirmModal({
                                        title: "Remove action",
                                        children: (
                                            <Text size="sm">
                                                Remove the <b>{a.type}</b> action? The rule still runs, it just stops
                                                doing this.
                                            </Text>
                                        ),
                                        labels: {confirm: "Remove", cancel: "Cancel"},
                                        confirmProps: {color: "red"},
                                        onConfirm: () => onChange(actions.filter((_, j) => j !== i)),
                                    })
                                }
                            >
                                <IconTrash size={14}/>
                            </ActionIcon>
                        </Group>

                        {a.type === "webhook" && (
                            <Select
                                size="xs"
                                label="Target"
                                data={webhooks.map((w) => w.name)}
                                value={typeof p.target === "string" ? (p.target as string) : null}
                                onChange={(v) => setParams(i, {target: v ?? undefined})}
                                disabled={disabled}
                                placeholder={webhooks.length ? "Select a target" : "No targets yet"}
                                description={
                                    webhooks.length ? undefined : (
                                        <UnstyledButton onClick={onEditWebhooks} fz="xs" c="blue">
                                            Add a webhook target first
                                        </UnstyledButton>
                                    )
                                }
                            />
                        )}
                        {(a.type === "assign_tag" || a.type === "remove_tag") && (
                            <TagsInput size="xs" label="Tags" data={tagNames}
                                       value={Array.isArray(p.tags) ? (p.tags as string[]) : []}
                                       onChange={(v) => setParams(i, {tags: v})} disabled={disabled}/>
                        )}
                        {a.type === "install_profiles" && (
                            <MultiSelect size="xs" label="Profiles" data={profileIds}
                                         value={Array.isArray(p.profile_ids) ? (p.profile_ids as string[]) : []}
                                         onChange={(v) => setParams(i, {profile_ids: v})} searchable
                                         disabled={disabled}/>
                        )}
                        {a.type === "install_apps" && (
                            <MultiSelect size="xs" label="Apps" data={appIds}
                                         value={Array.isArray(p.app_ids) ? (p.app_ids as string[]) : []}
                                         onChange={(v) => setParams(i, {app_ids: v})} searchable disabled={disabled}/>
                        )}
                        {a.type === "send_command" && (
                            <Select size="xs" label="Command" data={commands.map((c) => ({
                                value: c.type,
                                label: `${c.label}${c.destructive ? " (destructive)" : ""}`
                            }))} value={typeof p.command === "string" ? (p.command as string) : null}
                                    onChange={(v) => setParams(i, {command: v ?? undefined})} searchable
                                    disabled={disabled}/>
                        )}
                    </Paper>
                );
            })}
            <Button size="compact-xs" variant="light" leftSection={<IconPlus size={14}/>} disabled={disabled}
                    onClick={() => onChange([...actions, {type: "webhook", params: {}, dry_run: true}])}>
                Add action
            </Button>
            <Text fz="xs" c="dimmed">
                A new remediation action starts in dry run: it records what it would have done and leaves the
                device alone until you turn dry run off.
            </Text>
        </Stack>
    );
}
