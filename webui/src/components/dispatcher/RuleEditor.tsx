import {useCallback, useEffect, useMemo, useRef, useState} from "react";
import {
    ActionIcon,
    Alert,
    Badge,
    Box,
    Button,
    Divider,
    Group,
    NavLink,
    NumberInput,
    ScrollArea,
    Select,
    Stack,
    Switch,
    Text,
    TextInput,
    Tooltip,
} from "@mantine/core";
import {useMediaQuery} from "@mantine/hooks";
import {modals} from "@mantine/modals";
import {notifications} from "@mantine/notifications";
import {
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
    type DispatcherCheckSpec,
    type DispatcherConfig,
    type DispatcherRule,
    type DispatcherWebhook,
    type Severity,
} from "../../../lib/api";
import {type Group as GroupDef, type Scope, useConfigResource, useTagRegistry} from "../../../lib/config";
import {useAuth} from "../../../lib/auth-context";
import {SEVERITIES, SEVERITY_COLORS} from "../../../lib/status-labels";
import {confirmDiscard, useBeforeUnload} from "../../../lib/use-unsaved-changes";
import {ScopeEditor} from "../config/ScopeEditor";
import {SidebarLayout} from "../layout/SidebarLayout";
import {GlassCard} from "../ui/GlassCard";
import {ActionsEditor} from "./ActionsEditor";
import {CheckPicker} from "./CheckPicker";
import {plural} from "./rule-summary";
import {RuleListItem} from "./RuleListItem";
import {WebhooksSection} from "./WebhooksSection";

// The sidebar selects one rule or the webhook targets, which share the document but belong to no single rule.
type Selection = { kind: "rule"; id: string } | { kind: "webhooks" };

type Doc = DispatcherConfig & { rules: DispatcherRule[]; webhooks: DispatcherWebhook[] };

// Worst first, and anything the catalog does not know about last.
const severityRank = (s: string) => {
    const i = SEVERITIES.indexOf(s as Severity);
    return i < 0 ? SEVERITIES.length : i;
};

const swatchColor = (severity: string) => `var(--mantine-color-${SEVERITY_COLORS[severity] ?? "gray"}-6)`;

export function RuleEditor({initialRuleId}: { initialRuleId?: string | null }) {
    const {token, isAdmin} = useAuth();
    const {data, setData, loading, saving, save, reload} = useConfigResource<DispatcherConfig>("dispatcher", {
        rules: [],
        webhooks: [],
    });
    // The document as last loaded or saved, serialized, to tell what is unsaved. Null until the first load finishes.
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
        const ids = (list: unknown) => ((list as { id: string }[] | undefined) ?? []).map((x) => x.id);
        api.getDispatcherCheckCatalog(token).then((c) => setChecks(c.checks)).catch(() => {
        });
        api.getCommandCatalog(token).then((c) => setCommands(c.commands)).catch(() => {
        });
        api.getConfig(token, "profiles").then((p) => setProfileIds(ids(p?.profiles))).catch(() => {
        });
        api.getConfig(token, "apps").then((a) => setAppIds(ids(a?.apps))).catch(() => {
        });
        api.getConfig(token, "groups").then((g) => setGroups((g?.groups as GroupDef[]) ?? [])).catch(() => {
        });
        // Enrolled only, as the dispatcher evaluates no other devices.
        api.listDevices(token, {state: "enrolled", limit: 500}).then((r) => setDevices(r.devices)).catch(() => {
        });
    }, [token]);

    const rules = useMemo(() => data?.rules ?? [], [data]);
    const webhooks = useMemo(() => data?.webhooks ?? [], [data]);
    // Worst tier first and config order within a tier (the sort is stable). Selection follows this order.
    const ordered = useMemo(
        () => [...rules].sort((a, b) => severityRank(a.severity) - severityRank(b.severity)),
        [rules],
    );

    // Clears a selection whose rule a reload or discard removed, and the effect below then selects the first rule.
    useEffect(() => {
        if (selection?.kind === "rule" && !rules.some((r) => r.id === selection.id)) setSelection(null);
    }, [rules, selection]);
    // The ?rule= deep link applies to the first selection only, so a later discard selects the top of the list instead
    // of the linked rule.
    const picked = useRef(false);
    useEffect(() => {
        if (selection) picked.current = true;
    }, [selection]);
    useEffect(() => {
        if (selection || !ordered.length) return;
        const wanted = picked.current ? null : initialRuleId;
        const hit = wanted && ordered.some((r) => r.id === wanted) ? wanted : ordered[0].id;
        // A link to a rule that no longer exists selects the top of the list, so name the one it could not find.
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
            return checks.find((c) => c.type === type)?.label ?? (type || "No check");
        },
        [checks],
    );

    const updateDoc = useCallback(
        (fn: (doc: Doc) => DispatcherConfig) =>
            setData((prev) => fn({...prev, rules: prev?.rules ?? [], webhooks: prev?.webhooks ?? []})),
        [setData],
    );

    const patchRule = useCallback(
        (patch: Partial<DispatcherRule>) =>
            updateDoc((doc) => ({...doc, rules: doc.rules.map((r, i) => (i === ruleIdx ? {...r, ...patch} : r))})),
        [updateDoc, ruleIdx],
    );

    const setWebhooks = (webhooks: DispatcherWebhook[]) => updateDoc((doc) => ({...doc, webhooks}));

    const createRule = () => {
        const base = "rule";
        let id = base;
        let n = 1;
        while (rules.some((r) => r.id === id)) id = `${base}-${++n}`;
        const created: DispatcherRule = {
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
        updateDoc((doc) => ({...doc, rules: [...doc.rules, created]}));
        setQuery("");
        setSelection({kind: "rule", id});
    };

    const deleteRule = () => {
        if (!rule) return;
        const target = rule;
        const idx = ordered.findIndex((r) => r.id === target.id);
        modals.openConfirmModal({
            title: "Delete rule",
            children: (
                <Text size="sm">
                    Delete <b>{target.name}</b>? Alerts it raised stay, but the rule stops evaluating once you
                    save.
                </Text>
            ),
            labels: {confirm: "Delete", cancel: "Cancel"},
            confirmProps: {color: "red"},
            onConfirm: () => {
                updateDoc((doc) => ({...doc, rules: doc.rules.filter((r) => r.id !== target.id)}));
                // Select the neighbour that takes the deleted rule's place, so the form does not empty out mid-edit.
                const rest = ordered.filter((r) => r.id !== target.id);
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
                                                        background: swatchColor(tier.severity),
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

                {/* Right: the selected rule or the webhook targets */}
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
                                            label="Resolve the alert once the device passes the check again."
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
                                        description="Alert only once the check has failed this long"
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

                                <Divider my="sm" label="Compliance check (raises an alert when true)"
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
