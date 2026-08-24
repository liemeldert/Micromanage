"use client";

import {useCallback, useEffect, useMemo, useRef, useState} from "react";
import {
    Anchor,
    Badge,
    Box,
    Button,
    Code,
    Group,
    Pagination,
    Paper,
    SegmentedControl,
    Select,
    Stack,
    Table,
    Text,
    TextInput,
    Title,
    Tooltip,
} from "@mantine/core";
import {notifications} from "@mantine/notifications";
import {IconFilterOff, IconRefresh, IconSearch} from "@tabler/icons-react";
import Link from "next/link";
import {api, type AuditLogEntry} from "../../../../../lib/api";
import {PageSkeleton} from "@/components/layout/PageSkeleton";
import {PageHeader} from "@/components/layout/PageHeader";
import {clickable} from "../../../../../lib/a11y";
import {useAuth} from "../../../../../lib/auth-context";
import {GlassCard} from "@/components/ui/GlassCard";

const PAGE_SIZE = 25;

function fmt(iso: string | null) {
    if (!iso) return "--";
    return new Date(iso).toLocaleString();
}

// Every action the controller writes, grouped for reading. The server filter is an exact match, so the list is
// offered rather than typed.
const ACTION_GROUPS: { group: string; items: string[] }[] = [
    {
        group: "Devices",
        items: ["device.command", "device.ddm_sync", "device.forget", "device.rekey", "device.tags"],
    },
    {
        group: "Escrowed secrets",
        items: ["device_secret.reveal", "device_secret.reveal_throttled"],
    },
    {
        group: "Alerts",
        items: [
            "alert.breakglass_dismiss",
            "alert.remediation_approve",
            "alert.remediation_reject",
        ],
    },
    {
        group: "Automated device enrollment",
        items: [
            "dep.default_profile",
            "dep.disown",
            "dep.profile.assign",
            "dep.profile.push",
            "dep.profile.unassign",
            "dep.server.create",
            "dep.server.link",
            "dep.server.remove",
            "dep.server.unlink",
            "dep.sync",
        ],
    },
    {group: "Configuration", items: ["app.upload", "config.restore", "config.update"]},
    {
        group: "Users",
        // password_change is written by any role changing their own password, not only by an admin changing
        // someone else's.
        items: ["user.create", "user.delete", "user.password_change", "user.update"],
    },
];

// Per-action colours: destructive or irreversible in red, changes in blue, additions in teal.
const ACTION_COLORS: Record<string, string> = {
    "alert.breakglass_dismiss": "orange",
    "alert.remediation_approve": "red",
    "alert.remediation_reject": "blue",
    "app.upload": "teal",
    "config.restore": "orange",
    "config.update": "blue",
    "dep.default_profile": "blue",
    "dep.disown": "orange",
    "dep.profile.assign": "indigo",
    "dep.profile.push": "indigo",
    "dep.profile.unassign": "orange",
    "dep.server.create": "teal",
    "dep.server.link": "teal",
    "dep.server.remove": "red",
    "dep.server.unlink": "orange",
    "dep.sync": "blue",
    "device.command": "violet",
    "device.ddm_sync": "blue",
    "device.forget": "red",
    "device.rekey": "orange",
    "device.tags": "grape",
    "device_secret.reveal": "red",
    "device_secret.reveal_throttled": "orange",
    "user.create": "teal",
    "user.delete": "red",
    "user.password_change": "orange",
    "user.update": "blue",
};

// An action this build does not know still takes a colour from its family rather than dropping to grey.
const PREFIX_COLORS: Record<string, string> = {
    alert: "orange",
    app: "teal",
    config: "blue",
    dep: "indigo",
    device: "violet",
    device_secret: "red",
    user: "cyan",
};

const actionColor = (action: string): string =>
    ACTION_COLORS[action] ?? PREFIX_COLORS[action.split(".")[0]] ?? "gray";

const TARGET_TYPES = ["alert", "app", "config", "dep_server", "device", "user"];

interface Filters {
    action: string;
    actor: string;
    target_type: string;
    target_id: string;
    // Three states: "any" applies no filter, "system" narrows to rows with no human behind them, "human" to the rest.
    written_by: "any" | "human" | "system";
    // Local "YYYY-MM-DDTHH:mm" from <input type="datetime-local">, converted to a UTC instant on the way out.
    since: string;
    until: string;
}

const NO_FILTERS: Filters = {
    action: "",
    actor: "",
    target_type: "",
    target_id: "",
    written_by: "any",
    since: "",
    until: "",
};

// A datetime-local value is a wall clock with no zone. Date reads it as local time, and the UTC form is what the
// server is sent, so neither side has to guess.
function toInstant(local: string): string | undefined {
    if (!local) return undefined;
    const d = new Date(local);
    return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

// Every filter that is actually narrowing the list. Not a filter(Boolean) over the values, because "human" sends
// system false, which is a real filter and a falsy one.
function countActive(f: Filters): number {
    return (
        (f.action ? 1 : 0) +
        (f.actor ? 1 : 0) +
        (f.target_type ? 1 : 0) +
        (f.target_id ? 1 : 0) +
        (f.written_by !== "any" ? 1 : 0) +
        (f.since ? 1 : 0) +
        (f.until ? 1 : 0)
    );
}

/**
 * Every action puts something different in detail, so this renders whatever is there rather than a fixed set of
 * fields. Tag changes get added and removed badges.
 */
function DetailCell({entry}: { entry: AuditLogEntry }) {
    const detail = entry.detail ?? {};
    const keys = Object.keys(detail);
    if (keys.length === 0) return <Text fz="xs" c="dimmed">--</Text>;

    const asList = (v: unknown): string[] =>
        Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

    const added = asList(detail.added);
    const removed = asList(detail.removed);
    const rest = keys.filter((k) => !["added", "removed"].includes(k));

    return (
        <Stack gap={2}>
            {(added.length > 0 || removed.length > 0) && (
                <Group gap={4} wrap="wrap">
                    {added.map((t) => (
                        <Badge key={`a-${t}`} size="xs" variant="light" color="teal">+{t}</Badge>
                    ))}
                    {removed.map((t) => (
                        <Badge key={`r-${t}`} size="xs" variant="light" color="red">-{t}</Badge>
                    ))}
                </Group>
            )}
            {rest.map((k) => {
                const v = detail[k];
                if (v === null || v === undefined || v === "") return null;
                const text = typeof v === "object" ? JSON.stringify(v) : String(v);
                return (
                    <Text key={k} fz="xs" style={{wordBreak: "break-word"}}>
                        <Text span c="dimmed">{k}:</Text> {text}
                    </Text>
                );
            })}
        </Stack>
    );
}

export default function AuditLogPage() {
    const {token, isAdmin} = useAuth();
    const [entries, setEntries] = useState<AuditLogEntry[]>([]);
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const [loading, setLoading] = useState(true);
    // What is being typed, and what has actually been sent. Kept apart so a half-typed device id does not send a
    // query per keystroke.
    const [draft, setDraft] = useState<Filters>(NO_FILTERS);
    const [filters, setFilters] = useState<Filters>(NO_FILTERS);
    // Last request wins, so paging during a slow request cannot leave the previous page's rows on screen.
    const reqSeq = useRef(0);

    const load = useCallback(async () => {
        // The endpoint is admin-only, so a member would get a 403 toast next to the message rendered below.
        if (!token || !isAdmin) return;
        const seq = ++reqSeq.current;
        setLoading(true);
        try {
            const res = await api.listAuditLog(token, {
                skip: (page - 1) * PAGE_SIZE,
                limit: PAGE_SIZE,
                ...(filters.action ? {action: filters.action} : {}),
                ...(filters.actor ? {actor: filters.actor} : {}),
                ...(filters.target_type ? {target_type: filters.target_type} : {}),
                ...(filters.target_id ? {target_id: filters.target_id} : {}),
                // The "human" case has to send system false, not nothing at all.
                ...(filters.written_by === "any" ? {} : {system: filters.written_by === "system"}),
                ...(toInstant(filters.since) ? {since: toInstant(filters.since)} : {}),
                ...(toInstant(filters.until) ? {until: toInstant(filters.until)} : {}),
            });
            if (seq !== reqSeq.current) return;
            setEntries(res.entries);
            setTotal(res.total);
        } catch (e: unknown) {
            if (seq === reqSeq.current) {
                notifications.show({color: "red", message: (e as Error).message});
            }
        } finally {
            if (seq === reqSeq.current) setLoading(false);
        }
    }, [token, page, isAdmin, filters]);

    useEffect(() => {
        load();
    }, [load]);

    const applyFilters = (next: Filters) => {
        setDraft(next);
        setFilters(next);
        setPage(1);
    };

    // Read the value before the state updater runs: React recycles the synthetic event, so e.currentTarget is null
    // by the time the callback is invoked.
    const editDraft = (key: keyof Filters) => (e: React.ChangeEvent<HTMLInputElement>) => {
        const v = e.currentTarget.value;
        setDraft((d) => ({...d, [key]: v}));
    };

    const activeFilters = useMemo(() => countActive(filters), [filters]);

    // The endpoint refuses a member anyway; this only saves them an empty table.
    if (!isAdmin) {
        return (
            <Stack gap="lg">
                <Title order={2}>Audit log</Title>
                <Text c="dimmed">Admin role required to view the audit log.</Text>
                <Anchor component={Link} href="/settings" fz="sm">
                    Back to settings
                </Anchor>
            </Stack>
        );
    }

    const rows = entries.map((e) => (
        <Table.Tr key={e.id}>
            <Table.Td style={{whiteSpace: "nowrap", verticalAlign: "top"}}>
                <Text fz="xs">{fmt(e.created_at)}</Text>
            </Table.Td>
            <Table.Td style={{verticalAlign: "top"}}>
                {e.actor_email ? (
                    <>
                        <Anchor
                            fz="sm"
                            onClick={() => applyFilters({...filters, actor: e.actor_email!})}
                        >
                            {e.actor_email}
                        </Anchor>
                        {e.actor_role && <Text fz="xs" c="dimmed">{e.actor_role}</Text>}
                    </>
                ) : (
                    // A null actor marks a write with nobody behind it.
                    <Tooltip
                        label="Written by a compliance rule, a flow, or the enrollment webhook"
                        withinPortal
                    >
                        <Badge size="sm" variant="light" color="gray">System</Badge>
                    </Tooltip>
                )}
            </Table.Td>
            <Table.Td style={{verticalAlign: "top"}}>
                <Badge
                    size="sm"
                    variant="light"
                    color={actionColor(e.action)}
                    style={{cursor: "pointer"}}
                    // Badge clips its own label, cutting the longest action names to "user.password_ch..." in a
                    // column with room to spare.
                    styles={{root: {overflow: "visible"}, label: {overflow: "visible"}}}
                    aria-label={`Filter the log to ${e.action}`}
                    {...clickable(() => applyFilters({...filters, action: e.action}))}
                >
                    {e.action}
                </Badge>
            </Table.Td>
            <Table.Td style={{verticalAlign: "top"}}>
                {e.target_type ? (
                    <Stack gap={2}>
                        <Text fz="xs">{e.target_type}</Text>
                        {e.target_id && (
                            <Group gap={4} wrap="nowrap">
                                {/* Shown whole: truncating to 8 characters made every row of a busy device look
                                    like the next. */}
                                <Code fz="xs" style={{wordBreak: "break-all"}}>{e.target_id}</Code>
                                {e.target_type === "device" && (
                                    <Anchor component={Link} href={`/devices/${e.target_id}`} fz="xs">
                                        open
                                    </Anchor>
                                )}
                            </Group>
                        )}
                        {e.target_id && (
                            <Anchor
                                fz="xs"
                                onClick={() =>
                                    applyFilters({...filters, target_type: e.target_type!, target_id: e.target_id!})
                                }
                            >
                                everything done to this
                            </Anchor>
                        )}
                    </Stack>
                ) : (
                    <Text fz="xs" c="dimmed">--</Text>
                )}
            </Table.Td>
            <Table.Td style={{verticalAlign: "top"}}>
                <DetailCell entry={e}/>
            </Table.Td>
        </Table.Tr>
    ));

    return (
        <Stack gap="lg">
            <PageHeader back={{href: "/settings", label: "Settings"}} actions={<>
                <Button leftSection={<IconRefresh size={14}/>} variant="light" onClick={() => load()}>
                    Refresh
                </Button>
            </>}/>

            <GlassCard withBorder p="md">
                <Group align="flex-end" gap="sm" wrap="wrap">
                    <Select
                        label="Action"
                        placeholder="Any"
                        data={ACTION_GROUPS}
                        value={draft.action || null}
                        onChange={(v) => applyFilters({...draft, action: v ?? ""})}
                        clearable
                        searchable
                        w={220}
                    />
                    <Select
                        label="Target type"
                        placeholder="Any"
                        data={TARGET_TYPES}
                        value={draft.target_type || null}
                        onChange={(v) => applyFilters({...draft, target_type: v ?? ""})}
                        clearable
                        w={150}
                    />
                    <TextInput
                        label="Actor"
                        description="Whole email address"
                        placeholder="admin@example.org"
                        value={draft.actor}
                        onChange={editDraft("actor")}
                        onKeyDown={(e) => e.key === "Enter" && applyFilters(draft)}
                        w={240}
                    />
                    <TextInput
                        label="Target ID"
                        description="Whole id, as shown in the table"
                        placeholder="device or user id"
                        value={draft.target_id}
                        onChange={editDraft("target_id")}
                        onKeyDown={(e) => e.key === "Enter" && applyFilters(draft)}
                        w={300}
                    />
                    <Box>
                        <Text fz="sm" fw={500} mb={2}>
                            Written by
                        </Text>
                        <SegmentedControl
                            size="xs"
                            value={draft.written_by}
                            onChange={(v) => applyFilters({...draft, written_by: v as Filters["written_by"]})}
                            data={[
                                {label: "Anyone", value: "any"},
                                {label: "A person", value: "human"},
                                {label: "System", value: "system"},
                            ]}
                        />
                    </Box>
                    <TextInput
                        type="datetime-local"
                        label="From"
                        description="Your local time"
                        value={draft.since}
                        onChange={editDraft("since")}
                        onKeyDown={(e) => e.key === "Enter" && applyFilters(draft)}
                        w={220}
                    />
                    <TextInput
                        type="datetime-local"
                        label="To"
                        description="Your local time"
                        value={draft.until}
                        onChange={editDraft("until")}
                        onKeyDown={(e) => e.key === "Enter" && applyFilters(draft)}
                        w={220}
                    />
                    <Button
                        leftSection={<IconSearch size={14}/>}
                        variant="light"
                        onClick={() => applyFilters(draft)}
                    >
                        Apply
                    </Button>
                    {activeFilters > 0 && (
                        <Button
                            leftSection={<IconFilterOff size={14}/>}
                            variant="subtle"
                            color="gray"
                            onClick={() => applyFilters(NO_FILTERS)}
                        >
                            Clear
                        </Button>
                    )}
                </Group>
                <Text fz="xs" c="dimmed" mt="sm">
                    Action, actor and target match the whole value, because the server writes all three rather than
                    anyone typing them. To follow one administrator, filter by their email; to see what was done to
                    one device, use the &quot;everything done to this&quot; link on any of its
                    rows. <b>Written by</b> separates what a person did from what Micromanage did on its own, and the
                    dates bound both ends of the window.
                </Text>
            </GlassCard>

            <Text fz="sm" c="dimmed">
                {total} {total === 1 ? "entry" : "entries"}
                {activeFilters > 0 ? " matching these filters" : ""}
            </Text>

            {loading ? (
                <PageSkeleton variant="table"/>
            ) : entries.length === 0 ? (
                <Text c="dimmed" ta="center" py="xl">
                    {activeFilters > 0 ? "Nothing matches these filters." : "No audit entries yet."}
                </Text>
            ) : (
                <>
                    <Paper withBorder style={{overflowX: "auto"}}>
                        <Table highlightOnHover verticalSpacing="sm">
                            <Table.Thead>
                                <Table.Tr>
                                    <Table.Th>When</Table.Th>
                                    <Table.Th>Actor</Table.Th>
                                    <Table.Th>Action</Table.Th>
                                    <Table.Th>Target</Table.Th>
                                    <Table.Th>What changed</Table.Th>
                                </Table.Tr>
                            </Table.Thead>
                            <Table.Tbody>{rows}</Table.Tbody>
                        </Table>
                    </Paper>

                    <Pagination
                        total={Math.ceil(total / PAGE_SIZE)}
                        value={page}
                        onChange={setPage}
                    />
                </>
            )}
        </Stack>
    );
}
