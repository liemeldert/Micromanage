"use client";

// Device details: identity card, section navigation and quick actions in a left rail, with a Summary landing view
// (gauges, security posture, key facts) and the deeper sections behind it. Commands come from the server's catalog.

import {Fragment, use, useCallback, useEffect, useRef, useState} from "react";
import {useRouter} from "next/navigation";
import Link from "next/link";
import {
    ActionIcon,
    Alert,
    Anchor,
    Badge,
    Box,
    Button,
    Code,
    Collapse,
    Group,
    Loader,
    NavLink,
    Progress,
    SimpleGrid,
    Stack,
    Table,
    Text,
    TextInput,
    ThemeIcon,
    Title,
    Tooltip,
} from "@mantine/core";
import {modals} from "@mantine/modals";
import {notifications} from "@mantine/notifications";
import {
    IconActivityHeartbeat,
    IconAlertTriangle,
    IconApps,
    IconArrowLeft,
    IconBattery3,
    IconBrandApple,
    IconCertificate,
    IconCheck,
    IconChevronDown,
    IconChevronRight,
    IconClock,
    IconCpu,
    IconDatabase,
    IconDeviceDesktop,
    IconDeviceIpad,
    IconDeviceLaptop,
    IconDeviceMobile,
    IconDeviceTv,
    IconDotsCircleHorizontal,
    IconFileDescription,
    IconHistory,
    IconInfoCircle,
    IconLayoutDashboard,
    IconMapPin,
    IconPencil,
    IconRefresh,
    IconRobot,
    IconServer,
    IconShieldLock,
    IconSitemap,
    IconTags,
    IconTarget,
    IconTerminal2,
    IconTrash,
    IconUserCog,
    IconWand,
    IconWifi,
    IconX,
} from "@tabler/icons-react";
import {
    api,
    ApiError,
    AUDIT_TAG_ACTION,
    type CatalogCommand,
    type DdmDeclarationReported,
    type DdmDeviceState,
    type Device,
    type DeviceDetail,
    type DispatcherAlert,
    type FlowRunSummary,
    type ScopeExplain,
    type ScopeExplainEntry,
    type Task,
} from "../../../../../lib/api";
import {clickable} from "../../../../../lib/a11y";
import {useAuth} from "../../../../../lib/auth-context";
import {TaskDetailDrawer} from "@/components/TaskDetailDrawer";
import {TaskErrorBody} from "@/components/TaskErrorPanel";
import {CommandsPanel, QuickActionsCard, RefreshButton} from "@/components/DeviceCommandKit";
import {FactRow} from "@/components/ui/FactRow";
import {GlassAlert} from "@/components/ui/GlassAlert";
import {glassClassName} from "@/components/ui/glass";
import {Value} from "@/components/ui/Value";
import {DeviceTagsField} from "@/components/DeviceTagsField";
import {PageSkeleton} from "@/components/layout/PageSkeleton";
import {SidebarLayout} from "@/components/layout/SidebarLayout";
import {BreakTheGlassCard} from "@/components/BreakTheGlassCard";
import {type DeviceLocation, DeviceLocationMap} from "@/components/DeviceLocationMap";
import {type AttrItem, flattenToDotPaths, organizeAttributes,} from "../../../../../lib/device-attributes";
import {timeSince} from "../../../../../lib/time";
import {describeTaskType} from "../../../../../lib/task-errors";
import {
    agreementNote,
    type DeploymentKind,
    type ReconciledDeployment,
    reconcileDeployments,
} from "../../../../../lib/deployments";
import {DEPLOYMENT_STATUS_LABELS, STATUS_COLORS,} from "../../../../../lib/status-labels";
import {
    ACTOR_LABELS,
    type ActorKind,
    attributeTags,
    automationEvents,
    parseTagAudit,
    parseTimelineEntry,
    reversibleTags,
    type TagAuditRow,
} from "../../../../../lib/automation";
import {GlassCard} from "@/components/ui/GlassCard";

function seenColor(iso: string): string {
    const age = Date.now() - new Date(iso).getTime();
    if (age < 60 * 60 * 1000) return "teal";
    if (age < 7 * 86400 * 1000) return "yellow";
    return "gray";
}

function deviceIcon(model: string) {
    const m = (model || "").toLowerCase();
    if (m.includes("macbook")) return IconDeviceLaptop;
    if (m.includes("mac")) return IconDeviceDesktop;
    if (m.includes("ipad")) return IconDeviceIpad;
    if (m.includes("iphone") || m.includes("ipod")) return IconDeviceMobile;
    if (m.includes("appletv") || m.includes("apple tv")) return IconDeviceTv;
    return IconDeviceLaptop;
}

const ENROLL_META: Record<string, { label: string; color: string }> = {
    enrolled: {label: "Enrolled", color: "teal"},
    unenrolled: {label: "Unenrolled", color: "gray"},
    pending: {label: "Pending", color: "indigo"},
};

// enrollment_state arrives as a plain string, so degrade an unknown value instead of throwing on the lookup.
function enrollMeta(state: string): { label: string; color: string } {
    return ENROLL_META[state] ?? {label: state || "Unknown", color: "gray"};
}

// Per-category icons for the section nav.
const SECTION_ICONS: Record<string, React.FC<{ size?: number }>> = {
    Hardware: IconCpu,
    Software: IconBrandApple,
    Security: IconShieldLock,
    Network: IconWifi,
    Cellular: IconDeviceMobile,
    Management: IconServer,
    Other: IconDotsCircleHorizontal,
};

function pick(obj: unknown, ...keys: string[]): string {
    // Device-reported inventory arrives as the dictionaries Apple sends. A row stored as a bare identifier string
    // would render as a line of dashes, so show the string itself.
    if (typeof obj === "string") return obj;
    if (!obj || typeof obj !== "object") return "--";
    const rec = obj as Record<string, unknown>;
    for (const k of keys) {
        const v = rec[k];
        if (v !== undefined && v !== null && v !== "") return String(v);
    }
    return "--";
}

//  Small display primitives


// Structured inventory values. Apple reports arrays and dictionaries for keys like the firewall app exceptions and
// OSUpdateSettings, which reach the fact tables as one long line of raw JSON. Parsing that text back lets the row
// show a summary with the formatted JSON behind a click.
function parseStructured(text: string): Record<string, unknown> | unknown[] | undefined {
    const t = text.trim();
    if (!t.startsWith("[") && !t.startsWith("{")) return undefined;
    try {
        const v: unknown = JSON.parse(t);
        return typeof v === "object" && v !== null ? (v as Record<string, unknown> | unknown[]) : undefined;
    } catch {
        return undefined;
    }
}

function StructuredFactRow({
                               label,
                               parsed,
                           }: {
    label: string;
    parsed: Record<string, unknown> | unknown[];
}) {
    const [open, setOpen] = useState(false);
    const isArray = Array.isArray(parsed);
    const count = isArray ? parsed.length : Object.keys(parsed).length;
    if (count === 0) {
        return (
            <FactRow label={label}>
                <Text fz="sm" c="dimmed">None</Text>
            </FactRow>
        );
    }
    return (
        <FactRow
            label={label}
            details={
                <Collapse expanded={open}>
                    <Code
                        block
                        mt={4}
                        style={{whiteSpace: "pre-wrap", wordBreak: "break-word", textAlign: "left"}}
                    >
                        {JSON.stringify(parsed, null, 2)}
                    </Code>
                </Collapse>
            }
        >
            <Anchor
                component="button"
                type="button"
                fz="sm"
                onClick={() => setOpen((o) => !o)}
                aria-expanded={open}
                aria-label={`${open ? "Hide" : "Show"} ${label}`}
            >
                {isArray ? `array (${count} item${count === 1 ? "" : "s"})` : "object"}
            </Anchor>
        </FactRow>
    );
}

function CheckRow({label, value}: { label: string; value: boolean | undefined }) {
    return (
        <FactRow label={label}>
            {value === undefined ? (
                <Text fz="sm" c="dimmed">--</Text>
            ) : (
                <ThemeIcon size="sm" radius="xl" variant="light" color={value ? "teal" : "gray"}>
                    {value ? <IconCheck size={12}/> : <IconX size={12}/>}
                </ThemeIcon>
            )}
        </FactRow>
    );
}

function BoolOrText({item}: { item: AttrItem }) {
    if (item.isBool && typeof item.boolValue === "boolean") {
        return (
            <Badge size="sm" variant="light" color={item.boolValue ? "teal" : "gray"}>
                {item.boolValue ? "Yes" : "No"}
            </Badge>
        );
    }
    return <Value label={item.label}>{item.value}</Value>;
}

function PropertyGrid({items}: { items: AttrItem[] }) {
    return (
        <SimpleGrid cols={{base: 1, sm: 2}} spacing="xl" verticalSpacing={0}>
            {items.map((it) => {
                const parsed = it.isBool ? undefined : parseStructured(it.value);
                return parsed !== undefined ? (
                    <StructuredFactRow key={it.key} label={it.label} parsed={parsed}/>
                ) : (
                    <FactRow key={it.key} label={it.label}><BoolOrText item={it}/></FactRow>
                );
            })}
        </SimpleGrid>
    );
}

// One card of matched and excluded rows for profiles, apps or groups, each with the server's reason.
function ScopeGroupCard({
                            title,
                            icon: Icon,
                            entries,
                        }: {
    title: string;
    icon: React.FC<{ size?: number }>;
    entries: ScopeExplainEntry[];
}) {
    return (
        <GlassCard withBorder p="md">
            <Group gap="xs" mb="sm">
                <Icon size={16}/>
                <Text fz="sm" fw={600}>{title} ({entries.length})</Text>
            </Group>
            {entries.length === 0 ? (
                <Text fz="sm" c="dimmed">No {title.toLowerCase()} configured for this tenant.</Text>
            ) : (
                <Stack gap={0}>
                    {entries.map((e) => (
                        <Box
                            key={e.id}
                            py={8}
                            style={{borderBottom: "1px solid var(--mantine-color-default-border)"}}
                        >
                            <Group justify="space-between" wrap="nowrap" gap="sm">
                                <Text fz="sm" fw={500} truncate style={{minWidth: 0}}>{e.name}</Text>
                                <Badge
                                    size="sm"
                                    variant="light"
                                    color={e.matched ? "teal" : "gray"}
                                    style={{flexShrink: 0}}
                                >
                                    {e.matched ? "Receives" : "Excluded"}
                                </Badge>
                            </Group>
                            <Text fz="xs" c="dimmed" mt={2} style={{wordBreak: "break-word"}}>
                                {e.reason}
                            </Text>
                        </Box>
                    ))}
                </Stack>
            )}
        </GlassCard>
    );
}

// DDM validity to badge colour. Valid and active is healthy, invalid is a real problem. Unknown or pending stays
// neutral, since it only means the device has not checked in on this token.
function ddmStatusBadge(active: boolean, valid: DdmDeclarationReported["valid"] | undefined) {
    if (valid === "invalid") return {color: "red", label: "invalid"};
    if (valid === "valid" && active) return {color: "teal", label: "active"};
    if (valid === "valid" && !active) return {color: "gray", label: "inactive"};
    return {color: "gray", label: "pending"};
}

function DdmSection({
                        ddm,
                        loading,
                        error,
                        syncing,
                        isAdmin,
                        expandedRow,
                        onToggleRow,
                        onRefresh,
                        onSync,
                    }: {
    ddm: DdmDeviceState | null;
    loading: boolean;
    error: string | null;
    syncing: boolean;
    isAdmin: boolean;
    expandedRow: string | null;
    onToggleRow: (identifier: string) => void;
    onRefresh: () => void;
    onSync: () => void;
}) {
    if (loading) return <PageSkeleton variant="detail"/>;
    if (error) {
        return (
            <Alert color="red" variant="light" icon={<IconAlertTriangle size={16}/>}>
                {error}
            </Alert>
        );
    }
    if (!ddm) return <Text fz="sm" c="dimmed">No declarative management data available.</Text>;

    if (!ddm.supported) {
        return (
            <GlassCard withBorder p="md">
                <Text fz="sm" c="dimmed">
                    This device doesn&apos;t support Declarative Device Management (requires a
                    sufficiently new OS / MDM channel). Configuration is delivered through profiles instead.
                </Text>
            </GlassCard>
        );
    }
    if (!ddm.tenant_enabled) {
        return (
            <GlassCard withBorder p="md">
                <Text fz="sm" c="dimmed">
                    Declarative Device Management is turned off for this tenant. Turn it on in Settings to
                    start enforcing declarations on this device.
                </Text>
            </GlassCard>
        );
    }

    const driftSet = new Set(ddm.drift ?? []);
    const statusFacts = flattenToDotPaths(ddm.status_items);

    return (
        <Stack gap="md">
            <GlassCard withBorder p="md">
                <Group justify="space-between" align="flex-start" wrap="wrap">
                    <Group gap="lg" wrap="wrap">
                        <Stack gap={2}>
                            <Text fz="xs" c="dimmed">Enabled</Text>
                            <Badge size="sm" variant="light" color="teal">
                                {ddm.enabled_at ? new Date(ddm.enabled_at).toLocaleString() : "yes"}
                            </Badge>
                        </Stack>
                        <Stack gap={2}>
                            <Text fz="xs" c="dimmed">Last sync</Text>
                            <Text
                                fz="sm">{ddm.last_sync_at ? new Date(ddm.last_sync_at).toLocaleString() : "never"}</Text>
                        </Stack>
                        {driftSet.size > 0 && (
                            <Stack gap={2}>
                                <Text fz="xs" c="dimmed">Drift</Text>
                                <Badge size="sm" variant="light" color="orange">
                                    {driftSet.size} item{driftSet.size === 1 ? "" : "s"}
                                </Badge>
                            </Stack>
                        )}
                    </Group>
                    <Group gap="xs">
                        <Tooltip label="Reload declarative state">
                            <ActionIcon variant="subtle" color="gray" onClick={onRefresh}>
                                <IconRefresh size={16}/>
                            </ActionIcon>
                        </Tooltip>
                        {isAdmin && (
                            <Button size="xs" variant="light" loading={syncing} onClick={onSync}>
                                Sync now
                            </Button>
                        )}
                    </Group>
                </Group>
            </GlassCard>

            <GlassCard withBorder p="md">
                <Text fz="sm" fw={600} mb="md">Declarations ({ddm.desired.length})</Text>
                {ddm.desired.length === 0 ? (
                    <Text fz="sm" c="dimmed">No declarations scoped to this device.</Text>
                ) : (
                    <Box style={{overflowX: "auto"}}>
                        <Table fz="sm" verticalSpacing="xs">
                            <Table.Thead>
                                <Table.Tr>
                                    <Table.Th style={{width: 24}}/>
                                    <Table.Th>Name</Table.Th>
                                    <Table.Th>Type</Table.Th>
                                    <Table.Th>Status</Table.Th>
                                </Table.Tr>
                            </Table.Thead>
                            <Table.Tbody>
                                {ddm.desired.map((d) => {
                                    const rep = ddm.reported[d.identifier];
                                    const badge = ddmStatusBadge(rep?.active ?? false, rep?.valid);
                                    const drifted = driftSet.has(d.identifier);
                                    const reasons = rep?.reasons ?? [];
                                    const expanded = expandedRow === d.identifier;
                                    return (
                                        <Fragment key={d.identifier}>
                                            <Table.Tr
                                                style={{
                                                    cursor: reasons.length ? "pointer" : undefined,
                                                    background: drifted ? "var(--mantine-color-orange-light)" : undefined,
                                                }}
                                                {...(reasons.length
                                                    ? {
                                                        "aria-expanded": expanded,
                                                        "aria-label": `${expanded ? "Hide" : "Show"} reasons for ${d.name || d.identifier}`,
                                                        ...clickable(() => onToggleRow(d.identifier)),
                                                    }
                                                    : {})}
                                            >
                                                <Table.Td>
                                                    {reasons.length > 0 &&
                                                        (expanded ? <IconChevronDown size={14}/> :
                                                            <IconChevronRight size={14}/>)}
                                                </Table.Td>
                                                <Table.Td>
                                                    <Text fz="sm">{d.name || d.identifier}</Text>
                                                    <Text fz="xs" c="dimmed"
                                                          style={{fontFamily: "monospace"}}>{d.identifier}</Text>
                                                </Table.Td>
                                                {/* Always the full reverse-DNS identifier: a short form would
                            duplicate the Name column for server-managed types. */}
                                                <Table.Td>
                                                    <Text fz="xs" style={{fontFamily: "monospace"}}>{d.type}</Text>
                                                </Table.Td>
                                                <Table.Td>
                                                    <Group gap={6} wrap="nowrap">
                                                        <Badge size="xs" color={badge.color}
                                                               variant="light">{badge.label}</Badge>
                                                        {drifted && <Badge size="xs" color="orange"
                                                                           variant="outline">drift</Badge>}
                                                    </Group>
                                                </Table.Td>
                                            </Table.Tr>
                                            {reasons.length > 0 && (
                                                <Table.Tr>
                                                    <Table.Td colSpan={4} p={0}
                                                              style={{border: expanded ? undefined : "none"}}>
                                                        <Collapse expanded={expanded}>
                                                            <Stack gap={4} p="sm" pl={36}>
                                                                {reasons.map((r, i) => (
                                                                    <Box key={i}>
                                                                        {r.code && (
                                                                            <Text fz="xs" fw={600}
                                                                                  c="orange">{r.code}</Text>
                                                                        )}
                                                                        {r.description && <Text fz="xs"
                                                                                                c="dimmed">{r.description}</Text>}
                                                                    </Box>
                                                                ))}
                                                            </Stack>
                                                        </Collapse>
                                                    </Table.Td>
                                                </Table.Tr>
                                            )}
                                        </Fragment>
                                    );
                                })}
                            </Table.Tbody>
                        </Table>
                    </Box>
                )}
            </GlassCard>

            <GlassCard withBorder p="md">
                <Text fz="sm" fw={600} mb="xs">Status items</Text>
                {statusFacts.length === 0 ? (
                    <Text fz="sm" c="dimmed">No status facts reported yet.</Text>
                ) : (
                    <SimpleGrid cols={{base: 1, md: 2}} spacing="xl" verticalSpacing={0}>
                        {statusFacts.map((f) => {
                            // Dot-path flattening leaves array values, and nothing else, as JSON text, so they get
                            // the same summary and expander as the attribute tabs.
                            const parsed = f.isBool ? undefined : parseStructured(f.value);
                            return parsed !== undefined ? (
                                <StructuredFactRow key={f.path} label={f.path} parsed={parsed}/>
                            ) : (
                                <FactRow key={f.path} label={f.path}>
                                    {f.isBool ? (
                                        <Badge size="sm" variant="light" color={f.boolValue ? "teal" : "gray"}>
                                            {f.boolValue ? "Yes" : "No"}
                                        </Badge>
                                    ) : (
                                        <Text fz="sm" style={{wordBreak: "break-word"}}>{f.value}</Text>
                                    )}
                                </FactRow>
                            );
                        })}
                    </SimpleGrid>
                )}
            </GlassCard>
        </Stack>
    );
}

// One Managed deployments table, for apps or profiles, each row shown with the install attempt it is tracking. The
// row is the current fact and the attempt is context for it; lib/deployments.ts does the join.
function ManagedDeploymentsCard({
                                    kind,
                                    rows,
                                    onOpenTask,
                                }: {
    kind: DeploymentKind;
    rows: ReconciledDeployment[];
    onOpenTask: (t: Task) => void;
}) {
    const thing = kind === "app" ? "app" : "profile";

    return (
        <GlassCard withBorder p="md">
            <Text fz="sm" fw={600} mb="md">Managed deployments ({rows.length})</Text>

            {rows.length === 0 ? (
                <Text fz="sm" c="dimmed">No managed {thing}s targeted at this device.</Text>
            ) : (
                <Box style={{overflowX: "auto"}}>
                    <Table fz="sm" verticalSpacing="xs">
                        <Table.Thead>
                            <Table.Tr>
                                <Table.Th>{kind === "app" ? "App" : "Profile"}</Table.Th>
                                {kind === "app" && <Table.Th>Version</Table.Th>}
                                <Table.Th>Status</Table.Th>
                                <Table.Th>Last install attempt</Table.Th>
                            </Table.Tr>
                        </Table.Thead>
                        <Table.Tbody>
                            {rows.map((r) => {
                                const note = r.conflicted ? agreementNote(r, kind) : null;
                                return (
                                    <Table.Tr key={r.id}>
                                        <Table.Td>
                                            <Text fz="sm">{r.name}</Text>
                                            {r.name !== r.id && (
                                                <Text fz="xs" c="dimmed" style={{fontFamily: "monospace"}}>{r.id}</Text>
                                            )}
                                            {/* The row's own account of the failure, so a failed deployment
                          explains itself here rather than in the Activity tab. */}
                                            {r.lastError && (
                                                <Text fz="xs" c="red" mt={2}
                                                      style={{maxWidth: 460, whiteSpace: "pre-wrap"}}>
                                                    {r.lastError}
                                                </Text>
                                            )}
                                            {note && (
                                                <Text fz="xs" c="dimmed" mt={2} style={{maxWidth: 460}}>{note}</Text>
                                            )}
                                            {/* A compliance rule put this on a device whose own scope never asked
                          for it, so the rule is worth naming. The sentence about it staying
                          only holds while the row is still held: a row at unscoped got there
                          because the rule holding it is gone. */}
                                            {r.remediationRuleId && (
                                                <Text fz="xs" c="blue" mt={2} style={{maxWidth: 460}}>
                                                    Installed by rule <Code>{r.remediationRuleId}</Code>.
                                                    {r.status !== "unscoped" &&
                                                        " Stays on the device until that rule is deleted, even though it is " +
                                                        "outside this device's own scope."}
                                                </Text>
                                            )}
                                        </Table.Td>
                                        {kind === "app" && <Table.Td>{r.version ?? "--"}</Table.Td>}
                                        <Table.Td>
                                            <Group gap={4} wrap="nowrap">
                                                <Badge size="xs" color={STATUS_COLORS[r.status] ?? "gray"}
                                                       variant="light">
                                                    {DEPLOYMENT_STATUS_LABELS[r.status] ?? r.status}
                                                </Badge>
                                                {r.agreement === "stalled" && (
                                                    <Tooltip label="Its install attempt is over and this never settled"
                                                             withinPortal>
                                                        <ThemeIcon size="xs" radius="xl" variant="light" color="orange">
                                                            <IconAlertTriangle size={10}/>
                                                        </ThemeIcon>
                                                    </Tooltip>
                                                )}
                                            </Group>
                                            {r.updatedAt && (
                                                <Text fz="xs" c="dimmed" mt={2}>{timeSince(r.updatedAt)}</Text>
                                            )}
                                        </Table.Td>
                                        <Table.Td>
                                            {r.attempt ? (
                                                <Group
                                                    gap={6}
                                                    wrap="nowrap"
                                                    style={{cursor: "pointer"}}
                                                    aria-label={`Open the install attempt for ${r.name}`}
                                                    {...clickable(() => onOpenTask(r.attempt!))}
                                                >
                                                    <Badge
                                                        size="xs"
                                                        variant="light"
                                                        color={STATUS_COLORS[r.attempt.status] ?? "gray"}
                                                    >
                                                        {r.attempt.status}
                                                    </Badge>
                                                    <Text fz="xs" c="dimmed">
                                                        {r.attempt.completed_at || r.attempt.created_at
                                                            ? timeSince((r.attempt.completed_at ?? r.attempt.created_at)!)
                                                            : ""}
                                                    </Text>
                                                </Group>
                                            ) : r.attemptId ? (
                                                // The row names an attempt that has dropped off the recent-task
                                                // list. It was tried; only the record has aged out.
                                                <Tooltip label={r.attemptId} withinPortal>
                                                    <Text fz="xs" c="dimmed">older than the recent tasks</Text>
                                                </Tooltip>
                                            ) : (
                                                <Text fz="xs" c="dimmed">none recorded</Text>
                                            )}
                                        </Table.Td>
                                    </Table.Tr>
                                );
                            })}
                        </Table.Tbody>
                    </Table>
                </Box>
            )}

            <Text fz="xs" c="dimmed" mt="sm">
                Status is what Micromanage believes is on the device: installed when the device answers, failed
                when the device reports an error or an attempt times out with no answer. The attempt column shows the
                install that
                produced it, for as long as that task stays among the 10 most recent on this device.
            </Text>
        </GlassCard>
    );
}

// A command task arrives described as "<type slug> on <serial>", which puts raw slugs like rotate_filevault_key in
// the activity lists. Swap the slug for the display name used elsewhere; any other description is already prose.
function taskTitle(t: Task): string {
    const prefix = `${t.type} on `;
    return t.description.startsWith(prefix)
        ? `${describeTaskType(t.type)}${t.description.slice(t.type.length)}`
        : t.description;
}

const ACTOR_META: Record<ActorKind, { color: string; icon: React.FC<{ size?: number }> }> = {
    compliance: {color: "orange", icon: IconActivityHeartbeat},
    flow: {color: "grape", icon: IconSitemap},
    manual: {color: "gray", icon: IconUserCog},
};

// Compliance rules and automation flows in one place, with the device's tags attributed to whichever of them put
// each one there. Nothing else in the product changes a device on its own.
function AutomationSection({
                               device,
                               alerts,
                               runs,
                               tasks,
                               tagAudit,
                               isAdmin,
                               router,
                           }: {
    device: Device;
    alerts: DispatcherAlert[];
    runs: FlowRunSummary[];
    tasks: Task[];
    tagAudit: TagAuditRow[] | null;
    isAdmin: boolean;
    router: ReturnType<typeof useRouter>;
}) {
    const events = automationEvents(alerts, runs);
    const attributions = attributeTags(device.tags ?? [], alerts, runs, tasks, tagAudit);
    const automated = attributions.filter((a) => a.sources.some((s) => s.kind !== "manual"));
    const activeAlerts = alerts.filter((a) => a.status !== "resolved");

    return (
        <Stack gap="md">
            <GlassCard withBorder p="md">
                <Group gap="xs" mb={6}>
                    <IconRobot size={16}/>
                    <Text fz="sm" fw={600}>What changes this device automatically</Text>
                </Group>
                <Text fz="sm" c="dimmed">
                    Two systems can act on a device with nobody driving them, and both are listed here.
                    Nothing else in Micromanage changes a device on its own.
                </Text>
                <SimpleGrid cols={{base: 1, sm: 2}} spacing="md" mt="md">
                    <Box
                        p="sm"
                        style={{
                            border: "1px solid var(--mantine-color-default-border)",
                            borderRadius: "var(--mantine-radius-sm)",
                            cursor: "pointer"
                        }}
                        {...clickable(() => router.push("/compliance"), "link")}
                    >
                        <Group gap={6} mb={2}>
                            <IconActivityHeartbeat size={14}/>
                            <Text fz="sm" fw={500}>Compliance rules</Text>
                            <Badge size="xs" variant="light" color={activeAlerts.length ? "orange" : "gray"}>
                                {activeAlerts.length} active
                            </Badge>
                        </Group>
                        <Text fz="xs" c="dimmed">
                            Check the device against a policy, raise an alert, and can tag or remediate it.
                        </Text>
                    </Box>
                    <Box
                        p="sm"
                        style={{
                            border: "1px solid var(--mantine-color-default-border)",
                            borderRadius: "var(--mantine-radius-sm)",
                            cursor: "pointer"
                        }}
                        {...clickable(() => router.push("/atc"), "link")}
                    >
                        <Group gap={6} mb={2}>
                            <IconSitemap size={14}/>
                            <Text fz="sm" fw={500}>Automation flows</Text>
                            <Badge size="xs" variant="light" color={runs.length ? "grape" : "gray"}>
                                {runs.length} run{runs.length === 1 ? "" : "s"}
                            </Badge>
                        </Group>
                        <Text fz="xs" c="dimmed">
                            Run step by step at enrollment or on a schedule, and can tag, rename, or install.
                        </Text>
                    </Box>
                </SimpleGrid>
            </GlassCard>

            <GlassCard withBorder p="md">
                <Group gap="xs" mb="sm">
                    <IconTags size={16}/>
                    <Text fz="sm" fw={600}>Where this device&apos;s tags came from</Text>
                </Group>
                {(device.tags ?? []).length === 0 ? (
                    <Text fz="sm" c="dimmed">This device has no tags.</Text>
                ) : (
                    <Stack gap={0}>
                        {attributions.map((a) => (
                            <Group
                                key={a.tag}
                                justify="space-between"
                                wrap="nowrap"
                                gap="md"
                                py={8}
                                style={{borderBottom: "1px solid var(--mantine-color-default-border)"}}
                            >
                                <Badge variant="light"
                                       color={a.sources.some((s) => s.kind !== "manual") ? "orange" : "blue"}>
                                    {a.tag}
                                </Badge>
                                <Box style={{textAlign: "right", minWidth: 0}}>
                                    {a.sources.length === 0 ? (
                                        <Text fz="xs" c="dimmed">
                                            No record of who added this. It was set by hand, or before the retained
                                            history window.
                                        </Text>
                                    ) : (
                                        // A Box rather than a Text wrapper: Text renders a p, and Badge renders a
                                        // div, which React will not hydrate.
                                        a.sources.map((s, i) => (
                                            <Box key={i}>
                                                <Text span fz="xs">
                                                    {ACTOR_LABELS[s.kind]}{" "}
                                                    {s.href ? (
                                                        <Anchor component={Link} href={s.href} fz="xs">
                                                            {s.actor}
                                                        </Anchor>
                                                    ) : (
                                                        <b>{s.actor}</b>
                                                    )}
                                                    {s.at && <Text span c="dimmed"> · {timeSince(s.at)}</Text>}
                                                    {s.note && <Text span c="dimmed"> · {s.note}</Text>}
                                                </Text>
                                                {!s.recorded && (
                                                    <Tooltip
                                                        label="Worked out from a related alert, flow run or task. Nothing recorded the tag change itself."
                                                        withinPortal
                                                    >
                                                        <Badge component="span" size="xs" variant="outline" color="gray"
                                                               ml={6}>
                                                            inferred
                                                        </Badge>
                                                    </Tooltip>
                                                )}
                                            </Box>
                                        ))
                                    )}
                                </Box>
                            </Group>
                        ))}
                    </Stack>
                )}
                {automated.length > 0 && (
                    <Text fz="xs" c="dimmed" mt="sm">
                        Tags applied by a compliance rule are taken back automatically when its alert
                        resolves. Remove one by hand while the rule still matches and it just comes back.
                    </Text>
                )}
                {!isAdmin && (
                    <Text fz="xs" c="dimmed" mt="sm">
                        The tag record itself needs an admin role to read, so what you see here is worked out
                        from this device&apos;s alerts, flow runs and tasks. It can miss a tag whose cause has
                        since been cleared.
                    </Text>
                )}
            </GlassCard>

            {isAdmin && (
                <GlassCard withBorder p="md">
                    <Group gap="xs" mb="sm">
                        <IconHistory size={16}/>
                        <Text fz="sm" fw={600}>Tag history</Text>
                    </Group>
                    {tagAudit === null ? (
                        <Text fz="sm" c="dimmed">The tag record could not be read.</Text>
                    ) : tagAudit.length === 0 ? (
                        <Text fz="sm" c="dimmed">
                            No tag change has been recorded for this device. Tags it already carries were set
                            before this record existed.
                        </Text>
                    ) : (
                        <Stack gap={0}>
                            {tagAudit.map((row, i) => {
                                const meta = ACTOR_META[row.kind];
                                const Icon = meta.icon;
                                return (
                                    <Group
                                        key={i}
                                        justify="space-between"
                                        wrap="nowrap"
                                        align="flex-start"
                                        gap="md"
                                        py={8}
                                        style={{borderBottom: "1px solid var(--mantine-color-default-border)"}}
                                    >
                                        <Box style={{minWidth: 0}}>
                                            <Group gap={4} wrap="wrap">
                                                <Icon size={14}/>
                                                {row.added.map((t) => (
                                                    <Badge key={`a-${t}`} size="xs" variant="light"
                                                           color="teal">+{t}</Badge>
                                                ))}
                                                {row.removed.map((t) => (
                                                    <Badge key={`r-${t}`} size="xs" variant="light"
                                                           color="red">-{t}</Badge>
                                                ))}
                                            </Group>
                                            <Text fz="xs" c="dimmed" mt={2}>
                                                {ACTOR_LABELS[row.kind]} <b>{row.actor}</b>
                                                {row.reason && ` · ${row.reason}`}
                                            </Text>
                                        </Box>
                                        {row.at && (
                                            <Text fz="xs" c="dimmed" style={{flexShrink: 0}}>{timeSince(row.at)}</Text>
                                        )}
                                    </Group>
                                );
                            })}
                        </Stack>
                    )}
                    <Text fz="xs" c="dimmed" mt="sm">
                        Every tag change since this record started, whether a person, a compliance rule or an
                        automation flow made it. The full log is under{" "}
                        <Anchor component={Link} href="/settings/audit-log" fz="xs">Settings</Anchor>.
                    </Text>
                </GlassCard>
            )}

            <GlassCard withBorder p="md">
                <Text fz="sm" fw={600} mb="sm">Automated activity ({events.length})</Text>
                {events.length === 0 ? (
                    <Text fz="sm" c="dimmed">
                        No compliance rule or automation flow has acted on this device.
                    </Text>
                ) : (
                    <Stack gap={6}>
                        {events.map((e) => {
                            const meta = ACTOR_META[e.kind];
                            const Icon = meta.icon;
                            return (
                                <Group
                                    key={e.id}
                                    justify="space-between"
                                    wrap="nowrap"
                                    align="flex-start"
                                    p="xs"
                                    style={{
                                        borderRadius: "var(--mantine-radius-sm)",
                                        borderLeft: `3px solid var(--mantine-color-${e.severity ? SEVERITY_COLOR[e.severity] ?? meta.color : meta.color}-6)`,
                                        background: "var(--mantine-color-default-hover)",
                                        cursor: e.href ? "pointer" : undefined,
                                    }}
                                    {...(e.href
                                        ? {"aria-label": e.summary, ...clickable(() => router.push(e.href!), "link")}
                                        : {})}
                                >
                                    <Box style={{minWidth: 0}}>
                                        <Group gap={6} wrap="nowrap">
                                            <Icon size={14}/>
                                            <Text fz="sm" fw={500} truncate>{e.actor}</Text>
                                            <Badge size="xs" variant="outline" color={meta.color}>
                                                {e.kind === "compliance" ? "rule" : "flow"}
                                            </Badge>
                                        </Group>
                                        <Text fz="xs" c="dimmed" mt={2}>{e.summary}</Text>
                                        {e.tags.length > 0 && (
                                            <Group gap={4} mt={4}>
                                                <Text fz="xs" c="dimmed">tagged</Text>
                                                {e.tags.map((t) => (
                                                    <Badge key={t} size="xs" variant="light" color="orange">{t}</Badge>
                                                ))}
                                            </Group>
                                        )}
                                    </Box>
                                    <Stack gap={2} align="flex-end" style={{flexShrink: 0}}>
                                        {e.status && (
                                            <Badge
                                                size="sm"
                                                variant="light"
                                                color={
                                                    {
                                                        running: "blue",
                                                        waiting: "yellow",
                                                        completed: "teal",
                                                        failed: "red",
                                                        cancelled: "gray",
                                                        resolved: "gray",
                                                        open: "orange",
                                                        acknowledged: "yellow",
                                                        pending: "gray"
                                                    }[e.status] ?? "gray"
                                                }
                                            >
                                                {e.status}
                                            </Badge>
                                        )}
                                        {e.at && <Text fz="xs" c="dimmed">{timeSince(e.at)}</Text>}
                                    </Stack>
                                </Group>
                            );
                        })}
                    </Stack>
                )}
            </GlassCard>

            {runs.length > 0 && (
                <GlassCard withBorder p="md">
                    <Text fz="sm" fw={600} mb="sm">Step-by-step flow history</Text>
                    <Stack gap="sm">
                        {runs.map((r) => (
                            <Box key={r.id}>
                                <Group gap={6} mb={4}>
                                    <Text fz="sm" fw={500}>{r.flow_id}</Text>
                                    <Badge
                                        size="xs"
                                        variant="light"
                                        color={
                                            {
                                                running: "blue",
                                                waiting: "yellow",
                                                completed: "teal",
                                                failed: "red",
                                                cancelled: "gray"
                                            }[r.status] ?? "gray"
                                        }
                                    >
                                        {r.status}
                                    </Badge>
                                    <Anchor component={Link} href={`/atc/runs/${r.id}`} fz="xs">open run</Anchor>
                                </Group>
                                <Stack gap={2} pl="sm"
                                       style={{borderLeft: "2px solid var(--mantine-color-default-border)"}}>
                                    {(r.timeline ?? []).map((entry, i) => {
                                        const parsed = parseTimelineEntry(entry);
                                        return (
                                            <Text key={i} fz="xs" c="dimmed">
                                                {new Date(entry.at).toLocaleString()}: {parsed.summary}
                                            </Text>
                                        );
                                    })}
                                </Stack>
                            </Box>
                        ))}
                    </Stack>
                </GlassCard>
            )}

            {alerts.length > 0 && (
                <GlassCard withBorder p="md">
                    <Text fz="sm" fw={600} mb="sm">Compliance alerts ({activeAlerts.length} active)</Text>
                    <Stack gap={6}>
                        {alerts.map((a) => (
                            <Group
                                key={a.id}
                                justify="space-between"
                                wrap="nowrap"
                                p="xs"
                                style={{
                                    borderRadius: "var(--mantine-radius-sm)",
                                    borderLeft: `3px solid var(--mantine-color-${SEVERITY_COLOR[a.severity] ?? "gray"}-6)`,
                                    background: "var(--mantine-color-default-hover)",
                                    cursor: "pointer",
                                }}
                                aria-label={a.summary}
                                {...clickable(() => router.push("/compliance"), "link")}
                            >
                                <Group gap="xs" wrap="nowrap" style={{minWidth: 0}}>
                                    <Badge color={SEVERITY_COLOR[a.severity] ?? "gray"} variant="filled" tt="uppercase">
                                        {a.severity}
                                    </Badge>
                                    <Box style={{minWidth: 0}}>
                                        <Text fz="sm" truncate>{a.summary}</Text>
                                        {reversibleTags(a).length > 0 && (
                                            <Text fz="xs" c="dimmed">
                                                applied {reversibleTags(a).join(", ")}
                                            </Text>
                                        )}
                                    </Box>
                                </Group>
                                <Badge size="sm" variant="light" color={a.status === "resolved" ? "gray" : "orange"}>
                                    {a.status}
                                </Badge>
                            </Group>
                        ))}
                    </Stack>
                </GlassCard>
            )}
        </Stack>
    );
}

//  Page

// Same triage scale the dispatcher AlertBoard uses.
const SEVERITY_COLOR: Record<string, string> = {
    black: "dark",
    red: "red",
    yellow: "yellow",
    green: "green",
};

// DELETE /devices/{id} reports destroyed secrets by kind, without the kind_label the secrets ledger carries.
const SECRET_KIND_LABELS: Record<string, string> = {
    managed_admin_password: "Managed admin password",
    firmware_password: "Firmware password",
    recovery_lock: "Recovery lock password",
    filevault_prk: "FileVault recovery key",
};

function secretKindLabel(kind: string): string {
    return SECRET_KIND_LABELS[kind] ?? kind.replace(/_/g, " ");
}

// The forget-device DELETE has two 409s and only one is retryable with discard_secrets. detail.code separates them;
// the prose match covers a controller that predates that code.
function isUnrevealedSecrets409(e: ApiError): boolean {
    const code = (e.detail as { code?: unknown } | null | undefined)?.code;
    if (typeof code === "string") return code === "unrevealed_secrets";
    return /escrowed secret/i.test(e.message);
}

// The page fills the window and scrolls its two columns rather than itself, so the device's name, its state and
// whatever it is complaining about stay in view while the detail under them is read. The subtraction is the
// dashboard layout's own padding (spacing lg, top and bottom).
const PAGE_HEIGHT = "calc(100vh - var(--mantine-spacing-lg) * 2)";

// Space between the floating banners and the first card under them.
const BANNER_GAP = 12;

export default function DeviceDetailPage({params}: { params: Promise<{ id: string }> }) {
    const {id} = use(params);
    const {token, isAdmin} = useAuth();
    const router = useRouter();
    const [detail, setDetail] = useState<DeviceDetail | null>(null);
    const [catalog, setCatalog] = useState<CatalogCommand[]>([]);
    const [loading, setLoading] = useState(true);
    const [section, setSection] = useState("summary");
    const [selectedTask, setSelectedTask] = useState<Task | null>(null);
    const [cancellingTask, setCancellingTask] = useState<string | null>(null);
    const [retryingTask, setRetryingTask] = useState<string | null>(null);
    const [renaming, setRenaming] = useState(false);
    const [nameDraft, setNameDraft] = useState("");
    const [savingName, setSavingName] = useState(false);
    const [forgetting, setForgetting] = useState(false);

    // Scope-explain is fetched only once the Scope section is opened, since most visits never open it.
    const [scope, setScope] = useState<ScopeExplain | null>(null);
    const [scopeLoading, setScopeLoading] = useState(false);
    const [scopeError, setScopeError] = useState<string | null>(null);

    // Declarative Device Management state, fetched on the same terms once the Declarations section is opened.
    const [ddm, setDdm] = useState<DdmDeviceState | null>(null);
    const [ddmLoading, setDdmLoading] = useState(false);
    const [ddmError, setDdmError] = useState<string | null>(null);
    const [ddmSyncing, setDdmSyncing] = useState(false);
    const [expandedDdmRow, setExpandedDdmRow] = useState<string | null>(null);

    const load = async (background = false) => {
        if (!token) return;
        if (!background) setLoading(true);
        try {
            const d = await api.getDevice(token, id);
            setDetail(d);
            setSelectedTask((cur) => (cur ? d.recent_tasks.find((t) => t.id === cur.id) ?? cur : cur));
        } catch (e: unknown) {
            if (!background) notifications.show({color: "red", message: (e as Error).message});
        } finally {
            if (!background) setLoading(false);
        }
    };

    useEffect(() => {
        load();
    }, [token, id]); // eslint-disable-line react-hooks/exhaustive-deps

    // Command catalog is static per session, so fetch it once.
    useEffect(() => {
        if (!token) return;
        api.getCommandCatalog(token).then((r) => setCatalog(r.commands)).catch(() => {
        });
    }, [token]);

    // Deployment rows carry only the config id, while the install tasks that produced them are described by name.
    // apps.yaml and profiles.yaml give the names, which both label a row and match it to a task whose details were
    // never stamped.
    const [nameMaps, setNameMaps] = useState<{ apps: Record<string, string>; profiles: Record<string, string> }>({
        apps: {},
        profiles: {},
    });
    useEffect(() => {
        if (!token) return;
        type NamedList = { apps?: { id?: string; name?: string }[]; profiles?: { id?: string; name?: string }[] };
        Promise.all([
            api.getConfig(token, "apps").catch(() => null),
            api.getConfig(token, "profiles").catch(() => null),
        ]).then(([a, p]) => {
            const index = (rows: { id?: string; name?: string }[] | undefined) => {
                const out: Record<string, string> = {};
                for (const row of rows ?? []) if (row?.id) out[row.id] = row.name || row.id;
                return out;
            };
            setNameMaps({
                apps: index((a as NamedList | null)?.apps),
                profiles: index((p as NamedList | null)?.profiles),
            });
        });
    }, [token]);

    // Compliance alerts and ATC flow runs for this device, best-effort since either feature may be unconfigured.
    // Both are re-fetched alongside the device, so a flow run a just-sent command started still appears.
    const [deviceAlerts, setDeviceAlerts] = useState<DispatcherAlert[]>([]);
    const [deviceRuns, setDeviceRuns] = useState<FlowRunSummary[]>([]);
    // recent_tasks on the device payload is capped at 10 with no total, so counting it would read as this device's
    // entire history. /api/v1/tasks carries a real total for the same device_id, and a limit of 1 reads it cheaply.
    // Null while loading or after a failed fetch, so the tab shows no count rather than a wrong one.
    const [taskTotal, setTaskTotal] = useState<number | null>(null);
    // Every recorded tag change on this device, whoever made it. Null means the log could not be read, the normal
    // case for a member since /api/v1/audit-log is admin-only, and the Automation tab then falls back to inferring
    // provenance from alerts, flow timelines and tasks.
    const [tagAudit, setTagAudit] = useState<TagAuditRow[] | null>(null);
    const loadActivity = useCallback(async () => {
        if (!token) return;
        await Promise.all([
            api.listAlerts(token, {device_id: id}).then((r) => setDeviceAlerts(r.alerts)).catch(() => {
            }),
            api.getDeviceFlowRuns(token, id).then((r) => setDeviceRuns(r.flow_runs)).catch(() => {
            }),
            api.listTasks(token, {
                device_id: id,
                limit: 1
            }).then((r) => setTaskTotal(r.total)).catch(() => setTaskTotal(null)),
            isAdmin
                ? api
                    .listAuditLog(token, {
                        action: AUDIT_TAG_ACTION,
                        target_type: "device",
                        target_id: id,
                        limit: 200,
                    })
                    .then((r) => setTagAudit(parseTagAudit(r.entries)))
                    .catch(() => setTagAudit(null))
                : (setTagAudit(null), Promise.resolve()),
        ]);
    }, [token, id, isAdmin]);

    useEffect(() => {
        loadActivity();
    }, [loadActivity]);

    // Command results arrive over the webhook, so the page polls the device. The baseline is quiet at 15s; after a
    // command is sent it polls every 3s for 45s, so a query response or a lock-state change shows up promptly.
    const fastUntilRef = useRef(0);
    const handleDispatched = () => {
        fastUntilRef.current = Date.now() + 45_000;
        load(true);
        loadActivity();
    };
    useEffect(() => {
        let cancelled = false;
        let timer: ReturnType<typeof setTimeout>;
        const tick = async () => {
            if (cancelled) return;
            if (document.visibilityState === "visible") await Promise.all([load(true), loadActivity()]);
            if (cancelled) return;
            const fast = Date.now() < fastUntilRef.current;
            timer = setTimeout(tick, fast ? 3_000 : 15_000);
        };
        timer = setTimeout(tick, 15_000);
        return () => {
            cancelled = true;
            clearTimeout(timer);
        };
    }, [token, id]); // eslint-disable-line react-hooks/exhaustive-deps

    const handleCancelTask = async (taskId: string) => {
        if (!token) return;
        setCancellingTask(taskId);
        try {
            const res = await api.cancelTask(token, taskId);
            notifications.show({color: "teal", message: res.message});
        } catch (e: unknown) {
            notifications.show({color: "red", message: (e as Error).message});
        } finally {
            setCancellingTask(null);
            // Also after a refusal: "already failed, cannot be cancelled" means the row
            // on screen is out of date, so re-read rather than leave it saying running.
            load(true);
        }
    };

    const handleRetryTask = async (taskId: string) => {
        if (!token) return;
        setRetryingTask(taskId);
        try {
            const res = await api.retryTask(token, taskId);
            notifications.show({color: "teal", message: res.message});
            setSelectedTask(null); // close the drawer if the retried task was open
        } catch (e: unknown) {
            notifications.show({color: "red", message: (e as Error).message});
        } finally {
            setRetryingTask(null);
            load(true);
        }
    };

    // The device the lazy fetches below are allowed to write their result for: a response
    // for the previous device must not land on this one after a fast switch.
    const shownIdRef = useRef(id);

    // Loaded on the first visit to the Scope section and not refetched on later visits in the same session.
    const loadScope = async () => {
        if (!token || scope || scopeLoading) return;
        setScopeLoading(true);
        setScopeError(null);
        try {
            const r = await api.explainDeviceScope(token, id);
            if (shownIdRef.current !== id) return;
            setScope(r);
        } catch (e: unknown) {
            if (shownIdRef.current !== id) return;
            setScopeError(e instanceof ApiError ? e.message : (e as Error).message);
        } finally {
            setScopeLoading(false);
        }
    };

    // Loaded on the first visit to the Declarations section; the section's own Refresh button re-pulls it.
    const loadDdm = async (force = false) => {
        if (!token) return;
        if (!force && (ddm || ddmLoading)) return;
        setDdmLoading(true);
        setDdmError(null);
        try {
            const r = await api.getDeviceDdm(token, id);
            if (shownIdRef.current !== id) return;
            setDdm(r);
        } catch (e: unknown) {
            if (shownIdRef.current !== id) return;
            setDdmError(e instanceof ApiError ? e.message : (e as Error).message);
        } finally {
            setDdmLoading(false);
        }
    };

    // Next keeps this page mounted when only the [id] segment changes, as it does when jumping straight from one
    // device to another, so every piece of per-device state would otherwise stay on screen under the wrong device.
    // The lazy sections are the worst of it: their loaders return early once state is set.
    useEffect(() => {
        shownIdRef.current = id;
        setScope(null);
        setScopeError(null);
        setDdm(null);
        setDdmError(null);
        setExpandedDdmRow(null);
        setSelectedTask(null);
        setDeviceAlerts([]);
        setDeviceRuns([]);
        setTaskTotal(null);
        setTagAudit(null);
        setRenaming(false);
    }, [id]);

    // Single trigger for the lazy sections: opening one, and having one already open when the reset above clears
    // it. A recorded error blocks the refetch so a failure does not retry in a loop; re-entering clears and retries.
    const bannerRef = useRef<HTMLDivElement | null>(null);
    const [bannerHeight, setBannerHeight] = useState(0);
    const [errorDismissed, setErrorDismissed] = useState(false);
    const [stateDismissed, setStateDismissed] = useState(false);

    // The banners can be put away. A different failure arriving brings the banner back, since dismissing one
    // says nothing about the next.
    const errorKey = detail?.device?.last_task_error?.task_id ?? null;
    useEffect(() => {
        setErrorDismissed(false);
    }, [errorKey]);

    // How much of the columns the banners cover, measured rather than assumed: the text wraps to a different
    // number of lines depending on the window and on what went wrong.
    useEffect(() => {
        const el = bannerRef.current;
        if (!el) {
            setBannerHeight(0);
            return;
        }
        const measure = () => setBannerHeight(el.getBoundingClientRect().height
            ? Math.round(el.getBoundingClientRect().height) + BANNER_GAP
            : 0);
        measure();
        const observer = new ResizeObserver(measure);
        observer.observe(el);
        return () => observer.disconnect();
    }, [errorKey, errorDismissed, stateDismissed]);

    useEffect(() => {
        if (section === "scope" && !scope && !scopeError && !scopeLoading) loadScope();
        if (section === "declarations" && !ddm && !ddmError && !ddmLoading) loadDdm();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [section, id, token, scope, scopeError, scopeLoading, ddm, ddmError, ddmLoading]);

    const handleDdmSync = async () => {
        if (!token) return;
        setDdmSyncing(true);
        try {
            const res = await api.syncDeviceDdm(token, id);
            notifications.show({
                color: res.queued ? "teal" : "gray",
                message: res.queued ? "Declarative sync queued." : "Nothing to sync.",
            });
            await loadDdm(true);
        } catch (e: unknown) {
            notifications.show({
                color: "red",
                title: "Sync failed",
                message: e instanceof ApiError ? e.message : (e as Error).message,
            });
        } finally {
            setDdmSyncing(false);
        }
    };

    if (loading) return <Box py={80} style={{textAlign: "center"}}><Loader/></Box>;
    if (!detail) return <Text c="red">Device not found.</Text>;

    const {device, installed_apps, installed_profiles, recent_tasks} = detail;
    const attrs = (device.attributes ?? {}) as Record<string, unknown>;
    const sec = (attrs.SecurityInfo ?? {}) as Record<string, unknown>;
    // Apple nests the firewall flags one level deeper than the rest of SecurityInfo, under FirewallSettings. Some
    // stored inventories carry a flat SecurityInfo.FirewallEnabled instead, read as a fallback.
    const firewallSettings = (sec.FirewallSettings ?? {}) as Record<string, unknown>;
    const deviceProfiles = detail.device_profiles ?? [];
    const deviceApps = detail.device_apps ?? [];
    const groups = organizeAttributes(device.attributes);
    const DevIcon = deviceIcon(device.device_model);
    const enrolled = device.enrollment_state === "enrolled";

    const startRename = () => {
        setNameDraft(device.name ?? device.hostname ?? "");
        setRenaming(true);
    };
    const submitRename = async () => {
        if (!token) return;
        const name = nameDraft.trim();
        if (!name) return;
        setSavingName(true);
        try {
            const res = await api.renameDevice(token, id, name);
            notifications.show({
                color: "teal",
                message: res.pushed ? "Name saved and rename pushed to the device" : "Name saved",
            });
            setRenaming(false);
            await load(true);
        } catch (e) {
            notifications.show({color: "red", title: "Rename failed", message: (e as Error).message});
        } finally {
            setSavingName(false);
        }
    };

    // The server 409s a device still holding escrowed passwords nobody has read, since forgetting destroys the only
    // copy. That refusal is retryable with discard_secrets once an admin has confirmed the loss.
    const handleForget = async (discardSecrets = false) => {
        if (!token) return;
        setForgetting(true);
        try {
            const res = await api.deleteDevice(token, id, discardSecrets);
            const kinds = res.discarded_secret_kinds ?? [];
            notifications.show({
                color: "teal",
                message: kinds.length
                    ? `${res.message}. Destroyed ${kinds.length} stored password${kinds.length === 1 ? "" : "s"}: ${kinds
                        .map(secretKindLabel)
                        .join(", ")}.`
                    : res.message,
                autoClose: kinds.length ? 12_000 : undefined,
            });
            router.push("/devices");
        } catch (e: unknown) {
            if (e instanceof ApiError && e.status === 409 && !discardSecrets && isUnrevealedSecrets409(e)) {
                await confirmDiscardSecrets();
                return;
            }
            notifications.show({
                color: "red",
                title: "Couldn't forget device",
                message: e instanceof ApiError ? e.message : (e as Error).message,
            });
        } finally {
            setForgetting(false);
        }
    };

    // Name what is about to be destroyed from the secrets ledger, rather than parse it back out of the server's
    // prose.
    const confirmDiscardSecrets = async () => {
        let labels: string[] = [];
        try {
            const r = await api.getDeviceSecrets(token!, id);
            labels = r.secrets.filter((s) => s.sealed).map((s) => s.kind_label);
        } catch {
            /* fall back to the generic wording below */
        }
        modals.openConfirmModal({
            title: "This device holds passwords nobody has read",
            children: (
                <Stack gap="sm">
                    <Text size="sm">
                        Micromanage is storing the only copy of{" "}
                        {labels.length ? (
                            <b>{labels.join(", ").toLowerCase()}</b>
                        ) : (
                            <b>one or more recovery passwords</b>
                        )}{" "}
                        for <b>{device.display_name}</b>. Nobody has ever revealed{" "}
                        {labels.length === 1 ? "it" : "them"}.
                    </Text>
                    <Text size="sm">
                        Forgetting the device deletes {labels.length === 1 ? "it" : "them"} permanently. If
                        this Mac is still locked, or you may ever need to log into its managed admin account,
                        you will not be able to get back in.
                    </Text>
                    <Alert color="orange" variant="light" icon={<IconAlertTriangle size={16}/>}>
                        <Text fz="sm">
                            Cancel, reveal what you need from <b>Break the glass</b> on the Summary tab, then
                            come back.
                        </Text>
                    </Alert>
                </Stack>
            ),
            labels: {confirm: "Forget and destroy the passwords", cancel: "Keep the device"},
            confirmProps: {color: "red"},
            onConfirm: () => handleForget(true),
        });
    };

    const confirmForget = () => {
        modals.openConfirmModal({
            title: "Forget device",
            children: (
                <Text size="sm">
                    Permanently remove <b>{device.display_name}</b> from Micromanage? Its history, tags,
                    and group membership will be deleted. This cannot be undone.
                </Text>
            ),
            labels: {confirm: "Forget device", cancel: "Cancel"},
            confirmProps: {color: "red"},
            onConfirm: () => handleForget(),
        });
    };

    // Gauges
    // -1 is Apple's sentinel for hardware with no battery, and a reported HasBattery of false says the same thing.
    // Either one hides the Charge card rather than show a negative percentage.
    const battery =
        typeof attrs.BatteryLevel === "number" && attrs.BatteryLevel >= 0 && attrs.HasBattery !== false
            ? attrs.BatteryLevel
            : null;
    const capacity = typeof attrs.DeviceCapacity === "number" ? attrs.DeviceCapacity : null;
    const available = typeof attrs.AvailableDeviceCapacity === "number" ? attrs.AvailableDeviceCapacity : null;
    const usedPct = capacity && available !== null ? Math.round(((capacity - available) / capacity) * 100) : null;

    const bool = (v: unknown): boolean | undefined => (typeof v === "boolean" ? v : undefined);

    // Location, from a DeviceLocation command. Lost Mode only.
    const rawLoc = attrs.DeviceLocation as Record<string, unknown> | undefined;
    const location: DeviceLocation | null =
        rawLoc && typeof rawLoc.Latitude === "number" && typeof rawLoc.Longitude === "number"
            ? {
                Latitude: rawLoc.Latitude as number,
                Longitude: rawLoc.Longitude as number,
                HorizontalAccuracy: typeof rawLoc.HorizontalAccuracy === "number" ? rawLoc.HorizontalAccuracy : null,
                Timestamp: typeof rawLoc.Timestamp === "string" ? rawLoc.Timestamp : null,
            }
            : null;
    const lostMode = bool(attrs.IsMDMLostModeEnabled) === true;
    // Location can be requested from a supervised iOS device in Lost Mode, and shown whenever a fix is already held.
    const isMacModel = (device.device_model || "").toLowerCase().includes("mac");
    const showLocationCard = location !== null || (bool(attrs.IsSupervised) && !isMacModel);

    const activeAlerts = deviceAlerts.filter((a) => a.status !== "resolved");
    const automationCount = activeAlerts.length + deviceRuns.length;

    // Join each deployment row to the install task that last tried to produce it, so the Apps and Profiles tabs
    // cannot quietly contradict the Activity tab.
    const appRows = reconcileDeployments(installed_apps, recent_tasks, "app", nameMaps.apps);
    const profileRows = reconcileDeployments(installed_profiles, recent_tasks, "profile", nameMaps.profiles);
    const appConflicts = appRows.filter((r) => r.conflicted).length;
    const profileConflicts = profileRows.filter((r) => r.conflicted).length;

    const SECTIONS = [
        {value: "summary", label: "Summary", icon: IconLayoutDashboard},
        ...groups.map((g) => ({
            value: g.category,
            label: g.category,
            icon: SECTION_ICONS[g.category] ?? IconDotsCircleHorizontal
        })),
        // Both tabs hold two tables, and this count is the managed-deployment one, the number that is always known.
        // The device-reported inventory count depends on the device having answered, and has its own heading.
        {
            value: "profiles",
            label: `Profiles (${installed_profiles.length})${profileConflicts ? " ⚠" : ""}`,
            icon: IconCertificate,
        },
        {value: "declarations", label: "Declarations", icon: IconFileDescription},
        {
            value: "apps",
            label: `Apps (${installed_apps.length})${appConflicts ? " ⚠" : ""}`,
            icon: IconApps,
        },
        {value: "scope", label: "Scope", icon: IconTarget},
        // taskTotal is the device's real task count; recent_tasks is only ever the 10 most recent, so the label
        // carries no count until that total arrives.
        {value: "tasks", label: taskTotal !== null ? `Activity (${taskTotal})` : "Activity", icon: IconClock},
        {value: "commands", label: "Commands", icon: IconTerminal2},
        // Compliance rules and automation flows share one tab.
        {
            value: "automation",
            label: `Automation${automationCount ? ` (${automationCount})` : ""}`,
            icon: IconRobot,
        },
    ];

    return (
        <Stack gap="lg" style={{height: PAGE_HEIGHT, minHeight: 0}}>
            <Group justify="space-between" style={{flexShrink: 0}}>
                <Group>
                    <ActionIcon variant="subtle" onClick={() => router.push("/devices")}>
                        <IconArrowLeft size={18}/>
                    </ActionIcon>
                    {renaming ? (
                        <Group gap={4} wrap="nowrap">
                            <TextInput
                                value={nameDraft}
                                onChange={(e) => setNameDraft(e.currentTarget.value)}
                                onKeyDown={(e) => {
                                    if (e.key === "Enter") submitRename();
                                    if (e.key === "Escape") setRenaming(false);
                                }}
                                size="sm"
                                w={240}
                                autoFocus
                                data-autofocus
                                disabled={savingName}
                            />
                            <Tooltip label="Save & push">
                                <ActionIcon variant="light" color="teal" loading={savingName}
                                            disabled={!nameDraft.trim()} onClick={submitRename}>
                                    <IconCheck size={16}/>
                                </ActionIcon>
                            </Tooltip>
                            <ActionIcon variant="subtle" color="gray" onClick={() => setRenaming(false)}
                                        disabled={savingName}>
                                <IconX size={16}/>
                            </ActionIcon>
                            {device.suggested_name && device.suggested_name !== nameDraft.trim() && (
                                <Tooltip label={`Use naming template: ${device.suggested_name}`}>
                                    <ActionIcon variant="subtle" color="blue"
                                                onClick={() => setNameDraft(device.suggested_name!)}>
                                        <IconWand size={16}/>
                                    </ActionIcon>
                                </Tooltip>
                            )}
                        </Group>
                    ) : (
                        <Group gap={4} wrap="nowrap">
                            <Title order={2}>{device.display_name}</Title>
                            <Tooltip label="Rename device">
                                <ActionIcon variant="subtle" color="gray" size="sm" onClick={startRename}>
                                    <IconPencil size={15}/>
                                </ActionIcon>
                            </Tooltip>
                        </Group>
                    )}
                    <Badge variant="light" color={enrollMeta(device.enrollment_state).color}>
                        {enrollMeta(device.enrollment_state).label}
                    </Badge>
                    {enrolled && (
                        <Tooltip label={`Last seen ${new Date(device.last_seen).toLocaleString()}`}>
                            {/* tt="none": Badge uppercases, and "8M AGO" reads as months. */}
                            <Badge variant="dot" color={seenColor(device.last_seen)} tt="none">
                                {timeSince(device.last_seen)}
                            </Badge>
                        </Tooltip>
                    )}
                </Group>
                <Group gap="xs">
                    {/* Re-poll the whole device. */}
                    {enrolled && (
                        <RefreshButton
                            device={device}
                            catalog={catalog}
                            commandType="refresh_info"
                            label="Refresh device"
                            size="sm"
                            variant="default"
                            onDispatched={handleDispatched}
                        />
                    )}
                    {/* Destructive and admin-only. The server also refuses it while the device is enrolled. */}
                    {isAdmin && (
                        <Tooltip
                            label={enrolled ? "Unenroll the device before forgetting it" : "Permanently remove this device"}
                        >
                            <Box style={{display: "inline-flex"}}>
                                <ActionIcon
                                    variant="subtle"
                                    color="red"
                                    size="lg"
                                    disabled={enrolled}
                                    loading={forgetting}
                                    onClick={confirmForget}
                                    aria-label="Forget device"
                                >
                                    <IconTrash size={18}/>
                                </ActionIcon>
                            </Box>
                        </Tooltip>
                    )}
                </Group>
            </Group>

            {/* The banners float over the columns rather than pushing them down the page, and the columns start
                below them so nothing opens covered. Scrolling then runs the content up behind the glass, which
                is the point of putting them on it. */}
            <Box style={{position: "relative", flex: 1, minHeight: 0}}>
                <Stack
                    ref={bannerRef}
                    gap="xs"
                    style={{position: "absolute", insetInline: 0, top: 0, zIndex: 3, pointerEvents: "none"}}
                >
                    {/* Explained in plain words. The upstream text names internal service hostnames and links to
                        generic HTTP status docs, so it stays behind "Technical details". */}
                    {device.last_task_error && !errorDismissed && (
                        <GlassAlert
                            color="red"
                            variant="light"
                            icon={<IconAlertTriangle size={16}/>}
                            withCloseButton
                            closeButtonLabel="Dismiss this failure"
                            onClose={() => setErrorDismissed(true)}
                            style={{pointerEvents: "auto"}}
                        >
                            <Text fz="sm" fw={600}>
                                {describeTaskType(device.last_task_error.task_type)} failed
                                {device.last_task_error.completed_at
                                    ? ` ${timeSince(device.last_task_error.completed_at)}`
                                    : device.last_task_error.created_at
                                        ? ` ${timeSince(device.last_task_error.created_at)}`
                                        : ""}
                            </Text>
                            {device.last_task_error.error ? (
                                <TaskErrorBody error={device.last_task_error.error}/>
                            ) : (
                                <Text fz="sm">No reason was recorded.</Text>
                            )}
                        </GlassAlert>
                    )}

                    {!enrolled && !stateDismissed && (
                        <GlassAlert
                            color={device.enrollment_state === "pending" ? "indigo" : "gray"}
                            variant="light"
                            icon={<IconInfoCircle size={16}/>}
                            withCloseButton
                            closeButtonLabel="Dismiss this notice"
                            onClose={() => setStateDismissed(true)}
                            style={{pointerEvents: "auto"}}
                        >
                            {device.enrollment_state === "pending" ? (
                                <>This device is <b>pre-provisioned</b> and hasn&apos;t enrolled yet. Its saved
                                    state (group membership) will apply automatically when it enrolls. Commands
                                    and live inventory become available after enrollment.</>
                            ) : (
                                <>This device is <b>unenrolled</b>
                                    {device.unenrolled_at ? ` (since ${new Date(device.unenrolled_at).toLocaleString()})` : ""}.
                                    Its history and last-known state are retained; if it re-enrolls, everything
                                    below is restored. Commands are unavailable while unenrolled.</>
                            )}
                        </GlassAlert>
                    )}
                </Stack>

            <SidebarLayout
                fill
                insetTop={bannerHeight}
                sidebar={
                    <Stack gap="md">
                        <GlassCard withBorder p="md" lift="quiet">
                            <Group wrap="nowrap" gap="sm">
                                <ThemeIcon size={54} variant="light">
                                    <DevIcon size={34}/>
                                </ThemeIcon>
                                <div style={{minWidth: 0}}>
                                    <Text fw={700} truncate>{device.serial_number}</Text>
                                    <Text fz="xs" c="dimmed" truncate>{device.device_model}</Text>
                                    <Text fz="xs"
                                          c="dimmed">{attrs.OSVersion ? `OS ${attrs.OSVersion}` : device.os_version}</Text>
                                </div>
                            </Group>
                            <Group gap={6} mt="sm">
                                {bool(attrs.IsSupervised) &&
                                    <Badge size="xs" variant="light" color="blue">Supervised</Badge>}
                                {bool(attrs.IsAppleSilicon) &&
                                    <Badge size="xs" variant="light" color="grape">Apple silicon</Badge>}
                                {bool(attrs.IsMDMLostModeEnabled) &&
                                    <Badge size="xs" variant="light" color="red">Lost Mode</Badge>}
                            </Group>
                            <Box mt="sm">
                                <DeviceTagsField device={device} onChanged={handleDispatched}/>
                            </Box>
                        </GlassCard>

                        <GlassCard withBorder p={6} lift="quiet">
                            {SECTIONS.map((s) => (
                                <NavLink
                                    key={s.value}
                                    label={s.label}
                                    leftSection={<s.icon size={15}/>}
                                    active={section === s.value}
                                    onClick={() => {
                                        setSection(s.value);
                                        // Opening a lazy section is also the retry for one whose fetch failed.
                                        if (s.value === "scope") setScopeError(null);
                                        if (s.value === "declarations") setDdmError(null);
                                    }}
                                    // A row inside a surface that is itself answering the pointer, so it
                                    // answers more quietly and lends the card its colour rather than
                                    // competing with it.
                                    className={glassClassName({material: "none", nested: true})}
                                    style={{borderRadius: "var(--mantine-radius-sm)"}}
                                />
                            ))}
                        </GlassCard>

                        {enrolled && (
                            <QuickActionsCard
                                device={device}
                                catalog={catalog}
                                onDispatched={handleDispatched}
                                onShowAll={() => setSection("commands")}
                            />
                        )}
                    </Stack>
                }
            >
                {section === "summary" && (
                    <Stack gap="md">
                        <GlassCard withBorder p="md">
                            <Text fz="sm" fw={600} mb="xs">Details</Text>
                            <SimpleGrid cols={{base: 1, md: 2}} spacing="xl" verticalSpacing={0}>
                                <FactRow label="Hostname" value={device.hostname || "--"}/>
                                <FactRow
                                    label="Model"
                                    value={pick(attrs, "ModelName", "ProductName") !== "--"
                                        ? pick(attrs, "ModelName", "ProductName")
                                        : device.device_model}
                                />
                                <FactRow label="Serial" value={device.serial_number} mono/>
                                <FactRow label="OS version">
                                    <Value label="OS version">{device.os_version}</Value>
                                    {typeof attrs.BuildVersion === "string" ?
                                        <Text span fz="xs" c="dimmed"> ({attrs.BuildVersion})</Text> : null}
                                </FactRow>
                                <FactRow label="UDID" value={device.udid || "--"} mono/>
                                {/* A pre-provisioned device has never enrolled, so this column holds the date
                      its record was created. A date is not something anyone retypes. */}
                                <FactRow
                                    label={device.enrollment_state === "pending" ? "Added" : "Enrolled"}
                                    value={new Date(device.enrollment_date).toLocaleDateString()}
                                    copyable={false}
                                />
                                {/* last_seen, in the header badge, is when the device last spoke on its own.
                      This is the poll schedule, which backs off the longer a device stays
                      quiet. */}
                                <FactRow
                                    label="Last polled"
                                    value={`${timeSince(device.last_polled_at)}, every ${device.poll_interval_minutes} min`}
                                    copyable={false}
                                />
                                <CheckRow label="Supervised" value={bool(attrs.IsSupervised)}/>
                                <FactRow label="Member of">
                                    <Group gap={4} justify="flex-end">
                                        {device.groups.length
                                            ? device.groups.map((g) => <Badge key={g} size="xs" variant="dot"
                                                                              color="blue">{g}</Badge>)
                                            : <Text fz="sm" c="dimmed">no groups</Text>}
                                    </Group>
                                </FactRow>
                            </SimpleGrid>
                        </GlassCard>

                        {isAdmin && <BreakTheGlassCard deviceId={device.id}/>}

                        {(battery !== null || usedPct !== null) && (
                            <SimpleGrid cols={{base: 1, sm: 2}} spacing="md">
                                {battery !== null && (
                                    <GlassCard withBorder p="md">
                                        <Group gap="xs" mb={6}>
                                            <IconBattery3 size={16}/>
                                            <Text fz="sm" fw={600}>Charge</Text>
                                            <Text fz="sm" c="dimmed">{Math.round(battery * 100)}%</Text>
                                        </Group>
                                        <Progress value={battery * 100} color={battery > 0.2 ? "teal" : "red"}
                                                  size="lg" radius="sm"/>
                                    </GlassCard>
                                )}
                                {usedPct !== null && (
                                    <GlassCard withBorder p="md">
                                        <Group gap="xs" mb={6}>
                                            <IconDatabase size={16}/>
                                            <Text fz="sm" fw={600}>Storage</Text>
                                            <Text fz="sm" c="dimmed">
                                                {available!.toFixed(1)} GB free of {capacity!.toFixed(0)} GB
                                            </Text>
                                        </Group>
                                        <Progress value={usedPct} color={usedPct > 90 ? "red" : "blue"} size="lg"
                                                  radius="sm"/>
                                    </GlassCard>
                                )}
                            </SimpleGrid>
                        )}

                        <GlassCard withBorder p="md">
                            <Group justify="space-between" mb="xs">
                                <Text fz="sm" fw={600}>Security</Text>
                                <RefreshButton device={device} catalog={catalog} commandType="security_info"
                                               disabled={!enrolled} onDispatched={handleDispatched}/>
                            </Group>
                            <SimpleGrid cols={{base: 1, md: 2}} spacing="xl" verticalSpacing={0}>
                                <CheckRow label="Passcode set" value={bool(sec.PasscodePresent)}/>
                                <CheckRow label="Passcode compliant" value={bool(sec.PasscodeCompliant)}/>
                                <CheckRow label="FileVault" value={bool(sec.FDE_Enabled)}/>
                                <CheckRow label="Firewall"
                                          value={bool(firewallSettings.FirewallEnabled ?? sec.FirewallEnabled)}/>
                                {/* SIP is reported inside SecurityInfo, never at the top level of attributes,
                      so reading it off attrs gives a different value. */}
                                <CheckRow label="System Integrity Protection"
                                          value={bool(sec.SystemIntegrityProtectionEnabled)}/>
                                <CheckRow label="Activation Lock" value={bool(attrs.IsActivationLockEnabled)}/>
                                <CheckRow label="Find My" value={bool(attrs.IsDeviceLocatorServiceEnabled)}/>
                                <CheckRow label="iCloud Backup" value={bool(attrs.IsCloudBackupEnabled)}/>
                            </SimpleGrid>
                            {Object.keys(sec).length === 0 && (
                                <Text fz="xs" c="dimmed" mt="xs">
                                    Security posture not collected yet. Click <b>Refresh</b> above to ask the
                                    device.
                                </Text>
                            )}
                        </GlassCard>

                        {showLocationCard && (
                            <GlassCard withBorder p="md">
                                <Group justify="space-between" mb="xs">
                                    <Group gap="xs">
                                        <IconMapPin size={16}/>
                                        <Text fz="sm" fw={600}>Location</Text>
                                    </Group>
                                    <Tooltip
                                        label={lostMode ? "Ask the device to report its location" : "Only available while the device is in Lost Mode"}
                                        withinPortal
                                    >
                                        <Box style={{display: "flex"}}>
                                            <RefreshButton
                                                device={device}
                                                catalog={catalog}
                                                commandType="device_location"
                                                label={location ? "Update" : "Request location"}
                                                disabled={!lostMode}
                                                onDispatched={handleDispatched}
                                            />
                                        </Box>
                                    </Tooltip>
                                </Group>
                                {location ? (
                                    <>
                                        <DeviceLocationMap location={location}/>
                                        {location.Timestamp && (
                                            <Text fz="xs" c="dimmed" mt={6}>
                                                As of {new Date(location.Timestamp).toLocaleString()}
                                            </Text>
                                        )}
                                    </>
                                ) : lostMode ? (
                                    // Already in Lost Mode, so the copy below does not ask for it to be turned
                                    // on.
                                    <Text fz="sm" c="dimmed">
                                        This device is in Lost Mode but hasn&apos;t reported a location yet.
                                        Use{" "}
                                        <b>Request location</b> above. It only answers while powered on and online,
                                        so this can take a while; the map appears here as soon as it does.
                                    </Text>
                                ) : (
                                    <Text fz="sm" c="dimmed">
                                        No location reported. Location can only be requested while the device is in
                                        Lost Mode: turn it on from Quick actions, then use <b>Request location</b>.
                                    </Text>
                                )}
                            </GlassCard>
                        )}

                        {recent_tasks.length > 0 && (
                            <GlassCard withBorder p="md">
                                <Group justify="space-between" mb="xs">
                                    <Text fz="sm" fw={600}>Recent activity</Text>
                                    <Anchor component="button" type="button" fz="xs"
                                            onClick={() => setSection("tasks")}>
                                        View all
                                    </Anchor>
                                </Group>
                                <Stack gap={6}>
                                    {recent_tasks.slice(0, 3).map((t) => (
                                        <Group key={t.id} justify="space-between" wrap="nowrap"
                                               style={{cursor: "pointer"}}
                                               aria-label={`Open task ${taskTitle(t)}`}
                                               {...clickable(() => setSelectedTask(t))}>
                                            <Text fz="sm" truncate>{taskTitle(t)}</Text>
                                            <Badge size="xs" color={STATUS_COLORS[t.status] ?? "gray"}
                                                   variant="light">{t.status}</Badge>
                                        </Group>
                                    ))}
                                </Stack>
                                {/* The Activity tab holds only the 10 most recent tasks, so this is the way to
                      a device's full history, filtered on the fleet-wide Tasks page. */}
                                <Anchor component={Link} href={`/settings/tasks?device_id=${id}`} fz="xs" mt={8}
                                        display="inline-block">
                                    View all tasks for this device{taskTotal !== null ? ` (${taskTotal})` : ""}
                                </Anchor>
                            </GlassCard>
                        )}
                    </Stack>
                )}

                {groups.map((g) => section === g.category && (
                    <Stack key={g.category} gap="md">
                        {/* Recovery credentials belong under Security, and also render on Summary. */}
                        {g.category === "Security" && isAdmin && <BreakTheGlassCard deviceId={device.id}/>}
                        <GlassCard withBorder p="md">
                            <Text fz="sm" fw={600} mb="xs">{g.category}</Text>
                            <PropertyGrid items={g.items}/>
                        </GlassCard>
                    </Stack>
                ))}

                {section === "profiles" && (
                    <Stack gap="md">
                        {/* Managed first, matching the Apps tab: the tab's count is this card's. */}
                        <ManagedDeploymentsCard kind="profile" rows={profileRows} onOpenTask={setSelectedTask}/>
                        <GlassCard withBorder p="md">
                            <Group justify="space-between" mb="md">
                                <Text fz="sm" fw={600}>On device ({deviceProfiles.length})</Text>
                                <RefreshButton device={device} catalog={catalog} commandType="profile_list"
                                               disabled={!enrolled} onDispatched={handleDispatched}/>
                            </Group>
                            {deviceProfiles.length === 0 ? (
                                <Text fz="sm" c="dimmed">Not queried yet. Click <b>Refresh</b> to ask the
                                    device.</Text>
                            ) : (
                                <Box style={{overflowX: "auto"}}>
                                    <Table fz="sm" verticalSpacing="xs">
                                        <Table.Thead>
                                            <Table.Tr>
                                                <Table.Th>Name</Table.Th><Table.Th>Identifier</Table.Th>
                                                <Table.Th>Version</Table.Th><Table.Th>Managed</Table.Th>
                                            </Table.Tr>
                                        </Table.Thead>
                                        <Table.Tbody>
                                            {deviceProfiles.map((p, i) => (
                                                <Table.Tr key={i}>
                                                    <Table.Td>{pick(p, "PayloadDisplayName", "PayloadIdentifier")}</Table.Td>
                                                    <Table.Td><Text fz="xs"
                                                                    style={{fontFamily: "monospace"}}>{pick(p, "PayloadIdentifier")}</Text></Table.Td>
                                                    <Table.Td>{pick(p, "PayloadVersion")}</Table.Td>
                                                    <Table.Td>{p.IsManaged ? <Badge size="xs" color="blue"
                                                                                    variant="light">managed</Badge> : "--"}</Table.Td>
                                                </Table.Tr>
                                            ))}
                                        </Table.Tbody>
                                    </Table>
                                </Box>
                            )}
                        </GlassCard>
                    </Stack>
                )}

                {section === "declarations" && (
                    <DdmSection
                        ddm={ddm}
                        loading={ddmLoading}
                        error={ddmError}
                        syncing={ddmSyncing}
                        isAdmin={isAdmin}
                        expandedRow={expandedDdmRow}
                        onToggleRow={(id2) => setExpandedDdmRow((cur) => (cur === id2 ? null : id2))}
                        onRefresh={() => loadDdm(true)}
                        onSync={handleDdmSync}
                    />
                )}

                {section === "apps" && (
                    <Stack gap="md">
                        {/* Managed first: it is what the tab's count refers to. The device-reported inventory
                  below runs to hundreds of rows on a Mac. */}
                        <ManagedDeploymentsCard kind="app" rows={appRows} onOpenTask={setSelectedTask}/>
                        <GlassCard withBorder p="md">
                            <Group justify="space-between" mb="md">
                                <Text fz="sm" fw={600}>On device ({deviceApps.length})</Text>
                                <RefreshButton device={device} catalog={catalog} commandType="app_list"
                                               disabled={!enrolled} onDispatched={handleDispatched}/>
                            </Group>
                            {deviceApps.length === 0 ? (
                                <Text fz="sm" c="dimmed">Not queried yet. Click <b>Refresh</b> to ask the
                                    device.</Text>
                            ) : (
                                <Box style={{overflowX: "auto"}}>
                                    <Table fz="sm" verticalSpacing="xs">
                                        <Table.Thead>
                                            <Table.Tr><Table.Th>Name</Table.Th><Table.Th>Identifier</Table.Th><Table.Th>Version</Table.Th></Table.Tr>
                                        </Table.Thead>
                                        <Table.Tbody>
                                            {deviceApps.map((a, i) => (
                                                <Table.Tr key={i}>
                                                    <Table.Td>{pick(a, "Name", "AppName")}</Table.Td>
                                                    <Table.Td><Text fz="xs"
                                                                    style={{fontFamily: "monospace"}}>{pick(a, "Identifier", "BundleId")}</Text></Table.Td>
                                                    <Table.Td>{pick(a, "ShortVersion", "Version")}</Table.Td>
                                                </Table.Tr>
                                            ))}
                                        </Table.Tbody>
                                    </Table>
                                </Box>
                            )}
                        </GlassCard>
                    </Stack>
                )}

                {section === "scope" && (
                    scopeLoading ? (
                        <Box py={60} style={{textAlign: "center"}}><Loader/></Box>
                    ) : scopeError ? (
                        <Alert color="red" variant="light" icon={<IconAlertTriangle size={16}/>}>
                            {scopeError}
                        </Alert>
                    ) : scope ? (
                        <Stack gap="md">
                            <Text fz="xs" c="dimmed">
                                Why this device does or doesn&apos;t receive each profile, app, and group,
                                evaluated against its current attributes and group membership.
                            </Text>
                            <ScopeGroupCard title="Profiles" icon={IconCertificate} entries={scope.profiles}/>
                            <ScopeGroupCard title="Apps" icon={IconApps} entries={scope.apps}/>
                            <ScopeGroupCard title="Groups" icon={IconSitemap} entries={scope.groups}/>
                        </Stack>
                    ) : (
                        <Text fz="sm" c="dimmed">No scope data available.</Text>
                    )
                )}

                {section === "tasks" && (
                    <GlassCard withBorder p="md">
                        <Group justify="space-between" mb="xs">
                            <Text fz="xs" c="dimmed">
                                {taskTotal !== null && taskTotal > recent_tasks.length
                                    ? `Showing the ${recent_tasks.length} most recent of ${taskTotal} tasks.`
                                    : "Most recent tasks."}
                            </Text>
                            <Anchor component={Link} href={`/settings/tasks?device_id=${id}`} fz="xs">
                                View all tasks for this device
                            </Anchor>
                        </Group>
                        {recent_tasks.length === 0 ? (
                            <Text fz="sm" c="dimmed">No recent tasks</Text>
                        ) : (
                            <Stack gap="xs">
                                {recent_tasks.map((t) => (
                                    <Box
                                        key={t.id}
                                        p="sm"
                                        style={{
                                            border: "1px solid var(--mantine-color-default-border)",
                                            borderRadius: "var(--mantine-radius-sm)",
                                            cursor: "pointer"
                                        }}
                                        aria-label={`Open task ${taskTitle(t)}`}
                                        {...clickable(() => setSelectedTask(t))}
                                    >
                                        <Group justify="space-between" mb={4}>
                                            <Text fz="sm" fw={500}>{taskTitle(t)}</Text>
                                            <Badge size="sm" color={STATUS_COLORS[t.status] ?? "gray"}
                                                   variant="light">{t.status}</Badge>
                                        </Group>
                                        {t.status === "running" && <Progress value={t.progress} size="xs" mt={4}/>}
                                        {/* Explained, with the raw upstream text one click away inside the
                          panel. */}
                                        {t.error && (
                                            <Box mt={4} c="red" onClick={(e) => e.stopPropagation()}
                                                 style={{cursor: "auto"}}>
                                                <TaskErrorBody error={t.error}/>
                                            </Box>
                                        )}
                                        <Text fz="xs" c="dimmed" mt={4}>
                                            {t.created_at ? new Date(t.created_at).toLocaleString() : ""}
                                        </Text>
                                    </Box>
                                ))}
                            </Stack>
                        )}
                    </GlassCard>
                )}

                {section === "commands" && (
                    enrolled ? (
                        <CommandsPanel device={device} catalog={catalog} onDispatched={handleDispatched}/>
                    ) : (
                        <GlassCard withBorder p="md">
                            <Text fz="sm" c="dimmed">
                                Commands are unavailable while the device is {device.enrollment_state}. They become
                                available once it enrolls and has an active MDM channel.
                            </Text>
                        </GlassCard>
                    )
                )}

                {section === "automation" && (
                    <AutomationSection
                        device={device}
                        alerts={deviceAlerts}
                        runs={deviceRuns}
                        tagAudit={tagAudit}
                        isAdmin={isAdmin}
                        tasks={recent_tasks}
                        router={router}
                    />
                )}
            </SidebarLayout>
            </Box>

            <TaskDetailDrawer
                task={selectedTask}
                opened={selectedTask !== null}
                onClose={() => setSelectedTask(null)}
                onCancel={handleCancelTask}
                cancelling={cancellingTask !== null}
                onRetry={handleRetryTask}
                retrying={retryingTask !== null}
            />
        </Stack>
    );
}
