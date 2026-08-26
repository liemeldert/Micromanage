"use client";

import {forwardRef, useCallback, useEffect, useRef, useState} from "react";
import {useRouter, useSearchParams} from "next/navigation";
import {
    ActionIcon,
    Badge,
    Box,
    Button,
    Group,
    Modal,
    Pagination,
    Paper,
    SegmentedControl,
    Stack,
    Table,
    TagsInput,
    Text,
    TextInput,
    Tooltip,
} from "@mantine/core";
import {useDebouncedValue} from "@mantine/hooks";
import {notifications} from "@mantine/notifications";
import {IconBrandApple, IconChevronRight, IconDeviceDesktopOff, IconPlus, IconRefresh,} from "@tabler/icons-react";
import {api, type Device, type EnrollmentState} from "../../../../lib/api";
import {PageSkeleton} from "@/components/layout/PageSkeleton";
import {PageHeader} from "@/components/layout/PageHeader";
import {useAuth} from "../../../../lib/auth-context";
import {type Group as GroupDef, useTagRegistry} from "../../../../lib/config";
import {timeSince} from "../../../../lib/time";
import {
    DEVICE_FILTER_LABELS_INLINE,
    type DeviceFilterKey,
    deviceQueryParams,
    formatDeviceQuery,
    parseDeviceQuery,
    withDeviceFilter,
} from "../../../../lib/device-filter";
import {usePeekGesture} from "@/components/ui/use-peek-gesture";
import {DevicePeekModal} from "@/components/DevicePeekModal";
import {DeviceSearchBar, type FilterValueSource} from "@/components/devices/DeviceSearchBar";
import {useFilterHistory} from "@/components/devices/use-filter-history";
import {openCommandPaletteWith} from "@/components/CommandPalette";
import {glassClassName, glassToneStyle} from "@/components/ui/glass";
import {Interactable} from "@/components/ui/Interactable";

const PAGE_SIZE = 20;

// Badge clips its label with an ellipsis once the column is narrower than the pill, which lets table layout
// squeeze single-word badges arbitrarily thin. Visible overflow gives the label back its min-content width.
const NO_TRUNCATE_BADGE_STYLES = {root: {overflow: "visible" as const}, label: {overflow: "visible" as const}};

const STATE_META: Record<string, { label: string; color: string }> = {
    enrolled: {label: "Enrolled", color: "teal"},
    unenrolled: {label: "Unenrolled", color: "gray"},
    pending: {label: "Pending", color: "indigo"},
};

// enrollment_state is a free string, so an unrecognised value still has to render as a readable chip.
function stateMeta(state: string): { label: string; color: string } {
    return STATE_META[state] ?? {label: state || "Unknown", color: "gray"};
}

// The chip's own element. The row behind it opens the device and starts a hold of its own, so the events the
// chip answers stop here. Interactable hands its handlers down as props, which this keeps rather than replaces.
const ChipSpan = forwardRef<HTMLSpanElement, React.ComponentPropsWithoutRef<"span">>(
    function ChipSpan({onPointerDown, onClick, onKeyDown, ...rest}, ref) {
        return (
            <span
                ref={ref}
                // Interactable sets the same pair for anything it can activate, and the spread keeps its value.
                role="button"
                tabIndex={0}
                {...rest}
                onPointerDown={(event) => {
                    event.stopPropagation();
                    onPointerDown?.(event);
                }}
                onClick={(event) => {
                    event.stopPropagation();
                    onClick?.(event);
                }}
                onKeyDown={(event) => {
                    // Enter and space activate the chip, so they stop short of the page's type-to-search key
                    // handler on the window.
                    if (event.key === "Enter" || event.key === " ") event.stopPropagation();
                    onKeyDown?.(event);
                }}
            />
        );
    },
);

// A value in a row that also names a filter. Clicking it narrows the list; holding it, or force clicking it on
// a Mac trackpad, hands the same filter to the command palette instead.
function FilterChip({
                        filterKey,
                        value,
                        onFilter,
                        children,
                    }: {
    filterKey: DeviceFilterKey;
    value: string;
    onFilter: (key: DeviceFilterKey, value: string, additive: boolean) => void;
    children: React.ReactNode;
}) {
    const filter = `${filterKey}:${value}`;
    // Shift adds to the current filters instead of replacing them. Activation carries no event, so the
    // modifier is read from the event ahead of it.
    const additive = useRef(false);
    const readModifier = (event: { shiftKey: boolean }) => {
        additive.current = event.shiftKey;
    };

    return (
        <Interactable
            component={ChipSpan}
            nested
            className="mm-filter-chip"
            data-peek-filter={filter}
            title={`Filter by ${DEVICE_FILTER_LABELS_INLINE[filterKey]} ${value}. Shift to add to the `
                + "current filters."}
            onClickCapture={readModifier}
            onKeyDownCapture={readModifier}
            onActivate={() => onFilter(filterKey, value, additive.current)}
            onPeek={() => openCommandPaletteWith(filter)}
        >
            {children}
        </Interactable>
    );
}

export default function DevicesPage() {
    const {token, isAdmin} = useAuth();
    const router = useRouter();

    const [devices, setDevices] = useState<Device[]>([]);
    const [total, setTotal] = useState(0);
    const [counts, setCounts] = useState({all: 0, enrolled: 0, unenrolled: 0, pending: 0});
    const [page, setPage] = useState(1);
    // One string holds the free text and every filter, in the same syntax the command palette accepts. The
    // tabs and the badges in a row all edit this rather than keeping their own state, and the history around
    // it makes a filter change undoable.
    const filterHistory = useFilterHistory("");
    const search = filterHistory.value;
    const setSearch = filterHistory.setValue;
    const searchInputRef = useRef<HTMLInputElement>(null);
    const tableBodyRef = useRef<HTMLTableSectionElement>(null);
    const [loading, setLoading] = useState(true);
    // Only the first load gets the skeleton, so a filter change does not swap readable rows back to placeholders.
    const [everLoaded, setEverLoaded] = useState(false);
    const {tagNames, colorOf, labelOf} = useTagRegistry();
    // Filter options describe the whole fleet, so group names come from groups.yaml and tags from the registry
    // rather than from the rows on the current page.
    const [configGroups, setConfigGroups] = useState<string[]>([]);

    // Add-placeholder modal
    const [addOpen, setAddOpen] = useState(false);
    // Hold a row, or force click it on a Mac trackpad, to look at a device without leaving the list.
    const [peekId, setPeekId] = useState<string | null>(null);
    const peek = usePeekGesture(setPeekId, (filter) => openCommandPaletteWith(filter));
    const [addSerial, setAddSerial] = useState("");
    const [addModel, setAddModel] = useState("");
    const [addGroups, setAddGroups] = useState<string[]>([]);
    const [adding, setAdding] = useState(false);

    // ?q= carries a filter query from the command palette. Read on every change rather than once on mount,
    // since the palette can send one while this page is already open, which does not remount it.
    const urlQuery = useSearchParams().get("q") ?? "";
    const appliedUrlQuery = useRef<string | null>(null);
    useEffect(() => {
        if (appliedUrlQuery.current === urlQuery) return;
        appliedUrlQuery.current = urlQuery;
        setSearch(urlQuery);
        setPage(1);
    }, [urlQuery, setSearch]);

    const [debounced] = useDebouncedValue(search, 300);

    // Last request wins, so a slow load answering after a newer one cannot put the previous filter's rows back.
    const reqSeq = useRef(0);

    const load = useCallback(async () => {
        if (!token) return;
        const seq = ++reqSeq.current;
        setLoading(true);
        try {
            const res = await api.listDevices(token, {
                skip: (page - 1) * PAGE_SIZE,
                limit: PAGE_SIZE,
                ...deviceQueryParams(debounced),
            });
            if (seq !== reqSeq.current) return; // superseded by a newer request
            setDevices(res.devices);
            setTotal(res.total);
            setCounts(res.counts);
            setEverLoaded(true);
        } catch (e: unknown) {
            if (seq === reqSeq.current) {
                notifications.show({color: "red", message: (e as Error).message});
            }
        } finally {
            if (seq === reqSeq.current) setLoading(false);
        }
    }, [token, page, debounced]);

    useEffect(() => {
        load();
    }, [load]);

    useEffect(() => {
        if (!token) return;
        api
            .getConfig(token, "groups")
            .then((g) => setConfigGroups((((g as { groups?: GroupDef[] })?.groups) ?? []).map((x) => x.name)))
            .catch(() => {
            });
    }, [token]);

    // Defined groups first, plus any group seen on the loaded page, since a device can carry a group that is no
    // longer in groups.yaml.
    const allGroups = Array.from(
        new Set([...configGroups, ...devices.flatMap((d) => d.groups)]),
    ).sort();
    // Registry tags first, plus any free-form tag seen on the loaded page. Labelled to match the row badges,
    // while the value stays the raw name the API filters on.
    const allTags = Array.from(
        new Set([...tagNames, ...devices.flatMap((d) => d.tags ?? [])]),
    )
        .sort()
        .map((t) => ({value: t, label: labelOf(t)}));

    // What the search box suggests for each attribute. Models and OS versions come from the loaded page, since
    // the fleet has no separate catalogue of either.
    const filterValues: FilterValueSource = {
        tag: allTags,
        group: allGroups,
        model: Array.from(new Set(devices.map((d) => d.device_model).filter(Boolean))).sort(),
        os: Array.from(new Set(devices.map((d) => d.os_version).filter(Boolean))).sort(),
    };

    const filtersActive = search.trim().length > 0;
    const clearFilters = () => {
        setSearch("");
        setPage(1);
    };

    const handleAdd = async () => {
        if (!token || !addSerial.trim()) return;
        setAdding(true);
        try {
            await api.createPlaceholderDevice(token, {
                serial_number: addSerial.trim(),
                device_model: addModel.trim() || undefined,
                groups: addGroups,
            });
            notifications.show({color: "teal", message: `Placeholder created for ${addSerial.trim()}`});
            setAddOpen(false);
            setAddSerial("");
            setAddModel("");
            setAddGroups([]);
            // Jump to the Pending tab to show the new placeholder and drop the other filters, since a placeholder
            // has no tags and only the groups just typed, and a leftover filter would hide the row.
            setPage(1);
            setSearch("state:pending");
        } catch (e) {
            notifications.show({color: "red", title: "Couldn't add device", message: (e as Error).message});
        } finally {
            setAdding(false);
        }
    };

    const stateFilter = parseDeviceQuery(search).filters.state ?? "all";

    // Every control that narrows the list goes through here, so one edit cannot strand another filter. A plain
    // click replaces the filters that are there; shift-click adds to them.
    const setFilter = (key: DeviceFilterKey, value: string | null, additive = false) => {
        setSearch((current) => {
            if (additive || !value) return withDeviceFilter(current, key, value);
            return formatDeviceQuery({filters: {[key]: value}, text: parseDeviceQuery(current).text});
        });
        setPage(1);
    };

    const focusFirstRow = useCallback(() => {
        tableBodyRef.current?.querySelector<HTMLElement>("tr[data-peek-id]")?.focus();
    }, []);

    // A printable key with nothing else focused goes to the search box, so typing narrows the list without
    // clicking into it first. An arrow key goes to the list, so it walks the rows rather than scrolling the
    // window past them, which is what it did when no row had focus yet.
    useEffect(() => {
        const onKeyDown = (event: KeyboardEvent) => {
            if (event.metaKey || event.ctrlKey || event.altKey) return;
            // Something nearer the key already dealt with it. The search box is the one that matters: it takes
            // the arrows to walk its own suggestions, and this would otherwise pull focus onto the table from
            // under the list the reader is choosing from.
            if (event.defaultPrevented) return;
            const active = document.activeElement as HTMLElement | null;
            const typing = Boolean(active) && (active!.tagName === "INPUT" || active!.tagName === "TEXTAREA"
                || active!.isContentEditable);

            if (event.key === "ArrowDown" || event.key === "ArrowUp") {
                // A row already has it, and its own handler is walking the list.
                if (active?.closest("tr[data-peek-id]")) return;
                // A field takes its own arrows, and the search box hands the list its down-arrow itself.
                if (typing) return;
                event.preventDefault();
                focusFirstRow();
                return;
            }

            if (event.key.length !== 1 || typing) return;
            searchInputRef.current?.focus();
        };
        window.addEventListener("keydown", onKeyDown);
        return () => window.removeEventListener("keydown", onKeyDown);
    }, [focusFirstRow]);

    const onRowKeyDown = (event: React.KeyboardEvent<HTMLTableRowElement>, device: Device) => {
        if (event.target !== event.currentTarget) return;
        const rows = Array.from(
            tableBodyRef.current?.querySelectorAll<HTMLElement>("tr[data-peek-id]") ?? [],
        );
        const here = rows.indexOf(event.currentTarget);

        if (event.key === "ArrowDown") {
            event.preventDefault();
            rows[Math.min(here + 1, rows.length - 1)]?.focus();
            return;
        }
        if (event.key === "ArrowUp") {
            event.preventDefault();
            if (here <= 0) searchInputRef.current?.focus();
            else rows[here - 1]?.focus();
            return;
        }
        if (event.key === " ") {
            // Space peeks, Enter opens. Without the default stopped, the page scrolls instead. Pressing it
            // again on the row being peeked puts the peek away, so the one key does both.
            event.preventDefault();
            setPeekId((current) => (current === device.id ? null : device.id));
            return;
        }
        if (event.key === "Enter") {
            event.preventDefault();
            router.push(`/devices/${device.id}`);
        }
    };

    const peekDevice = devices.find((d) => d.id === peekId) ?? null;

    const rows = devices.map((d) => {
        const active = d.enrollment_state === "enrolled";
        const recent = active && new Date(d.last_seen).getTime() > Date.now() - 7 * 86400000;
        // A check-in within the hour is worth a quiet green edge. Seven days is most of the fleet most of the
        // time, which would make the glow mean nothing.
        const justSeen = active && new Date(d.last_seen).getTime() > Date.now() - 3600000;
        return (
            <Table.Tr
                key={d.id}
                aria-label={`Open ${d.display_name || d.serial_number || "device"}`}
                role="button"
                tabIndex={0}
                onClick={peek.guardActivate(() => router.push(`/devices/${d.id}`))}
                onKeyDown={(e) => onRowKeyDown(e, d)}
                {...peek.rowProps(d.id)}
                // After the spread, since the gesture supplies a class of its own and this adds the tone to it.
                className={glassClassName({
                    material: "none",
                    interactive: true,
                    tone: justSeen ? "positive" : "neutral",
                })}
                style={{
                    cursor: "pointer",
                    opacity: active ? 1 : 0.6,
                    ...(justSeen ? glassToneStyle(0.4) : {}),
                }}
            >
                <Table.Td>
                    <Group gap={6} wrap="nowrap">
                        {d.management_type === "apple_mdm" && (
                            <Tooltip label="Apple MDM"><IconBrandApple size={15} style={{opacity: 0.6}}/></Tooltip>
                        )}
                        <div>
                            <Text fz="sm" fw={500}>{d.display_name || d.serial_number || "--"}</Text>
                            <Text fz="xs" c="dimmed">
                                {d.serial_number || (d.udid ? d.udid.slice(0, 8) + "…" : "not enrolled")}
                            </Text>
                        </div>
                    </Group>
                </Table.Td>
                <Table.Td>
                    <Badge
                        size="sm"
                        variant="light"
                        color={stateMeta(d.enrollment_state).color}
                        styles={NO_TRUNCATE_BADGE_STYLES}
                    >
                        {stateMeta(d.enrollment_state).label}
                    </Badge>
                </Table.Td>
                <Table.Td>
                    {d.device_model ? (
                        <FilterChip filterKey="model" value={d.device_model} onFilter={setFilter}>
                            <Text fz="sm">{d.device_model}</Text>
                        </FilterChip>
                    ) : (
                        <Text fz="sm">--</Text>
                    )}
                </Table.Td>
                <Table.Td>
                    {/* Plain text, like the Model column. In a Badge the padding and the label's ellipsis
              collapse this column to "1..." at 1280px wide. */}
                    {d.os_version ? (
                        <FilterChip filterKey="os" value={d.os_version} onFilter={setFilter}>
                            <Text fz="sm">{d.os_version}</Text>
                        </FilterChip>
                    ) : (
                        <Text fz="xs" c="dimmed">--</Text>
                    )}
                </Table.Td>
                <Table.Td>
                    <Group gap={4} wrap="wrap">
                        {d.groups.slice(0, 3).map((g) => (
                            <FilterChip key={g} filterKey="group" value={g} onFilter={setFilter}>
                                <Badge variant="dot" size="xs" color="blue" styles={NO_TRUNCATE_BADGE_STYLES}>
                                    {g}
                                </Badge>
                            </FilterChip>
                        ))}
                        {d.groups.length > 3 && (
                            <Badge variant="dot" size="xs" color="gray" styles={NO_TRUNCATE_BADGE_STYLES}>
                                +{d.groups.length - 3}
                            </Badge>
                        )}
                    </Group>
                </Table.Td>
                <Table.Td>
                    <Group gap={4} wrap="wrap">
                        {(d.tags ?? []).slice(0, 2).map((t) => (
                            <FilterChip key={t} filterKey="tag" value={t} onFilter={setFilter}>
                                <Badge
                                    variant="light"
                                    size="xs"
                                    color={colorOf(t) || "gray"}
                                    styles={NO_TRUNCATE_BADGE_STYLES}
                                >
                                    {labelOf(t)}
                                </Badge>
                            </FilterChip>
                        ))}
                        {(d.tags?.length ?? 0) > 2 && (
                            <Badge variant="light" size="xs" color="gray">+{(d.tags!.length) - 2}</Badge>
                        )}
                    </Group>
                </Table.Td>
                <Table.Td>
                    {active ? (
                        // Badge uppercases its label unless tt is set, which turns "8m ago" into "8M AGO"
                        // and reads as eight months.
                        <Badge
                            variant="light"
                            color={recent ? "teal" : "gray"}
                            size="sm"
                            tt="none"
                            styles={NO_TRUNCATE_BADGE_STYLES}
                        >
                            {timeSince(d.last_seen)}
                        </Badge>
                    ) : d.enrollment_state === "unenrolled" && d.unenrolled_at ? (
                        <Text fz="xs" c="dimmed">left {timeSince(d.unenrolled_at)}</Text>
                    ) : (
                        <Text fz="xs" c="dimmed">--</Text>
                    )}
                </Table.Td>
                <Table.Td>
                    <ActionIcon variant="subtle" color="gray" size="sm"><IconChevronRight size={14}/></ActionIcon>
                </Table.Td>
            </Table.Tr>
        );
    });

    const seg = (s: EnrollmentState | "all", label: string) => ({
        value: s,
        label: `${label} (${counts[s]})`,
    });

    return (
        <Stack gap="lg">
            <PageHeader actions={
                <Group gap="sm">
                    {isAdmin && (
                        <Button leftSection={<IconPlus size={14}/>} variant="light" onClick={() => setAddOpen(true)}>
                            Add device
                        </Button>
                    )}
                    <Button leftSection={<IconRefresh size={14}/>} variant="light" onClick={load}>
                        Refresh
                    </Button>
                </Group>
            }/>

            {/* The four tabs need about 373px and SegmentedControl clips its own overflow, so minWidth stops it
          shrinking below its labels and this box scrolls it on a narrow viewport. */}
            <Box style={{overflowX: "auto"}}>
                <SegmentedControl
                    fullWidth
                    value={stateFilter}
                    // Additive, since the tabs are a view over whatever is already filtered rather
                    // than a filter of their own.
                    onChange={(v) => setFilter("state", v === "all" ? null : v, true)}
                    style={{minWidth: "max-content"}}
                    data={[
                        seg("all", "All"),
                        seg("enrolled", "Enrolled"),
                        seg("unenrolled", "Unenrolled"),
                        seg("pending", "Pending"),
                    ]}
                />
            </Box>

            {/* One control across the page, with group and tag among the attributes it suggests. */}
            <Group gap="sm" wrap="nowrap">
                <DeviceSearchBar
                    value={search}
                    onChange={(next) => {
                        setSearch(next);
                        setPage(1);
                    }}
                    source={filterValues}
                    inputRef={searchInputRef}
                    onLeaveDown={focusFirstRow}
                    undo={filterHistory.undo}
                    redo={filterHistory.redo}
                    canUndo={filterHistory.canUndo}
                    canRedo={filterHistory.canRedo}
                />
            </Group>

            {loading && !everLoaded ? (
                <PageSkeleton variant="table"/>
            ) : devices.length === 0 ? (
                <Stack align="center" py="xl" gap="xs">
                    <IconDeviceDesktopOff size={28} style={{opacity: 0.4}}/>
                    {/* "No devices yet" is only true of an empty fleet; with filters on it would contradict the
              tab counts above. */}
                    <Text c="dimmed">
                        {counts.all === 0
                            ? "No devices yet."
                            : filtersActive
                                ? "No devices match these filters."
                                : "No devices to show."}
                    </Text>
                    {counts.all > 0 && filtersActive && (
                        <Button variant="subtle" size="xs" onClick={clearFilters}>
                            Clear filters
                        </Button>
                    )}
                </Stack>
            ) : (
                <>
                    {/* No ancestor up to body sets overflow-x, so without this the table's overflow drags the
              sidebar and header along instead of scrolling in place. */}
                    <Paper
                        withBorder
                        style={{
                            overflowX: "auto",
                            // A refetch dims the rows in place rather than replacing them.
                            opacity: loading ? 0.55 : 1,
                            transition: "opacity 140ms ease",
                        }}
                    >
                        {/* No highlightOnHover, since the rows carry their own hover wash and Mantine's grey
                            underneath it reads as a muddy overlay. */}
                        <Table withColumnBorders={false} verticalSpacing="sm">
                            <Table.Thead>
                                <Table.Tr>
                                    <Table.Th>Device</Table.Th>
                                    <Table.Th>State</Table.Th>
                                    <Table.Th>Model</Table.Th>
                                    <Table.Th>OS</Table.Th>
                                    <Table.Th>Groups</Table.Th>
                                    <Table.Th>Tags</Table.Th>
                                    <Table.Th>Activity</Table.Th>
                                    <Table.Th/>
                                </Table.Tr>
                            </Table.Thead>
                            <Table.Tbody ref={(node) => {
                                tableBodyRef.current = node;
                                (peek.containerRef as React.RefObject<HTMLElement | null>).current = node;
                            }}>
                                {rows}
                            </Table.Tbody>
                        </Table>
                    </Paper>

                    {total > PAGE_SIZE && (
                        <Pagination total={Math.ceil(total / PAGE_SIZE)} value={page} onChange={setPage}/>
                    )}
                </>
            )}

            <Modal opened={addOpen} onClose={() => setAddOpen(false)}
                   title={<Text fw={600}>Pre-provision a device</Text>}>
                <Stack gap="md">
                    <Text fz="sm" c="dimmed">
                        Register a device by serial number before it enrolls. Its group membership is
                        applied automatically when the physical device enrolls.
                    </Text>
                    <TextInput
                        label="Serial number"
                        placeholder="C02XY1234ABC"
                        required
                        value={addSerial}
                        onChange={(e) => setAddSerial(e.currentTarget.value)}
                        data-autofocus
                    />
                    <TextInput
                        label="Model (optional)"
                        placeholder="iPad Pro 12.9-inch"
                        value={addModel}
                        onChange={(e) => setAddModel(e.currentTarget.value)}
                    />
                    <TagsInput
                        label="Groups (optional)"
                        description="Pre-assign groups; membership is re-evaluated on enrollment."
                        placeholder="Type a group and press Enter"
                        data={allGroups}
                        value={addGroups}
                        onChange={setAddGroups}
                    />
                    <Group justify="flex-end">
                        <Button variant="subtle" color="gray" onClick={() => setAddOpen(false)}>Cancel</Button>
                        <Button loading={adding} disabled={!addSerial.trim()} onClick={handleAdd}>Add device</Button>
                    </Group>
                </Stack>
            </Modal>

            <DevicePeekModal
                device={peekDevice}
                opened={peekDevice !== null}
                onClose={() => setPeekId(null)}
                onOpenDevice={() => {
                    if (peekDevice) router.push(`/devices/${peekDevice.id}`);
                }}
                stateLabel={peekDevice ? stateMeta(peekDevice.enrollment_state).label : ""}
                stateColor={peekDevice ? stateMeta(peekDevice.enrollment_state).color : "gray"}
                tagLabel={labelOf}
                tagColor={colorOf}
            />
        </Stack>
    );
}
