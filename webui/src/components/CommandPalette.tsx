// The command palette, opened with mod+K or the Search row at the top of the sidebar. It merges three sources in
// the browser: pages from the static registry in lib/palette.ts, devices from the same debounced device search the
// devices page runs, and groups, profiles, apps and tags filtered in memory from the four config documents.

import {useCallback, useEffect, useMemo, useRef, useState} from "react";
import {useRouter} from "next/navigation";
import {Box, Group, Loader, Text, UnstyledButton} from "@mantine/core";
import {useDebouncedValue, useLocalStorage} from "@mantine/hooks";
import {createSpotlight, Spotlight, useSpotlight} from "@mantine/spotlight";
import {
    IconApps,
    IconDeviceLaptop,
    IconFileCertificate,
    IconFilter,
    IconSearch,
    IconStack2,
    IconTag,
} from "@tabler/icons-react";
import {api, type Device} from "../../lib/api";
import {useAuth} from "../../lib/auth-context";
import type {App, Group as GroupDef, Profile, TagDef} from "../../lib/config";
import {matchesQuery, paletteDestinations} from "../../lib/palette";
import {
    DEVICE_FILTER_KEYS,
    DEVICE_FILTER_LABELS,
    deviceQueryParams,
    formatDeviceQuery,
    parseDeviceQuery,
} from "../../lib/device-filter";
import {SHOW_YAML_STORAGE_KEY} from "../../lib/preferences";

// Its own store, not the package-level singleton, so this component can read the open flag and the selected index
// it repairs.
const [paletteStore, paletteActions] = createSpotlight();

// What the sidebar Search row calls. The @mantine/spotlight global spotlight drives a different store.
export const commandPalette = paletteActions;

// Handed over by openCommandPaletteWith and picked up when the palette next opens. The store has no public
// setter for the query, so the component controls it and reads this on the way in.
let pendingQuery: string | null = null;

/** Open the palette on a prepared query, which is how a filter chip hands one over. */
export function openCommandPaletteWith(query: string) {
    pendingQuery = query;
    paletteActions.open();
}

const ACTIONS_LIST_ID = "mm-palette-actions";
// Eight device rows is what fits without the list turning into the devices page.
const DEVICE_LIMIT = 8;
// A little tighter than the devices page (300 ms there), so the palette keeps up with typing.
const DEVICE_DEBOUNCE_MS = 250;
// Rows per config group. Past this, the entity's own page is the place to look.
const ENTITY_LIMIT = 6;
// How long loaded config documents are reused before the next open refetches. They are a few kB each and change
// only when an editor saves.
const ENTITY_TTL_MS = 60_000;

interface EntitySnapshot {
    groups: GroupDef[];
    apps: App[];
    profiles: Profile[];
    tags: TagDef[];
}

const EMPTY_ENTITIES: EntitySnapshot = {groups: [], apps: [], profiles: [], tags: []};

interface DeviceResults {
    // The trimmed query these rows answer. Rows are shown only when it matches the box, which also discards
    // out-of-order responses.
    query: string;
    devices: Device[];
    // The request failed, as opposed to running and matching nothing. The two render differently.
    failed?: boolean;
}

function exactSerialMatch(devices: Device[], query: string): Device | undefined {
    const q = query.trim().toLowerCase();
    if (!q) return undefined;
    return devices.find((d) => (d.serial_number ?? "").toLowerCase() === q);
}

// Identifying detail for one device on a single line: serial, model, enrollment state, minus whatever the row label
// already shows.
function deviceDescription(device: Device, label: string): string {
    const parts = [device.serial_number, device.device_model, device.enrollment_state];
    return parts
        .filter((p): p is string => !!p && p !== label)
        .join(", ");
}

export function CommandPalette() {
    const router = useRouter();
    const {token, isAdmin} = useAuth();
    const {opened} = useSpotlight(paletteStore);
    // Controlled, so a filter chip can open the palette with the query already written.
    const [query, setQuery] = useState("");

    useEffect(() => {
        if (!opened) return;
        if (pendingQuery === null) return;
        setQuery(pendingQuery);
        pendingQuery = null;
    }, [opened]);
    const [showYaml] = useLocalStorage({key: SHOW_YAML_STORAGE_KEY, defaultValue: false});

    const [entities, setEntities] = useState<EntitySnapshot>(EMPTY_ENTITIES);
    const [entitiesReady, setEntitiesReady] = useState(false);
    const [deviceResults, setDeviceResults] = useState<DeviceResults | null>(null);
    const [deviceLoading, setDeviceLoading] = useState(false);

    const entitiesFetchedAt = useRef(0);
    const entitiesInFlight = useRef(false);
    const enterLookup = useRef(false);
    // Query whose rows must not be auto-selected. Set when an Enter lookup comes back without the device the scan
    // named, and cleared by typing anything else.
    const noAutoSelectFor = useRef<string | null>(null);

    const q = query.trim();
    // Debounce the term the palette is showing. Closing it drops the term at once, so reopening does not search for
    // whatever was typed last time.
    const [debouncedQuery] = useDebouncedValue(opened ? q : "", DEVICE_DEBOUNCE_MS);

    //  Config documents

    const loadEntities = useCallback(async () => {
        if (!token || entitiesInFlight.current) return;
        if (entitiesReady && Date.now() - entitiesFetchedAt.current < ENTITY_TTL_MS) return;
        entitiesInFlight.current = true;
        // A config file that does not exist yet is a 404, which reads as an empty list rather than an error worth
        // a notification.
        const read = async <T, >(type: "groups" | "apps" | "profiles" | "tags", key: string): Promise<T[]> => {
            try {
                const res = (await api.getConfig(token, type)) as Record<string, unknown> | null;
                const list = res?.[key];
                return Array.isArray(list) ? (list as T[]) : [];
            } catch {
                return [];
            }
        };
        try {
            const [groups, apps, profiles, tags] = await Promise.all([
                read<GroupDef>("groups", "groups"),
                read<App>("apps", "apps"),
                read<Profile>("profiles", "profiles"),
                read<TagDef>("tags", "tags"),
            ]);
            setEntities({groups, apps, profiles, tags});
            entitiesFetchedAt.current = Date.now();
            setEntitiesReady(true);
        } finally {
            entitiesInFlight.current = false;
        }
    }, [token, entitiesReady]);

    //  Devices

    useEffect(() => {
        if (!opened || !token || !debouncedQuery) {
            setDeviceLoading(false);
            return;
        }
        let cancelled = false;
        setDeviceLoading(true);
        api
            // The same filter syntax the devices page takes, so "tag:quarantine" narrows these rows too.
            .listDevices(token, {...deviceQueryParams(debouncedQuery), limit: DEVICE_LIMIT})
            .then((res) => {
                if (!cancelled) setDeviceResults({query: debouncedQuery, devices: res.devices});
            })
            .catch(() => {
                if (!cancelled) {
                    setDeviceResults({query: debouncedQuery, devices: [], failed: true});
                }
            })
            .finally(() => {
                if (!cancelled) setDeviceLoading(false);
            });
        return () => {
            cancelled = true;
        };
    }, [opened, token, debouncedQuery]);

    //  Rows

    const destinations = useMemo(
        () => paletteDestinations({isAdmin, showYaml}),
        [isAdmin, showYaml],
    );

    const pageMatches = useMemo(
        () => destinations.filter((d) => matchesQuery(q, d.label, d.description, d.keywords)),
        [destinations, q],
    );

    // A query carrying tag:, group:, model:, os: or state: can be handed to the devices page whole.
    const deviceFilters = useMemo(() => parseDeviceQuery(q).filters, [q]);
    const filterKeys = DEVICE_FILTER_KEYS.filter((key) => deviceFilters[key]);
    const filterSummary = filterKeys
        .map((key) => `${DEVICE_FILTER_LABELS[key]} ${deviceFilters[key]}`)
        .join(", ");

    const devicesSettled = !!deviceResults && deviceResults.query === q;
    const found = q && devicesSettled ? deviceResults.devices : [];
    const serialHit = exactSerialMatch(found, q);
    const devices = serialHit ? [serialHit, ...found.filter((d) => d.id !== serialHit.id)] : found;

    const groupMatches = useMemo(
        () =>
            q
                ? entities.groups
                    .filter((g) => matchesQuery(q, g.name, g.description))
                    .slice(0, ENTITY_LIMIT)
                : [],
        [entities.groups, q],
    );
    const profileMatches = useMemo(
        () =>
            q
                ? entities.profiles
                    .filter((p) => matchesQuery(q, p.name, p.id, p.description, p.payload_type))
                    .slice(0, ENTITY_LIMIT)
                : [],
        [entities.profiles, q],
    );
    const appMatches = useMemo(
        () =>
            q
                ? entities.apps
                    .filter((a) => matchesQuery(q, a.name, a.id, a.bundle_id))
                    .slice(0, ENTITY_LIMIT)
                : [],
        [entities.apps, q],
    );
    const tagMatches = useMemo(
        () =>
            q
                ? entities.tags
                    .filter((t) => matchesQuery(q, t.name, t.label, t.description))
                    .slice(0, ENTITY_LIMIT)
                : [],
        [entities.tags, q],
    );

    const rowCount =
        pageMatches.length +
        devices.length +
        groupMatches.length +
        profileMatches.length +
        appMatches.length +
        tagMatches.length;

    // Nothing counts as not found until every source has answered for this query, or the empty state flashes while
    // the device search and the config documents are still pending. Without a token neither can answer, so fall back
    // to the pages, which need no server.
    const settled = !q || !token || (devicesSettled && entitiesReady);
    const busy = !!q && (!settled || deviceLoading);
    // Reported even when pages or config entities matched, since a short list does not show that device rows are
    // missing.
    const deviceSearchFailed = devicesSettled && !!deviceResults?.failed;

    const go = useCallback(
        (href: string) => {
            router.push(href);
        },
        [router],
    );

    //  Selection repair

    const clearSelection = () => {
        document
            .getElementById(ACTIONS_LIST_ID)
            ?.querySelector("[data-selected]")
            ?.removeAttribute("data-selected");
    };

    useEffect(() => {
        if (!opened || !q || noAutoSelectFor.current === q) return;
        const list = document.getElementById(ACTIONS_LIST_ID);
        if (!list || list.querySelector("[data-selected]")) return;
        const first = list.querySelector("[data-action]");
        if (!first) return;
        first.setAttribute("data-selected", "true");
        paletteStore.updateState((s) => ({...s, selected: 0}));
    });

    //  Enter before the device search has caught up

    // A barcode scanner sends Enter inside the debounce window, before the matching row exists. This runs only
    // then, since Enter belongs to a page or config entity row whenever one already matches.
    const openFilteredDevices = () => {
        const query = formatDeviceQuery({filters: deviceFilters, text: parseDeviceQuery(q).text});
        go(`/devices?q=${encodeURIComponent(query)}`);
    };

    const handleSearchKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
        // ArrowUp from the top of the list, or from the box with nothing selected, opens the filter bar rather
        // than wrapping the selection round to the last row.
        if (event.key === "ArrowUp" && filterKeys.length > 0) {
            const list = document.getElementById(ACTIONS_LIST_ID);
            const selected = list?.querySelector("[data-selected]");
            const first = list?.querySelector("[data-action]");
            if (!selected || selected === first) {
                event.preventDefault();
                openFilteredDevices();
                return;
            }
        }

        // This handler runs before Spotlight's own, and so before its composition guard, where an IME commit would
        // otherwise read as Enter.
        if (event.key !== "Enter" || event.nativeEvent.isComposing) return;
        if (!token || !q || rowCount > 0 || devicesSettled || enterLookup.current) return;
        enterLookup.current = true;
        clearSelection();
        setDeviceLoading(true);
        // The palette can be closed or retyped while this request is still pending. Adopting the answer then would
        // navigate after an Escape, or roll the results back to an older query with nothing left to re-trigger the
        // debounced search.
        const stale = () => {
            const state = paletteStore.getState();
            return !state.opened || state.query.trim() !== q;
        };
        api
            .listDevices(token, {search: q, limit: DEVICE_LIMIT})
            .then((res) => {
                if (stale()) return;
                const hit = exactSerialMatch(res.devices, q);
                // Enter auto-repeats when held, and a scanner can send more than one. With no exact match, leave
                // the list unselected so a repeat does not open whichever row happens to come back first.
                if (!hit) noAutoSelectFor.current = q;
                setDeviceResults({query: q, devices: res.devices});
                if (hit) {
                    paletteActions.close();
                    go(`/devices/${hit.id}`);
                }
            })
            .catch(() => {
                if (stale()) return;
                noAutoSelectFor.current = q;
                setDeviceResults({query: q, devices: [], failed: true});
            })
            .finally(() => {
                enterLookup.current = false;
                setDeviceLoading(false);
            });
    };

    return (
        <Spotlight.Root
            store={paletteStore}
            query={query}
            onQueryChange={setQuery}
            tagsToIgnore={["TEXTAREA"]}
            scrollable
            maxHeight={420}
            classNames={{
                inner: "mm-palette-inner",
                overlay: "mm-palette-overlay",
                content: "mm-palette-content mm-glass-surface",
                search: "mm-palette-search mm-glass-input",
            }}
            transitionProps={{
                transition: "pop",
                duration: 220,
                timingFunction: "cubic-bezier(0.16, 1, 0.3, 1)",
            }}
            onSpotlightOpen={() => {
                setDeviceResults(null);
                noAutoSelectFor.current = null;
                loadEntities();
            }}
        >
            <Spotlight.Search
                placeholder="Search devices, groups, profiles, apps and pages"
                leftSection={<IconSearch size={18} stroke={1.5}/>}
                // Fixed width whether or not the loader is there, so the box does not twitch on every keystroke.
                rightSection={<Box w={20}>{busy ? <Loader size="xs"/> : null}</Box>}
                onKeyDown={handleSearchKeyDown}
            />

            {/* Sits between the box and the results rather than at the top of them, so ArrowDown still walks
              straight into the devices and ArrowUp from the first one reaches this. */}
            <Box className={`mm-palette-filterbar${filterKeys.length > 0 ? " mm-palette-filterbar-open" : ""}`}>
                <UnstyledButton
                    className="mm-palette-filterbar-button"
                    tabIndex={-1}
                    onClick={openFilteredDevices}
                >
                    <Group gap="xs" wrap="nowrap">
                        <IconFilter size={16} stroke={1.5}/>
                        <Text fz="sm" fw={500}>Open in Devices</Text>
                        <Text fz="xs" c="dimmed" truncate>{filterSummary}</Text>
                    </Group>
                    <Text fz="xs" c="dimmed" style={{flexShrink: 0}}>up arrow</Text>
                </UnstyledButton>
            </Box>

            <Spotlight.ActionsList id={ACTIONS_LIST_ID}>
                {serialHit && (
                    <Spotlight.ActionsGroup label="Devices">
                        {devices.map((d) => (
                            <DeviceAction key={d.id} device={d} onSelect={go}/>
                        ))}
                    </Spotlight.ActionsGroup>
                )}

                {pageMatches.length > 0 && (
                    <Spotlight.ActionsGroup label="Pages">
                        {pageMatches.map((d) => (
                            <Spotlight.Action
                                key={d.id}
                                label={d.label}
                                description={d.description}
                                leftSection={<d.icon size={18} stroke={1.5}/>}
                                onClick={() => go(d.href)}
                            />
                        ))}
                    </Spotlight.ActionsGroup>
                )}

                {!serialHit && devices.length > 0 && (
                    <Spotlight.ActionsGroup label="Devices">
                        {devices.map((d) => (
                            <DeviceAction key={d.id} device={d} onSelect={go}/>
                        ))}
                    </Spotlight.ActionsGroup>
                )}

                {groupMatches.length > 0 && (
                    <Spotlight.ActionsGroup label="Groups">
                        {groupMatches.map((g) => (
                            <Spotlight.Action
                                key={g.name}
                                label={g.name}
                                description={g.description}
                                leftSection={<IconStack2 size={18} stroke={1.5}/>}
                                onClick={() => go("/groups")}
                            />
                        ))}
                    </Spotlight.ActionsGroup>
                )}

                {profileMatches.length > 0 && (
                    <Spotlight.ActionsGroup label="Profiles">
                        {profileMatches.map((p) => (
                            <Spotlight.Action
                                key={p.id}
                                label={p.name || p.id}
                                description={p.description || p.id}
                                leftSection={<IconFileCertificate size={18} stroke={1.5}/>}
                                onClick={() => go(`/profiles/${encodeURIComponent(p.id)}`)}
                            />
                        ))}
                    </Spotlight.ActionsGroup>
                )}

                {appMatches.length > 0 && (
                    <Spotlight.ActionsGroup label="Apps">
                        {appMatches.map((a) => (
                            <Spotlight.Action
                                key={a.id}
                                label={a.name || a.id}
                                description={a.bundle_id}
                                leftSection={<IconApps size={18} stroke={1.5}/>}
                                onClick={() => go("/apps")}
                            />
                        ))}
                    </Spotlight.ActionsGroup>
                )}

                {tagMatches.length > 0 && (
                    <Spotlight.ActionsGroup label="Tags">
                        {tagMatches.map((t) => (
                            <Spotlight.Action
                                key={t.name}
                                label={t.label || t.name}
                                description={t.description || t.name}
                                leftSection={<IconTag size={18} stroke={1.5}/>}
                                onClick={() => go("/settings")}
                            />
                        ))}
                    </Spotlight.ActionsGroup>
                )}

                {deviceSearchFailed && (
                    <Box px="md" py="xs">
                        <Text fz="sm" c="dimmed">
                            Device search did not answer, so matching devices are missing from this list.
                            Everything else was searched.
                        </Text>
                    </Box>
                )}

                {q.length > 0 && settled && rowCount === 0 && !deviceSearchFailed && (
                    <Spotlight.Empty>Nothing matches that.</Spotlight.Empty>
                )}
            </Spotlight.ActionsList>
        </Spotlight.Root>
    );
}

function DeviceAction({device, onSelect}: { device: Device; onSelect: (href: string) => void }) {
    const label = device.display_name || device.serial_number || device.udid || "Device";
    return (
        <Spotlight.Action
            label={label}
            description={deviceDescription(device, label)}
            leftSection={<IconDeviceLaptop size={18} stroke={1.5}/>}
            onClick={() => onSelect(`/devices/${device.id}`)}
        />
    );
}
