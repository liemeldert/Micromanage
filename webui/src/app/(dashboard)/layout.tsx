"use client";

import {useEffect, useMemo, useState} from "react";
import Link from "next/link";
import {usePathname, useRouter} from "next/navigation";
import {
    ActionIcon,
    AppShell,
    Avatar,
    Box,
    Burger,
    Collapse,
    Group,
    ScrollArea,
    Text,
    UnstyledButton,
    useMantineColorScheme,
} from "@mantine/core";
import {useDisclosure, useLocalStorage} from "@mantine/hooks";
import {IconChevronRight, IconLogout, IconMoon, IconSearch, IconSun} from "@tabler/icons-react";
import {useAuth} from "../../../lib/auth-context";
import {SHOW_YAML_STORAGE_KEY} from "../../../lib/preferences";
import {activeHref, NAV_GROUPS, type PaletteDestination, sidebarTree} from "../../../lib/palette";
import {glassClassName} from "@/components/ui/glass";
import {CommandPalette, commandPalette} from "@/components/CommandPalette";

const BRAND_GRADIENT: React.CSSProperties = {
    background: "linear-gradient(to left, #7928CA, #FF0080)",
    WebkitBackgroundClip: "text",
    WebkitTextFillColor: "transparent",
    backgroundClip: "text",
};

// default to folded open, I guess for now since we don't have many nav elements.
// In the future, I think we will add another nav bar along top or bottom
const OPEN_GROUPS_KEY = "mm-nav-open-groups-2";
const ALL_GROUPS = Object.keys(NAV_GROUPS);

// Exact matches only: /atc is the flow canvas, but /atc/runs under it is an ordinary list page.
const FULL_BLEED_ROUTES = ["/atc"];

export default function DashboardLayout({children}: { children: React.ReactNode }) {
    const {isAuthenticated, hydrated, email, isAdmin, logout} = useAuth();
    const router = useRouter();
    const pathname = usePathname();
    // Canvas pages run to the edges. A margin around a workspace only shrinks the workspace.
    const fullBleed = FULL_BLEED_ROUTES.includes(pathname);
    const [opened, {toggle, close}] = useDisclosure();
    const {colorScheme, toggleColorScheme} = useMantineColorScheme();
    const [showYaml] = useLocalStorage({key: SHOW_YAML_STORAGE_KEY, defaultValue: false});
    const [openGroups, setOpenGroups] = useLocalStorage<string[]>({
        key: OPEN_GROUPS_KEY,
        defaultValue: ALL_GROUPS,
        getInitialValueInEffect: true,
    });
    // Read after mount: the shortcut label depends on the platform, and deciding
    // it during render would make the server and client markup disagree.
    const [modLabel, setModLabel] = useState("Ctrl K");

    // Nav and command palette read the same table in lib/palette.ts, sections included, so nothing
    // here decides what goes where.
    const tree = useMemo(() => sidebarTree({isAdmin, showYaml}), [isAdmin, showYaml]);
    // Matched against the unfiltered table, so a page hidden by role highlights nothing rather than
    // highlighting the wrong row.
    const here = useMemo(() => {
        const full = sidebarTree({isAdmin: true, showYaml});
        return activeHref(
            pathname,
            full.flatMap((e) => (e.kind === "item" ? [e.item.href] : e.items.map((i) => i.href))),
        );
    }, [pathname, showYaml]);
    const hereGroup = useMemo(() => {
        for (const entry of tree) {
            if (entry.kind === "group" && entry.items.some((i) => i.href === here)) {
                return entry.group.id;
            }
        }
        return null;
    }, [tree, here]);

    useEffect(() => {
        const ua = typeof navigator === "undefined" ? "" : navigator.userAgent;
        if (/Mac|iPad|iPhone|iPod/.test(ua)) setModLabel("⌘ K");
    }, []);

    // Arriving at a page expands its section; while you stay there the header still folds it. Keyed
    // on the pathname so every navigation re-expands, including between two pages of one section.
    useEffect(() => {
        if (!hereGroup) return;
        setOpenGroups((prev) => (prev.includes(hereGroup) ? prev : [...prev, hereGroup]));
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [pathname, hereGroup]);

    useEffect(() => {
        // Wait until persisted auth is restored before deciding to redirect,
        // otherwise a page refresh bounces a logged-in user to /login.
        if (hydrated && !isAuthenticated) router.replace("/login");
    }, [hydrated, isAuthenticated, router]);

    if (!hydrated || !isAuthenticated) return null;

    const toggleGroup = (id: string) =>
        setOpenGroups((prev) => (prev.includes(id) ? prev.filter((g) => g !== id) : [...prev, id]));

    return (
        <>
            {/* Mounted inside the authed shell so it can use the session token. */}
            <CommandPalette/>
            <AppShell
                // Height 0 from sm up so the bar takes no space on desktop, where the
                // navbar is always open and there is nothing for it to do.
                header={{height: {base: 56, sm: 0}}}
                navbar={{width: 248, breakpoint: "sm", collapsed: {mobile: !opened}}}
                padding={0}
            >
                {/*  Header: the only way to reach the nav once it collapses  */}
                <AppShell.Header hiddenFrom="sm" className="mm-nav-surface">
                    <Group h="100%" px="md" gap="sm">
                        <Burger
                            opened={opened}
                            onClick={toggle}
                            size="sm"
                            color="white"
                            aria-label="Toggle navigation"
                        />
                        <Text fw={700} fz="lg" style={BRAND_GRADIENT}>
                            Micromanage
                        </Text>
                    </Group>
                </AppShell.Header>

                {/*  Navbar  */}
                <AppShell.Navbar className="mm-nav-surface">
                    <AppShell.Section px="md" py="lg" visibleFrom="sm">
                        <Text fw={700} fz="lg" style={BRAND_GRADIENT}>
                            Micromanage
                        </Text>
                    </AppShell.Section>

                    <AppShell.Section px="xs" pb="xs">
                        <UnstyledButton
                            className={glassClassName({
                                material: "none", interactive: true, lift: "quiet", className: "mm-nav-search",
                            })}
                            onClick={() => {
                                close();
                                commandPalette.open();
                            }}
                        >
                            <IconSearch size={16}/>
                            <Text fz="sm" style={{flex: 1}}>
                                Search
                            </Text>
                            <Text component="span" fz={11} className="mm-nav-kbd" visibleFrom="sm">
                                {modLabel}
                            </Text>
                        </UnstyledButton>
                    </AppShell.Section>

                    <AppShell.Section grow component={ScrollArea} type="auto" px="xs" pb="xs">
                        {tree.map((entry) => {
                            if (entry.kind === "item") {
                                return (
                                    <NavItem
                                        key={entry.item.href}
                                        destination={entry.item}
                                        active={here === entry.item.href}
                                        onNavigate={close}
                                    />
                                );
                            }
                            const holdsHere = entry.items.some((i) => i.href === here);
                            const expanded = openGroups.includes(entry.group.id);
                            return (
                                <Box key={entry.group.id} mb={2}>
                                    <UnstyledButton
                                        className={glassClassName({
                                            material: "none", interactive: true, lift: "quiet",
                                            className: "mm-nav-link mm-nav-group",
                                        })}
                                        onClick={() => toggleGroup(entry.group.id)}
                                        aria-expanded={expanded}
                                        // A closed section holding the current page is
                                        // the only row left that can say where you are.
                                        data-holds-here={holdsHere && !expanded ? true : undefined}
                                    >
                                        <entry.group.icon size={18} className="mm-nav-icon"/>
                                        <Text fz="sm" style={{flex: 1}}>
                                            {entry.group.label}
                                        </Text>
                                        <IconChevronRight
                                            size={14}
                                            className="mm-nav-chevron"
                                            data-expanded={expanded ? true : undefined}
                                        />
                                    </UnstyledButton>
                                    <Collapse expanded={expanded}>
                                        <Box className="mm-nav-children">
                                            {entry.items.map((item) => (
                                                <NavItem
                                                    key={item.href}
                                                    destination={item}
                                                    active={here === item.href}
                                                    onNavigate={close}
                                                    child
                                                />
                                            ))}
                                        </Box>
                                    </Collapse>
                                </Box>
                            );
                        })}
                    </AppShell.Section>

                    <AppShell.Section p="sm" className="mm-nav-footer">
                        <Group justify="space-between" wrap="nowrap">
                            <Group gap="xs" wrap="nowrap" style={{minWidth: 0}}>
                                <Avatar size="sm" color="blue" radius="xl">
                                    {(email ?? "?")[0].toUpperCase()}
                                </Avatar>
                                <Text fz="xs" c="dark.2" truncate maw={110}>
                                    {email}
                                </Text>
                            </Group>
                            <Group gap={4} wrap="nowrap">
                                <ActionIcon
                                    variant="subtle"
                                    color="gray"
                                    size="sm"
                                    onClick={() => toggleColorScheme()}
                                    title="Toggle color scheme"
                                >
                                    {colorScheme === "dark" ? <IconSun size={14}/> : <IconMoon size={14}/>}
                                </ActionIcon>
                                <ActionIcon
                                    variant="subtle"
                                    color="red"
                                    size="sm"
                                    onClick={() => {
                                        logout();
                                        router.push("/login");
                                    }}
                                    title="Sign out"
                                >
                                    <IconLogout size={14}/>
                                </ActionIcon>
                            </Group>
                        </Group>
                    </AppShell.Section>
                </AppShell.Navbar>

                {/*  Main  */}
                <AppShell.Main>
                    <Box p={fullBleed ? 0 : "lg"} style={{minHeight: "100vh"}}>
                        {children}
                    </Box>
                </AppShell.Main>
            </AppShell>
        </>
    );
}

function NavItem({
                     destination,
                     active,
                     onNavigate,
                     child,
                 }: {
    destination: PaletteDestination;
    active: boolean;
    onNavigate: () => void;
    child?: boolean;
}) {
    return (
        // A real <a href>: cmd-click / middle-click / "open in new tab" all work,
        // and the destination shows in the status bar.
        <Link
            href={destination.href}
            className={glassClassName({
                material: "none", interactive: true, lift: "quiet", className: "mm-nav-link",
            })}
            data-active={active ? true : undefined}
            data-child={child ? true : undefined}
            // On a phone the navbar is an overlay: leaving it open would cover the
            // page it just navigated to.
            onClick={onNavigate}
        >
            <destination.icon size={child ? 16 : 18} className="mm-nav-icon"/>
            <Text fz={child ? 13 : 14} lh={1.25}>
                {destination.navLabel ?? destination.label}
            </Text>
        </Link>
    );
}
