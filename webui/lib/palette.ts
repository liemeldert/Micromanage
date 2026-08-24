// Every destination in the app, in one table. The sidebar renders the entries flagged sidebar
// and the command palette offers all of them, so a page added here shows up in both.

import type {TablerIcon} from "@tabler/icons-react";
import {
    IconActivityHeartbeat,
    IconAdjustmentsHorizontal,
    IconApps,
    IconBuildingStore,
    IconClipboardList,
    IconDeviceLaptop,
    IconDeviceMobileShare,
    IconDevices,
    IconFileCertificate,
    IconFileCode,
    IconFileDescription,
    IconHistory,
    IconLayoutDashboard,
    IconListCheck,
    IconListDetails,
    IconPackages,
    IconSettings,
    IconShieldCheck,
    IconSitemap,
    IconStack2,
    IconTag,
    IconTopologyStar3,
    IconUsers,
    IconVectorBezier2,
} from "@tabler/icons-react";

/** Collapsible sidebar sections. A group has no page of its own and the palette never offers
 * one; membership and order come from the destination table below. */
export type NavGroupId = "devices" | "deployment" | "automation" | "compliance" | "admin";

export interface NavGroup {
    id: NavGroupId;
    label: string;
    icon: TablerIcon;
}

// Every icon here and in the table below is used once. Repeated glyphs stop being useful for
// scanning the nav.
export const NAV_GROUPS: Record<NavGroupId, NavGroup> = {
    devices: {id: "devices", label: "Devices", icon: IconDeviceLaptop},
    deployment: {id: "deployment", label: "Library", icon: IconPackages},
    automation: {id: "automation", label: "Flows", icon: IconSitemap},
    compliance: {id: "compliance", label: "Compliance", icon: IconShieldCheck},
    admin: {id: "admin", label: "Settings", icon: IconSettings},
};

export interface PaletteDestination {
    // Stable key, also the React key and the Spotlight action id.
    id: string;
    label: string;
    href: string;
    icon: TablerIcon;
    // The sidebar section this page belongs to. Ungrouped pages sit at the top
    // level of the nav, in table order.
    group?: NavGroupId;
    // Sidebar label for when the group already names the subject: "Flows > Editor" rather than
    // "Flows > Flows". The palette keeps the full label, where the entry stands alone.
    navLabel?: string;
    // One short line under the label in the palette. Not shown in the sidebar.
    description?: string;
    // Extra search terms: old names, acronyms, and words the label does not contain.
    keywords?: string[];
    // Rendered in the sidebar nav. Entries without it are reached from another page's content
    // or from the palette.
    sidebar?: boolean;
    // The page refuses non-admins, so neither the sidebar nor the palette offers it to them.
    // Hidden rather than greyed out.
    adminOnly?: boolean;
    // Only reachable when the raw YAML view is switched on in Settings. The palette honours the
    // same switch as the sidebar, so it is not a way around it.
    requiresYaml?: boolean;
}

// Sidebar entries come first, in sidebar order, so the nav is a filter with no re-sorting.
// The palette shows them in the same order.
export const PALETTE_DESTINATIONS: PaletteDestination[] = [
    {
        id: "dashboard",
        label: "Dashboard",
        href: "/dashboard",
        icon: IconLayoutDashboard,
        description: "Fleet overview",
        keywords: ["home", "overview", "summary"],
        sidebar: true,
    },
    {
        id: "devices",
        label: "Devices",
        navLabel: "All devices",
        href: "/devices",
        icon: IconDevices,
        group: "devices",
        description: "Every device, with filters",
        keywords: ["hardware", "mac", "ipad", "iphone", "inventory", "fleet"],
        sidebar: true,
    },
    {
        id: "enrollment",
        label: "Enrollment",
        // "Devices > Enrollment" next to "Automated Enrollment" reads as the same thing twice.
        // The palette keeps the short name, where the description does the work.
        navLabel: "Manual enrollment",
        href: "/enrollment",
        icon: IconDeviceMobileShare,
        group: "devices",
        description: "Manual enrollment profiles and QR codes",
        keywords: ["enroll", "ota", "manual", "qr", "onboard"],
        sidebar: true,
    },
    {
        // Distinct from "Enrollment" above, which is the manual profile-install flow. This one is
        // Apple Business/School Manager zero-touch provisioning.
        id: "dep",
        label: "Automated Enrollment",
        href: "/dep",
        icon: IconBuildingStore,
        group: "devices",
        description: "Apple Business and School Manager, zero touch",
        keywords: ["dep", "ade", "abm", "asm", "automated device enrollment", "zero touch",
            "apple business manager", "apple school manager"],
        sidebar: true,
        adminOnly: true,
    },
    {
        id: "groups",
        label: "Groups",
        href: "/groups",
        icon: IconStack2,
        group: "devices",
        description: "Rules that decide which devices belong together",
        keywords: ["group", "membership", "scope", "cohort"],
        sidebar: true,
    },
    {
        id: "apps",
        label: "Apps",
        href: "/apps",
        icon: IconApps,
        group: "deployment",
        description: "Application packages and their versions",
        keywords: ["app", "software", "package", "install", "pkg"],
        sidebar: true,
    },
    {
        id: "profiles",
        label: "Profiles",
        href: "/profiles",
        icon: IconFileCertificate,
        group: "deployment",
        description: "Configuration profiles",
        keywords: ["profile", "mobileconfig", "payload", "restriction", "wifi"],
        sidebar: true,
    },
    {
        id: "declarations",
        label: "Declarations",
        href: "/declarations",
        icon: IconFileDescription,
        group: "deployment",
        description: "Declarative device management",
        keywords: ["ddm", "declarative", "declaration", "activation"],
        sidebar: true,
    },
    {
        id: "flows-overview",
        label: "Flow Overview",
        navLabel: "Overview",
        href: "/atc/overview",
        icon: IconTopologyStar3,
        group: "automation",
        description: "Every flow, what starts it, and how often it has run",
        keywords: ["atc", "flows", "overview", "automation", "list", "cards"],
        sidebar: true,
    },
    {
        // The product names (ATC, Dispatcher) are introduced on their own pages, next to what
        // they do. The nav uses the plain word.
        id: "flows",
        label: "Flows",
        navLabel: "Editor",
        href: "/atc",
        icon: IconVectorBezier2,
        group: "automation",
        description: "Automation flows and rules",
        keywords: ["atc", "automation", "dispatcher", "workflow", "rules", "trigger"],
        sidebar: true,
    },
    {
        id: "compliance",
        label: "Compliance",
        navLabel: "Alerts",
        href: "/compliance",
        icon: IconActivityHeartbeat,
        group: "compliance",
        description: "Where the fleet has drifted from what the rules ask for",
        keywords: ["alert", "alerts", "drift", "posture", "check", "compliant", "dispatcher"],
        sidebar: true,
    },
    {
        // The dispatcher's two views are two pages, so each one is a destination.
        id: "compliance-rules",
        label: "Compliance rules",
        navLabel: "Rules",
        href: "/compliance/rules",
        icon: IconListDetails,
        description: "What counts as a deviation, and what to do about it",
        keywords: ["rule", "dispatcher", "severity", "remediation", "webhook", "check"],
        sidebar: true,
        group: "compliance",
    },
    {
        id: "tasks",
        label: "System tasks",
        href: "/settings/tasks",
        icon: IconListCheck,
        description: "Queued and completed work",
        keywords: ["queue", "job", "command", "history", "failed", "tasks"],
        sidebar: true,
        group: "admin",
    },
    {
        // Shown only when enabled in Settings, Interface.
        id: "yaml",
        label: "YAML",
        href: "/yaml",
        icon: IconFileCode,
        description: "Raw configuration files",
        keywords: ["raw", "config", "text", "editor", "source"],
        sidebar: true,
        requiresYaml: true,
    },
    {
        id: "settings",
        label: "Settings",
        navLabel: "General",
        href: "/settings",
        icon: IconAdjustmentsHorizontal,
        group: "admin",
        description: "Tenant, interface and account settings",
        keywords: ["preferences", "config", "options", "admin"],
        sidebar: true,
    },

    // Pages and sections with no sidebar entry, found by name in the palette.
    {
        id: "flow-runs",
        label: "Flow runs",
        navLabel: "Run history",
        href: "/atc/runs",
        icon: IconHistory,
        description: "Flow run history for the whole fleet",
        keywords: ["atc", "runs", "executions", "history", "automation"],
        sidebar: true,
        group: "automation",
    },
    {
        id: "audit-log",
        label: "Audit log",
        href: "/settings/audit-log",
        icon: IconClipboardList,
        description: "Who changed what, and when",
        keywords: ["audit", "log", "trail", "changes", "who", "security"],
        sidebar: true,
        group: "admin",
        adminOnly: true,
    },
    {
        // A section of the Settings page rather than a page of its own, so the link points at
        // Settings. Listed separately because "tags" is the term that gets searched for.
        id: "settings-tags",
        label: "Settings: Tag registry",
        href: "/settings",
        icon: IconTag,
        description: "Tag names, labels and chip colours",
        keywords: ["tag", "tags", "label", "registry", "colour", "color"],
    },
    {
        id: "settings-users",
        label: "Settings: Users",
        href: "/settings",
        icon: IconUsers,
        description: "Console accounts and roles",
        keywords: ["user", "users", "account", "role", "admin", "member", "password", "invite"],
        adminOnly: true,
    },
];

// Sidebar entries, in order, honouring the YAML toggle and the viewer's role.
export function sidebarDestinations(opts: {
    isAdmin: boolean;
    showYaml: boolean;
}): PaletteDestination[] {
    return PALETTE_DESTINATIONS.filter(
        (d) => d.sidebar && (!d.adminOnly || opts.isAdmin) && (!d.requiresYaml || opts.showYaml),
    );
}

export type SidebarEntry =
    | { kind: "item"; item: PaletteDestination }
    | { kind: "group"; group: NavGroup; items: PaletteDestination[] };

/** One pass over the table: an ungrouped page stands on its own, and a group takes the position
 * of its first surviving member. A group whose pages are all filtered out never appears. */
export function sidebarTree(opts: {
    isAdmin: boolean;
    showYaml: boolean;
}): SidebarEntry[] {
    const entries: SidebarEntry[] = [];
    const open = new Map<NavGroupId, { kind: "group"; group: NavGroup; items: PaletteDestination[] }>();
    for (const destination of sidebarDestinations(opts)) {
        if (!destination.group) {
            entries.push({kind: "item", item: destination});
            continue;
        }
        let group = open.get(destination.group);
        if (!group) {
            group = {kind: "group", group: NAV_GROUPS[destination.group], items: []};
            open.set(destination.group, group);
            entries.push(group);
        }
        group.items.push(destination);
    }
    return entries;
}

/** Which href the current path is on, by longest match. Plain prefix matching would mark both
 * /compliance and /compliance/rules active, and likewise /atc and /atc/runs. */
export function activeHref(pathname: string, hrefs: string[]): string | null {
    let best: string | null = null;
    for (const href of hrefs) {
        if (pathname !== href && !pathname.startsWith(href + "/")) continue;
        if (!best || href.length > best.length) best = href;
    }
    return best;
}

// Destinations the palette may offer this user.
export function paletteDestinations(opts: {
    isAdmin: boolean;
    showYaml: boolean;
}): PaletteDestination[] {
    return PALETTE_DESTINATIONS.filter(
        (d) => (!d.adminOnly || opts.isAdmin) && (!d.requiresYaml || opts.showYaml),
    );
}

// Case-insensitive substring match against any of the given fields. Literal rather than fuzzy:
// at this many entries, fuzzy matching mostly surfaces rows unrelated to the query.
export function matchesQuery(query: string, ...fields: (string | string[] | null | undefined)[]): boolean {
    const q = query.trim().toLowerCase();
    if (!q) return true;
    return fields.some((f) => {
        if (!f) return false;
        const values = Array.isArray(f) ? f : [f];
        return values.some((v) => typeof v === "string" && v.toLowerCase().includes(q));
    });
}
