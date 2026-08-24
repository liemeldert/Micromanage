// Where a device's tags came from.
//
// A device.tags audit row names the subsystem that added or removed a tag, the flow node or rule inside it, and a
// reason when a rule took its own tag back. It covers removals and outlives the run or alert behind it, so it wins
// over inference wherever it exists.
//
// Inference over compliance alerts, flow timelines and tag_update tasks covers the two cases it misses: a member
// cannot read the admin-only audit endpoint, and a tag applied before the tenant had tag auditing has no row.
// Inferred sources are marked as such, since the timeline parse is string-matching on server-formatted messages.

import {
    AUDIT_TAG_ACTION,
    type AuditLogEntry,
    type DispatcherAlert,
    type FlowRunSummary,
    type TagAuditDetail,
    type Task
} from "./api";

export type ActorKind = "compliance" | "flow" | "manual";

export interface TagSource {
    kind: ActorKind;
    /** Rule id, flow id, or the user's email. */
    actor: string;
    /** When the tag was applied, if known. */
    at: string | null;
    /** Link to the alert, run or rule behind it. */
    href?: string;
    /** True when this came from an audit row, false when it was inferred from an alert, flow timeline or task. */
    recorded?: boolean;
    /** Dispatcher's revert reason, e.g. "alert resolved (compliant again)". */
    note?: string;
}

export interface TagAttribution {
    tag: string;
    sources: TagSource[];
}

/** One thing an automated system did to this device. */
export interface AutomationEvent {
    id: string;
    kind: ActorKind;
    /** Human name of the system that acted ("Compliance rule: firewall-required"). */
    actor: string;
    /** What it did, in plain words. */
    summary: string;
    /** Tags it applied, when the action was a tag write. */
    tags: string[];
    at: string | null;
    status?: string;
    severity?: string;
    href?: string;
}

// The flow timeline's tag message, formatted exactly: tags added=['a', 'b'] removed=['c']
const TAG_MSG_RE = /^tags\s+added=\[(.*?)]\s+removed=\[(.*?)]$/;

// Python list-of-str repr, e.g. "'corp', 'byod'".
function parsePyList(s: string): string[] {
    return Array.from(s.matchAll(/'([^']*)'|"([^"]*)"/g))
        .map((m) => m[1] ?? m[2] ?? "")
        .filter(Boolean);
}

export interface ParsedTimelineEntry {
    at: string;
    node: string | null;
    /** Original message, kept for the details view. */
    message: string;
    /** Plain-language rendering, falling back to the raw message. */
    summary: string;
    added: string[];
    removed: string[];
}

/** Translate one FlowRun timeline entry into something readable. */
export function parseTimelineEntry(entry: {
    at: string;
    node: string | null;
    message: string;
}): ParsedTimelineEntry {
    const msg = entry.message ?? "";
    const base = {at: entry.at, node: entry.node, message: msg, added: [] as string[], removed: [] as string[]};

    const tagMatch = TAG_MSG_RE.exec(msg);
    if (tagMatch) {
        const added = parsePyList(tagMatch[1]);
        const removed = parsePyList(tagMatch[2]);
        const parts: string[] = [];
        if (added.length) parts.push(`added the tag${added.length > 1 ? "s" : ""} ${added.join(", ")}`);
        if (removed.length) parts.push(`removed the tag${removed.length > 1 ? "s" : ""} ${removed.join(", ")}`);
        return {...base, added, removed, summary: parts.join(" and ") || "changed tags"};
    }

    let m = /^install_profiles queued=\[(.*?)]$/.exec(msg);
    if (m) return {...base, summary: `queued profile install: ${parsePyList(m[1]).join(", ") || "none"}`};

    m = /^install_apps queued=\[(.*?)]$/.exec(msg);
    if (m) return {...base, summary: `queued app install: ${parsePyList(m[1]).join(", ") || "none"}`};

    m = /^set_name -> '(.*)'$/.exec(msg);
    if (m) return {...base, summary: `renamed the device to ${m[1]}`};

    m = /^waiting for (\S+)(?: \(timeout (\S+)\))?/.exec(msg);
    if (m) return {...base, summary: `waited for ${m[1].replace(/_/g, " ")}${m[2] ? ` (up to ${m[2]})` : ""}`};

    m = /^resumed on (\S+)$/.exec(msg);
    if (m) return {...base, summary: `continued after ${m[1].replace(/_/g, " ")}`};

    if (msg === "wait timed out") return {...base, summary: "gave up waiting for the device"};
    if (msg === "completed") return {...base, summary: "finished"};

    m = /^branch -> (true|false)$/.exec(msg);
    if (m) return {...base, summary: `took the "${m[1]}" branch`};

    return {...base, summary: msg};
}

/** Every tag-writing step across a device's flow runs, newest first. */
function flowTagEvents(runs: FlowRunSummary[]): AutomationEvent[] {
    const out: AutomationEvent[] = [];
    for (const run of runs) {
        for (const [i, entry] of (run.timeline ?? []).entries()) {
            const parsed = parseTimelineEntry(entry);
            if (!parsed.added.length && !parsed.removed.length) continue;
            out.push({
                id: `${run.id}:${i}`,
                kind: "flow",
                actor: run.flow_id,
                summary: parsed.summary,
                tags: [...parsed.added, ...parsed.removed],
                at: entry.at,
                status: run.status,
                href: `/atc/runs/${run.id}`,
            });
        }
    }
    return out;
}

/** One entry per flow run and per compliance alert, newest first. */
export function automationEvents(
    alerts: DispatcherAlert[],
    runs: FlowRunSummary[],
): AutomationEvent[] {
    const fromAlerts: AutomationEvent[] = alerts.map((a) => ({
        id: a.id,
        kind: "compliance",
        actor: a.rule_id,
        summary: a.summary,
        tags: reversibleTags(a),
        at: a.first_detected_at ?? a.opened_at ?? a.updated_at,
        status: a.status,
        severity: a.severity,
        href: "/compliance",
    }));

    const fromRuns: AutomationEvent[] = runs.map((r) => ({
        id: r.id,
        kind: "flow",
        actor: r.flow_id,
        summary:
            r.status === "waiting" && r.waiting_signal
                ? `Waiting for ${r.waiting_signal.replace(/_/g, " ")}`
                : (r.timeline ?? []).length
                    ? parseTimelineEntry(r.timeline[r.timeline.length - 1]).summary
                    : "No steps recorded",
        tags: flowTagEvents([r]).flatMap((e) => e.tags),
        at: r.started_at ?? r.updated_at,
        status: r.status,
        href: `/atc/runs/${r.id}`,
    }));

    return [...fromAlerts, ...fromRuns].sort((a, b) =>
        (b.at ?? "").localeCompare(a.at ?? ""),
    );
}

/** Tags a compliance rule applied and will take back when the alert resolves. */
export function reversibleTags(alert: DispatcherAlert): string[] {
    const bucket = (alert.detail ?? {})["reversible_tags"];
    return Array.isArray(bucket) ? bucket.filter((t): t is string => typeof t === "string") : [];
}

const SOURCE_KIND: Record<string, ActorKind> = {
    console: "manual",
    atc: "flow",
    dispatcher: "compliance",
};

function strings(value: unknown): string[] {
    return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/** One device.tags audit row, narrowed to the fields this module reads. */
export interface TagAuditRow {
    at: string | null;
    kind: ActorKind;
    /** Rule id, "flow:node", or the admin's email. */
    actor: string;
    added: string[];
    removed: string[];
    /** Dispatcher's revert reason, present only when a rule took a tag back. */
    reason: string | null;
    href?: string;
}

/** Read one device's device.tags rows into something the UI can render. Rows arrive newest first and stay so. */
export function parseTagAudit(entries: AuditLogEntry[]): TagAuditRow[] {
    return entries
        .filter((e) => e.action === AUDIT_TAG_ACTION)
        .map((e) => {
            const d = (e.detail ?? {}) as TagAuditDetail;
            const source = typeof d.source === "string" ? d.source : "";
            const kind = SOURCE_KIND[source] ?? "manual";
            const ref = typeof d.source_ref === "string" ? d.source_ref : "";
            // A console row is attributed to the admin who made it, an automated one to the rule or flow node.
            const actor = e.actor_email || ref || (source ? `the ${source} subsystem` : "the system");
            return {
                at: e.created_at,
                kind,
                actor,
                added: strings(d.added),
                removed: strings(d.removed),
                reason: typeof d.reason === "string" ? d.reason : null,
                href: kind === "compliance" ? "/compliance" : kind === "flow" ? "/atc" : undefined,
            };
        });
}

/**
 * Who put each of this device's tags there.
 *
 * Pass null when the log could not be read, and every tag falls back to inference. A tag with neither predates tag
 * auditing, fell outside the retained alert, run and task history, or arrived with an import.
 */
export function attributeTags(
    tags: string[],
    alerts: DispatcherAlert[],
    runs: FlowRunSummary[],
    tasks: Task[],
    audit: TagAuditRow[] | null,
): TagAttribution[] {
    const byTag = new Map<string, TagSource[]>(tags.map((t) => [t, []]));
    const add = (tag: string, src: TagSource) => {
        const list = byTag.get(tag);
        if (!list) return; // tag has since been removed from the device
        if (list.some((s) => s.kind === src.kind && s.actor === src.actor)) return;
        list.push(src);
    };

    // Newest first, so the most recent writer of a tag is listed first.
    for (const row of audit ?? []) {
        for (const tag of row.added) {
            add(tag, {
                kind: row.kind,
                actor: row.actor,
                at: row.at,
                href: row.href,
                recorded: true,
                note: row.reason ?? undefined,
            });
        }
    }

    // Inference, for tags no audit row accounts for. A tag the audit already explains is skipped, so a renamed rule
    // or a differently worded timeline cannot contradict the record.
    const unexplained = (tag: string) => (byTag.get(tag) ?? []).length === 0;

    for (const alert of alerts) {
        for (const tag of reversibleTags(alert)) {
            if (!unexplained(tag)) continue;
            add(tag, {
                kind: "compliance",
                actor: alert.rule_id,
                at: alert.first_detected_at ?? alert.opened_at,
                href: "/compliance",
            });
        }
    }

    for (const event of flowTagEvents(runs)) {
        for (const tag of event.tags) {
            if (!unexplained(tag)) continue;
            add(tag, {kind: "flow", actor: event.actor, at: event.at, href: event.href});
        }
    }

    for (const task of tasks) {
        if (task.type !== "tag_update") continue;
        const details = (task.details ?? {}) as Record<string, unknown>;
        for (const tag of strings(details.added)) {
            if (!unexplained(tag)) continue;
            add(tag, {kind: "manual", actor: task.user || "a console user", at: task.created_at});
        }
    }

    return tags.map((tag) => ({tag, sources: byTag.get(tag) ?? []}));
}

export const ACTOR_LABELS: Record<ActorKind, string> = {
    compliance: "Compliance rule",
    flow: "Automation flow",
    manual: "Set by hand",
};
