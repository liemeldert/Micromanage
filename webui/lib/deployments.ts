// Display join between managed deployment rows and the tasks that produced them, matched on the row's last_task_id.
// A row's status is the state the item on the device is believed to be in; a task's status is what one attempt did.
// An app row can also sit at accepted, an ack that no inventory report has confirmed. Its task is already complete by
// then, so agreementOf treats it as settled like any other finished row. Nothing here repairs a row, it only names
// where the two legitimately read differently.

import type {Task} from "./api";

export type DeploymentKind = "app" | "profile";

/** A deployment row as it arrives on the device detail endpoint. */
export interface RawDeployment {
    app_id?: string;
    profile_id?: string;
    version?: string;
    status: string;
    install_date: string | null;
    /** Failure reason recorded on the row itself. */
    last_error?: string | null;
    /** The attempt the row is tracking. Null on rows written before a task ran. */
    last_task_id?: string | null;
    /** "remediation:<rule_id>" when a compliance rule installed this, else null. */
    install_source?: string | null;
    updated_at?: string | null;
}

// Mirrors REMEDIATION_SOURCE_PREFIX in controller/services/profile_manager.py, so client and server agree on what a
// mark looks like. Anything else, an empty value included, reads as no rule.
const REMEDIATION_SOURCE_PREFIX = "remediation:";

function remediationRuleId(installSource: string | null | undefined): string | null {
    if (!installSource || !installSource.startsWith(REMEDIATION_SOURCE_PREFIX)) return null;
    return installSource.slice(REMEDIATION_SOURCE_PREFIX.length) || null;
}

export type Agreement =
/** Nothing to say: no attempt linked, or the attempt matches the row. */
    | "ok"
    /** The linked attempt is still going, so this row is about to change. */
    | "in_flight"
    /** The row says installed and its attempt failed: the device answered after the attempt was written off. */
    | "late_confirmation"
    /** The row never reached a settled state and its attempt is over. */
    | "stalled";

export interface ReconciledDeployment {
    /** app_id / profile_id */
    id: string;
    /** Friendly name from apps.yaml / profiles.yaml; falls back to the id. */
    name: string;
    version?: string;
    status: string;
    install_date: string | null;
    /** The row's own explanation of a failure, independent of the task. */
    lastError: string | null;
    updatedAt: string | null;
    /** The linked attempt. Null next to a non-null attemptId means it has aged out of the recent-task list. */
    attempt: Task | null;
    attemptId: string | null;
    agreement: Agreement;
    /** True where the row and its attempt are worth explaining side by side. */
    conflicted: boolean;
    /** The compliance rule that installed this, on a row the device's own scope never asked for. */
    remediationRuleId: string | null;
}

/** The attempt a row points at, if it is among the tasks we loaded. */
export function linkedAttempt(tasks: Task[], lastTaskId: string | null | undefined): Task | null {
    if (!lastTaskId) return null;
    return tasks.find((t) => t.id === lastTaskId) ?? null;
}

function agreementOf(status: string, attempt: Task | null): Agreement {
    if (!attempt) return "ok";
    if (attempt.status === "running" || attempt.status === "pending") return "in_flight";
    if (attempt.status === "failed") {
        if (status === "installed") return "late_confirmation";
        if (status === "installing" || status === "pending") return "stalled";
    }
    return "ok";
}

// A still-running attempt is an update in progress, not a disagreement.
const CONFLICTING: Agreement[] = ["late_confirmation", "stalled"];

export function reconcileDeployments(
    rows: RawDeployment[],
    tasks: Task[],
    kind: DeploymentKind,
    nameById: Record<string, string>,
): ReconciledDeployment[] {
    return rows.map((row) => {
        const id = (kind === "app" ? row.app_id : row.profile_id) ?? "";
        const name = nameById[id] || id;
        const attemptId = row.last_task_id ?? null;
        const attempt = linkedAttempt(tasks, attemptId);
        const agreement = agreementOf(row.status, attempt);
        return {
            id,
            name,
            version: row.version,
            status: row.status,
            install_date: row.install_date,
            lastError: row.last_error ?? null,
            updatedAt: row.updated_at ?? null,
            attempt,
            attemptId,
            agreement,
            conflicted: CONFLICTING.includes(agreement),
            remediationRuleId: remediationRuleId(row.install_source),
        };
    });
}

/** What to say about a row whose state and attempt read differently. */
export function agreementNote(d: ReconciledDeployment, kind: DeploymentKind): string | null {
    const thing = kind === "app" ? "app" : "profile";
    switch (d.agreement) {
        case "late_confirmation":
            return (
                `The install attempt was written off before the device answered, then the device ` +
                `confirmed the ${thing} was on. The status here is the later of the two.`
            );
        case "stalled":
            return `Still recorded as "${d.status}", but its install attempt is over, so nothing is coming.`;
        default:
            return null;
    }
}
