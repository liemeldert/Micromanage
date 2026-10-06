// Strings to use for alert messages

import type {FlowGap} from "../api";

export const ALERT_BOARD_STRINGS = {
    loadErrorTitle: "Couldn't load alerts",
    staleData: "Anything below is from the last time we were able to reach the server. It may be out of date.",
    empty: (showResolved: boolean, severity: string | null) =>
        `No ${showResolved ? "" : "active "}${severity ? `${severity} ` : ""}alerts.`,
    evaluated: (devices: number) => `Evaluated ${devices} device${devices === 1 ? "" : "s"}`,
    noDevice: "No device on this alert",
    adminOnly: "admin only",
    failingState: "Failing state",
    reasonLabel: "Reason",
    reasonDescription: "Optional. This is just for future reference on the audit log.",
};

export const CREDENTIAL_REVEAL_STRINGS = {
    burstTitle: "Revealed too quickly",
    burstBody: (reveals?: number) =>
        `This was one of ${reveals || "several"} passwords revealed in rapid succession. This could indicate that ` +
        "an account was compromised. If you are not sure, check the audit log.",
    burstBadge: (reveals?: number) => (reveals ? `revealed in a burst of ${reveals}` : "revealed too quickly"),
    lastRevealedBy: "Last revealed by",
    revealedOn: (time: string) => ` on ${time}`,
    noRevealer: "No record of who revealed it. This should not happen so something's wrong.",
    firstRevealedBy: (name: string) => `First revealed by ${name}.`,
    revealCount: (count: number) => `Revealed ${count} times in total.`,
    closesOnRotation: "This closes automatically when the password is rotated.",
    adminOnlyTooltip: "Only an admin can dismiss this.",
    dismissButton: "Dismiss",
    peekResolve: "Resolve the alert",
    dismissTitle: "Dismiss this credential reveal alert?",
    dismissBody:
        "This alert records that somebody revealed a device password. It closes once that password is " +
        "rotated, so dismissing it says you have decided no rotation is needed. Dismissing it does not rotate the " +
        "password or change any device state.",
    dismissPlaceholder: "Alert dismissal reason (optional)",
    dismissConfirm: "Dismiss alert",
};

export const REMEDIATION_STRINGS = {
    approvalBadge: "approval required",
    pendingHeading: "Pending admin approval (destructive)",
    untilApproved: ", which never runs until approved",
    reject: "Reject",
    approve: "Approve & run",
    rejectTitle: "Reject this queued command?",
    rejectBody:
        " will never run which could leave the device in a broken or inconsistent state.",
    rejectPlaceholder: "Reason for rejecting(optional)",
    ledgerHeading: "Remediation ledger",
    ledgerLine: (at: string, action: string, dryRun: boolean, outcome: string) =>
        `${at} · ${action}${dryRun ? " (dry-run)" : ""} → ${outcome}`,
};

export const ATC_ALERT_STRINGS = {
    releaseFromSetup: "Release from setup",
    openRun: "Open details for the run that failed",
    flow: "Flow",
    stoppedAt: "stopped at",
    stoppedBeforeStep: "stopped before it reached a step",
    startedBy: (event: string) => `(started by ${event})`,
    heldBadge: "held in setup",
    releasedBadge: "released unverified",
    heldTitle: "Still in Setup Assistant",
    heldBody:
        "The run stopped before it could release this device, so it is likely stuck in setup on the step where it waits " +
        "to be released by Remote Management. The device is likely unusable until it gets released. ",
    failures: (count: number, first: string, last: string) =>
        `${count} failures, first ${first}, most recent ${last}.`,
    failedOnce: (at: string) => `Failed ${at}.`,
};

export const GAP_LEDGER_STRINGS = {
    broken: {
        title: "The device exited setup early and is missing something defined by a flow",
        named: "The device left Setup Assistant. The following were defined in the flow but did not appear to run:",
        unnamed:
            "The device has left Setup Assistant, but we ha ve detected some anomalies. The flow appears to be " +
            "holding for something indefinitely.",
    },
    policy: {
        title: "The device exited setup early, but nothing appears to be missing",
        named:
            "It left Setup Assistant before the wait step had anything to hold, because this device was not " +
            "entitled to the items below yet.",
        unnamed: "It left Setup Assistant before the wait block and does not appear to be missing anything.",
    },
};

export function gapHeadline(gap: FlowGap): string {
    const node = gap.node || "an earlier step";
    switch (gap.kind) {
        case "not_queued":
            return `${node} did not properly queue all blocks`;
        case "barrier_empty":
            return `the wait at ${node} had nothing to wait for`;
        case "never_arrived":
            return `${node} gave up waiting for these`;
        default:
            return `${node} recorded a ${gap.kind} gap`;
    }
}
