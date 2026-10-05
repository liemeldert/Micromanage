// Badge colours and display words for the status columns, shared by the device page, the task drawer and the
// flow-run pages so they cannot drift apart.

/** Task.status, as the controller writes it. */
export const TASK_STATUS_COLORS: Record<string, string> = {
    pending: "yellow",
    running: "blue",
    completed: "teal",
    failed: "red",
    cancelled: "gray",
};

/** AppDeployment.status / ProfileDeployment.status. */
export const DEPLOYMENT_STATUS_COLORS: Record<string, string> = {
    installed: "teal",
    installing: "blue",
    pending: "yellow",
    failed: "red",
    unscoped: "gray",
    // The device acknowledged the install command and no inventory report has confirmed the app yet.
    accepted: "cyan",
};

// The device page puts a deployment row and the task that produced it in the same lookup, so it needs both sets.
export const STATUS_COLORS: Record<string, string> = {
    ...TASK_STATUS_COLORS,
    ...DEPLOYMENT_STATUS_COLORS,
};

// Deployment statuses that need a friendlier word than the raw column value. "unscoped" is a device that left the
// app's scope after installing, with nothing uninstalled; "accepted" is an acknowledged install not yet confirmed.
export const DEPLOYMENT_STATUS_LABELS: Record<string, string> = {
    unscoped: "No longer in scope",
    accepted: "Accepted, waiting for confirmation",
};

/** FlowRun.status. */
export const FLOW_RUN_STATUS_COLORS: Record<string, string> = {
    running: "blue",
    waiting: "yellow",
    completed: "teal",
    failed: "red",
    cancelled: "gray",
};
