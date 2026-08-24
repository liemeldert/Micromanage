// Task.error arrives as raw upstream text: httpx messages naming internal hostnames, stack-trace fragments, S3 client
// errors. Recognized failures become a plain cause plus a next step; everything else is scrubbed of URLs and host:port
// pairs before it can be rendered, with the original kept behind a details expander.

export interface ExplainedError {
    // Plain-language cause. Safe to render directly.
    headline: string;
    // What to do about it, when we know.
    nextStep?: string;
    // In-app destination, never an external documentation link.
    link?: { href: string; label: string };
    // The original text, for the details expander. Never rendered by default.
    raw: string;
    // False when the headline is already the raw text, so callers can skip the expander.
    hasDetail: boolean;
}

// httpx appends "for url '<address>'" and a "For more information check: <link>" line. Both go.
const MDN_LINE_RE = /\n?\s*For more information check:.*$/gim;
const FOR_URL_RE = /\s*for url\s*(['"`])?\S*?\1?(?=[\s,.]|$)/gi;
const URL_RE = /\b(?:https?|wss?):\/\/\S+/gi;
// Internal service addresses (nanomdm:9000, postgres:5432, 10.0.0.4:8001).
const HOSTPORT_RE = /\b[a-z0-9][a-z0-9._-]*:\d{2,5}\b/gi;

/** Strip internal URLs, host:port pairs and doc links out of arbitrary error text. */
export function scrubInternals(raw: string): string {
    return raw
        .replace(MDN_LINE_RE, "")
        .replace(FOR_URL_RE, "")
        .replace(URL_RE, "")
        .replace(HOSTPORT_RE, "")
        .replace(/\s*\(\s*\)\s*/g, " ")
        .replace(/\s*['"`]\s*['"`]\s*/g, " ")
        .replace(/\s+/g, " ")
        .replace(/\s+([,.;:])/g, "$1")
        .replace(/[\s,;:-]+$/, "")
        .trim();
}

// Push failures on a fresh install are nearly always a missing or expired APNs certificate, which leaves no push topic.
const PUSH_HINT =
    "This almost always means the APNs push certificate hasn't been uploaded yet, or it has expired. " +
    "Until that's fixed, no command can reach any device.";
const ENROLLMENT_LINK = {href: "/enrollment", label: "Check enrollment setup"};

interface Rule {
    match: (raw: string) => boolean;
    headline: string;
    nextStep?: string;
    link?: { href: string; label: string };
}

const RULES: Rule[] = [
    {
        // Distinctive prefix the controller puts on a command that timed out.
        match: (r) => /timed out: no device response/i.test(r),
        headline: "The device never answered.",
        nextStep:
            "It was switched off, asleep, or off the network the whole time the command was waiting. " +
            "Check the device is on and online, then retry.",
    },
    {
        // Failures talking to the MDM push service, matched on the enqueue/push path or the service hostname.
        match: (r) => /\/v1\/(enqueue|push)\/|nanomdm/i.test(r),
        headline: "Micromanage couldn't hand the command to Apple's push service.",
        nextStep: PUSH_HINT,
        link: ENROLLMENT_LINK,
    },
    {
        match: (r) => /\b(apns|push topic|missing topic|mdm_topic)\b/i.test(r),
        headline: "Apple push notifications aren't set up.",
        nextStep: PUSH_HINT,
        link: ENROLLMENT_LINK,
    },
    {
        match: (r) =>
            /(connection refused|cannot connect|connect(ion)? error|name or service not known|failed to resolve|network is unreachable)/i.test(r),
        headline: "Micromanage couldn't reach one of its own background services.",
        nextStep: "The problem is on the server side, so the device is fine. Ask whoever runs the server to check it, then retry.",
    },
    {
        match: (r) => /\b(401|403|unauthorized|forbidden|invalid credentials)\b/i.test(r),
        headline: "Micromanage was refused access by an upstream service.",
        nextStep: "A stored credential or certificate is wrong or expired. Check the enrollment and storage settings.",
        link: ENROLLMENT_LINK,
    },
    {
        match: (r) => /\b(s3|bucket|nosuchkey|access denied)\b/i.test(r),
        headline: "The app package couldn't be fetched from storage.",
        nextStep: "Check the S3 settings and that the package was uploaded for this version.",
        link: {href: "/settings", label: "Open storage settings"},
    },
    {
        match: (r) => /not supervised|requires supervision/i.test(r),
        headline: "The device isn't supervised, so it refused this command.",
        nextStep: "Supervision is set at enrollment. A device already in use has to be erased and re-enrolled to become supervised.",
    },
];

/**
 * Explain a raw task/command error. Always safe to render: headline and nextStep never
 * contain upstream URLs or internal hostnames.
 */
export function explainError(raw: string | null | undefined): ExplainedError | null {
    const original = (raw ?? "").trim();
    if (!original) return null;

    for (const rule of RULES) {
        if (rule.match(original)) {
            return {
                headline: rule.headline,
                nextStep: rule.nextStep,
                link: rule.link,
                raw: original,
                hasDetail: true,
            };
        }
    }

    // Unknown failure: show it scrubbed, and keep the expander when scrubbing removed something.
    const scrubbed = scrubInternals(original);
    return {
        headline: scrubbed || "The operation failed for an unrecognized reason.",
        raw: original,
        hasDetail: scrubbed !== original || !scrubbed,
    };
}

// Task.type is rendered beside the error text. Only the types that show up on a failure need an entry.
const TASK_TYPE_LABELS: Record<string, string> = {
    app_install: "Install app",
    app_remove: "Remove app",
    profile_install: "Install profile",
    profile_remove: "Remove profile",
    tag_update: "Update tags",
    set_name: "Rename device",
    refresh_info: "Refresh device information",
    security_info: "Refresh security posture",
    profile_list: "Refresh profile inventory",
    app_list: "Refresh app inventory",
    ddm_sync: "Declarative sync",
    // Command tasks carry the command type as their task type, so these mirror the Commands panel labels.
    restrictions: "Restrictions in effect",
    certificate_list: "Certificate list",
    managed_app_list: "Managed app status",
    provisioning_profile_list: "Provisioning profiles",
    device_information: "Custom device query",
    available_os_updates: "Available OS updates",
    os_update_status: "OS update status",
    restart: "Restart",
    shutdown: "Shut down",
    lock: "Lock device",
    clear_passcode: "Clear passcode",
    clear_restrictions_password: "Clear Screen Time password",
    unlock_user_account: "Unlock user account",
    set_recovery_lock: "Set Recovery Lock",
    verify_recovery_lock: "Verify Recovery Lock",
    set_firmware_password: "Set firmware password",
    verify_firmware_password: "Verify firmware password",
    rotate_filevault_key: "Rotate FileVault recovery key",
    enable_remote_desktop: "Enable Remote Desktop",
    disable_remote_desktop: "Disable Remote Desktop",
    erase: "Erase device",
    enable_lost_mode: "Enable Lost Mode",
    disable_lost_mode: "Disable Lost Mode",
    device_location: "Request location",
    play_lost_mode_sound: "Play Lost Mode sound",
    user_list: "User list",
    logout_user: "Log out current user",
    delete_user: "Delete user",
};

export function describeTaskType(type: string): string {
    return TASK_TYPE_LABELS[type] ?? type.replace(/_/g, " ");
}
