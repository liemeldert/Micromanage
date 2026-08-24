// Relative timestamps, shared by every page that shows one so they agree on the wording.

// How long until a deadline, or null once it has passed. Past due is a state a run can sit in for minutes, so
// callers word it rather than print a negative number.
export function timeUntil(iso: string | null | undefined): string | null {
    if (!iso) return null;
    const then = new Date(iso).getTime();
    if (Number.isNaN(then)) return null;
    const mins = Math.round((then - Date.now()) / 60000);
    if (mins <= 0) return null;
    if (mins < 60) return `${mins}m`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h`;
    return `${Math.floor(hrs / 24)}d`;
}

export function timeSince(iso: string | null | undefined): string {
    if (!iso) return "--";
    const then = new Date(iso).getTime();
    if (Number.isNaN(then)) return "--";
    const mins = Math.floor((Date.now() - then) / 60000);
    if (mins < 0) return "just now"; // clock skew between server and browser
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
}
