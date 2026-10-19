export const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

// One line of scope for the sidebar. An empty scope matches every device.
export function scopeSummary(scope: Record<string, unknown> | undefined): string {
    const count = (key: string) => (Array.isArray(scope?.[key]) ? (scope![key] as unknown[]).length : 0);
    const parts: string[] = [];
    const groups = count("groups");
    const conditions = count("conditions");
    const included = count("include_devices");
    const excluded = count("exclude_devices");
    if (groups) parts.push(plural(groups, "group"));
    if (conditions) parts.push(plural(conditions, "condition"));
    if (included) parts.push(`${included} pinned`);
    if (excluded) parts.push(`${excluded} excluded`);
    return parts.length ? parts.join(" · ") : "All devices";
}
