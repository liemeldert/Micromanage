// One filter syntax for the device list and the command palette. "tag:quarantine model:MacBook broken screen"
// narrows by tag and model and searches the rest as free text. A value may be quoted when it contains spaces, a
// space after the colon is allowed, and unknown keys stay in the free text rather than being dropped.
//
// parseDeviceQuery and formatDeviceQuery are inverses over the filters, so formatting a parsed query gives the
// same filters back in DEVICE_FILTER_KEYS order.

export const DEVICE_FILTER_KEYS = ["tag", "group", "model", "os", "state"] as const;

export type DeviceFilterKey = (typeof DEVICE_FILTER_KEYS)[number];

export type DeviceFilters = Partial<Record<DeviceFilterKey, string>>;

export interface ParsedDeviceQuery {
    filters: DeviceFilters;
    /** Everything that was not a filter, sent on as the search term. */
    text: string;
}

/** What each key narrows, for the hints the palette and the search box show. */
export const DEVICE_FILTER_LABELS: Record<DeviceFilterKey, string> = {
    tag: "Tag",
    group: "Group",
    model: "Model",
    os: "OS version",
    state: "Enrollment state",
};

/** The same names mid-sentence. Lowercasing the map above would render OS as os. */
export const DEVICE_FILTER_LABELS_INLINE: Record<DeviceFilterKey, string> = {
    tag: "tag",
    group: "group",
    model: "model",
    os: "OS version",
    state: "enrollment state",
};

function isFilterKey(word: string): word is DeviceFilterKey {
    return (DEVICE_FILTER_KEYS as readonly string[]).includes(word);
}

// Splits on whitespace but keeps a quoted run together, so tag:"school issued" survives as one token.
function tokenize(input: string): string[] {
    const tokens: string[] = [];
    let current = "";
    let quote: string | null = null;

    for (const char of input) {
        if (quote) {
            if (char === quote) quote = null;
            else current += char;
            continue;
        }
        if (char === '"' || char === "'") {
            quote = char;
            continue;
        }
        if (/\s/.test(char)) {
            if (current) tokens.push(current);
            current = "";
            continue;
        }
        current += char;
    }
    if (current) tokens.push(current);
    return tokens;
}

/** Split a query into the filters it names and the free text left over. */
export function parseDeviceQuery(input: string): ParsedDeviceQuery {
    const filters: DeviceFilters = {};
    const text: string[] = [];
    const tokens = tokenize(input ?? "");

    for (let i = 0; i < tokens.length; i += 1) {
        const token = tokens[i];
        const colon = token.indexOf(":");
        if (colon <= 0) {
            text.push(token);
            continue;
        }
        const key = token.slice(0, colon).toLowerCase();
        if (!isFilterKey(key)) {
            text.push(token);
            continue;
        }
        let value = token.slice(colon + 1);
        // "tag: quarantine" puts the value in the next token.
        if (!value && i + 1 < tokens.length) {
            value = tokens[i + 1];
            i += 1;
        }
        if (value) filters[key] = value;
    }

    return {filters, text: text.join(" ")};
}

function quoteIfNeeded(value: string): string {
    return /\s/.test(value) ? `"${value}"` : value;
}

/** Write filters and free text back out as one query string. */
export function formatDeviceQuery({filters, text}: ParsedDeviceQuery): string {
    const parts = DEVICE_FILTER_KEYS
        .filter((key) => filters[key])
        .map((key) => `${key}:${quoteIfNeeded(filters[key] as string)}`);
    if (text.trim()) parts.push(text.trim());
    return parts.join(" ");
}

/** Add, replace or (with an empty value) drop one filter, leaving the rest of the query alone. */
export function withDeviceFilter(input: string, key: DeviceFilterKey, value: string | null): string {
    const parsed = parseDeviceQuery(input);
    if (value) parsed.filters[key] = value;
    else delete parsed.filters[key];
    return formatDeviceQuery(parsed);
}

/** The filter keys the list request understands, ready to spread into listDevices. */
export function deviceQueryParams(input: string): {
    tag?: string;
    group?: string;
    model?: string;
    os?: string;
    state?: string;
    search?: string;
} {
    const {filters, text} = parseDeviceQuery(input);
    return {
        ...(filters.tag ? {tag: filters.tag} : {}),
        ...(filters.group ? {group: filters.group} : {}),
        ...(filters.model ? {model: filters.model} : {}),
        ...(filters.os ? {os: filters.os} : {}),
        ...(filters.state && filters.state !== "all" ? {state: filters.state} : {}),
        ...(text.trim() ? {search: text.trim()} : {}),
    };
}
