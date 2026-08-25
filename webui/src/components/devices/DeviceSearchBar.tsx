// The device list's one filter control. Committed filters sit in the box as removable chips, and whatever is
// still being typed stays plain text beside them. A named attribute with a value narrows the list as it is
// typed; Space, Enter or picking a suggestion turns it into a chip.
//
// The suggestion list is a plain positioned element rather than a Popover, so it works inside the table toolbar
// without depending on the overlay stack.

import {useEffect, useMemo, useRef, useState} from "react";
import {ActionIcon, Badge, Box, CloseButton, Text, Tooltip} from "@mantine/core";
import {IconArrowBackUp, IconArrowForwardUp, IconSearch} from "@tabler/icons-react";
import {
    DEVICE_FILTER_KEYS,
    DEVICE_FILTER_LABELS,
    DEVICE_FILTER_LABELS_INLINE,
    type DeviceFilterKey,
    formatDeviceQuery,
    parseDeviceQuery,
} from "../../../lib/device-filter";

/** The values the page can offer for each attribute. Enrollment state is not one of them, since the box holds
 * the whole set of states itself. */
export interface FilterValueSource {
    tag: { value: string; label: string }[];
    group: string[];
    model: string[];
    os: string[];
}

interface Suggestion {
    key: DeviceFilterKey;
    value: string;
    label: string;
    hint: string;
}

const STATE_VALUES = ["enrolled", "unenrolled", "pending"];

// How long the caret has to sit still before the suggestion hint appears.
const HINT_DELAY_MS = 700;

// Accepted spellings for each attribute, including the plurals and one synonym.
const KEY_ALIASES: Record<string, DeviceFilterKey> = {
    tag: "tag",
    tags: "tag",
    group: "group",
    groups: "group",
    model: "model",
    models: "model",
    os: "os",
    osversion: "os",
    state: "state",
    status: "state",
};

// "tag:" or "tag: quar", with a key KEY_ALIASES knows. Anything else is free text. The value is trimmed, so a
// space after the colon does not become part of it.
function draftFilter(draft: string): { key: DeviceFilterKey; partial: string } | null {
    const match = /^([A-Za-z]+):(.*)$/.exec(draft.trim());
    if (!match) return null;
    const key = KEY_ALIASES[match[1].toLowerCase()];
    if (!key) return null;
    return {key, partial: match[2].trim()};
}

/** The attribute a bare word names, so "tags" alone can become "tag:". */
function bareKey(draft: string): DeviceFilterKey | null {
    return KEY_ALIASES[draft.trim().toLowerCase()] ?? null;
}

function valuesFor(key: DeviceFilterKey, source: FilterValueSource): { value: string; label: string }[] {
    if (key === "tag") return source.tag;
    if (key === "group") return source.group.map((g) => ({value: g, label: g}));
    if (key === "model") return source.model.map((m) => ({value: m, label: m}));
    if (key === "os") return source.os.map((o) => ({value: o, label: o}));
    return STATE_VALUES.map((s) => ({value: s, label: s}));
}

/** The single attribute whose values contain this word exactly. Ambiguous words are left as plain text. */
function inferFilter(draft: string, source: FilterValueSource): { key: DeviceFilterKey; value: string } | null {
    const typed = draft.trim().toLowerCase();
    if (!typed) return null;
    const hits: { key: DeviceFilterKey; value: string }[] = [];
    for (const key of DEVICE_FILTER_KEYS) {
        for (const candidate of valuesFor(key, source)) {
            if (candidate.value.toLowerCase() !== typed && candidate.label.toLowerCase() !== typed) continue;
            hits.push({key, value: candidate.value});
            break;
        }
    }
    return hits.length === 1 ? hits[0] : null;
}

export function DeviceSearchBar({
                                    value,
                                    onChange,
                                    source,
                                    inputRef: externalRef,
                                    onLeaveDown,
                                    undo,
                                    redo,
                                    canUndo,
                                    canRedo,
                                }: {
    value: string;
    onChange: (next: string) => void;
    source: FilterValueSource;
    /** So the page can hand typing straight to the box. */
    inputRef?: React.RefObject<HTMLInputElement | null>;
    /** Down arrow leaves the box for the list behind it. */
    onLeaveDown?: () => void;
    undo: () => void;
    redo: () => void;
    canUndo: boolean;
    canRedo: boolean;
}) {
    const parsed = useMemo(() => parseDeviceQuery(value), [value]);

    const [draft, setDraft] = useState(parsed.text);
    const [open, setOpen] = useState(false);
    // The suggestion hint waits for the typing to stop, so it does not flicker behind a moving caret.
    const [hintVisible, setHintVisible] = useState(false);
    const [highlight, setHighlight] = useState(0);
    // The attribute currently in the input, so clearing the text also clears the filter it was building rather
    // than leaving the last value behind as a chip.
    const typingKey = useRef<DeviceFilterKey | null>(null);
    const ownRef = useRef<HTMLInputElement>(null);
    const inputRef = externalRef ?? ownRef;

    // A query arriving from the URL or the palette replaces whatever was being typed.
    const lastText = useRef(parsed.text);
    useEffect(() => {
        if (parsed.text === lastText.current) return;
        lastText.current = parsed.text;
        typingKey.current = null;
        setDraft(parsed.text);
    }, [parsed.text]);

    const pending = draftFilter(draft);
    // The attribute being typed lives in the input, so it is not also drawn as a chip beside it.
    const chips = DEVICE_FILTER_KEYS.filter(
        (key) => parsed.filters[key] && !(pending?.partial && pending.key === key),
    );

    const suggestions = useMemo<Suggestion[]>(() => {
        const typed = draft.trim().toLowerCase();

        if (pending) {
            const wanted = pending.partial.toLowerCase();
            const hit = (v: { value: string; label: string }) =>
                !wanted || v.label.toLowerCase().includes(wanted) || v.value.toLowerCase().includes(wanted);
            return valuesFor(pending.key, source)
                .filter(hit)
                .slice(0, 8)
                .map((v) => ({
                    key: pending.key,
                    value: v.value,
                    label: v.label,
                    hint: DEVICE_FILTER_LABELS[pending.key],
                }));
        }

        // With nothing typed, offer the attributes themselves. Typed text matches values across every attribute,
        // so a tag name alone is enough to find the filter for it.
        if (!typed) {
            return DEVICE_FILTER_KEYS
                .filter((key) => !parsed.filters[key])
                .map((key) => ({key, value: "", label: `${key}:`, hint: DEVICE_FILTER_LABELS[key]}));
        }

        const hits: Suggestion[] = [];
        for (const key of DEVICE_FILTER_KEYS) {
            for (const v of valuesFor(key, source)) {
                if (!v.label.toLowerCase().includes(typed) && !v.value.toLowerCase().includes(typed)) continue;
                hits.push({key, value: v.value, label: v.label, hint: DEVICE_FILTER_LABELS[key]});
                if (hits.length >= 8) return hits;
            }
        }
        return hits;
    }, [draft, pending, source, parsed.filters]);

    useEffect(() => setHighlight(0), [draft]);

    useEffect(() => {
        setHintVisible(false);
        if (open || !draft || suggestions.length === 0) return;
        const timer = window.setTimeout(() => setHintVisible(true), HINT_DELAY_MS);
        return () => window.clearTimeout(timer);
    }, [draft, open, suggestions.length]);

    const commitQuery = (filters: typeof parsed.filters, text: string) => {
        onChange(formatDeviceQuery({filters, text}));
    };

    // Every keystroke reaches the query, so the list stays in step with what the box says.
    const pushDraft = (next: string) => {
        setDraft(next);
        // Record what this edit commits, so the sync effect does not read it as a query arriving from outside.
        const typed = draftFilter(next);
        const nextText = typed ? "" : next;
        lastText.current = nextText;

        // A named attribute with a value narrows the list straight away, even though it is still in the input
        // rather than in a chip.
        const filters = {...parsed.filters};
        if (typingKey.current && (!typed || typed.key !== typingKey.current)) {
            delete filters[typingKey.current];
        }
        if (typed) {
            if (typed.partial) filters[typed.key] = typed.partial;
            else delete filters[typed.key];
        }
        typingKey.current = typed ? typed.key : null;
        commitQuery(filters, nextText);
        // Naming an attribute opens its value list. Plain text waits for the right arrow instead.
        setOpen(Boolean(typed));
    };

    const applyFilter = (key: DeviceFilterKey, filterValue: string) => {
        if (!filterValue) {
            // An attribute with no value yet, so put the key in the box and wait for one.
            setDraft(`${key}:`);
            setOpen(true);
            inputRef.current?.focus();
            return;
        }
        setDraft("");
        lastText.current = "";
        typingKey.current = null;
        commitQuery({...parsed.filters, [key]: filterValue}, "");
        setOpen(false);
        inputRef.current?.focus();
    };

    const removeChip = (key: DeviceFilterKey) => {
        const next = {...parsed.filters};
        delete next[key];
        commitQuery(next, draftFilter(draft) ? "" : draft);
    };

    const onKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
        const atEnd = event.currentTarget.selectionStart === draft.length
            && event.currentTarget.selectionEnd === draft.length;

        if (event.key === "ArrowRight" && atEnd && suggestions.length > 0) {
            event.preventDefault();
            if (!open) setOpen(true);
            else setHighlight((h) => Math.min(h + 1, suggestions.length - 1));
            return;
        }
        if (event.key === "ArrowDown") {
            if (open) {
                event.preventDefault();
                setHighlight((h) => Math.min(h + 1, suggestions.length - 1));
                return;
            }
            // Nothing open, so the arrow belongs to the list rather than the box.
            event.preventDefault();
            onLeaveDown?.();
            return;
        }
        if (event.key === "ArrowUp" && open) {
            event.preventDefault();
            setHighlight((h) => Math.max(h - 1, 0));
            return;
        }
        if (event.key === "Escape") {
            setOpen(false);
            return;
        }
        if (event.key === "Backspace" && !draft && chips.length > 0) {
            removeChip(chips[chips.length - 1]);
            return;
        }
        if (event.key !== "Enter" && event.key !== " ") return;

        const choice = open && suggestions[highlight];
        if (choice && choice.value) {
            event.preventDefault();
            applyFilter(choice.key, choice.value);
            return;
        }
        if (pending?.partial) {
            event.preventDefault();
            applyFilter(pending.key, pending.partial);
            return;
        }

        // "tags" on its own names an attribute, so space turns it into "tag:" and offers the values.
        const bare = bareKey(draft);
        if (bare) {
            event.preventDefault();
            setDraft(`${bare}:`);
            setOpen(true);
            return;
        }

        // A word naming exactly one known value becomes that filter without the attribute being typed.
        const inferred = inferFilter(draft, source);
        if (inferred) {
            event.preventDefault();
            applyFilter(inferred.key, inferred.value);
        }
    };

    return (
        <Box style={{position: "relative", flex: 1, minWidth: 0}}>
            {/* Hand-rolled rather than a TextInput, so the chips sit inside the border with the caret instead
              of beside the box. */}
            <Box className="mm-device-search-box" onClick={() => inputRef.current?.focus()}>
                <IconSearch size={14} style={{flexShrink: 0, opacity: 0.55}}/>
                {chips.map((key) => (
                    <Badge
                        key={key}
                        variant="light"
                        size="lg"
                        radius="sm"
                        style={{flexShrink: 0, textTransform: "none"}}
                        rightSection={
                            <CloseButton
                                size={14}
                                variant="transparent"
                                aria-label={`Remove ${DEVICE_FILTER_LABELS[key]} filter`}
                                onMouseDown={(e) => e.preventDefault()}
                                onClick={() => removeChip(key)}
                            />
                        }
                    >
                        {key}: {parsed.filters[key]}
                    </Badge>
                ))}
                <input
                    ref={inputRef}
                    value={draft}
                    onChange={(e) => pushDraft(e.currentTarget.value)}
                    onKeyDown={onKeyDown}
                    // A click on a suggestion has to register before the list is dismissed.
                    onBlur={() => window.setTimeout(() => setOpen(false), 120)}
                    placeholder={chips.length ? "" : "Search, or filter by tag, group, model, OS…"}
                    aria-label="Search and filter devices"
                    // Sized to its content once there is any, so the hint sits against the caret rather than
                    // the far edge. Empty, it takes the width the placeholder needs.
                    style={draft
                        ? {width: `${draft.length + 1}ch`, flex: "0 1 auto"}
                        : {flex: 1, minWidth: "12rem"}}
                />

                <Text
                    fz="xs"
                    c="dimmed"
                    className={`mm-search-hint${hintVisible ? " mm-search-hint-visible" : ""}`}
                    aria-hidden
                >
                    → for suggestions
                </Text>

                {draft ? <Box style={{flex: 1, minWidth: 0}}/> : null}

                <Tooltip label="Undo filter change" withArrow openDelay={400}>
                    <ActionIcon
                        variant="subtle"
                        color="gray"
                        size="sm"
                        disabled={!canUndo}
                        aria-label="Undo filter change"
                        onMouseDown={(e) => e.preventDefault()}
                        onClick={undo}
                        style={{flexShrink: 0}}
                    >
                        <IconArrowBackUp size={15}/>
                    </ActionIcon>
                </Tooltip>
                <Tooltip label="Redo filter change" withArrow openDelay={400}>
                    <ActionIcon
                        variant="subtle"
                        color="gray"
                        size="sm"
                        disabled={!canRedo}
                        aria-label="Redo filter change"
                        onMouseDown={(e) => e.preventDefault()}
                        onClick={redo}
                        style={{flexShrink: 0}}
                    >
                        <IconArrowForwardUp size={15}/>
                    </ActionIcon>
                </Tooltip>
            </Box>

            {open && pending?.partial && suggestions.length === 0 && (
                <Box className="mm-search-suggestions mm-glass-surface">
                    <Box className="mm-search-suggestion mm-search-suggestion-empty">
                        <Text fz="sm">
                            No {DEVICE_FILTER_LABELS_INLINE[pending.key]} matches “{pending.partial}”
                        </Text>
                    </Box>
                </Box>
            )}

            {open && suggestions.length > 0 && (
                <Box className="mm-search-suggestions mm-glass-surface" role="listbox">
                    {suggestions.map((s, i) => (
                        <Box
                            key={`${s.key}:${s.value}:${i}`}
                            role="option"
                            aria-selected={i === highlight}
                            data-active={i === highlight || undefined}
                            className="mm-search-suggestion"
                            onMouseDown={(e) => e.preventDefault()}
                            onMouseEnter={() => setHighlight(i)}
                            onClick={() => applyFilter(s.key, s.value)}
                        >
                            <Text fz="sm">{s.value ? `${s.key}: ${s.label}` : s.label}</Text>
                            <Text fz="xs" c="dimmed">{s.hint}</Text>
                        </Box>
                    ))}
                </Box>
            )}
        </Box>
    );
}
