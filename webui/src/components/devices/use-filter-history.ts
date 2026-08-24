"use client";

// The device query, with undo and redo over the filters. Only a filter change adds a step; typing free text
// updates the current entry in place, so undo does not walk back through a search term one keystroke at a time.

import {useCallback, useMemo, useState} from "react";

import {parseDeviceQuery} from "../../../lib/device-filter";

interface History {
    stack: string[];
    index: number;
}

function filterSignature(query: string): string {
    return JSON.stringify(parseDeviceQuery(query).filters);
}

export function useFilterHistory(initial = "") {
    const [history, setHistory] = useState<History>({stack: [initial], index: 0});

    const commit = useCallback((next: string | ((current: string) => string)) => {
        setHistory((state) => {
            const current = state.stack[state.index] ?? "";
            const resolved = typeof next === "function" ? next(current) : next;
            if (resolved === current) return state;

            if (filterSignature(resolved) === filterSignature(current)) {
                // Same filters, so this is a text edit rather than a step.
                return {
                    stack: state.stack.map((entry, i) => (i === state.index ? resolved : entry)),
                    index: state.index,
                };
            }
            return {
                stack: [...state.stack.slice(0, state.index + 1), resolved],
                index: state.index + 1,
            };
        });
    }, []);

    const undo = useCallback(() => {
        setHistory((state) => ({...state, index: Math.max(state.index - 1, 0)}));
    }, []);

    const redo = useCallback(() => {
        setHistory((state) => ({...state, index: Math.min(state.index + 1, state.stack.length - 1)}));
    }, []);

    return useMemo(() => ({
        value: history.stack[history.index] ?? "",
        setValue: commit,
        undo,
        redo,
        canUndo: history.index > 0,
        canRedo: history.index < history.stack.length - 1,
    }), [history, commit, undo, redo]);
}
