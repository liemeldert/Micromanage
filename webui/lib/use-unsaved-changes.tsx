// Guards for editors holding unsaved work: the browser's leave-the-page prompt, and an in-app confirmation for
// buttons that discard a draft without unloading the document.

import {useEffect} from "react";
import {Text} from "@mantine/core";
import {modals} from "@mantine/modals";

/**
 * Warn on reload, tab close and typed-in URLs while dirty. Client-side navigation does not reach this, so use
 * confirmDiscard on those buttons.
 */
export function useBeforeUnload(dirty: boolean) {
    useEffect(() => {
        if (!dirty) return;
        const handler = (e: BeforeUnloadEvent) => {
            e.preventDefault();
            e.returnValue = "";
        };
        window.addEventListener("beforeunload", handler);
        return () => window.removeEventListener("beforeunload", handler);
    }, [dirty]);
}

/** Run onConfirm, asking first when there is unsaved work to lose. */
export function confirmDiscard(opts: {
    dirty: boolean;
    /** What is about to be thrown away, e.g. "this profile". */
    what: string;
    onConfirm: () => void;
}) {
    if (!opts.dirty) {
        opts.onConfirm();
        return;
    }
    modals.openConfirmModal({
        title: "Discard your edits?",
        children: (
            <Text size="sm">
                Your changes to {opts.what} have not been saved. Leaving discards them, and there is no
                undo.
            </Text>
        ),
        labels: {confirm: "Discard edits", cancel: "Keep editing"},
        confirmProps: {color: "red"},
        onConfirm: opts.onConfirm,
    });
}
