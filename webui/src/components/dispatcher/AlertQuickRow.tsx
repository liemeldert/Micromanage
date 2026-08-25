// One alert in the dashboard board, built from SwipeActions for the two triage gestures and Interactable for
// the hover, press and peek.
//
// Acknowledging runs on the drag itself. Resolving ends an alert, so it waits for a press on the revealed
// action instead.

import {Text} from "@mantine/core";
import {IconArrowBackUp, IconCheck} from "@tabler/icons-react";
import {Interactable} from "../ui/Interactable";
import {SwipeActions} from "../ui/SwipeActions";

export function AlertQuickRow({
                                  severityColor,
                                  summary,
                                  detail,
                                  acknowledged,
                                  onAcknowledge,
                                  onResolve,
                                  onOpen,
                                  onPeek,
                                  onDismissed,
                              }: {
    severityColor: string;
    summary: string;
    detail: string;
    acknowledged: boolean;
    onAcknowledge: () => void;
    onResolve: () => void;
    onOpen: () => void;
    onPeek: () => void;
    onDismissed: () => void;
}) {
    return (
        <SwipeActions
            onDismissed={onDismissed}
            left={acknowledged ? {
                // An acknowledged row is only on the board because acknowledged ones are being shown, so the
                // same edge puts it back rather than acknowledging it a second time.
                label: `Restore ${summary}`,
                icon: <IconArrowBackUp size={16}/>,
                color: "gray",
                onAction: onAcknowledge,
                immediate: true,
            } : {
                label: `Acknowledge ${summary}`,
                icon: <IconCheck size={16}/>,
                color: "blue",
                onAction: onAcknowledge,
                immediate: true,
                // Acknowledging is the dashboard saying it has been seen, so the row leaves the board.
                dismiss: true,
            }}
            right={{
                label: `Resolve ${summary}`,
                icon: <IconCheck size={16}/>,
                color: "teal",
                onAction: onResolve,
            }}
        >
            <Interactable
                nested
                className={`mm-alert-row mm-severity-${severityColor}`}
                onActivate={onOpen}
                onPeek={onPeek}
            >
                <Text fz="xs" lineClamp={2}>
                    {summary}
                </Text>
                <Text fz="xs" c="dimmed" truncate>
                    {acknowledged ? `Acknowledged · ${detail}` : detail}
                </Text>
            </Interactable>
        </SwipeActions>
    );
}
