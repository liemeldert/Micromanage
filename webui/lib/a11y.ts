import type {KeyboardEvent} from "react";

/**
 * Props that give a clickable non-button element (a table row, a card) the keyboard path a button has: focus stop,
 * announced role, Enter/Space. Spread it in place of a bare onClick.
 */
export function clickable(onActivate: () => void, role: "button" | "link" = "button") {
    return {
        role,
        tabIndex: 0,
        onClick: onActivate,
        onKeyDown: (e: KeyboardEvent) => {
            // Keys pressed inside a nested control belong to that control.
            if (e.target !== e.currentTarget) return;
            if (e.key !== "Enter" && e.key !== " ") return;
            e.preventDefault();
            onActivate();
        },
    };
}
