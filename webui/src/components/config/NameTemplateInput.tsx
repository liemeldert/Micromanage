import {useRef, useState} from "react";
import {Combobox, Text, TextInput, useCombobox} from "@mantine/core";
import {NAME_VARIABLES} from "../../../lib/config";

/**
 * Single-line template editor with inline variable autocomplete. Typing an opening brace, optionally followed by a
 * partial name, opens a dropdown of device-state variables filtered by what has been typed; picking one inserts the
 * braced variable at the cursor.
 * There is deliberately no always-on palette of every variable: the autocomplete is the discovery
 * mechanism, and the full list lives in the docs.
 */

interface Props {
    value: string;
    onChange: (next: string) => void;
    label?: string;
    placeholder?: string;
}

// The unclosed variable token immediately before the cursor: its start index and the partial name typed after the
// brace. Null when the cursor is not inside one, which keeps the dropdown shut.
function tokenAtCursor(value: string, cursor: number): { start: number; query: string } | null {
    const before = value.slice(0, cursor);
    const open = before.lastIndexOf("{");
    if (open === -1) return null;
    const seg = before.slice(open + 1);
    // A closing brace or whitespace before the cursor means a variable name is no longer being typed.
    if (/[}\s]/.test(seg)) return null;
    return {start: open, query: seg.toLowerCase()};
}

export function NameTemplateInput({value, onChange, label, placeholder}: Props) {
    const ref = useRef<HTMLInputElement>(null);
    const [token, setToken] = useState<{ start: number; query: string } | null>(null);
    const combobox = useCombobox({
        onDropdownClose: () => combobox.resetSelectedOption(),
    });

    const options = token
        ? NAME_VARIABLES.filter((v) => v.key.toLowerCase().includes(token.query))
        : [];

    function refresh(next: string, cursor: number) {
        const t = tokenAtCursor(next, cursor);
        setToken(t);
        if (t && NAME_VARIABLES.some((v) => v.key.toLowerCase().includes(t.query))) {
            combobox.openDropdown();
            combobox.updateSelectedOptionIndex();
        } else {
            combobox.closeDropdown();
        }
    }

    function handleChange(next: string) {
        onChange(next);
        refresh(next, ref.current?.selectionStart ?? next.length);
    }

    function insert(key: string) {
        if (!token || !ref.current) return;
        let end = ref.current.selectionStart ?? value.length;
        while (end < value.length && /[^{}\s]/.test(value[end])) end += 1;
        if (value[end] === "}") end += 1;
        const before = value.slice(0, token.start);
        const after = value.slice(end);
        const chunk = `{${key}}`;
        const next = `${before}${chunk}${after}`;
        onChange(next);
        setToken(null);
        combobox.closeDropdown();
        // Restore focus and drop the caret just after the inserted variable.
        const caret = before.length + chunk.length;
        requestAnimationFrame(() => {
            ref.current?.focus();
            ref.current?.setSelectionRange(caret, caret);
        });
    }

    return (
        <Combobox store={combobox} withinPortal={false} onOptionSubmit={insert}>
            <Combobox.Target>
                <TextInput
                    ref={ref}
                    label={label}
                    placeholder={placeholder}
                    value={value}
                    onChange={(e) => handleChange(e.currentTarget.value)}
                    onClick={(e) => refresh(value, e.currentTarget.selectionStart ?? value.length)}
                    onKeyUp={(e) => {
                        // Arrow keys move the caret without changing the value; keep the
                        // token state in sync so the dropdown reflects the caret position.
                        if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
                            refresh(value, e.currentTarget.selectionStart ?? value.length);
                        }
                    }}
                    onKeyDown={(e) => {
                        if (!combobox.dropdownOpened) return;
                        if (e.key === "ArrowDown") {
                            e.preventDefault();
                            combobox.selectNextOption();
                        } else if (e.key === "ArrowUp") {
                            e.preventDefault();
                            combobox.selectPreviousOption();
                        } else if (e.key === "Enter") {
                            // Take the highlighted option instead of submitting the form.
                            e.preventDefault();
                            combobox.clickSelectedOption();
                        } else if (e.key === "Escape") {
                            e.preventDefault();
                            combobox.closeDropdown();
                        }
                    }}
                    onBlur={() => combobox.closeDropdown()}
                />
            </Combobox.Target>
            <Combobox.Dropdown>
                <Combobox.Options mah={220} style={{overflowY: "auto"}}>
                    {options.length === 0 ? (
                        <Combobox.Empty>No matching variables</Combobox.Empty>
                    ) : (
                        options.map((v) => (
                            <Combobox.Option value={v.key} key={v.key}>
                                <Text fz="sm" ff="monospace">{`{${v.key}}`}</Text>
                                <Text fz="xs" c="dimmed">
                                    {v.description}
                                </Text>
                            </Combobox.Option>
                        ))
                    )}
                </Combobox.Options>
            </Combobox.Dropdown>
        </Combobox>
    );
}
