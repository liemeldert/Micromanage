"use client";

import { useRef, useState } from "react";
import { Combobox, Text, TextInput, useCombobox } from "@mantine/core";
import { NAME_VARIABLES } from "../../../lib/config";

/**
 * A single-line template editor with an inline `{`-triggered variable
 * autocomplete. Typing `{` (optionally followed by a partial name) opens a
 * dropdown of device-state variables filtered by what's been typed; selecting
 * one inserts `{variable}` at the cursor. There is deliberately no always-on
 * palette of every variable -- discovery is the autocomplete; the full list
 * lives in the docs.
 */

interface Props {
  value: string;
  onChange: (next: string) => void;
  label?: string;
  placeholder?: string;
}

// The open-`{` token immediately preceding the cursor, if any: its start index
// and the partial text typed after the brace. Returns null when the cursor
// isn't inside an unclosed variable token (so the dropdown stays shut).
function tokenAtCursor(value: string, cursor: number): { start: number; query: string } | null {
  const before = value.slice(0, cursor);
  const open = before.lastIndexOf("{");
  if (open === -1) return null;
  const seg = before.slice(open + 1);
  // A closed `}` or whitespace between the `{` and the cursor means we're no
  // longer typing a variable name.
  if (/[}\s]/.test(seg)) return null;
  return { start: open, query: seg.toLowerCase() };
}

export function NameTemplateInput({ value, onChange, label, placeholder }: Props) {
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
    const cursor = ref.current.selectionStart ?? value.length;
    // Replace the WHOLE token being edited, not just the text before the caret:
    // consume any remaining variable-name characters after the caret and a
    // single trailing `}` if present. Without this, completing a variable in the
    // middle of an existing `{token}` would orphan its tail (e.g. editing
    // `{ser|ial}` -> `{serial}ial}`).
    let end = cursor;
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
        <Combobox.Options mah={220} style={{ overflowY: "auto" }}>
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
