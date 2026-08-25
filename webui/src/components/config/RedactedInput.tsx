import {useState} from "react";
import {Button, PasswordInput, Stack, TextInput} from "@mantine/core";

/** Sentinel the controller returns in place of a stored credential. Sending it back unchanged keeps that value. */
export const REDACTED = "***redacted***";

/** Credential field that shows a placeholder for the sentinel and leaves it in the document until someone types. */
export function RedactedInput({
                                  value,
                                  onChange,
                                  password = false,
                                  label,
                                  placeholder,
                                  disabled,
                                  w,
                                  style,
                              }: {
    value: string;
    onChange: (v: string) => void;
    password?: boolean;
    label?: string;
    placeholder?: string;
    disabled?: boolean;
    w?: number | string;
    style?: React.CSSProperties;
}) {
    const [replacing, setReplacing] = useState(false);
    const sealed = value === REDACTED && !replacing;
    const Input = password ? PasswordInput : TextInput;

    return (
        <Stack gap={2} w={w} style={style}>
            <Input
                label={label}
                placeholder={sealed ? "set, leave blank to keep" : placeholder}
                value={sealed ? "" : value}
                disabled={disabled}
                onChange={(e) => {
                    if (value === REDACTED && !replacing) setReplacing(true);
                    onChange(e.currentTarget.value);
                }}
            />
            {replacing && (
                <Button
                    size="compact-xs"
                    variant="subtle"
                    color="gray"
                    w="fit-content"
                    onClick={() => {
                        setReplacing(false);
                        onChange(REDACTED);
                    }}
                >
                    Keep the saved value
                </Button>
            )}
        </Stack>
    );
}
