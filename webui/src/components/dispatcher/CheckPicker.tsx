import {NumberInput, Select, Stack, TagsInput, TextInput} from "@mantine/core";
import {type DispatcherCheckSpec} from "../../../lib/api";

export function CheckPicker({checks, value, onChange, profileIds, tagNames, disabled}: {
    checks: DispatcherCheckSpec[];
    value: Record<string, unknown>;
    onChange: (c: Record<string, unknown>) => void;
    profileIds: string[];
    tagNames: string[];
    disabled: boolean;
}) {
    const spec = checks.find((c) => c.type === value.type);
    const patch = (p: Record<string, unknown>) => onChange({...value, ...p});
    const text = (name: string) => (typeof value[name] === "string" ? (value[name] as string) : null);
    return (
        <Stack gap="xs">
            <Select
                label="Check"
                data={checks.map((c) => ({value: c.type, label: c.label}))}
                value={text("type")}
                onChange={(v) => onChange({type: v ?? undefined})}
                description={spec?.description}
                searchable
                disabled={disabled}
            />
            {(spec?.params ?? []).map((p) => {
                if (p.type === "tags") {
                    return <TagsInput key={p.name} label={p.label} data={tagNames}
                                      value={Array.isArray(value[p.name]) ? (value[p.name] as string[]) : []}
                                      onChange={(v) => patch({[p.name]: v})} disabled={disabled}/>;
                }
                if (p.name === "profile_id") {
                    return <Select key={p.name} label={p.label} data={profileIds} value={text(p.name)}
                                   onChange={(v) => patch({[p.name]: v ?? undefined})} searchable disabled={disabled}/>;
                }
                if (p.type === "select") {
                    return <Select key={p.name} label={p.label} data={p.options ?? []} value={text(p.name)}
                                   onChange={(v) => patch({[p.name]: v ?? undefined})} disabled={disabled}/>;
                }
                if (p.type === "int") {
                    const n = value[p.name];
                    return <NumberInput key={p.name} label={p.label} value={typeof n === "number" ? n : undefined}
                                        onChange={(v) => patch({[p.name]: v})} disabled={disabled}/>;
                }
                return <TextInput key={p.name} label={p.label} description={p.help} value={String(value[p.name] ?? "")}
                                  onChange={(e) => patch({[p.name]: e.currentTarget.value})} disabled={disabled}/>;
            })}
        </Stack>
    );
}
