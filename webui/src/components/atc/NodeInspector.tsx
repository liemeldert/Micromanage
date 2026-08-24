"use client";

import {useState} from "react";
import {
    ActionIcon,
    Alert,
    Badge,
    Button,
    Divider,
    Group,
    MultiSelect,
    NumberInput,
    PasswordInput,
    Select,
    Stack,
    Switch,
    TagsInput,
    Text,
    TextInput,
} from "@mantine/core";
import {IconInfoCircle, IconPlus, IconTrash} from "@tabler/icons-react";
import type {CatalogCommand, Device, FlowNode, FlowNodeSpec, StartKind, WaitSignal,} from "../../../lib/api";
import type {Condition, Group as GroupDef, Scope} from "../../../lib/config";
import {ConditionBuilder} from "../config/ConditionBuilder";
import {NameTemplateInput} from "../config/NameTemplateInput";
import {REDACTED} from "../config/RedactedInput";
import {ScopeEditor} from "../config/ScopeEditor";

const GATE_EDGES = [
    {value: "on_release", label: "on_release"},
    {value: "on_cancel", label: "on_cancel"},
    {value: "on_wait", label: "on_wait"},
];

// GET /api/v1/config/flows returns the REDACTED sentinel in place of every stored static password, and PUT swaps it
// back for the saved value. Rendered into the field as it arrives, it would read as a password of ***redacted***.

/** Static-password field that shows the saved password as unchanged rather than as the sentinel. */
function SecretParamInput({
                              label,
                              value,
                              onChange,
                          }: {
    label: string;
    value: unknown;
    onChange: (v: string) => void;
}) {
    const stored = typeof value === "string" ? value : "";
    // A stored password shows as an empty field until someone types. Leaving it empty keeps the sentinel in the
    // document, so the server restores the saved value.
    const [replacing, setReplacing] = useState(false);
    const sealed = stored === REDACTED && !replacing;

    return (
        <Stack gap={4}>
            <PasswordInput
                label={label}
                placeholder={sealed ? "unchanged" : undefined}
                description={
                    sealed
                        ? "A password is saved for this step. Leave this blank to keep it, or type a new one to replace it."
                        : undefined
                }
                value={sealed ? "" : stored}
                onChange={(e) => {
                    const next = e.currentTarget.value;
                    if (stored === REDACTED && !replacing) setReplacing(true);
                    onChange(next);
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
                        onChange(REDACTED); // put the sentinel back: keep the stored password
                    }}
                >
                    Keep the saved password instead
                </Button>
            )}
        </Stack>
    );
}

/** The opt-out on a step that the release barrier waits for. Label and help come from the step catalog, so the
 * editor shows the same wording the server publishes. The switch renders even when a node's spec carries no gate
 * param, since an author left without the control has to hand-edit flows.yaml.
 *
 * An absent key means the barrier waits and only a literal false opts out, so turning the wait back on writes
 * undefined and drops the key rather than leaving gate: true in the document. */
function GateSwitch({
                        spec,
                        p,
                        patch,
                    }: {
    spec?: FlowNodeSpec;
    p: Record<string, unknown>;
    patch: (next: Record<string, unknown>) => void;
}) {
    const gateSpec = spec?.params.find((x) => x.name === "gate");
    return (
        <Switch
            label={gateSpec?.label ?? "Wait for this before releasing the device"}
            description={gateSpec?.help}
            checked={p.gate !== false}
            onChange={(e) => patch({gate: e.currentTarget.checked ? undefined : false})}
        />
    );
}

/** Per-node parameter editor for the ATC flow canvas. Reuses the condition and naming builders, so scope and naming
 * are edited here the same way as everywhere else in the console. */
export function NodeInspector({
                                  node,
                                  spec,
                                  onChange,
                                  tagNames,
                                  profileIds,
                                  appIds,
                                  commands,
                                  groupNames,
                                  devices,
                                  allGroups,
                                  startKinds,
                              }: {
    node: FlowNode;
    spec?: FlowNodeSpec;
    onChange: (params: Record<string, unknown>) => void;
    tagNames: string[];
    profileIds: string[];
    appIds: string[];
    commands: CatalogCommand[];
    groupNames: string[];
    devices: Device[];
    allGroups: GroupDef[];
    startKinds: StartKind[];
}) {
    const p = node.params ?? {};
    const patch = (next: Record<string, unknown>) => onChange({...p, ...next});
    const asList = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : []);

    const waitSignals: WaitSignal[] = (spec?.params.find((x) => x.type === "signal")?.options ??
        []) as WaitSignal[];

    // Only non-destructive commands may be used as a flow step (server enforces it too).
    const commandOptions = commands
        .filter((c) => !c.destructive)
        .map((c) => ({value: c.type, label: c.label}));
    const selectedCommand = commands.find((c) => c.type === p.command);

    return (
        <Stack gap="sm">
            {spec && (
                <Text fz="xs" c="dimmed">
                    {spec.description}
                </Text>
            )}

            {node.type === "start" && (
                <Stack gap="xs">
                    <Select
                        label="Trigger"
                        data={startKinds.map((k) => ({value: k.value, label: k.label}))}
                        value={typeof p.kind === "string" ? p.kind : null}
                        onChange={(v) => patch({kind: v ?? undefined})}
                    />
                    {typeof p.kind === "string" && p.kind ? (
                        <Text fz="xs" c="dimmed">
                            {startKinds.find((k) => k.value === p.kind)?.description}
                        </Text>
                    ) : null}
                    {p.kind === "schedule" && (
                        <NumberInput
                            label="Interval (minutes)"
                            description="How often this start fires for in-scope devices."
                            min={1}
                            value={typeof p.interval_minutes === "number" ? p.interval_minutes : 1440}
                            onChange={(v) => patch({interval_minutes: typeof v === "number" ? v : 1440})}
                        />
                    )}
                    <Divider my={4} label="Applies to" labelPosition="left"/>
                    <ScopeEditor
                        scope={(p.match ?? {}) as Scope}
                        onChange={(m) => patch({match: m as Record<string, unknown>})}
                        devices={devices}
                        allGroups={allGroups}
                        groupsLabel="Applies to groups"
                        groupsDescription="Empty applies to every device of this trigger kind."
                        emptyMatchesAll
                        emptyAllLabel="every device of this trigger kind"
                    />
                </Stack>
            )}

            {node.type === "manual_gate" && (
                <GateInspector p={p} patch={patch}/>
            )}

            {(node.type === "assign_tag" || node.type === "remove_tag") && (
                <TagsInput
                    label={node.type === "assign_tag" ? "Tags to add" : "Tags to remove"}
                    description="Registry tags are suggested; free-form tags are allowed."
                    placeholder="Type a tag and press Enter"
                    data={tagNames}
                    value={asList(p.tags)}
                    onChange={(v) => patch({tags: v})}
                    clearable
                />
            )}

            {node.type === "set_name" && (
                <NameTemplateInput
                    value={String(p.template ?? "")}
                    onChange={(t) => patch({template: t})}
                    label="Name template"
                    placeholder="IT-{serial}"
                />
            )}

            {node.type === "install_profiles" && (
                <Stack gap="xs">
                    <MultiSelect
                        label="Profiles"
                        description="Installed now (imperative). Scope the profile to keep it maintained."
                        placeholder={profileIds.length ? "Select profiles" : "No profiles defined"}
                        data={profileIds}
                        value={asList(p.profile_ids)}
                        onChange={(v) => patch({profile_ids: v})}
                        searchable
                    />
                    <GateSwitch spec={spec} p={p} patch={patch}/>
                </Stack>
            )}

            {node.type === "install_apps" && (
                <Stack gap="xs">
                    <MultiSelect
                        label="Apps"
                        description="Installs the version the device is entitled to (apps.yaml scoping)."
                        placeholder={appIds.length ? "Select apps" : "No apps defined"}
                        data={appIds}
                        value={asList(p.app_ids)}
                        onChange={(v) => patch({app_ids: v})}
                        searchable
                    />
                    <GateSwitch spec={spec} p={p} patch={patch}/>
                </Stack>
            )}

            {node.type === "sync_declarations" && <GateSwitch spec={spec} p={p} patch={patch}/>}

            {node.type === "send_command" && (
                <Stack gap="xs">
                    <Select
                        label="Command"
                        placeholder="Select a command"
                        data={commandOptions}
                        value={typeof p.command === "string" ? p.command : null}
                        onChange={(v) => patch({command: v ?? undefined, params: {}})}
                        searchable
                    />
                    {selectedCommand && selectedCommand.params.length > 0 && (
                        <CommandParamsForm
                            command={selectedCommand}
                            value={(p.params as Record<string, unknown>) ?? {}}
                            onChange={(cp) => patch({params: cp})}
                        />
                    )}
                    <GateSwitch spec={spec} p={p} patch={patch}/>
                    <Alert variant="light" color="gray" p="xs" icon={<IconInfoCircle size={14}/>}>
                        Destructive commands (erase, lock, …) can never run from an automated flow.
                    </Alert>
                </Stack>
            )}

            {node.type === "branch" && (
                <div>
                    <Text fz="sm" fw={500} mb={4}>
                        Condition (takes the <b>true</b> edge when it matches, else <b>false</b>)
                    </Text>
                    <ConditionBuilder
                        conditions={p.condition ? [p.condition as Condition] : []}
                        onChange={(list) => patch({condition: list[0] ?? undefined})}
                        groupNames={groupNames}
                        tagNames={tagNames}
                        emptyHint="Add the condition to branch on."
                    />
                </div>
            )}

            {node.type === "wait_for" && (
                <Stack gap="xs">
                    <Select
                        label="Wait for signal"
                        data={waitSignals.map((s) => ({value: s.value, label: s.label}))}
                        value={typeof p.signal === "string" ? p.signal : null}
                        onChange={(v) => patch({signal: v ?? undefined})}
                    />
                    {typeof p.signal === "string" && p.signal ? (
                        <Text fz="xs" c="dimmed">
                            {waitSignals.find((s) => s.value === p.signal)?.description}
                        </Text>
                    ) : null}
                    <NumberInput
                        label="Timeout (minutes)"
                        description="After this, the timeout edge is taken (or the run fails)."
                        min={1}
                        value={typeof p.timeout_minutes === "number" ? p.timeout_minutes : 60}
                        onChange={(v) => patch({timeout_minutes: typeof v === "number" ? v : 60})}
                    />
                    <GateSwitch spec={spec} p={p} patch={patch}/>
                </Stack>
            )}

            {node.type === "configure_accounts" && (
                <Stack gap="xs">
                    <Select
                        label="User account prompt"
                        description="What the user is asked to create during Setup Assistant."
                        data={[
                            {value: "prompt_admin", label: "Prompt to create an Admin account"},
                            {value: "prompt_standard", label: "Prompt to create a Standard account"},
                            {value: "skip", label: "Don't prompt (skip account creation)"},
                        ]}
                        value={typeof p.primary_account === "string" ? p.primary_account : null}
                        onChange={(v) => patch({primary_account: v ?? undefined})}
                    />
                    <Switch
                        label="Lock the account fields"
                        description="The pre-filled name / short name can't be edited by the user."
                        checked={p.lock_primary_account === true}
                        onChange={(e) => patch({lock_primary_account: e.currentTarget.checked})}
                    />
                    <Group grow>
                        <TextInput
                            label="Pre-fill full name"
                            value={typeof p.primary_full_name === "string" ? p.primary_full_name : ""}
                            onChange={(e) => patch({primary_full_name: e.currentTarget.value || undefined})}
                        />
                        <TextInput
                            label="Pre-fill short name"
                            value={typeof p.primary_short_name === "string" ? p.primary_short_name : ""}
                            onChange={(e) => patch({primary_short_name: e.currentTarget.value || undefined})}
                        />
                    </Group>
                    <Divider label="Managed admin" labelPosition="left" my={2}/>
                    <Switch
                        label="Create a hidden MDM-managed admin"
                        description="Its password is escrowed for break-glass recovery."
                        checked={p.managed_admin === true}
                        onChange={(e) => patch({managed_admin: e.currentTarget.checked})}
                    />
                    {p.managed_admin === true && (
                        <>
                            <Group grow>
                                <TextInput
                                    label="Short name"
                                    placeholder="mmadmin"
                                    value={typeof p.managed_admin_shortname === "string" ? p.managed_admin_shortname : ""}
                                    onChange={(e) => patch({managed_admin_shortname: e.currentTarget.value || undefined})}
                                />
                                <TextInput
                                    label="Full name"
                                    placeholder="Managed Admin"
                                    value={typeof p.managed_admin_fullname === "string" ? p.managed_admin_fullname : ""}
                                    onChange={(e) => patch({managed_admin_fullname: e.currentTarget.value || undefined})}
                                />
                            </Group>
                            <Switch
                                label="Hide the account"
                                description="Hidden from the login window and Users list."
                                checked={p.managed_admin_hidden !== false}
                                onChange={(e) => patch({managed_admin_hidden: e.currentTarget.checked})}
                            />
                            <Select
                                label="Password"
                                data={[
                                    {value: "generate", label: "Auto-generate & escrow"},
                                    {value: "static", label: "Use the value entered below"},
                                ]}
                                value={
                                    typeof p.managed_admin_password_source === "string"
                                        ? p.managed_admin_password_source
                                        : "generate"
                                }
                                onChange={(v) => patch({managed_admin_password_source: v ?? "generate"})}
                            />
                            {p.managed_admin_password_source === "static" && (
                                <SecretParamInput
                                    label="Static password"
                                    value={p.managed_admin_password}
                                    onChange={(v) => patch({managed_admin_password: v})}
                                />
                            )}
                        </>
                    )}
                    <Alert variant="light" color="gray" icon={<IconInfoCircle size={16}/>}>
                        Only applies while an automatically enrolled Mac is held in Setup Assistant (needs the
                        enrollment
                        profile&apos;s &quot;Await device configured&quot;). Place this <b>before</b>{" "}
                        Release from Setup Assistant.
                    </Alert>
                </Stack>
            )}

            {node.type === "set_firmware_lock" && (
                <Stack gap="xs">
                    <Select
                        label="Password"
                        data={[
                            {value: "generate", label: "Auto-generate & escrow"},
                            {value: "static", label: "Use the value entered below"},
                        ]}
                        value={typeof p.password_source === "string" ? p.password_source : null}
                        onChange={(v) => patch({password_source: v ?? undefined})}
                    />
                    {p.password_source === "static" && (
                        <SecretParamInput
                            label="Static password"
                            value={p.password}
                            onChange={(v) => patch({password: v})}
                        />
                    )}
                    <Alert variant="light" color="gray" icon={<IconInfoCircle size={16}/>}>
                        Apple silicon → Recovery Lock; Intel → EFI firmware password. Requires
                        supervision. The password is escrowed for break-glass recovery.
                    </Alert>
                </Stack>
            )}

            {node.type === "end" && (
                <Text fz="sm" c="dimmed">
                    Terminal node. The run completes when it reaches an end.
                </Text>
            )}

            <Divider my={4}/>
            <Group gap={6}>
                <Text fz="xs" c="dimmed">
                    Node id
                </Text>
                <Badge variant="light" size="sm">
                    {node.id}
                </Badge>
            </Group>
        </Stack>
    );
}

interface GateOption {
    label: string;
    edge: string;
}

function GateInspector({
                           p,
                           patch,
                       }: {
    p: Record<string, unknown>;
    patch: (next: Record<string, unknown>) => void;
}) {
    const options: GateOption[] = Array.isArray(p.options)
        ? (p.options as GateOption[]).map((o) => ({
            label: String(o?.label ?? ""),
            edge: String(o?.edge ?? "on_release")
        }))
        : [];

    const setOptions = (next: GateOption[]) => patch({options: next});
    const updateOption = (i: number, next: Partial<GateOption>) =>
        setOptions(options.map((o, idx) => (idx === i ? {...o, ...next} : o)));

    return (
        <Stack gap="xs">
            <TextInput
                label="Alert summary"
                placeholder="Device stuck in setup > 30m"
                value={String(p.summary ?? "")}
                onChange={(e) => patch({summary: e.currentTarget.value})}
            />
            <Select
                label="Severity"
                data={["green", "yellow", "red", "black"]}
                value={typeof p.severity === "string" ? p.severity : "yellow"}
                onChange={(v) => patch({severity: v ?? "yellow"})}
            />
            <Text fz="sm" fw={500} mt={4}>
                Decision options
            </Text>
            <Text fz="xs" c="dimmed">
                Each option is a button on the alert; picking it resumes the run down that edge.
            </Text>
            {options.map((o, i) => (
                <Group key={i} gap={6} wrap="nowrap" align="flex-end">
                    <TextInput
                        style={{flex: 1}}
                        size="xs"
                        label={i === 0 ? "Label" : undefined}
                        placeholder="Release device from setup"
                        value={o.label}
                        onChange={(e) => updateOption(i, {label: e.currentTarget.value})}
                    />
                    <Select
                        w={130}
                        size="xs"
                        label={i === 0 ? "Edge" : undefined}
                        data={GATE_EDGES}
                        value={o.edge}
                        onChange={(v) => updateOption(i, {edge: v ?? "on_release"})}
                    />
                    <ActionIcon
                        variant="subtle"
                        color="red"
                        onClick={() => setOptions(options.filter((_, idx) => idx !== i))}
                    >
                        <IconTrash size={16}/>
                    </ActionIcon>
                </Group>
            ))}
            <Button
                size="compact-xs"
                variant="light"
                leftSection={<IconPlus size={14}/>}
                onClick={() => setOptions([...options, {label: "", edge: "on_wait"}])}
                w="fit-content"
            >
                Add option
            </Button>
            <Alert variant="light" color="gray" p="xs" icon={<IconInfoCircle size={14}/>}>
                The run pauses here until an admin picks an option on the alert board.
            </Alert>
        </Stack>
    );
}

function CommandParamsForm({
                               command,
                               value,
                               onChange,
                           }: {
    command: CatalogCommand;
    value: Record<string, unknown>;
    onChange: (v: Record<string, unknown>) => void;
}) {
    return (
        <Stack gap={6}>
            {command.params.map((param) => (
                <TextInput
                    key={param.name}
                    size="xs"
                    label={param.label}
                    required={param.required === true}
                    description={
                        param.secret
                            ? "Avoid secrets here. flows.yaml is stored in plain text and versioned."
                            : param.help
                    }
                    value={String(value[param.name] ?? "")}
                    onChange={(e) => onChange({...value, [param.name]: e.currentTarget.value})}
                />
            ))}
        </Stack>
    );
}
