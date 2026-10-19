import {
    ActionIcon,
    Badge,
    Button,
    Group,
    MultiSelect,
    Paper,
    Select,
    Stack,
    Switch,
    TagsInput,
    Text,
    Tooltip,
    UnstyledButton,
} from "@mantine/core";
import {modals} from "@mantine/modals";
import {IconAlertTriangle, IconPlus, IconTrash} from "@tabler/icons-react";
import {type CatalogCommand, type DispatcherAction, type DispatcherWebhook} from "../../../lib/api";

const REMEDIATION_TYPES = new Set(["install_profiles", "install_apps", "send_command"]);
const ACTION_TYPES = ["webhook", "assign_tag", "remove_tag", "install_profiles", "install_apps", "send_command"];

export function ActionsEditor({
                                  actions,
                                  onChange,
                                  webhooks,
                                  tagNames,
                                  profileIds,
                                  appIds,
                                  commands,
                                  disabled,
                                  onEditWebhooks
                              }: {
    actions: DispatcherAction[];
    onChange: (a: DispatcherAction[]) => void;
    webhooks: DispatcherWebhook[];
    tagNames: string[];
    profileIds: string[];
    appIds: string[];
    commands: CatalogCommand[];
    disabled: boolean;
    onEditWebhooks: () => void;
}) {
    const patch = (i: number, p: Partial<DispatcherAction>) =>
        onChange(actions.map((a, j) => (i === j ? {...a, ...p} : a)));
    const setParams = (i: number, params: Record<string, unknown>) => patch(i, {params});
    const commandOptions = commands.map((c) => ({
        value: c.type,
        label: `${c.label}${c.destructive ? " (destructive)" : ""}`,
    }));
    return (
        <Stack gap="xs">
            {actions.map((a, i) => {
                const p = a.params ?? {};
                const cmd = commands.find((c) => c.type === p.command);
                const isDestructive = a.type === "send_command" && cmd?.destructive;
                return (
                    <Paper key={i} withBorder radius="sm" p="xs">
                        <Group justify="space-between" mb={6}>
                            <Group gap="xs">
                                <Select
                                    size="xs"
                                    data={ACTION_TYPES}
                                    value={a.type}
                                    onChange={(v) => {
                                        const type = v ?? "webhook";
                                        // Remediations start in dry run, written out as the server reads a missing
                                        // dry_run as false.
                                        patch(i, {
                                            type,
                                            params: {},
                                            dry_run: REMEDIATION_TYPES.has(type) ? true : undefined,
                                        });
                                    }}
                                    w={160}
                                    disabled={disabled}
                                />
                                {REMEDIATION_TYPES.has(a.type) && (
                                    <Switch size="xs" label="Dry run" checked={Boolean(a.dry_run)}
                                            onChange={(e) => patch(i, {dry_run: e.currentTarget.checked})}
                                            disabled={disabled}/>
                                )}
                                {isDestructive && (
                                    <Tooltip
                                        label={
                                            "Destructive commands never run on their own; they require admin " +
                                            "approval on the alert."
                                        }
                                        multiline w={240}>
                                        <Badge color="orange" variant="light"
                                               leftSection={<IconAlertTriangle size={12}/>}>
                                            approval required
                                        </Badge>
                                    </Tooltip>
                                )}
                            </Group>
                            <ActionIcon
                                variant="subtle"
                                color="red"
                                disabled={disabled}
                                aria-label="Remove action"
                                onClick={() =>
                                    modals.openConfirmModal({
                                        title: "Remove action",
                                        children: (
                                            <Text size="sm">
                                                Remove the <b>{a.type}</b> action? The rule keeps evaluating without
                                                it.
                                            </Text>
                                        ),
                                        labels: {confirm: "Remove", cancel: "Cancel"},
                                        confirmProps: {color: "red"},
                                        onConfirm: () => onChange(actions.filter((_, j) => j !== i)),
                                    })
                                }
                            >
                                <IconTrash size={14}/>
                            </ActionIcon>
                        </Group>

                        {a.type === "webhook" && (
                            <Select
                                size="xs"
                                label="Target"
                                data={webhooks.map((w) => w.name)}
                                value={typeof p.target === "string" ? (p.target as string) : null}
                                onChange={(v) => setParams(i, {target: v ?? undefined})}
                                disabled={disabled}
                                placeholder={webhooks.length ? "Select a target" : "No targets yet"}
                                description={
                                    webhooks.length ? undefined : (
                                        <UnstyledButton onClick={onEditWebhooks} fz="xs" c="blue">
                                            Add a webhook target first
                                        </UnstyledButton>
                                    )
                                }
                            />
                        )}
                        {(a.type === "assign_tag" || a.type === "remove_tag") && (
                            <TagsInput size="xs" label="Tags" data={tagNames}
                                       value={Array.isArray(p.tags) ? (p.tags as string[]) : []}
                                       onChange={(v) => setParams(i, {tags: v})} disabled={disabled}/>
                        )}
                        {a.type === "install_profiles" && (
                            <MultiSelect size="xs" label="Profiles" data={profileIds}
                                         value={Array.isArray(p.profile_ids) ? (p.profile_ids as string[]) : []}
                                         onChange={(v) => setParams(i, {profile_ids: v})} searchable
                                         disabled={disabled}/>
                        )}
                        {a.type === "install_apps" && (
                            <MultiSelect size="xs" label="Apps" data={appIds}
                                         value={Array.isArray(p.app_ids) ? (p.app_ids as string[]) : []}
                                         onChange={(v) => setParams(i, {app_ids: v})} searchable disabled={disabled}/>
                        )}
                        {a.type === "send_command" && (
                            <Select size="xs" label="Command" data={commandOptions}
                                    value={typeof p.command === "string" ? (p.command as string) : null}
                                    onChange={(v) => setParams(i, {command: v ?? undefined})} searchable
                                    disabled={disabled}/>
                        )}
                    </Paper>
                );
            })}
            <Button size="compact-xs" variant="light" leftSection={<IconPlus size={14}/>} disabled={disabled}
                    onClick={() => onChange([...actions, {type: "webhook", params: {}}])}>
                Add action
            </Button>
            <Text fz="xs" c="dimmed">
                A new remediation action starts in dry run: it records what it would have done and leaves the
                device alone until you turn dry run off.
            </Text>
        </Stack>
    );
}
