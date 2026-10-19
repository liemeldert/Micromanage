import {useMemo, useState} from "react";
import {Button, Code, Group, Modal, Stack, Text} from "@mantine/core";
import {IconDeviceFloppy} from "@tabler/icons-react";
import {type Device} from "../../../lib/api";
import {type App, type AppVersion, type Group as GroupDef, type Rollout, type Scope} from "../../../lib/config";
import {confirmDiscard} from "../../../lib/use-unsaved-changes";
import {RolloutEditor} from "../config/RolloutEditor";
import {ScopeEditor} from "../config/ScopeEditor";

// Edits one version's groups, conditions, device overrides and rollout. The version, key and digest identify the
// package and stay read-only, so new bytes need a new version.
export function VersionScopeModal({
                                      app,
                                      version,
                                      allGroups,
                                      devices,
                                      saving,
                                      onClose,
                                      onSave,
                                  }: {
    app: App;
    version: AppVersion;
    allGroups: GroupDef[];
    devices: Device[];
    saving: boolean;
    onClose: () => void;
    onSave: (scope: Scope, rollout: Rollout | undefined) => Promise<void>;
}) {
    const stored: Scope = useMemo(
        () => ({
            groups: version.groups ?? [],
            conditions: version.conditions ?? [],
            ...(version.include_devices ? {include_devices: version.include_devices} : {}),
            ...(version.exclude_devices ? {exclude_devices: version.exclude_devices} : {}),
        }),
        [version],
    );
    const [scope, setScope] = useState<Scope>(stored);
    const [rollout, setRollout] = useState<Rollout | undefined>(version.rollout);

    const dirty =
        JSON.stringify(scope) !== JSON.stringify(stored) ||
        JSON.stringify(rollout ?? null) !== JSON.stringify(version.rollout ?? null);

    // A version needs at least one group, condition or included device.
    const valid =
        (scope.groups?.length ?? 0) > 0 ||
        (scope.conditions?.length ?? 0) > 0 ||
        (scope.include_devices?.length ?? 0) > 0;

    function requestClose() {
        confirmDiscard({dirty, what: `version ${version.version}`, onConfirm: onClose});
    }

    return (
        <Modal opened onClose={requestClose} size="lg" title={`Edit v${version.version} of ${app.name}`}>
            <Stack gap="md">
                <Stack gap={4}>
                    <Text fz="xs" c="dimmed">
                        Key: <Code fz="xs">{version.s3_key}</Code>
                    </Text>
                    <Text fz="xs" c="dimmed">
                        SHA-256: <Code fz="xs">{version.sha256}</Code>
                    </Text>
                </Stack>
                <ScopeEditor
                    scope={scope}
                    onChange={setScope}
                    devices={devices}
                    allGroups={allGroups}
                    previous={stored}
                    groupsLabel="Install on groups"
                    groupsDescription="Devices in any of these groups receive this version."
                />
                <RolloutEditor rollout={rollout} onChange={setRollout}/>
                <Group justify="space-between" mt="sm">
                    <Button variant="default" onClick={requestClose}>Cancel</Button>
                    <Button
                        leftSection={<IconDeviceFloppy size={16}/>}
                        onClick={() => onSave(scope, rollout)}
                        loading={saving}
                        disabled={!dirty || !valid}
                    >
                        Save version
                    </Button>
                </Group>
            </Stack>
        </Modal>
    );
}
