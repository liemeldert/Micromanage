// Tags on the device identity card: one field holding the tags as pills, the way a search bar holds its query,
// rather than a card of its own. POST /devices/{id}/tags answers with whether group membership moved.
//
// Pills sit inside the input so the control is the size of a field whatever the device is wearing, and adding a
// tag happens where the tags already are. Mantine's TagsInput would be the short way to write this, but it paints
// every pill the same colour; the registry gives each tag its own, which is what makes them scannable.

import {useEffect, useRef, useState} from "react";
import {Combobox, Loader, Pill, PillsInput, Text, useCombobox,} from "@mantine/core";
import {IconTag} from "@tabler/icons-react";
import {modals} from "@mantine/modals";
import {notifications} from "@mantine/notifications";
import {api, type Device} from "../../lib/api";
import {useAuth} from "../../lib/auth-context";
import {useTagRegistry} from "../../lib/config";

export function DeviceTagsField({
                                    device,
                                    onChanged,
                                }: {
    device: Device;
    onChanged?: () => void;
}) {
    const {token} = useAuth();
    const {tagNames, colorOf, labelOf} = useTagRegistry();
    const [tags, setTags] = useState<string[]>(device.tags ?? []);
    const [draft, setDraft] = useState("");
    const [saving, setSaving] = useState(false);
    const combobox = useCombobox({onDropdownClose: () => combobox.resetSelectedOption()});

    // Re-sync from the server copy when its contents change; the array identity changes every
    // render. Skipped while a write is pending so the optimistic value is not clobbered.
    const key = (device.tags ?? []).join(" ");
    const savingRef = useRef(saving);
    savingRef.current = saving;
    const missedSync = useRef(false);
    useEffect(() => {
        if (savingRef.current) {
            missedSync.current = true;
            return;
        }
        setTags(device.tags ?? []);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [key]);
    useEffect(() => {
        if (!saving && missedSync.current) {
            missedSync.current = false;
            setTags(device.tags ?? []);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [saving]);

    const apply = async (add: string[], remove: string[]) => {
        if (!token || saving) return;
        const prev = tags;
        const optimistic = [
            ...tags.filter((t) => !remove.includes(t)),
            ...add.filter((t) => !tags.includes(t)),
        ];
        setTags(optimistic);
        setSaving(true);
        try {
            const res = await api.updateDeviceTags(token, device.id, {add, remove});
            setTags(res.device.tags ?? optimistic);
            if (res.groups_changed) {
                notifications.show({
                    color: "teal",
                    message: "Tags updated; group membership recomputed",
                });
            }
            onChanged?.();
        } catch (e) {
            setTags(prev);
            notifications.show({color: "red", message: (e as Error).message});
        } finally {
            setSaving(false);
        }
    };

    const addTag = (name: string) => {
        const t = name.trim();
        setDraft("");
        combobox.closeDropdown();
        if (t && !tags.includes(t)) apply([t], []);
    };

    // A tag can be what puts this device in a group, so removing one can pull profiles and apps
    // off the device.
    const confirmRemove = (t: string) =>
        modals.openConfirmModal({
            title: "Remove tag",
            children: (
                <Text size="sm">
                    Remove <b>{labelOf(t)}</b> from this device? Groups that match on this tag drop the
                    device, and the profiles and apps they scope come off with it.
                </Text>
            ),
            labels: {confirm: "Remove", cancel: "Cancel"},
            confirmProps: {color: "red"},
            onConfirm: () => apply([], [t]),
        });

    const suggestions = tagNames
        .filter((n) => !tags.includes(n))
        .filter((n) => n.toLowerCase().includes(draft.trim().toLowerCase()));

    return (
        <Combobox store={combobox} withinPortal onOptionSubmit={addTag}>
            <Combobox.DropdownTarget>
                <PillsInput
                    size="xs"
                    disabled={saving}
                    // The icon sits inside the field rather than above it, pinned to the first line, so the field
                    // grows downward as tags wrap and the icon stays where it was. What tags are for is on the
                    // Tags settings page; it does not need restating on every device.
                    leftSection={saving ? <Loader size={11}/> : <IconTag size={14}/>}
                    leftSectionProps={{style: {alignItems: "flex-start", paddingTop: 7}}}
                    leftSectionPointerEvents="none"
                    onClick={() => combobox.openDropdown()}
                >
                    <Pill.Group>
                        {tags.map((t) => (
                            <Pill
                                key={t}
                                withRemoveButton
                                disabled={saving}
                                onRemove={() => confirmRemove(t)}
                                style={{
                                    // The registry colour, mixed into the field's own surface rather than painted
                                    // over it, so a pill reads as part of the control it sits in.
                                    backgroundColor: colorOf(t)
                                        ? `color-mix(in srgb, var(--mantine-color-${colorOf(t)}-6) 18%, transparent)`
                                        : undefined,
                                    color: colorOf(t)
                                        ? `var(--mantine-color-${colorOf(t)}-9)`
                                        : undefined,
                                }}
                            >
                                {labelOf(t)}
                            </Pill>
                        ))}
                        <Combobox.EventsTarget>
                            <PillsInput.Field
                                value={draft}
                                placeholder={tags.length ? "" : "Add a tag"}
                                onChange={(event) => {
                                    combobox.openDropdown();
                                    combobox.updateSelectedOptionIndex();
                                    setDraft(event.currentTarget.value);
                                }}
                                onFocus={() => combobox.openDropdown()}
                                onBlur={() => combobox.closeDropdown()}
                                onKeyDown={(event) => {
                                    if (event.key === "Enter") {
                                        event.preventDefault();
                                        addTag(draft);
                                        return;
                                    }
                                    // Backspace on an empty field takes the last tag off, which is what every
                                    // other pill field does. It still asks first.
                                    if (event.key === "Backspace" && draft.length === 0 && tags.length) {
                                        event.preventDefault();
                                        confirmRemove(tags[tags.length - 1]);
                                    }
                                }}
                            />
                        </Combobox.EventsTarget>
                    </Pill.Group>
                </PillsInput>
            </Combobox.DropdownTarget>

            <Combobox.Dropdown>
                <Combobox.Options>
                    {suggestions.length > 0 ? (
                        suggestions.map((n) => (
                            <Combobox.Option value={n} key={n}>
                                <Text fz="xs">{labelOf(n)}</Text>
                            </Combobox.Option>
                        ))
                    ) : (
                        <Combobox.Empty>
                            {draft.trim() ? "Press Enter to add it" : "Every tag is already on this device"}
                        </Combobox.Empty>
                    )}
                </Combobox.Options>
            </Combobox.Dropdown>
        </Combobox>
    );
}
