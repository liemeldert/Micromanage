import {useState} from "react";
import {notifications} from "@mantine/notifications";
import {api, type CatalogCommand, type Device} from "../../../../lib/api";
import {explainError} from "../../../../lib/task-errors";
import {useAuth} from "../../../../lib/auth-context";
import {commandWarning, withPushStatus} from "./command-support";
import {CommandModal} from "./CommandModal";

// Sends a command with no parameters, warning or destructive effect straight away, and opens CommandModal for the rest.
export function useCommandRunner(device: Device, onDispatched: () => void) {
    const {token} = useAuth();
    const [modalEntry, setModalEntry] = useState<CatalogCommand | null>(null);
    const [busyType, setBusyType] = useState<string | null>(null);

    const runOrOpen = async (entry: CatalogCommand) => {
        if (!entry.destructive && entry.params.length === 0 && !commandWarning(entry, device)) {
            if (!token) return;
            setBusyType(entry.type);
            try {
                const res = await api.sendCommand(token, device.id, entry.type, {});
                notifications.show({
                    color: "teal",
                    message: withPushStatus(res, `${entry.label} sent to ${device.serial_number}`),
                });
                onDispatched();
            } catch (e) {
                const raw = (e as Error).message;
                const explained = explainError(raw);
                notifications.show({
                    color: "red",
                    title: "Command failed",
                    message: explained ? `${explained.headline} ${explained.nextStep ?? ""}`.trim() : raw,
                });
            } finally {
                setBusyType(null);
            }
            return;
        }
        setModalEntry(entry);
    };

    const modal = (
        <CommandModal
            device={device}
            entry={modalEntry}
            opened={modalEntry !== null}
            onClose={() => setModalEntry(null)}
            onDone={onDispatched}
        />
    );

    return {runOrOpen, busyType, modal};
}
