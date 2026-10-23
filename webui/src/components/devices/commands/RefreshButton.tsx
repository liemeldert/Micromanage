import {useState} from "react";
import {Button} from "@mantine/core";
import {notifications} from "@mantine/notifications";
import {IconRefresh} from "@tabler/icons-react";
import {api, type CatalogCommand, type Device} from "../../../../lib/api";
import {withPushStatus} from "./command-support";

// Runs one contextual command, such as an inventory refresh, from the tab whose data it updates.
export function RefreshButton({
                                  device,
                                  catalog,
                                  commandType,
                                  label,
                                  size = "xs",
                                  variant = "light",
                                  disabled = false,
                                  onDispatched,
                              }: {
    device: Device;
    catalog: CatalogCommand[];
    commandType: string;
    label?: string;
    size?: string;
    variant?: string;
    disabled?: boolean;
    onDispatched: () => void;
}) {
    const [busy, setBusy] = useState(false);
    const entry = catalog.find((c) => c.type === commandType);
    if (!entry) return null;

    const run = async () => {
        setBusy(true);
        try {
            const res = await api.sendCommand(device.id, commandType, {});
            notifications.show({
                color: "teal",
                message: withPushStatus(res, `${entry.label} requested. Updates when the device responds.`),
            });
            onDispatched();
        } catch (e) {
            notifications.show({color: "red", title: "Command failed", message: (e as Error).message});
        } finally {
            setBusy(false);
        }
    };

    return (
        <Button size={size} variant={variant} leftSection={<IconRefresh size={14}/>}
                loading={busy} disabled={disabled} onClick={run}>
            {label ?? "Refresh"}
        </Button>
    );
}
