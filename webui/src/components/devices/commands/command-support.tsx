import {Badge} from "@mantine/core";
import {IconMapPin, IconPower, IconRefresh, IconSettings, IconShieldLock, IconUsers} from "@tabler/icons-react";
import {type CatalogCommand, type Device} from "../../../../lib/api";
import {devicePlatformCategory} from "../../../../lib/config";
import {describeTaskType} from "../../../../lib/task-errors";

export const ADMIN_ROLE_REASON = "Requires the admin role";

// A failed push still stores the command, and the device runs it at its next check-in.
export function withPushStatus(res: { result?: { push_failed?: boolean } }, message: string): string {
    return res.result?.push_failed ? "Queued. The push failed, so the device runs it at its next check-in." : message;
}

// Commands whose confirmation needs more than a parameter form.
export const KNOWN_FLOWS: Record<
    string,
    {
        danger?: boolean; // red alert and confirm button, for a command that destroys data
        serialConfirm?: boolean; // the serial number has to be typed before the command can be sent
        returnToService?: boolean; // the erase modal's re-enroll section
        escrowKind?: string; // the DeviceSecret kind it writes or reads, so the modal can name the stored credential
        ackRestart?: boolean; // an explicit acknowledgement that the Mac restarts
    }
> = {
    restart: {},
    shutdown: {},
    // Clearing an iOS passcode leaves the device unlocked, so it confirms like erase.
    clear_passcode: {danger: true, serialConfirm: true},
    clear_restrictions_password: {},
    lock: {},
    enable_lost_mode: {},
    disable_lost_mode: {},
    delete_user: {danger: true},
    erase: {danger: true, serialConfirm: true, returnToService: true},
    rotate_filevault_key: {escrowKind: "filevault_prk"},
    set_recovery_lock: {escrowKind: "recovery_lock"},
    verify_recovery_lock: {escrowKind: "recovery_lock"},
    set_firmware_password: {escrowKind: "firmware_password", danger: true, ackRestart: true},
    verify_firmware_password: {escrowKind: "firmware_password"},
    fetch_activation_lock_bypass_code: {},
};

export const CATEGORY_ICONS: Record<string, React.FC<{ size?: number }>> = {
    Queries: IconRefresh,
    Power: IconPower,
    Security: IconShieldLock,
    "Lost Mode": IconMapPin,
    Users: IconUsers,
    Management: IconSettings,
};

export function isMac(device: Device) {
    return (device.device_model || "").toLowerCase().includes("mac");
}

// Why Apple will not run this command on this device, or null if it will. Mirrors the server's check, which lets
// through a device that has not reported IsSupervised or IsAppleSilicon yet.
export function unsupportedReason(entry: CatalogCommand, device: Device): string | null {
    const attrs = (device.attributes ?? {}) as Record<string, unknown>;
    const platform = devicePlatformCategory(device.device_model);
    const platforms = entry.platforms;
    if (platforms?.length && platform !== "Other" && !platforms.includes(platform)) {
        return `${entry.label} does not run on ${platform}.`;
    }
    if (attrs.IsSupervised === false) {
        if (entry.supervised) {
            return `${entry.label} only works on a supervised device.`;
        }
        // Some commands need supervision on some platforms only, such as Restart on iOS and tvOS.
        if (entry.supervised_platforms?.includes(platform)) {
            return `${entry.label} only works on a supervised ${platform}.`;
        }
    }
    const wants = entry.apple_silicon;
    const has = attrs.IsAppleSilicon;
    if (typeof wants === "boolean" && typeof has === "boolean" && wants !== has) {
        return (
            `${entry.label} is an ${wants ? "Apple silicon" : "Intel"} command. ` +
            `This Mac reports as ${has ? "Apple silicon" : "Intel"}.`
        );
    }
    return null;
}

// A caution shown in the confirmation that does not block the send. The enrollment date only approximates when the
// device was supervised, so an old enrollment may still return a code.
export function commandWarning(entry: CatalogCommand, device: Device): string | null {
    if (entry.type === "fetch_activation_lock_bypass_code" && device.enrollment_date) {
        const enrolledAt = new Date(device.enrollment_date).getTime();
        if (!Number.isNaN(enrolledAt) && (Date.now() - enrolledAt) / (1000 * 86400) > 15) {
            return (
                "This device enrolled more than 15 days ago. Apple only provides the bypass code within 15 days of " +
                "supervision, so the device may return no code."
            );
        }
    }
    return null;
}

// One-word verdict beside a command's label; the full sentence is the catalog description.
export function reversalBadge(entry: CatalogCommand) {
    if (entry.reversible === false) {
        return <Badge size="xs" color="red" variant="light">permanent</Badge>;
    }
    if (entry.reversible === true) {
        return <Badge size="xs" color="gray" variant="light">reversible</Badge>;
    }
    return null;
}

// created_by is an actor slug (mdm:<command type>, admin:<email>, atc:<flow>). mdm:security_info is the escrow
// profile, which reports the key in SecurityInfo.
export function escrowActorText(createdBy: string, entry: CatalogCommand): string {
    if (createdBy === "mdm:security_info") return "the escrow profile";
    if (createdBy.startsWith("mdm:")) {
        const type = createdBy.slice("mdm:".length);
        return `the ${type === entry.type ? entry.label : describeTaskType(type)} command`;
    }
    return createdBy;
}
