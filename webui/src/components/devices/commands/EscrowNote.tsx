import {Alert, Stack, Text} from "@mantine/core";
import {type CatalogCommand, type DeviceSecret, secretLifecycle} from "../../../../lib/api";
import {escrowActorText} from "./command-support";

// The recovery credential already escrowed for this Mac, shown in the lock-command modals to say whether leaving the
// current password blank works.
export function EscrowNote({entry, secret}: { entry: CatalogCommand; secret: DeviceSecret | null }) {
    const setting = entry.type.startsWith("set_");
    // FileVault rotation unlocks with the Mac's current personal recovery key, since a user password fails over MDM.
    const rotating = entry.type === "rotate_filevault_key";
    if (secret === null) {
        return (
            <Alert color="blue" variant="light">
                <Text fz="xs">
                    {rotating
                        ? "No FileVault recovery key is escrowed for this Mac yet. Enter its current " +
                        "recovery key below if somebody holds it; the new key is escrowed and can be revealed " +
                        "from the recovery credentials card. If nobody holds the current key, rotate once on " +
                        "the Mac itself (sudo fdesetup changerecovery -personal) and the escrow " +
                        "profile reports the new key here on the next security refresh."
                        : setting
                            ? "Nothing is escrowed for this Mac yet. The password you set below becomes the " +
                            "escrowed copy, and you read it back by breaking the glass on the Summary " +
                            "or Security tab. " +
                            "Leave Current password blank unless somebody set a lock on this Mac outside " +
                            "Micromanage."
                            : "Nothing is escrowed for this Mac. Type the password you want to verify."}
                </Text>
            </Alert>
        );
    }
    const life = secretLifecycle(secret);
    const when = (ts?: string) => (ts ? new Date(ts).toLocaleString() : "");
    return (
        <Alert color={life.pending_task_id || life.unconfirmed_task_id ? "orange" : "blue"} variant="light">
            <Stack gap={4}>
                <Text fz="xs">
                    {/* Lowercased mid-sentence, except FileVault, which is a brand name. */}
                    Micromanage holds a {secret.kind_label.startsWith("FileVault")
                    ? secret.kind_label
                    : secret.kind_label.toLowerCase()} for this Mac
                    {secret.created_by ? `, set by ${escrowActorText(secret.created_by, entry)}` : ""}
                    {secret.updated_at ? ` on ${when(secret.updated_at)}` : ""}.{" "}
                    {rotating
                        ? "Leave the field blank to unlock the rotation with it; the new key replaces " +
                        "it in escrow."
                        : setting ? "Leave Current password blank to use it." : "Leave the field blank to check it."}
                </Text>
                {life.pending_task_id && (
                    <Text fz="xs" fw={500}>
                        A change is already in progress. A device rejects subsequent commands until it responds to the
                        first one.
                    </Text>
                )}
                {life.unconfirmed_task_id && (
                    <Text fz="xs" fw={500}>
                        The Mac has not acknowledged this password, so it may not work.
                        {life.unconfirmed_reason ? ` ${life.unconfirmed_reason}.` : ""}
                    </Text>
                )}
                {life.verified_at &&
                    <Text fz="xs" c="dimmed">Last verified against the Mac on {when(life.verified_at)}.</Text>}
                {life.verify_failed_at && (
                    <Text fz="xs" fw={500}>
                        It failed verification on {when(life.verify_failed_at)} and does not unlock this Mac.
                    </Text>
                )}
            </Stack>
        </Alert>
    );
}
