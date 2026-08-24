"use client";

// What a route's error boundary renders. A centered dialog rather than a page of text, so a failure
// reads as something that happened to the app rather than as the page the reader asked for. The glass
// surface and radius come from the Modal defaults in lib/theme.ts.
//
// It cannot be dismissed, because behind it is a route that threw and has nothing to show. The only ways
// out are retrying and leaving.

import Link from "next/link";
import {Alert, Button, Code, Group, Modal, Stack, Text, ThemeIcon} from "@mantine/core";
import {IconAlertTriangle, IconRefresh} from "@tabler/icons-react";

export function PageErrorModal({
                                   error,
                                   reset,
                                   homeHref = "/dashboard",
                                   homeLabel = "Back to dashboard",
                                   title = "This page failed to load",
                               }: {
    error: Error & { digest?: string };
    reset: () => void;
    homeHref?: string;
    homeLabel?: string;
    title?: string;
}) {
    return (
        <Modal
            opened
            onClose={reset}
            centered
            size="md"
            withCloseButton={false}
            closeOnClickOutside={false}
            closeOnEscape={false}
            title={
                <Group gap="xs">
                    <ThemeIcon color="red" variant="light" size="sm" radius="xl">
                        <IconAlertTriangle size={14}/>
                    </ThemeIcon>
                    <Text fw={600}>{title}</Text>
                </Group>
            }
        >
            <Stack gap="md">
                <Alert color="red" variant="light">
                    <Text fz="sm" style={{wordBreak: "break-word"}}>
                        {error.message || "No message came with this error."}
                    </Text>
                    {/* A production build redacts the message, leaving this id as the only way to find the
                        error in the server log. */}
                    {error.digest && (
                        <Text fz="xs" c="dimmed" mt={6}>
                            digest <Code fz="xs">{error.digest}</Code>
                        </Text>
                    )}
                </Alert>
                <Group justify="flex-end">
                    <Button component={Link} href={homeHref} variant="default">
                        {homeLabel}
                    </Button>
                    <Button leftSection={<IconRefresh size={16}/>} onClick={reset}>
                        Try again
                    </Button>
                </Group>
            </Stack>
        </Modal>
    );
}
