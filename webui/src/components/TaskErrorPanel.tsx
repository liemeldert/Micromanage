"use client";

// A failed task's error as a plain cause, a next step, and a link to the page that fixes it. The original text names
// internal hostnames, so it stays collapsed behind "Technical details".

import {useState} from "react";
import {Alert, Anchor, Box, Code, Group, Text, UnstyledButton} from "@mantine/core";
import {IconAlertTriangle, IconChevronDown, IconChevronRight} from "@tabler/icons-react";
import Link from "next/link";
import {explainError} from "../../lib/task-errors";

function Details({raw}: { raw: string }) {
    const [open, setOpen] = useState(false);
    return (
        <Box mt={6}>
            <UnstyledButton onClick={() => setOpen((o) => !o)}>
                <Group gap={2} wrap="nowrap">
                    {open ? <IconChevronDown size={12}/> : <IconChevronRight size={12}/>}
                    <Text fz="xs" c="dimmed" td="underline">
                        Technical details
                    </Text>
                </Group>
            </UnstyledButton>
            {open && (
                <Code block mt={4} style={{fontSize: 11, whiteSpace: "pre-wrap", wordBreak: "break-word"}}>
                    {raw}
                </Code>
            )}
        </Box>
    );
}

/** Body of an explained error: cause, next step, link, details toggle. */
export function TaskErrorBody({error, prefix}: { error: string | null | undefined; prefix?: string }) {
    const explained = explainError(error);
    if (!explained) return null;
    return (
        <>
            <Text fz="sm">
                {prefix ? <b>{prefix} </b> : null}
                {explained.headline}
            </Text>
            {explained.nextStep && (
                <Text fz="xs" mt={4}>
                    {explained.nextStep}
                </Text>
            )}
            {explained.link && (
                <Anchor component={Link} href={explained.link.href} fz="xs" mt={4} display="inline-block">
                    {explained.link.label}
                </Anchor>
            )}
            {explained.hasDetail && <Details raw={explained.raw}/>}
        </>
    );
}

/** Full-width alert form, for a page banner or a drawer. */
export function TaskErrorPanel({
                                   error,
                                   prefix,
                                   color = "red",
                               }: {
    error: string | null | undefined;
    prefix?: string;
    color?: string;
}) {
    if (!explainError(error)) return null;
    return (
        <Alert color={color} variant="light" icon={<IconAlertTriangle size={16}/>}>
            <TaskErrorBody error={error} prefix={prefix}/>
        </Alert>
    );
}
