"use client";

// Apple Declarative Device Management (DDM): the tenant's authored declarations.yaml, summarized read-only here.
// Editing happens in the raw YAML editor, since declarations are authored as Apple's structured declaration JSON.

import {useEffect, useState} from "react";
import {useRouter} from "next/navigation";
import {Alert, Badge, Button, Code, Group, Stack, Text, Tooltip,} from "@mantine/core";
import {IconAlertTriangle, IconFileDescription, IconInfoCircle, IconPencil} from "@tabler/icons-react";
import Link from "next/link";
import {api, ApiError, type DeclarationSummary, type TenantInfo} from "../../../../lib/api";
import {useAuth} from "../../../../lib/auth-context";
import {PageSkeleton} from "@/components/layout/PageSkeleton";
import {PageHeader} from "@/components/layout/PageHeader";
import {GlassCard} from "@/components/ui/GlassCard";

// "com.apple.configuration.legacy" -> "legacy" in the badge; every native declaration type shares this prefix.
const TYPE_PREFIX = "com.apple.configuration.";
// Declaration types the server manages itself rather than ones a tenant authors, so they carry no shared prefix to
// strip. Labeled by hand.
const KNOWN_DECLARATION_TYPE_LABELS: Record<string, string> = {
    "com.apple.management.server-capabilities": "Server capabilities",
    "com.apple.configuration.softwareupdate.enforcement.specific": "Software update enforcement",
};

function shortType(type: string): string {
    if (KNOWN_DECLARATION_TYPE_LABELS[type]) return KNOWN_DECLARATION_TYPE_LABELS[type];
    return type.startsWith(TYPE_PREFIX) ? type.slice(TYPE_PREFIX.length) : type;
}

export default function DeclarationsPage() {
    const router = useRouter();
    // A member cannot write declarations.yaml and the YAML page this hands off to is read-only for them, so the
    // buttons say View rather than Edit.
    const {token, isAdmin} = useAuth();
    const [declarations, setDeclarations] = useState<DeclarationSummary[]>([]);
    const [tenant, setTenant] = useState<TenantInfo | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        if (!token) return;
        setLoading(true);
        Promise.all([api.listDeclarations(token), api.getTenant(token)])
            .then(([d, t]) => {
                setDeclarations(d.declarations);
                setTenant(t);
                setError(null);
            })
            .catch((e: unknown) => setError(e instanceof ApiError ? e.message : (e as Error).message))
            .finally(() => setLoading(false));
    }, [token]);

    return (
        <Stack gap="lg">
            <PageHeader
                badge={
                    <Badge variant="light" color="yellow" size="sm">
                        WIP
                    </Badge>
                }
                description="Declarations are built into the backend, however, are not yet structured in the UI. For now, it is only available in the YAML editor."
                actions={
                    <Button
                        variant="light"
                        leftSection={isAdmin ? <IconPencil size={14}/> : <IconFileDescription size={14}/>}
                        onClick={() => router.push("/yaml?type=declarations")}
                    >
                        {isAdmin ? "Edit YAML" : "View YAML"}
                    </Button>
                }
            />

            {tenant && !tenant.ddm_enabled && (
                <Alert color="orange" variant="light" icon={<IconInfoCircle size={16}/>}>
                    Declarative Device Management is turned off for this tenant, so nothing below is being
                    sent to devices yet. Turn it on in{" "}
                    <Text component={Link} href="/settings" fw={600} c="orange" style={{textDecoration: "underline"}}>
                        Settings
                    </Text>{" "}
                    to start enforcing declarations.
                </Alert>
            )}

            {error && (
                <Alert color="red" variant="light" icon={<IconInfoCircle size={16}/>}>
                    {error}
                </Alert>
            )}

            {loading ? (
                <PageSkeleton variant="table"/>
            ) : declarations.length === 0 ? (
                <GlassCard withBorder py={48}>
                    <Stack align="center" gap="xs">
                        <IconFileDescription size={36} opacity={0.4}/>
                        <Text c="dimmed">No declarations defined yet.</Text>
                        {isAdmin && (
                            <Button
                                variant="light"
                                leftSection={<IconPencil size={16}/>}
                                onClick={() => router.push("/yaml?type=declarations")}
                            >
                                Add one in the YAML editor
                            </Button>
                        )}
                    </Stack>
                </GlassCard>
            ) : (
                <Stack gap="sm">
                    {declarations.map((d) => (
                        <GlassCard key={d.id} withBorder padding="md">
                            <Group justify="space-between" align="flex-start" wrap="nowrap">
                                <Stack gap={6} style={{flex: 1, minWidth: 0}}>
                                    <Group gap="xs">
                                        <Text fw={600}>{d.name || d.id}</Text>
                                        <Badge color="grape" variant="light" size="sm">
                                            {shortType(d.type)}
                                        </Badge>
                                        {d.not_served ? (
                                            // Scope matches, but something outside declarations.yaml (an environment
                                            // setting, a missing bridged profile) stops it being built for anyone.
                                            // The device count moves into the tooltip rather than standing alone.
                                            <Tooltip
                                                multiline
                                                w={280}
                                                label={
                                                    typeof d.scoped_count === "number"
                                                        ? `${d.not_served} (scope matches ${d.scoped_count} device${d.scoped_count === 1 ? "" : "s"}, but none can receive it)`
                                                        : d.not_served
                                                }
                                            >
                                                <Badge color="orange" variant="light" size="sm"
                                                       leftSection={<IconAlertTriangle size={10}/>}>
                                                    not served
                                                </Badge>
                                            </Tooltip>
                                        ) : (
                                            typeof d.scoped_count === "number" && (
                                                <Badge color="gray" variant="light" size="sm">
                                                    {d.scoped_count} device{d.scoped_count === 1 ? "" : "s"}
                                                </Badge>
                                            )
                                        )}
                                    </Group>
                                    {d.description && (
                                        <Text fz="sm" c="dimmed">
                                            {d.description}
                                        </Text>
                                    )}
                                    <Group gap={6} wrap="wrap">
                                        <Text fz="xs" c="dimmed">
                                            id <Code>{d.id}</Code>
                                        </Text>
                                        {(d.scope?.groups ?? []).length === 0 ? (
                                            <Badge variant="outline" color="orange" size="sm">
                                                no groups
                                            </Badge>
                                        ) : (
                                            (d.scope?.groups ?? []).map((g) => (
                                                <Badge key={g} variant="dot" size="sm" color="blue">
                                                    {g}
                                                </Badge>
                                            ))
                                        )}
                                        {(d.scope?.platforms ?? []).map((p) => (
                                            <Badge key={p} variant="outline" size="sm" color="teal">
                                                {p}
                                            </Badge>
                                        ))}
                                        {(d.scope?.conditions ?? 0) > 0 && (
                                            <Badge variant="outline" size="sm" color="gray">
                                                {d.scope!.conditions} condition{d.scope!.conditions === 1 ? "" : "s"}
                                            </Badge>
                                        )}
                                        {d.scope?.rollout && (
                                            <Badge variant="outline" size="sm" color="yellow">
                                                gradual rollout
                                            </Badge>
                                        )}
                                    </Group>
                                </Stack>
                            </Group>
                        </GlassCard>
                    ))}
                </Stack>
            )}
        </Stack>
    );
}
