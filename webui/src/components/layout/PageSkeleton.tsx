// Placeholders each route shows from its loading.tsx while the first request is out. The variants match
// the layouts the app actually uses, so the skeleton settles into the real content instead of jumping.

import {Card, Group, SimpleGrid, Skeleton, Stack} from "@mantine/core";

export type SkeletonVariant = "table" | "grid" | "detail" | "form" | "dashboard";

function PageHeader() {
    return (
        <Group justify="space-between" align="flex-start">
            <Stack gap={6}>
                <Skeleton height={26} width={190}/>
                <Skeleton height={12} width={320}/>
            </Stack>
            <Group gap="xs">
                <Skeleton height={34} width={96} radius="var(--mantine-radius-default)"/>
                <Skeleton height={34} width={112} radius="var(--mantine-radius-default)"/>
            </Group>
        </Group>
    );
}

function TableRows({rows = 8}: { rows?: number }) {
    // Staggered widths so the block reads as a table rather than a solid grey slab.
    const widths = ["42%", "68%", "55%", "74%", "48%", "61%", "70%", "52%"];
    return (
        <Stack gap={0}>
            {Array.from({length: rows}, (_, i) => (
                <Group key={i} justify="space-between" wrap="nowrap" py={11} px="md">
                    <Skeleton height={11} width={widths[i % widths.length]}/>
                    <Skeleton height={20} width={72} radius="xl"/>
                </Group>
            ))}
        </Stack>
    );
}

function CardGrid({count = 6}: { count?: number }) {
    return (
        <SimpleGrid cols={{base: 1, sm: 2, lg: 3}} spacing="md">
            {Array.from({length: count}, (_, i) => (
                <Card key={i} withBorder padding="md">
                    <Group justify="space-between" wrap="nowrap" mb="md">
                        <Stack gap={6} style={{flex: 1}}>
                            <Skeleton height={14} width="62%"/>
                            <Skeleton height={10} width="82%"/>
                        </Stack>
                        <Skeleton height={22} width={22} circle/>
                    </Group>
                    <Group gap="md" wrap="nowrap">
                        <Skeleton height={64} width={64} circle/>
                        <Stack gap={8} style={{flex: 1}}>
                            <Skeleton height={11} width="70%"/>
                            <Skeleton height={18} width={90} radius="xl"/>
                        </Stack>
                    </Group>
                </Card>
            ))}
        </SimpleGrid>
    );
}

function FormFields({count = 5}: { count?: number }) {
    return (
        <Stack gap="md">
            {Array.from({length: count}, (_, i) => (
                <Stack key={i} gap={6}>
                    <Skeleton height={10} width={110}/>
                    <Skeleton height={36} radius="var(--mantine-radius-default)"/>
                </Stack>
            ))}
        </Stack>
    );
}

export function PageSkeleton({variant = "table"}: { variant?: SkeletonVariant }) {
    if (variant === "dashboard") {
        return (
            <Stack gap="lg">
                <PageHeader/>
                <SimpleGrid cols={{base: 1, sm: 2, lg: 4}} spacing="md">
                    {Array.from({length: 4}, (_, i) => (
                        <Card key={i} withBorder padding="md">
                            <Skeleton height={10} width="58%" mb="sm"/>
                            <Skeleton height={30} width="42%"/>
                        </Card>
                    ))}
                </SimpleGrid>
                <SimpleGrid cols={{base: 1, lg: 2}} spacing="md">
                    {Array.from({length: 2}, (_, i) => (
                        <Card key={i} withBorder padding="md">
                            <Skeleton height={12} width={150} mb="md"/>
                            <Skeleton height={220}/>
                        </Card>
                    ))}
                </SimpleGrid>
            </Stack>
        );
    }

    if (variant === "grid") {
        return (
            <Stack gap="lg">
                <PageHeader/>
                <CardGrid/>
            </Stack>
        );
    }

    if (variant === "form") {
        return (
            <Stack gap="lg">
                <PageHeader/>
                <Card withBorder padding="md" maw={720}>
                    <FormFields/>
                </Card>
            </Stack>
        );
    }

    if (variant === "detail") {
        return (
            <Stack gap="lg">
                <PageHeader/>
                <Group align="flex-start" gap="lg" wrap="nowrap">
                    <Stack gap="md" style={{flex: "0 0 340px"}}>
                        <Card withBorder padding="md">
                            <Stack gap="sm">
                                {Array.from({length: 7}, (_, i) => (
                                    <Skeleton key={i} height={30}/>
                                ))}
                            </Stack>
                        </Card>
                        <Card withBorder padding="md">
                            <Skeleton height={12} width={110} mb="sm"/>
                            <Stack gap="xs">
                                <Skeleton height={32}/>
                                <Skeleton height={32}/>
                            </Stack>
                        </Card>
                    </Stack>
                    <Stack gap="md" style={{flex: "1 1 0", minWidth: 0}}>
                        {Array.from({length: 2}, (_, i) => (
                            <Card key={i} withBorder padding="md">
                                <Skeleton height={12} width={130} mb="md"/>
                                <SimpleGrid cols={{base: 1, sm: 2}} spacing="xl" verticalSpacing="sm">
                                    {Array.from({length: 8}, (_, j) => (
                                        <Group key={j} justify="space-between" wrap="nowrap">
                                            <Skeleton height={10} width="46%"/>
                                            <Skeleton height={10} width="28%"/>
                                        </Group>
                                    ))}
                                </SimpleGrid>
                            </Card>
                        ))}
                    </Stack>
                </Group>
            </Stack>
        );
    }

    return (
        <Stack gap="lg">
            <PageHeader/>
            <Card withBorder padding={0}>
                <TableRows/>
            </Card>
        </Stack>
    );
}
