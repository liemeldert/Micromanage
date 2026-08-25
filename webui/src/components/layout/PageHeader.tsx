// Page heading. The icon and the default title come from the destination table in lib/palette, so the nav and the
// page cannot disagree. A route missing from that table renders the title it passes, and no icon unless it names one.

import Link from "next/link";
import {usePathname} from "next/navigation";
import {Anchor, Group, Stack, Text, ThemeIcon, Title} from "@mantine/core";
import {IconArrowLeft, type TablerIcon} from "@tabler/icons-react";
import type {ReactNode} from "react";
import {activeHref, PALETTE_DESTINATIONS} from "../../../lib/palette";

export function PageHeader({
                               title,
                               description,
                               actions,
                               icon,
                               back,
                               badge,
                           }: {
    /** Defaults to the destination table's label for this route. */
    title?: ReactNode;
    /** Shown only when passed. */
    description?: ReactNode | null;
    /** Buttons for the right-hand side. */
    actions?: ReactNode;
    /** Only for routes the destination table does not cover. */
    icon?: TablerIcon;
    /** Renders a link back to a parent page above the title. */
    back?: { href: string; label: string };
    /** Sits beside the title, for a status the whole page carries. */
    badge?: ReactNode;
}) {
    const pathname = usePathname() ?? "";
    const match = activeHref(pathname, PALETTE_DESTINATIONS.map((d) => d.href));
    const dest = PALETTE_DESTINATIONS.find((d) => d.href === match);

    const Icon = icon ?? dest?.icon;
    const heading = title ?? dest?.label ?? "";
    // A description shows only when the page passes one. The commented line falls back to the table's copy instead.
    // const sub = description === undefined ? dest?.description : description;
    const sub = description ?? null;

    return (
        <Group justify="space-between" align="flex-start" wrap="nowrap" gap="md">
            <Group gap="sm" align="flex-start" wrap="nowrap" style={{minWidth: 0}}>
                {Icon && (
                    <ThemeIcon variant="light" size={38} radius="md" style={{flexShrink: 0}}>
                        <Icon size={21}/>
                    </ThemeIcon>
                )}
                <Stack gap={2} style={{minWidth: 0}}>
                    {back && (
                        <Anchor component={Link} href={back.href} fz="xs" c="dimmed" underline="never">
                            <Group gap={4} wrap="nowrap">
                                <IconArrowLeft size={12}/>
                                {back.label}
                            </Group>
                        </Anchor>
                    )}
                    <Group gap="xs" align="center" wrap="nowrap">
                        <Title order={2}>{heading}</Title>
                        {badge}
                    </Group>
                    {sub && (
                        <Text fz="sm" c="dimmed">
                            {sub}
                        </Text>
                    )}
                </Stack>
            </Group>
            {actions && (
                <Group gap="xs" wrap="nowrap" style={{flexShrink: 0}}>
                    {actions}
                </Group>
            )}
        </Group>
    );
}
