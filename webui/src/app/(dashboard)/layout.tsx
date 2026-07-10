"use client";

import { useEffect } from "react";
import { useRouter, usePathname } from "next/navigation";
import {
  AppShell,
  Box,
  Burger,
  Group,
  NavLink,
  ScrollArea,
  Text,
  Avatar,
  ActionIcon,
  Divider,
  useMantineColorScheme,
} from "@mantine/core";
import { useDisclosure, useLocalStorage } from "@mantine/hooks";
import {
  IconLayoutDashboard,
  IconDeviceLaptop,
  IconDeviceMobileShare,
  IconStack2,
  IconApps,
  IconFileCertificate,
  IconFileCode,
  IconListCheck,
  IconSettings,
  IconLogout,
  IconMoon,
  IconSun,
} from "@tabler/icons-react";
import { useAuth } from "../../../lib/auth-context";
import { SHOW_YAML_STORAGE_KEY } from "../../../lib/preferences";

const NAV_ITEMS = [
  { label: "Dashboard",  icon: IconLayoutDashboard,    href: "/dashboard" },
  { label: "Devices",    icon: IconDeviceLaptop,       href: "/devices" },
  { label: "Enrollment", icon: IconDeviceMobileShare,  href: "/enrollment" },
  { label: "Groups",     icon: IconStack2,             href: "/groups" },
  { label: "Apps",       icon: IconApps,               href: "/apps" },
  { label: "Profiles",   icon: IconFileCertificate,    href: "/profiles" },
  { label: "Tasks",      icon: IconListCheck,          href: "/tasks" },
  { label: "Settings",   icon: IconSettings,           href: "/settings" },
];

// Shown only when enabled in Settings → Interface.
const YAML_NAV_ITEM = { label: "YAML", icon: IconFileCode, href: "/yaml" };

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, hydrated, email, logout } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const [opened, { toggle }] = useDisclosure();
  const { colorScheme, toggleColorScheme } = useMantineColorScheme();
  const [showYaml] = useLocalStorage({ key: SHOW_YAML_STORAGE_KEY, defaultValue: false });

  // Insert the optional YAML view between Tasks and Settings.
  const navItems = showYaml
    ? [...NAV_ITEMS.slice(0, -1), YAML_NAV_ITEM, NAV_ITEMS[NAV_ITEMS.length - 1]]
    : NAV_ITEMS;

  useEffect(() => {
    // Wait until persisted auth is restored before deciding to redirect,
    // otherwise a page refresh bounces a logged-in user to /login.
    if (hydrated && !isAuthenticated) router.replace("/login");
  }, [hydrated, isAuthenticated, router]);

  if (!hydrated || !isAuthenticated) return null;

  return (
    <AppShell
      navbar={{ width: 220, breakpoint: "sm", collapsed: { mobile: !opened } }}
      padding={0}
    >
      {/* ── Navbar ────────────────────────────────────────────────── */}
      <AppShell.Navbar
        style={{ background: "var(--mantine-color-dark-8, #1a1b1e)", borderRight: "none" }}
      >
        <AppShell.Section p="md">
          <Group gap="xs">
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" color="white" />
            <Text
              fw={700}
              fz="lg"
              style={{
                background: "linear-gradient(to left, #7928CA, #FF0080)",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
                backgroundClip: "text",
              }}
            >
              Micromanage
            </Text>
          </Group>
        </AppShell.Section>

        <Divider color="dark.6" />

        <AppShell.Section grow component={ScrollArea} p="xs" mt="xs">
          {navItems.map((item) => {
            const active = pathname === item.href || pathname.startsWith(item.href + "/");
            return (
              <NavLink
                key={item.href}
                label={item.label}
                leftSection={<item.icon size={18} />}
                active={active}
                onClick={() => router.push(item.href)}
                mb={4}
                styles={{
                  root: {
                    borderRadius: 6,
                    color: active ? "white" : "var(--mantine-color-dark-2)",
                    "&:hover": { background: "var(--mantine-color-dark-6)" },
                  },
                }}
              />
            );
          })}
        </AppShell.Section>

        <Divider color="dark.6" />

        <AppShell.Section p="sm">
          <Group justify="space-between">
            <Group gap="xs">
              <Avatar size="sm" color="blue" radius="xl">
                {(email ?? "?")[0].toUpperCase()}
              </Avatar>
              <Text fz="xs" c="dark.2" truncate maw={110}>
                {email}
              </Text>
            </Group>
            <Group gap={4}>
              <ActionIcon
                variant="subtle"
                color="gray"
                size="sm"
                onClick={() => toggleColorScheme()}
                title="Toggle color scheme"
              >
                {colorScheme === "dark" ? <IconSun size={14} /> : <IconMoon size={14} />}
              </ActionIcon>
              <ActionIcon
                variant="subtle"
                color="red"
                size="sm"
                onClick={() => { logout(); router.push("/login"); }}
                title="Sign out"
              >
                <IconLogout size={14} />
              </ActionIcon>
            </Group>
          </Group>
        </AppShell.Section>
      </AppShell.Navbar>

      {/* ── Main ─────────────────────────────────────────────────── */}
      <AppShell.Main>
        <Box p="lg" style={{ minHeight: "100vh" }}>
          {children}
        </Box>
      </AppShell.Main>
    </AppShell>
  );
}
