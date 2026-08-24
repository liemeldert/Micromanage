import "@mantine/core/styles.css";
import "@mantine/notifications/styles.css";
import "@mantine/charts/styles.css";
import "@mantine/code-highlight/styles.css";
import "@mantine/spotlight/styles.css";
import "./globals.css";

import type {Metadata, Viewport} from "next";
import {ColorSchemeScript, MantineProvider} from "@mantine/core";
import {Notifications} from "@mantine/notifications";
import {ModalsProvider} from "@mantine/modals";
import {AuthProvider} from "../../lib/auth-context";
import {GlassPointer} from "@/components/ui/glass-pointer";
import {theme} from "../../lib/theme";

export const metadata: Metadata = {
    title: "Micromanage",
    description: "YAML-driven Apple MDM compliance controller",
    // Safari reads these rather than manifest.ts, so an iOS home-screen launch opens without browser
    // chrome the way an installed Android copy does.
    appleWebApp: {
        capable: true,
        title: "Micromanage",
        statusBarStyle: "default",
    },
};

// Tints the browser and OS chrome around the page, following the scheme the app is drawn in.
export const viewport: Viewport = {
    themeColor: [
        {media: "(prefers-color-scheme: light)", color: "#ffffff"},
        {media: "(prefers-color-scheme: dark)", color: "#1a1b1e"},
    ],
};

export default function RootLayout({children}: { children: React.ReactNode }) {
    return (
        <html lang="en" suppressHydrationWarning>
        <head>
            <ColorSchemeScript defaultColorScheme="light"/>
            <title>Micromanage</title>
        </head>
        <body>
        <MantineProvider theme={theme} defaultColorScheme="light">
            <Notifications position="top-right" limit={5}/>
            {/* Drives the cursor highlight, the lean and the press glow for every glass surface, modals included. */}
            <GlassPointer/>
            <ModalsProvider>
                <AuthProvider>{children}</AuthProvider>
            </ModalsProvider>
        </MantineProvider>
        </body>
        </html>
    );
}
