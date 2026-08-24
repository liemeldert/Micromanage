import type {MetadataRoute} from "next";

// Installability on Android and Chrome. The Apple side of the same thing is the appleWebApp block in
// layout.tsx, since Safari reads its own meta tags rather than this file.
export default function manifest(): MetadataRoute.Manifest {
    return {
        name: "Micromanage",
        short_name: "Micromanage",
        description: "YAML-driven Apple MDM compliance controller",
        // The root sends an authenticated visitor to the dashboard and everyone else to the login page.
        start_url: "/",
        id: "/",
        display: "standalone",
        // The app boots into the light scheme, so the splash matches it rather than flashing.
        background_color: "#ffffff",
        theme_color: "#ffffff",
        icons: [
            {src: "/icon.png", sizes: "192x192", type: "image/png"},
            {src: "/icon-512.png", sizes: "512x512", type: "image/png"},
        ],
    };
}
