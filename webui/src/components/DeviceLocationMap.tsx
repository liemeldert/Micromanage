// Leaflet map whose tiles come from the controller's same-origin tile proxy with the bearer token, rendered as
// blob: images. The CSP allows img-src 'self' blob: and connect-src 'self', so no third-party tile CDN.

import {useEffect, useRef} from "react";
import {Anchor, Box, Group, Text} from "@mantine/core";
import {IconExternalLink} from "@tabler/icons-react";
import "leaflet/dist/leaflet.css";
import {useAuth} from "../../lib/auth-context";

export interface DeviceLocation {
    Latitude: number;
    Longitude: number;
    HorizontalAccuracy?: number | null;
    Timestamp?: string | null;
}

export function DeviceLocationMap({location, height = 260}: { location: DeviceLocation; height?: number }) {
    const {token} = useAuth();
    const ref = useRef<HTMLDivElement>(null);
    const {Latitude: lat, Longitude: lon, HorizontalAccuracy: acc} = location;

    useEffect(() => {
        let map: import("leaflet").Map | undefined;
        let cancelled = false;

        (async () => {
            const L = (await import("leaflet")).default;
            if (cancelled || !ref.current) return;

            map = L.map(ref.current, {attributionControl: true, zoomControl: true}).setView([lat, lon], 15);

            // L.TileLayer.extend() is not typed for a custom constructor, hence the cast.
            const AuthTiles = L.TileLayer.extend({
                createTile(this: unknown, coords: {
                    x: number;
                    y: number;
                    z: number
                }, done: (e: Error | null, t: HTMLImageElement) => void) {
                    const img = document.createElement("img");
                    img.setAttribute("role", "presentation");
                    const url = `/api/proxy/api/v1/map/tile/${coords.z}/${coords.x}/${coords.y}`;
                    fetch(url, {headers: token ? {Authorization: `Bearer ${token}`} : {}})
                        .then((r) => (r.ok ? r.blob() : Promise.reject(new Error(String(r.status)))))
                        .then((blob) => {
                            const objUrl = URL.createObjectURL(blob);
                            // Revoke on either outcome so an undecodable tile can't leak the URL.
                            const cleanup = () => URL.revokeObjectURL(objUrl);
                            img.onload = cleanup;
                            img.onerror = cleanup;
                            img.src = objUrl;
                            done(null, img);
                        })
                        .catch((e) => done(e as Error, img));
                    return img;
                },
            }) as unknown as new (url: string, opts: import("leaflet").TileLayerOptions) => import("leaflet").TileLayer;

            new AuthTiles("", {
                maxZoom: 19,
                noWrap: true,
                attribution: "&copy; OpenStreetMap contributors",
            }).addTo(map);

            L.circleMarker([lat, lon], {
                radius: 8, color: "#1c7ed6", fillColor: "#1c7ed6", fillOpacity: 0.9, weight: 2,
            }).addTo(map);
            // Accuracy radius (meters), when reported.
            if (acc && acc > 0) {
                L.circle([lat, lon], {
                    radius: acc,
                    color: "#1c7ed6",
                    fillColor: "#1c7ed6",
                    fillOpacity: 0.1,
                    weight: 1
                }).addTo(map);
            }
            // Leaflet needs a size recalculation once the container has laid out.
            setTimeout(() => map?.invalidateSize(), 100);
        })();

        return () => {
            cancelled = true;
            map?.remove();
        };
    }, [lat, lon, acc, token]);

    return (
        <Box>
            <Box
                ref={ref}
                style={{
                    height,
                    borderRadius: "var(--mantine-radius-sm)",
                    overflow: "hidden",
                    border: "1px solid var(--mantine-color-default-border)",
                    zIndex: 0
                }}
            />
            <Group justify="space-between" mt={6}>
                <Text fz="xs" c="dimmed" style={{fontFamily: "monospace"}}>
                    {lat.toFixed(5)}, {lon.toFixed(5)}{acc ? ` ±${Math.round(acc)}m` : ""}
                </Text>
                <Group gap="sm">
                    <Anchor fz="xs" href={`https://maps.apple.com/?ll=${lat},${lon}&q=Device`} target="_blank"
                            rel="noopener noreferrer">
                        <Group gap={2}>Apple Maps <IconExternalLink size={11}/></Group>
                    </Anchor>
                    <Anchor fz="xs" href={`https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=16/${lat}/${lon}`}
                            target="_blank" rel="noopener noreferrer">
                        <Group gap={2}>OpenStreetMap <IconExternalLink size={11}/></Group>
                    </Anchor>
                </Group>
            </Group>
        </Box>
    );
}
