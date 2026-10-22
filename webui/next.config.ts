import type {NextConfig} from "next";

const ContentSecurityPolicy = [
    "default-src 'self'",
    // The dev server evaluates code at runtime; a production build does not.
    process.env.NODE_ENV === "production"
        ? "script-src 'self' 'unsafe-inline'"
        : "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
].join("; ");

const securityHeaders = [
    {key: "Content-Security-Policy", value: ContentSecurityPolicy},
    {key: "X-Frame-Options", value: "DENY"},
    {key: "X-Content-Type-Options", value: "nosniff"},
    {key: "Referrer-Policy", value: "strict-origin-when-cross-origin"},
    {key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()"},
];

const nextConfig: NextConfig = {
    output: "standalone",
    poweredByHeader: false,
    async headers() {
        return [{source: "/:path*", headers: securityHeaders}];
    },
};

export default nextConfig;
