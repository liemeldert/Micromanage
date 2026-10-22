import {type NextRequest, NextResponse} from "next/server";

const CONTROLLER = process.env.CONTROLLER_URL ?? "http://localhost:8001";

// Request timeout. Generous as a fleet sync or an ABM device pull can take minutes, and multipart bodies get a longer
// cap for package uploads of hundreds of MB.
const TIMEOUT_MS = Number(process.env.PROXY_TIMEOUT_MS) || 300_000;
const UPLOAD_TIMEOUT_MS = Number(process.env.PROXY_UPLOAD_TIMEOUT_MS) || 600_000;

// Upstream response headers that are not copied through: hop-by-hop headers; content-encoding, content-length and
// content-range, which describe the encoded body while fetch returns it decoded; and set-cookie and www-authenticate,
// since the only cookie on this origin is the session cookie set below.
const DROP_RESPONSE_HEADERS = new Set([
    "connection",
    "transfer-encoding",
    "keep-alive",
    "content-encoding",
    "content-length",
    "content-range",
    "set-cookie",
    "www-authenticate",
]);

const SESSION_COOKIE = "mm_session";
const SESSION_FALLBACK_SECONDS = 43200;

// Controller responses that carry a fresh session token, which goes into the cookie instead of the body.
const TOKEN_ISSUING_REQUESTS = new Set([
    "POST /api/v1/auth/login",
    "POST /api/v1/auth/mfa/verify",
    "POST /api/v1/auth/password",
    "POST /api/v1/auth/mfa/confirm",
    "DELETE /api/v1/auth/mfa",
]);

const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function isHttps(req: NextRequest): boolean {
    return req.headers.get("x-forwarded-proto") === "https" || req.nextUrl.protocol === "https:";
}

// Moves access_token from a sign-in response body into the session cookie; any other body is returned unchanged.
function withSessionCookie(req: NextRequest, text: string, status: number, headers: Headers): NextResponse {
    let body: unknown;
    try {
        body = JSON.parse(text);
    } catch {
        return new NextResponse(text, {status, headers});
    }
    const token = (body as { access_token?: unknown } | null)?.access_token;
    if (typeof token !== "string" || !token) return new NextResponse(text, {status, headers});

    const rest: Record<string, unknown> = {...(body as Record<string, unknown>)};
    delete rest.access_token;
    const expiresIn = Number(rest.expires_in);
    const res = NextResponse.json(rest, {status, headers});
    res.cookies.set(SESSION_COOKIE, token, {
        httpOnly: true,
        sameSite: "strict",
        path: "/",
        maxAge: Number.isFinite(expiresIn) && expiresIn > 0 ? expiresIn : SESSION_FALLBACK_SECONDS,
        secure: isHttps(req),
    });
    return res;
}

function clientIp(req: NextRequest): string | null {
    const fwd = req.headers.get("x-forwarded-for");
    if (fwd) return fwd;
    return req.headers.get("x-real-ip");
}

async function proxy(req: NextRequest, segments: string[]) {
    const path = "/" + segments.join("/");
    const search = req.nextUrl.search;
    const url = `${CONTROLLER}${path}${search}`;

    const contentType = req.headers.get("content-type") ?? "application/json";
    const headers: Record<string, string> = {"Content-Type": contentType};
    const auth = req.headers.get("authorization");
    const session = req.cookies.get(SESSION_COOKIE)?.value;
    if (auth) {
        headers["Authorization"] = auth;
    } else if (session) {
        // A state-changing call authenticated by the cookie must also carry a header that a cross-site form cannot set.
        if (UNSAFE_METHODS.has(req.method) && req.headers.get("x-mm-client") !== "web") {
            return NextResponse.json(
                {detail: "Missing the web client header. Reload the page and try again."},
                {status: 403},
            );
        }
        headers["Authorization"] = `Bearer ${session}`;
    }
    // If-Match carries the version a config editor is saving against; without it the controller cannot detect a
    // conflicting save.
    const ifMatch = req.headers.get("if-match");
    if (ifMatch) headers["If-Match"] = ifMatch;
    const ip = clientIp(req);
    if (ip) headers["X-Forwarded-For"] = ip;

    // The body streams through instead of buffering a multi-hundred-MB .pkg into this process. fetch requires
    // duplex half whenever the body is a stream.
    const hasBody = req.method !== "GET" && req.method !== "HEAD";
    const timeout = contentType.startsWith("multipart/") ? UPLOAD_TIMEOUT_MS : TIMEOUT_MS;

    let upstream: Response;
    try {
        upstream = await fetch(url, {
            method: req.method,
            headers,
            body: hasBody ? req.body : undefined,
            duplex: "half",
            redirect: "manual",
            signal: AbortSignal.timeout(timeout),
        } as RequestInit & { duplex: "half" });
    } catch (err: unknown) {
        if (err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError")) {
            return NextResponse.json(
                {detail: `Controller did not answer within ${Math.round(timeout / 1000)}s.`},
                {status: 504},
            );
        }
        const cause = err instanceof Error ? err.message : String(err);
        return NextResponse.json(
            {
                detail: `Controller unreachable at ${CONTROLLER}. Check that it's running and reachable from this server. (${cause})`,
            },
            {status: 502},
        );
    }

    const resHeaders = new Headers();
    upstream.headers.forEach((v, k) => {
        if (!DROP_RESPONSE_HEADERS.has(k.toLowerCase())) resHeaders.set(k, v);
    });

    if (TOKEN_ISSUING_REQUESTS.has(`${req.method} ${path}`) && upstream.ok) {
        return withSessionCookie(req, await upstream.text(), upstream.status, resHeaders);
    }
    return new NextResponse(upstream.body, {status: upstream.status, headers: resHeaders});
}

type RouteContext = { params: Promise<{ path: string[] }> };

export async function GET(req: NextRequest, ctx: RouteContext) {
    return proxy(req, (await ctx.params).path);
}

export async function POST(req: NextRequest, ctx: RouteContext) {
    return proxy(req, (await ctx.params).path);
}

export async function PUT(req: NextRequest, ctx: RouteContext) {
    return proxy(req, (await ctx.params).path);
}

export async function PATCH(req: NextRequest, ctx: RouteContext) {
    return proxy(req, (await ctx.params).path);
}

export async function DELETE(req: NextRequest, ctx: RouteContext) {
    return proxy(req, (await ctx.params).path);
}
