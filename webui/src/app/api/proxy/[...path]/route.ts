import {type NextRequest, NextResponse} from "next/server";

const CONTROLLER = process.env.CONTROLLER_URL ?? "http://localhost:8001";

// How long the controller gets to answer before the request is abandoned. The default is generous because a fleet
// sync or an ABM device pull can take minutes; multipart bodies get a longer cap still, since package uploads run
// to hundreds of MB.
const TIMEOUT_MS = Number(process.env.PROXY_TIMEOUT_MS) || 300_000;
const UPLOAD_TIMEOUT_MS = Number(process.env.PROXY_UPLOAD_TIMEOUT_MS) || 600_000;

// Upstream response headers that must not be copied through. Hop-by-hop headers belong to the upstream connection,
// not this one. content-encoding, content-length and content-range describe the encoded upstream body, but fetch
// hands back a decoded stream, so the browser would fail to decode it and the advertised length would be wrong.
// set-cookie and www-authenticate would let the controller set cookies on this origin or raise a browser auth
// prompt, and auth here is a bearer token the client holds.
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
    if (auth) headers["Authorization"] = auth;
    // If-Match carries the version a config editor is saving against; dropping it turns every conflict-checked save
    // into last write wins.
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
