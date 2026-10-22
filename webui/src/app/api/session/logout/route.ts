import {type NextRequest, NextResponse} from "next/server";

const CONTROLLER = process.env.CONTROLLER_URL ?? "http://localhost:8001";

const SESSION_COOKIE = "mm_session";

// Ends this browser's session on the controller, then clears the session cookie whatever the controller returned. With
// ?scope=local only the cookie is cleared, for a token the controller has already refused.
export async function POST(req: NextRequest) {
    if (req.headers.get("x-mm-client") !== "web") {
        return NextResponse.json(
            {detail: "Missing the web client header. Reload the page and try again."},
            {status: 403},
        );
    }
    const session = req.cookies.get(SESSION_COOKIE)?.value;
    if (session && req.nextUrl.searchParams.get("scope") !== "local") {
        try {
            await fetch(`${CONTROLLER}/api/v1/auth/logout`, {
                method: "POST",
                headers: {Authorization: `Bearer ${session}`},
                redirect: "manual",
                signal: AbortSignal.timeout(10_000),
            });
        } catch {
        }
    }
    const res = new NextResponse(null, {status: 204});
    res.cookies.set(SESSION_COOKIE, "", {
        httpOnly: true,
        sameSite: "strict",
        path: "/",
        maxAge: 0,
        secure: req.headers.get("x-forwarded-proto") === "https" || req.nextUrl.protocol === "https:",
    });
    return res;
}
