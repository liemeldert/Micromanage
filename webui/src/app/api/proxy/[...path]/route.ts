import { type NextRequest, NextResponse } from "next/server";

const CONTROLLER = process.env.CONTROLLER_URL ?? "http://localhost:8001";

async function proxy(req: NextRequest, segments: string[]) {
  const path = "/" + segments.join("/");
  const search = req.nextUrl.search;
  const url = `${CONTROLLER}${path}${search}`;

  const headers: Record<string, string> = {
    "Content-Type": req.headers.get("content-type") ?? "application/json",
  };
  const auth = req.headers.get("authorization");
  if (auth) headers["Authorization"] = auth;

  // Use arrayBuffer (not text) so binary bodies so. multipart app-package
  // uploads and pass through to the controller without corruption.
  const body =
    req.method !== "GET" && req.method !== "HEAD"
      ? await req.arrayBuffer()
      : undefined;

  let upstream: Response;
  try {
    upstream = await fetch(url, {
      method: req.method,
      headers,
      body,
      redirect: "manual",
    });
  } catch (err: unknown) {
    const cause = err instanceof Error ? err.message : String(err);
    return NextResponse.json(
      {
        detail:
          `Controller unreachable at ${CONTROLLER}. Contact your administrator for help.` +
          `(${cause})`,
      },
      { status: 502 },
    );
  }

  const resBody = await upstream.arrayBuffer();
  const resHeaders = new Headers();
  upstream.headers.forEach((v, k) => {
    if (!["connection", "transfer-encoding", "keep-alive"].includes(k.toLowerCase())) {
      resHeaders.set(k, v);
    }
  });

  return new NextResponse(resBody, { status: upstream.status, headers: resHeaders });
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
