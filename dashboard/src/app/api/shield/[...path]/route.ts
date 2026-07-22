import { NextRequest, NextResponse } from "next/server";
import { shieldAPIURL } from "@/lib/server-api";

async function forward(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const token = request.cookies.get("shield_session")?.value;
  if (!token) return NextResponse.json({ error: "Authentication required" }, { status: 401 });
  const { path } = await context.params;
  const target = shieldAPIURL(`/${path.join("/")}`);
  try {
    const upstream = await fetch(target, {
      method: request.method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": request.headers.get("content-type") ?? "application/json" },
      body: request.method === "GET" || request.method === "HEAD" ? undefined : await request.text(),
      cache: "no-store",
    });
    return new NextResponse(upstream.body, { status: upstream.status, headers: { "Content-Type": upstream.headers.get("content-type") ?? "application/json" } });
  } catch {
    return NextResponse.json({ error: "Shield API is unreachable" }, { status: 503 });
  }
}

export const GET = forward;
export const POST = forward;
