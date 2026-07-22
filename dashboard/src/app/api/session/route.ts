import { NextRequest, NextResponse } from "next/server";
import { verifyShieldToken } from "@/lib/server-api";

function isSecureRequest(request: NextRequest): boolean {
  const forwardedProto = request.headers.get("x-forwarded-proto")?.split(",", 1)[0]?.trim().toLowerCase();
  return forwardedProto === "https" || request.nextUrl.protocol === "https:";
}

export async function POST(request: NextRequest) {
  const payload = (await request.json().catch(() => null)) as { token?: unknown } | null;
  const token = typeof payload?.token === "string" ? payload.token.trim() : "";
  if (!token) return NextResponse.json({ error: "API token is required" }, { status: 400 });
  try {
    if (!(await verifyShieldToken(token))) return NextResponse.json({ error: "Shield rejected the API token" }, { status: 401 });
  } catch {
    return NextResponse.json({ error: "Shield API is unreachable" }, { status: 503 });
  }
  const response = NextResponse.json({ ok: true });
  response.cookies.set("shield_session", token, { httpOnly: true, sameSite: "strict", secure: isSecureRequest(request), path: "/", maxAge: 60 * 60 * 12 });
  return response;
}

export async function DELETE(request: NextRequest) {
  const response = NextResponse.json({ ok: true });
  response.cookies.set("shield_session", "", { httpOnly: true, sameSite: "strict", secure: isSecureRequest(request), path: "/", maxAge: 0 });
  return response;
}
