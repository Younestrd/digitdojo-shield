import { NextRequest, NextResponse } from "next/server";

const publicPaths = new Set(["/login"]);

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (pathname.startsWith("/api/") || pathname.startsWith("/_next/") || publicPaths.has(pathname)) return NextResponse.next();
  if (!request.cookies.has("shield_session")) return NextResponse.redirect(new URL("/login", request.url));
  return NextResponse.next();
}

export const config = { matcher: ["/((?!favicon.ico).*)"] };
