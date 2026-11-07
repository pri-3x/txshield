import { NextResponse, type NextRequest } from "next/server";
import { checkAuth } from "@/lib/basicAuth";

// Runs for every page request, including server actions and router
// prefetches (the matcher must not exclude any request by header: headers
// are attacker-controlled, so an exclusion would bypass authentication).
// See src/lib/basicAuth.ts for the optional dashboard authentication.

// Strict, nonce-based Content Security Policy (see Next.js CSP guide). The
// dashboard renders attacker-influenced strings (revert reasons, decoded
// string arguments, reputation reasons); CSP is the second line of defense
// behind React's escaping. No 'unsafe-inline' for scripts or styles: charts
// use SVG attributes rather than style attributes.
export async function proxy(request: NextRequest) {
  const denied = await checkAuth(request);
  if (denied) return denied;

  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const isDev = process.env.NODE_ENV === "development";
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  // Static build assets are public; everything else, including prefetch
  // requests, goes through authentication.
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
