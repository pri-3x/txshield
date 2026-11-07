import { NextResponse, type NextRequest } from "next/server";

/**
 * Optional HTTP Basic authentication for the whole dashboard.
 *
 * The dashboard calls the API with its own server-side API key, so anyone who
 * can reach the dashboard can run analyses and read the stored history with
 * that key. Set TXSHIELD_DASHBOARD_BASIC_AUTH="user:password" (password of at
 * least 16 characters) or put the dashboard behind an authenticating reverse
 * proxy before exposing it beyond localhost. Use HTTPS: Basic credentials are
 * only base64-encoded.
 */
const MIN_PASSWORD = 16;

export type AuthConfig = { kind: "off" } | { kind: "on"; expected: string } | { kind: "invalid" };

export function parseAuthConfig(raw: string | undefined): AuthConfig {
  if (!raw) return { kind: "off" };
  const i = raw.indexOf(":");
  if (i < 1 || raw.length - i - 1 < MIN_PASSWORD) return { kind: "invalid" };
  return { kind: "on", expected: raw };
}

const fromEnv = parseAuthConfig(process.env.TXSHIELD_DASHBOARD_BASIC_AUTH);
if (fromEnv.kind === "invalid") {
  console.error(`TXSHIELD_DASHBOARD_BASIC_AUTH must be "user:password" with a password of at least ${MIN_PASSWORD} characters; refusing all requests`);
}

async function digest(s: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
}

/** Compares SHA-256 digests in constant time (equal-length inputs). */
async function sameSecret(a: string, b: string): Promise<boolean> {
  const [x, y] = await Promise.all([digest(a), digest(b)]);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

function decodeBasic(header: string | null): string {
  const b64 = header?.match(/^Basic\s+([A-Za-z0-9+/=]+)\s*$/i)?.[1];
  if (!b64) return "";
  try {
    return Buffer.from(b64, "base64").toString("utf8");
  } catch {
    return "";
  }
}

/** Returns a response that ends the request, or undefined when authorized. */
export async function checkAuth(request: Pick<NextRequest, "headers">, cfg: AuthConfig = fromEnv): Promise<Response | undefined> {
  if (cfg.kind === "off") return undefined;
  if (cfg.kind === "invalid") return new NextResponse("Dashboard authentication is misconfigured", { status: 500 });
  if (await sameSecret(decodeBasic(request.headers.get("authorization")), cfg.expected)) return undefined;
  return new NextResponse("Authentication required", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="TxShield", charset="UTF-8"', "Cache-Control": "no-store" },
  });
}
