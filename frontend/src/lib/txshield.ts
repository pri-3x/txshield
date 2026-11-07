import "server-only";
import { TxShield } from "@txshield/sdk";

// Server-side client. The API key (if any) stays on the dashboard server and
// never reaches the browser; browsers only talk to this Next.js app.
let client: TxShield | undefined;

export function txshield(): TxShield {
  if (!client) {
    client = new TxShield({
      baseUrl: process.env.TXSHIELD_API_URL ?? "http://localhost:8080",
      apiKey: process.env.TXSHIELD_API_KEY || undefined,
      timeoutMs: 55_000,
    });
  }
  return client;
}

/** API location for display (never includes credentials). */
export function apiLocation(): string {
  try {
    const u = new URL(process.env.TXSHIELD_API_URL ?? "http://localhost:8080");
    return `${u.protocol}//${u.host}`;
  } catch {
    return "(invalid TXSHIELD_API_URL)";
  }
}
