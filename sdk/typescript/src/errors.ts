import type { FieldError } from "./types.js";

/**
 * Error kinds. Server kinds are passed through; the client adds:
 * - `network`: the request did not reach the server or the connection failed
 * - `aborted`: the caller's AbortSignal fired
 * - `invalid_response`: the server answered with something that is not valid API JSON
 * (client-side timeouts use the server's `timeout` kind, code `client_timeout`).
 */
export type TxShieldErrorKind =
  | "invalid_input"
  | "not_found"
  | "payload_too_large"
  | "rate_limited"
  | "unsupported"
  | "unavailable"
  | "timeout"
  | "internal"
  | "network"
  | "aborted"
  | "invalid_response";

export interface TxShieldErrorInit {
  kind: TxShieldErrorKind;
  code: string;
  message: string;
  status?: number;
  fields?: FieldError[];
  requestId?: string;
  retryAfterMs?: number;
  cause?: unknown;
}

/** The single error type thrown by the SDK. */
export class TxShieldError extends Error {
  readonly kind: TxShieldErrorKind;
  /** Stable machine-readable code, e.g. "validation_failed", "rate_limited". */
  readonly code: string;
  /** HTTP status, when a response was received. */
  readonly status?: number;
  /** Per-field validation problems. */
  readonly fields: FieldError[];
  /** Server request ID for log correlation. */
  readonly requestId?: string;
  /** Server-advised wait (from Retry-After), when present. */
  readonly retryAfterMs?: number;

  constructor(init: TxShieldErrorInit) {
    const detail = init.fields?.length ? ` (${init.fields.map((f) => `${f.field}: ${f.message}`).join("; ")})` : "";
    super(`${init.message}${detail}`, init.cause === undefined ? undefined : { cause: init.cause });
    this.name = "TxShieldError";
    this.kind = init.kind;
    this.code = init.code;
    this.status = init.status;
    this.fields = init.fields ?? [];
    this.requestId = init.requestId;
    this.retryAfterMs = init.retryAfterMs;
  }

  /** True for errors worth retrying later (rate limits, outages, timeouts, network). */
  get retryable(): boolean {
    return (
      this.kind === "rate_limited" ||
      this.kind === "network" ||
      this.kind === "timeout" ||
      (this.kind === "unavailable" && !PERMANENT_UNAVAILABLE.has(this.code))
    );
  }
}

/** 503 codes that describe server configuration, not a transient outage. */
export const PERMANENT_UNAVAILABLE = new Set(["persistence_disabled", "engine_unavailable"]);

/** Type guard. */
export function isTxShieldError(e: unknown): e is TxShieldError {
  return e instanceof TxShieldError;
}

const statusKinds: Record<number, TxShieldErrorKind> = {
  400: "invalid_input",
  401: "invalid_input",
  404: "not_found",
  405: "invalid_input",
  413: "payload_too_large",
  422: "unsupported",
  429: "rate_limited",
  503: "unavailable",
  504: "timeout",
};

/** Fallback kind for an HTTP status when the body is not an API error. */
export function kindForStatus(status: number): TxShieldErrorKind {
  return statusKinds[status] ?? (status >= 500 ? "internal" : "invalid_response");
}
