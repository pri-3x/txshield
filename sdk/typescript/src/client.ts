import { TxShieldError, kindForStatus, PERMANENT_UNAVAILABLE } from "./errors.js";
import type { TxShieldErrorKind } from "./errors.js";
import type {
  AddressQuery,
  AddressReport,
  AnalysisPage,
  AnalysisResult,
  AnalysisStats,
  AnalyzeInput,
  ApprovalAnalysis,
  DecodedCall,
  DecodeInput,
  HealthResponse,
  InfoResponse,
  ListAnalysesQuery,
  RequestOptions,
  RiskReport,
  SimulateInput,
  SimulationResult,
  TransactionLookup,
} from "./types.js";
import { isAddress, toAnalyzeBody, toDecodeBody, toSimulateBody, validationError } from "./validate.js";

export interface TxShieldOptions {
  /** API base URL, e.g. "http://localhost:8080". */
  baseUrl: string;
  /** Sent as "Authorization: Bearer <apiKey>" when the server requires keys. */
  apiKey?: string;
  /** Deadline for each call, including retries (default 60 000 ms). Simulation can take seconds. */
  timeoutMs?: number;
  /** Retries for transient failures: network errors, 429, 502-504 (default 2). */
  maxRetries?: number;
  /** Custom fetch implementation (defaults to globalThis.fetch). */
  fetch?: typeof fetch;
  /** Extra headers sent with every request. */
  headers?: Record<string, string>;
}

const RETRY_STATUSES = new Set([429, 502, 503, 504]);
const MAX_RETRY_AFTER_MS = 30_000;

/**
 * Client for the TxShield API. Every method returns a promise and reports
 * every failure (including client-side validation) by rejecting with a
 * TxShieldError; nothing throws synchronously.
 *
 * TxShield never signs or broadcasts transactions, and a low risk score is
 * never a safety guarantee.
 *
 * ```ts
 * const shield = new TxShield({ baseUrl: "http://localhost:8080" });
 * const result = await shield.analyze({ chainId: 1, from, to, value: "0", data });
 * console.log(result.riskScore, result.findings);
 * ```
 */
export class TxShield {
  readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly fetchImpl: typeof fetch;
  private readonly headers: Record<string, string>;

  constructor(options: TxShieldOptions) {
    if (!options || typeof options.baseUrl !== "string") {
      throw new TypeError("TxShield: options.baseUrl is required");
    }
    let url: URL;
    try {
      url = new URL(options.baseUrl);
    } catch {
      throw new TypeError("TxShield: options.baseUrl must be an absolute URL");
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new TypeError("TxShield: options.baseUrl must use http or https");
    }
    if (url.search || url.hash) {
      throw new TypeError("TxShield: options.baseUrl must not contain a query or fragment");
    }
    this.baseUrl = url.toString().replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.timeoutMs = positiveInt(options.timeoutMs, 60_000, "timeoutMs");
    this.maxRetries = options.maxRetries === undefined ? 2 : nonNegativeInt(options.maxRetries, "maxRetries");
    const f = options.fetch ?? globalThis.fetch;
    if (typeof f !== "function") {
      throw new TypeError("TxShield: no fetch implementation available; pass options.fetch (Node 18+ has a global fetch)");
    }
    this.fetchImpl = f;
    this.headers = { ...(options.headers ?? {}) };
  }

  /** Full analysis: decode, reputation, contract checks, simulation, rules, risk score. */
  async analyze(input: AnalyzeInput, opts?: RequestOptions): Promise<AnalysisResult> {
    const report = await this.request<RiskReport>("POST", "/api/v1/analyze", toAnalyzeBody(input), opts);
    return withConvenience(report);
  }

  /** Simulation only. A revert is a successful result with `status: "reverted"`. */
  async simulate(input: SimulateInput, opts?: RequestOptions): Promise<SimulationResult> {
    return this.request("POST", "/api/v1/simulate", toSimulateBody(input), opts);
  }

  /** Permissions the transaction grants, what is currently in force on-chain, and approval findings. */
  async analyzeApprovals(input: AnalyzeInput, opts?: RequestOptions): Promise<ApprovalAnalysis> {
    return this.request("POST", "/api/v1/approvals/analyze", toAnalyzeBody(input), opts);
  }

  /** Offline calldata decoding (no chain access, nothing stored). */
  async decode(input: DecodeInput, opts?: RequestOptions): Promise<DecodedCall> {
    return this.request("POST", "/api/v1/decode", toDecodeBody(input), opts);
  }

  /**
   * Fetches a transaction by hash, ready to pass to `analyze()`. Mined
   * transactions replay on top of their parent block (see `notes`).
   */
  async getTransaction(hash: string, query: { chainId: number | bigint }, opts?: RequestOptions): Promise<TransactionLookup> {
    if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) throw validationError([{ field: "hash", message: "must be a 0x-prefixed 32-byte hash" }]);
    return this.request("GET", `/api/v1/transactions/${hash}?chainId=${chainParam(query.chainId)}`, undefined, opts);
  }

  /** Contract facts, reputation, and stored analyses involving an address. */
  async inspectAddress(address: string, query: AddressQuery, opts?: RequestOptions): Promise<AddressReport> {
    if (!isAddress(address)) throw validationError([{ field: "address", message: "must be a 0x-prefixed 20-byte address" }]);
    const params = pageParams(query);
    params.set("chainId", chainParam(query.chainId));
    return this.request("GET", `/api/v1/address/${address}?${params}`, undefined, opts);
  }

  /** Stored analyses, newest first. Requires server persistence. */
  async listAnalyses(query: ListAnalysesQuery = {}, opts?: RequestOptions): Promise<AnalysisPage> {
    const params = pageParams(query);
    if (query.chainId !== undefined) params.set("chainId", chainParam(query.chainId));
    if (query.minScore !== undefined) {
      if (!Number.isInteger(query.minScore) || query.minScore < 0 || query.minScore > 100) {
        throw validationError([{ field: "minScore", message: "must be an integer between 0 and 100" }]);
      }
      params.set("minScore", String(query.minScore));
    }
    if (query.address !== undefined) {
      if (!isAddress(query.address)) throw validationError([{ field: "address", message: "must be a 0x-prefixed 20-byte address" }]);
      params.set("address", query.address);
    }
    if (query.since !== undefined) params.set("since", sinceParam(query.since));
    const qs = params.toString();
    return this.request("GET", `/api/v1/analyses${qs ? `?${qs}` : ""}`, undefined, opts);
  }

  /** One stored analysis (with the server's privacy options applied). */
  async getAnalysis(id: string, opts?: RequestOptions): Promise<AnalysisResult> {
    if (!/^[0-9a-fA-F-]{36}$/.test(id)) throw validationError([{ field: "id", message: "must be a UUID" }]);
    return withConvenience(await this.request<RiskReport>("GET", `/api/v1/analyses/${id}`, undefined, opts));
  }

  /** Aggregate statistics. Requires server persistence. */
  async stats(query: { since?: Date | string } = {}, opts?: RequestOptions): Promise<AnalysisStats> {
    const qs = query.since !== undefined ? `?${new URLSearchParams({ since: sinceParam(query.since) })}` : "";
    return this.request("GET", `/api/v1/stats${qs}`, undefined, opts);
  }

  /** Server configuration: chains, simulator, rules, reputation sources. */
  async info(opts?: RequestOptions): Promise<InfoResponse> {
    return this.request("GET", "/api/v1/info", undefined, opts);
  }

  /** Health with dependency checks. Resolves for both 200 and 503 (inspect `status`). */
  async health(opts?: RequestOptions): Promise<HealthResponse> {
    return this.request("GET", "/health", undefined, opts, [503]);
  }

  private async request<T>(method: string, path: string, body: unknown, opts: RequestOptions = {}, okStatuses: number[] = []): Promise<T> {
    const timeoutMs = opts.timeoutMs === undefined ? this.timeoutMs : positiveInt(opts.timeoutMs, this.timeoutMs, "timeoutMs");
    const deadline = Date.now() + timeoutMs;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new DeadlineError()), timeoutMs);
    const onAbort = () => controller.abort(opts.signal?.reason);
    if (opts.signal) {
      if (opts.signal.aborted) {
        clearTimeout(timer);
        throw aborted(opts.signal.reason);
      }
      opts.signal.addEventListener("abort", onAbort, { once: true });
    }
    const headers: Record<string, string> = { Accept: "application/json", ...this.headers };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (this.apiKey) headers.Authorization = `Bearer ${this.apiKey}`;
    if (opts.requestId) headers["X-Request-ID"] = opts.requestId;
    const payload = body === undefined ? undefined : JSON.stringify(body);

    try {
      for (let attempt = 0; ; attempt++) {
        let err: TxShieldError;
        try {
          const res = await this.fetchImpl(this.baseUrl + path, { method, headers, body: payload, signal: controller.signal });
          if (res.ok || okStatuses.includes(res.status)) {
            return (await parseJSON(res)) as T;
          }
          err = await responseError(res);
        } catch (e) {
          if (e instanceof TxShieldError) throw e;
          if (controller.signal.aborted) {
            throw controller.signal.reason instanceof DeadlineError ? timeoutError(timeoutMs) : aborted(controller.signal.reason);
          }
          err = new TxShieldError({ kind: "network", code: "network_error", message: "could not reach the TxShield API", cause: e });
        }
        const retryable = err.kind === "network" || (err.status !== undefined && RETRY_STATUSES.has(err.status) && !PERMANENT_UNAVAILABLE.has(err.code));
        if (!retryable || attempt >= this.maxRetries) throw err;
        const delay = err.retryAfterMs ?? backoff(attempt);
        if (Date.now() + delay >= deadline) throw err;
        await sleep(delay, controller.signal).catch(() => {
          throw controller.signal.reason instanceof DeadlineError ? timeoutError(timeoutMs) : aborted(controller.signal.reason);
        });
      }
    } finally {
      clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onAbort);
    }
  }
}

class DeadlineError extends Error {}

function timeoutError(ms: number): TxShieldError {
  return new TxShieldError({ kind: "timeout", code: "client_timeout", message: `request did not complete within ${ms} ms` });
}

function aborted(reason: unknown): TxShieldError {
  return new TxShieldError({ kind: "aborted", code: "aborted", message: "request was aborted", cause: reason });
}

async function parseJSON(res: Response): Promise<unknown> {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new TxShieldError({
      kind: "invalid_response", code: "invalid_json", message: "the server returned a response that is not JSON",
      status: res.status, requestId: res.headers.get("X-Request-ID") ?? undefined, cause: e,
    });
  }
}

async function responseError(res: Response): Promise<TxShieldError> {
  const requestId = res.headers.get("X-Request-ID") ?? undefined;
  const retryAfterMs = parseRetryAfter(res.headers.get("Retry-After"));
  let detail: { kind?: string; code?: string; message?: string; fields?: { field: string; message: string }[]; requestId?: string } | undefined;
  try {
    const body = (await res.json()) as { error?: typeof detail };
    detail = body?.error;
  } catch {
    // Not an API error body (proxy page, empty body): fall back to the status.
  }
  return new TxShieldError({
    kind: (detail?.kind as TxShieldErrorKind | undefined) ?? kindForStatus(res.status),
    code: detail?.code ?? `http_${res.status}`,
    message: detail?.message ?? `HTTP ${res.status}`,
    status: res.status,
    fields: detail?.fields,
    requestId: detail?.requestId ?? requestId,
    retryAfterMs,
  });
}

/** Parses Retry-After (seconds or HTTP date), capped at 30 s. */
export function parseRetryAfter(v: string | null): number | undefined {
  if (!v) return undefined;
  const secs = Number(v);
  let ms: number;
  if (Number.isFinite(secs)) ms = secs * 1000;
  else {
    const at = Date.parse(v);
    if (Number.isNaN(at)) return undefined;
    ms = at - Date.now();
  }
  return Math.min(Math.max(ms, 0), MAX_RETRY_AFTER_MS);
}

/** Exponential backoff with full jitter: uniform in [0, min(8 s, 500 ms * 2^attempt)]. */
function backoff(attempt: number): number {
  return Math.random() * Math.min(8_000, 500 * 2 ** attempt);
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(signal.reason);
    const t = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(t);
      reject(signal.reason);
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function withConvenience(report: RiskReport): AnalysisResult {
  return Object.assign(report, { riskScore: report.risk.score, riskCategory: report.risk.category });
}

function pageParams(q: { limit?: number; offset?: number }): URLSearchParams {
  const p = new URLSearchParams();
  if (q.limit !== undefined) {
    if (!Number.isInteger(q.limit) || q.limit < 1 || q.limit > 100) throw validationError([{ field: "limit", message: "must be an integer between 1 and 100" }]);
    p.set("limit", String(q.limit));
  }
  if (q.offset !== undefined) {
    if (!Number.isInteger(q.offset) || q.offset < 0 || q.offset > 10_000) throw validationError([{ field: "offset", message: "must be an integer between 0 and 10000" }]);
    p.set("offset", String(q.offset));
  }
  return p;
}

function chainParam(c: number | bigint): string {
  let v: bigint;
  try {
    v = BigInt(c);
  } catch {
    throw validationError([{ field: "chainId", message: "must be an integer" }]);
  }
  if (v < 1n || v > 2n ** 53n - 1n) throw validationError([{ field: "chainId", message: "must be between 1 and 2^53-1" }]);
  return v.toString();
}

function sinceParam(s: Date | string): string {
  const d = s instanceof Date ? s : new Date(s);
  if (Number.isNaN(d.getTime())) throw validationError([{ field: "since", message: "must be a Date or RFC 3339 string" }]);
  return d.toISOString();
}

function positiveInt(v: number | undefined, def: number, name: string): number {
  if (v === undefined) return def;
  if (!Number.isFinite(v) || v <= 0) throw new TypeError(`TxShield: ${name} must be a positive number`);
  return v;
}

function nonNegativeInt(v: number, name: string): number {
  if (!Number.isInteger(v) || v < 0) throw new TypeError(`TxShield: ${name} must be a non-negative integer`);
  return v;
}
