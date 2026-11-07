import { describe, expect, it, vi } from "vitest";
import { TxShield, TxShieldError, isTxShieldError, parseRetryAfter, toWireTransaction } from "../src/index.js";

const FROM = "0x1111111111111111111111111111111111111111";
const TO = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const APPROVE =
  "0x095ea7b3000000000000000000000000dead000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

type Scripted = { status?: number; body?: unknown; raw?: string; headers?: Record<string, string> } | Error;

/** A fetch mock that replays scripted responses and records requests. */
function mockFetch(...script: Scripted[]) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fn = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    const next = script.shift();
    if (!next) throw new Error("unexpected request");
    if (next instanceof Error) throw next;
    const text = next.raw ?? JSON.stringify(next.body ?? {});
    return new Response(text, { status: next.status ?? 200, headers: { "Content-Type": "application/json", ...(next.headers ?? {}) } });
  });
  return { fetch: fn as unknown as typeof fetch, calls };
}

const report = (score: number, category = "low") => ({
  id: "6f1c0d4e-1a2b-4c3d-8e9f-0a1b2c3d4e5f",
  risk: { score, category, confidence: "medium", contributions: [] },
  findings: [],
  approvals: [],
  verdict: "No significant risks detected by enabled checks.",
  disclaimer: "x",
});

describe("construction", () => {
  it("validates options", () => {
    expect(() => new TxShield({ baseUrl: "not a url" })).toThrow(/absolute URL/);
    expect(() => new TxShield({ baseUrl: "ftp://x" })).toThrow(/http or https/);
    expect(() => new TxShield({ baseUrl: "http://x?a=1" })).toThrow(/query/);
    expect(() => new TxShield({ baseUrl: "http://x", timeoutMs: 0 })).toThrow(/timeoutMs/);
    expect(() => new TxShield({ baseUrl: "http://x", maxRetries: -1 })).toThrow(/maxRetries/);
    expect(new TxShield({ baseUrl: "http://localhost:8080///" }).baseUrl).toBe("http://localhost:8080");
  });
});

describe("analyze", () => {
  it("sends the wire format and adds convenience fields", async () => {
    const m = mockFetch({ body: report(22, "moderate"), headers: { "X-Request-ID": "srv-1" } });
    const shield = new TxShield({ baseUrl: "http://api.test/", apiKey: "secret-key", fetch: m.fetch, headers: { "X-Team": "a" } });
    const res = await shield.analyze(
      { chainId: 1n, from: FROM, to: TO, value: 10n ** 18n, data: APPROVE, gas: 21000, maxFeePerGas: "0x3b9aca00", simulate: false, abi: "[]" },
      { requestId: "client-1" },
    );
    expect(res.riskScore).toBe(22);
    expect(res.riskCategory).toBe("moderate");
    expect(res.risk.score).toBe(22);

    const call = m.calls[0]!;
    expect(call.url).toBe("http://api.test/api/v1/analyze");
    expect(call.init.method).toBe("POST");
    const h = call.init.headers as Record<string, string>;
    expect(h.Authorization).toBe("Bearer secret-key");
    expect(h["X-Request-ID"]).toBe("client-1");
    expect(h["X-Team"]).toBe("a");
    expect(h["Content-Type"]).toBe("application/json");
    expect(JSON.parse(call.init.body as string)).toEqual({
      chainId: 1, from: FROM, to: TO, value: "1000000000000000000", data: APPROVE, gas: "21000",
      maxFeePerGas: "1000000000", simulate: false, abi: [],
    });
  });

  it("collects every client-side validation problem before sending", async () => {
    const m = mockFetch();
    const shield = new TxShield({ baseUrl: "http://api.test", fetch: m.fetch });
    const err = await shield
      .analyze({ chainId: 0, from: "0x12", to: "nope", data: "0xabc", value: -1n, gasPrice: 1, maxFeePerGas: 2, block: "pending", rpcUrl: "http://x", abi: "{" })
      .catch((e) => e);
    expect(isTxShieldError(err)).toBe(true);
    expect(err.kind).toBe("invalid_input");
    expect(err.code).toBe("client_validation");
    expect(err.fields.map((f: { field: string }) => f.field).sort()).toEqual(
      ["abi", "block", "chainId", "data", "from", "gasPrice", "rpcUrl", "to", "value"].sort(),
    );
    expect(m.calls).toHaveLength(0);
  });

  it("rejects unsafe JavaScript numbers instead of losing precision", () => {
    expect(() => toWireTransaction({ chainId: 1, from: FROM, to: TO, value: 2 ** 60 })).toThrow(/safe integer/);
    expect(toWireTransaction({ chainId: 1, from: FROM, to: TO, value: 2n ** 60n }).value).toBe("1152921504606846976");
  });

  it("accepts contract creation and fee rules like the server", () => {
    expect(toWireTransaction({ chainId: 1, from: FROM, data: "0x6080" }).to).toBeUndefined();
    expect(() => toWireTransaction({ chainId: 1, from: FROM })).toThrow(/to/);
    expect(() => toWireTransaction({ chainId: 1, from: FROM, to: TO, maxPriorityFeePerGas: 1 })).toThrow(/maxFeePerGas/);
    expect(() => toWireTransaction({ chainId: 1, from: FROM, to: TO, maxFeePerGas: 1, maxPriorityFeePerGas: 2 })).toThrow(/must not exceed/);
    expect(() => toWireTransaction({ chainId: 1, from: FROM, to: TO, gas: 0 })).toThrow(/greater than 0/);
    expect(toWireTransaction({ chainId: 1, from: FROM, to: TO, block: 19_000_000 }).block).toBe("19000000");
    expect(toWireTransaction({ chainId: 1, from: FROM, to: TO, block: "0x" + "ab".repeat(32) }).block).toHaveLength(66);
  });
});

describe("errors", () => {
  it("maps API error bodies", async () => {
    const m = mockFetch({
      status: 400,
      body: { error: { kind: "invalid_input", code: "validation_failed", message: "request validation failed", fields: [{ field: "from", message: "invalid EIP-55 checksum" }], requestId: "r-9" } },
    });
    const err = await new TxShield({ baseUrl: "http://api.test", fetch: m.fetch }).analyze({ chainId: 1, from: FROM, to: TO }).catch((e) => e);
    expect(err).toBeInstanceOf(TxShieldError);
    expect(err).toMatchObject({ status: 400, kind: "invalid_input", code: "validation_failed", requestId: "r-9" });
    expect(err.message).toContain("from: invalid EIP-55 checksum");
    expect(err.retryable).toBe(false);
  });

  it("handles non-JSON error pages from proxies", async () => {
    const m = mockFetch({ status: 502, raw: "<html>Bad Gateway</html>", headers: { "Content-Type": "text/html" } });
    const err = await new TxShield({ baseUrl: "http://api.test", fetch: m.fetch, maxRetries: 0 }).info().catch((e) => e);
    expect(err).toMatchObject({ status: 502, kind: "internal", code: "http_502" });
  });

  it("reports invalid JSON success bodies", async () => {
    const m = mockFetch({ raw: "not json" });
    const err = await new TxShield({ baseUrl: "http://api.test", fetch: m.fetch }).info().catch((e) => e);
    expect(err).toMatchObject({ kind: "invalid_response", code: "invalid_json" });
  });
});

describe("retries", () => {
  it("retries 429 honoring Retry-After, then succeeds", async () => {
    const m = mockFetch(
      { status: 429, body: { error: { kind: "rate_limited", code: "rate_limited", message: "slow down" } }, headers: { "Retry-After": "0" } },
      { status: 503, body: { error: { kind: "unavailable", code: "rpc_unavailable", message: "down" } }, headers: { "Retry-After": "0" } },
      { body: report(0) },
    );
    const res = await new TxShield({ baseUrl: "http://api.test", fetch: m.fetch }).analyze({ chainId: 1, from: FROM, to: TO });
    expect(res.riskScore).toBe(0);
    expect(m.calls).toHaveLength(3);
  });

  it("retries network errors but not permanent 503s or client errors", async () => {
    let m = mockFetch(new TypeError("fetch failed"), { body: { status: "ok" } });
    await new TxShield({ baseUrl: "http://api.test", fetch: m.fetch }).health();
    expect(m.calls).toHaveLength(2);

    m = mockFetch({ status: 503, body: { error: { kind: "unavailable", code: "persistence_disabled", message: "off" } } });
    const err = await new TxShield({ baseUrl: "http://api.test", fetch: m.fetch }).listAnalyses().catch((e) => e);
    expect(err.code).toBe("persistence_disabled");
    expect(err.retryable).toBe(false);
    expect(m.calls).toHaveLength(1);

    m = mockFetch({ status: 422, body: { error: { kind: "unsupported", code: "simulation_unavailable", message: "no" } } });
    await new TxShield({ baseUrl: "http://api.test", fetch: m.fetch }).simulate({ chainId: 1, from: FROM, to: TO }).catch(() => undefined);
    expect(m.calls).toHaveLength(1);
  });

  it("gives up after maxRetries and when the wait would pass the deadline", async () => {
    const busy = { status: 503, body: { error: { kind: "unavailable", code: "rpc_unavailable", message: "x" } }, headers: { "Retry-After": "0" } };
    let m = mockFetch(busy, busy, busy);
    let err = await new TxShield({ baseUrl: "http://api.test", fetch: m.fetch, maxRetries: 2 }).info().catch((e) => e);
    expect(m.calls).toHaveLength(3);
    expect(err.retryable).toBe(true);

    m = mockFetch({ ...busy, headers: { "Retry-After": "20" } });
    const start = Date.now();
    err = await new TxShield({ baseUrl: "http://api.test", fetch: m.fetch, timeoutMs: 1000 }).info().catch((e) => e);
    expect(Date.now() - start).toBeLessThan(500);
    expect(err.retryAfterMs).toBe(20_000);
  });

  it("parses Retry-After forms", () => {
    expect(parseRetryAfter("3")).toBe(3000);
    expect(parseRetryAfter("9999")).toBe(30_000);
    expect(parseRetryAfter(null)).toBeUndefined();
    expect(parseRetryAfter("garbage")).toBeUndefined();
    expect(parseRetryAfter(new Date(Date.now() + 2000).toUTCString())).toBeGreaterThan(0);
  });
});

describe("timeouts and cancellation", () => {
  const hanging = () =>
    (async (_url: string | URL | Request, init?: RequestInit) =>
      new Promise<Response>((_, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      })) as unknown as typeof fetch;

  it("times out with kind timeout", async () => {
    const err = await new TxShield({ baseUrl: "http://api.test", fetch: hanging(), timeoutMs: 30 }).info().catch((e) => e);
    expect(err).toMatchObject({ kind: "timeout", code: "client_timeout" });
  });

  it("honors per-call timeout and caller AbortSignal", async () => {
    const shield = new TxShield({ baseUrl: "http://api.test", fetch: hanging(), timeoutMs: 60_000 });
    expect(await shield.info({ timeoutMs: 20 }).catch((e) => e.code)).toBe("client_timeout");
    const ac = new AbortController();
    const p = shield.info({ signal: ac.signal });
    ac.abort();
    expect(await p.catch((e) => e.kind)).toBe("aborted");
    expect(await shield.info({ signal: AbortSignal.abort() }).catch((e) => e.kind)).toBe("aborted");
  });
});

describe("queries", () => {
  it("builds query strings and validates parameters (always rejecting, never throwing)", async () => {
    const m = mockFetch({ body: { items: [], total: 0, limit: 5, offset: 10 } }, { body: { address: TO } }, { body: report(5) }, { body: { total: 0 } });
    const shield = new TxShield({ baseUrl: "http://api.test", fetch: m.fetch });
    await shield.listAnalyses({ limit: 5, offset: 10, chainId: 1, minScore: 60, address: TO, since: new Date("2026-01-01T00:00:00Z") });
    expect(m.calls[0]!.url).toBe(`http://api.test/api/v1/analyses?limit=5&offset=10&chainId=1&minScore=60&address=${TO}&since=2026-01-01T00%3A00%3A00.000Z`);
    await shield.inspectAddress(TO, { chainId: 11155111n, limit: 3 });
    expect(m.calls[1]!.url).toBe(`http://api.test/api/v1/address/${TO}?limit=3&chainId=11155111`);
    expect((await shield.getAnalysis("6f1c0d4e-1a2b-4c3d-8e9f-0a1b2c3d4e5f")).riskScore).toBe(5);
    await shield.stats({ since: "2026-01-01T00:00:00Z" });
    expect(m.calls[3]!.url).toContain("/api/v1/stats?since=");

    await expect(shield.listAnalyses({ limit: 0 })).rejects.toThrow(/limit/);
    await expect(shield.listAnalyses({ minScore: 101 })).rejects.toThrow(/minScore/);
    await expect(shield.inspectAddress("0x12", { chainId: 1 })).rejects.toThrow(/address/);
    await expect(shield.inspectAddress(TO, { chainId: 0 })).rejects.toThrow(/chainId/);
    await expect(shield.getAnalysis("../../etc/passwd")).rejects.toThrow(/UUID/);
    await expect(shield.stats({ since: "yesterday" })).rejects.toThrow(/since/);
  });

  it("health resolves on 503 so callers can read dependency status", async () => {
    const m = mockFetch({ status: 503, body: { status: "unhealthy", checks: { postgres: { status: "fail", critical: true } } } });
    const h = await new TxShield({ baseUrl: "http://api.test", fetch: m.fetch, maxRetries: 0 }).health();
    expect(h.status).toBe("unhealthy");
  });
});

describe("decode and transaction lookup", () => {
  it("decode sends calldata only and validates it", async () => {
    const m = mockFetch({ body: { kind: "contract_call", method: "approve", source: "builtin", callType: "call" } });
    const shield = new TxShield({ baseUrl: "http://api.test", fetch: m.fetch });
    const c = await shield.decode({ data: APPROVE });
    expect(c.method).toBe("approve");
    expect(JSON.parse(m.calls[0]!.init.body as string)).toEqual({ data: APPROVE });
    await expect(shield.decode({ data: "0x" })).rejects.toThrow(/data/);
    await expect(shield.decode({ data: APPROVE, to: "0x12" })).rejects.toThrow(/to/);
  });

  it("getTransaction validates the hash and passes chainId", async () => {
    const hash = "0x" + "ab".repeat(32);
    const m = mockFetch({ body: { hash, chainId: 1, transaction: { chainId: 1, from: FROM }, notes: [] } });
    const shield = new TxShield({ baseUrl: "http://api.test", fetch: m.fetch });
    const lk = await shield.getTransaction(hash, { chainId: 1 });
    expect(lk.transaction.from).toBe(FROM);
    expect(m.calls[0]!.url).toBe(`http://api.test/api/v1/transactions/${hash}?chainId=1`);
    await expect(shield.getTransaction("0x1234", { chainId: 1 })).rejects.toThrow(/hash/);
  });
});
