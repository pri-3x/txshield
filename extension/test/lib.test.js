import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const lib = require("../src/lib.js");
// Fixtures are real /api/v1/analyze responses from the local Anvil demo chain.
const drainer = JSON.parse(readFileSync(new URL("./fixtures/drainer-report.json", import.meta.url)));
const send = JSON.parse(readFileSync(new URL("./fixtures/send-report.json", import.meta.url)));
const approve = JSON.parse(readFileSync(new URL("./fixtures/approve-report.json", import.meta.url)));

const FROM = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

describe("toApiRequest", () => {
  it("maps wallet params to an analyze request", () => {
    const r = lib.toApiRequest({ from: FROM, to: drainer.transaction.to, value: "0x2386f26fc10000", data: "0x4e71d92d", gas: "0x5208" }, "0x7a69");
    expect(r).toEqual({ ok: true, request: { chainId: 31337, from: FROM, to: drainer.transaction.to, value: "0x2386f26fc10000", data: "0x4e71d92d", gas: "0x5208", simulate: true } });
  });

  it("accepts input/gasLimit aliases and contract creation", () => {
    const r = lib.toApiRequest({ from: FROM, input: "0x6080", gasLimit: 100000 }, 1);
    expect(r.ok && r.request).toMatchObject({ chainId: 1, data: "0x6080", gas: "100000" });
    expect(r.request.to).toBeUndefined();
  });

  it.each([
    [{ to: FROM }, "0x1", "missing or invalid sender"],
    [{ from: "0x123", to: FROM }, "0x1", "missing or invalid sender"],
    [{ from: FROM, to: "nope" }, "0x1", "invalid recipient"],
    [{ from: FROM, to: FROM, data: "0xzz" }, "0x1", "invalid calldata"],
    [{ from: FROM, to: FROM, value: "-1" }, "0x1", "invalid value"],
    [{ from: FROM, to: FROM }, undefined, "unknown chain"],
    [{ from: FROM }, "0x1", "transaction has neither recipient nor data"],
  ])("rejects %j", (tx, chain, error) => {
    expect(lib.toApiRequest(tx, chain)).toEqual({ ok: false, error });
  });
});

describe("normalizeApiUrl", () => {
  it("accepts http(s) and rejects other schemes or embedded credentials", () => {
    expect(lib.normalizeApiUrl("https://api.example.org/")).toBe("https://api.example.org");
    expect(lib.normalizeApiUrl("http://127.0.0.1:18080")).toBe("http://127.0.0.1:18080");
    expect(lib.normalizeApiUrl("javascript:alert(1)")).toBeNull();
    expect(lib.normalizeApiUrl("ftp://x")).toBeNull();
    expect(lib.normalizeApiUrl("https://user:pw@x.org")).toBeNull();
  });
});

describe("decide", () => {
  it("warns at or above the threshold and on reverts", () => {
    expect(lib.decide(drainer, 20)).toBe("warn");
    expect(lib.decide(send, 20)).toBe("allow");
    expect(lib.decide({ ...send, simulation: { ...send.simulation, status: "reverted" } }, 20)).toBe("warn");
  });
});

describe("viewModel", () => {
  it("explains a drainer in plain language", () => {
    const vm = lib.viewModel(drainer, { dashboardUrl: "http://localhost:3000/" });
    expect(vm.category).toBe("critical");
    expect(vm.headline).toBe("Don't sign this. It sends 0.01 ETH, 1,000 TUSD* and NFT #1 out of your wallet, and you receive nothing.");
    expect(vm.sends.map((s) => s.label)).toEqual(["0.01 ETH", "1,000 TUSD", "NFT #1"]);
    expect(vm.sends[1]).toMatchObject({ unverified: true, entireBalance: true });
    expect(vm.receivesNothing).toBe(true);
    expect(vm.recipients).toContain("0x3C44…93BC");
    expect(vm.reasons).toHaveLength(3);
    expect(vm.reasons[0]).toEqual({ severity: "high", title: "Unexpected asset leaves the wallet", count: 2 }); // one line per reason
    expect(new Set(vm.reasons.map((r) => r.title)).size).toBe(3);
    expect(vm.reportUrl).toBe(`http://localhost:3000/analyses/${drainer.id}`);
    expect(vm.anyUnverified).toBe(true);
  });

  it("names the spender and the permission an approval grants", () => {
    const vm = lib.viewModel(approve, {});
    expect(vm.category).toBe("critical");
    expect(vm.headline).toBe("Don't sign this. It lets 0x0000…dEaD spend an unlimited amount of your tokens at 0x9fE4…a6e0.");
    expect(vm.permissions).toEqual([{ spender: "0x0000…dEaD", what: "an unlimited amount of your tokens at 0x9fE4…a6e0", unlimited: true, signed: false }]);
    expect(vm.reasons[0].severity).toBe("critical");
  });

  it("never calls a transaction safe", () => {
    for (const r of [drainer, send, approve]) {
      const text = JSON.stringify(lib.viewModel(r, {})).replace("not a guarantee of safety", "");
      expect(text).not.toMatch(/\bsafe\b/i);
    }
    expect(lib.viewModel(send, {}).headline).toBe("No significant risks detected by enabled checks.");
  });

  it("strips hidden characters from token symbols and finding titles", () => {
    const evil = structuredClone(drainer);
    evil.balanceChanges[1].asset.symbol = "US‮DC​";
    evil.findings[0].title = "Totally\u0007 fine";
    const vm = lib.viewModel(evil, {});
    expect(vm.sends[1].label).toBe("1,000 USDC");
    expect(vm.reasons.map((r) => r.title).join(" ")).not.toMatch(/[\u0000-\u001f‮​]/);
  });

  it("says when nothing was simulated", () => {
    const r = { ...send, simulation: { status: "not_run", incompleteReasons: ["no RPC endpoint is configured for this chain"] }, balanceChanges: [] };
    const vm = lib.viewModel(r, {});
    expect(vm.simulated).toBe(false);
    expect(vm.notSimulatedReason).toMatch(/no RPC endpoint/);
  });
});

describe("analyze", () => {
  const settings = { ...lib.DEFAULTS, apiUrl: "https://api.example.org", apiKey: "k" };
  it("posts the request with the key and returns the report", async () => {
    let seen;
    const fetchImpl = async (url, init) => {
      seen = { url, init };
      return { ok: true, status: 200, json: async () => drainer };
    };
    const res = await lib.analyze(settings, { chainId: 1, from: FROM, to: FROM }, fetchImpl);
    expect(res.ok).toBe(true);
    expect(seen.url).toBe("https://api.example.org/api/v1/analyze");
    expect(seen.init.headers.Authorization).toBe("Bearer k");
    expect(seen.init.credentials).toBe("omit");
  });

  it("turns API errors and network failures into messages", async () => {
    const err = await lib.analyze(settings, {}, async () => ({ ok: false, status: 400, json: async () => ({ error: { message: "request validation failed", fields: [{ field: "from", message: "bad" }] } }) }));
    expect(err).toEqual({ ok: false, status: 400, error: "TxShield API error: request validation failed (from: bad)" });
    const down = await lib.analyze(settings, {}, async () => {
      throw new TypeError("fetch failed");
    });
    expect(down.ok).toBe(false);
    expect(down.error).toMatch(/Could not reach/);
    expect((await lib.analyze({ ...settings, apiUrl: "file:///x" }, {})).ok).toBe(false);
  });
});
