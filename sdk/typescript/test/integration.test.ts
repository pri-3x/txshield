// Integration tests: drive a real `txshield serve` through the SDK.
//
// The server binary is taken from TXSHIELD_BIN, or built with `go build`
// when Go is available. If `anvil` is installed, a local chain is started
// and wired in so simulation and contract checks run for real. No external
// network is used.
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TxShield, TxShieldError } from "../src/index.js";

const repoRoot = resolve(__dirname, "../../..");
const API_KEY = "sdk-integration-key-0123456789";
// Anvil's first two default development accounts (unlocked and funded on a
// fresh local chain; never used on real networks).
const DEV0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const DEV1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const BLOCKED = "0x000000000000000000000000000000000000dEaD";

function has(cmd: string, versionArg = "--version"): boolean {
  try {
    execFileSync(cmd, [versionArg], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const addr = s.address();
      s.close(() => (addr && typeof addr === "object" ? res(addr.port) : rej(new Error("no port"))));
    });
  });
}

async function waitFor(url: string, ms = 20_000): Promise<void> {
  const end = Date.now() + ms;
  for (;;) {
    try {
      const r = await fetch(url, { method: url.endsWith("/livez") ? "GET" : "POST", headers: { "Content-Type": "application/json" }, body: url.endsWith("/livez") ? undefined : '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' });
      if (r.ok) return;
    } catch {
      // not up yet
    }
    if (Date.now() > end) throw new Error(`timed out waiting for ${url}`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

const binary = process.env.TXSHIELD_BIN || (has("go", "version") ? "build" : "");
const withAnvil = has("anvil");
const procs: ChildProcess[] = [];
let baseUrl = "";

describe.skipIf(!binary)("SDK against a real txshield server", () => {
  beforeAll(async () => {
    let bin = process.env.TXSHIELD_BIN ?? "";
    if (!bin) {
      bin = join(mkdtempSync(join(tmpdir(), "txshield-sdk-")), "txshield");
      execFileSync("go", ["build", "-o", bin, "./cmd/txshield"], { cwd: repoRoot, stdio: "inherit" });
    }
    const env: Record<string, string> = {
      ...(process.env as Record<string, string>),
      TXSHIELD_API_KEYS: API_KEY,
      TXSHIELD_REPUTATION_FILES: join(repoRoot, "configs/reputation/example-blocklist.json"),
      TXSHIELD_RATE_LIMIT_RPS: "0",
      TXSHIELD_LOG_LEVEL: "warn",
    };
    if (withAnvil) {
      const anvilPort = await freePort();
      procs.push(spawn("anvil", ["--host", "127.0.0.1", "--port", String(anvilPort), "--silent"], { stdio: "ignore" }));
      await waitFor(`http://127.0.0.1:${anvilPort}`);
      env.TXSHIELD_RPC_URLS = `31337=http://127.0.0.1:${anvilPort}`;
      env.TXSHIELD_SIMULATOR = "anvil";
    }
    const port = await freePort();
    env.TXSHIELD_HTTP_ADDR = `127.0.0.1:${port}`;
    procs.push(spawn(bin, ["serve"], { env, stdio: ["ignore", "ignore", "inherit"] }));
    baseUrl = `http://127.0.0.1:${port}`;
    await waitFor(`${baseUrl}/livez`);
  }, 180_000);

  afterAll(() => {
    for (const p of procs) p.kill("SIGTERM");
  });

  const client = () => new TxShield({ baseUrl, apiKey: API_KEY, timeoutMs: 30_000 });

  it("rejects requests without the API key", async () => {
    const err = await new TxShield({ baseUrl }).info().catch((e) => e);
    expect(err).toBeInstanceOf(TxShieldError);
    expect(err).toMatchObject({ status: 401, code: "unauthorized" });
    expect(err.requestId).toBeTruthy();
  });

  it("info and health are typed and populated", async () => {
    const info = await client().info();
    expect(info.rules).toBeGreaterThan(20);
    expect(info.reputationSources).toContain("list:example-blocklist");
    const health = await client().health();
    expect(["ok", "degraded"]).toContain(health.status);
  });

  it("analyze returns a typed report with convenience fields", async () => {
    const r = await client().analyze({
      chainId: 1, from: DEV1, to: USDC, value: 0n,
      data: "0x095ea7b3000000000000000000000000000000000000000000000000000000000000dead" + "f".repeat(64),
      simulate: false,
    });
    expect(r.riskScore).toBe(r.risk.score);
    expect(r.riskCategory).toBe("critical");
    const ids = r.findings.map((f) => f.ruleId);
    expect(ids).toContain("TXS-APPROVAL-005");
    expect(r.approvals[0]?.unlimited).toBe(true);
    expect(r.verdict.toLowerCase()).not.toContain("safe");
  });

  it("server-side validation surfaces field errors", async () => {
    // Mixed-case address with a bad EIP-55 checksum: shape-valid on the
    // client, rejected by the server.
    const err = await client().analyze({ chainId: 1, from: "0x70997970c51812dc3a010c7d01b50e0d17dc79C8", to: USDC }).catch((e) => e);
    expect(err).toMatchObject({ status: 400, kind: "invalid_input", code: "validation_failed" });
    expect(err.fields[0]).toMatchObject({ field: "from" });
  });

  it("history endpoints report disabled persistence without retrying", async () => {
    const start = Date.now();
    const err = await client().listAnalyses().catch((e) => e);
    expect(err).toMatchObject({ status: 503, code: "persistence_disabled", retryable: false });
    expect(Date.now() - start).toBeLessThan(2_000);
  });

  it.skipIf(!withAnvil)("simulates on a local fork and analyzes with simulation", async () => {
    const sim = await client().simulate({ chainId: 31337, from: DEV0, to: DEV1, value: 10n ** 18n });
    expect(sim.status).toBe("success");
    expect(sim.backend).toBe("anvil");
    expect(sim.balanceChanges?.[0]?.delta).toBe("-1000000000000000000");

    const r = await client().analyze({ chainId: 31337, from: DEV0, to: DEV1, value: "1000000000000000000" });
    expect(r.simulation?.backend).toBe("anvil");
    expect(r.risk.confidence).toBe("high");
    expect(r.riskScore).toBe(0);

    const appr = await client().analyzeApprovals({ chainId: 31337, from: DEV0, to: DEV1, value: 1 });
    expect(appr.approvals).toHaveLength(0);

    const addr = await client().inspectAddress(DEV1, { chainId: 31337 });
    expect(addr.contract?.isContract).toBe(false);
  });
});
