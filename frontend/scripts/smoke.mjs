// Smoke test: real API + real dashboard build, no mocks.
//
//   npm run build && npm run test:smoke
//
// Starts anvil (local chain), `txshield serve` (built with Go unless
// TXSHIELD_BIN is set) with an API key, and `next start`. If
// TXSHIELD_TEST_DATABASE_URL points at a migrated Postgres database, history
// pages are checked too. Fails with a non-zero exit code on any problem.
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import axe from "axe-core";
import { JSDOM, VirtualConsole } from "jsdom";
import { TxShield } from "@txshield/sdk";

const here = fileURLToPath(new URL(".", import.meta.url));
const frontend = resolve(here, "..");
const repo = resolve(frontend, "..");
const API_KEY = "dashboard-smoke-key-0123456789";
const BASIC = "smoke:dashboard-smoke-password";
const AUTH = { authorization: "Basic " + Buffer.from(BASIC).toString("base64") };
const DEV0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const DEV1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const procs = [];
let failures = 0;

const check = (ok, msg) => {
  console.log(`${ok ? "ok  " : "FAIL"} ${msg}`);
  if (!ok) failures++;
};

const freePort = () =>
  new Promise((res) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => res(port));
    });
  });

async function waitFor(url, init, ms = 60_000) {
  const end = Date.now() + ms;
  for (;;) {
    try {
      const r = await fetch(url, init);
      if (r.status < 500) return;
    } catch {}
    if (Date.now() > end) throw new Error(`timed out waiting for ${url}`);
    await new Promise((r) => setTimeout(r, 200));
  }
}

// Each service runs in its own process group so children (e.g. Next.js
// workers) are stopped too.
function start(cmd, args, env) {
  const p = spawn(cmd, args, { env: { ...process.env, ...env }, stdio: ["ignore", "ignore", "inherit"], detached: true });
  procs.push(p);
  return p;
}

async function a11y(html, name) {
  // Server-rendered HTML only (no client scripts run); axe is evaluated
  // inside the jsdom window. Color contrast needs real layout and is
  // checked visually instead.
  const virtualConsole = new VirtualConsole(); // drop jsdom "not implemented" noise (canvas)
  const { window } = new JSDOM(html, { runScripts: "outside-only", virtualConsole });
  window.eval(axe.source);
  const res = await window.axe.run(window.document, { rules: { "color-contrast": { enabled: false } } });
  const v = res.violations.map((x) => `${x.id} (${x.nodes.length})`);
  check(v.length === 0, `${name}: no axe violations${v.length ? ` -> ${v.join(", ")}` : ""}`);
}

async function page(base, path) {
  const r = await fetch(base + path, { redirect: "manual", headers: AUTH });
  return { status: r.status, csp: r.headers.get("content-security-policy") ?? "", html: await r.text() };
}

try {
  let bin = process.env.TXSHIELD_BIN;
  if (!bin) {
    bin = join(mkdtempSync(join(tmpdir(), "txshield-smoke-")), "txshield");
    execFileSync("go", ["build", "-o", bin, "./cmd/txshield"], { cwd: repo, stdio: "inherit" });
  }
  const anvilPort = await freePort();
  start("anvil", ["--host", "127.0.0.1", "--port", String(anvilPort), "--silent"]);
  await waitFor(`http://127.0.0.1:${anvilPort}`, { method: "POST", headers: { "content-type": "application/json" }, body: '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' });

  const apiPort = await freePort();
  const db = process.env.TXSHIELD_TEST_DATABASE_URL;
  start(bin, ["serve"], {
    TXSHIELD_HTTP_ADDR: `127.0.0.1:${apiPort}`,
    TXSHIELD_API_KEYS: API_KEY,
    TXSHIELD_RPC_URLS: `31337=http://127.0.0.1:${anvilPort}`,
    TXSHIELD_REPUTATION_FILES: join(repo, "configs/reputation/example-blocklist.json"),
    TXSHIELD_RATE_LIMIT_RPS: "0",
    TXSHIELD_LOG_LEVEL: "warn",
    ...(db ? { TXSHIELD_DATABASE_URL: db } : {}),
  });
  const apiUrl = `http://127.0.0.1:${apiPort}`;
  await waitFor(`${apiUrl}/livez`);

  const webPort = await freePort();
  start(process.execPath, [join(frontend, ".next/standalone/server.js")], {
    PORT: String(webPort),
    HOSTNAME: "127.0.0.1",
    TXSHIELD_API_URL: apiUrl,
    TXSHIELD_API_KEY: API_KEY,
    TXSHIELD_DASHBOARD_BASIC_AUTH: BASIC,
    NEXT_TELEMETRY_DISABLED: "1",
  });
  const web = `http://127.0.0.1:${webPort}`;
  await waitFor(`${web}/scan`, { headers: AUTH });

  // Dashboard authentication covers pages, prefetches, and server actions.
  const anon = await fetch(`${web}/`, { redirect: "manual" });
  check(anon.status === 401 && /^Basic /.test(anon.headers.get("www-authenticate") ?? ""), `unauthenticated page request is refused (status ${anon.status})`);
  const prefetch = await fetch(`${web}/analyses`, { headers: { "next-router-prefetch": "1", purpose: "prefetch", rsc: "1" } });
  check(prefetch.status === 401, `prefetch headers do not bypass authentication (status ${prefetch.status})`);
  const action = await fetch(`${web}/scan`, { method: "POST", headers: { "next-action": "0".repeat(42), "content-type": "text/plain" }, body: "[]" });
  check(action.status === 401, `server action without credentials is refused (status ${action.status})`);
  const wrong = await fetch(`${web}/`, { headers: { authorization: "Basic " + Buffer.from("smoke:wrong-password-wrong-pw").toString("base64") } });
  check(wrong.status === 401, "wrong password is refused");

  // Real analyses through the API (what the scanner's server actions do).
  const api = new TxShield({ baseUrl: apiUrl, apiKey: API_KEY });
  const critical = await api.analyze({
    chainId: 31337, from: DEV1, to: "0x000000000000000000000000000000000000dEaD",
    data: "0x095ea7b3000000000000000000000000000000000000000000000000000000000000dead" + "f".repeat(64),
  });
  const transfer = await api.analyze({ chainId: 31337, from: DEV0, to: DEV1, value: 10n ** 18n });
  check(critical.riskCategory === "critical" && transfer.riskScore === 0 && transfer.simulation?.backend === "anvil", "API produced real analyses (critical approval, simulated transfer)");

  const dash = await page(web, "/");
  check(dash.status === 200 && dash.html.includes("Overview"), "dashboard renders");
  check(/script-src 'self' 'nonce-[^']+' 'strict-dynamic'/.test(dash.csp) && !/script-src[^;]*unsafe-inline/.test(dash.csp), "strict nonce CSP on pages");
  const nonce = dash.csp.match(/'nonce-([^']+)'/)?.[1];
  const scripts = [...dash.html.matchAll(/<script\b[^>]*>/g)].map((m) => m[0]);
  check(scripts.length > 0 && scripts.every((s) => s.includes(`nonce="${nonce}"`)), `every script tag carries the request nonce (${scripts.length} scripts)`);
  if (db) {
    check(dash.html.includes("High or critical") && dash.html.includes("Risk distribution"), "dashboard shows stats and charts");
    const report = await page(web, `/analyses/${critical.id}`);
    const ok = report.status === 200 && report.html.includes("Score breakdown") && report.html.includes("Interaction with a blocklisted address");
    check(ok, `stored report page renders findings (status ${report.status})`);
    if (!ok) console.log(report.html.replace(/<script[\s\S]*?<\/script>/g, "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").slice(0, 1500));
    await a11y(report.html, "report page");
  } else {
    check(dash.html.includes("History is disabled"), "dashboard explains disabled history");
  }
  await a11y(dash.html, "dashboard");

  const scan = await page(web, "/scan");
  check(scan.status === 200 && scan.html.includes("Transaction scanner") && scan.html.includes("Anvil (local)"), "scanner renders with configured chain");
  await a11y(scan.html, "scanner");

  const addr = await page(web, `/address?address=${DEV1}&chainId=31337`);
  check(addr.status === 200 && addr.html.includes("Account (no code)"), "address inspector shows on-chain facts");
  await a11y(addr.html, "address inspector");

  const blocked = await page(web, `/address?address=0x000000000000000000000000000000000000dEaD&chainId=31337`);
  check(blocked.html.includes("Blocked"), "address inspector shows reputation");

  const missing = await page(web, "/analyses/00000000-0000-4000-8000-000000000000");
  check(missing.status === 404 || !db, "unknown analysis is a 404");

  for (const [name, p] of [["dashboard", dash], ["scanner", scan], ["address", addr]]) {
    check(!p.html.includes(API_KEY), `${name}: API key never sent to the browser`);
  }
} catch (e) {
  console.error(e);
  failures++;
} finally {
  for (const p of procs) {
    try {
      process.kill(-p.pid, "SIGTERM");
    } catch {}
  }
}
console.log(failures ? `\n${failures} check(s) failed` : "\nall smoke checks passed");
process.exit(failures ? 1 : 0);
