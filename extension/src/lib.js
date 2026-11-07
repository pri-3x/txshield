/*
 * TxShield extension: pure logic shared by the background worker, the
 * content script, the options page, the test harness, and the unit tests.
 * No DOM, no chrome.* APIs. Loaded as a classic script (sets
 * globalThis.TxShieldLib) or required as a CommonJS module in tests.
 */
(function (root, factory) {
  const lib = factory();
  if (typeof module === "object" && module.exports) module.exports = lib;
  else root.TxShieldLib = lib;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const DEFAULTS = Object.freeze({
    apiUrl: "http://127.0.0.1:18080",
    apiKey: "",
    dashboardUrl: "http://localhost:3000",
    threshold: 20, // warn at "moderate" (20+) and above
    timeoutMs: 25000,
  });

  const CHAIN_SYMBOL = { 1: "ETH", 10: "ETH", 8453: "ETH", 42161: "ETH", 17000: "ETH", 11155111: "ETH", 31337: "ETH", 56: "BNB", 137: "POL" };
  const CHAIN_NAME = { 1: "Ethereum", 10: "OP Mainnet", 56: "BNB Smart Chain", 137: "Polygon", 8453: "Base", 17000: "Holesky", 42161: "Arbitrum One", 11155111: "Sepolia", 31337: "Anvil (local)" };

  const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
  const HEX_DATA = /^0x([0-9a-fA-F]{2})*$/;
  const QTY = /^(0x[0-9a-fA-F]+|[0-9]+)$/;

  /** Accepts http(s) URLs only and strips a trailing slash. */
  function normalizeApiUrl(raw) {
    let u;
    try {
      u = new URL(String(raw || "").trim());
    } catch {
      return null;
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    if (u.username || u.password) return null; // credentials belong in the API key field
    return u.origin + u.pathname.replace(/\/+$/, "");
  }

  function parseChainId(hexOrNumber) {
    if (typeof hexOrNumber === "number" && Number.isSafeInteger(hexOrNumber) && hexOrNumber > 0) return hexOrNumber;
    if (typeof hexOrNumber === "string") {
      const n = hexOrNumber.startsWith("0x") ? parseInt(hexOrNumber, 16) : parseInt(hexOrNumber, 10);
      if (Number.isSafeInteger(n) && n > 0) return n;
    }
    return null;
  }

  /**
   * Converts eth_sendTransaction params (EIP-1193 / JSON-RPC shape) into a
   * TxShield analyze request. Returns { ok, request } or { ok: false, error }.
   */
  function toApiRequest(tx, chainIdRaw) {
    if (!tx || typeof tx !== "object") return { ok: false, error: "missing transaction" };
    const chainId = parseChainId(chainIdRaw ?? tx.chainId);
    if (!chainId) return { ok: false, error: "unknown chain" };
    if (typeof tx.from !== "string" || !ADDRESS.test(tx.from)) return { ok: false, error: "missing or invalid sender" };
    const req = { chainId, from: tx.from, simulate: true };
    if (tx.to != null && tx.to !== "") {
      if (typeof tx.to !== "string" || !ADDRESS.test(tx.to)) return { ok: false, error: "invalid recipient" };
      req.to = tx.to;
    }
    const data = tx.data ?? tx.input;
    if (data != null && data !== "") {
      if (typeof data !== "string" || !HEX_DATA.test(data)) return { ok: false, error: "invalid calldata" };
      req.data = data;
    }
    for (const [from, to] of [["value", "value"], ["gas", "gas"], ["gasLimit", "gas"]]) {
      const v = tx[from];
      if (v == null || v === "" || req[to] !== undefined) continue;
      const s = typeof v === "number" ? String(v) : v;
      if (typeof s !== "string" || !QTY.test(s)) return { ok: false, error: `invalid ${from}` };
      req[to] = s;
    }
    if (!req.to && !req.data) return { ok: false, error: "transaction has neither recipient nor data" };
    return { ok: true, request: req };
  }

  /** Calls POST /api/v1/analyze. Never throws. */
  async function analyze(settings, request, fetchImpl) {
    const base = normalizeApiUrl(settings.apiUrl);
    if (!base) return { ok: false, error: "The TxShield API URL in the extension settings is not a valid http(s) URL." };
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), settings.timeoutMs || DEFAULTS.timeoutMs);
    try {
      const headers = { "Content-Type": "application/json" };
      if (settings.apiKey) headers.Authorization = `Bearer ${settings.apiKey}`;
      const res = await (fetchImpl || fetch)(`${base}/api/v1/analyze`, { method: "POST", headers, body: JSON.stringify(request), signal: ctrl.signal, credentials: "omit" });
      let body = null;
      try {
        body = await res.json();
      } catch {
        // non-JSON error page
      }
      if (!res.ok) {
        const msg = body && body.error && typeof body.error.message === "string" ? body.error.message : `HTTP ${res.status}`;
        const fields = body && body.error && Array.isArray(body.error.fields) ? body.error.fields.map((f) => `${f.field}: ${f.message}`).join("; ") : "";
        return { ok: false, error: `TxShield API error: ${msg}${fields ? ` (${fields})` : ""}`, status: res.status };
      }
      if (!body || !body.risk || typeof body.risk.score !== "number") return { ok: false, error: "TxShield API returned an unexpected response." };
      return { ok: true, report: body };
    } catch (e) {
      const aborted = e && e.name === "AbortError";
      return { ok: false, error: aborted ? "The TxShield API did not answer in time." : "Could not reach the TxShield API. Check the API URL in the extension settings." };
    } finally {
      clearTimeout(timer);
    }
  }

  /** "warn" shows the full warning; "allow" lets the transaction through with a short notice. */
  function decide(report, threshold) {
    const t = Number.isFinite(threshold) ? threshold : DEFAULTS.threshold;
    if (report.simulation && report.simulation.status === "reverted") return "warn";
    return report.risk.score >= t ? "warn" : "allow";
  }

  // --- formatting -----------------------------------------------------------

  function formatUnits(value, decimals, maxFraction) {
    const s = String(value);
    if (!/^-?\d+$/.test(s)) return s;
    const neg = s.startsWith("-");
    const n = BigInt(neg ? s.slice(1) : s);
    const d = decimals === undefined ? 18 : decimals;
    const mf = maxFraction === undefined ? 6 : maxFraction;
    const base = 10n ** BigInt(d);
    const whole = n / base;
    const frac = (n % base).toString().padStart(d, "0").slice(0, mf).replace(/0+$/, "");
    if (whole === 0n && frac === "" && n !== 0n) return `${neg ? "-" : ""}<0.${"0".repeat(mf - 1)}1`;
    return `${neg ? "-" : ""}${whole.toLocaleString("en-US")}${frac ? "." + frac : ""}`;
  }

  function groupDigits(v) {
    return /^-?\d+$/.test(v) ? v.replace(/\B(?=(\d{3})+(?!\d))/g, ",") : v;
  }

  /** Strips control, format (bidi, zero-width) characters and caps length. */
  function cleanText(s, max) {
    if (typeof s !== "string") return "";
    const out = s.replace(/[\u0000-\u001f\u007f-\u009f­​-‏‪-‮⁠-⁩﻿]/g, "");
    const m = max || 200;
    return out.length > m ? out.slice(0, m) + "…" : out;
  }

  function shortHex(v) {
    return typeof v === "string" && v.length > 12 ? `${v.slice(0, 6)}…${v.slice(-4)}` : String(v || "");
  }

  function sameAddr(a, b) {
    return typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();
  }

  /** One asset movement as text: { label: "1,000 TUSD", unverified: true }. */
  function describeAsset(asset, amount, chainId) {
    const abs = String(amount).replace(/^-/, "");
    if (asset.kind === "native") return { label: `${formatUnits(abs)} ${CHAIN_SYMBOL[chainId] || "native"}`, unverified: false };
    const symbol = cleanText(asset.symbol, 16);
    if (asset.kind === "erc721") {
      const id = asset.tokenId ? ` #${cleanText(String(asset.tokenId), 40)}` : "";
      const name = symbol ? `${symbol}${id}` : `NFT${id}`;
      return { label: abs === "1" || !abs ? name : `${groupDigits(abs)} × ${name}`, unverified: Boolean(symbol), address: asset.address };
    }
    if (asset.kind === "erc20" && Number.isInteger(asset.decimals) && asset.decimals >= 0 && asset.decimals <= 77) {
      return { label: `${formatUnits(abs, asset.decimals)} ${symbol || "tokens"}`, unverified: true, address: asset.address };
    }
    return { label: `${groupDigits(abs)} ${symbol || (asset.kind === "erc1155" ? "ERC-1155 units" : "token base units")}`, unverified: Boolean(symbol), address: asset.address };
  }

  function joinList(items) {
    if (items.length <= 1) return items.join("");
    return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
  }

  const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const CATEGORY_LABEL = { low: "Low observed risk", moderate: "Moderate risk", elevated: "Elevated risk", high: "High risk", critical: "Critical risk" };

  /**
   * What the warning shows, derived only from the report. Plain language for
   * people who will never read calldata. Never says "safe".
   */
  function viewModel(report, settings) {
    const tx = report.transaction || {};
    const chainId = tx.chainId;
    const sender = tx.from;
    const sim = report.simulation;
    const simRan = Boolean(sim && (sim.status === "success" || sim.status === "reverted"));
    const changes = (report.balanceChanges || (sim && sim.balanceChanges) || []).filter((b) => !sender || sameAddr(b.owner, sender) || b.owner === "[redacted-sender]");
    const transfers = (sim && sim.assetTransfers) || [];

    // NFT balance changes carry no token IDs; take them from the transfers.
    const nftIds = (address, outgoing) =>
      transfers
        .filter((t) => t.asset.kind === "erc721" && sameAddr(t.asset.address, address) && (outgoing ? sameAddr(t.from, sender) : sameAddr(t.to, sender)))
        .map((t) => t.asset.tokenId)
        .filter(Boolean);

    const sends = [];
    const receives = [];
    for (const b of changes) {
      const out = String(b.delta).startsWith("-");
      const list = out ? sends : receives;
      if (b.asset.kind === "erc721") {
        const ids = nftIds(b.asset.address, out);
        if (ids.length) {
          for (const id of ids.slice(0, 5)) list.push(describeAsset({ ...b.asset, tokenId: id }, "1", chainId));
          continue;
        }
      }
      const whole = out && String(b.after) === "0" && b.asset.kind !== "native";
      list.push({ ...describeAsset(b.asset, b.delta, chainId), entireBalance: whole });
    }

    // Every distinct address the sender's assets move to.
    const recipients = [];
    for (const t of transfers) {
      if (sameAddr(t.from, sender) && !sameAddr(t.to, sender) && !recipients.some((r) => sameAddr(r, t.to))) recipients.push(t.to);
    }

    // Token permissions the sender grants (approvals, operator approvals, permits).
    const symbolOf = (token) => {
      const hit = changes.concat(transfers.map((t) => ({ asset: t.asset }))).find((c) => sameAddr(c.asset.address, token) && c.asset.symbol);
      return hit ? cleanText(hit.asset.symbol, 16) : "";
    };
    const permissions = [];
    for (const a of report.approvals || []) {
      if (!a.ownerIsSender || a.revocation || a.approved === false) continue;
      const sym = symbolOf(a.token);
      const token = sym ? `${sym}*` : `tokens at ${shortHex(a.token)}`;
      let what;
      if (a.approved === true) what = `every NFT you own in collection ${shortHex(a.token)}`;
      else if (a.tokenId) what = `NFT #${cleanText(String(a.tokenId), 40)} of ${shortHex(a.token)}`;
      else if (a.unlimited) what = `an unlimited amount of your ${token}`;
      else what = `up to ${groupDigits(String(a.amount || "0"))} base units of your ${token}`;
      permissions.push({ spender: shortHex(a.spender), what, unlimited: Boolean(a.unlimited || a.approved === true), signed: Boolean(a.signed) });
    }

    const cat = report.risk.category;
    let headline;
    if (sim && sim.status === "reverted") {
      headline = "This transaction would fail. It reverts in simulation, and you would still pay gas.";
    } else if ((cat === "high" || cat === "critical") && sends.length && !receives.length) {
      headline = `Don't sign this. It sends ${joinList(sends.slice(0, 3).map((s) => s.label + (s.unverified ? "*" : "")))}${sends.length > 3 ? " and more" : ""} out of your wallet, and you receive nothing.`;
    } else if ((cat === "high" || cat === "critical") && permissions.length) {
      const p = permissions[0];
      headline = `Don't sign this. It lets ${p.spender} spend ${p.what}${permissions.length > 1 ? `, plus ${permissions.length - 1} more permission(s)` : ""}.`;
    } else if (cat === "high" || cat === "critical") {
      headline = "Don't sign this unless you are certain. TxShield found serious risks.";
    } else if (cat === "low") {
      headline = "No significant risks detected by enabled checks.";
    } else {
      headline = "Review this carefully before signing.";
    }

    const findings = [...(report.findings || [])].sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0));
    // One line per distinct reason (a rule can fire once per asset).
    const reasons = [];
    for (const f of findings) {
      if (f.severity === "info") continue;
      const title = cleanText(f.title, 120);
      const seen = reasons.find((r) => r.title === title);
      if (seen) seen.count += 1;
      else reasons.push({ severity: f.severity, title, count: 1 });
    }
    reasons.splice(3);

    const base = normalizeApiUrl(settings && settings.dashboardUrl);
    return {
      score: report.risk.score,
      category: cat,
      categoryLabel: CATEGORY_LABEL[cat] || cat,
      confidence: report.risk.confidence,
      headline,
      sends,
      receives,
      receivesNothing: simRan && sends.length > 0 && receives.length === 0,
      permissions: permissions.slice(0, 4),
      recipients: recipients.slice(0, 3).map(shortHex),
      reasons,
      recommendation: cleanText((report.recommendations || [])[0] || "", 240),
      simulated: simRan,
      notSimulatedReason: simRan ? "" : cleanText((sim && sim.incompleteReasons && sim.incompleteReasons[0]) || "This transaction was not simulated, so wallet changes are unknown.", 200),
      anyUnverified: sends.concat(receives).some((s) => s.unverified),
      chainName: CHAIN_NAME[chainId] || `chain ${chainId}`,
      target: shortHex(tx.to || ""),
      reportUrl: base && report.id ? `${base}/analyses/${encodeURIComponent(report.id)}` : "",
      disclaimer: "TxShield checks are heuristics and not exhaustive. A low score is not a guarantee of safety.",
    };
  }

  return { DEFAULTS, normalizeApiUrl, parseChainId, toApiRequest, analyze, decide, viewModel, formatUnits, cleanText, shortHex, describeAsset };
});
