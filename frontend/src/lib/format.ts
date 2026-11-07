/** Shared formatting helpers. Everything chain-derived is untrusted text. */

const CHAINS: Record<number, { name: string; symbol: string }> = {
  1: { name: "Ethereum", symbol: "ETH" },
  10: { name: "OP Mainnet", symbol: "ETH" },
  56: { name: "BNB Smart Chain", symbol: "BNB" },
  137: { name: "Polygon PoS", symbol: "POL" },
  8453: { name: "Base", symbol: "ETH" },
  17000: { name: "Holesky", symbol: "ETH" },
  31337: { name: "Anvil (local)", symbol: "ETH" },
  42161: { name: "Arbitrum One", symbol: "ETH" },
  11155111: { name: "Sepolia", symbol: "ETH" },
};

export const KNOWN_CHAINS = Object.entries(CHAINS).map(([id, c]) => ({ id: Number(id), ...c }));

export function chainName(id: number): string {
  return CHAINS[id]?.name ?? `Chain ${id}`;
}

export function nativeSymbol(id: number): string {
  return CHAINS[id]?.symbol ?? "native";
}

/** 0x1234…abcd for display; the full value goes in title / copy. */
export function shortHex(v: string, head = 6, tail = 4): string {
  return v.length > head + tail + 1 ? `${v.slice(0, head)}…${v.slice(-tail)}` : v;
}

/**
 * Formats an integer string of base units with `decimals` (exact, bigint
 * math; no floating point). Negative values keep their sign.
 */
export function formatUnits(value: string, decimals = 18, maxFraction = 6): string {
  if (!/^-?\d+$/.test(value)) return value;
  const neg = value.startsWith("-");
  const n = BigInt(neg ? value.slice(1) : value);
  const base = 10n ** BigInt(decimals);
  const whole = n / base;
  const frac = (n % base).toString().padStart(decimals, "0").slice(0, maxFraction).replace(/0+$/, "");
  if (whole === 0n && frac === "" && n !== 0n) {
    // Nonzero but below display precision: say so instead of rounding.
    return `${neg ? "-" : ""}<0.${"0".repeat(maxFraction - 1)}1`;
  }
  const wholeStr = whole.toLocaleString("en-US");
  return `${neg ? "-" : ""}${wholeStr}${frac ? "." + frac : ""}`;
}

/** Groups digits of a large integer string (token base units of unknown decimals). */
export function groupDigits(value: string): string {
  if (!/^-?\d+$/.test(value)) return value;
  return value.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

const MAX_UINT256 = ((1n << 256n) - 1n).toString();
const MAX_UINT160 = ((1n << 160n) - 1n).toString();

/** Describes an approval amount, naming the unlimited sentinels. */
export function describeAmount(v: string | undefined): string {
  if (!v) return "–";
  if (v === MAX_UINT256) return "Unlimited (2²⁵⁶−1)";
  if (v === MAX_UINT160) return "Unlimited (2¹⁶⁰−1, Permit2)";
  return groupDigits(v);
}

export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

/**
 * Makes invisible and direction-changing characters visible. Chain data
 * (revert strings, decoded string arguments, reputation reasons) can carry
 * bidi overrides or zero-width characters to disguise text; React escapes
 * HTML but would still render those faithfully.
 */
export function visible(s: string | undefined | null, max = 500): string {
  if (!s) return "";
  let out = s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f​-‏‪-‮⁠-⁩﻿]/g, (c) =>
    `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
  if (out.length > max) out = out.slice(0, max) + "…";
  return out;
}
