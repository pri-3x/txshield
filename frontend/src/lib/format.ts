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

/** A simulated asset as returned by the API (symbol and decimals are self-reported by the token). */
export interface AssetLike {
  kind: string;
  address?: string;
  tokenId?: string;
  symbol?: string;
  decimals?: number;
}

/**
 * Display name and amount for an asset. Native amounts use the chain's
 * 18-decimal native unit. Token symbol and decimals come from the token
 * contract and are flagged `unverified`; without decimals, amounts stay raw
 * base units rather than guessing.
 */
export function assetDisplay(asset: AssetLike, amount: string, chainId: number): { name: string; amount: string; unverified: boolean; raw: boolean } {
  if (asset.kind === "native") return { name: nativeSymbol(chainId), amount: formatUnits(amount), unverified: false, raw: false };
  const symbol = visible(asset.symbol, 16);
  const fallback = asset.kind === "erc721" ? "NFT" : asset.kind === "erc1155" ? "ERC-1155" : "Token";
  const name = (symbol || fallback) + (asset.tokenId ? ` #${asset.tokenId}` : "");
  if (asset.kind === "erc20" && asset.decimals !== undefined && asset.decimals <= 77) {
    return { name, amount: formatUnits(amount, asset.decimals), unverified: true, raw: false };
  }
  return { name, amount: groupDigits(amount), unverified: Boolean(symbol), raw: asset.kind === "erc20" };
}

/** Names of standard selectors, for labelling call-trace frames (selectors are exact). */
export const KNOWN_SELECTORS: Record<string, string> = {
  "0x70a08231": "balanceOf",
  "0xdd62ed3e": "allowance",
  "0xa9059cbb": "transfer",
  "0x23b872dd": "transferFrom",
  "0x095ea7b3": "approve",
  "0xe985e9c5": "isApprovedForAll",
  "0xa22cb465": "setApprovalForAll",
  "0x42842e0e": "safeTransferFrom",
  "0xb88d4fde": "safeTransferFrom",
  "0x2eb2c2d6": "safeBatchTransferFrom",
  "0x6352211e": "ownerOf",
  "0x081812fc": "getApproved",
  "0x313ce567": "decimals",
  "0x95d89b41": "symbol",
  "0x06fdde03": "name",
  "0x18160ddd": "totalSupply",
  "0xd505accf": "permit",
  "0xac9650d8": "multicall",
  "0x82ad56cb": "aggregate3",
  "0xd0e30db0": "deposit",
  "0x2e1a7d4d": "withdraw",
  "0x01ffc9a7": "supportsInterface",
};
