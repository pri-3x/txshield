import { TxShieldError } from "./errors.js";
import type { AnalyzeInput, DecodeInput, FieldError, Quantity, SimulateInput, TransactionInput } from "./types.js";

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HEX_DATA = /^0x(?:[0-9a-fA-F]{2})*$/;
const DECIMAL = /^[0-9]+$/;
const HEX_QTY = /^0x[0-9a-fA-F]+$/;
const BLOCK_HASH = /^0x[0-9a-fA-F]{64}$/;
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_CHAIN_ID = 2n ** 53n - 1n;

/** Wire format of a transaction (what the API expects). */
export interface WireTransaction {
  chainId: number;
  from: string;
  to?: string;
  value?: string;
  data?: string;
  gas?: string;
  gasPrice?: string;
  maxFeePerGas?: string;
  maxPriorityFeePerGas?: string;
  block?: string;
}

/**
 * Checks the shape of an address (0x + 40 hex). EIP-55 checksums are
 * verified by the server, which rejects mixed-case addresses with a bad
 * checksum.
 */
export function isAddress(v: unknown): v is string {
  return typeof v === "string" && ADDRESS.test(v);
}

function quantity(field: string, v: Quantity | undefined, errs: FieldError[]): string | undefined {
  if (v === undefined) return undefined;
  let n: bigint | undefined;
  if (typeof v === "bigint") n = v;
  else if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) {
      errs.push({ field, message: "number must be a safe integer; pass a string or bigint for large values" });
      return undefined;
    }
    n = BigInt(v);
  } else if (typeof v === "string") {
    const s = v.trim();
    if (DECIMAL.test(s)) n = BigInt(s);
    else if (HEX_QTY.test(s)) n = BigInt(s);
    else {
      errs.push({ field, message: "must be a non-negative integer (decimal or 0x-hex)" });
      return undefined;
    }
  } else {
    errs.push({ field, message: "must be a bigint, number, or string" });
    return undefined;
  }
  if (n < 0n || n > MAX_UINT256) {
    errs.push({ field, message: "out of uint256 range" });
    return undefined;
  }
  return n.toString();
}

/** Validates and converts a transaction to wire format, reporting every problem at once. */
export function toWireTransaction(tx: TransactionInput): WireTransaction {
  const errs: FieldError[] = [];
  let chainId = 0;
  try {
    const c = BigInt(tx.chainId);
    if (c < 1n || c > MAX_CHAIN_ID) errs.push({ field: "chainId", message: "must be between 1 and 2^53-1" });
    else chainId = Number(c);
  } catch {
    errs.push({ field: "chainId", message: "must be an integer" });
  }
  if (!isAddress(tx.from)) errs.push({ field: "from", message: "must be a 0x-prefixed 20-byte address" });
  if (tx.to !== undefined && tx.to !== "" && !isAddress(tx.to)) errs.push({ field: "to", message: "must be a 0x-prefixed 20-byte address" });
  if (tx.data !== undefined && !HEX_DATA.test(tx.data)) errs.push({ field: "data", message: "must be 0x-prefixed hex with an even number of digits" });
  if ((tx.to === undefined || tx.to === "") && (tx.data === undefined || tx.data === "0x")) {
    errs.push({ field: "to", message: "is required unless data contains contract creation bytecode" });
  }

  const wire: WireTransaction = { chainId, from: tx.from };
  if (tx.to) wire.to = tx.to;
  if (tx.data !== undefined) wire.data = tx.data;
  const q = (k: "value" | "gas" | "gasPrice" | "maxFeePerGas" | "maxPriorityFeePerGas") => {
    const v = quantity(k, tx[k], errs);
    if (v !== undefined) wire[k] = v;
  };
  q("value");
  q("gas");
  q("gasPrice");
  q("maxFeePerGas");
  q("maxPriorityFeePerGas");
  if (wire.gas === "0") errs.push({ field: "gas", message: "must be greater than 0" });
  if (tx.gasPrice !== undefined && (tx.maxFeePerGas !== undefined || tx.maxPriorityFeePerGas !== undefined)) {
    errs.push({ field: "gasPrice", message: "cannot be combined with EIP-1559 fee fields" });
  }
  if (tx.maxPriorityFeePerGas !== undefined && tx.maxFeePerGas === undefined) {
    errs.push({ field: "maxFeePerGas", message: "is required when maxPriorityFeePerGas is set" });
  }
  if (wire.maxFeePerGas !== undefined && wire.maxPriorityFeePerGas !== undefined && BigInt(wire.maxPriorityFeePerGas) > BigInt(wire.maxFeePerGas)) {
    errs.push({ field: "maxPriorityFeePerGas", message: "must not exceed maxFeePerGas" });
  }
  if (tx.block !== undefined) {
    const b = tx.block;
    if (typeof b === "bigint" || typeof b === "number") {
      if (typeof b === "number" && !Number.isSafeInteger(b)) errs.push({ field: "block", message: "must be a safe integer" });
      else if (BigInt(b) < 0n) errs.push({ field: "block", message: "must be non-negative" });
      else wire.block = b.toString();
    } else if (["latest", "safe", "finalized"].includes(b) || DECIMAL.test(b) || BLOCK_HASH.test(b) || (HEX_QTY.test(b) && b.length <= 18)) {
      wire.block = b;
    } else {
      errs.push({ field: "block", message: "must be latest, safe, finalized, a block number, or a 32-byte block hash" });
    }
  }
  if (errs.length) throw validationError(errs);
  return wire;
}

/** Builds the body of analyze / approvals requests. */
export function toAnalyzeBody(input: AnalyzeInput): Record<string, unknown> {
  const errs: FieldError[] = [];
  let wire: WireTransaction | undefined;
  try {
    wire = toWireTransaction(input);
  } catch (e) {
    if (e instanceof TxShieldError) errs.push(...e.fields);
    else throw e;
  }
  const body: Record<string, unknown> = { ...wire };
  if (input.abi !== undefined) {
    if (typeof input.abi === "string") {
      try {
        body.abi = JSON.parse(input.abi);
      } catch {
        errs.push({ field: "abi", message: "is not valid JSON" });
      }
    } else if (Array.isArray(input.abi)) body.abi = input.abi;
    else errs.push({ field: "abi", message: "must be an ABI array or its JSON string" });
  }
  if (input.simulate !== undefined) body.simulate = input.simulate;
  if (input.persist !== undefined) body.persist = input.persist;
  if (input.rpcUrl !== undefined) {
    if (!/^https:\/\//.test(input.rpcUrl)) errs.push({ field: "rpcUrl", message: "must be an https URL" });
    else body.rpcUrl = input.rpcUrl;
  }
  if (errs.length) throw validationError(errs);
  return body;
}

/** Builds the body of simulate requests. */
export function toSimulateBody(input: SimulateInput): Record<string, unknown> {
  const { rpcUrl, ...tx } = input;
  return toAnalyzeBody({ ...tx, rpcUrl });
}

/** Builds the body of decode requests. */
export function toDecodeBody(input: DecodeInput): Record<string, unknown> {
  const errs: FieldError[] = [];
  const body: Record<string, unknown> = {};
  if (typeof input.data !== "string" || !HEX_DATA.test(input.data) || input.data === "0x") {
    errs.push({ field: "data", message: "must be non-empty 0x-prefixed hex with an even number of digits" });
  } else body.data = input.data;
  if (input.to !== undefined && input.to !== "") {
    if (!isAddress(input.to)) errs.push({ field: "to", message: "must be a 0x-prefixed 20-byte address" });
    else body.to = input.to;
  }
  const v = quantity("value", input.value, errs);
  if (v !== undefined) body.value = v;
  if (input.abi !== undefined) {
    if (typeof input.abi === "string") {
      try {
        body.abi = JSON.parse(input.abi);
      } catch {
        errs.push({ field: "abi", message: "is not valid JSON" });
      }
    } else if (Array.isArray(input.abi)) body.abi = input.abi;
    else errs.push({ field: "abi", message: "must be an ABI array or its JSON string" });
  }
  if (errs.length) throw validationError(errs);
  return body;
}

export function validationError(fields: FieldError[]): TxShieldError {
  return new TxShieldError({ kind: "invalid_input", code: "client_validation", message: "request validation failed", fields });
}
