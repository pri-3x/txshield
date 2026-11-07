"use server";

import { isTxShieldError, type AnalysisResult, type AnalyzeInput, type DecodedCall, type FieldError, type TransactionLookup } from "@txshield/sdk";
import { txshield } from "@/lib/txshield";

export interface ActionError {
  message: string;
  code: string;
  fields: FieldError[];
  requestId?: string;
}

export type Result<T> = { ok: true; data: T } | { ok: false; error: ActionError };

function fail(e: unknown): { ok: false; error: ActionError } {
  if (isTxShieldError(e)) {
    return { ok: false, error: { message: e.message, code: e.code, fields: e.fields, requestId: e.requestId } };
  }
  // Never leak internal errors (paths, URLs) to the browser.
  console.error("scanner action failed", e);
  return { ok: false, error: { message: "Unexpected error while contacting the TxShield API", code: "unexpected", fields: [] } };
}

const str = (fd: FormData, k: string) => {
  const v = fd.get(k);
  return typeof v === "string" ? v.trim() : "";
};

/** Analyze a transaction from the scanner form. */
export async function analyzeAction(fd: FormData): Promise<Result<AnalysisResult>> {
  const chain = str(fd, "chainId");
  const input: AnalyzeInput = {
    chainId: /^\d+$/.test(chain) ? BigInt(chain) : 0,
    from: str(fd, "from"),
    to: str(fd, "to") || undefined,
    value: str(fd, "value") || undefined,
    data: str(fd, "data") || undefined,
    gas: str(fd, "gas") || undefined,
    block: str(fd, "block") || undefined,
    simulate: fd.get("simulate") === "on",
    abi: str(fd, "abi") || undefined,
  };
  try {
    return { ok: true, data: await txshield().analyze(input) };
  } catch (e) {
    return fail(e);
  }
}

/** Look up a transaction by hash and return it as analyzer input. */
export async function lookupAction(fd: FormData): Promise<Result<TransactionLookup>> {
  const chain = str(fd, "chainId");
  try {
    return { ok: true, data: await txshield().getTransaction(str(fd, "hash"), { chainId: /^\d+$/.test(chain) ? BigInt(chain) : 0 }) };
  } catch (e) {
    return fail(e);
  }
}

/** Decode calldata only (no sender, no simulation). */
export async function decodeAction(fd: FormData): Promise<Result<DecodedCall>> {
  try {
    return { ok: true, data: await txshield().decode({ data: str(fd, "data"), to: str(fd, "to") || undefined, abi: str(fd, "abi") || undefined }) };
  } catch (e) {
    return fail(e);
  }
}
