import type { components } from "./generated/openapi.js";

type S = components["schemas"];

// Response types, generated from the server's OpenAPI document.
export type RiskReport = S["RiskReport"];
export type RiskAssessment = S["RiskAssessment"];
export type ScoreContribution = S["ScoreContribution"];
export type Finding = S["Finding"];
export type Evidence = S["Evidence"];
export type DecodedCall = S["DecodedCall"];
export type DecodedParam = S["DecodedParam"];
export type TransactionSummary = S["TransactionSummary"];
export type SimulationResult = S["SimulationResult"];
export type CallFrame = S["CallFrame"];
export type AssetRef = S["AssetRef"];
export type AssetTransfer = S["AssetTransfer"];
export type BalanceChange = S["BalanceChange"];
export type ApprovalGrant = S["ApprovalGrant"];
export type ApprovalChange = S["ApprovalChange"];
export type ApprovalState = S["ApprovalState"];
export type ApprovalWithState = S["ApprovalWithState"];
export type ApprovalAnalysis = S["ApprovalAnalysis"];
export type AddressReport = S["AddressReport"];
export type AddressReputation = S["AddressReputation"];
export type ContractInfo = S["ContractInfo"];
export type ReputationRecord = S["ReputationRecord"];
export type AnalysisSummary = S["AnalysisSummary"];
export type AnalysisPage = S["PageResponseOfAnalysisSummary"];
export type AnalysisStats = S["AnalysisStats"];
export type InfoResponse = S["InfoResponse"];
export type HealthResponse = S["HealthResponse"];
export type ErrorDetail = S["ErrorDetail"];
export type FieldError = S["FieldError"];
export type TransactionLookup = S["TransactionLookup"];

/** Input of `decode()`: calldata, optionally with target, value, and ABI. */
export interface DecodeInput {
  data: string;
  to?: string;
  value?: Quantity;
  abi?: unknown[] | string;
}

export type RiskCategory = RiskAssessment["category"];
export type Severity = Finding["severity"];
export type Confidence = Finding["confidence"];

/** An integer: bigint, a safe-integer number, or a decimal / 0x-hex string. */
export type Quantity = bigint | number | string;

/** Transaction fields accepted by analysis and simulation calls. */
export interface TransactionInput {
  chainId: number | bigint;
  from: string;
  /** Omit for contract creation. */
  to?: string;
  value?: Quantity;
  data?: string;
  gas?: Quantity;
  /** Legacy fee. Mutually exclusive with the EIP-1559 fields. */
  gasPrice?: Quantity;
  maxFeePerGas?: Quantity;
  maxPriorityFeePerGas?: Quantity;
  /** "latest" (default), "safe", "finalized", a block number, or a block hash. */
  block?: string | number | bigint;
}

export interface AnalyzeInput extends TransactionInput {
  /** Target contract ABI (array or JSON string), used for decoding. */
  abi?: unknown[] | string;
  /** Run a fork simulation (server default: true for analyze, false for approvals). */
  simulate?: boolean;
  /** Store the analysis when the server has persistence enabled (default true). */
  persist?: boolean;
  /** Caller-supplied RPC endpoint; only accepted if the server allows it. */
  rpcUrl?: string;
}

export interface SimulateInput extends TransactionInput {
  rpcUrl?: string;
}

/** A risk report with convenience accessors for the headline numbers. */
export type AnalysisResult = RiskReport & {
  /** Same as `risk.score` (0-100). A low score is not a safety guarantee. */
  riskScore: number;
  /** Same as `risk.category`. */
  riskCategory: RiskCategory;
};

export interface ListAnalysesQuery {
  limit?: number;
  offset?: number;
  chainId?: number | bigint;
  minScore?: number;
  address?: string;
  /** Lower bound (Date or RFC 3339 string). */
  since?: Date | string;
}

export interface AddressQuery {
  chainId: number | bigint;
  limit?: number;
  offset?: number;
}

export interface RequestOptions {
  /** Cancels the request. */
  signal?: AbortSignal;
  /** Overrides the client's timeout for this call (whole call, including retries). */
  timeoutMs?: number;
  /** Sent as X-Request-ID for correlation with server logs. */
  requestId?: string;
}
