# @txshield/sdk

TypeScript client for the [TxShield](../../README.md) EVM transaction security
and simulation API. Analyze a transaction **before** it is signed: decoded
calls, token permissions, simulated asset movements, security findings, and a
transparent 0–100 risk score.

> TxShield never signs or broadcasts transactions. A low score means *no
> significant risks were detected by the enabled checks*. It is never a
> guarantee that a transaction is safe.

- Typed responses generated from the server's OpenAPI document
- Client-side validation (addresses, hex, `bigint`-safe quantities, fee rules)
- One error type (`TxShieldError`) with `kind`, `code`, `fields`, `requestId`
- Timeouts, `AbortSignal` support, and retries for transient failures only
- ESM and CommonJS, Node.js 20+ and modern browsers (uses `fetch`); no runtime dependencies

## Install

```bash
npm install @txshield/sdk
```

## Quick start

```ts
import { TxShield } from "@txshield/sdk";

const shield = new TxShield({
  baseUrl: "http://localhost:8080",
  apiKey: process.env.TXSHIELD_API_KEY, // only if the server sets TXSHIELD_API_KEYS
});

const result = await shield.analyze({
  chainId: 11155111,
  from: "0x...",
  to: "0x...",
  value: "0",
  data: "0x...",
});

console.log(result.riskScore);    // same as result.risk.score
console.log(result.riskCategory); // "low" | "moderate" | "elevated" | "high" | "critical"
console.log(result.findings);     // each with severity, confidence, source, evidence, mitigation
console.log(result.verdict);      // never says "safe"
```

## Methods

| Method | Endpoint | Returns |
|---|---|---|
| `analyze(input, opts?)` | `POST /api/v1/analyze` | `AnalysisResult` (risk report plus `riskScore`/`riskCategory`) |
| `simulate(input, opts?)` | `POST /api/v1/simulate` | `SimulationResult` (a revert resolves with `status: "reverted"`) |
| `analyzeApprovals(input, opts?)` | `POST /api/v1/approvals/analyze` | `ApprovalAnalysis` (grants, current on-chain state, approval findings) |
| `decode({ data, to?, value?, abi? })` | `POST /api/v1/decode` | `DecodedCall` (offline, nothing stored) |
| `getTransaction(hash, { chainId })` | `GET /api/v1/transactions/{hash}` | `TransactionLookup` (pass `.transaction` to `analyze()`) |
| `inspectAddress(address, { chainId, limit?, offset? })` | `GET /api/v1/address/{address}` | `AddressReport` |
| `listAnalyses({ limit?, offset?, chainId?, minScore?, address?, since? })` | `GET /api/v1/analyses` | `AnalysisPage` |
| `getAnalysis(id)` | `GET /api/v1/analyses/{id}` | `AnalysisResult` |
| `stats({ since? })` | `GET /api/v1/stats` | `AnalysisStats` |
| `info()` | `GET /api/v1/info` | `InfoResponse` |
| `health()` | `GET /health` | `HealthResponse` (resolves on 503 too; check `status`) |

Transaction input:

- `chainId`, `from`, and `to` (omit `to` to deploy)
- `value`, `gas`, `gasPrice` **or** `maxFeePerGas` + `maxPriorityFeePerGas`
- `data` (0x-hex)
- `block` (`"latest"`, `"safe"`, `"finalized"`, a number, or a hash)

Quantities accept `bigint`, safe-integer `number`, or decimal / 0x-hex
`string`. Unsafe numbers are rejected rather than silently rounded.
`analyze`/`analyzeApprovals` also take:

- `abi`: the target's ABI, as an array or a JSON string
- `simulate`
- `persist`
- `rpcUrl`: only if the server allows caller endpoints

Every method returns a promise and reports every failure, including
client-side validation, by **rejecting**. Nothing throws synchronously.

## Errors

```ts
import { isTxShieldError } from "@txshield/sdk";

try {
  await shield.analyze(tx);
} catch (e) {
  if (isTxShieldError(e)) {
    e.kind;        // "invalid_input" | "rate_limited" | "unavailable" | "timeout" | "network" | "aborted" | ...
    e.code;        // e.g. "validation_failed", "client_validation", "client_timeout", "persistence_disabled"
    e.status;      // HTTP status when a response was received
    e.fields;      // [{ field: "from", message: "invalid EIP-55 checksum" }]
    e.requestId;   // correlate with server logs
    e.retryable;   // worth retrying later?
  }
}
```

Client-side validation checks address *shape*. EIP-55 checksums are verified
by the server, which rejects mixed-case addresses with a bad checksum
(`kind: "invalid_input"`, with `fields`).

## Timeouts, cancellation, retries

```ts
const shield = new TxShield({ baseUrl, timeoutMs: 60_000, maxRetries: 2 });
await shield.analyze(tx, { timeoutMs: 10_000, signal: controller.signal, requestId: "checkout-42" });
```

- `timeoutMs` bounds the **whole call, including retries** (default 60 s;
  simulations can take a few seconds).
- **Retried:** network errors and HTTP 429/502/503/504, with exponential
  backoff and full jitter. `Retry-After` is honored (capped at 30 s), and a
  retry is skipped if it would pass the deadline.
- **Not retried:** 503s that describe server configuration
  (`persistence_disabled`, `engine_unavailable`), and every other client
  error.

## Types

All request and response types are exported (`RiskReport`, `Finding`,
`SimulationResult`, `ApprovalGrant`, ...), as are the raw generated
`components` and `paths` for advanced use. Amounts are decimal **strings**:
convert with `BigInt(x)`.

## Development

```bash
npm ci
npm run generate          # regenerate src/generated/openapi.ts from ../../internal/api/openapi.json
npm run typecheck
npm test                  # unit tests (mocked fetch)
npm run test:integration  # builds and starts a real `txshield serve` (needs Go; uses anvil if installed)
npm run build             # dist/esm + dist/cjs
```

`.npmrc` sets `legacy-peer-deps=true` to work around an npm 10 resolver crash
on vitest 4.1's optional peers. The required peers (`vite`, `@types/node`) are
pinned explicitly.

See [`examples/`](examples) for runnable scripts.
