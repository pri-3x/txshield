# TxShield HTTP API

The machine-readable contract is the OpenAPI 3.1 document, served at
`GET /api/v1/openapi.json` (source: [`internal/api/openapi.json`](../internal/api/openapi.json)).
It is generated from the Go types the handlers use, and CI fails if it drifts
from the code or if any route is undocumented. The TypeScript SDK's types are
generated from the same document ([`sdk/typescript`](../sdk/typescript/README.md)).
This page is the guide.

TxShield never signs or broadcasts transactions, and never labels a
transaction safe.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/analyze` | Full analysis: decode, reputation, contract facts, simulation, rules, risk report |
| POST | `/api/v1/simulate` | Simulation only |
| POST | `/api/v1/decode` | Offline calldata decoding (`data`, optional `to`, `value`, `abi`); nothing stored |
| GET | `/api/v1/transactions/{hash}?chainId=` | Fetch a transaction from the configured RPC in `/analyze` request form; mined transactions replay on their parent block (approximation: earlier transactions in that block are not re-applied) |
| POST | `/api/v1/approvals/analyze` | Permissions a transaction grants, the permission currently in force on-chain, approval findings scored on their own |
| GET | `/api/v1/address/{address}?chainId=` | Contract facts, reputation (resolved status and every record), stored analyses involving the address |
| GET | `/api/v1/analyses` | Stored analyses, newest first (`limit`, `offset`, `chainId`, `minScore`, `address`, `since`) |
| GET | `/api/v1/analyses/{id}` | One stored report |
| GET | `/api/v1/stats` | Totals, high-risk count, by category, by chain |
| GET | `/api/v1/info` | Configured chains, simulator, rule count, reputation sources |
| GET | `/api/v1/openapi.json` | OpenAPI document |
| GET | `/health`, `/livez`, `/metrics` | Readiness with dependency checks, liveness, Prometheus |

## Example

```bash
curl -s localhost:8080/api/v1/analyze -H 'Content-Type: application/json' -d '{
  "chainId": 11155111,
  "from": "0x1111111111111111111111111111111111111111",
  "to":   "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "value": "0",
  "data": "0x095ea7b3000000000000000000000000dead000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
}'
```

Request fields: `chainId`, `from` (required); `to` (omit for contract
creation); `value`, `gas`, `gasPrice` | (`maxFeePerGas`, `maxPriorityFeePerGas`)
as decimal strings, JSON numbers, or 0x-hex; `data` as 0x-hex; `block`
(`latest`, `safe`, `finalized`, number, or hash); `abi` (JSON ABI of the
target); `simulate` (default true for `/analyze`, false for
`/approvals/analyze`); `persist` (default true); `rpcUrl` (only if the operator
allows it, see below). Unknown fields are rejected, because a typo in a fee
field must not be silently ignored.

Key response fields of `/analyze`:

- `risk.score` (0-100), `risk.category`, `risk.confidence`
- `risk.contributions`: how each finding moved the score
- `verdict`: never "safe"
- `findings[]`: each carries `severity`, `confidence`, `source` (`fact` |
  `heuristic` | `external`), `evidence`, `mitigation`, `falsePositiveNotes`
- `approvals[]`, `simulation`, `balanceChanges`, `recommendations`,
  `enabledChecks`
- `warnings`: what was not checked and why

## Errors

Every error has the same shape:

```json
{"error": {"kind": "invalid_input", "code": "validation_failed", "message": "request validation failed",
           "fields": [{"field": "from", "message": "is required"}], "requestId": "9f2c..."}}
```

| HTTP | `kind` | Typical cause |
|---|---|---|
| 400 | invalid_input | Validation, malformed JSON, unknown field, bad ABI, forbidden `rpcUrl` |
| 401 | invalid_input (`code: unauthorized`) | API keys configured and missing or wrong |
| 404 | not_found | Unknown route, analysis not found or expired |
| 405 | invalid_input (`code: method_not_allowed`) | Wrong method |
| 413 | payload_too_large | Body over `TXSHIELD_MAX_BODY_BYTES`, oversized ABI |
| 422 | unsupported | Chain has no simulator, RPC endpoint serves a different chain |
| 429 | rate_limited | Per-client limit; honor `Retry-After` |
| 503 | unavailable | Persistence disabled (history endpoints), dependency down |
| 504 | timeout | Analysis or simulation exceeded its deadline |

A transaction that **reverts in simulation** is not an error: it is a 200
response with `simulation.status: "reverted"`. Infrastructure failures during
`/analyze` do not fail the request either. The report states
`simulation.status: "error"` and lowers `risk.confidence`.

Every response carries `X-Request-ID`. A well-formed incoming one is
preserved for correlation.

## Chains and RPC

- Chains with an RPC endpoint in `TXSHIELD_RPC_URLS` get contract facts and
  simulation.
- Other chains are analyzed offline: static checks only, with a warning in
  the report.
- `rpcUrl` in requests is rejected unless `TXSHIELD_ALLOW_USER_RPC=true`.
  When allowed:
  - Only https is accepted.
  - The host must resolve to public addresses only, and the IP is re-checked
    at connect time (blocks DNS rebinding).
  - Redirects are refused.
  - Simulation is limited to the `rpc-trace` backend, because Anvil would
    open its own unguarded connections.

## Authentication, limits, CORS

| Setting | Effect |
|---|---|
| `TXSHIELD_API_KEYS=k1,k2` | Requires `Authorization: Bearer <key>` on `/api/` routes (except `openapi.json`). Keys must be at least 24 characters, are stored as SHA-256 digests, and are compared in constant time. |
| `TXSHIELD_RATE_LIMIT_RPS` / `_BURST` | Token bucket per client IP on `/api/` routes (default 5 rps, burst 20; RPS 0 disables). |
| `TXSHIELD_TRUST_PROXY_HEADERS=true` | Use the last `X-Forwarded-For` entry as the client IP (only behind a proxy that sets it). |
| `TXSHIELD_CORS_ORIGINS=https://dash.example` | Explicit browser origins; wildcards are rejected. |
| `TXSHIELD_MAX_BODY_BYTES`, `TXSHIELD_MAX_CALLDATA_BYTES`, `TXSHIELD_REQUEST_TIMEOUT` | Request size and time bounds. |

Without API keys the API is open. Bind it to localhost (the Compose default)
or put it behind an authenticating proxy.

## Persistence and privacy

With `TXSHIELD_DATABASE_URL` set, analyses are stored (unless `persist:
false`) and expire after `TXSHIELD_RETENTION_DAYS` (default 30; a worker
purges hourly). Defaults minimize stored data:

| Setting (default) | When off |
|---|---|
| `TXSHIELD_STORE_SENDER=false` | The sender address is removed from columns and replaced with `[redacted-sender]` everywhere in the stored report, findings, and simulation (including padded log topics). |
| `TXSHIELD_STORE_CALLDATA=false` | Raw calldata, decoded parameter values, call traces, and logs are not stored. Kept: selector, calldata hash, method names, findings, approvals, asset movements, balance changes. |

`GET /api/v1/analyses/{id}` returns the stored copy, with these options
applied. Storage failures never fail an analysis: the response carries a
warning instead.

## Metrics

On top of the HTTP request metrics: `txshield_analyses_total{category}`,
`txshield_analysis_duration_seconds`,
`txshield_simulations_total{backend,status,completeness}`,
`txshield_rate_limited_total`,
`txshield_store_errors_total`, and `txshield_dependency_up{dependency}` (which
includes `rpc:<chainId>` and `simulator:anvil`).
