# TxShield

**Open-source EVM transaction security & simulation engine.** TxShield analyzes an
unsigned transaction *before* it is signed: it decodes the call, simulates it on a
local fork, checks for dangerous approvals and suspicious interactions, and returns
a transparent, explainable risk report.

> **Project status: Phase 7 of 8 complete.** The analysis engine, fork
> simulation, REST API (OpenAPI 3.1), CLI, TypeScript SDK, and the security
> dashboard all work end to end. Phase 8 (hardening and release preparation)
> remains. See [`DEVELOPMENT_STATUS.md`](DEVELOPMENT_STATUS.md)
> for exactly what works.

TxShield never asks for private keys, never signs, and never broadcasts. It will
never call a transaction "safe": its strongest positive verdict is *"No significant
risks detected by enabled checks."*

## What works today

| Feature | Status |
|---|---|
| `txshield serve`: HTTP server with graceful shutdown | ✅ |
| `GET /health` (dependency checks), `GET /livez`, `GET /metrics` (Prometheus), `GET /api/v1/info` | ✅ |
| Request IDs, structured JSON errors, panic recovery, body-size limits, request timeouts, security headers | ✅ |
| Env-based configuration with validation and secret redaction | ✅ |
| Transaction input validation (`pkg/models.ParseTransaction`) | ✅ |
| PostgreSQL schema + migrations | ✅ |
| Docker image, Docker Compose stack, GitHub Actions CI | ✅ (Compose stack not yet run end-to-end; see status file) |
| Offline calldata decoder: ERC-20/721/1155, Permit/Permit2, Uniswap V2/V3/Universal Router, Multicall/Multicall3, Safe, proxy upgrades, nested calls, user ABIs | ✅ ([docs](docs/decoder.md)) |
| `txshield decode` CLI (text and JSON output) | ✅ |
| Security engine: 29 rules (approvals, reputation, value transfer, dangerous patterns), pluggable engine with panic/timeout isolation | ✅ ([rules](docs/security-rules.md)) |
| Reputation: JSON allow/block lists, Postgres records, external-adapter interface | ✅ |
| Risk scoring 0–100 with dedup, decay, floors, per-finding contributions | ✅ ([method](docs/risk-scoring.md)) |
| `txshield analyze` (offline: calldata + reputation lists; exit code 3 on high risk) | ✅ |
| Fork simulation (Anvil worker pool), `rpc-trace` fallback, traces, events, balance diffs | ✅ ([design](docs/simulation.md)) |
| On-chain contract checks: code, EIP-7702, proxies (1167/1967/beacon/1822), ERC-165/ERC-20 detection | ✅ |
| Hardened read-only RPC client: method allowlist, retries with jitter, circuit breaker, size caps, key redaction | ✅ |
| `txshield analyze --rpc`, `txshield simulate` | ✅ |
| Solidity fixtures (malicious + benign) executed on local Anvil in CI | ✅ |
| REST API: analyze, simulate, approvals, address inspector, history, stats ([guide](docs/api.md), OpenAPI at `/api/v1/openapi.json`) | ✅ |
| Persistence with privacy defaults (sender and calldata not stored unless enabled), retention purge | ✅ |
| Per-client rate limiting, optional API keys, CORS allowlist, SSRF guard for opt-in user RPC URLs | ✅ |
| CLI `approval-check` (current on-chain allowance / operator / Permit2) | ✅ |
| TypeScript SDK `@txshield/sdk`: typed (generated from OpenAPI), validation, timeouts, retries, ESM + CJS ([README](sdk/typescript/README.md)) | ✅ (not yet published to npm) |
| Dashboard (Next.js): overview, scanner (parameters / tx hash / calldata), security report, history, address inspector ([README](frontend/README.md)) | ✅ |
| Release hardening: independent security review with fixes, [benchmarks](docs/benchmarks.md), release workflow (binaries, multi-arch images with SBOM and provenance) | ✅ |

## Quick start

Requirements: Go ≥ 1.26 (use the latest patch release, see *Security* below), or Docker.

```bash
make build
./bin/txshield serve
```

```bash
curl -s localhost:8080/health
```

Analyze over HTTP (see [docs/api.md](docs/api.md)):

```bash
curl -s localhost:8080/api/v1/analyze -H 'Content-Type: application/json' -d '{"chainId":1,"from":"0x1111111111111111111111111111111111111111","to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0x095ea7b30000000000000000000000002222222222222222222222222222222222222222ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}'
```

Analyze with on-chain checks and a local fork simulation (needs [Foundry](https://getfoundry.sh)'s `anvil`; never signs or broadcasts):

```bash
./bin/txshield analyze --chain sepolia --rpc "$RPC_URL" --from 0x... --to 0x... --data 0x...
```

```bash
./bin/txshield simulate --chain sepolia --rpc "$RPC_URL" --tx transaction.json
```

Analyze a transaction offline (no RPC, no keys):

```bash
./bin/txshield analyze --from 0x1111111111111111111111111111111111111111 --to 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 --data 0x095ea7b30000000000000000000000002222222222222222222222222222222222222222ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff --reputation configs/reputation/example-blocklist.json
```

From TypeScript ([SDK](sdk/typescript/README.md)):

```ts
const shield = new TxShield({ baseUrl: "http://localhost:8080" });
const result = await shield.analyze({ chainId: 1, from, to, value: "0", data });
console.log(result.riskScore, result.findings);
```

Decode calldata offline (no RPC needed):

```bash
./bin/txshield decode --to 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 --data 0x095ea7b30000000000000000000000002222222222222222222222222222222222222222ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
```

With PostgreSQL and Redis via Docker Compose:

```bash
cp .env.example .env
```

```bash
docker compose up --build
```

Compose binds everything to `127.0.0.1`. The dashboard is on http://localhost:3000,
the API on `:8080`, and Postgres on `:55432`.

## Configuration

All configuration comes from `TXSHIELD_*` environment variables; see
[`.env.example`](.env.example) for the full list. The most important ones:

| Variable | Default | Purpose |
|---|---|---|
| `TXSHIELD_HTTP_ADDR` | `127.0.0.1:8080` | Listen address. Loopback by default; the Docker image sets `:8080`. |
| `TXSHIELD_RPC_URLS` | — | `chainId=url` pairs, comma-separated. Operator-trusted; redacted in logs; never returned by the API. |
| `TXSHIELD_DATABASE_URL` | — | Enables persistence. Empty means stateless. |
| `TXSHIELD_REDIS_URL` | — | Optional cache. |
| `TXSHIELD_ALLOW_USER_RPC` | `false` | Whether API clients may supply RPC URLs (https only, SSRF-guarded, rpc-trace simulation only). |
| `TXSHIELD_SIMULATOR` | `anvil` | `anvil`, `rpc-trace`, or `none`. |
| `TXSHIELD_API_KEYS` | — | When set, `/api/` routes require `Authorization: Bearer <key>`. |
| `TXSHIELD_RATE_LIMIT_RPS` / `_BURST` | `5` / `20` | Per-client-IP limit on `/api/` routes. |
| `TXSHIELD_REPUTATION_FILES` | — | Comma-separated JSON allow/block lists. |
| `TXSHIELD_CORS_ORIGINS` | — | Allowed browser origins (no wildcards). |
| `TXSHIELD_STORE_SENDER` | `false` | Persist sender addresses (privacy). |
| `TXSHIELD_RETENTION_DAYS` | `30` | Retention for stored analyses. |
| `TXSHIELD_DASHBOARD_BASIC_AUTH` | — | Dashboard only: `user:password` (password ≥ 16 characters) to require HTTP Basic auth on every dashboard request. |

## Browser extension

[`extension/`](extension/README.md) is a Chrome/Edge/Brave extension
(prototype) that checks each transaction a website asks your wallet to send,
before the wallet opens, and shows a plain-language warning ("Don't sign
this. It sends 1,000 TUSD* and NFT #1 out of your wallet, and you receive
nothing."). It uses a TxShield API you configure.

## Deploying

[`deploy/oracle/`](deploy/oracle/README.md) runs the whole stack on one VM
(Oracle Cloud Always Free works) with automatic HTTPS, API keys, and a
dashboard password.

## Exposing TxShield beyond localhost

Everything binds to `127.0.0.1` by default. Before exposing it:

1. **API:** set `TXSHIELD_API_KEYS` (or put an authenticating reverse proxy in
   front), terminate TLS at the proxy, and set
   `TXSHIELD_TRUST_PROXY_HEADERS=true` only if that proxy sets
   `X-Forwarded-For`. Add a global rate limit at the proxy: TxShield's limit is
   per client (IPv6 per /64).
2. **Dashboard:** it calls the API with its own key, so anyone who can reach
   it can run analyses and read history. Set `TXSHIELD_DASHBOARD_BASIC_AUTH`
   or use an auth proxy, and serve it over HTTPS.
3. Do not route `/metrics` or `/health` through a public proxy.
4. Keep `TXSHIELD_ALLOW_USER_RPC=false` unless callers must bring their own
   endpoints.

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities and the
[threat model](docs/threat-model.md) for what TxShield does and does not defend.

## Development

```bash
make test-race     # unit tests with race detector
make fuzz          # decoder fuzz targets
make bench         # benchmarks
make fixtures      # regenerate security scenario fixtures
make lint          # golangci-lint v2
make vuln          # govulncheck
make test-integration TEST_DATABASE_URL=postgres://...   # needs Postgres and Foundry (anvil, forge)
```

## Repository layout

```
cmd/txshield/        CLI + server entrypoint (dependency wiring)
internal/api/        HTTP gateway: routing, middleware, handlers, generated OpenAPI
internal/config/     env configuration + validation
internal/decoder/    offline calldata decoder (signature parser, ABI registry, nested calls)
internal/security/   rules engine, approvals, reputation, scoring
internal/analyzer/   orchestration + report generation
internal/evm/        read-only RPC client, chain registry, contract inspector
internal/simulator/  Anvil fork simulator, rpc-trace fallback, event/trace parsing
internal/logging/    slog setup + untrusted-string sanitizer
internal/metrics/    Prometheus collectors
internal/storage/    PostgreSQL analysis store (privacy options, retention)
internal/netguard/   SSRF guard for user-supplied URLs
internal/cache/      Redis cache
pkg/models/          public data types (transaction, findings, simulation, report)
pkg/interfaces/      module contracts (Decoder, Rule, Simulator, ReputationProvider, ...)
pkg/txerrors/        structured errors -> HTTP status / exit codes
migrations/          SQL migrations (golang-migrate format)
tests/integration/   tests needing real infrastructure (build tag `integration`)
tests/fixtures/      malicious/benign scenario fixtures (synthetic) + generator
configs/reputation/  example reputation list (placeholder entry only)
sdk/typescript/      @txshield/sdk TypeScript client
frontend/            Next.js dashboard
contracts/           Solidity test fixtures (Foundry); deliberately malicious ones included
docs/                architecture, threat model
```

## Documentation

- [Architecture & implementation plan](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Transaction decoder](docs/decoder.md)
- [Simulation](docs/simulation.md)
- [Security rules](docs/security-rules.md)
- [Risk scoring methodology](docs/risk-scoring.md)
- [HTTP API](docs/api.md) (OpenAPI: `internal/api/openapi.json`)
- [Benchmarks and methodology](docs/benchmarks.md)
- [Changelog](CHANGELOG.md), [Contributing](CONTRIBUTING.md), [Security policy](SECURITY.md)

## Security

- No private keys, no signing, no broadcasting, by construction.
- Reports separate **facts** (observed), **heuristics** (inferred), and **external**
  reputation data.
- Detection is not exhaustive, and simulation is not proof of safety.
- Build with the latest Go 1.26 patch release. Older patch releases contain
  standard-library vulnerabilities that `govulncheck` flags as reachable from
  TxShield's HTTP code. CI enforces this.

## License

Apache-2.0. See [LICENSE](LICENSE).
