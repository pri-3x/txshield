# Development Status

Last updated: 2026-11-07. Current phase: **8 (Hardening & release), complete** except the items under *Not verified*. All eight phases are implemented.

## Post-release: dashboard redesign (analyst console)

After reviewing three prototype directions (on a design canvas, using a real
drainer scan), direction B, the analyst console, was implemented.

| Area | Files | Tested |
|---|---|---|
| Dark console theme; every text pair computed against WCAG AA (lowest 5.85:1) | `frontend/src/app/globals.css`, `src/lib/risk.ts` | contrast computed; axe on every page |
| Shell: top bar with active nav (History link added) and header search by tx hash / address / analysis ID | `src/app/layout.tsx`, `src/components/NavLinks.tsx`, `src/app/go/page.tsx`, `src/lib/search.ts` | unit test for input classification |
| Report: summary bar; score breakdown and coverage; findings table sorted by severity with expandable evidence; balance diff, transfers, call trace with named standard selectors; JSON download and copy link | `src/components/report.tsx`, `FindingsTable.tsx`, `ReportActions.tsx` | component tests + axe; smoke; visual check at 1440 and 375 px |
| Overview, scanner, history, address restyled | `src/app/**` | smoke; no horizontal overflow at 375 px on all pages |
| API: token symbol/decimals from the token contract (sanitized, unverified, after rules) | `internal/evm/tokenmeta.go`, `internal/analyzer/analyzer.go` | unit tests (hostile symbols) + integration (real token) |
| Fix: net-loss finding listed the call's ETH twice | `internal/security/rules/value.go` | unit + integration |

Test results (2026-11-07): Go race tests all packages ok; golangci-lint 0
issues; integration 18 passed (Postgres + Anvil); dashboard 27 unit tests;
smoke 21 checks passed with Postgres history.

Limitation: the console is dark only (no light theme).

## Phase 8: Hardening & release (completed, with open items)

### Security review

An independent reviewer (a separate agent given only the code and the threat
model, read-only) checked seven invariants and found 3 high, several medium
and low findings. Every finding was fixed or documented; each fix has a test
that fails without it (mutation-checked where noted).

| Finding | Severity | Fix | Test |
|---|---|---|---|
| ABI decoding bomb: aliased array offsets made 29 KB of calldata allocate 2.6 GB (unbounded at 128 KiB); request timeout cannot stop it | High | Element-budget walk before every unpack (`internal/decoder/budget.go`) | Bomb via `Decode` and via the real API (122 KB refused in 0.03 s, server 22 MB RSS); canonical nested encodings still decode; fuzz property `FuzzElementBudget` (added to `make fuzz`/CI) |
| RPC URL with API key logged on timeout/cancel errors (5xx logs) | High | `classify` redacts every branch | Per-path leak test (timeout, cancel, 5xx, 4xx, garbage); mutation-checked |
| Dashboard exposes its API key's power to anyone who can reach it | High/Medium | Optional HTTP Basic auth in `proxy.ts` on every request; matcher no longer skips prefetch headers (that exclusion would have been an auth bypass) | Unit tests; smoke: 401 for no creds, prefetch headers, server action POST, wrong password |
| `/health` drives upstream RPC per unauthenticated probe | Medium | 5 s shared cache, detached context | 50 concurrent probes run checks once |
| Approvals endpoint: one RPC read per approval, unbounded | Medium | Cap 20 + warning | Fake node counts exactly 20 `eth_call` for 30 approvals |
| Rate limiter: IPv6 rotation; shared overflow bucket drained by floods | Medium | Key IPv6 by /64; evict instead of overflow | Unit tests |
| Caller-supplied-RPC reports stored in shared history | Medium/Low | Never persisted (warning); user RPC responses capped at 8 MiB | Unit test |
| Fork URL (API key) visible in Anvil's process arguments | Low | Loopback fork relay with random token; refuses send/sign/admin/anvil methods; never echoes upstream errors | Relay unit tests; integration asserts no worker argument contains the upstream URL |
| Anvil port race / reuse after crash | Low | `--port 0` + read bound address from output; restart workers whose process exited; `--no-cors` | Integration: kill worker, next simulation restarts it |
| Plain calldata hash links stored rows to public transactions | Low | HMAC with per-process key when calldata storage is off | Unit test |
| Uncapped caller gas; auth before rate limit; extra IPv6 ranges; `:8080` default bind | Low/Info | Gas ≤ 1e9; limiter wraps auth; 8 more blocked ranges; default `127.0.0.1:8080` | Unit tests |

Accepted and documented (threat model §4): unauthenticated `/metrics`, no
separate simulation quota, `Registry.Reader` background context.

### Performance

Profiling the parallel API benchmark showed ~44% of CPU in scheduler/timer
contention from one goroutine + timer per rule. Rules now run on one
supervised worker with a single reusable timer (a timed-out rule is abandoned
and a fresh worker continues, so isolation is unchanged), and in-memory
reputation providers are queried inline. Results (Apple M4), full table and
methodology in [docs/benchmarks.md](docs/benchmarks.md):

| | Before | After |
|---|---|---|
| Rules, ERC-20 transfer | 29-31 µs, 327 allocs | 14.8-15.8 µs, 73 allocs |
| Offline analysis | 57-68 µs | 40-51 µs |
| API, parallel, 4 cores | 43-51 µs/op | 20-21.5 µs/op (~48k req/s) |
| API, parallel, 10 cores | 68-70 µs/op | 34-36 µs/op; 12-14 µs/op with `GOGC=400` (remaining limit is GC) |
| Simulation, 1 / 2 / 4 workers (local upstream) | n/a | 26.8 / 13.9 / 7.2 ms/op |

Found while benchmarking: the fork relay's default HTTP transport kept only 2
idle connections, churning thousands of sockets; fixed with a pooled
keep-alive transport. Anvil itself opens ~25-30 connections per re-fork; on
macOS that caps sustained simulation at ~18/s per host (documented; Linux
reuses loopback TIME_WAIT ports by default).

### Release engineering

| Area | Files |
|---|---|
| Release workflow on `v*` tags: verify (tag = SDK version, CHANGELOG entry, fmt, vet, race tests, govulncheck) → linux/darwin amd64/arm64 binaries + SHA256SUMS + build-provenance attestation; multi-arch API and dashboard images to GHCR with BuildKit SBOM and provenance plus attestation → GitHub release with notes from CHANGELOG; npm publish with provenance only when `PUBLISH_NPM=true`, behind the `npm` environment | `.github/workflows/release.yml` |
| All actions (CI and release) pinned to full commit SHAs of releases at least 2 weeks old; both workflows pass actionlint 1.7.7 | `.github/workflows/*.yml` |
| CHANGELOG (Keep a Changelog), SECURITY.md (private reporting; detection gaps vs vulnerabilities), CONTRIBUTING.md (checks, generated files, rule checklist, wording rules) | root |
| Docs: benchmarks page; threat model T17-T28 updated/added; simulation lifecycle; README exposure checklist, config table, links | `docs/`, `README.md`, `frontend/README.md` |
| CLI: `--version` alias; analyze summary no longer says "offline mode" | `cmd/txshield/main.go` |

### Clean-clone verification

The repo was copied without `node_modules`, `.next`, `dist`, `bin` and the
README quick start followed: `make build`; `serve` + `curl /health` +
`curl /api/v1/analyze`; offline `analyze` and `decode`; `analyze --rpc` and
`simulate --tx` against a local Anvil (through the fork relay); SDK and
dashboard `npm ci`, typecheck, lint, tests, build. All worked. Port 8080 was
taken by an unrelated local program, so the server ran on 18080.

### Test results (local, 2026-11-07, Apple M4, Go 1.26.2, Node 22, Anvil 1.8.5, Postgres 15)

```
go test -race ./...                      17 packages ok
golangci-lint v2.6.2 (integration tag)   0 issues
govulncheck (Go 1.26.10)                 No vulnerabilities found
govulncheck (Go 1.26.2)                  stdlib CVEs fixed in 1.26.9/1.26.10 (known; CI uses latest patch)
make fuzz FUZZTIME=15s                   3 targets ok
fixtures / SDK generated types           no drift
integration (Postgres + Anvil + Forge)   17 passed, 0 skipped
SDK integration (real server + anvil)    6 passed
dashboard unit                           26 passed
dashboard smoke (Postgres history)       21 checks passed
actionlint 1.7.7                         ok (ci.yml, release.yml)
```

### Phase 8 limitations

- Docker images not built and `docker compose up` not run: the Docker daemon
  was not running. The release workflow's image jobs are therefore untested.
- No workflow has run on GitHub (no remote repository). Action major versions
  were raised (e.g. checkout v4 → v7) when pinning; first CI run must confirm.
- Nothing was published (GitHub release, GHCR, npm).

## Phase 7: Dashboard (completed)

| Area | Files | Tested |
|---|---|---|
| New API endpoints the dashboard needed: `POST /api/v1/decode` (offline decode, no sender) and `GET /api/v1/transactions/{hash}` (lookup, replay on parent block, notes on approximation and tx types) | `internal/api/handlers_tx.go` | unit + integration (real mined tx looked up and re-analyzed) |
| SDK: `decode()`, `getTransaction()`; types regenerated | `sdk/typescript` | 18 unit tests |
| Next.js 16 app (App Router, React 19, Tailwind 4), standalone output | `frontend/` | build |
| Pages: dashboard (stats, risk and chain charts, high-risk and recent), scanner (parameters / tx hash / calldata), security report, history with filters and pagination, address inspector | `frontend/src/app/**` | component tests + smoke |
| Security report components: score band and contributions, findings with source/evidence/mitigation/false-positive notes, permissions with current state, simulation (balance changes, transfers, trace, notes), decoded call tree, limitations, disclaimer | `frontend/src/components/report.tsx` | component tests |
| Server-only SDK client (API key never reaches browsers), server actions for the scanner | `src/lib/txshield.ts`, `src/app/scan/actions.ts` | smoke asserts key absent from pages |
| Strict nonce CSP via `proxy.ts` (no `unsafe-inline`), security headers, untrusted-text rendering (`visible()`), `react/no-danger` lint | `src/proxy.ts`, `src/lib/format.ts`, `eslint.config.mjs` | smoke (CSP, nonces on all scripts) + tests (inert markup, bidi exposed) |
| Accessibility: landmarks, skip link, labelled fields with linked errors, ARIA tabs with arrow keys, chart names, table views, non-color status cues | components | axe-core on components and on every server-rendered page |
| Charts per the data-viz method: single-series SVG bars, one validated hue, rounded data ends, direct labels, per-bar tooltip/focus, table view, light and dark steps | `src/components/BarChart.tsx` | tests + visual check |
| Docker (distroless Node, non-root, healthcheck), Compose `dashboard` service, CI job (typecheck, lint, tests, build, smoke with Postgres + anvil, prod audit) | `frontend/Dockerfile`, `docker-compose.yml`, CI | compose validated; image not built locally |

### Design decisions

- **The browser never talks to the API directly.** It talks only to the
  dashboard's server components and server actions.
  - The API key stays server-side, and no CORS configuration is needed.
  - The trade-off is that server actions are endpoints: whoever can reach the
    dashboard can analyze through it. This is documented, and Compose binds it
    to localhost.
- **Transaction-hash replay is labelled an approximation.** The API returns
  notes saying that earlier transactions in the same block are not
  re-applied, and the scanner shows them before the user analyzes.
- **No `'unsafe-inline'` anywhere in the CSP.** Charts use SVG attributes
  rather than inline styles.
- **SDK installed as a packed copy** (`install-links`). Turbopack does not
  follow symlinks outside the app root, and Docker needs the copy anyway.
- **Dependencies pinned and at least 2 weeks old.** Next 16.4.2, React 19.3.1,
  Tailwind 4.3.3, ESLint 10.13, TypeScript 5.9.3, vitest 4.1.12, jsdom 30.1.3,
  axe-core 4.14.0, Testing Library 16.3.3 / dom 10.4.2.

### Found and fixed during visual and automated checks

- Duplicate landmark names (table regions vs card headings; two analysis
  tables; a duplicated heading id), found by axe.
- White button text on the dark-mode accent was about 3.7:1; a dedicated
  button token now gives 6.6:1 (light) and 4.6:1 (dark).
- Chart text rendered at about 7–8px on phones; re-proportioned to render at
  about 13px.
- Values below display precision showed as "0.000001" instead of
  "<0.000001".
- Method signatures wrapped mid-word; now shown as the function name with the
  signature in the tooltip.
- A redacted sender appeared as a copyable "address"; it now says "Not stored".
- `/analyses` was a dead end; added the history page.
- React Compiler lint caught JSX inside `try/catch` and a render-time mutation.

### Test results (local, 2026-11-07, Node 22.23.2, Go 1.26.2/1.26.10, Anvil 1.8.5, Postgres 15)

```
Go: vet, gofmt, golangci-lint (incl. integration)     clean / 0 issues
Go unit (race)                                         16 packages pass
Go integration (race)                                  all pass (new: TestTransactionLookupAndReplay)
govulncheck (go1.26.10)                                No vulnerabilities found
SDK: typecheck, 18 unit tests, build                   pass; npm audit 0
Dashboard: tsc, eslint                                 clean
Dashboard: vitest (unit, component, axe)               23 passed
Dashboard: next build                                  ok (standalone)
Dashboard: smoke (real API + anvil + Postgres)         17/17 checks pass; also passes without a database
Dashboard: npm audit --omit=dev                        0 vulnerabilities
```

Visual check in the in-app browser against a live local stack (real analyses
on the local chain and offline mainnet):

- every page at desktop width in light and dark mode
- the dashboard at phone width
- a scanner run end to end through the server action, with the Anvil
  simulation shown in the report

### Phase 7 limitations

- **Docker images not built locally** (no daemon); the CI `docker` job builds both.
- **Dev-only advisory accepted:** `minimatch` ReDoS in the ESLint toolchain.
  The fix needs a major version that ESLint plugins do not support yet;
  production dependencies are clean.
- **No browser end-to-end tests** (e.g. Playwright). Client interactions are
  covered by component tests; full pages by the smoke test and the manual
  visual check.
- **Token amounts are shown as raw base units**, since token decimals are
  deliberately not trusted.
- **Address inspector "token approvals"** is limited to approvals seen in
  stored analyses (no chain-wide approval index).
- **No dashboard authentication** of its own; rely on API keys plus network
  placement or an authenticating proxy.

## Phase 6: TypeScript SDK (completed)

| Area | Files | Tested |
|---|---|---|
| Types generated from `internal/api/openapi.json` (openapi-typescript); CI fails if they drift | `sdk/typescript/src/generated/openapi.ts`, `src/types.ts` | CI drift check |
| `TxShield` client: `analyze` (with `riskScore`/`riskCategory` convenience fields, matching the spec's example), `simulate`, `analyzeApprovals`, `inspectAddress`, `listAnalyses`, `getAnalysis`, `stats`, `info`, `health` | `src/client.ts` | unit + integration |
| Client-side validation mirroring the server: address shape, hex data, chain ID range, `bigint`/safe-number/string quantities up to uint256, fee-field rules, block refs, ABI, https-only `rpcUrl`, query params; all problems reported at once | `src/validate.ts` | unit |
| `TxShieldError` (kind, code, status, fields, requestId, retryAfterMs, `retryable`); non-JSON error pages and invalid JSON handled | `src/errors.ts` | unit |
| Whole-call deadline incl. retries, per-call timeout, caller `AbortSignal`; retries only for network errors and 429/502/503/504 (not configuration 503s), `Retry-After` honored and capped, backoff with full jitter, no retry past the deadline | `src/client.ts` | unit (mocked fetch) |
| Dual ESM + CJS build with declarations (no runtime dependencies); package contents verified with `npm pack` | `tsconfig.*.json`, `scripts/` | build + require/import smoke |
| Integration tests: build and start a real `txshield serve` (API keys, reputation list, Anvil chain) and drive it through the SDK | `test/integration.test.ts` | 6 tests |
| README, two examples (typechecked), CI job (generate-drift, typecheck, unit, build, pack, integration, `npm audit`) | `README.md`, `examples/`, `.github/workflows/ci.yml` | n/a |

### Design decisions

- **Generated types, hand-written client.** Response shapes come from the OpenAPI document (single source of truth). Method ergonomics (`bigint` inputs, convenience fields, error class) are hand-written.
- **Every method rejects; nothing throws synchronously.** Found by a test: an `async` method rejected while non-async ones threw, which is an inconsistent contract, so all methods are now `async`.
- **No runtime dependencies.** Uses global `fetch` and `AbortController`.
- **Node 20+.** Node 18 is end-of-life and the test runner needs 20+, so claiming 18 would have been untested.
- **Pinned dev tooling, ≥ 2 weeks old.** TypeScript 5.9.3, openapi-typescript 7.13.0, vitest 4.1.12, vite 7.3.7, @types/node 22.20.5.
  - vitest 4.0.18 had two advisories (one critical) fixed only in 4.1.12.
  - 4.1.12 triggers an npm 10 resolver crash (`edgesOut`), so `.npmrc` sets `legacy-peer-deps` and the real peers are pinned explicitly.
  - `npm audit`: 0 vulnerabilities.

### Test results (local, 2026-11-06, Node 22.23.2)

```
tsc --noEmit (strict, noUncheckedIndexedAccess)   clean (src, tests, examples)
vitest unit                                        16 passed
vitest integration (real server + anvil)           6 passed; no leftover processes
npm run build                                      dist/esm + dist/cjs; require() and import both load
npm pack --dry-run                                 26 files, 19.4 kB, no dangling source maps
npm audit                                          0 vulnerabilities
```

### Phase 6 limitations

- **Not published to npm.** The package name `@txshield/sdk` is unclaimed and publishing needs your account and approval.
- **No Go SDK.** The spec says "Go SDK where appropriate"; Go users can import `pkg/models` and call the HTTP API, but there is no dedicated Go client package yet.
- **Checksums are not validated client-side.** EIP-55 needs keccak; doing it would add a dependency, so the server validates instead.
- **Browser use is not separately tested** (the integration tests run in Node). It uses only standard `fetch` and `AbortController`.

## Phase 5: API & CLI (completed)

| Area | Files | Tested |
|---|---|---|
| Endpoints: `POST /api/v1/analyze`, `/simulate`, `/approvals/analyze`; `GET /api/v1/address/{address}`, `/analyses`, `/analyses/{id}`, `/stats`, `/openapi.json`; `/api/v1/info` extended | `internal/api/handlers*.go`, `engine.go` | unit (offline engine + in-memory store) and integration (Anvil + Postgres) |
| Request validation: strict JSON (unknown fields rejected), transaction parsing, ABI limits, pagination bounds, RFC 3339 filters | `internal/api` | unit |
| Per-chain component selection: operator RPC, opt-in user RPC (SSRF-guarded, rpc-trace only), or offline with an explicit warning | `internal/api/engine.go` | unit + integration |
| SSRF guard: https only; public IPs checked at DNS resolution and again at dial time (DNS rebinding); IPv4-mapped/NAT64/6to4/Teredo handled; redirects refused | `internal/netguard`, `evm.Options.PublicOnly` | unit (incl. a real dial refused) |
| Per-IP token-bucket rate limiting (bounded key table, `Retry-After`), trusted-proxy option, CORS allowlist (no wildcards), optional API keys (SHA-256, constant-time) | `internal/api/protect.go` | unit |
| Postgres `AnalysisStore`: atomic write of analysis + simulation + findings + address ledger; privacy defaults (sender redacted everywhere incl. padded topics; calldata/params/traces/logs dropped); list/filter/paginate, stats, purge | `internal/storage/analyses.go` | integration |
| Retention worker (hourly purge), engine wiring in `serve`, non-critical health checks (`rpc:<chain>`, `simulator:anvil`), Anvil workers stopped on shutdown | `cmd/txshield/{engine,serve}.go` | smoke test of the binary |
| Metrics: analyses by category, analysis latency, simulations by backend/status/completeness, rate-limited requests, store errors | `internal/metrics` | via API tests and smoke test |
| OpenAPI 3.1 generated from Go types; CI fails on drift or undocumented routes; validated with Redocly CLI (0 errors, 5 style warnings) | `internal/api/openapi.json`, `openapi_gen_test.go` | unit |
| CLI `approval-check`: ERC-20 allowance or ERC-721/1155 operator status (by detected standard), Permit2 allowance, spender code and reputation; exit 3 when risky | `cmd/txshield/approvalcheck.go` | integration against fixture approvals |
| On-chain approval state reader shared by API and CLI (allowance, isApprovedForAll, getApproved, Permit2 allowance; selectors verified by computation) | `internal/security/approvals/current.go` | integration |
| Docs: API guide, threat model T3/T4/T10/T19/T20, architecture, README, `.env.example` | `docs/api.md` etc. | n/a |

### Design decisions

- **Generated OpenAPI.** Schemas are reflected from the exact Go types the handlers encode, and paths are declared beside the routes, so the spec cannot silently drift (`go test ./internal/api -run TestOpenAPISpec -update`).
- **Added optional API-key auth** (not in the original spec). The OpenAPI linter flagged the missing security scheme, and an analysis/simulation API without auth invites abuse. It is off by default for local use; Compose binds to 127.0.0.1.
- **Unconfigured chains still get an answer.** Static analysis runs with a clear warning instead of failing; `/simulate` returns 422.
- **User-supplied RPC never reaches Anvil.** Anvil makes its own connections, which TxShield cannot SSRF-check at dial time, so user URLs only get the guarded rpc-trace backend.
- **Persistence never fails an analysis.** A storage error becomes a warning plus a metric.
- **Removed a metric** (`rule_failures_total`) that I had declared but never incremented, rather than ship a dead series.
- **History lists return summaries**, not full reports (payload size); `GET /analyses/{id}` returns the stored report.

### Test results (local, 2026-11-06, Apple M4, Postgres 15, Anvil 1.8.5)

```
go vet ./... (default + integration)               clean
golangci-lint v2.6.0 (default + integration)       0 issues
go test -race -count=1 ./...                       16 packages pass
go test -race -tags integration ./tests/...        14 tests pass (new: TestAnalysisStorePrivacyAndQueries,
                                                   TestAPIEndToEnd, TestCLIApprovalCheck); no leaked anvil processes
govulncheck (go1.26.10)                            No vulnerabilities found
Redocly CLI 1.25 lint of openapi.json              valid (5 style warnings: localhost server, ops endpoints without 4xx)
coverage: api 87.3%, netguard 95.2%, config 89.9% (unit); storage+api 60.2% under integration
```

Binary smoke test (`txshield serve` with Postgres, API key, reputation list, CORS):
- no key gave 401; `/health`, `/livez`, `/metrics`, `/openapi.json` stayed open
- `/analyze` scored 85 critical from the blocklist; the stored row had `from_address` NULL
- `/analyses`, `/address`, `/info`, and metrics all behaved as expected
- SIGTERM exited 0
- neither the API key nor the sender address appeared in logs

### Phase 5 limitations

- **The API is open unless `TXSHIELD_API_KEYS` is set.** There are no per-key scopes or quotas; rate limits are per IP.
- **Rate limiting is in-process.** Several replicas each apply their own limit (no shared Redis limiter yet).
- **History by address relies on the ledger,** so addresses that appear only in undecoded calldata are recorded as `interacted`.
- **No transaction-hash input yet.** Analyzing a mined transaction by hash (scanner requirement) is not implemented.
- **Token approvals listing for an address** (Address Inspector "token approvals") covers only approvals seen in stored analyses or checked with `approval-check`; there is no chain-wide approval indexer.
- **Docker image still not built locally** (no daemon); the CI `docker` job builds it.

## Phase 4: Simulation Engine (completed)

| Area | Files | Tested |
|---|---|---|
| HTTP JSON-RPC client (in-house, no new deps): upstream read-only method allowlist, local-only send access (loopback IPs), retries with exponential backoff + full jitter (transient errors only), circuit breaker, response size cap, no redirects, no env proxies, API-key redaction in all errors | `internal/evm/{jsonrpc,client,resilience}.go` | unit with recording fake node (allowlist, retries, breaker, redaction, size cap, redirect, cancellation) |
| Chain registry with one-time `eth_chainId` verification | `internal/evm/registry.go` | unit |
| Contract inspector: code/hash, EIP-7702 delegation, EIP-1167/1967/beacon/1822/legacy-OZ proxies, ERC-165 (with `0xffffffff` compliance check), ERC-20 heuristic, LRU cache for pinned blocks | `internal/evm/inspector.go` | unit + real contracts on Anvil |
| Event parsing (ERC-20/721/1155, ApprovalForAll, WETH deposit/withdrawal), trace conversion (reverted-frame effects dropped, frame/IO caps), revert decoding (Error/Panic/custom) | `internal/simulator/{events,trace}.go` | unit |
| Anvil fork simulator: worker pool, re-fork per job, chain-ID check, zero-fee execution, impersonation, receipt polling, trace, events, sender balance diffs, completeness + reasons, notes, worker kill on error | `internal/simulator/anvil.go` | integration (real Anvil) |
| `rpc-trace` fallback simulator (`debug_traceCall`, `eth_call` fallback) | `internal/simulator/rpctrace.go` | integration |
| Analyzer resolves the block once per analysis (`Chains`) | `internal/analyzer` | unit + integration |
| CLI: `analyze --rpc/--simulator/--block/--tx`, new `simulate` command (exit 5 on revert) | `cmd/txshield/{analyze,simulate,txinput}.go` | unit + CLI integration test against a local chain |
| Solidity fixtures: TestToken, TestNFT, SimpleExchange, ERC1967Proxy, Cloner (benign); Drainer, Forwarder, ReentrantVault + VaultAttacker, Reverter, DelegateExecutor + OwnerHijack (malicious) | `contracts/fixtures/*.sol` | compiled by Forge and executed in integration tests |
| Docker: pinned Foundry v1.8.5 with SHA-256 verification, distroless `cc` runtime, tmpfs HOME; CI installs Foundry for integration tests | `Dockerfile`, `docker-compose.yml`, `.github/workflows/ci.yml` | compose validated; **image not built** (no Docker daemon) |
| Docs | `docs/simulation.md`, architecture §4.3, threat model T6/T12/T17/T18 | n/a |

### Design decisions

- **Own JSON-RPC client instead of go-ethereum's `rpc`.** That package pulls in WebSocket, OpenTelemetry, and gopsutil. About 100 lines of HTTP client give full control (allowlist, size cap, redirects). Trade-off: no WebSocket endpoints.
- **Allowlist, not denylist, for upstream methods.** New or vendor-specific mutating methods are refused by default.
- **Worker pool with re-fork instead of a process per simulation.** Measured 25-30 ms warm vs ~130 ms cold. Each job starts from a fresh fork, and a worker in an unknown state is killed.
- **Fees zeroed during simulation.** Native balance diffs then show value movements only. The trade-off (contracts reading `tx.gasprice`/`basefee` see 0) is recorded in result notes and the docs.
- **Pre-execution rejection is a "revert", infrastructure failure is an error.** Insufficient funds is a property of the transaction; an unreachable RPC says nothing about it.

### Behavior changes found by real execution (Phase 3 code)

Running rules against real simulated traces exposed three issues, now fixed and tested:
1. **False positive:** a swap on an *undecoded* contract triggered TXS-VALUE-001, because its token arguments were not seen as referenced. Address-shaped words of undecoded calldata now count as referenced (trade-off documented in the rule).
2. **Under-weighted backdoor:** a delegatecall into an address supplied in calldata was rated low. It is now high/medium (arbitrary delegatecall).
3. **Revert reason wording:** reasons are now decoded by TxShield first, so they read the same across backends.

### Test results (local, 2026-11-06, Apple M4, Anvil/Forge 1.8.5, Postgres 15)

```
go vet ./... (default + integration tags)         clean
gofmt -l .                                        clean
golangci-lint v2.6.0 (default + integration tags) 0 issues
go test -race -count=1 ./...                      15 packages pass
go test -race -tags integration ./tests/...       11 tests pass:
  TestAnvilSimulatesWithoutBroadcasting  (incl. 6 concurrent sims; chain unchanged afterwards)
  TestAnvilDrainerEffects, TestAnvilReverts (string/panic/custom/insufficient funds)
  TestAnvilInfrastructureFailuresAreErrors (chain mismatch, upstream down, timeout)
  TestRPCTraceFallback, TestInspectorOnRealContracts
  TestEndToEndAnalysis (9 cases), TestCLIAgainstLocalChain, TestAnvilColdStart
  TestMigrationsUpDown, TestPostgresReputationProvider
govulncheck (go1.26.10)                           No vulnerabilities found
coverage: evm 84.8% (unit); simulator 24.4% unit / 70.7% simulator+evm under integration
```

End-to-end analysis on real execution (score / category, confidence high in all cases):

| Case | Score | Rules |
|---|---|---|
| Drainer `claim()` with 1 ETH | 83 critical | VALUE-001..005 |
| Forwarded `transferFrom` | 61 high | PATTERN-008, VALUE-003 |
| Re-entrant vault attack | 40 elevated | PATTERN-010, VALUE-003, VALUE-004 |
| Approve to EOA | 34 moderate | APPROVAL-004 |
| Delegatecall backdoor | 30 moderate | PATTERN-001 (calldata-supplied target) |
| Calldata to EOA | 22 moderate | INTERACT-005 |
| Reverting swap | 8 low | SIM-001 |
| ERC-20 transfer; swap on undecoded exchange | 0 low | none |

Simulation overhead (local upstream, so no network latency): warm 25-29 ms, cold start ~130 ms. Methodology is in `docs/simulation.md`.

### Phase 4 limitations

- **Docker image is not built or verified.** No Docker daemon was available. The Foundry download and checksum were verified locally; the image build runs in CI's `docker` job.
- The API server does not use the simulator yet (Phase 5). `TXSHIELD_SIMULATION_*` config is defined but not wired, and server shutdown does not yet stop Anvil workers.
- WebSocket RPC endpoints are not supported.
- Simulated block time uses Anvil's clock; fees are zeroed; contracts can detect simulation. All are documented and reported in result notes.
- Balance diffs cover the sender only.
- No state overrides, and no historical replay by transaction hash.
- The fork URL (with any API key) is visible in Anvil's process arguments on the host.

## Phase 3: Security Engine (completed)

| Area | Files | Tested |
|---|---|---|
| Call-tree walk with msg.sender/context tracking, address-role collection, finding builder | `internal/security/core` | unit (84.8%) |
| Approval extraction: ERC-20 approve/increaseAllowance, ERC-721 approve (standard resolved from contract facts), setApprovalForAll, EIP-2612, DAI permit, Permit2 approve/permit/batch, Universal Router PERMIT2 commands; owner tracking through Multicall3/Safe/self-multicall | `internal/security/approvals/extract.go` | unit |
| 7 approval rules (unlimited, very large, operator, EOA spender, flagged spender, unknown spender, long-lived Permit2) | `internal/security/approvals/rules.go` | unit incl. false positives (94.2%) |
| Rule engine: concurrent, per-rule timeout, panic isolation, findings cap, rule-ID integrity, metadata validation | `internal/security/rules/engine.go` | unit |
| 22 further rules: 6 interaction/reputation, 5 value-transfer, 10 dangerous-pattern, 1 simulation | `internal/security/rules/*.go` | unit incl. false positives (93.3%) |
| Reputation: JSON list provider (strict validation), static provider, Postgres provider (`contract_reputation`), aggregator with timeouts and failure warnings, `Effective()` resolution policy | `internal/security/reputation` | unit + Postgres integration test |
| Risk scorer: fingerprint dedup, severity x confidence x source points, per-rule repeat decay, probabilistic combination, high-confidence floors, assessment confidence, JSON-configurable weights | `internal/security/scoring` | unit (91.7%) |
| Analyzer: decode, reputation and contract facts in parallel, optional simulation, rules, score, report (summary, verdict, recommendations, enabled checks, warnings, disclaimer); degrades instead of failing on dependency errors | `internal/analyzer` | unit + 19 scenarios (89.1%) |
| `txshield analyze` offline CLI (`--reputation`, `--scoring-config`, `--abi`, `--fail-on`, `--json`), exit code 3 on high risk | `cmd/txshield/analyze.go` | unit |
| Security scenario fixtures: 11 malicious/unusual + 8 benign, 7 of them explicit false-positive cases; generated from real ABI encodings; CI drift check | `tests/fixtures/` | run through the full analyzer in CI |
| Decoder additions: flash-loan signatures (Aave, Balancer, Uniswap V3, ERC-3156, V2 pair swap) | `internal/decoder/builtin.go` | 6 new pinned selectors |
| Docs: scoring methodology, rule catalog (test-enforced), list format | `docs/risk-scoring.md`, `docs/security-rules.md` | doc-sync test |

### Design decisions

- **Approvals judged only when they touch the sender's assets.** `msg.sender` is tracked through the decoded tree. An approve inside Multicall3 belongs to Multicall3, not the user. A self-multicall or Safe execution counts as the user's. This removes a whole class of false positives.
- **Rules stay silent without their inputs.** EOA, unverified, and code checks need chain facts; value rules need a successful simulation; "unknown address" rules need at least one reputation source. Missing inputs lower assessment confidence instead of producing guesses.
- **Facts, heuristics, and external opinion are distinct.** An operator-list record is a fact ("the operator flagged this"); third-party data is `external` and weighs less. External data alone cannot force the critical band.
- **Probabilistic combination with floors** (see `docs/risk-scoring.md`). It is bounded, gives diminishing returns, and one well-supported critical finding always yields "critical".
- **Solidity fixtures moved to Phase 4.** The spec's malicious/benign Solidity fixtures only make sense once they can be executed on Anvil. Phase 3's security fixtures are transaction scenarios with synthetic chain facts and simulation results, which test every rule deterministically without a node.
- **Offline `analyze` now, `--rpc` later.** The analyzer accepts optional inspector and simulator implementations; Phase 4 supplies them and Phase 5 wires `--rpc`.

### Interface changes

- `ReputationProvider.Lookup` now returns `[]models.ReputationRecord` (a provider can hold chain-specific and all-chain records).
- `AnalysisContext` gained `Now`, `ContractsKnown`, `ReputationSources`, and `Approvals`. `RiskReport` gained `Approvals`.
- `models.MaxChainID = 2^53-1` is enforced in validation (exact in JavaScript, fits Postgres BIGINT).

### Test results (local, 2026-11-06, Apple M4)

```
go vet ./... (incl. -tags integration)    clean
gofmt -l .                                clean
golangci-lint v2.6.0                      0 issues
go test -race -count=1 ./...              all 14 test packages pass
integration (local Postgres 15)           TestMigrationsUpDown PASS, TestPostgresReputationProvider PASS
FuzzDecodeKnownSelector 30s (new signatures)   0 failures
govulncheck (go1.26.10)                   No vulnerabilities found
```

Scenario outcomes (score / category / rules fired):

| Scenario | Score | Rules |
|---|---|---|
| malicious-unlimited-approval-blocklisted-spender | 89 critical | APPROVAL-005, APPROVAL-001, INTERACT-003 |
| malicious-multicall-to-blocklisted | 86 critical | INTERACT-001, INTERACT-003 |
| malicious-fake-claim-drainer | 82 critical | VALUE-001..005 |
| malicious-proxy-upgrade | 76 high | PATTERN-005, -001, -004 |
| malicious-nft-operator-approval-to-eoa | 64 high | APPROVAL-003, -004 |
| malicious-forwarded-transferfrom | 60 high | PATTERN-008 |
| malicious-safe-delegatecall | 60 high | PATTERN-001, -004 |
| permit2-unlimited-long-lived-via-router | 28 moderate | APPROVAL-001, -007, PATTERN-002 |
| malicious-calldata-to-eoa | 22 moderate | INTERACT-005 |
| benign-unlimited-approval-known-router | 22 moderate | APPROVAL-001 |
| failed-transaction-revert | 8 low | SIM-001 |
| unusual-flash-loan-reentrancy | 5 low | PATTERN-007, -010 |
| 7 other benign / false-positive scenarios | 0 low | none above info |

### Phase 3 limitations

- Value-transfer, trace, and revert rules are tested only on **synthetic** simulation results; Phase 4 produces real ones.
- Contract facts (code, proxies, ERC-165 standards) have no implementation yet (`ContractInspector` is Phase 4). Offline, ERC-20 vs ERC-721 `approve` stays ambiguous.
- No external reputation adapter ships (the interface exists). There is no default allowlist of well-known contracts, deliberately: a wrong built-in address would be worse than none.
- No Slither integration yet (optional, needs verified source; planned with contract metadata).
- Scoring weights are expert defaults, not fitted to labelled data.
- Detection is not exhaustive. Known gaps include signature-only phishing (off-chain `eth_signTypedData` permits that never reach a transaction), address poisoning, and aggregator calldata not covered by the decoder.

## Phase 2: Transaction Decoder (completed)

| Area | Files | Tested |
|---|---|---|
| Human-readable signature parser (tuples, nested arrays, aliases, strict base-type validation) | `internal/decoder/sigparse.go` | unit |
| ABI registry: 71 built-in signatures (plus 14 Universal Router command layouts) across ERC-20/721/1155, EIP-2612, DAI permit, Permit2, WETH, Uniswap V2/V3/SwapRouter02/Universal Router, Multicall, Multicall3, Ownable, proxy admin, Gnosis Safe | `internal/decoder/registry.go`, `builtin.go` | 35 selectors pinned to known mainnet values; every selector checked against keccak; duplicate signatures rejected |
| Decoder core: native transfer, creation, unknown selector, short calldata, malformed args, selector collisions (candidates), user ABI with precedence and target scoping, trailing-byte / non-canonical encoding warnings, panic recovery | `internal/decoder/decoder.go` | unit |
| JSON-safe rendering of all ABI type families | `internal/decoder/render.go` | unit |
| Nested decoding: self-multicall, Multicall3 (all variants, with values), Universal Router commands 0x00-0x0e (allow-revert flag, unknown commands, length mismatch), Safe `execTransaction` (delegatecall detection), `upgradeToAndCall` / ProxyAdmin `upgradeAndCall` | `internal/decoder/nested.go` | unit |
| Uniswap V3 path decoding (derived param) | `internal/decoder/annotate.go` | unit |
| Depth (4) and call-count (256) budgets; context cancellation | `decoder.go` | unit |
| `txshield decode` (text + JSON, `--abi`, stdin, terminal-escape sanitizing, exit codes) | `cmd/txshield/decode.go` | unit |
| Model/interface changes: `DecodedCall.CallType`, `.Label`, `.Value`; `Decoder.Decode(ctx, tx, DecodeOptions)` | `pkg/models/report.go`, `pkg/interfaces` | compile + decoder tests |
| Docs: contract, supported signatures, rendering rules, limits, benchmark methodology | `docs/decoder.md` | n/a |
| Fuzz targets `FuzzDecode`, `FuzzDecodeKnownSelector`; `make fuzz`, `make bench`; 20s fuzz smoke run per target in CI | `internal/decoder/fuzz_test.go`, `Makefile`, CI | see below |

### Design decisions

- **Own signature parser instead of JSON ABIs for built-ins.** Keeps the catalog readable and reviewable (one line per function). It also lets users pass signatures later (e.g. `--sig`). It is validated against real selectors.
- **Shared signatures are registered once with a combined standard** (`erc20|erc721`). Calldata cannot distinguish them, so the decoder does not guess. Phase 3 resolves the standard via chain state (ERC-165 / code inspection).
- **Re-encoding check.** Each decode is re-packed and compared with the input, which surfaces trailing data and non-canonical encodings. It costs roughly half the decode time and is kept deliberately.
- **Universal Router: only command types 0x00-0x0e are decoded.** Higher command types differ between router versions, so they are reported raw instead of risking a wrong label.
- **A user ABI applies only to the top-level target.** It covers self-multicall children, but never contracts reached via Multicall3, Safe, or similar containers.

### Test results (local run, 2026-11-06, Apple M4, macOS)

```
go vet ./...                          clean
gofmt -l .                            clean
golangci-lint v2.6.0                  0 issues
go test -race -count=1 ./...          all 8 test packages pass
  coverage: decoder 92.9%, cmd/txshield 63.4% (others unchanged from Phase 1)
FuzzDecode                45s   ~8.2M execs, 0 failures
FuzzDecodeKnownSelector   90s   ~13.2M execs, 0 failures
govulncheck (go1.26.10)               No vulnerabilities found
```

Benchmarks are in `docs/decoder.md` (ERC-20 transfer ~1.1 µs; Universal Router swap ~6 µs; 50-call Multicall3 ~168 µs).

### Phase 2 limitations

- No 4-byte signature database: selectors outside the built-in set and any user ABI decode as `unknown`. An offline signature-DB adapter (`DecodeSignature` source) is a possible later addition.
- Universal Router command types 0x10+ (v4 swaps, NFT marketplaces, position manager) are not decoded.
- Other aggregators (1inch, 0x, Paraswap, CoW), Seaport, and Blur are not decoded; they appear as `unknown` with raw calldata.
- Contract-creation init code is not analyzed.
- The decoder is not yet exposed over HTTP; `/api/v1/analyze` arrives in Phase 5.
- Decoded token amounts are raw integers; decimals and symbols need chain reads (Phase 3/4).

## Phase 1: Architecture & Foundation (completed)

| Area | Files | Tested |
|---|---|---|
| Architecture, module contracts, implementation plan, risks, ambiguities | `docs/architecture.md` | n/a |
| Threat model | `docs/threat-model.md` | n/a |
| Structured errors | `pkg/txerrors` | unit |
| Data contracts and transaction validation | `pkg/models` | unit |
| Module interfaces | `pkg/interfaces` | compile-checked |
| Env config with validation and secret redaction | `internal/config` | unit |
| Chain registry | `internal/evm/chains.go` | unit |
| Logging + untrusted-string sanitizer | `internal/logging` | unit |
| Prometheus metrics | `internal/metrics` | via API tests |
| HTTP gateway (`/health`, `/livez`, `/metrics`, `/api/v1/info`, middleware) | `internal/api` | unit |
| Postgres / Redis health | `internal/storage`, `internal/cache` | manual smoke test |
| CLI `serve`, `version`, `healthcheck` | `cmd/txshield` | unit + graceful-shutdown test |
| Schema (7 tables) + migrations | `migrations/` | integration test |
| Dockerfile, Compose, Makefile, CI | root | compose validated; see below |

Phase 1 manual smoke test: `/health` returned 200 with Postgres and Redis ok; RPC keys were redacted from logs; SIGTERM shut down gracefully; a dead Postgres returned 503 on `/health` and 200 on `/livez`.

## Not verified

- **Docker image build and `docker compose up`.** The Docker daemon was not running in the development environment.
- **GitHub Actions (CI and release).** Not run yet (no remote repository; the folder is not a git repository).
- **Simulation against a real network endpoint.** All simulation tests use a local Anvil chain by design.
- **Linux performance.** Benchmarks were measured on macOS only.

## Known limitations (overall)

- Docker images and GitHub Actions have not run (no Docker daemon, no remote repository).
- SDK not published to npm.
- Local Go is 1.26.2. Build with 1.26.10+ (CI does); older patch releases have reachable stdlib CVEs.
- Detection is heuristic and not exhaustive; see `docs/threat-model.md` §4 for accepted residual risks.

## Next steps (need you)

1. Merge the pull request into `main` once CI is green on GitHub.
2. Start Docker and run `docker compose up --build` once, then tag `v0.1.0` to exercise the release workflow.
3. For npm: create the `npm` environment with required reviewers, add `NPM_TOKEN`, set `PUBLISH_NPM=true`.
