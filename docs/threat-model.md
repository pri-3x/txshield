# TxShield Threat Model

Status: **initial (Phase 1)**. Revisited in Phase 8 against the implemented code.
Mitigations marked *(planned)* are not implemented yet.

## 1. Assets

| Asset | Why it matters |
|---|---|
| Integrity of the risk report | Users decide whether to sign based on it. A manipulated "low risk" report is the primary harm. |
| Operator RPC credentials (API keys embedded in RPC URLs) | Cost and quota abuse; provider account takeover. |
| Server host and internal network | SSRF or simulation escape could reach internal services. |
| Stored analyses | Can link wallet addresses to activity (privacy). |
| Availability | Wallet integrations may block signing on TxShield responses. |

TxShield holds **no private keys** and has no signing or broadcasting code paths, so
"steal funds directly" is out of scope by construction.

## 2. Trust boundaries

```
 [Untrusted]                     [TxShield process]                 [Semi-trusted]
 API client / SDK / browser ──▶ API gateway ──▶ engine ──▶ Anvil fork ──▶ Upstream RPC
 Analyzed calldata & contracts                     │
 Token metadata, contract names                    └──▶ External reputation providers
 User-supplied RPC URL (if enabled)                         [Trusted]: operator config,
                                                            PostgreSQL, Redis
```

- **Everything in a request is untrusted**, including the contract code it targets.
- **On-chain data is attacker-controlled** wherever an attacker can deploy code:
  token symbols, names, decimals, revert strings, event data, and execution
  behavior under simulation.
- **Upstream RPC is semi-trusted**: assumed honest about chain state but may be
  unavailable, rate-limited, or lack debug APIs.
- **External reputation data is opinion**, never fact; always labeled
  `source: external`.

## 3. Threats and mitigations

| # | Threat | Mitigation | Status |
|---|---|---|---|
| T1 | Oversized bodies / calldata exhaust memory | `http.MaxBytesReader` body limit; calldata size limit in validation | Done (body limit, calldata limit, decoder depth/call budgets) |
| T2 | Slowloris / long requests | `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, per-request context timeout | Done |
| T3 | SSRF via user-controlled RPC URL | Disabled by default; guard resolves DNS and rejects private/loopback/link-local/metadata ranges, re-checks on redirect and on each dial Also rejects IPv4-compatible `::/96`, SIIT, local-use NAT64, ORCHID, benchmarking, and RFC 9637 documentation ranges | Done: `internal/netguard` (https only, public IPs at DNS and connect time, no redirects); Anvil never forks user URLs |
| T4 | RPC quota abuse by API clients | Per-client rate limiting; simulation concurrency cap; caching of immutable reads | Done: per-IP token bucket, Anvil worker pool bounds concurrent simulations, optional API keys |
| T5 | Contract evades detection by detecting simulation (coinbase, timestamp, gasleft, impersonation) | Pin and report the simulated block; static rules (approvals, embedded transfers, reputation) work without simulation; never present simulation as proof; simulation notes list environment differences (zero fees, block time) | Mitigated, not solvable: documented residual risk |
| T6 | Gas bombs / giant traces in simulation | Gas cap (block limit or 30M), response size cap (64 MiB), trace frame cap (5,000) and per-frame I/O cap, log cap (2,000), per-simulation timeout with worker kill, container memory limit | Done |
| T7 | Social engineering via token metadata ("USDC" fake token) | Identify tokens by `(chainId, address)`; rules never read symbol, name, or decimals; the symbol a contract reports is kept to letters, digits, currency signs and `.-_+` (no spaces, control, bidi, or zero-width characters), at most 16 characters; the dashboard shows it with `*` "unverified" next to the token address, and shows raw base units when no decimals are reported | Done. A spoofed symbol still displays (marked unverified); users must check the address |
| T8 | Log injection (newlines, ANSI escapes in user input) | Structured JSON logging; `logging.Sanitize` truncates and escapes control characters | Done |
| T9 | Report tampering in transit | TLS termination is the deployer's responsibility; documented in deployment docs | Docs (Phase 8) |
| T10 | Privacy: linking sender addresses to analyses | Persistence optional; sender storage opt-in; retention via `expires_at` | Done: sender and calldata not stored by default (redacted from stored JSON too); hourly retention purge |
| T11 | Untrusted script execution (e.g. Slither on hostile source) | Slither optional, subprocess with timeout, never on fetched-and-trusted input, never with network | Planned (Phase 3, optional) |
| T12 | Accidental broadcast | Upstream clients use a read-only method allowlist enforced before network I/O; sending is only possible through `DialLocal` (loopback IPs, TxShield's own Anvil); Anvil binds 127.0.0.1 on random ports; tests assert denied methods never reach the network and that simulations leave the real chain unchanged | Done |
| T13 | Dependency compromise | Minimal dependencies; `go.sum` pinned; CI runs `govulncheck` | govulncheck in CI: done |
| T14 | Panics from malformed input crash the server | Recovery middleware returns structured 500; fuzz tests for decoder | Done: recovery middleware; decoder recovers ABI-library panics; decoder fuzzed (2 targets, CI smoke run) |
| T17 | RPC API keys leaked via errors, logs, or responses | URLs redacted in every client error path (connection, timeout, cancellation, HTTP status, malformed response; tested per path) before errors are logged; config errors and logs redacted; never returned by the API. Anvil never sees the provider URL: it forks through a loopback relay (`/fork/<random token>`), so the key is not in process arguments | Done (security review: timeout/cancel errors leaked the URL into 5xx logs, fixed) |
| T18 | Redirect- or proxy-based SSRF from a trusted endpoint | RPC client refuses redirects and ignores environment proxy settings | Done |
| T19 | Unauthenticated access to an expensive API (simulation load, history disclosure) | Optional API keys (SHA-256 digests, constant-time compare); server listens on 127.0.0.1 by default and Compose binds to 127.0.0.1; rate limiting runs before authentication; `/health` results cached for 5 s so probes cannot drive upstream RPC calls; approvals endpoint reads current allowance for at most 20 approvals per request; history needs persistence explicitly enabled | Done; operators must enable keys or an auth proxy when exposing the API |
| T20 | Client IP spoofing or address rotation to evade rate limits | `X-Forwarded-For` ignored unless `TXSHIELD_TRUST_PROXY_HEADERS`; then only the last (proxy-appended) hop is used; IPv6 clients keyed by /64; key table bounded, and when full an arbitrary entry is evicted (no shared overflow bucket a flood could drain) | Done. A client with many /64s (e.g. a /48) still gets many buckets; put a global limit in the reverse proxy |
| T21 | XSS or text spoofing via attacker-controlled chain strings rendered in the dashboard | React text rendering only (`react/no-danger` lint error); `visible()` exposes bidi/zero-width/control characters; strict nonce CSP with no `unsafe-inline`; tests assert injected markup stays inert | Done |
| T22 | API key exposure through the dashboard | API calls only in server components and server actions (`server-only` module); smoke test asserts the key never appears in served pages. The dashboard acts with its API key for anyone who can reach it, so it supports HTTP Basic auth (`TXSHIELD_DASHBOARD_BASIC_AUTH`) enforced in `proxy.ts` for every request, including server actions and prefetches (smoke-tested) | Done. Without Basic auth or an auth proxy, expose the dashboard only on localhost |
| T23 | ABI decoding allocation bomb: aliased offsets make a few KiB of calldata decode into billions of values (go-ethereum follows offsets without bounds; the request timeout cannot stop it) | Before decoding, `checkElementBudget` walks the head/offset layout without allocating and refuses inputs that would create more than `2 × (len/32) + 256` values; applies to built-in and user ABIs; fuzz-tested property: accepted inputs never exceed the budget | Done (found in security review; 29 KB previously allocated 2.6 GB) |
| T24 | Caller-supplied RPC results poisoning shared history | Reports built from a caller-supplied endpoint are never stored (warning added); user RPC responses capped at 8 MiB | Done |
| T25 | Linking stored analyses to on-chain transactions | Without `STORE_CALLDATA`, `calldata_hash` is an HMAC under a random per-process key instead of keccak256 | Done. `to`, `value`, selector, block, and time can still narrow down a public transaction for rare contracts |
| T26 | Anvil worker port takeover or crash | Anvil picks its own port (`--port 0`) and TxShield reads the bound address from its output (no check-then-use race); a worker whose process exited is restarted instead of re-forking whatever listens on its old port; `--no-cors` stops browser pages from reading Anvil responses | Done (integration-tested) |
| T27 | Fork relay misuse by a local user who learns the token | Relay listens on 127.0.0.1 only, token is 128 random bits per upstream, refuses send/sign/admin/anvil/debug_set methods, never echoes upstream errors | Done. A local user with the token can spend RPC quota on reads while TxShield runs |
| T28 | Unbounded caller gas sent upstream | `gas` limited to 1,000,000,000 at validation | Done |
| T15 | Poisoned reputation data (attacker gets a malicious contract allowlisted, or a list file is malformed) | Operator allowlists override only *external* opinions, never an operator blocklist; list files with any invalid entry are rejected entirely; every record shows its source | Done |
| T16 | Pathological input exhausts the rule engine | Per-rule timeout, panic isolation, 100 findings per rule, address cap per analysis (64), decoder budgets | Done |

## 4. Residual risks (accepted, documented to users)

- `/metrics` is unauthenticated on the API listener (like `/health`); do not
  route it through a public proxy.
- Simulation load is limited by the per-client rate limit and the worker
  queue timeout, not by a separate simulation quota; callers may choose
  historical blocks, which needs an archive-capable upstream and costs more.
- `Registry.Reader` verifies a chain's endpoint with a background context
  (bounded to 10 s) because the `ChainRegistry` interface has no context.

- Simulation is computed against a specific block; state can change before inclusion.
- Detection is rule-based and not exhaustive. A low score is "no significant risks
  detected by enabled checks", never "safe".
- Reputation data can be stale or wrong in both directions.
