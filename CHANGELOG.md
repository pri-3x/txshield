# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0, minor versions may
contain breaking changes to the API, CLI, and SDK; they are listed under
**Changed**.

The release workflow publishes the section whose heading matches the tag
(`## [0.1.0]` for `v0.1.0`), so keep that heading format.

## [0.1.0] - Unreleased

First public release.

### Added

- **Decoder**: offline calldata decoding for ERC-20/721/1155, Permit and
  Permit2, Uniswap V2/V3 and Universal Router, Multicall/Multicall3, Safe,
  proxy upgrades, flash loans, nested calls, and user-supplied ABIs; trailing
  data and non-canonical encoding warnings.
- **Security engine**: 29 rules across approvals, interactions, value transfer,
  dangerous patterns, and simulation results, with panic and timeout
  isolation; reputation from JSON lists and Postgres with an operator-first
  resolution policy; 0-100 risk scoring with confidence, deduplication, and
  per-finding contributions. Reports never call a transaction "safe".
- **Simulation**: Anvil fork worker pool (per-job re-fork, impersonation, call
  traces, events, balance diffs) and an `rpc-trace` fallback.
- **RPC client**: read-only method allowlist, retries with jitter, circuit
  breaker, response size caps, URL redaction; SSRF guard for opt-in
  caller-supplied endpoints.
- **REST API** with OpenAPI 3.1: analyze, simulate, approvals, decode,
  transaction lookup, address inspector, history, stats, health, metrics.
  Optional API keys, per-client rate limiting, CORS allowlist.
- **Persistence** (optional) with privacy defaults: sender and calldata are
  not stored unless enabled; retention purge.
- **CLI** `txshield`: `serve`, `analyze`, `simulate`, `approval-check`,
  `decode`, `healthcheck`.
- **TypeScript SDK** `@txshield/sdk`: types generated from OpenAPI,
  client-side validation, timeouts, retries, ESM and CommonJS builds.
- **Dashboard** (Next.js): an analyst console with overview, scanner,
  security report (summary bar, score breakdown, findings table with
  evidence, balance diff, asset transfers, call trace), history and address
  inspector; header search by tx hash, address or analysis ID; strict nonce
  CSP; optional HTTP Basic auth.
- **Token display metadata**: simulated token assets carry the symbol and
  decimals their contracts report (sanitized, at most 16 tokens per report),
  labelled unverified and never used by the security rules.
- **Deployment**: Docker images (API with pinned, checksum-verified Anvil;
  distroless dashboard), Docker Compose stack, CI, and a release workflow
  that publishes binaries with checksums and provenance, and multi-arch
  images with SBOM and provenance.
- **Docs**: architecture, threat model, decoder, simulation, rules, scoring,
  API, and [benchmarks with methodology](docs/benchmarks.md).

### Security

Fixed before release, from an independent review (details in the
[threat model](docs/threat-model.md), T17-T28):

- ABI decoding could be made to allocate gigabytes from a few KiB of calldata
  (aliased array offsets). Decoding now has an element budget.
- RPC endpoint URLs, which usually carry API keys, could reach server logs on
  timeouts and cancellations. All error paths are now redacted.
- The dashboard let anyone who could reach it use its API key. It now
  supports HTTP Basic auth on every request, including server actions.
- Anvil no longer receives the provider URL in its process arguments (fork
  relay), picks its own port, runs with CORS disabled, and crashed workers
  are restarted rather than reused.
- Health checks are cached so unauthenticated probes cannot drive upstream
  RPC calls; approvals requests read at most 20 current allowances; caller gas
  is capped; rate limiting runs before authentication and groups IPv6 by /64.
- Analyses built from caller-supplied RPC endpoints are not stored; stored
  calldata hashes are keyed when calldata storage is off; more non-routable
  IPv6 ranges are rejected by the SSRF guard.
- The server listens on 127.0.0.1 by default.

### Fixed

- The "assets leave and nothing comes back" finding listed the ETH sent with
  the call twice (once as the call's value, once as the simulated transfer).

[0.1.0]: https://github.com/pri-3x/txshield/releases/tag/v0.1.0
