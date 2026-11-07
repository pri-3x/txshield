# Contributing to TxShield

Thanks for helping. This page covers setup, the checks CI runs, and the
conventions that keep TxShield's security claims honest.

Security vulnerabilities: please follow [SECURITY.md](SECURITY.md) instead of
opening an issue.

## Setup

- Go: the latest 1.26 patch release (older patches fail `govulncheck`).
- Foundry (Anvil, Forge) v1.8.5 for simulation and integration tests.
- Node.js ≥ 20.19 for the SDK and dashboard.
- PostgreSQL 16 for persistence tests (`docker compose up -d postgres` gives
  one on `127.0.0.1:55432`).

## Checks

Run what CI runs before opening a pull request:

```bash
make fmt-check vet lint
```

```bash
go test -race -count=1 ./...
```

```bash
make fuzz FUZZTIME=20s
```

```bash
make test-integration TEST_DATABASE_URL=postgres://txshield:txshield@localhost:55432/txshield?sslmode=disable
```

SDK (`sdk/typescript`): `npm ci && npm run typecheck && npm test && npm run build && npm run test:integration`.

Dashboard (`frontend`, after building the SDK): `npm ci && npm run typecheck && npm run lint && npm test && npm run build && npm run test:smoke`.

## Generated files

Regenerate and commit these when you change their sources; CI fails on drift.

| File | Source | Command |
|---|---|---|
| `internal/api/openapi.json` | API types in `internal/api` | `go test ./internal/api -run TestOpenAPISpec -update` |
| `sdk/typescript/src/generated/openapi.ts` | `openapi.json` | `npm run generate` (in `sdk/typescript`) |
| `tests/fixtures/scenarios/*.json` | `tests/fixtures/gen` | `make fixtures` |

## Adding or changing a security rule

1. Implement `interfaces.Rule` with complete metadata: ID, name, description,
   mitigation, and false-positive notes (the engine refuses to start without
   them).
2. Mark evidence honestly: `fact` for observed data, `heuristic` for
   inference, `external` for third-party data.
3. Add a malicious **and** a benign scenario fixture, and table tests for
   edge cases.
4. Document the rule in [docs/security-rules.md](docs/security-rules.md); a
   test checks that every registered rule is documented.

## Wording rules

These apply to code, reports, docs, and pull request descriptions:

- Never call a transaction "safe". A low score means "no significant risks
  detected by enabled checks".
- Never describe detection as exhaustive or complete.
- Never trust token symbols, names, or other on-chain metadata in logic or UI
  without labelling them as unverified.
- Do not publish benchmark or test numbers you did not measure; include the
  command and machine (see [docs/benchmarks.md](docs/benchmarks.md)).

## Hard limits

Pull requests that add any of these will not be accepted: storing private
keys, signing transactions, broadcasting transactions, or executing code
from analyzed contracts outside the Anvil sandbox.

## Releases

Maintainers: update `CHANGELOG.md` (a `## [x.y.z]` section) and the SDK
version in `sdk/typescript/package.json`, then push a `vx.y.z` tag. The
release workflow verifies both, builds binaries and images, and creates the
GitHub release. npm publishing runs only when the repository variable
`PUBLISH_NPM` is `true`, behind the `npm` environment's required reviewers.

## License

By contributing you agree that your contributions are licensed under the
Apache License 2.0.
