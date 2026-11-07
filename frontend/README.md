# TxShield dashboard

Next.js (App Router) + TypeScript + Tailwind CSS security dashboard for
TxShield. All data comes from the TxShield API through
[`@txshield/sdk`](../sdk/typescript). There are no mock data in production
flows. The scanner's "Example input (demo)" menu only pre-fills form fields;
the analysis is always real.

The UI is an analyst console: a dark, dense layout of panels with
uppercase header bars, built for reviewing many transactions. The header
search takes a transaction hash (opens it in the scanner), an address (opens
the address inspector), or an analysis ID.

| Page | What it shows |
|---|---|
| `/` Overview | Totals, high-risk count, risk and chain distribution, high-risk and recent analyses (needs API persistence) |
| `/scan` Scanner | Analyze from **transaction parameters**, a **transaction hash** (looked up, then replayed on its parent block), or **calldata only** (offline decode). The result is the full security report. |
| `/analyses` | History with risk filters and pagination |
| `/analyses/{id}` | Stored security report |
| `/address` | Address inspector: on-chain facts, reputation records, analyses involving the address |

The security report is a summary bar over three columns (one column on a
phone):

- **Summary bar:** score tile, band, confidence, verdict, top finding,
  from / to / value / call / chain and block, copy link and JSON download.
- **Left:** score breakdown (points per rule, with how they combine) and
  coverage (simulation, rules that ran, gas, timing, enabled checks).
- **Middle:** findings table sorted by severity, with source (fact /
  heuristic / external), confidence and points; each row expands to its
  evidence, mitigation and false-positive notes. Then recommendations,
  token permissions (with whether each is in force now) and the decoded call.
- **Right:** sender balance diff, asset transfers, and the call trace, with
  standard selectors named from a fixed table of exact selectors.

## Run

Point the dashboard at a running API:

```bash
cd ../sdk/typescript && npm ci && npm run build   # the dashboard installs the SDK as a packed copy
cd ../../frontend && npm ci
TXSHIELD_API_URL=http://localhost:8080 npm run dev
```

Production: `npm run build && npm start` (standalone server), or via Docker
Compose (`docker compose up` serves it on http://localhost:3000).

| Variable | Default | Purpose |
|---|---|---|
| `TXSHIELD_API_URL` | `http://localhost:8080` | TxShield API base URL (server-side only) |
| `TXSHIELD_API_KEY` | — | API key when the API sets `TXSHIELD_API_KEYS`. **Server-side only**: it is never sent to browsers (the smoke test asserts this). |
| `TXSHIELD_DASHBOARD_BASIC_AUTH` | — | `user:password` (password ≥ 16 characters). When set, every request needs HTTP Basic credentials, including server actions and router prefetches. A malformed value refuses all requests. Use HTTPS. |

## Security design

- **The browser only talks to the dashboard.** API calls happen in server
  components and server actions (`src/lib/txshield.ts` is `server-only`), so
  the API key and API location stay server-side and no CORS is needed.
- **Strict CSP** (`src/proxy.ts`):
  - per-request nonce plus `'strict-dynamic'` for scripts
  - nonce-only styles, so there is no `'unsafe-inline'` anywhere; charts use
    SVG attributes instead of `style`
  - `frame-ancestors 'none'`, `form-action 'self'`, `object-src 'none'`
- **Untrusted chain data** (revert strings, decoded string arguments,
  reputation reasons, token-related text):
  - rendered as text only; ESLint forbids `dangerouslySetInnerHTML`
  - passed through `visible()`, which shows bidi overrides, zero-width
    characters and control characters as `\uXXXX` so they cannot disguise
    text
- **Tokens are identified by address.** The API attaches the symbol and
  decimals the token contract reports. Any contract can claim to be "USDC",
  so the UI marks them with `*` and "unverified", and without reported
  decimals it shows raw base units rather than guessing. Amounts use exact
  `bigint` math, and the unlimited sentinels are named explicitly.
- **Server actions are endpoints.** Anyone who can reach the dashboard can run
  analyses and read history through it, with the dashboard's API key. Compose
  binds it to 127.0.0.1; before exposing it, set
  `TXSHIELD_DASHBOARD_BASIC_AUTH` or put an authenticating proxy in front.
  `src/proxy.ts` enforces Basic auth on every request; its matcher excludes
  only static build assets, never requests by header (headers are
  attacker-controlled). All API calls share the dashboard's IP, so the API's
  per-client rate limit applies to all dashboard users together.

## Accessibility

- Semantic landmarks, a skip link, and labelled forms with inline,
  `aria-describedby`-linked field errors.
- ARIA tabs with arrow-key navigation.
- Charts have an accessible name, per-bar hover/focus labels, and a table
  view.
- Status is never conveyed by color alone (labels and icons).
- `prefers-reduced-motion` is respected.
- Dark console theme only. Every text and background pair was computed
  against WCAG AA (lowest text pair 5.85:1; tags 7.1:1 or more; the chart
  bar 4.98:1 against panels).

Automated checks:

- axe-core on rendered components (`npm test`)
- axe-core on every server-rendered page (`npm run test:smoke`)

Contrast ratios were computed from the palette, because jsdom has no layout.

## Tests

```bash
npm run typecheck && npm run lint
npm test            # unit, component and accessibility tests (vitest + jsdom + axe-core)
npm run build
npm run test:smoke  # starts anvil, a real `txshield serve`, and the built dashboard; checks every page
```

`test:smoke` needs Go and Foundry (`anvil`). Set `TXSHIELD_TEST_DATABASE_URL`
to a migrated Postgres to cover the history pages too.

`.npmrc` sets:

- `install-links=true`: the SDK is installed as a copy, which Turbopack and
  Docker need
- `legacy-peer-deps=true`: works around an npm 10 resolver crash with vitest 4.1

`npm audit` reports a moderate `minimatch` ReDoS that reaches only the ESLint
toolchain (dev-only, patterns come from our own config). Production
dependencies audit clean.
