# Security policy

TxShield analyzes untrusted transactions and talks to RPC endpoints that
often carry API keys, so we treat vulnerabilities in it seriously.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
**[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)**
(the repository's *Security* tab, then *Report a vulnerability*). Do not open
a public issue.

Include what you can of: affected version or commit, configuration, steps or a
proof of concept, and the impact you observed. We aim to acknowledge reports
within 3 business days and to agree on a disclosure date with you; credit is
given in the advisory unless you prefer otherwise.

## Supported versions

Before 1.0, only the latest release receives security fixes.

## What counts as a vulnerability

In scope, for example:

- Memory or CPU exhaustion from a single small request (e.g. ABI decoding,
  trace parsing).
- Leaks of RPC URLs, API keys, database credentials, or stored sender data
  through responses, logs, errors, or process metadata.
- SSRF through caller-supplied RPC URLs, or any path that makes TxShield sign
  or broadcast a transaction.
- Authentication or rate-limit bypasses in the API or the dashboard.
- XSS or content spoofing in the dashboard from on-chain data.

**Missed detections are not vulnerabilities by themselves.** TxShield's
checks are heuristics and are documented as not exhaustive; a malicious
transaction that scores low is a detection gap. Please open a regular issue
for those, ideally with a reproducible transaction, so it can become a rule
and a test fixture. If a detection gap comes from a bug that silently
disables checks (for example, a rule that never runs), report it privately.

## Hardening guidance

See *Exposing TxShield beyond localhost* in the [README](README.md) and the
[threat model](docs/threat-model.md), including its accepted residual risks.
