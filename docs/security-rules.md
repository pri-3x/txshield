# Security Rules

TxShield ships 29 rules. Each has a stable ID, default severity and confidence,
mitigation, and documented false positives. Those strings live in code
(`Metadata()` of each rule) and are returned in every finding. This page is
the overview. A test (`TestRuleCatalogDocumented`) fails if a rule is missing
here.

Detection is **not exhaustive**. Rules flag patterns and evidence; they do not
prove malice, and the absence of findings does not prove safety.

Columns: **Sev/Conf** is default severity / confidence. **Needs** lists the
inputs a rule requires: `calldata` (always available), `chain` (RPC contract
facts), `rep` (reputation sources), `sim` (simulation).

## Approvals (`internal/security/approvals`)

Only grants that touch the **sender's** assets are judged (owner is the
sender, or the Safe being executed). Grants made by intermediary contracts and
revocations are listed in the report but not scored.

| ID | Name | Sev/Conf | Needs | Notes |
|---|---|---|---|---|
| TXS-APPROVAL-001 | Unlimited token allowance | medium/high | calldata | ERC-20 max, increaseAllowance max, EIP-2612, DAI `allowed`, Permit2 uint160 max. Confidence medium when ERC-20 vs ERC-721 is unresolved. |
| TXS-APPROVAL-002 | Very large token allowance | medium/medium | calldata | ≥ 2^128 base units, configurable. Low confidence if the standard is unresolved (ENS-style token IDs). |
| TXS-APPROVAL-003 | Collection-wide NFT operator approval | high/high | calldata | `setApprovalForAll(op, true)`. Marketplaces need it, and so do drainers. |
| TXS-APPROVAL-004 | Approval to an externally owned account | high/medium | chain | Spender has no code. |
| TXS-APPROVAL-005 | Approval to a flagged spender | critical/high | rep | Suspicious gives high. Operator allowlists override external opinions. |
| TXS-APPROVAL-006 | Approval to a spender with no reputation record | low/low | rep | Only when at least one source is configured. |
| TXS-APPROVAL-007 | Long-lived Permit2 allowance | low/high | calldata | Expiration more than 90 days out, configurable. |

## Interactions and reputation (`internal/security/rules/interaction.go`)

| ID | Name | Sev/Conf | Needs | Notes |
|---|---|---|---|---|
| TXS-INTERACT-001 | Interaction with a blocklisted address | critical/high | rep | Any role (target, recipient, parameter, traced call) except spender-only (APPROVAL-005 covers that). |
| TXS-INTERACT-002 | Interaction with a suspicious address | high/medium | rep | |
| TXS-INTERACT-003 | Target contract has no reputation record | low/low | rep | "Requires investigation", not malicious. Not raised for plain transfers. |
| TXS-INTERACT-004 | Unverified contract | medium/medium | chain + verification source | Silent when no verification source is configured. |
| TXS-INTERACT-005 | Function call sent to an account without code | medium/high | chain | Wrong address or wrong network. |
| TXS-INTERACT-006 | Execution reaches contracts not named in calldata | info/low | sim (trace) | Lists them. Routers legitimately call pools. |

## Value transfer (`internal/security/rules/value.go`)

These rules need a successful simulation (completeness `full` or `partial`),
and stay silent when the transaction reverts or simulation did not run.

| ID | Name | Sev/Conf | Needs | Notes |
|---|---|---|---|---|
| TXS-VALUE-001 | Unexpected asset leaves the wallet | high/medium | sim | Token not referenced anywhere in calldata (including decoded swap paths, and address-shaped arguments of undecoded calls). |
| TXS-VALUE-002 | Several different assets leave the wallet | high/medium | sim | 3 or more distinct assets. |
| TXS-VALUE-003 | Assets leave and nothing comes back | high/medium | sim | Skipped for explicit sends (transfer, safeTransferFrom, plain ETH). |
| TXS-VALUE-004 | Native currency sent to a non-payable or unrecognized function | medium/high | calldata | Low confidence for unrecognized functions. |
| TXS-VALUE-005 | Entire token balance leaves the wallet | low/high | sim | Weak alone; a draining signal in combination. |

## Dangerous patterns (`internal/security/rules/pattern.go`)

| ID | Name | Sev/Conf | Needs | Notes |
|---|---|---|---|---|
| TXS-PATTERN-001 | Delegatecall execution | high/high | calldata (+trace, chain) | Decoded delegatecalls (Safe `operation=1`, upgrade-and-call). In traces, a delegatecall into an address supplied in the calldata (arbitrary delegatecall) is high/medium; other delegatecalls to non-implementations are low/low. |
| TXS-PATTERN-002 | Off-chain signature permit used | info/high | calldata | Amounts and spenders are judged by approval rules. |
| TXS-PATTERN-003 | Batched execution | info/high | calldata | 2 or more nested calls or router commands. |
| TXS-PATTERN-004 | Ownership change | medium/high | calldata | transfer/accept/renounce. |
| TXS-PATTERN-005 | Proxy upgrade or admin change | high/high | calldata | |
| TXS-PATTERN-006 | Self-destruct during execution | medium/high | sim (trace) | |
| TXS-PATTERN-007 | Flash loan | low/medium | calldata/trace | Aave, Balancer, Uniswap V3 `flash`, ERC-3156, V2 flash swaps. |
| TXS-PATTERN-008 | Token transfer or approval hidden in forwarded calldata | high/medium | calldata | Scans `bytes` arguments and raw ABI words of unknown calls. High confidence when the embedded call moves the sender's tokens. |
| TXS-PATTERN-009 | Extra data after encoded arguments | info/high | calldata | Trailing bytes or non-canonical encoding. |
| TXS-PATTERN-010 | Re-entrant call | info/low | sim (trace) | Callbacks re-enter by design. |

## Simulation (`internal/security/rules/pattern.go`)

| ID | Name | Sev/Conf | Needs | Notes |
|---|---|---|---|---|
| TXS-SIM-001 | Transaction is expected to revert | low/high | sim | Revert reason is attacker-controlled and sanitized. Infrastructure failures are never reported as reverts. |

## Engine guarantees (`internal/security/rules/engine.go`)

- Rules run concurrently, each with a timeout (default 2 s).
- A rule that panics, errors, or times out is reported as a report warning and
  lowers assessment confidence. It never aborts the analysis.
- Findings are capped at 100 per rule.
- Rules cannot set another rule's ID on their findings.
- Metadata is validated at startup: unique IDs, and every field required.

## Writing a rule

Implement `interfaces.Rule`:

```go
type myRule struct{}

func (myRule) Metadata() models.RuleMetadata {
    return models.RuleMetadata{ID: "ORG-001", Name: "...", Description: "...",
        Category: models.CategoryInteraction, DefaultSeverity: models.SeverityMedium,
        DefaultConfidence: models.ConfidenceMedium, Mitigation: "...", FalsePositiveNotes: "..."}
}

func (r myRule) Evaluate(ctx context.Context, ac *interfaces.AnalysisContext) ([]models.Finding, error) {
    // Read ac.Decoded, ac.Approvals, ac.Simulation, ac.Contracts, ac.Reputation.
    // Use core.NewFinding(r.Metadata(), subjectKeys...) for consistent fingerprints.
    return nil, nil
}
```

Guidelines: stay silent when required inputs are missing
(`ac.ContractsKnown`, simulation completeness), label inferred findings
`SourceHeuristic`, sanitize attacker-controlled strings, and add both a true
positive and a false-positive scenario to `tests/fixtures/gen`.

## Reputation list format

```json
{
  "name": "team-blocklist",
  "entries": [
    {"chainId": 1, "address": "0x...", "status": "blocked",
     "reason": "drainer reported in incident #12", "labels": ["drainer"], "confidence": "high"}
  ]
}
```

- `status`: `allowed`, `suspicious`, or `blocked`.
- `chainId` 0 or omitted means every chain.
- `confidence` defaults to high.
- Addresses must be valid, and mixed-case addresses must carry a correct
  EIP-55 checksum. **A list with any invalid entry is rejected entirely**,
  because a silently skipped blocklist entry is a security bug.

Resolution when sources disagree:
1. An operator `blocked` wins.
2. Otherwise an operator `allowed` wins over external opinions.
3. Otherwise the most severe status wins.

Overridden records still appear as evidence.
