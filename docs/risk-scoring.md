# Risk Scoring Methodology

TxShield turns findings into a 0-100 score with a category and a confidence
level. The method is deterministic, configurable, and auditable: every report
lists each finding's contribution to the score.

> A score is a summary of what the **enabled checks observed**. A low score
> never means a transaction is safe. The best verdict TxShield gives is
> *"No significant risks detected by enabled checks."*

Implementation: [`internal/security/scoring`](../internal/security/scoring/scoring.go).

## 1. Categories

| Score | Category | Meaning |
|---|---|---|
| 0-19 | `low` | Low observed risk |
| 20-39 | `moderate` | Moderate observed risk |
| 40-59 | `elevated` | Elevated risk |
| 60-79 | `high` | High risk |
| 80-100 | `critical` | Critical risk |

## 2. Steps

### 2.1 Deduplication

Every finding carries a **fingerprint**: the rule ID plus the subjects that
make it distinct (for approvals, `token|spender`). Findings with the same
fingerprint are merged; the most severe, then most confident, copy is kept.
The same issue reported twice (e.g. the same approval nested in two places)
therefore counts once.

### 2.2 Points per finding

```
points = severityPoints[severity] x confidenceWeight[confidence] x sourceWeight[source]
```

| Severity | Points | | Confidence | Weight | | Source | Weight |
|---|---|---|---|---|---|---|---|
| info | 0 | | low | 0.50 | | fact | 1.00 |
| low | 8 | | medium | 0.75 | | heuristic | 0.90 |
| medium | 22 | | high | 1.00 | | external | 0.85 |
| high | 45 | | | | | | |
| critical | 85 | | | | | | |

`source` distinguishes **facts** (observed in calldata, chain state, or
simulation, including "the operator's list flags this address"),
**heuristics** (inferred patterns), and **external** reputation (third-party
opinion). Informational findings are shown but never move the score.

### 2.3 Repeat decay (same rule, different subjects)

Within one rule, findings are sorted by points and the k-th is multiplied by
`repeatDecay^(k-1)` (default 0.5). Ten unlimited approvals are worse than
one, but not ten times worse.

### 2.4 Combination

Contributions combine like independent probabilities instead of a plain sum:

```
combined = 100 x (1 - product(1 - points_i / 100))
```

The result is bounded by 100 and has diminishing returns: two independent
medium findings (22 each) give 39, not 44.

### 2.5 Floors

A single well-supported serious finding must determine the category, even if
nothing else fired:

| Finding (confidence **high**) | Minimum score |
|---|---|
| critical | 80 (critical band) |
| high | 60 (high band) |

When the finding's source is `external`, the floor of the next lower severity
applies (a third-party blocklist alone cannot force "critical"). A floor that
raises the score appears as its own contribution (`fingerprint: "floor"`) with
the reason.

### 2.6 Assessment confidence

Separate from the score, `confidence` states how complete the analysis was:

| Condition | Penalty |
|---|---|
| no simulation, or simulation completeness `none` | 2 |
| simulation completeness `partial` | 1 |
| each rule that failed or timed out (max 2) | 1 |

Penalty 0 gives `high`, 1-2 gives `medium`, and 3 or more gives `low`. No
enabled checks always gives `low`. Offline analysis (no RPC, no simulation) is
therefore at most `medium`.

## 3. Worked examples (from the scenario fixtures)

| Scenario | Findings | Score |
|---|---|---|
| ERC-20 transfer | none | 0, *No significant risks detected by enabled checks* |
| Unlimited approval to an allowlisted router | APPROVAL-001 medium/high/fact = 22 | 22 moderate |
| Unlimited approval to a blocklisted spender | APPROVAL-005 critical/high/fact (85), APPROVAL-001 (22), INTERACT-003 low/low/heuristic (3.6) | 89 critical |
| Fake `claim()` drainer (simulated) | VALUE-001 x3, -002, -003 (high/medium/fact, 33.75 each before decay), VALUE-004, VALUE-005 | 82 critical |
| `setApprovalForAll` to an account without code | APPROVAL-003 high/high/fact (45, floor 60), APPROVAL-004 high/medium/fact (33.75) | 64 high |
| Reverting swap | SIM-001 low/high/fact = 8 | 8 low |

All 19 scenarios and their expected ranges live in
[`tests/fixtures/scenarios`](../tests/fixtures/scenarios) and run in CI.

## 4. Configuration

Weights can be overridden with a JSON file (`txshield analyze --scoring-config file.json`).
Omitted keys keep their defaults. The file is validated: points in [0,100] and
non-decreasing with severity, weights in [0,1], decay in (0,1].

```json
{
  "severityPoints": {"medium": 25},
  "repeatDecay": 0.4,
  "floors": {"high": 60, "critical": 85}
}
```

## 5. Known limitations

- Scores depend on which checks ran. Offline reports cannot see asset
  movements, and confidence is lowered accordingly.
- Weights are expert-chosen defaults, not fitted to labelled data. They are
  pinned by the scenario fixtures so changes are deliberate and reviewed.
- Correlated findings from different rules (e.g. a spender that is both an EOA
  and unknown) are combined as if independent, which slightly overstates them.
  Rules avoid the most direct overlaps (e.g. a blocklisted spender is reported
  by APPROVAL-005 only, not also by INTERACT-001).
