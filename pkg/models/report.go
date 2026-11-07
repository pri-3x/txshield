package models

import "time"

// CallKind classifies the top-level shape of a transaction.
type CallKind string

const (
	CallNativeTransfer   CallKind = "native_transfer"
	CallContract         CallKind = "contract_call"
	CallContractCreation CallKind = "contract_creation"
	CallUnknown          CallKind = "unknown" // selector not recognized
)

// DecodeSource records where the ABI used for decoding came from.
type DecodeSource string

const (
	DecodeBuiltin   DecodeSource = "builtin"  // TxShield's bundled ABIs
	DecodeUserABI   DecodeSource = "user_abi" // ABI supplied with the request
	DecodeSignature DecodeSource = "signature_db"
	DecodeNone      DecodeSource = "none"
)

// DecodedParam is one decoded function argument. Value holds a
// JSON-serializable representation (addresses as checksummed hex, integers
// as decimal strings, bytes as 0x hex, tuples/arrays as nested values).
type DecodedParam struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value any    `json:"value"`
}

// CallType describes how a (possibly nested) call is executed.
type CallType string

const (
	CallTypeCall          CallType = "call"
	CallTypeDelegateCall  CallType = "delegatecall"   // runs in the caller's storage context
	CallTypeSelf          CallType = "self"           // multicall to the same contract (often delegatecall to self)
	CallTypeRouterCommand CallType = "router_command" // Universal Router internal command, not an EVM call
	CallTypeCreate        CallType = "create"
)

// DecodedCall is the decoded form of a call. Recognizing a selector says
// nothing about whether the call is safe.
type DecodedCall struct {
	Kind       CallKind       `json:"kind"`
	CallType   CallType       `json:"callType"`
	Label      string         `json:"label,omitempty"` // position within a parent, e.g. "aggregate3 call 2"
	Target     string         `json:"target,omitempty"`
	Value      Quantity       `json:"value,omitempty"` // native value sent with this call, when known
	Selector   string         `json:"selector,omitempty"`
	Method     string         `json:"method,omitempty"`
	Signature  string         `json:"signature,omitempty"`
	Standard   string         `json:"standard,omitempty"` // e.g. "erc20", "uniswap-v2-router"
	Params     []DecodedParam `json:"params,omitempty"`
	Source     DecodeSource   `json:"source"`
	Candidates []string       `json:"candidates,omitempty"` // other signatures sharing the selector
	RawData    string         `json:"rawData,omitempty"`    // set when decoding was not possible
	Children   []DecodedCall  `json:"children,omitempty"`   // multicall / router sub-calls
	Warnings   []string       `json:"warnings,omitempty"`
}

// RiskCategory is the human-facing band for a risk score.
type RiskCategory string

const (
	RiskLow      RiskCategory = "low"      // 0-19
	RiskModerate RiskCategory = "moderate" // 20-39
	RiskElevated RiskCategory = "elevated" // 40-59
	RiskHigh     RiskCategory = "high"     // 60-79
	RiskCritical RiskCategory = "critical" // 80-100
)

// CategoryForScore maps a 0-100 score to its band. Out-of-range scores are
// clamped.
func CategoryForScore(score int) RiskCategory {
	switch {
	case score >= 80:
		return RiskCritical
	case score >= 60:
		return RiskHigh
	case score >= 40:
		return RiskElevated
	case score >= 20:
		return RiskModerate
	default:
		return RiskLow
	}
}

// ScoreContribution explains how one deduplicated finding or signal affected
// the score, so the scoring is auditable by users.
type ScoreContribution struct {
	Fingerprint string  `json:"fingerprint"`
	RuleID      string  `json:"ruleId,omitempty"`
	Points      float64 `json:"points"`
	Reason      string  `json:"reason"`
}

// RiskAssessment is the scorer's output.
type RiskAssessment struct {
	Score         int                 `json:"score"`
	Category      RiskCategory        `json:"category"`
	Confidence    Confidence          `json:"confidence"`
	Contributions []ScoreContribution `json:"contributions"`
}

// TransactionSummary is a short human-oriented description of the transaction.
type TransactionSummary struct {
	ChainID     uint64   `json:"chainId"`
	ChainName   string   `json:"chainName,omitempty"`
	From        string   `json:"from"`
	To          string   `json:"to,omitempty"`
	Value       Quantity `json:"value"`
	Kind        CallKind `json:"kind"`
	Method      string   `json:"method,omitempty"`
	Description string   `json:"description"`
	Block       string   `json:"block"`
}

// Disclaimer is attached to every report.
const Disclaimer = "TxShield reports what its enabled checks observed. Simulation and " +
	"static analysis cannot guarantee that a transaction is safe; on-chain state can " +
	"change before inclusion and malicious contracts can behave differently outside simulation."

// NoSignificantRisks is the strongest positive verdict TxShield ever issues.
const NoSignificantRisks = "No significant risks detected by enabled checks."

// RiskReport is the full analysis output.
type RiskReport struct {
	ID              string             `json:"id"`
	RequestID       string             `json:"requestId,omitempty"`
	EngineVersion   string             `json:"engineVersion"`
	AnalyzedAt      time.Time          `json:"analyzedAt"`
	Transaction     TransactionSummary `json:"transaction"`
	Decoded         *DecodedCall       `json:"decoded,omitempty"`
	Risk            RiskAssessment     `json:"risk"`
	Verdict         string             `json:"verdict"`
	Findings        []Finding          `json:"findings"`
	Approvals       []ApprovalGrant    `json:"approvals"`
	Simulation      *SimulationResult  `json:"simulation,omitempty"`
	BalanceChanges  []BalanceChange    `json:"balanceChanges,omitempty"`
	Recommendations []string           `json:"recommendations"`
	EnabledChecks   []string           `json:"enabledChecks"`
	Warnings        []string           `json:"warnings,omitempty"` // engine-level issues, e.g. a rule failed
	Disclaimer      string             `json:"disclaimer"`
}

// AnalysisSummary is a compact view of a stored analysis for listings.
type AnalysisSummary struct {
	ID           string       `json:"id"`
	AnalyzedAt   time.Time    `json:"analyzedAt"`
	ChainID      uint64       `json:"chainId"`
	From         string       `json:"from,omitempty"` // empty when sender storage is disabled
	To           string       `json:"to,omitempty"`
	Kind         CallKind     `json:"kind"`
	Method       string       `json:"method,omitempty"`
	Score        int          `json:"score"`
	Category     RiskCategory `json:"category"`
	Confidence   Confidence   `json:"confidence"`
	FindingCount int          `json:"findingCount"`
	Completeness Completeness `json:"simulationCompleteness"`
}
