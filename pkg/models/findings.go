package models

import (
	"encoding/json"
	"fmt"
)

// Severity is the potential impact of a finding if it reflects real malicious
// behavior. It is ordered: comparisons like s >= SeverityHigh are valid.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// ParseSeverity parses a severity name.
func ParseSeverity(v string) (Severity, error) {
	for i, n := range severityNames {
		if n == v {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q", v)
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	p, err := ParseSeverity(v)
	if err != nil {
		return err
	}
	*s = p
	return nil
}

// Confidence is how likely a finding reflects real behavior rather than a
// false positive. Ordered like Severity.
type Confidence int

const (
	ConfidenceLow Confidence = iota
	ConfidenceMedium
	ConfidenceHigh
)

var confidenceNames = [...]string{"low", "medium", "high"}

func (c Confidence) String() string {
	if c < 0 || int(c) >= len(confidenceNames) {
		return fmt.Sprintf("confidence(%d)", int(c))
	}
	return confidenceNames[c]
}

// ParseConfidence parses a confidence name.
func ParseConfidence(v string) (Confidence, error) {
	for i, n := range confidenceNames {
		if n == v {
			return Confidence(i), nil
		}
	}
	return 0, fmt.Errorf("unknown confidence %q", v)
}

func (c Confidence) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

func (c *Confidence) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	p, err := ParseConfidence(v)
	if err != nil {
		return err
	}
	*c = p
	return nil
}

// EvidenceSource distinguishes what TxShield observed from what it inferred
// or was told by a third party. Reports must always surface this.
type EvidenceSource string

const (
	// SourceFact: directly observed from calldata, chain state, or simulation.
	SourceFact EvidenceSource = "fact"
	// SourceHeuristic: inferred from patterns; may be wrong.
	SourceHeuristic EvidenceSource = "heuristic"
	// SourceExternal: reported by an external reputation provider or list.
	SourceExternal EvidenceSource = "external"
)

// Category groups related rules.
type Category string

const (
	CategoryApproval         Category = "approval"
	CategoryInteraction      Category = "interaction"
	CategoryValueTransfer    Category = "value_transfer"
	CategoryDangerousPattern Category = "dangerous_pattern"
	CategoryReputation       Category = "reputation"
	CategorySimulation       Category = "simulation"
)

// RuleMetadata describes a security rule. Every rule must provide all fields.
type RuleMetadata struct {
	ID                 string     `json:"id"` // stable, e.g. "TXS-APPROVAL-001"
	Name               string     `json:"name"`
	Description        string     `json:"description"`
	Category           Category   `json:"category"`
	DefaultSeverity    Severity   `json:"defaultSeverity"`
	DefaultConfidence  Confidence `json:"defaultConfidence"`
	Mitigation         string     `json:"mitigation"`
	FalsePositiveNotes string     `json:"falsePositiveNotes"`
	References         []string   `json:"references,omitempty"`
}

// Evidence is one observation supporting a finding.
type Evidence struct {
	Type   string            `json:"type"` // e.g. "calldata_param", "simulation_log", "reputation_record"
	Detail string            `json:"detail"`
	Source EvidenceSource    `json:"source"`
	Data   map[string]string `json:"data,omitempty"`
}

// Finding is a single security observation produced by a rule.
type Finding struct {
	RuleID             string         `json:"ruleId"`
	Title              string         `json:"title"`
	Description        string         `json:"description"`
	Category           Category       `json:"category"`
	Severity           Severity       `json:"severity"`
	Confidence         Confidence     `json:"confidence"`
	Source             EvidenceSource `json:"source"`
	Evidence           []Evidence     `json:"evidence,omitempty"`
	Subjects           []string       `json:"subjects,omitempty"` // addresses involved, checksummed hex
	Mitigation         string         `json:"mitigation"`
	FalsePositiveNotes string         `json:"falsePositiveNotes,omitempty"`
	// Fingerprint identifies "the same issue" for deduplication. Rules set it
	// from RuleID plus the subject(s) that make the finding distinct (e.g.
	// token+spender for approvals). The scorer counts each fingerprint once.
	Fingerprint string `json:"fingerprint"`
}
