// Package scoring converts findings into a transparent 0-100 risk score.
// The methodology is documented in docs/risk-scoring.md; every score comes
// with per-finding contributions so users can audit it.
package scoring

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"

	"github.com/txshield/txshield/pkg/interfaces"
	"github.com/txshield/txshield/pkg/models"
)

// Config holds the scoring weights. All fields are required after
// Normalize; LoadConfig fills omitted fields with defaults.
type Config struct {
	// SeverityPoints: base points (0-100) per severity name.
	SeverityPoints map[string]float64 `json:"severityPoints"`
	// ConfidenceWeight: multiplier (0-1) per confidence name.
	ConfidenceWeight map[string]float64 `json:"confidenceWeight"`
	// SourceWeight: multiplier (0-1) per evidence source (fact, heuristic, external).
	SourceWeight map[string]float64 `json:"sourceWeight"`
	// RepeatDecay: the k-th distinct finding of the same rule is weighted
	// RepeatDecay^(k-1), so ten approvals do not count ten times.
	RepeatDecay float64 `json:"repeatDecay"`
	// Floors: minimum score imposed by a single high-confidence finding of
	// the given severity (non-external sources). External-source findings
	// impose the floor of the next lower severity.
	Floors map[string]float64 `json:"floors"`
}

// DefaultConfig returns the documented default weights.
func DefaultConfig() Config {
	return Config{
		SeverityPoints:   map[string]float64{"info": 0, "low": 8, "medium": 22, "high": 45, "critical": 85},
		ConfidenceWeight: map[string]float64{"low": 0.5, "medium": 0.75, "high": 1},
		SourceWeight:     map[string]float64{"fact": 1, "heuristic": 0.9, "external": 0.85},
		RepeatDecay:      0.5,
		Floors:           map[string]float64{"high": 60, "critical": 80},
	}
}

// Validate checks ranges and monotonicity.
func (c Config) Validate() error {
	var errs []string
	prev := -1.0
	for _, s := range []string{"info", "low", "medium", "high", "critical"} {
		v, ok := c.SeverityPoints[s]
		if !ok || v < 0 || v > 100 {
			errs = append(errs, fmt.Sprintf("severityPoints.%s must be in [0,100]", s))
		} else if v < prev {
			errs = append(errs, "severityPoints must not decrease with severity")
		}
		prev = v
	}
	for _, s := range []string{"low", "medium", "high"} {
		if v, ok := c.ConfidenceWeight[s]; !ok || v < 0 || v > 1 {
			errs = append(errs, fmt.Sprintf("confidenceWeight.%s must be in [0,1]", s))
		}
	}
	for _, s := range []string{"fact", "heuristic", "external"} {
		if v, ok := c.SourceWeight[s]; !ok || v < 0 || v > 1 {
			errs = append(errs, fmt.Sprintf("sourceWeight.%s must be in [0,1]", s))
		}
	}
	if c.RepeatDecay <= 0 || c.RepeatDecay > 1 {
		errs = append(errs, "repeatDecay must be in (0,1]")
	}
	for k, v := range c.Floors {
		if _, err := models.ParseSeverity(k); err != nil || v < 0 || v > 100 {
			errs = append(errs, fmt.Sprintf("floors.%s invalid", k))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("scoring config: %s", strings.Join(errs, "; "))
	}
	return nil
}

// LoadConfig reads a JSON config; omitted keys keep their defaults.
func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied config path, not request input
	if err != nil {
		return Config{}, err
	}
	defer func() { _ = f.Close() }()
	return ParseConfig(f)
}

// ParseConfig parses a JSON config over the defaults.
func ParseConfig(r io.Reader) (Config, error) {
	var override Config
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&override); err != nil {
		return Config{}, fmt.Errorf("scoring config: %w", err)
	}
	c := DefaultConfig()
	merge := func(dst, src map[string]float64) {
		for k, v := range src {
			dst[k] = v
		}
	}
	merge(c.SeverityPoints, override.SeverityPoints)
	merge(c.ConfidenceWeight, override.ConfidenceWeight)
	merge(c.SourceWeight, override.SourceWeight)
	if override.Floors != nil {
		c.Floors = override.Floors
	}
	if override.RepeatDecay != 0 {
		c.RepeatDecay = override.RepeatDecay
	}
	return c, c.Validate()
}

// Scorer implements interfaces.RiskScorer.
type Scorer struct{ cfg Config }

var _ interfaces.RiskScorer = (*Scorer)(nil)

// New returns a scorer; cfg must be valid.
func New(cfg Config) (*Scorer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Scorer{cfg: cfg}, nil
}

// Deduplicate keeps one finding per fingerprint (the most severe, then most
// confident) and returns them sorted by severity, confidence, rule ID.
func Deduplicate(findings []models.Finding) []models.Finding {
	best := map[string]models.Finding{}
	order := []string{}
	for _, f := range findings {
		fp := f.Fingerprint
		if fp == "" {
			fp = f.RuleID
		}
		cur, ok := best[fp]
		if !ok {
			order = append(order, fp)
			best[fp] = f
			continue
		}
		if f.Severity > cur.Severity || (f.Severity == cur.Severity && f.Confidence > cur.Confidence) {
			best[fp] = f
		}
	}
	out := make([]models.Finding, 0, len(order))
	for _, fp := range order {
		out = append(out, best[fp])
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		return a.RuleID < b.RuleID
	})
	return out
}

// Score computes the assessment. It is deterministic for a given input.
func (s *Scorer) Score(in interfaces.ScoringInput) models.RiskAssessment {
	findings := Deduplicate(in.Findings)
	type scored struct {
		f      models.Finding
		points float64
		reason string
	}
	byRule := map[string][]scored{}
	var ruleOrder []string
	for _, f := range findings {
		base := s.cfg.SeverityPoints[f.Severity.String()]
		w := s.cfg.ConfidenceWeight[f.Confidence.String()] * s.cfg.SourceWeight[string(f.Source)]
		if _, ok := byRule[f.RuleID]; !ok {
			ruleOrder = append(ruleOrder, f.RuleID)
		}
		byRule[f.RuleID] = append(byRule[f.RuleID], scored{f: f, points: base * w,
			reason: fmt.Sprintf("%s severity (%.0f) x %s confidence (%.2f) x %s source (%.2f)",
				f.Severity, base, f.Confidence, s.cfg.ConfidenceWeight[f.Confidence.String()], f.Source, s.cfg.SourceWeight[string(f.Source)])})
	}

	var contributions []models.ScoreContribution
	survive := 1.0 // probability-style combination: 1 - prod(1 - p)
	for _, rule := range ruleOrder {
		group := byRule[rule]
		sort.SliceStable(group, func(i, j int) bool { return group[i].points > group[j].points })
		for k, sc := range group {
			pts := sc.points * math.Pow(s.cfg.RepeatDecay, float64(k))
			reason := sc.reason
			if k > 0 {
				reason += fmt.Sprintf(" x repeat decay %.3f (finding %d of this rule)", math.Pow(s.cfg.RepeatDecay, float64(k)), k+1)
			}
			p := math.Min(math.Max(pts/100, 0), 1)
			survive *= 1 - p
			contributions = append(contributions, models.ScoreContribution{Fingerprint: sc.f.Fingerprint, RuleID: rule, Points: round2(pts), Reason: reason})
		}
	}
	combined := 100 * (1 - survive)

	floor := 0.0
	floorReason := ""
	for _, f := range findings {
		if f.Confidence != models.ConfidenceHigh {
			continue
		}
		sev := f.Severity
		if f.Source == models.SourceExternal && sev > models.SeverityInfo {
			sev-- // third-party opinion alone imposes a weaker floor
		}
		if v, ok := s.cfg.Floors[sev.String()]; ok && v > floor {
			floor = v
			floorReason = fmt.Sprintf("%s finding %s with high confidence sets a minimum score of %.0f", f.Severity, f.RuleID, v)
		}
	}
	score := combined
	if floor > combined {
		contributions = append(contributions, models.ScoreContribution{Fingerprint: "floor", Points: round2(floor - combined), Reason: floorReason})
		score = floor
	}
	sort.SliceStable(contributions, func(i, j int) bool { return contributions[i].Points > contributions[j].Points })
	if contributions == nil {
		contributions = []models.ScoreContribution{}
	}
	final := int(math.Round(math.Min(math.Max(score, 0), 100)))
	return models.RiskAssessment{
		Score:         final,
		Category:      models.CategoryForScore(final),
		Confidence:    assessmentConfidence(in),
		Contributions: contributions,
	}
}

// assessmentConfidence reflects how complete the analysis was, independent
// of the score: missing simulation and failed rules reduce it.
func assessmentConfidence(in interfaces.ScoringInput) models.Confidence {
	if in.EnabledChecks == 0 {
		return models.ConfidenceLow
	}
	penalty := 0
	switch {
	case in.Simulation == nil || in.Simulation.Completeness == models.CompletenessNone:
		penalty += 2
	case in.Simulation.Completeness == models.CompletenessPartial:
		penalty++
	}
	penalty += min(in.FailedRules, 2)
	switch {
	case penalty == 0:
		return models.ConfidenceHigh
	case penalty <= 2:
		return models.ConfidenceMedium
	default:
		return models.ConfidenceLow
	}
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
