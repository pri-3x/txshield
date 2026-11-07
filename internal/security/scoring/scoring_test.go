package scoring

import (
	"slices"
	"strings"
	"testing"

	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
)

func f(rule, fp string, sev models.Severity, conf models.Confidence, src models.EvidenceSource) models.Finding {
	return models.Finding{RuleID: rule, Fingerprint: fp, Severity: sev, Confidence: conf, Source: src}
}

var full = &models.SimulationResult{Completeness: models.CompletenessFull}

func score(t *testing.T, fs ...models.Finding) models.RiskAssessment {
	t.Helper()
	s, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return s.Score(interfaces.ScoringInput{Findings: fs, Simulation: full, EnabledChecks: 10})
}

func TestNoFindingsIsLowNotSafe(t *testing.T) {
	a := score(t)
	if a.Score != 0 || a.Category != models.RiskLow || a.Confidence != models.ConfidenceHigh || a.Contributions == nil {
		t.Fatalf("%+v", a)
	}
}

func TestInfoFindingsDoNotScore(t *testing.T) {
	if a := score(t, f("A", "a", models.SeverityInfo, models.ConfidenceHigh, models.SourceFact)); a.Score != 0 {
		t.Fatalf("%+v", a)
	}
}

func TestSingleFindings(t *testing.T) {
	cases := []struct {
		name string
		f    models.Finding
		want int
		cat  models.RiskCategory
	}{
		{"unlimited approval (medium/high/fact)", f("A", "a", models.SeverityMedium, models.ConfidenceHigh, models.SourceFact), 22, models.RiskModerate},
		{"high heuristic medium-conf", f("A", "a", models.SeverityHigh, models.ConfidenceMedium, models.SourceHeuristic), 30, models.RiskModerate},
		{"high fact high-conf hits floor", f("A", "a", models.SeverityHigh, models.ConfidenceHigh, models.SourceFact), 60, models.RiskHigh},
		{"critical fact high-conf", f("A", "a", models.SeverityCritical, models.ConfidenceHigh, models.SourceFact), 85, models.RiskCritical},
		{"critical external high-conf: weaker floor", f("A", "a", models.SeverityCritical, models.ConfidenceHigh, models.SourceExternal), 72, models.RiskHigh},
		{"low", f("A", "a", models.SeverityLow, models.ConfidenceLow, models.SourceHeuristic), 4, models.RiskLow},
	}
	for _, c := range cases {
		a := score(t, c.f)
		if a.Score != c.want || a.Category != c.cat {
			t.Errorf("%s: score %d (%s), want %d (%s); contributions %+v", c.name, a.Score, a.Category, c.want, c.cat, a.Contributions)
		}
	}
}

func TestDuplicateFingerprintsCountOnce(t *testing.T) {
	one := score(t, f("A", "x", models.SeverityMedium, models.ConfidenceHigh, models.SourceFact))
	dup := score(t,
		f("A", "x", models.SeverityMedium, models.ConfidenceHigh, models.SourceFact),
		f("A", "x", models.SeverityMedium, models.ConfidenceHigh, models.SourceFact),
		f("A", "x", models.SeverityLow, models.ConfidenceLow, models.SourceFact))
	if one.Score != dup.Score || len(dup.Contributions) != 1 {
		t.Fatalf("one=%d dup=%d contributions=%+v", one.Score, dup.Score, dup.Contributions)
	}
}

func TestDedupKeepsMostSevere(t *testing.T) {
	out := Deduplicate([]models.Finding{
		f("A", "x", models.SeverityLow, models.ConfidenceHigh, models.SourceFact),
		f("A", "x", models.SeverityHigh, models.ConfidenceLow, models.SourceFact),
		f("B", "y", models.SeverityCritical, models.ConfidenceLow, models.SourceFact),
	})
	if len(out) != 2 || out[0].RuleID != "B" || out[1].Severity != models.SeverityHigh {
		t.Fatalf("%+v", out)
	}
}

func TestRepeatDecayAndBoundedness(t *testing.T) {
	var fs []models.Finding
	for i := 0; i < 50; i++ {
		fs = append(fs, f("A", string(rune('a'+i)), models.SeverityMedium, models.ConfidenceHigh, models.SourceFact))
	}
	a := score(t, fs...)
	// 22 * (1 + .5 + .25 + ...) combined probabilistically stays well below
	// what 50 independent medium findings would give.
	if a.Score >= 40 || a.Score <= 22 {
		t.Fatalf("decayed score = %d", a.Score)
	}
	if !strings.Contains(a.Contributions[1].Reason, "repeat decay") {
		t.Fatalf("reason = %s", a.Contributions[1].Reason)
	}

	var many []models.Finding
	for i := 0; i < 30; i++ {
		many = append(many, f(string(rune('A'+i)), string(rune('A'+i)), models.SeverityCritical, models.ConfidenceHigh, models.SourceFact))
	}
	if a := score(t, many...); a.Score != 100 {
		t.Fatalf("score must saturate at 100, got %d", a.Score)
	}
}

func TestIndependentFindingsCombine(t *testing.T) {
	a := score(t,
		f("A", "a", models.SeverityMedium, models.ConfidenceHigh, models.SourceFact),
		f("B", "b", models.SeverityMedium, models.ConfidenceHigh, models.SourceFact))
	// 1 - (1-.22)^2 = .3916
	if a.Score != 39 {
		t.Fatalf("score = %d", a.Score)
	}
}

func TestFloorContributionExplained(t *testing.T) {
	a := score(t, f("TXS-X", "a", models.SeverityHigh, models.ConfidenceHigh, models.SourceFact))
	var floor *models.ScoreContribution
	for i := range a.Contributions {
		if a.Contributions[i].Fingerprint == "floor" {
			floor = &a.Contributions[i]
		}
	}
	if floor == nil || floor.Points != 15 || !strings.Contains(floor.Reason, "TXS-X") {
		t.Fatalf("contributions = %+v", a.Contributions)
	}
}

func TestAssessmentConfidence(t *testing.T) {
	s, _ := New(DefaultConfig())
	cases := []struct {
		in   interfaces.ScoringInput
		want models.Confidence
	}{
		{interfaces.ScoringInput{Simulation: full, EnabledChecks: 1}, models.ConfidenceHigh},
		{interfaces.ScoringInput{Simulation: &models.SimulationResult{Completeness: models.CompletenessPartial}, EnabledChecks: 1}, models.ConfidenceMedium},
		{interfaces.ScoringInput{EnabledChecks: 1}, models.ConfidenceMedium},              // no simulation
		{interfaces.ScoringInput{EnabledChecks: 1, FailedRules: 1}, models.ConfidenceLow}, // no sim + failed rule
		{interfaces.ScoringInput{Simulation: full, EnabledChecks: 1, FailedRules: 5}, models.ConfidenceMedium},
		{interfaces.ScoringInput{Simulation: full}, models.ConfidenceLow}, // nothing enabled
	}
	for i, c := range cases {
		if got := s.Score(c.in).Confidence; got != c.want {
			t.Errorf("case %d: %s, want %s", i, got, c.want)
		}
	}
}

func TestConfigParsingAndValidation(t *testing.T) {
	c, err := ParseConfig(strings.NewReader(`{"severityPoints":{"medium":30},"repeatDecay":0.25}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.SeverityPoints["medium"] != 30 || c.SeverityPoints["high"] != 45 || c.RepeatDecay != 0.25 {
		t.Fatalf("%+v", c)
	}
	for _, bad := range []string{
		`{"severityPoints":{"low":50}}`,   // not monotonic (low > medium)
		`{"confidenceWeight":{"high":2}}`, // out of range
		`{"repeatDecay":-1}`,              // out of range
		`{"floors":{"apocalyptic":10}}`,   // unknown severity
		`{"unknown":1}`,                   // unknown field
	} {
		if _, err := ParseConfig(strings.NewReader(bad)); err == nil {
			t.Errorf("expected error for %s", bad)
		}
	}
}

func TestDeterministic(t *testing.T) {
	fs := []models.Finding{
		f("A", "a", models.SeverityMedium, models.ConfidenceHigh, models.SourceFact),
		f("B", "b", models.SeverityHigh, models.ConfidenceMedium, models.SourceHeuristic),
		f("A", "c", models.SeverityLow, models.ConfidenceHigh, models.SourceFact),
	}
	first := score(t, fs...)
	for i := 0; i < 20; i++ {
		rev := slices.Clone(fs)
		slices.Reverse(rev)
		if a := score(t, rev...); a.Score != first.Score || len(a.Contributions) != len(first.Contributions) {
			t.Fatal("score depends on input order")
		}
	}
}
