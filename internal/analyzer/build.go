package analyzer

import (
	"fmt"
	"time"

	"github.com/pri-3x/txshield/internal/decoder"
	"github.com/pri-3x/txshield/internal/security/reputation"
	"github.com/pri-3x/txshield/internal/security/rules"
	"github.com/pri-3x/txshield/internal/security/scoring"
	"github.com/pri-3x/txshield/pkg/interfaces"
)

// BuildOptions configures the standard analyzer wiring.
type BuildOptions struct {
	EngineVersion     string
	ReputationFiles   []string // JSON allow/block lists
	ExtraReputation   []interfaces.ReputationProvider
	ScoringConfigPath string // optional JSON overrides of scoring weights
	Rules             rules.Config
	DecoderLimits     decoder.Limits
	RuleTimeout       time.Duration
	ReputationTimeout time.Duration
	Inspector         interfaces.ContractInspector // optional
	Simulator         interfaces.Simulator         // optional
	Chains            interfaces.ChainRegistry     // optional; resolves blocks
}

// Build wires the built-in decoder, rules, scorer, and reputation sources.
func Build(o BuildOptions) (*Analyzer, error) {
	eng, err := rules.NewEngine(o.RuleTimeout, rules.Default(o.Rules)...)
	if err != nil {
		return nil, err
	}
	cfg := scoring.DefaultConfig()
	if o.ScoringConfigPath != "" {
		if cfg, err = scoring.LoadConfig(o.ScoringConfigPath); err != nil {
			return nil, err
		}
	}
	scorer, err := scoring.New(cfg)
	if err != nil {
		return nil, err
	}
	providers := append([]interfaces.ReputationProvider{}, o.ExtraReputation...)
	for _, path := range o.ReputationFiles {
		p, err := reputation.LoadListFile(path)
		if err != nil {
			return nil, fmt.Errorf("reputation list: %w", err)
		}
		providers = append(providers, p)
	}
	var agg *reputation.Aggregator
	if len(providers) > 0 {
		agg = reputation.NewAggregator(o.ReputationTimeout, providers...)
	}
	return New(Deps{
		Decoder:       decoder.New(decoder.Builtin(), o.DecoderLimits),
		Rules:         eng,
		Scorer:        scorer,
		Reputation:    agg,
		Inspector:     o.Inspector,
		Simulator:     o.Simulator,
		Chains:        o.Chains,
		EngineVersion: o.EngineVersion,
	})
}
