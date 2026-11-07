// Package interfaces defines the contracts between TxShield modules.
//
// The analyzer depends only on these interfaces, so new decoders, security
// rules, simulation backends, reputation sources, chain adapters, and storage
// backends can be added without modifying the orchestrator. Implementations
// live under internal/.
package interfaces

import (
	"context"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/txshield/txshield/pkg/models"
)

// DecodeOptions carries per-request decoding inputs.
type DecodeOptions struct {
	// ABIJSON is an optional contract ABI (standard JSON ABI format) for the
	// top-level target. When it defines the selector, it takes precedence
	// over built-in signatures.
	ABIJSON []byte
}

// Decoder turns raw calldata into a structured call description.
//
// Decode must not perform network I/O and must not return an error for
// unrecognized or malformed calldata: it returns a DecodedCall with
// Kind=unknown (or warnings) and the raw data instead. Errors are reserved
// for invalid options (e.g. a malformed ABI) and cancellation.
type Decoder interface {
	Decode(ctx context.Context, tx *models.Transaction, opts DecodeOptions) (*models.DecodedCall, error)
}

// ChainReader is the read-only subset of JSON-RPC that analysis needs.
// Implementations must never expose transaction-sending methods.
type ChainReader interface {
	ChainID(ctx context.Context) (*big.Int, error)
	BlockNumber(ctx context.Context) (uint64, error)
	CodeAt(ctx context.Context, addr common.Address, block *big.Int) ([]byte, error)
	BalanceAt(ctx context.Context, addr common.Address, block *big.Int) (*big.Int, error)
	StorageAt(ctx context.Context, addr common.Address, slot common.Hash, block *big.Int) ([]byte, error)
	// CallContract performs eth_call. A successful call is not evidence of safety.
	CallContract(ctx context.Context, tx *models.Transaction, block *big.Int) ([]byte, error)
	EstimateGas(ctx context.Context, tx *models.Transaction) (uint64, error)
	// ResolveBlock turns a tag, number, or hash into a concrete block, so
	// every read in an analysis uses the same state.
	ResolveBlock(ctx context.Context, ref models.BlockRef) (models.BlockInfo, error)
}

// ChainRegistry resolves configured chains to RPC readers.
type ChainRegistry interface {
	// Reader returns the reader for chainID, or a txerrors KindUnsupported
	// error when the chain is not configured.
	Reader(chainID uint64) (ChainReader, error)
	// RPCURL returns the operator-configured RPC endpoint for chainID. Used by
	// fork simulators. Never returned to API clients (may contain API keys).
	RPCURL(chainID uint64) (string, error)
	Chains() []uint64
}

// SimulationRequest is the input to a Simulator.
type SimulationRequest struct {
	Tx *models.Transaction
	// BlockNumber is the concrete block to execute on top of. The analyzer
	// resolves tags (latest/safe/finalized) once so that all reads and the
	// simulation see the same state.
	BlockNumber uint64
	// TrackTokens lists token contracts whose balances should be diffed for
	// the sender and recipient in addition to tokens discovered in the trace.
	TrackTokens []common.Address
	// Timeout bounds the whole simulation including backend startup.
	Timeout time.Duration
}

// Simulator executes a transaction against forked or historical state without
// broadcasting it.
//
// Error contract: a transaction that reverts is a successful simulation with
// Status=reverted and err == nil. A non-nil err means the simulation could not
// be performed (infrastructure failure) and is a *txerrors.Error of kind
// Unavailable, Timeout, Unsupported, or Internal.
type Simulator interface {
	Name() string
	Capabilities() models.SimulatorCapabilities
	Simulate(ctx context.Context, req SimulationRequest) (*models.SimulationResult, error)
}

// ReputationProvider returns opinions about an address. Providers return an
// empty slice when they have no record. A provider may return several
// records (e.g. a chain-specific and an all-chains list entry). Results are
// opinions, not facts.
type ReputationProvider interface {
	Name() string
	Kind() models.ReputationSourceKind
	Lookup(ctx context.Context, chainID uint64, addr common.Address) ([]models.ReputationRecord, error)
}

// ContractInspector gathers on-chain facts about addresses (code presence,
// proxy implementation slots, interface support).
type ContractInspector interface {
	Inspect(ctx context.Context, chainID uint64, addr common.Address, block uint64) (*models.ContractInfo, error)
}

// AnalysisContext is the immutable input every rule receives. Rules must
// treat all fields as read-only; maps may be shared across rules.
type AnalysisContext struct {
	Tx          *models.Transaction
	Decoded     *models.DecodedCall
	Simulation  *models.SimulationResult // nil when simulation was not run
	BlockNumber uint64
	// Now is the reference time for expiry checks (block time when known).
	Now time.Time
	// Contracts holds on-chain facts. ContractsKnown is false when no chain
	// access was available; rules that need contract facts must then stay
	// silent rather than guess.
	Contracts      map[common.Address]*models.ContractInfo
	ContractsKnown bool
	// Reputation holds records for every address involved. ReputationSources
	// names the providers consulted; when empty, "unknown address" rules must
	// not fire (everything would be unknown).
	Reputation        map[common.Address][]models.ReputationRecord
	ReputationSources []string
	// Approvals are the permission grants extracted from the decoded calls.
	Approvals []models.ApprovalGrant
}

// Rule is a pluggable security detector.
//
// Evaluate returns zero or more findings. Returning an error marks the rule as
// failed for this analysis (surfaced as a report warning and lowered
// confidence) but never aborts the analysis.
type Rule interface {
	Metadata() models.RuleMetadata
	Evaluate(ctx context.Context, ac *AnalysisContext) ([]models.Finding, error)
}

// RuleResult captures one rule's execution for reporting and metrics.
type RuleResult struct {
	RuleID   string
	Findings []models.Finding
	Err      error
	Duration time.Duration
}

// RuleEngine runs a set of rules against an analysis context.
type RuleEngine interface {
	Rules() []models.RuleMetadata
	Run(ctx context.Context, ac *AnalysisContext) []RuleResult
}

// ScoringInput is everything the risk scorer considers.
type ScoringInput struct {
	Findings      []models.Finding
	Simulation    *models.SimulationResult
	FailedRules   int
	EnabledChecks int
}

// RiskScorer converts findings and signals into a 0-100 score. It must be
// deterministic and must deduplicate findings by Fingerprint.
type RiskScorer interface {
	Score(in ScoringInput) models.RiskAssessment
}

// Page is a cursor-free offset page request.
type Page struct {
	Limit  int
	Offset int
}

// AnalysisFilter narrows ListAnalyses.
type AnalysisFilter struct {
	ChainID  *uint64
	Address  *common.Address // matches any role in analysis_history
	MinScore *int
	Since    *time.Time
}

// AnalysisStats aggregates stored analyses for the dashboard.
type AnalysisStats struct {
	Total      int64                         `json:"total"`
	HighRisk   int64                         `json:"highRisk"` // score >= 60
	ByCategory map[models.RiskCategory]int64 `json:"byCategory"`
	ByChain    map[uint64]int64              `json:"byChain"`
}

// AnalysisStore persists reports. Optional: the engine works without it.
type AnalysisStore interface {
	SaveReport(ctx context.Context, r *models.RiskReport, tx *models.Transaction) error
	GetReport(ctx context.Context, id string) (*models.RiskReport, error)
	ListReports(ctx context.Context, f AnalysisFilter, p Page) ([]models.AnalysisSummary, int64, error)
	Stats(ctx context.Context, since *time.Time) (*AnalysisStats, error)
	// PurgeExpired deletes analyses past their retention and returns the count.
	PurgeExpired(ctx context.Context, now time.Time) (int64, error)
}

// Cache is a small byte-oriented cache used for immutable chain reads and
// metadata. Implementations: Redis, in-memory.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Set(ctx context.Context, key string, val []byte, ttl time.Duration) error
}

// HealthChecker reports the health of one dependency.
type HealthChecker interface {
	Name() string
	// Critical dependencies make /health return 503 when failing.
	Critical() bool
	Check(ctx context.Context) error
}
