// Package reputation provides contract/address reputation sources and the
// policy that combines them.
//
// Sources:
//   - ListProvider: operator-maintained JSON allow/block lists (kind "list").
//   - StaticProvider: in-memory records (tests, embedding).
//   - PostgresProvider: locally maintained records in contract_reputation
//     (kind "local").
//   - External adapters implement interfaces.ReputationProvider with kind
//     "external"; none is required for core functionality.
//
// Reputation is opinion, not fact. Every record carries its source.
package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
)

// ---------------------------------------------------------------------------
// Static provider

// StaticProvider serves records from memory. Records with ChainID 0 apply to
// every chain.
type StaticProvider struct {
	name    string
	kind    models.ReputationSourceKind
	records map[common.Address][]models.ReputationRecord
}

// NewStaticProvider builds a provider from records.
func NewStaticProvider(name string, kind models.ReputationSourceKind, records []models.ReputationRecord) *StaticProvider {
	p := &StaticProvider{name: name, kind: kind, records: map[common.Address][]models.ReputationRecord{}}
	for _, r := range records {
		a := common.HexToAddress(r.Address)
		r.Address = a.Hex()
		if r.Source == "" {
			r.Source = name
		}
		r.SourceKind = kind
		p.records[a] = append(p.records[a], r)
	}
	return p
}

func (p *StaticProvider) Name() string                      { return p.name }
func (p *StaticProvider) Kind() models.ReputationSourceKind { return p.kind }

// Lookup returns records matching the chain (or all-chain records).
// InMemory marks the provider as answering without I/O; the aggregator
// queries it inline instead of through its worker pool.
func (p *StaticProvider) InMemory() bool { return true }

func (p *StaticProvider) Lookup(_ context.Context, chainID uint64, addr common.Address) ([]models.ReputationRecord, error) {
	var out []models.ReputationRecord
	now := time.Now()
	for _, r := range p.records[addr] {
		if r.ChainID != 0 && r.ChainID != chainID {
			continue
		}
		if r.ExpiresAt != nil && r.ExpiresAt.Before(now) {
			continue
		}
		r.ChainID = chainID
		out = append(out, r)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// List files

// ListFile is the on-disk format of an allow/block list.
//
//	{
//	  "name": "team-blocklist",
//	  "entries": [
//	    {"chainId": 1, "address": "0x...", "status": "blocked",
//	     "reason": "drainer reported in incident #12", "labels": ["drainer"],
//	     "confidence": "high"}
//	  ]
//	}
//
// chainId 0 (or omitted) applies to every chain.
type ListFile struct {
	Name    string      `json:"name"`
	Entries []ListEntry `json:"entries"`
}

// ListEntry is one list record.
type ListEntry struct {
	ChainID    uint64   `json:"chainId"`
	Address    string   `json:"address"`
	Status     string   `json:"status"`
	Reason     string   `json:"reason"`
	Labels     []string `json:"labels"`
	Confidence string   `json:"confidence"`
}

const (
	maxListBytes  = 32 << 20
	maxReasonLen  = 512
	maxLabelLen   = 64
	maxLabels     = 16
	maxListNameLn = 64
)

// LoadListFile reads and validates a list file.
func LoadListFile(path string) (*StaticProvider, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied config path, not request input
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return ParseList(io.LimitReader(f, maxListBytes+1), path)
}

// ParseList validates a list document. Every entry problem is reported with
// its index; a list with any invalid entry is rejected as a whole, because a
// silently skipped blocklist entry is a security bug.
func ParseList(r io.Reader, origin string) (*StaticProvider, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(data) > maxListBytes {
		return nil, fmt.Errorf("%s: list exceeds %d bytes", origin, maxListBytes)
	}
	var lf ListFile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&lf); err != nil {
		return nil, fmt.Errorf("%s: %w", origin, err)
	}
	name := strings.TrimSpace(lf.Name)
	if name == "" || len(name) > maxListNameLn {
		return nil, fmt.Errorf("%s: list name is required (max %d chars)", origin, maxListNameLn)
	}
	var errs []string
	records := make([]models.ReputationRecord, 0, len(lf.Entries))
	for i, e := range lf.Entries {
		addr, err := models.ParseAddress(e.Address)
		if err != nil {
			errs = append(errs, fmt.Sprintf("entry %d: address: %v", i, err))
			continue
		}
		status := models.ReputationStatus(e.Status)
		switch status {
		case models.ReputationAllowed, models.ReputationSuspicious, models.ReputationBlocked:
		default:
			errs = append(errs, fmt.Sprintf("entry %d: status must be allowed, suspicious, or blocked", i))
			continue
		}
		conf := models.ConfidenceHigh
		if e.Confidence != "" {
			if conf, err = models.ParseConfidence(e.Confidence); err != nil {
				errs = append(errs, fmt.Sprintf("entry %d: %v", i, err))
				continue
			}
		}
		if len(e.Reason) > maxReasonLen || len(e.Labels) > maxLabels {
			errs = append(errs, fmt.Sprintf("entry %d: reason or labels too long", i))
			continue
		}
		for _, l := range e.Labels {
			if len(l) > maxLabelLen {
				errs = append(errs, fmt.Sprintf("entry %d: label too long", i))
			}
		}
		records = append(records, models.ReputationRecord{
			ChainID: e.ChainID, Address: addr.Hex(), Status: status, Source: "list:" + name,
			Reason: e.Reason, Labels: e.Labels, Confidence: conf,
		})
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("%s: %d invalid entries: %s", origin, len(errs), strings.Join(errs, "; "))
	}
	return NewStaticProvider("list:"+name, models.ReputationSourceList, records), nil
}

// ---------------------------------------------------------------------------
// Aggregation and policy

// Aggregator queries all providers concurrently with a per-lookup timeout.
type Aggregator struct {
	providers   []interfaces.ReputationProvider
	timeout     time.Duration
	concurrency int
}

// NewAggregator combines providers.
func NewAggregator(timeout time.Duration, providers ...interfaces.ReputationProvider) *Aggregator {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &Aggregator{providers: providers, timeout: timeout, concurrency: 8}
}

// Sources returns provider names.
func (a *Aggregator) Sources() []string {
	out := make([]string, len(a.providers))
	for i, p := range a.providers {
		out[i] = p.Name()
	}
	return out
}

// LookupAll fetches records for every address. Provider failures are
// returned as warnings, never as errors: missing reputation must not block
// analysis, but the report must say it is incomplete.
func (a *Aggregator) LookupAll(ctx context.Context, chainID uint64, addrs []common.Address) (map[common.Address][]models.ReputationRecord, []string) {
	out := make(map[common.Address][]models.ReputationRecord, len(addrs))
	if len(a.providers) == 0 || len(addrs) == 0 {
		return out, nil
	}
	var mu sync.Mutex
	var warnings []string
	failed := map[string]bool{}
	record := func(p interfaces.ReputationProvider, addr common.Address, recs []models.ReputationRecord, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			if !failed[p.Name()] {
				failed[p.Name()] = true
				warnings = append(warnings, fmt.Sprintf("reputation source %s failed; its data is missing from this report", p.Name()))
			}
			return
		}
		for _, r := range recs {
			r.SourceKind = p.Kind()
			if r.Source == "" {
				r.Source = p.Name()
			}
			out[addr] = append(out[addr], r)
		}
	}

	// In-memory providers answer inline: a goroutine and a timeout context
	// per lookup would cost far more than the lookup itself.
	type job struct {
		p    interfaces.ReputationProvider
		addr common.Address
	}
	var remote []job
	for _, p := range a.providers {
		if m, ok := p.(interface{ InMemory() bool }); ok && m.InMemory() {
			for _, addr := range addrs {
				if ctx.Err() != nil {
					break
				}
				recs, err := p.Lookup(ctx, chainID, addr)
				record(p, addr, recs, err)
			}
			continue
		}
		for _, addr := range addrs {
			remote = append(remote, job{p, addr})
		}
	}

	if len(remote) > 0 {
		jobs := make(chan job)
		var wg sync.WaitGroup
		for range min(a.concurrency, len(remote)) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range jobs {
					lctx, cancel := context.WithTimeout(ctx, a.timeout)
					recs, err := j.p.Lookup(lctx, chainID, j.addr)
					cancel()
					record(j.p, j.addr, recs, err)
				}
			}()
		}
	feed:
		for _, j := range remote {
			select {
			case jobs <- j:
			case <-ctx.Done():
				break feed
			}
		}
		close(jobs)
		wg.Wait()
	}
	for addr := range out {
		sort.SliceStable(out[addr], func(i, j int) bool { return out[addr][i].Source < out[addr][j].Source })
	}
	sort.Strings(warnings)
	return out, warnings
}

// Effective resolves records from several sources into one status:
//
//  1. A "blocked" record from an operator source (local or list) wins.
//  2. Otherwise an operator "allowed" record wins over external opinions:
//     the operator's explicit decision overrides third-party data.
//  3. Otherwise the most severe external/operator status applies
//     (blocked > suspicious > allowed > unknown).
//
// The overridden records are still shown in reports.
func Effective(records []models.ReputationRecord) models.ReputationStatus {
	operator := func(r models.ReputationRecord) bool {
		return r.SourceKind == models.ReputationSourceLocal || r.SourceKind == models.ReputationSourceList
	}
	for _, r := range records {
		if operator(r) && r.Status == models.ReputationBlocked {
			return models.ReputationBlocked
		}
	}
	for _, r := range records {
		if operator(r) && r.Status == models.ReputationAllowed {
			return models.ReputationAllowed
		}
	}
	rank := map[models.ReputationStatus]int{models.ReputationUnknown: 0, models.ReputationAllowed: 1, models.ReputationSuspicious: 2, models.ReputationBlocked: 3}
	best := models.ReputationUnknown
	for _, r := range records {
		if rank[r.Status] > rank[best] {
			best = r.Status
		}
	}
	return best
}
