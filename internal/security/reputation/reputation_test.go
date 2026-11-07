package reputation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/txshield/txshield/pkg/models"
)

var (
	addrA = common.HexToAddress("0x1111111111111111111111111111111111111111")
	addrB = common.HexToAddress("0x2222222222222222222222222222222222222222")
)

const validList = `{
  "name": "team",
  "entries": [
    {"chainId": 1, "address": "0x1111111111111111111111111111111111111111", "status": "blocked", "reason": "drainer", "labels": ["drainer"]},
    {"address": "0x2222222222222222222222222222222222222222", "status": "allowed", "confidence": "medium"}
  ]
}`

func TestParseListAndLookup(t *testing.T) {
	p, err := ParseList(strings.NewReader(validList), "test")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "list:team" || p.Kind() != models.ReputationSourceList {
		t.Fatalf("name/kind = %s/%s", p.Name(), p.Kind())
	}
	recs, _ := p.Lookup(context.Background(), 1, addrA)
	if len(recs) != 1 || recs[0].Status != models.ReputationBlocked || recs[0].Confidence != models.ConfidenceHigh || recs[0].Source != "list:team" {
		t.Fatalf("chain 1: %+v", recs)
	}
	if recs, _ := p.Lookup(context.Background(), 10, addrA); len(recs) != 0 {
		t.Fatalf("chain-specific entry leaked to chain 10: %+v", recs)
	}
	if recs, _ := p.Lookup(context.Background(), 10, addrB); len(recs) != 1 || recs[0].ChainID != 10 {
		t.Fatalf("all-chain entry must apply to chain 10: %+v", recs)
	}
}

func TestParseListRejectsInvalidEntries(t *testing.T) {
	cases := map[string]string{
		"bad address":   `{"name":"x","entries":[{"address":"0x12","status":"blocked"}]}`,
		"bad status":    `{"name":"x","entries":[{"address":"0x1111111111111111111111111111111111111111","status":"evil"}]}`,
		"bad conf":      `{"name":"x","entries":[{"address":"0x1111111111111111111111111111111111111111","status":"blocked","confidence":"very"}]}`,
		"no name":       `{"entries":[]}`,
		"unknown field": `{"name":"x","entries":[],"extra":1}`,
		"not json":      `nope`,
	}
	for name, doc := range cases {
		if _, err := ParseList(strings.NewReader(doc), "t"); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestExpiredStaticRecordIgnored(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	p := NewStaticProvider("s", models.ReputationSourceLocal, []models.ReputationRecord{
		{Address: addrA.Hex(), Status: models.ReputationBlocked, ExpiresAt: &past},
	})
	if recs, _ := p.Lookup(context.Background(), 1, addrA); len(recs) != 0 {
		t.Fatalf("expired record returned: %+v", recs)
	}
}

func rec(kind models.ReputationSourceKind, st models.ReputationStatus) models.ReputationRecord {
	return models.ReputationRecord{SourceKind: kind, Status: st}
}

func TestEffectivePolicy(t *testing.T) {
	L, X := models.ReputationSourceList, models.ReputationSourceExternal
	cases := []struct {
		name string
		recs []models.ReputationRecord
		want models.ReputationStatus
	}{
		{"none", nil, models.ReputationUnknown},
		{"operator block beats operator allow", []models.ReputationRecord{rec(L, models.ReputationAllowed), rec(L, models.ReputationBlocked)}, models.ReputationBlocked},
		{"operator allow beats external block", []models.ReputationRecord{rec(X, models.ReputationBlocked), rec(L, models.ReputationAllowed)}, models.ReputationAllowed},
		{"external only: worst wins", []models.ReputationRecord{rec(X, models.ReputationAllowed), rec(X, models.ReputationSuspicious)}, models.ReputationSuspicious},
		{"local block", []models.ReputationRecord{rec(models.ReputationSourceLocal, models.ReputationBlocked)}, models.ReputationBlocked},
	}
	for _, c := range cases {
		if got := Effective(c.recs); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

type failingProvider struct{ delay time.Duration }

func (failingProvider) Name() string                      { return "flaky" }
func (failingProvider) Kind() models.ReputationSourceKind { return models.ReputationSourceExternal }
func (f failingProvider) Lookup(ctx context.Context, _ uint64, _ common.Address) ([]models.ReputationRecord, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("upstream 500")
}

func TestAggregatorToleratesFailures(t *testing.T) {
	list, err := ParseList(strings.NewReader(validList), "t")
	if err != nil {
		t.Fatal(err)
	}
	agg := NewAggregator(50*time.Millisecond, list, failingProvider{delay: time.Second})
	start := time.Now()
	got, warnings := agg.LookupAll(context.Background(), 1, []common.Address{addrA, addrB})
	if time.Since(start) > 900*time.Millisecond {
		t.Fatal("per-lookup timeout not enforced")
	}
	if len(got[addrA]) != 1 || len(got[addrB]) != 1 {
		t.Fatalf("records = %+v", got)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "flaky") {
		t.Fatalf("warnings = %v (want exactly one per failing provider)", warnings)
	}
	if s := agg.Sources(); len(s) != 2 {
		t.Fatalf("sources = %v", s)
	}
}
