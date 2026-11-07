package models

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/txshield/txshield/pkg/txerrors"
)

func TestParseAddress(t *testing.T) {
	cases := []struct {
		in      string
		wantErr string
	}{
		{"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", ""}, // valid EIP-55
		{"0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", ""}, // all lower
		{"0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED", ""}, // all upper
		{"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD", "checksum"},
		{"5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "0x-prefixed"},
		{"0x5aaeb6053f3e94c9b9a09f33669435e7ef1bea", "20 bytes"},
		{"0xzzaeb6053f3e94c9b9a09f33669435e7ef1beaed", "invalid hex"},
	}
	for _, c := range cases {
		_, err := ParseAddress(c.in)
		if c.wantErr == "" && err != nil {
			t.Errorf("ParseAddress(%q) unexpected error: %v", c.in, err)
		}
		if c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
			t.Errorf("ParseAddress(%q) err = %v, want containing %q", c.in, err, c.wantErr)
		}
	}
}

func TestParseUint256(t *testing.T) {
	ok := map[string]string{
		"0":                            "0",
		"123":                          "123",
		"0x7b":                         "123",
		"0x" + strings.Repeat("f", 64): MaxUint256.String(),
	}
	for in, want := range ok {
		v, err := ParseUint256(in)
		if err != nil || v.String() != want {
			t.Errorf("ParseUint256(%q) = %v, %v; want %s", in, v, err, want)
		}
	}
	for _, in := range []string{"", "-1", "1.5", "1e18", "0x", "0x1" + strings.Repeat("0", 64), "abc"} {
		if _, err := ParseUint256(in); err == nil {
			t.Errorf("ParseUint256(%q) expected error", in)
		}
	}
}

func TestParseBlockRef(t *testing.T) {
	if r, err := ParseBlockRef(""); err != nil || r.Tag != BlockLatest {
		t.Fatalf("empty: %+v %v", r, err)
	}
	if r, err := ParseBlockRef("19000000"); err != nil || r.Number == nil || *r.Number != 19000000 {
		t.Fatalf("decimal: %+v %v", r, err)
	}
	if r, err := ParseBlockRef("0x10"); err != nil || r.Number == nil || *r.Number != 16 || r.String() != "0x10" {
		t.Fatalf("hex: %+v %v", r, err)
	}
	h := "0x" + strings.Repeat("ab", 32)
	if r, err := ParseBlockRef(h); err != nil || r.Hash == nil || r.String() != h {
		t.Fatalf("hash: %+v %v", r, err)
	}
	for _, in := range []string{"pending", "earliest", "nope", "-5"} {
		if _, err := ParseBlockRef(in); err == nil {
			t.Errorf("ParseBlockRef(%q) expected error", in)
		}
	}
}

func TestQuantityUnmarshal(t *testing.T) {
	var r TransactionRequest
	in := `{"chainId":1,"from":"0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed","to":"0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed","value":1000,"gas":"0x5208","maxFeePerGas":"30000000000"}`
	if err := json.Unmarshal([]byte(in), &r); err != nil {
		t.Fatal(err)
	}
	tx, err := ParseTransaction(r, ParseLimits{MaxCalldataBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Value.Int64() != 1000 || tx.Gas == nil || *tx.Gas != 21000 || tx.FeeModel() != FeeEIP1559 {
		t.Fatalf("unexpected parse: value=%v gas=%v fee=%s", tx.Value, tx.Gas, tx.FeeModel())
	}
}

const addr = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"

func fieldSet(err error) map[string]bool {
	e, ok := txerrors.As(err)
	if !ok {
		return nil
	}
	m := map[string]bool{}
	for _, f := range e.Fields {
		m[f.Field] = true
	}
	return m
}

func TestParseTransactionCollectsAllErrors(t *testing.T) {
	_, err := ParseTransaction(TransactionRequest{
		From:         "0xbad",
		To:           "nope",
		Value:        "-1",
		Data:         "0xzz",
		GasPrice:     "1",
		MaxFeePerGas: "2",
		Block:        "pending",
	}, ParseLimits{})
	if txerrors.KindOf(err) != txerrors.KindInvalidInput {
		t.Fatalf("want invalid input, got %v", err)
	}
	got := fieldSet(err)
	for _, f := range []string{"chainId", "from", "to", "value", "data", "gasPrice", "block"} {
		if !got[f] {
			t.Errorf("missing field error for %q; got %v", f, got)
		}
	}
}

func TestParseTransactionRules(t *testing.T) {
	lim := ParseLimits{MaxCalldataBytes: 4}

	// Contract creation: no `to`, but bytecode present.
	tx, err := ParseTransaction(TransactionRequest{ChainID: 1, From: addr, Data: "0x6080"}, lim)
	if err != nil || !tx.IsContractCreation() {
		t.Fatalf("creation: %v", err)
	}
	if _, ok := tx.Selector(); ok {
		t.Fatal("creation must not report a selector")
	}

	// No `to` and no data is invalid.
	if _, err := ParseTransaction(TransactionRequest{ChainID: 1, From: addr}, lim); !fieldSet(err)["to"] {
		t.Fatalf("expected 'to' error, got %v", err)
	}

	// Calldata over limit.
	if _, err := ParseTransaction(TransactionRequest{ChainID: 1, From: addr, To: addr, Data: "0x0102030405"}, lim); !fieldSet(err)["data"] {
		t.Fatalf("expected 'data' size error, got %v", err)
	}

	// Priority fee above max fee.
	if _, err := ParseTransaction(TransactionRequest{ChainID: 1, From: addr, To: addr, MaxFeePerGas: "1", MaxPriorityFeePerGas: "2"}, lim); !fieldSet(err)["maxPriorityFeePerGas"] {
		t.Fatalf("expected priority fee error, got %v", err)
	}

	// Priority fee without max fee.
	if _, err := ParseTransaction(TransactionRequest{ChainID: 1, From: addr, To: addr, MaxPriorityFeePerGas: "2"}, lim); !fieldSet(err)["maxFeePerGas"] {
		t.Fatalf("expected maxFeePerGas required error, got %v", err)
	}

	// Gas zero / overflow.
	for _, g := range []Quantity{"0", "1000000001", "0xffffffffffffffff"} {
		if _, err := ParseTransaction(TransactionRequest{ChainID: 1, From: addr, To: addr, Gas: g}, lim); !fieldSet(err)["gas"] {
			t.Fatalf("gas %s: expected gas error, got %v", g, err)
		}
	}
	if _, err := ParseTransaction(TransactionRequest{ChainID: 1, From: addr, To: addr, Gas: "1000000000"}, lim); err != nil {
		t.Fatalf("gas at the cap rejected: %v", err)
	}

	// Selector extraction.
	tx, err = ParseTransaction(TransactionRequest{ChainID: 1, From: addr, To: addr, Data: "0x095ea7b3"}, lim)
	if err != nil {
		t.Fatal(err)
	}
	if sel, ok := tx.Selector(); !ok || sel != [4]byte{0x09, 0x5e, 0xa7, 0xb3} {
		t.Fatalf("selector = %x, %v", sel, ok)
	}
	if tx.FeeModel() != FeeUnspecified || tx.Value.Sign() != 0 {
		t.Fatal("defaults wrong")
	}
}

func TestCategoryForScore(t *testing.T) {
	cases := map[int]RiskCategory{
		-5: RiskLow, 0: RiskLow, 19: RiskLow, 20: RiskModerate, 39: RiskModerate,
		40: RiskElevated, 59: RiskElevated, 60: RiskHigh, 79: RiskHigh, 80: RiskCritical, 100: RiskCritical, 150: RiskCritical,
	}
	for s, want := range cases {
		if got := CategoryForScore(s); got != want {
			t.Errorf("CategoryForScore(%d) = %s, want %s", s, got, want)
		}
	}
}

func TestSeverityConfidenceJSON(t *testing.T) {
	f := Finding{Severity: SeverityHigh, Confidence: ConfidenceMedium}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"severity":"high"`) || !strings.Contains(string(b), `"confidence":"medium"`) {
		t.Fatalf("unexpected JSON: %s", b)
	}
	var back Finding
	if err := json.Unmarshal(b, &back); err != nil || back.Severity != SeverityHigh || back.Confidence != ConfidenceMedium {
		t.Fatalf("roundtrip failed: %+v %v", back, err)
	}
	if err := json.Unmarshal([]byte(`{"severity":"apocalyptic"}`), &back); err == nil {
		t.Fatal("expected error for unknown severity")
	}
	if SeverityCritical <= SeverityHigh || SeverityLow <= SeverityInfo {
		t.Fatal("severity must be ordered")
	}
}
