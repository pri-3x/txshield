package simulator

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/pri-3x/txshield/pkg/models"
)

var (
	tok   = common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	alice = common.HexToAddress("0x1111111111111111111111111111111111111111")
	bob   = common.HexToAddress("0x2222222222222222222222222222222222222222")
)

func h(a common.Address) common.Hash { return common.BytesToHash(a.Bytes()) }
func w(v int64) []byte               { return common.LeftPadBytes(big.NewInt(v).Bytes(), 32) }

func TestTopicHashes(t *testing.T) {
	if topicTransfer.Hex() != "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" ||
		topicApproval.Hex() != "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925" {
		t.Fatal("well-known topic hash mismatch")
	}
}

func TestParseLogs(t *testing.T) {
	batch := append(append(append(append(w(64), w(160)...), w(2)...), append(w(7), w(8)...)...), append(w(2), append(w(10), w(20)...)...)...)
	logs := []RawLog{
		{Address: tok, Topics: []common.Hash{topicTransfer, h(alice), h(bob)}, Data: w(1000)},
		{Address: tok, Topics: []common.Hash{topicTransfer, h(alice), h(bob), common.BigToHash(big.NewInt(42))}},
		{Address: tok, Topics: []common.Hash{topicApproval, h(alice), h(bob)}, Data: w(5)},
		{Address: tok, Topics: []common.Hash{topicApprovalForAll, h(alice), h(bob)}, Data: w(1)},
		{Address: tok, Topics: []common.Hash{topicTransferSingle, h(bob), h(alice), h(bob)}, Data: append(w(3), w(4)...)},
		{Address: tok, Topics: []common.Hash{topicTransferBatch, h(bob), h(alice), h(bob)}, Data: batch},
		{Address: tok, Topics: []common.Hash{topicDeposit, h(alice)}, Data: w(9)},
		{Address: tok, Topics: []common.Hash{topicWithdrawal, h(alice)}, Data: w(9)},
		{Address: tok, Topics: []common.Hash{topicTransfer, h(alice)}, Data: w(1)}, // malformed: ignored
		{Address: tok},
	}
	ev := ParseLogs(logs)
	if len(ev.Logs) != len(logs) {
		t.Fatalf("logs %d", len(ev.Logs))
	}
	tr := ev.Transfers
	if len(tr) != 7 {
		t.Fatalf("transfers = %d: %+v", len(tr), tr)
	}
	if tr[0].Asset.Kind != models.AssetERC20 || tr[0].Amount != "1000" || tr[0].From != alice.Hex() || tr[0].To != bob.Hex() || *tr[0].LogIndex != 0 {
		t.Fatalf("erc20 %+v", tr[0])
	}
	if tr[1].Asset.Kind != models.AssetERC721 || tr[1].Asset.TokenID != "42" {
		t.Fatalf("erc721 %+v", tr[1])
	}
	if tr[2].Asset.Kind != models.AssetERC1155 || tr[2].Asset.TokenID != "3" || tr[2].Amount != "4" || tr[2].From != alice.Hex() {
		t.Fatalf("1155 single %+v", tr[2])
	}
	if tr[3].Asset.TokenID != "7" || tr[3].Amount != "10" || tr[4].Asset.TokenID != "8" || tr[4].Amount != "20" {
		t.Fatalf("1155 batch %+v %+v", tr[3], tr[4])
	}
	if tr[5].From != (common.Address{}).Hex() || tr[5].To != alice.Hex() || tr[6].To != (common.Address{}).Hex() {
		t.Fatalf("weth %+v %+v", tr[5], tr[6])
	}
	if len(ev.Approvals) != 2 || ev.Approvals[0].Amount != "5" || !*ev.Approvals[1].Approved {
		t.Fatalf("approvals %+v", ev.Approvals)
	}
}

func TestParseLogsBoundsAndMalformedBatch(t *testing.T) {
	huge := append(append(w(64), w(96)...), w(1_000_000)...)
	ev := ParseLogs([]RawLog{{Address: tok, Topics: []common.Hash{topicTransferBatch, h(bob), h(alice), h(bob)}, Data: huge}})
	if len(ev.Transfers) != 0 {
		t.Fatal("malformed batch must be ignored")
	}
	many := make([]RawLog, MaxLogs+5)
	if ev := ParseLogs(many); !ev.Truncated || len(ev.Logs) != MaxLogs {
		t.Fatal("log cap")
	}
}

func TestConvertTraceDropsRevertedEffects(t *testing.T) {
	v := func(n int64) *hexutil.Big { return (*hexutil.Big)(big.NewInt(n)) }
	root := RawFrame{Type: "CALL", From: alice, To: &bob, Value: v(10), Calls: []RawFrame{
		{Type: "CALL", From: bob, To: &tok, Value: v(3), Logs: []RawLog{{Address: tok}}},
		{Type: "CALL", From: bob, To: &alice, Value: v(5), Error: "execution reverted", Calls: []RawFrame{
			{Type: "CALL", From: alice, To: &tok, Value: v(1), Logs: []RawLog{{Address: alice}}},
		}},
		{Type: "DELEGATECALL", From: bob, To: &tok, Value: v(10)},
	}}
	ct := ConvertTrace(root)
	if len(ct.NativeTransfers) != 2 || ct.NativeTransfers[0].Amount != "10" || ct.NativeTransfers[1].Amount != "3" {
		t.Fatalf("native transfers %+v", ct.NativeTransfers)
	}
	if len(ct.Logs) != 1 || ct.Logs[0].Address != tok {
		t.Fatalf("logs from reverted frames must be dropped: %+v", ct.Logs)
	}
	if len(ct.Root.Calls) != 3 || ct.Root.Calls[1].Error == "" || ct.Root.Value != "10" {
		t.Fatalf("%+v", ct.Root)
	}
}

func TestConvertTraceCapsFramesAndIO(t *testing.T) {
	root := RawFrame{Type: "CALL", Input: make([]byte, 10_000)}
	for i := 0; i < MaxTraceFrames+10; i++ {
		root.Calls = append(root.Calls, RawFrame{Type: "STATICCALL"})
	}
	ct := ConvertTrace(root)
	if !ct.Truncated || len(ct.Root.Calls) >= MaxTraceFrames+10 {
		t.Fatal("frame cap")
	}
	if len(ct.Root.Input) != 2+2*maxFrameIOBytes {
		t.Fatalf("input not clipped: %d", len(ct.Root.Input))
	}
}

func TestDecodeRevert(t *testing.T) {
	errString := hexutil.MustDecode("0x08c379a0" +
		"0000000000000000000000000000000000000000000000000000000000000020" +
		"0000000000000000000000000000000000000000000000000000000000000007" +
		"4558504952454400000000000000000000000000000000000000000000000000")
	cases := map[string]string{
		"":         "",
		"error":    "EXPIRED",
		"panic":    "panic 0x11 (arithmetic overflow or underflow)",
		"custom":   "custom error 0xdeadbeef",
		"short":    "revert data 0x0102",
		"bad":      "Error(string) with malformed payload",
		"badpanic": "panic 0x99",
	}
	inputs := map[string][]byte{
		"": nil, "error": errString,
		"panic":    append(hexutil.MustDecode("0x4e487b71"), w(0x11)...),
		"custom":   hexutil.MustDecode("0xdeadbeef00"),
		"short":    {1, 2},
		"bad":      append(hexutil.MustDecode("0x08c379a0"), append(w(1<<40), w(1)...)...),
		"badpanic": append(hexutil.MustDecode("0x4e487b71"), w(0x99)...),
	}
	for name, want := range cases {
		if got := DecodeRevert(inputs[name]); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	if got := revertDataFromRPCError([]byte(`"0x0102"`)); len(got) != 2 {
		t.Fatal("rpc error data")
	}
	if revertDataFromRPCError([]byte(`{"x":1}`)) != nil {
		t.Fatal("non-hex data")
	}
}

func TestFeeNotes(t *testing.T) {
	tx := &models.Transaction{MaxFeePerGas: big.NewInt(5)}
	if len(feeNotes(tx, models.BlockInfo{BaseFee: "10", Number: 1})) != 1 {
		t.Fatal("low fee cap must be noted")
	}
	if len(feeNotes(tx, models.BlockInfo{BaseFee: "3"})) != 0 || len(feeNotes(&models.Transaction{}, models.BlockInfo{BaseFee: "3"})) != 0 {
		t.Fatal("no note expected")
	}
}
