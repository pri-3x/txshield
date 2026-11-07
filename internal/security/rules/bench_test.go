package rules

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/pri-3x/txshield/pkg/models"
)

// Benchmarks for the full built-in rule set (29 rules) on representative
// analysis contexts. Methodology: docs/benchmarks.md.

func benchEngine(b *testing.B) *Engine {
	b.Helper()
	eng, err := NewEngine(time.Second, Default(Config{})...)
	if err != nil {
		b.Fatal(err)
	}
	return eng
}

func BenchmarkRulesERC20Transfer(b *testing.B) {
	t := &testing.T{}
	ac := ctxFor(t, usdc, 0, cd(t, "transfer(address,uint256)", attacker, big.NewInt(1)))
	eng := benchEngine(b)
	b.ReportAllocs()
	for b.Loop() {
		eng.Run(context.Background(), ac)
	}
}

func BenchmarkRulesDrainerWithSimulation(b *testing.B) {
	t := &testing.T{}
	transfers := []models.AssetTransfer{
		erc20(usdc, user, attacker, "1000"),
		erc20(dai, user, attacker, "5"),
		{Asset: models.AssetRef{Kind: models.AssetERC721, Address: pool.Hex(), TokenID: "7"}, From: user.Hex(), To: attacker.Hex(), Amount: "1"},
	}
	trace := &models.CallFrame{Type: "CALL", From: user.Hex(), To: drainer.Hex(), Calls: []models.CallFrame{
		{Type: "CALL", From: drainer.Hex(), To: usdc.Hex()}, {Type: "CALL", From: drainer.Hex(), To: dai.Hex()}, {Type: "CALL", From: drainer.Hex(), To: pool.Hex()},
	}}
	ac := ctxFor(t, drainer, 1e15, cd(t, "claim()"), sim(transfers, nil, trace), list(models.ReputationBlocked, drainer))
	eng := benchEngine(b)
	b.ReportAllocs()
	for b.Loop() {
		eng.Run(context.Background(), ac)
	}
}
