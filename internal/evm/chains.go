// Package evm contains chain metadata and (from Phase 4) the JSON-RPC client
// used for read-only chain access.
package evm

import (
	"fmt"
	"strconv"
	"strings"
)

// Chain is static metadata for a well-known EVM chain.
type Chain struct {
	ID          uint64
	Name        string // canonical CLI name
	DisplayName string
	NativeToken string
	Testnet     bool
}

// knownChains is intentionally small; any chain ID works if an RPC endpoint is
// configured. Names exist only for CLI convenience and report display.
var knownChains = []Chain{
	{ID: 1, Name: "ethereum", DisplayName: "Ethereum Mainnet", NativeToken: "ETH"},
	{ID: 10, Name: "optimism", DisplayName: "OP Mainnet", NativeToken: "ETH"},
	{ID: 56, Name: "bsc", DisplayName: "BNB Smart Chain", NativeToken: "BNB"},
	{ID: 137, Name: "polygon", DisplayName: "Polygon PoS", NativeToken: "POL"},
	{ID: 8453, Name: "base", DisplayName: "Base", NativeToken: "ETH"},
	{ID: 42161, Name: "arbitrum", DisplayName: "Arbitrum One", NativeToken: "ETH"},
	{ID: 31337, Name: "anvil", DisplayName: "Anvil (local)", NativeToken: "ETH", Testnet: true},
	{ID: 17000, Name: "holesky", DisplayName: "Holesky", NativeToken: "ETH", Testnet: true},
	{ID: 11155111, Name: "sepolia", DisplayName: "Sepolia", NativeToken: "ETH", Testnet: true},
}

var aliases = map[string]uint64{"mainnet": 1, "eth": 1, "op": 10, "arb": 42161, "matic": 137}

// ChainByID returns metadata for a known chain.
func ChainByID(id uint64) (Chain, bool) {
	for _, c := range knownChains {
		if c.ID == id {
			return c, true
		}
	}
	return Chain{}, false
}

// ResolveChain accepts a chain name, alias, or numeric ID. Unknown numeric IDs
// are accepted (returned with only ID set) because any EVM chain can be
// analyzed if an RPC endpoint is supplied.
func ResolveChain(s string) (Chain, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return Chain{}, fmt.Errorf("chain is required")
	}
	if id, err := strconv.ParseUint(s, 10, 64); err == nil {
		if id == 0 {
			return Chain{}, fmt.Errorf("chain ID must be > 0")
		}
		if c, ok := ChainByID(id); ok {
			return c, nil
		}
		return Chain{ID: id, Name: s, DisplayName: "Chain " + s}, nil
	}
	if id, ok := aliases[s]; ok {
		c, _ := ChainByID(id)
		return c, nil
	}
	for _, c := range knownChains {
		if c.Name == s {
			return c, nil
		}
	}
	return Chain{}, fmt.Errorf("unknown chain %q (use a numeric chain ID for unlisted chains)", s)
}
