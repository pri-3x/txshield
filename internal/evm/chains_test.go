package evm

import "testing"

func TestResolveChain(t *testing.T) {
	cases := map[string]uint64{
		"ethereum": 1, "Mainnet": 1, "sepolia": 11155111, "11155111": 11155111, "arb": 42161, "999999": 999999,
	}
	for in, want := range cases {
		c, err := ResolveChain(in)
		if err != nil || c.ID != want {
			t.Errorf("ResolveChain(%q) = %+v, %v; want %d", in, c, err, want)
		}
	}
	for _, in := range []string{"", "0", "notachain"} {
		if _, err := ResolveChain(in); err == nil {
			t.Errorf("ResolveChain(%q) expected error", in)
		}
	}
}
