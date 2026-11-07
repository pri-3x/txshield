package decoder

import (
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// Nested identifies how an entry's arguments embed further calls.
type Nested int

const (
	NestedNone Nested = iota
	// NestedSelfMulticall: bytes[] of calls executed against the same target
	// (Uniswap/ENS-style multicall, usually via DELEGATECALL to self).
	NestedSelfMulticall
	// NestedMulticall3: (target, [allowFailure], [value], callData)[] calls.
	NestedMulticall3
	// NestedUniversalRouter: execute(commands, inputs[, deadline]).
	NestedUniversalRouter
	// NestedSafeExec: Gnosis Safe execTransaction (to, value, data, operation).
	NestedSafeExec
	// NestedUpgradeAndCall: data delegatecalled into a new implementation.
	NestedUpgradeAndCall
)

// Entry is one known function signature.
type Entry struct {
	Method    abi.Method
	Signature string // canonical, e.g. "approve(address,uint256)"
	// Standard names the interface this signature belongs to. Multiple
	// standards sharing an identical signature are joined with "|" (e.g.
	// "erc20|erc721" for approve): calldata alone cannot tell them apart, so
	// later stages resolve the standard from chain state.
	Standard string
	Nested   Nested
	// ArgIndex locates nested-call arguments for Nested handlers that need it.
	ArgIndex []int
}

// Selector returns the 4-byte selector as 0x-hex.
func (e *Entry) Selector() string { return "0x" + hex.EncodeToString(e.Method.ID) }

// Registry maps 4-byte selectors to known signatures. It is immutable after
// construction and safe for concurrent use.
type Registry struct {
	bySelector map[[4]byte][]*Entry
	count      int
}

// spec is a registration request.
type spec struct {
	standard string
	sig      string
	nested   Nested
	argIndex []int
}

// NewRegistry builds a registry from specs. It rejects duplicate canonical
// signatures (they must be registered once with a combined standard).
func newRegistry(specs []spec) (*Registry, error) {
	r := &Registry{bySelector: map[[4]byte][]*Entry{}}
	seen := map[string]string{}
	for _, s := range specs {
		m, err := ParseSignature(s.sig)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[m.Sig]; dup {
			return nil, fmt.Errorf("signature %s registered twice (%s and %s)", m.Sig, prev, s.standard)
		}
		seen[m.Sig] = s.standard
		var sel [4]byte
		copy(sel[:], m.ID)
		r.bySelector[sel] = append(r.bySelector[sel], &Entry{
			Method: m, Signature: m.Sig, Standard: s.standard, Nested: s.nested, ArgIndex: s.argIndex,
		})
		r.count++
	}
	return r, nil
}

// Lookup returns all entries for a selector (more than one only on a true
// 4-byte collision between different signatures).
func (r *Registry) Lookup(sel [4]byte) []*Entry { return r.bySelector[sel] }

// Len returns the number of registered signatures.
func (r *Registry) Len() int { return r.count }

// Entries returns all entries sorted by signature (for docs and tests).
func (r *Registry) Entries() []*Entry {
	out := make([]*Entry, 0, r.count)
	for _, es := range r.bySelector {
		out = append(out, es...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Signature < out[j].Signature })
	return out
}

var builtin *Registry

func init() {
	r, err := newRegistry(builtinSpecs)
	if err != nil {
		// Built-in signatures are compile-time constants; failing here is a
		// programming error caught by tests.
		panic("decoder: invalid built-in registry: " + err.Error())
	}
	builtin = r
}

// Builtin returns the registry of signatures bundled with TxShield.
func Builtin() *Registry { return builtin }
