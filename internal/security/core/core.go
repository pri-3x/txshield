// Package core holds helpers shared by TxShield's security modules: walking
// the decoded call tree with execution context, reading decoded parameters,
// collecting involved addresses, and building findings consistently.
package core

import (
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/txshield/txshield/pkg/models"
)

// Frame is a decoded call together with its execution context.
type Frame struct {
	Call *models.DecodedCall
	// Self is the address whose storage/balance context executes the call:
	// the target for CALLs; the parent's context for DELEGATECALLs,
	// self-multicalls, and router commands.
	Self common.Address
	// Sender is msg.sender inside the call.
	Sender common.Address
	Path   string
	Depth  int
}

// Walk visits every decoded call depth-first, tracking msg.sender and the
// executing context. For contract creation only the root is visited.
func Walk(tx *models.Transaction, root *models.DecodedCall, fn func(Frame)) {
	if root == nil {
		return
	}
	var self common.Address
	if tx.To != nil {
		self = *tx.To
	}
	walk(Frame{Call: root, Self: self, Sender: tx.From, Path: "root"}, fn)
}

func walk(f Frame, fn func(Frame)) {
	fn(f)
	for i := range f.Call.Children {
		c := &f.Call.Children[i]
		child := Frame{Call: c, Depth: f.Depth + 1, Path: f.Path + " > " + c.Label}
		switch c.CallType {
		case models.CallTypeCall:
			child.Sender = f.Self
			child.Self = common.HexToAddress(c.Target)
		default: // delegatecall, self-multicall, router command
			child.Sender = f.Sender
			child.Self = f.Self
		}
		walk(child, fn)
	}
}

// Param returns the value of a top-level decoded parameter.
func Param(c *models.DecodedCall, name string) (any, bool) {
	return field(c.Params, name)
}

// Field returns a named field of a rendered tuple value.
func Field(v any, name string) (any, bool) {
	fields, ok := v.([]models.DecodedParam)
	if !ok {
		return nil, false
	}
	return field(fields, name)
}

func field(ps []models.DecodedParam, name string) (any, bool) {
	for _, p := range ps {
		if p.Name == name {
			return p.Value, true
		}
	}
	return nil, false
}

// AsAddress converts a rendered address value.
func AsAddress(v any) (common.Address, bool) {
	s, ok := v.(string)
	if !ok || !common.IsHexAddress(s) {
		return common.Address{}, false
	}
	return common.HexToAddress(s), true
}

// AsBig converts a rendered integer value (decimal string).
func AsBig(v any) (*big.Int, bool) {
	s, ok := v.(string)
	if !ok {
		return nil, false
	}
	b, ok := new(big.Int).SetString(s, 10)
	return b, ok
}

// AsBool converts a rendered bool value.
func AsBool(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

// MaxUint256 and MaxUint160 are the sentinel "unlimited" amounts used by
// ERC-20 and Permit2 respectively.
var (
	MaxUint256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	MaxUint160 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
)

// Role describes how an address appears in a transaction.
type Role string

const (
	RoleSender    Role = "sender"
	RoleTarget    Role = "target"
	RoleSpender   Role = "spender"
	RoleRecipient Role = "recipient"
	RoleToken     Role = "token"
	RoleParam     Role = "parameter"
	RoleTraced    Role = "traced"
)

// AddressRoles maps every address in a transaction to the roles it plays.
type AddressRoles map[common.Address]map[Role]bool

func (a AddressRoles) add(addr common.Address, r Role) {
	if addr == (common.Address{}) {
		return
	}
	if a[addr] == nil {
		a[addr] = map[Role]bool{}
	}
	a[addr][r] = true
}

// Roles returns the roles of addr as a sorted, comma-separated string.
func (a AddressRoles) Roles(addr common.Address) string {
	order := []Role{RoleTarget, RoleSpender, RoleRecipient, RoleToken, RoleParam, RoleTraced, RoleSender}
	var out []string
	for _, r := range order {
		if a[addr][r] {
			out = append(out, string(r))
		}
	}
	return strings.Join(out, ",")
}

// CollectAddresses gathers the sender, every call target, every address
// parameter (at any nesting level), approval spenders/tokens, and, when a
// trace is available, every traced call target.
func CollectAddresses(tx *models.Transaction, root *models.DecodedCall, approvals []models.ApprovalGrant, sim *models.SimulationResult) AddressRoles {
	roles := AddressRoles{}
	roles.add(tx.From, RoleSender)
	Walk(tx, root, func(f Frame) {
		if f.Call.Target != "" && f.Call.CallType != models.CallTypeRouterCommand {
			roles.add(common.HexToAddress(f.Call.Target), RoleTarget)
		}
		for _, p := range f.Call.Params {
			collectParam(roles, p)
		}
		if f.Call.Kind == models.CallUnknown && f.Call.RawData != "" {
			if raw, err := hexutil.Decode(f.Call.RawData); err == nil && len(raw) > 4 {
				for _, a := range AddressWords(raw[4:]) {
					roles.add(a, RoleParam)
				}
			}
		}
	})
	for _, g := range approvals {
		roles.add(common.HexToAddress(g.Spender), RoleSpender)
		if g.Token != "" {
			roles.add(common.HexToAddress(g.Token), RoleToken)
		}
	}
	if sim != nil && sim.Trace != nil {
		WalkTrace(sim.Trace, func(fr *models.CallFrame, _ []*models.CallFrame) {
			if common.IsHexAddress(fr.To) {
				roles.add(common.HexToAddress(fr.To), RoleTraced)
			}
		})
	}
	return roles
}

// collectParam records address-typed values, including those inside
// derived parameters such as decoded Uniswap paths (their tokens are part of
// what the user asked for).
func collectParam(roles AddressRoles, p models.DecodedParam) {
	switch v := p.Value.(type) {
	case string:
		if strings.HasPrefix(p.Type, "address") {
			if a, ok := AsAddress(v); ok {
				roles.add(a, roleForName(p.Name))
			}
		}
	case []any:
		for _, item := range v {
			collectParam(roles, models.DecodedParam{Name: p.Name, Type: elemType(p.Type), Value: item})
		}
	case []models.DecodedParam:
		for _, f := range v {
			collectParam(roles, f)
		}
	}
}

func elemType(t string) string {
	if i := strings.LastIndexByte(t, '['); i > 0 {
		return t[:i]
	}
	return t
}

func roleForName(name string) Role {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "spender") || strings.Contains(n, "operator"):
		return RoleSpender
	case n == "to" || strings.Contains(n, "recipient") || strings.Contains(n, "receiver"):
		return RoleRecipient
	case strings.Contains(n, "token") || n == "asset" || n == "path":
		return RoleToken
	default:
		return RoleParam
	}
}

// AddressWords returns address-shaped 32-byte words in ABI-encoded data: 12
// zero bytes followed by a 20-byte value of at least 2^128. The lower bound
// keeps ordinary amounts and small IDs from being mistaken for addresses.
// Used for calls TxShield cannot decode, where arguments are opaque.
func AddressWords(args []byte) []common.Address {
	var out []common.Address
	for off := 0; off+32 <= len(args); off += 32 {
		w := args[off : off+32]
		zero := true
		for _, b := range w[:12] {
			if b != 0 {
				zero = false
				break
			}
		}
		if zero && (w[12] != 0 || w[13] != 0 || w[14] != 0 || w[15] != 0) {
			out = append(out, common.BytesToAddress(w[12:]))
		}
	}
	return out
}

// WalkTrace visits every frame of a call trace with its ancestor stack.
func WalkTrace(root *models.CallFrame, fn func(f *models.CallFrame, ancestors []*models.CallFrame)) {
	var rec func(f *models.CallFrame, anc []*models.CallFrame)
	rec = func(f *models.CallFrame, anc []*models.CallFrame) {
		fn(f, anc)
		next := append(anc[:len(anc):len(anc)], f)
		for i := range f.Calls {
			rec(&f.Calls[i], next)
		}
	}
	rec(root, nil)
}

// NewFinding creates a finding pre-filled from rule metadata. The
// fingerprint is the rule ID plus the distinguishing keys (lowercased), so the
// same issue reported twice collapses during scoring.
func NewFinding(meta models.RuleMetadata, keys ...string) models.Finding {
	fp := meta.ID
	if len(keys) > 0 {
		fp += ":" + strings.ToLower(strings.Join(keys, "|"))
	}
	return models.Finding{
		RuleID:             meta.ID,
		Title:              meta.Name,
		Description:        meta.Description,
		Category:           meta.Category,
		Severity:           meta.DefaultSeverity,
		Confidence:         meta.DefaultConfidence,
		Source:             models.SourceFact,
		Mitigation:         meta.Mitigation,
		FalsePositiveNotes: meta.FalsePositiveNotes,
		Fingerprint:        fp,
	}
}

// Evidence is a shorthand constructor.
func Evidence(typ, detail string, src models.EvidenceSource, data map[string]string) models.Evidence {
	return models.Evidence{Type: typ, Detail: detail, Source: src, Data: data}
}
