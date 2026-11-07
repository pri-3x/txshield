package decoder

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// ParseSignature parses a human-readable Solidity function signature into an
// abi.Method. Parameter names are optional; tuples are written either as
// "(type name, ...)" or "tuple(type name, ...)", and may carry array suffixes.
//
//	approve(address spender, uint256 amount)
//	exactInputSingle((address tokenIn, address tokenOut, uint24 fee) params)
//	aggregate3((address target, bool allowFailure, bytes callData)[] calls)
//
// Unnamed parameters are named argN so that tuple components map to valid
// Go struct fields (a requirement of go-ethereum's ABI package).
func ParseSignature(sig string) (abi.Method, error) {
	p := &sigParser{s: strings.TrimSpace(sig)}
	name := p.ident()
	if name == "" {
		return abi.Method{}, fmt.Errorf("signature %q: missing function name", sig)
	}
	if !p.consume('(') {
		return abi.Method{}, fmt.Errorf("signature %q: expected '(' after name", sig)
	}
	params, err := p.params()
	if err != nil {
		return abi.Method{}, fmt.Errorf("signature %q: %w", sig, err)
	}
	p.skipSpace()
	if p.pos != len(p.s) {
		return abi.Method{}, fmt.Errorf("signature %q: unexpected trailing input at offset %d", sig, p.pos)
	}

	args := make(abi.Arguments, 0, len(params))
	for i, m := range params {
		t, err := abi.NewType(m.Type, "", m.Components)
		if err != nil {
			return abi.Method{}, fmt.Errorf("signature %q: parameter %d: %w", sig, i, err)
		}
		args = append(args, abi.Argument{Name: m.Name, Type: t})
	}
	// State mutability is unknown from a bare signature and irrelevant to
	// decoding; it is never used to make safety claims.
	return abi.NewMethod(name, name, abi.Function, "payable", false, true, args, nil), nil
}

type sigParser struct {
	s   string
	pos int
}

func (p *sigParser) skipSpace() {
	for p.pos < len(p.s) && unicode.IsSpace(rune(p.s[p.pos])) {
		p.pos++
	}
}

func (p *sigParser) consume(c byte) bool {
	p.skipSpace()
	if p.pos < len(p.s) && p.s[p.pos] == c {
		p.pos++
		return true
	}
	return false
}

func (p *sigParser) ident() string {
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		if c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (p.pos > start && c >= '0' && c <= '9') {
			p.pos++
			continue
		}
		break
	}
	return p.s[start:p.pos]
}

// params parses a parameter list after '(' up to and including ')'.
func (p *sigParser) params() ([]abi.ArgumentMarshaling, error) {
	var out []abi.ArgumentMarshaling
	if p.consume(')') {
		return out, nil
	}
	for i := 0; ; i++ {
		m, err := p.param()
		if err != nil {
			return nil, err
		}
		if m.Name == "" {
			m.Name = fmt.Sprintf("arg%d", i)
		}
		out = append(out, m)
		if p.consume(',') {
			continue
		}
		if p.consume(')') {
			return out, nil
		}
		return nil, fmt.Errorf("expected ',' or ')' at offset %d", p.pos)
	}
}

func (p *sigParser) param() (abi.ArgumentMarshaling, error) {
	var m abi.ArgumentMarshaling
	p.skipSpace()
	if strings.HasPrefix(p.s[p.pos:], "tuple(") {
		p.pos += len("tuple")
	}
	if p.consume('(') {
		comps, err := p.params()
		if err != nil {
			return m, err
		}
		m.Components = comps
		m.Type = "tuple"
	} else {
		m.Type = p.ident()
		if m.Type == "" {
			return m, fmt.Errorf("expected type at offset %d", p.pos)
		}
		m.Type = canonicalBase(m.Type)
		if err := validateBase(m.Type); err != nil {
			return m, err
		}
	}
	// Array suffixes.
	for {
		p.skipSpace()
		if p.pos >= len(p.s) || p.s[p.pos] != '[' {
			break
		}
		end := strings.IndexByte(p.s[p.pos:], ']')
		if end < 0 {
			return m, fmt.Errorf("unterminated array suffix at offset %d", p.pos)
		}
		m.Type += p.s[p.pos : p.pos+end+1]
		p.pos += end + 1
	}
	// Optional data location / indexed keywords, then optional name.
	for {
		word := p.ident()
		switch word {
		case "memory", "calldata", "storage", "indexed":
			continue
		case "":
			return m, nil
		default:
			m.Name = word
			return m, nil
		}
	}
}

// canonicalBase expands Solidity aliases to canonical ABI types, since the
// selector is computed from the canonical form.
func canonicalBase(t string) string {
	switch t {
	case "uint":
		return "uint256"
	case "int":
		return "int256"
	case "byte":
		return "bytes1"
	}
	return t
}

// validateBase rejects elementary types that are not valid Solidity ABI types
// (go-ethereum accepts some, such as uint7, that no compiler emits).
func validateBase(t string) error {
	switch t {
	case "address", "bool", "string", "bytes", "function":
		return nil
	}
	for _, prefix := range []string{"uint", "int"} {
		if rest, ok := strings.CutPrefix(t, prefix); ok {
			n, err := strconv.Atoi(rest)
			if err != nil || n < 8 || n > 256 || n%8 != 0 {
				return fmt.Errorf("invalid integer type %q", t)
			}
			return nil
		}
	}
	if rest, ok := strings.CutPrefix(t, "bytes"); ok {
		n, err := strconv.Atoi(rest)
		if err != nil || n < 1 || n > 32 {
			return fmt.Errorf("invalid fixed bytes type %q", t)
		}
		return nil
	}
	return fmt.Errorf("unknown type %q", t)
}
