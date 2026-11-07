package decoder

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// Well-known selectors observed on mainnet. These pin both the signature
// parser's canonicalization and the built-in signature strings.
var knownSelectors = map[string]string{
	"transfer(address,uint256)":                                                 "0xa9059cbb",
	"approve(address,uint256)":                                                  "0x095ea7b3",
	"transferFrom(address,address,uint256)":                                     "0x23b872dd",
	"increaseAllowance(address,uint256)":                                        "0x39509351",
	"setApprovalForAll(address,bool)":                                           "0xa22cb465",
	"safeTransferFrom(address,address,uint256)":                                 "0x42842e0e",
	"safeTransferFrom(address,address,uint256,bytes)":                           "0xb88d4fde",
	"safeTransferFrom(address,address,uint256,uint256,bytes)":                   "0xf242432a",
	"safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)":          "0x2eb2c2d6",
	"permit(address,address,uint256,uint256,uint8,bytes32,bytes32)":             "0xd505accf",
	"permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)":        "0x8fcbaf0c",
	"approve(address,address,uint160,uint48)":                                   "0x87517c45",
	"permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)":   "0x2b67b570",
	"permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)": "0x2a2d80d1",
	"transferFrom(address,address,uint160,address)":                             "0x36c78516",
	"deposit()":         "0xd0e30db0",
	"withdraw(uint256)": "0x2e1a7d4d",
	"swapExactTokensForTokens(uint256,uint256,address[],address,uint256)":                        "0x38ed1739",
	"swapExactETHForTokens(uint256,address[],address,uint256)":                                   "0x7ff36ab5",
	"swapExactTokensForETH(uint256,uint256,address[],address,uint256)":                           "0x18cbafe5",
	"exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))":         "0x414bf389",
	"exactInput((bytes,address,uint256,uint256,uint256))":                                        "0xc04b8d59",
	"exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))":                 "0x04e45aaf",
	"exactInput((bytes,address,uint256,uint256))":                                                "0xb858183f",
	"execute(bytes,bytes[],uint256)":                                                             "0x3593564c",
	"execute(bytes,bytes[])":                                                                     "0x24856bc3",
	"multicall(bytes[])":                                                                         "0xac9650d8",
	"multicall(uint256,bytes[])":                                                                 "0x5ae401dc",
	"aggregate((address,bytes)[])":                                                               "0x252dba42",
	"aggregate3((address,bool,bytes)[])":                                                         "0x82ad56cb",
	"aggregate3Value((address,bool,uint256,bytes)[])":                                            "0x174dea71",
	"transferOwnership(address)":                                                                 "0xf2fde38b",
	"upgradeTo(address)":                                                                         "0x3659cfe6",
	"upgradeToAndCall(address,bytes)":                                                            "0x4f1ef286",
	"execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)": "0x6a761202",
	"flashLoanSimple(address,address,uint256,bytes,uint16)":                                      "0x42b0b77c",
	"flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)":                      "0xab9c4b5d",
	"flashLoan(address,address[],uint256[],bytes)":                                               "0x5c38449e",
	"flash(address,uint256,uint256,bytes)":                                                       "0x490e6cbc",
	"flashLoan(address,address,uint256,bytes)":                                                   "0x5cffe9de",
	"swap(uint256,uint256,address,bytes)":                                                        "0x022c0d9f",
}

func TestBuiltinSelectors(t *testing.T) {
	bySig := map[string]*Entry{}
	for _, e := range Builtin().Entries() {
		bySig[e.Signature] = e
		// Selector must equal keccak256(canonical signature)[:4].
		want := "0x" + strings.ToLower(crypto.Keccak256Hash([]byte(e.Signature)).Hex()[2:10])
		if e.Selector() != want {
			t.Errorf("%s: selector %s != keccak %s", e.Signature, e.Selector(), want)
		}
	}
	for sig, sel := range knownSelectors {
		e, ok := bySig[sig]
		if !ok {
			t.Errorf("built-in registry missing %s", sig)
			continue
		}
		if e.Selector() != sel {
			t.Errorf("%s: selector = %s, want %s", sig, e.Selector(), sel)
		}
	}
}

func TestDuplicateSignatureRejected(t *testing.T) {
	_, err := newRegistry([]spec{
		{standard: "a", sig: "approve(address spender, uint256 amount)"},
		{standard: "b", sig: "approve(address to, uint256 tokenId)"},
	})
	if err == nil {
		t.Fatal("identical canonical signatures must be registered once")
	}
}

func TestParseSignature(t *testing.T) {
	cases := map[string]string{
		"foo()":                                          "foo()",
		"foo(uint x, int, byte b)":                       "foo(uint256,int256,bytes1)",
		"foo(address[2][] a, bytes calldata d)":          "foo(address[2][],bytes)",
		"foo(tuple(address a, (uint8 x)[] inner) t)":     "foo((address,(uint8)[]))",
		"  foo ( (address,bool)[3] , string memory s ) ": "foo((address,bool)[3],string)",
	}
	for in, want := range cases {
		m, err := ParseSignature(in)
		if err != nil {
			t.Errorf("ParseSignature(%q): %v", in, err)
			continue
		}
		if m.Sig != want {
			t.Errorf("ParseSignature(%q).Sig = %q, want %q", in, m.Sig, want)
		}
	}
	for _, bad := range []string{"", "(uint256)", "foo", "foo(uint256", "foo(uint256))", "foo(notatype)", "foo(uint256[)", "foo(uint7)"} {
		if _, err := ParseSignature(bad); err == nil {
			t.Errorf("ParseSignature(%q) expected error", bad)
		}
	}
}
