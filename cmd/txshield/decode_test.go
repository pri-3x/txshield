package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/txshield/txshield/pkg/models"
)

const approveMax = "0x095ea7b30000000000000000000000002222222222222222222222222222222222222222ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestDecodeText(t *testing.T) {
	code, out, errs := runCLI("decode", "--to", "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", "--data", approveMax)
	if code != ExitOK {
		t.Fatalf("code %d: %s", code, errs)
	}
	for _, want := range []string{"approve(address,uint256)", "erc20|erc721", "spender (address): 0x2222222222222222222222222222222222222222", "target: 0x3fC9"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestDecodeJSONWithoutTarget(t *testing.T) {
	code, out, errs := runCLI("decode", "--json", "--data", approveMax)
	if code != ExitOK {
		t.Fatalf("code %d: %s", code, errs)
	}
	var c models.DecodedCall
	if err := json.Unmarshal([]byte(out), &c); err != nil {
		t.Fatal(err)
	}
	if c.Method != "approve" || c.Target != "" {
		t.Fatalf("%+v", c)
	}
}

func TestDecodeInvalidInput(t *testing.T) {
	for _, args := range [][]string{
		{"decode"},
		{"decode", "--data", "0xzz"},
		{"decode", "--data", approveMax, "--to", "0x123"},
		{"decode", "--data", approveMax, "--value", "-1"},
		{"decode", "--data", approveMax, "--abi", "/does/not/exist.json"},
	} {
		if code, _, _ := runCLI(args...); code != ExitUsage {
			t.Errorf("%v: code %d, want %d", args, code, ExitUsage)
		}
	}
}

func TestDecodeUserABIAndTerminalSanitizing(t *testing.T) {
	dir := t.TempDir()
	abiFile := filepath.Join(dir, "abi.json")
	abiJSON := `[{"type":"function","name":"setName","inputs":[{"name":"name","type":"string"}],"outputs":[],"stateMutability":"nonpayable"}]`
	if err := os.WriteFile(abiFile, []byte(abiJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	// setName("\x1b[2J evil\n") — ANSI clear-screen plus a newline.
	data := "0xc47f0027" +
		"0000000000000000000000000000000000000000000000000000000000000020" +
		"000000000000000000000000000000000000000000000000000000000000000a" +
		"1b5b324a206576696c0a00000000000000000000000000000000000000000000"
	code, out, errs := runCLI("decode", "--to", "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", "--abi", abiFile, "--data", data)
	if code != ExitOK {
		t.Fatalf("code %d: %s", code, errs)
	}
	if strings.Contains(out, "\x1b") {
		t.Fatalf("raw escape sequence reached the terminal: %q", out)
	}
	if !strings.Contains(out, `name (string): \u001b[2J evil\n`) || !strings.Contains(out, "user_abi") {
		t.Fatalf("unexpected output: %q", out)
	}

	if err := os.WriteFile(abiFile, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI("decode", "--to", "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", "--abi", abiFile, "--data", data); code != ExitUsage {
		t.Fatalf("bad ABI: code %d", code)
	}
}
