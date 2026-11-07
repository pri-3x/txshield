package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pri-3x/txshield/internal/decoder"
	"github.com/pri-3x/txshield/internal/logging"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

const (
	cliMaxCalldataBytes = 1 << 20
	cliMaxABIBytes      = 4 << 20
	zeroAddress         = "0x0000000000000000000000000000000000000000"
)

func runDecode(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("decode", flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", "", "calldata as 0x-hex, or '-' to read it from stdin (required)")
	to := fs.String("to", "", "target contract address (optional; enables --abi matching and target display)")
	value := fs.String("value", "0", "native value in wei (decimal or 0x-hex)")
	abiPath := fs.String("abi", "", "path to a JSON ABI file for the target contract")
	asJSON := fs.Bool("json", false, "print JSON")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: txshield decode --data 0x... [--to 0x...] [--value wei] [--abi file.json] [--json]")
		fmt.Fprintln(stderr, "\nDecodes calldata offline (no RPC). Recognizing a function does not mean it is safe.")
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if *data == "-" {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 2*cliMaxCalldataBytes+16))
		if err != nil {
			fmt.Fprintf(stderr, "decode: reading stdin: %v\n", err)
			return ExitError
		}
		*data = strings.TrimSpace(string(b))
	}
	if *data == "" {
		fmt.Fprintln(stderr, "decode: --data is required")
		return ExitUsage
	}

	target := *to
	if target == "" {
		target = zeroAddress // placeholder; hidden in output
	}
	tx, err := models.ParseTransaction(models.TransactionRequest{
		ChainID: 1, From: zeroAddress, To: target, Value: models.Quantity(*value), Data: *data,
	}, models.ParseLimits{MaxCalldataBytes: cliMaxCalldataBytes})
	if err != nil {
		printCLIError(stderr, "decode", err)
		return ExitUsage
	}

	var opts interfaces.DecodeOptions
	if *abiPath != "" {
		f, err := os.Open(*abiPath)
		if err != nil {
			fmt.Fprintf(stderr, "decode: %v\n", err)
			return ExitUsage
		}
		opts.ABIJSON, err = io.ReadAll(io.LimitReader(f, cliMaxABIBytes+1))
		_ = f.Close()
		if err != nil {
			fmt.Fprintf(stderr, "decode: reading ABI: %v\n", err)
			return ExitError
		}
	}

	dec := decoder.New(decoder.Builtin(), decoder.Limits{MaxABIBytes: cliMaxABIBytes})
	call, err := dec.Decode(ctx, tx, opts)
	if err != nil {
		printCLIError(stderr, "decode", err)
		if txerrors.KindOf(err) == txerrors.KindInvalidInput || txerrors.KindOf(err) == txerrors.KindPayloadTooLarge {
			return ExitUsage
		}
		return ExitError
	}
	if *to == "" {
		call.Target = ""
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(call); err != nil {
			fmt.Fprintf(stderr, "decode: %v\n", err)
			return ExitError
		}
		return ExitOK
	}
	printCall(stdout, call, 0)
	return ExitOK
}

func printCLIError(w io.Writer, cmd string, err error) {
	if e, ok := txerrors.As(err); ok {
		fmt.Fprintf(w, "%s: %s\n", cmd, e.Message)
		for _, f := range e.Fields {
			fmt.Fprintf(w, "  --%s: %s\n", f.Field, f.Message)
		}
		return
	}
	fmt.Fprintf(w, "%s: %v\n", cmd, err)
}

// clean makes untrusted decoded text safe for a terminal (no ANSI escapes,
// control characters, or bidi overrides).
func clean(s string) string { return logging.Sanitize(s, 512) }

func printCall(w io.Writer, c *models.DecodedCall, depth int) {
	ind := strings.Repeat("  ", depth)
	head := string(c.Kind)
	switch {
	case c.Signature != "":
		head += "  " + c.Signature
	case c.Selector != "":
		head += "  selector " + c.Selector
	}
	var tags []string
	if c.Standard != "" {
		tags = append(tags, c.Standard)
	}
	if c.Source != "" && c.Source != models.DecodeNone {
		tags = append(tags, string(c.Source))
	}
	if c.CallType != "" && c.CallType != models.CallTypeCall {
		tags = append(tags, string(c.CallType))
	}
	if len(tags) > 0 {
		head += "  [" + strings.Join(tags, ", ") + "]"
	}
	if c.Label != "" {
		head = c.Label + ": " + head
	}
	fmt.Fprintln(w, ind+head)
	if c.Target != "" {
		fmt.Fprintf(w, "%s  target: %s\n", ind, c.Target)
	}
	if c.Value != "" {
		fmt.Fprintf(w, "%s  value:  %s wei\n", ind, c.Value)
	}
	for _, p := range c.Params {
		printParam(w, p, depth+1)
	}
	for _, cand := range c.Candidates {
		fmt.Fprintf(w, "%s  candidate: %s\n", ind, cand)
	}
	if c.RawData != "" {
		raw := c.RawData
		if len(raw) > 202 {
			raw = raw[:202] + fmt.Sprintf("... (%d bytes)", (len(c.RawData)-2)/2)
		}
		fmt.Fprintf(w, "%s  raw: %s\n", ind, raw)
	}
	for _, warn := range c.Warnings {
		fmt.Fprintf(w, "%s  ! %s\n", ind, clean(warn))
	}
	for i := range c.Children {
		printCall(w, &c.Children[i], depth+1)
	}
}

func printParam(w io.Writer, p models.DecodedParam, depth int) {
	ind := strings.Repeat("  ", depth)
	switch v := p.Value.(type) {
	case []models.DecodedParam:
		fmt.Fprintf(w, "%s%s (%s):\n", ind, clean(p.Name), p.Type)
		for _, f := range v {
			printParam(w, f, depth+1)
		}
	case []any:
		if len(v) == 0 {
			fmt.Fprintf(w, "%s%s (%s): []\n", ind, clean(p.Name), p.Type)
			return
		}
		fmt.Fprintf(w, "%s%s (%s):\n", ind, clean(p.Name), p.Type)
		for i, item := range v {
			printParam(w, models.DecodedParam{Name: fmt.Sprintf("[%d]", i), Type: elemType(p.Type), Value: item}, depth+1)
		}
	case string:
		fmt.Fprintf(w, "%s%s (%s): %s\n", ind, clean(p.Name), p.Type, clean(v))
	default:
		fmt.Fprintf(w, "%s%s (%s): %v\n", ind, clean(p.Name), p.Type, v)
	}
}

func elemType(t string) string {
	if i := strings.LastIndexByte(t, '['); i > 0 {
		return t[:i]
	}
	return t
}
