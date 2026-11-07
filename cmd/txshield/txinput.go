package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pri-3x/txshield/internal/evm"
	"github.com/pri-3x/txshield/internal/simulator"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

// txInput holds the transaction flags shared by analyze and simulate.
type txInput struct {
	chain, from, to, value, data, block, file *string
}

func addTxFlags(fs *flag.FlagSet) *txInput {
	return &txInput{
		chain: fs.String("chain", "ethereum", "chain name or numeric chain ID"),
		from:  fs.String("from", "", "sender address"),
		to:    fs.String("to", "", "target address (omit for contract creation)"),
		value: fs.String("value", "0", "native value in wei (decimal or 0x-hex)"),
		data:  fs.String("data", "", "calldata as 0x-hex, or '-' to read it from stdin"),
		block: fs.String("block", "", "block to analyze against: latest (default), safe, finalized, a number, or a hash"),
		file:  fs.String("tx", "", "JSON file with the transaction (chainId, from, to, value, data, gas, ...); overrides the other transaction flags"),
	}
}

// parse builds a validated transaction. A --tx file takes precedence; its
// chainId must match --chain when both are given.
func (in *txInput) parse(fs *flag.FlagSet) (*models.Transaction, evm.Chain, error) {
	ch, err := evm.ResolveChain(*in.chain)
	if err != nil {
		return nil, evm.Chain{}, txerrors.New(txerrors.KindInvalidInput, "bad_chain", err.Error())
	}
	var req models.TransactionRequest
	if *in.file != "" {
		raw, err := readLimited(*in.file, 4*cliMaxCalldataBytes)
		if err != nil {
			return nil, ch, txerrors.New(txerrors.KindInvalidInput, "bad_tx_file", err.Error())
		}
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			return nil, ch, txerrors.New(txerrors.KindInvalidInput, "bad_tx_file", "transaction file: "+err.Error())
		}
		chainSet := false
		fs.Visit(func(f *flag.Flag) { chainSet = chainSet || f.Name == "chain" })
		switch {
		case req.ChainID == 0:
			req.ChainID = ch.ID
		case chainSet && req.ChainID != ch.ID:
			return nil, ch, txerrors.New(txerrors.KindInvalidInput, "chain_conflict", fmt.Sprintf("--chain is %d but the transaction file says %d", ch.ID, req.ChainID))
		default:
			if ch, err = evm.ResolveChain(fmt.Sprint(req.ChainID)); err != nil {
				return nil, ch, txerrors.New(txerrors.KindInvalidInput, "bad_chain", err.Error())
			}
		}
	} else {
		data := *in.data
		if data == "-" {
			b, err := io.ReadAll(io.LimitReader(os.Stdin, 2*cliMaxCalldataBytes+16))
			if err != nil {
				return nil, ch, err
			}
			data = strings.TrimSpace(string(b))
		}
		req = models.TransactionRequest{ChainID: ch.ID, From: *in.from, To: *in.to, Value: models.Quantity(*in.value), Data: data}
	}
	if *in.block != "" {
		req.Block = *in.block
	}
	tx, err := models.ParseTransaction(req, models.ParseLimits{MaxCalldataBytes: cliMaxCalldataBytes})
	return tx, ch, err
}

// backends are the chain-dependent components built from --rpc.
type backends struct {
	registry  *evm.Registry
	inspector interfaces.ContractInspector
	simulator interfaces.Simulator
	close     func()
}

// buildBackends wires chain access. With no RPC URL everything stays nil
// (offline mode). The CLI user is the operator, so --rpc is trusted; the
// endpoint's chain ID is still verified against the transaction's chain.
func buildBackends(rpcURL string, chainID uint64, simKind, anvilPath string) (*backends, error) {
	b := &backends{close: func() {}}
	if rpcURL == "" {
		if simKind != "" && simKind != "none" {
			return nil, fmt.Errorf("--simulator %s needs --rpc", simKind)
		}
		return b, nil
	}
	b.registry = evm.NewRegistry(map[uint64]string{chainID: rpcURL}, evm.Options{})
	b.inspector = evm.NewInspector(b.registry, 0)
	switch simKind {
	case "", "anvil":
		a := simulator.NewAnvil(b.registry, simulator.AnvilOptions{Path: anvilPath, Workers: 1})
		b.simulator = a
		b.close = a.Close
	case "rpc-trace":
		b.simulator = simulator.NewRPCTrace(b.registry, 0)
	case "none":
	default:
		return nil, fmt.Errorf("--simulator must be anvil, rpc-trace, or none")
	}
	return b, nil
}

// exitFor maps an error to a CLI exit code.
func exitFor(err error) int {
	switch txerrors.KindOf(err) {
	case txerrors.KindInvalidInput, txerrors.KindPayloadTooLarge, txerrors.KindUnsupported, txerrors.KindNotFound:
		return ExitUsage
	default:
		return ExitError
	}
}
