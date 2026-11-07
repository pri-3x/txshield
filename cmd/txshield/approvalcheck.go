package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/txshield/txshield/internal/evm"
	"github.com/txshield/txshield/internal/security/approvals"
	"github.com/txshield/txshield/internal/security/reputation"
	"github.com/txshield/txshield/pkg/interfaces"
	"github.com/txshield/txshield/pkg/models"
)

// PermissionState is one permission currently in force.
type PermissionState struct {
	Kind    models.ApprovalKind  `json:"kind"`
	Via     string               `json:"via"` // "token" or "permit2"
	State   models.ApprovalState `json:"state"`
	Active  bool                 `json:"active"`
	Unbound bool                 `json:"unlimited"`
}

// ApprovalCheckResult is the output of `txshield approval-check`.
type ApprovalCheckResult struct {
	ChainID          uint64                    `json:"chainId"`
	Block            uint64                    `json:"block"`
	Token            models.ContractInfo       `json:"token"`
	Owner            string                    `json:"owner"`
	Spender          models.ContractInfo       `json:"spender"`
	SpenderStatus    models.ReputationStatus   `json:"spenderReputation"`
	ReputationRecord []models.ReputationRecord `json:"reputationRecords"`
	Permissions      []PermissionState         `json:"permissions"`
	Notes            []string                  `json:"notes"`
	Risky            bool                      `json:"risky"`
}

func runApprovalCheck(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("approval-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	chain := fs.String("chain", "ethereum", "chain name or numeric chain ID")
	rpcURL := fs.String("rpc", "", "RPC endpoint (http/https), required")
	tokenS := fs.String("token", "", "token contract address")
	ownerS := fs.String("owner", "", "owner (your wallet) address")
	spenderS := fs.String("spender", "", "spender / operator address")
	blockS := fs.String("block", "latest", "block to read at")
	asJSON := fs.Bool("json", false, "print JSON")
	var lists stringList
	fs.Var(&lists, "reputation", "reputation list file (JSON); repeatable")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: txshield approval-check --rpc URL --token 0x... --owner 0x... --spender 0x... [flags]")
		fmt.Fprintln(stderr, "\nReads the permissions currently in force (ERC-20 allowance, ERC-721/1155 operator status, Permit2 allowance).")
		fmt.Fprintln(stderr, "Exit codes: 0 no risky active permission, 3 risky active permission, 1 could not read, 2 invalid input.")
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	ch, err := evm.ResolveChain(*chain)
	if err != nil {
		fmt.Fprintf(stderr, "approval-check: %v\n", err)
		return ExitUsage
	}
	addrs := map[string]common.Address{}
	for name, v := range map[string]string{"token": *tokenS, "owner": *ownerS, "spender": *spenderS} {
		a, err := models.ParseAddress(v)
		if err != nil {
			fmt.Fprintf(stderr, "approval-check: --%s: %v\n", name, err)
			return ExitUsage
		}
		addrs[name] = a
	}
	ref, err := models.ParseBlockRef(*blockS)
	if err != nil || *rpcURL == "" {
		fmt.Fprintln(stderr, "approval-check: --rpc is required and --block must be valid")
		return ExitUsage
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	reg := evm.NewRegistry(map[uint64]string{ch.ID: *rpcURL}, evm.Options{})
	client, err := reg.Client(ctx, ch.ID)
	if err != nil {
		printCLIError(stderr, "approval-check", err)
		return exitFor(err)
	}
	blk, err := client.ResolveBlock(ctx, ref)
	if err != nil {
		printCLIError(stderr, "approval-check", err)
		return exitFor(err)
	}
	insp := evm.NewInspector(reg, 16)
	token, err := insp.Inspect(ctx, ch.ID, addrs["token"], blk.Number)
	if err != nil {
		printCLIError(stderr, "approval-check", err)
		return exitFor(err)
	}
	spender, err := insp.Inspect(ctx, ch.ID, addrs["spender"], blk.Number)
	if err != nil {
		printCLIError(stderr, "approval-check", err)
		return exitFor(err)
	}
	res := ApprovalCheckResult{ChainID: ch.ID, Block: blk.Number, Token: *token, Owner: addrs["owner"].Hex(), Spender: *spender,
		SpenderStatus: models.ReputationUnknown, ReputationRecord: []models.ReputationRecord{}, Permissions: []PermissionState{}, Notes: []string{}}

	grant := models.ApprovalGrant{Token: token.Address, Contract: token.Address, Owner: res.Owner, Spender: spender.Address}
	isNFT := slices.Contains(token.Standards, "erc721") || slices.Contains(token.Standards, "erc1155")
	if !token.IsContract {
		res.Notes = append(res.Notes, "the token address has no contract code on this chain")
	}
	if isNFT {
		grant.Kind = models.ApprovalOperator
		st := approvals.ReadCurrent(ctx, client, grant, blk.Number)
		active := st.ApprovedForAll != nil && *st.ApprovedForAll
		res.Permissions = append(res.Permissions, PermissionState{Kind: grant.Kind, Via: "token", State: st, Active: active, Unbound: active})
	} else if token.IsContract {
		grant.Kind = models.ApprovalERC20
		st := approvals.ReadCurrent(ctx, client, grant, blk.Number)
		active := st.Error == "" && st.Amount != "" && st.Amount != "0"
		res.Permissions = append(res.Permissions, PermissionState{Kind: grant.Kind, Via: "token", State: st, Active: active, Unbound: st.Unlimited})
		if !slices.Contains(token.Standards, "erc20") {
			res.Notes = append(res.Notes, "the token's standard could not be confirmed; ERC-20 allowance was read")
		}
	}
	// Permit2 allowances are separate from the token's own allowance.
	if code, err := client.CodeAt(ctx, approvals.CanonicalPermit2, nil); err == nil && len(code) > 0 && !isNFT {
		g := grant
		g.Kind, g.Contract = models.ApprovalPermit2, approvals.CanonicalPermit2.Hex()
		st := approvals.ReadCurrent(ctx, client, g, blk.Number)
		active := st.Error == "" && st.Amount != "" && st.Amount != "0" && st.Expiration != nil && *st.Expiration > blk.Timestamp
		res.Permissions = append(res.Permissions, PermissionState{Kind: g.Kind, Via: "permit2", State: st, Active: active, Unbound: st.Unlimited})
	}

	if len(lists) > 0 {
		var providers []interfaces.ReputationProvider
		for _, p := range lists {
			lp, err := reputation.LoadListFile(p)
			if err != nil {
				fmt.Fprintf(stderr, "approval-check: %v\n", err)
				return ExitUsage
			}
			providers = append(providers, lp)
		}
		recs, warns := reputation.NewAggregator(0, providers...).LookupAll(ctx, ch.ID, []common.Address{addrs["spender"]})
		if r := recs[addrs["spender"]]; len(r) > 0 {
			res.ReputationRecord, res.SpenderStatus = r, reputation.Effective(r)
		}
		res.Notes = append(res.Notes, warns...)
	}

	anyActive := false
	for _, p := range res.Permissions {
		if !p.Active {
			continue
		}
		anyActive = true
		if p.Unbound {
			res.Risky = true
			res.Notes = append(res.Notes, fmt.Sprintf("active unlimited %s permission (%s): the spender can move all of this asset", p.Kind, p.Via))
		}
	}
	if anyActive && !spender.IsContract {
		res.Risky = true
		res.Notes = append(res.Notes, "the spender has no contract code (an account), a common phishing pattern")
	}
	if anyActive && (res.SpenderStatus == models.ReputationBlocked || res.SpenderStatus == models.ReputationSuspicious) {
		res.Risky = true
		res.Notes = append(res.Notes, "the spender is "+string(res.SpenderStatus)+" according to configured reputation sources: revoke this permission")
	}
	if !anyActive {
		res.Notes = append(res.Notes, "no active permission for this spender was found")
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		fmt.Fprintf(stdout, "Token %s (%v) at block %d\nOwner %s -> spender %s (contract: %v, reputation: %s)\n",
			res.Token.Address, res.Token.Standards, res.Block, res.Owner, res.Spender.Address, res.Spender.IsContract, res.SpenderStatus)
		for _, p := range res.Permissions {
			desc := string(p.State.Amount)
			switch {
			case p.State.Error != "":
				desc = clean(p.State.Error)
			case p.State.ApprovedForAll != nil:
				desc = fmt.Sprintf("approvedForAll=%v", *p.State.ApprovedForAll)
			case p.Unbound:
				desc = "UNLIMITED"
			}
			fmt.Fprintf(stdout, "  %-18s via %-7s active=%-5v %s\n", p.Kind, p.Via, p.Active, desc)
		}
		for _, n := range res.Notes {
			fmt.Fprintf(stdout, "  - %s\n", clean(n))
		}
	}
	if res.Risky {
		return ExitRiskHigh
	}
	return ExitOK
}
