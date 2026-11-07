// Package approvals extracts token permission grants from a decoded
// transaction and provides the approval security rules.
//
// Extraction is factual (what the calldata grants, to whom, from whom).
// Judgement (is it risky?) lives in the rules, which document their false
// positives. An unlimited approval is not automatically malicious.
package approvals

import (
	"math/big"
	"slices"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pri-3x/txshield/internal/security/core"
	"github.com/pri-3x/txshield/pkg/models"
)

// Signatures recognized as grants (canonical form).
const (
	sigApprove           = "approve(address,uint256)"
	sigIncreaseAllowance = "increaseAllowance(address,uint256)"
	sigSetApprovalForAll = "setApprovalForAll(address,bool)"
	sigPermit2612        = "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"
	sigPermitDAI         = "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)"
	sigPermit2Approve    = "approve(address,address,uint160,uint48)"
	sigPermit2Single     = "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)"
	sigPermit2Batch      = "permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)"
)

// Extract returns every approval grant or revocation in the decoded call
// tree. contracts may be nil; it is used only to resolve whether an
// approve(address,uint256) targets an ERC-20 or an ERC-721.
func Extract(tx *models.Transaction, root *models.DecodedCall, contracts map[common.Address]*models.ContractInfo) []models.ApprovalGrant {
	var out []models.ApprovalGrant
	core.Walk(tx, root, func(f core.Frame) {
		c := f.Call
		if c.Kind != models.CallContract {
			return
		}
		add := func(g models.ApprovalGrant) {
			g.Via = f.Path
			g.OwnerIsSender = common.HexToAddress(g.Owner) == tx.From
			out = append(out, g)
		}
		switch {
		case c.Signature == sigApprove:
			extractApprove(f, contracts, add)
		case c.Signature == sigIncreaseAllowance:
			spender, _ := addrParam(c, "spender")
			amt, _ := bigParam(c, "addedValue")
			add(models.ApprovalGrant{
				Kind: models.ApprovalERC20Increase, Contract: f.Self.Hex(), Token: f.Self.Hex(),
				Owner: f.Sender.Hex(), Spender: spender.Hex(), Amount: models.QuantityFromBig(amt),
				Unlimited: isMax(amt, core.MaxUint256),
			})
		case c.Signature == sigSetApprovalForAll:
			op, _ := addrParam(c, "operator")
			v, _ := core.Param(c, "approved")
			approved, _ := core.AsBool(v)
			add(models.ApprovalGrant{
				Kind: models.ApprovalOperator, Contract: f.Self.Hex(), Token: f.Self.Hex(),
				Owner: f.Sender.Hex(), Spender: op.Hex(), Approved: &approved,
				Unlimited: approved, Revocation: !approved,
			})
		case c.Signature == sigPermit2612:
			owner, _ := addrParam(c, "owner")
			spender, _ := addrParam(c, "spender")
			amt, _ := bigParam(c, "value")
			deadline, _ := bigParam(c, "deadline")
			add(models.ApprovalGrant{
				Kind: models.ApprovalEIP2612, Contract: f.Self.Hex(), Token: f.Self.Hex(),
				Owner: owner.Hex(), Spender: spender.Hex(), Amount: models.QuantityFromBig(amt),
				Unlimited: isMax(amt, core.MaxUint256), Revocation: amt != nil && amt.Sign() == 0,
				Expiration: u64(deadline), Signed: true,
			})
		case c.Signature == sigPermitDAI:
			holder, _ := addrParam(c, "holder")
			spender, _ := addrParam(c, "spender")
			v, _ := core.Param(c, "allowed")
			allowed, _ := core.AsBool(v)
			expiry, _ := bigParam(c, "expiry")
			g := models.ApprovalGrant{
				Kind: models.ApprovalDAIPermit, Contract: f.Self.Hex(), Token: f.Self.Hex(),
				Owner: holder.Hex(), Spender: spender.Hex(), Unlimited: allowed, Revocation: !allowed, Signed: true,
			}
			if allowed {
				g.Amount = models.QuantityFromBig(core.MaxUint256)
			}
			if expiry != nil && expiry.Sign() != 0 { // 0 means the signature never expires
				g.Expiration = u64(expiry)
			}
			add(g)
		case c.Standard == "permit2" && c.Signature == sigPermit2Approve:
			token, _ := addrParam(c, "token")
			spender, _ := addrParam(c, "spender")
			amt, _ := bigParam(c, "amount")
			exp, _ := bigParam(c, "expiration")
			add(permit2Grant(models.ApprovalPermit2, f.Self.Hex(), token, f.Sender, spender, amt, exp, false))
		case c.Standard == "permit2" && (c.Signature == sigPermit2Single || c.Signature == sigPermit2Batch):
			owner, _ := addrParam(c, "owner")
			ps, _ := core.Param(c, "permitSingle")
			if ps == nil {
				ps, _ = core.Param(c, "permitBatch")
			}
			for _, g := range permit2FromStruct(ps, f.Self.Hex(), owner) {
				add(g)
			}
		case c.CallType == models.CallTypeRouterCommand && (c.Method == "PERMIT2_PERMIT" || c.Method == "PERMIT2_PERMIT_BATCH"):
			// The Universal Router forwards the permit to Permit2 with
			// msg.sender of execute() as the owner.
			ps, _ := core.Param(c, "permitSingle")
			if ps == nil {
				ps, _ = core.Param(c, "permitBatch")
			}
			for _, g := range permit2FromStruct(ps, "", f.Sender) {
				add(g)
			}
		}
	})
	return out
}

func extractApprove(f core.Frame, contracts map[common.Address]*models.ContractInfo, add func(models.ApprovalGrant)) {
	c := f.Call
	spender, _ := addrParam(c, "spender")
	amt, _ := bigParam(c, "amountOrTokenId")
	g := models.ApprovalGrant{Contract: f.Self.Hex(), Token: f.Self.Hex(), Owner: f.Sender.Hex(), Spender: spender.Hex()}
	std := ""
	if info := contracts[f.Self]; info != nil {
		switch {
		case slices.Contains(info.Standards, "erc721"):
			std = "erc721"
		case slices.Contains(info.Standards, "erc20"):
			std = "erc20"
		}
	}
	switch std {
	case "erc721":
		g.Kind = models.ApprovalNFTToken
		g.TokenID = models.QuantityFromBig(amt)
		g.Revocation = spender == (common.Address{})
	case "erc20":
		g.Kind = models.ApprovalERC20
		g.Amount = models.QuantityFromBig(amt)
		g.Unlimited = isMax(amt, core.MaxUint256)
		g.Revocation = amt != nil && amt.Sign() == 0
	default:
		g.Kind = models.ApprovalAmbiguous
		g.Amount = models.QuantityFromBig(amt)
		g.Unlimited = isMax(amt, core.MaxUint256)
		g.Revocation = (amt != nil && amt.Sign() == 0) || spender == (common.Address{})
	}
	add(g)
}

func permit2Grant(kind models.ApprovalKind, contract string, token, owner, spender common.Address, amt, exp *big.Int, signed bool) models.ApprovalGrant {
	return models.ApprovalGrant{
		Kind: kind, Contract: contract, Token: token.Hex(), Owner: owner.Hex(), Spender: spender.Hex(),
		Amount: models.QuantityFromBig(amt), Unlimited: isMax(amt, core.MaxUint160),
		Revocation: amt != nil && amt.Sign() == 0, Expiration: u64(exp), Signed: signed,
	}
}

// permit2FromStruct reads a rendered PermitSingle or PermitBatch tuple.
func permit2FromStruct(ps any, contract string, owner common.Address) []models.ApprovalGrant {
	spV, _ := core.Field(ps, "spender")
	spender, _ := core.AsAddress(spV)
	detailsV, _ := core.Field(ps, "details")
	var details []any
	switch d := detailsV.(type) {
	case []models.DecodedParam: // single
		details = []any{d}
	case []any: // batch
		details = d
	}
	var out []models.ApprovalGrant
	for _, d := range details {
		tV, _ := core.Field(d, "token")
		token, _ := core.AsAddress(tV)
		aV, _ := core.Field(d, "amount")
		amt, _ := core.AsBig(aV)
		eV, _ := core.Field(d, "expiration")
		exp, _ := core.AsBig(eV)
		out = append(out, permit2Grant(models.ApprovalPermit2Signed, contract, token, owner, spender, amt, exp, true))
	}
	return out
}

func addrParam(c *models.DecodedCall, name string) (common.Address, bool) {
	v, ok := core.Param(c, name)
	if !ok {
		return common.Address{}, false
	}
	return core.AsAddress(v)
}

func bigParam(c *models.DecodedCall, name string) (*big.Int, bool) {
	v, ok := core.Param(c, name)
	if !ok {
		return nil, false
	}
	return core.AsBig(v)
}

func isMax(v, max *big.Int) bool { return v != nil && v.Cmp(max) == 0 }

func u64(v *big.Int) *uint64 {
	if v == nil || !v.IsUint64() {
		return nil
	}
	x := v.Uint64()
	return &x
}
