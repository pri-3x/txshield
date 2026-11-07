package approvals

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/common"

	"github.com/pri-3x/txshield/internal/security/core"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
)

// CanonicalPermit2 is Permit2's deterministic deployment address, identical
// on every chain where it is deployed.
var CanonicalPermit2 = common.HexToAddress("0x000000000022D473030F116dDEE9F6B43aC78BA3")

var (
	selAllowance        = common.FromHex("dd62ed3e") // allowance(address,address)
	selIsApprovedForAll = common.FromHex("e985e9c5") // isApprovedForAll(address,address)
	selGetApproved      = common.FromHex("081812fc") // getApproved(uint256)
	selPermit2Allowance = common.FromHex("927da105") // allowance(address,address,address)
)

func word(b []byte) []byte { return common.LeftPadBytes(b, 32) }

func call(ctx context.Context, r interfaces.ChainReader, to common.Address, data []byte, block uint64) ([]byte, error) {
	gas := uint64(200_000)
	var blk *big.Int
	if block > 0 {
		blk = new(big.Int).SetUint64(block)
	}
	return r.CallContract(ctx, &models.Transaction{To: &to, Data: data, Gas: &gas, Value: new(big.Int)}, blk)
}

// ReadCurrent reads the on-chain value of the permission a grant would set,
// i.e. what is in force before the transaction executes.
func ReadCurrent(ctx context.Context, r interfaces.ChainReader, g models.ApprovalGrant, block uint64) models.ApprovalState {
	st := models.ApprovalState{Block: block}
	owner, spender, token := common.HexToAddress(g.Owner), common.HexToAddress(g.Spender), common.HexToAddress(g.Token)
	fail := func(err error) models.ApprovalState {
		st.Error = "could not read on-chain state: " + errMessage(err)
		return st
	}
	switch g.Kind {
	case models.ApprovalOperator:
		out, err := call(ctx, r, token, append(append(append([]byte{}, selIsApprovedForAll...), word(owner.Bytes())...), word(spender.Bytes())...), block)
		if err != nil || len(out) < 32 {
			return fail(err)
		}
		v := new(big.Int).SetBytes(out[:32]).Sign() != 0
		st.ApprovedForAll = &v
	case models.ApprovalNFTToken:
		id, _ := new(big.Int).SetString(string(g.TokenID), 10)
		if id == nil {
			id = new(big.Int)
		}
		out, err := call(ctx, r, token, append(append([]byte{}, selGetApproved...), word(id.Bytes())...), block)
		if err != nil || len(out) < 32 {
			return fail(err)
		}
		v := common.BytesToAddress(out[12:32]) == spender
		st.TokenApproved = &v
	case models.ApprovalPermit2, models.ApprovalPermit2Signed:
		p2 := CanonicalPermit2
		if g.Contract != "" {
			p2 = common.HexToAddress(g.Contract)
		}
		data := append(append(append(append([]byte{}, selPermit2Allowance...), word(owner.Bytes())...), word(token.Bytes())...), word(spender.Bytes())...)
		out, err := call(ctx, r, p2, data, block)
		if err != nil || len(out) < 64 {
			return fail(err)
		}
		amt := new(big.Int).SetBytes(out[:32])
		exp := new(big.Int).SetBytes(out[32:64]).Uint64()
		st.Amount, st.Unlimited, st.Expiration = models.QuantityFromBig(amt), amt.Cmp(core.MaxUint160) == 0, &exp
	default: // ERC-20 style allowance (incl. ambiguous approve, permits)
		out, err := call(ctx, r, token, append(append(append([]byte{}, selAllowance...), word(owner.Bytes())...), word(spender.Bytes())...), block)
		if err != nil || len(out) < 32 {
			return fail(err)
		}
		amt := new(big.Int).SetBytes(out[:32])
		st.Amount, st.Unlimited = models.QuantityFromBig(amt), amt.Cmp(core.MaxUint256) == 0
	}
	return st
}

func errMessage(err error) string {
	if err == nil {
		return "unexpected return data"
	}
	return "call failed"
}
