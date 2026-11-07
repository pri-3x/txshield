package api

import (
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/pri-3x/txshield/internal/evm"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

// DecodeRequest is the body of POST /api/v1/decode.
type DecodeRequest struct {
	// To is the target contract; omit for contract creation or unknown target.
	To    string          `json:"to,omitempty"`
	Value models.Quantity `json:"value,omitempty"`
	Data  string          `json:"data"`
	ABI   json.RawMessage `json:"abi,omitempty"`
}

// placeholderSender satisfies validation for decode-only requests; the
// decoder never uses the sender.
const placeholderSender = "0x0000000000000000000000000000000000000000"

// handleDecode serves POST /api/v1/decode: offline calldata decoding, no
// chain access, nothing stored.
func (s *Server) handleDecode(w http.ResponseWriter, r *http.Request) {
	e := s.engineOr503(w, r)
	if e == nil {
		return
	}
	var req DecodeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if strings.TrimSpace(req.Data) == "" {
		writeError(w, r, txerrors.Invalid(txerrors.FieldError{Field: "data", Message: "is required"}))
		return
	}
	to := req.To
	if to == "" {
		// Without a target the calldata is decoded as a call to an unknown
		// contract (not as contract creation), which is what users pasting
		// calldata expect.
		to = placeholderSender
	}
	tx, err := s.parseTx(models.TransactionRequest{ChainID: 1, From: placeholderSender, To: to, Value: req.Value, Data: req.Data})
	if err != nil {
		writeError(w, r, err)
		return
	}
	call, err := e.Analyzer.Decode(r.Context(), tx, interfaces.DecodeOptions{ABIJSON: req.ABI})
	if err != nil {
		writeError(w, r, err)
		return
	}
	if req.To == "" {
		call.Target = ""
	}
	writeJSON(w, http.StatusOK, call)
}

// TransactionLookup is the response of GET /api/v1/transactions/{hash}.
type TransactionLookup struct {
	Hash        string  `json:"hash"`
	ChainID     uint64  `json:"chainId"`
	BlockNumber *uint64 `json:"blockNumber,omitempty"` // nil while pending
	// Transaction is ready to submit to /analyze. For mined transactions
	// Block is the parent block, so a replay sees pre-transaction state.
	Transaction models.TransactionRequest `json:"transaction"`
	Notes       []string                  `json:"notes"`
}

var txHashRe = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)

type rpcTx struct {
	From                 common.Address  `json:"from"`
	To                   *common.Address `json:"to"`
	Value                *hexutil.Big    `json:"value"`
	Input                hexutil.Bytes   `json:"input"`
	Gas                  hexutil.Uint64  `json:"gas"`
	GasPrice             *hexutil.Big    `json:"gasPrice"`
	MaxFeePerGas         *hexutil.Big    `json:"maxFeePerGas"`
	MaxPriorityFeePerGas *hexutil.Big    `json:"maxPriorityFeePerGas"`
	BlockNumber          *hexutil.Uint64 `json:"blockNumber"`
	Type                 hexutil.Uint64  `json:"type"`
}

// handleTransaction serves GET /api/v1/transactions/{hash}?chainId=: fetches
// a transaction from the configured RPC so it can be re-analyzed.
func (s *Server) handleTransaction(w http.ResponseWriter, r *http.Request) {
	e := s.engineOr503(w, r)
	if e == nil {
		return
	}
	hash := r.PathValue("hash")
	if !txHashRe.MatchString(hash) {
		writeError(w, r, txerrors.Invalid(txerrors.FieldError{Field: "hash", Message: "must be a 0x-prefixed 32-byte hash"}))
		return
	}
	chainID, err := parseChainParam(r, true)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if e.Chains == nil {
		writeError(w, r, txerrors.New(txerrors.KindUnsupported, "chain_not_configured", "no RPC endpoint is configured for this chain"))
		return
	}
	c, err := e.Chains.Client(r.Context(), *chainID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	var t *rpcTx
	if err := c.Call(r.Context(), &t, "eth_getTransactionByHash", common.HexToHash(hash)); err != nil {
		var rpcErr *evm.RPCError
		if errors.As(err, &rpcErr) {
			err = txerrors.Wrap(err, txerrors.KindUnavailable, "rpc_error", "the RPC endpoint could not look up the transaction")
		}
		writeError(w, r, err)
		return
	}
	if t == nil {
		writeError(w, r, txerrors.New(txerrors.KindNotFound, "transaction_not_found", "transaction not found on this chain"))
		return
	}
	req := models.TransactionRequest{ChainID: *chainID, From: t.From.Hex(), Data: hexutil.Encode(t.Input), Gas: models.Quantity(uint64Str(uint64(t.Gas)))}
	if t.To != nil {
		req.To = t.To.Hex()
	}
	if t.Value != nil {
		req.Value = models.QuantityFromBig((*big.Int)(t.Value))
	}
	if t.MaxFeePerGas != nil {
		req.MaxFeePerGas = models.QuantityFromBig((*big.Int)(t.MaxFeePerGas))
		if t.MaxPriorityFeePerGas != nil {
			req.MaxPriorityFeePerGas = models.QuantityFromBig((*big.Int)(t.MaxPriorityFeePerGas))
		}
	} else if t.GasPrice != nil {
		req.GasPrice = models.QuantityFromBig((*big.Int)(t.GasPrice))
	}
	out := TransactionLookup{Hash: strings.ToLower(hash), ChainID: *chainID, Notes: []string{}}
	if t.BlockNumber != nil {
		n := uint64(*t.BlockNumber)
		out.BlockNumber = &n
		if n > 0 {
			req.Block = uint64Str(n - 1)
		}
		out.Notes = append(out.Notes, "Mined transaction: replaying on top of the parent block. Transactions earlier in the same block are not re-applied, so results can differ from what actually happened.")
	} else {
		out.Notes = append(out.Notes, "Pending transaction: analysis uses the latest block.")
	}
	if t.Type > 2 {
		out.Notes = append(out.Notes, "Transaction type "+uint64Str(uint64(t.Type))+" (e.g. blob or EIP-7702 authorization) is analyzed as a plain call; type-specific fields are ignored.")
	}
	out.Transaction = req
	writeJSON(w, http.StatusOK, out)
}

func uint64Str(v uint64) string { return new(big.Int).SetUint64(v).String() }
