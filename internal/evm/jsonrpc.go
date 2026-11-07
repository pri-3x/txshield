package evm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
)

// A minimal HTTP JSON-RPC 2.0 client. go-ethereum's rpc package is avoided
// on purpose: it pulls in WebSocket, OpenTelemetry, and system-metrics
// dependencies that TxShield does not need, and this keeps every byte on
// the wire under TxShield's control (allowlist, size cap, no redirects).

// RPCError is a JSON-RPC error response: a deterministic answer from the
// node (e.g. "execution reverted"), not an infrastructure failure.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("json-rpc error %d: %s", e.Code, e.Message) }

// HTTPError is a non-2xx HTTP response.
type HTTPError struct {
	StatusCode int
}

func (e *HTTPError) Error() string { return fmt.Sprintf("rpc endpoint returned HTTP %d", e.StatusCode) }

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      uint64 `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcResponse struct {
	ID     uint64          `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *RPCError       `json:"error"`
}

type httpRPC struct {
	url    string
	client *http.Client
	nextID atomic.Uint64
}

func (h *httpRPC) call(ctx context.Context, result any, method string, params ...any) error {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: h.nextID.Add(1), Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return &HTTPError{StatusCode: resp.StatusCode}
	}
	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		if errors.Is(err, errResponseTooLarge) {
			return err
		}
		return fmt.Errorf("decode response: %w", err)
	}
	if out.Error != nil {
		return out.Error
	}
	if result == nil {
		return nil
	}
	if len(out.Result) == 0 {
		return fmt.Errorf("empty result")
	}
	return json.Unmarshal(out.Result, result)
}
