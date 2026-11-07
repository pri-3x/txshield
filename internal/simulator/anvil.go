package simulator

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/pri-3x/txshield/internal/evm"
	"github.com/pri-3x/txshield/internal/logging"
	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

// AnvilOptions configures the Anvil fork simulator.
type AnvilOptions struct {
	Path           string        // anvil binary; default "anvil"
	Workers        int           // concurrent simulations (one anvil process each); default 2
	StartupTimeout time.Duration // default 15s
	Timeout        time.Duration // per simulation, including queueing; default 30s
	// MaxGas caps the gas limit used when the request does not set one.
	MaxGas uint64 // default 30,000,000
	// MaxResponseBytes caps trace/receipt responses from the local node.
	MaxResponseBytes int64 // default 64 MiB
}

func (o AnvilOptions) withDefaults() AnvilOptions {
	if o.Path == "" {
		o.Path = "anvil"
	}
	if o.Workers <= 0 {
		o.Workers = 2
	}
	if o.StartupTimeout <= 0 {
		o.StartupTimeout = 15 * time.Second
	}
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	if o.MaxGas == 0 {
		o.MaxGas = 30_000_000
	}
	if o.MaxResponseBytes <= 0 {
		o.MaxResponseBytes = 64 << 20
	}
	return o
}

// Anvil simulates transactions on private, ephemeral Anvil forks.
//
// Safety properties:
//   - Anvil binds to 127.0.0.1 on a port it picks itself (read back from its
//     output, so no other process can take the port in between), with CORS
//     disabled, and is owned by TxShield.
//   - Anvil never sees the upstream RPC URL (which usually holds an API key):
//     it forks through a loopback relay (see forkRelay), so the key does not
//     appear in process arguments.
//   - The sender is impersonated (anvil_impersonateAccount); no key exists.
//   - Transactions are executed only on the local fork. Anvil never forwards
//     transactions to the fork's upstream; the upstream is used for state reads.
//   - Each job re-forks (anvil_reset), discarding the previous job's state.
type Anvil struct {
	opts  AnvilOptions
	reg   *evm.Registry
	slots chan *anvilWorker
	relay *forkRelay

	mu      sync.Mutex
	workers []*anvilWorker
	closed  bool
}

var _ interfaces.Simulator = (*Anvil)(nil)

// NewAnvil creates the simulator. Processes start lazily on first use.
func NewAnvil(reg *evm.Registry, opts AnvilOptions) *Anvil {
	opts = opts.withDefaults()
	a := &Anvil{opts: opts, reg: reg, slots: make(chan *anvilWorker, opts.Workers), relay: newForkRelay(opts.MaxResponseBytes)}
	for i := 0; i < opts.Workers; i++ {
		w := &anvilWorker{opts: opts}
		a.workers = append(a.workers, w)
		a.slots <- w
	}
	return a
}

// Name implements interfaces.Simulator.
func (a *Anvil) Name() string { return "anvil" }

// Capabilities implements interfaces.Simulator.
func (a *Anvil) Capabilities() models.SimulatorCapabilities {
	return models.SimulatorCapabilities{Fork: true, CallTrace: true, BalanceDiff: true}
}

// Close stops all anvil processes.
func (a *Anvil) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	for _, w := range a.workers {
		w.stop()
	}
	a.relay.close()
}

// Simulate implements interfaces.Simulator.
func (a *Anvil) Simulate(ctx context.Context, req interfaces.SimulationRequest) (*models.SimulationResult, error) {
	if req.Tx == nil {
		return nil, txerrors.New(txerrors.KindInvalidInput, "missing_transaction", "transaction is required")
	}
	if req.Tx.IsContractCreation() && len(req.Tx.Data) == 0 {
		return nil, txerrors.New(txerrors.KindInvalidInput, "empty_creation", "contract creation needs init code")
	}
	timeout := a.opts.Timeout
	if req.Timeout > 0 && req.Timeout < timeout {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var w *anvilWorker
	select {
	case w = <-a.slots:
	case <-ctx.Done():
		return nil, txerrors.Wrap(ctx.Err(), txerrors.KindTimeout, "simulation_queue_timeout", "no simulation worker became available in time")
	}
	defer func() { a.slots <- w }()

	a.mu.Lock()
	closed := a.closed
	a.mu.Unlock()
	if closed {
		return nil, txerrors.New(txerrors.KindUnavailable, "simulator_closed", "simulator is shutting down")
	}

	start := time.Now()
	res, err := a.run(ctx, w, req)
	if err != nil {
		w.stop() // never reuse a worker in an unknown state
		if ctx.Err() != nil {
			return nil, txerrors.Wrap(err, txerrors.KindTimeout, "simulation_timeout", "simulation exceeded its time limit")
		}
		if _, ok := txerrors.As(err); ok {
			return nil, err
		}
		return nil, txerrors.Wrap(err, txerrors.KindUnavailable, "simulation_failed", "simulation backend failed")
	}
	res.DurationMs = time.Since(start).Milliseconds()
	return res, nil
}

type sendArgs struct {
	From     common.Address  `json:"from"`
	To       *common.Address `json:"to,omitempty"`
	Gas      hexutil.Uint64  `json:"gas"`
	GasPrice hexutil.Big     `json:"gasPrice"`
	Value    *hexutil.Big    `json:"value,omitempty"`
	Data     hexutil.Bytes   `json:"data,omitempty"`
}

type receipt struct {
	Status          hexutil.Uint64  `json:"status"`
	GasUsed         hexutil.Uint64  `json:"gasUsed"`
	BlockNumber     hexutil.Uint64  `json:"blockNumber"`
	ContractAddress *common.Address `json:"contractAddress"`
	Logs            []RawLog        `json:"logs"`
}

func (a *Anvil) run(ctx context.Context, w *anvilWorker, req interfaces.SimulationRequest) (*models.SimulationResult, error) {
	tx := req.Tx
	forkURL, err := a.reg.RPCURL(tx.ChainID)
	if err != nil {
		return nil, err
	}
	upstream, err := a.reg.Client(ctx, tx.ChainID) // also verifies the endpoint's chain ID
	if err != nil {
		return nil, err
	}
	ref := models.BlockRef{Tag: models.BlockLatest}
	if req.BlockNumber > 0 {
		n := req.BlockNumber
		ref = models.BlockRef{Number: &n}
	}
	block, err := upstream.ResolveBlock(ctx, ref)
	if err != nil {
		return nil, err
	}

	relayURL, err := a.relay.url(forkURL)
	if err != nil {
		return nil, txerrors.Wrap(err, txerrors.KindUnavailable, "fork_relay_failed", "could not start the simulation fork relay")
	}
	local, err := w.fork(ctx, relayURL, block.Number)
	if err != nil {
		return nil, err
	}
	var chainID hexutil.Big
	if err := local.Call(ctx, &chainID, "eth_chainId"); err != nil {
		return nil, err
	}
	if (*big.Int)(&chainID).Cmp(new(big.Int).SetUint64(tx.ChainID)) != 0 {
		return nil, txerrors.New(txerrors.KindUnsupported, "fork_chain_mismatch",
			fmt.Sprintf("fork reports chain %s but the transaction is for chain %d", (*big.Int)(&chainID), tx.ChainID))
	}

	res := &models.SimulationResult{
		Backend: "anvil", Status: models.SimSuccess, Completeness: models.CompletenessFull,
		ChainID: tx.ChainID, BlockNumber: block.Number, BlockHash: block.Hash,
		Notes: []string{
			"Executed in a new block on top of block " + strconv.FormatUint(block.Number, 10) + "; on-chain state may change before inclusion.",
			"Simulated with zero gas price, so native balance changes exclude transaction fees.",
		},
	}
	res.Notes = append(res.Notes, feeNotes(tx, block)...)
	var reasons []string

	// Fees are zeroed so balance diffs isolate value movements.
	if err := local.Call(ctx, nil, "anvil_setNextBlockBaseFeePerGas", "0x0"); err != nil {
		return nil, err
	}
	if err := local.Call(ctx, nil, "anvil_impersonateAccount", tx.From); err != nil {
		return nil, err
	}
	forkBlock := new(big.Int).SetUint64(block.Number)
	nativeBefore, err := local.BalanceAt(ctx, tx.From, forkBlock)
	if err != nil {
		return nil, err
	}

	args := sendArgs{From: tx.From, To: tx.To, Data: tx.Data}
	if tx.Value != nil && tx.Value.Sign() > 0 {
		args.Value = (*hexutil.Big)(tx.Value)
	}
	if est, err := local.EstimateGas(ctx, tx); err == nil {
		e := est
		res.GasEstimate = &e
	} else if !evm.IsExecutionError(err) {
		return nil, err
	}
	gas := a.opts.MaxGas
	if block.GasLimit > 0 && block.GasLimit < gas {
		gas = block.GasLimit
	}
	if tx.Gas != nil {
		gas = *tx.Gas // respect the caller's limit: running out of gas is a real outcome
	}
	args.Gas = hexutil.Uint64(gas)

	var hash common.Hash
	if err := local.Call(ctx, &hash, "eth_sendTransaction", args); err != nil {
		var rpcErr *evm.RPCError
		if errors.As(err, &rpcErr) {
			// Rejected before execution (insufficient funds, nonce, gas
			// limit above block limit). This is a property of the
			// transaction, not an infrastructure failure.
			res.Status = models.SimReverted
			res.RevertReason = "rejected before execution: " + logging.Sanitize(rpcErr.Message, 200)
			return res, nil
		}
		return nil, err
	}

	rc, err := waitReceipt(ctx, local, hash)
	if err != nil {
		return nil, err
	}
	res.GasUsed = uint64(rc.GasUsed)
	if rc.Status == 0 {
		res.Status = models.SimReverted
	}

	var raw RawFrame
	traceErr := local.Call(ctx, &raw, "debug_traceTransaction", hash, map[string]any{"tracer": "callTracer"})
	var trace ConvertedTrace
	if traceErr != nil {
		if _, infra := txerrors.As(traceErr); infra && ctx.Err() != nil {
			return nil, traceErr
		}
		reasons = append(reasons, "call trace unavailable")
	} else {
		trace = ConvertTrace(raw)
		res.Trace = trace.Root
		if trace.Truncated {
			reasons = append(reasons, fmt.Sprintf("call trace truncated at %d frames", MaxTraceFrames))
		}
		if res.Status == models.SimReverted {
			// Decode the raw data ourselves first so wording is identical
			// across backends; fall back to the node's own rendering.
			res.RevertReason = DecodeRevert(raw.Output)
			if res.RevertReason == "" {
				res.RevertReason = raw.RevertReason
			}
			if res.RevertReason == "" {
				res.RevertReason = raw.Error
			}
		}
	}

	if res.Status == models.SimReverted {
		res.Completeness = completeness(reasons)
		res.IncompleteReasons = reasons
		return res, nil
	}

	ev := ParseLogs(rc.Logs)
	res.Logs, res.ApprovalChanges = ev.Logs, ev.Approvals
	res.AssetTransfers = append(trace.NativeTransfers, ev.Transfers...)
	if ev.Truncated {
		reasons = append(reasons, fmt.Sprintf("only the first %d logs were kept", MaxLogs))
	}
	if traceErr != nil && tx.Value != nil && tx.Value.Sign() > 0 && tx.To != nil {
		// Without a trace, at least record the top-level value transfer.
		res.AssetTransfers = append([]models.AssetTransfer{{Asset: models.AssetRef{Kind: models.AssetNative}, From: tx.From.Hex(), To: tx.To.Hex(), Amount: models.QuantityFromBig(tx.Value)}}, res.AssetTransfers...)
	}

	changes, balReasons := balanceChanges(ctx, local, tx.From, nativeBefore, forkBlock, res.AssetTransfers)
	res.BalanceChanges = changes
	reasons = append(reasons, balReasons...)
	res.Completeness = completeness(reasons)
	res.IncompleteReasons = reasons
	return res, nil
}

// waitReceipt polls for the receipt: anvil auto-mines asynchronously, so the
// receipt can lag eth_sendTransaction by a few milliseconds.
func waitReceipt(ctx context.Context, c *evm.Client, hash common.Hash) (*receipt, error) {
	delay := 5 * time.Millisecond
	for {
		var rc *receipt
		if err := c.Call(ctx, &rc, "eth_getTransactionReceipt", hash); err != nil {
			return nil, err
		}
		if rc != nil {
			return rc, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("local fork did not mine the transaction: %w", ctx.Err())
		case <-time.After(delay):
		}
		if delay < 100*time.Millisecond {
			delay *= 2
		}
	}
}

func completeness(reasons []string) models.Completeness {
	if len(reasons) > 0 {
		return models.CompletenessPartial
	}
	return models.CompletenessFull
}

// feeNotes reports fee settings that would prevent inclusion even though the
// zero-fee simulation succeeded.
func feeNotes(tx *models.Transaction, block models.BlockInfo) []string {
	if block.BaseFee == "" {
		return nil
	}
	base, ok := new(big.Int).SetString(block.BaseFee, 10)
	if !ok {
		return nil
	}
	var feeCap *big.Int
	switch {
	case tx.MaxFeePerGas != nil:
		feeCap = tx.MaxFeePerGas
	case tx.GasPrice != nil:
		feeCap = tx.GasPrice
	default:
		return nil
	}
	if feeCap.Cmp(base) < 0 {
		return []string{fmt.Sprintf("The transaction's fee cap (%s wei) is below the base fee of block %d (%s wei); it would not be included until fees drop.", feeCap, block.Number, base)}
	}
	return nil
}

var (
	selBalanceOf     = common.FromHex("70a08231")
	selBalanceOf1155 = common.FromHex("00fdd58e")
)

// balanceChanges diffs the sender's balances for native currency and every
// token the sender sent or received, reading the fork block (before) and the
// simulated block (after).
func balanceChanges(ctx context.Context, c *evm.Client, owner common.Address, nativeBefore, forkBlock *big.Int, transfers []models.AssetTransfer) ([]models.BalanceChange, []string) {
	var out []models.BalanceChange
	var reasons []string
	if after, err := c.BalanceAt(ctx, owner, nil); err == nil {
		if after.Cmp(nativeBefore) != 0 {
			out = append(out, change(owner, models.AssetRef{Kind: models.AssetNative}, nativeBefore, after))
		}
	} else {
		reasons = append(reasons, "native balance after execution unavailable")
	}

	type key struct {
		kind  models.AssetKind
		token string
		id    string
	}
	seen := map[key]models.AssetRef{}
	var order []key
	ownerHex := owner.Hex()
	for _, t := range transfers {
		if t.Asset.Kind == models.AssetNative || (t.From != ownerHex && t.To != ownerHex) {
			continue
		}
		k := key{t.Asset.Kind, t.Asset.Address, ""}
		if t.Asset.Kind == models.AssetERC1155 {
			k.id = string(t.Asset.TokenID)
		}
		if _, ok := seen[k]; !ok {
			ref := t.Asset
			if ref.Kind == models.AssetERC721 {
				ref.TokenID = "" // ERC-721 balanceOf counts tokens in the collection
			}
			seen[k] = ref
			order = append(order, k)
		}
	}
	const maxTokens = 50
	if len(order) > maxTokens {
		reasons = append(reasons, fmt.Sprintf("balance diffs computed for the first %d of %d tokens", maxTokens, len(order)))
		order = order[:maxTokens]
	}
	for _, k := range order {
		ref := seen[k]
		data := append(append([]byte{}, selBalanceOf...), common.LeftPadBytes(owner.Bytes(), 32)...)
		if k.kind == models.AssetERC1155 {
			id, _ := new(big.Int).SetString(k.id, 10)
			if id == nil {
				id = new(big.Int)
			}
			data = append(append(append([]byte{}, selBalanceOf1155...), common.LeftPadBytes(owner.Bytes(), 32)...), common.LeftPadBytes(id.Bytes(), 32)...)
		}
		token := common.HexToAddress(k.token)
		before, err1 := readUint(ctx, c, token, data, forkBlock)
		after, err2 := readUint(ctx, c, token, data, nil)
		if err1 != nil || err2 != nil {
			reasons = append(reasons, "balance of "+k.token+" unavailable")
			continue
		}
		if before.Cmp(after) != 0 {
			out = append(out, change(owner, ref, before, after))
		}
	}
	return out, reasons
}

func readUint(ctx context.Context, c *evm.Client, to common.Address, data []byte, blk *big.Int) (*big.Int, error) {
	gas := uint64(200_000)
	out, err := c.CallContract(ctx, &models.Transaction{To: &to, Data: data, Gas: &gas, Value: new(big.Int)}, blk)
	if err != nil {
		return nil, err
	}
	if len(out) < 32 {
		return nil, fmt.Errorf("short return")
	}
	return new(big.Int).SetBytes(out[:32]), nil
}

func change(owner common.Address, asset models.AssetRef, before, after *big.Int) models.BalanceChange {
	return models.BalanceChange{
		Owner: owner.Hex(), Asset: asset,
		Before: models.QuantityFromBig(before), After: models.QuantityFromBig(after),
		Delta: models.Quantity(new(big.Int).Sub(after, before).String()),
	}
}

// ---------------------------------------------------------------------------
// Worker process management

type anvilWorker struct {
	opts AnvilOptions

	mu     sync.Mutex
	cmd    *exec.Cmd
	client *evm.Client
	stderr *boundedBuffer
	done   chan struct{}
}

// fork returns a client for a worker forked at (url, block), starting the
// process if needed and re-forking otherwise.
func (w *anvilWorker) fork(ctx context.Context, forkURL string, block uint64) (*evm.Client, error) {
	w.mu.Lock()
	running := w.cmd != nil
	if running {
		select {
		case <-w.done:
			// The process exited (crash, OOM kill). Never reuse its port:
			// another process may be listening there now.
			running = false
			w.cmd, w.client = nil, nil
		default:
		}
	}
	client := w.client
	w.mu.Unlock()
	if running {
		params := map[string]any{"forking": map[string]any{"jsonRpcUrl": forkURL, "blockNumber": block}}
		if err := client.Call(ctx, nil, "anvil_reset", params); err != nil {
			return nil, redact(err, forkURL)
		}
		return client, nil
	}
	return w.start(ctx, forkURL, block)
}

func (w *anvilWorker) start(ctx context.Context, forkURL string, block uint64) (*evm.Client, error) {
	// --port 0: anvil binds a free port itself and reports it on stdout, so
	// there is no window in which another process can take the port.
	// --no-storage-caching: never write fork state to disk (read-only
	// containers, no cross-request persistence).
	// --no-cors: browsers on this host cannot read anvil responses.
	// Not CommandContext: the worker outlives any single request context.
	cmd := exec.Command(w.opts.Path, //nolint:gosec,noctx // operator-configured binary; long-lived worker process
		"--host", "127.0.0.1", "--port", "0", "--no-cors",
		"--fork-url", forkURL, "--fork-block-number", strconv.FormatUint(block, 10),
		"--no-storage-caching")
	stderr := &boundedBuffer{max: 8192}
	stdout, stdoutW := io.Pipe()
	cmd.Stdout, cmd.Stderr = stdoutW, stderr
	if err := cmd.Start(); err != nil {
		return nil, txerrors.Wrap(err, txerrors.KindUnavailable, "anvil_start_failed", "could not start the anvil simulation backend")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); _ = stdoutW.Close(); close(done) }()
	addrCh := make(chan string, 1)
	go readListenAddr(stdout, addrCh)

	exited := func() error {
		msg := strings.ReplaceAll(stderr.String(), forkURL, "<fork-url>")
		return txerrors.Wrap(fmt.Errorf("anvil exited: %s", logging.Sanitize(msg, 500)), txerrors.KindUnavailable, "anvil_exited", "the simulation backend could not fork the chain (is the RPC endpoint reachable?)")
	}
	timeout := time.NewTimer(w.opts.StartupTimeout)
	defer timeout.Stop()
	var addr string
	select {
	case addr = <-addrCh:
	case <-done:
		return nil, exited()
	case <-timeout.C:
		_ = cmd.Process.Kill()
		return nil, txerrors.New(txerrors.KindTimeout, "anvil_start_timeout", "the simulation backend did not start in time")
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		return nil, txerrors.Wrap(ctx.Err(), txerrors.KindTimeout, "anvil_start_timeout", "the simulation backend did not start in time")
	}

	client, err := evm.DialLocal(ctx, "http://"+addr, evm.Options{MaxResponseBytes: w.opts.MaxResponseBytes, Retry: evm.RetryPolicy{MaxAttempts: 1}, BreakerThreshold: 1 << 30})
	if err != nil {
		_ = cmd.Process.Kill()
		return nil, err
	}
	for {
		pctx, cancel := context.WithTimeout(ctx, time.Second)
		_, perr := client.BlockNumber(pctx)
		cancel()
		if perr == nil {
			break
		}
		select {
		case <-done:
			return nil, exited()
		case <-timeout.C:
			_ = cmd.Process.Kill()
			return nil, txerrors.New(txerrors.KindTimeout, "anvil_start_timeout", "the simulation backend did not start in time")
		default:
		}
		if ctx.Err() != nil {
			_ = cmd.Process.Kill()
			return nil, txerrors.Wrap(ctx.Err(), txerrors.KindTimeout, "anvil_start_timeout", "the simulation backend did not start in time")
		}
		time.Sleep(50 * time.Millisecond)
	}
	w.mu.Lock()
	w.cmd, w.client, w.stderr, w.done = cmd, client, stderr, done
	w.mu.Unlock()
	return client, nil
}

func (w *anvilWorker) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cmd != nil && w.cmd.Process != nil {
		_ = w.cmd.Process.Kill()
		select {
		case <-w.done:
		case <-time.After(5 * time.Second):
		}
	}
	w.cmd, w.client = nil, nil
}

// readListenAddr scans anvil's stdout for "Listening on 127.0.0.1:<port>",
// sends the address once, and keeps draining the pipe so anvil never blocks
// on a full stdout.
func readListenAddr(r io.Reader, out chan<- string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	sent := false
	for sc.Scan() {
		if sent {
			continue
		}
		if rest, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "Listening on "); ok {
			if ap, err := netip.ParseAddrPort(strings.TrimSpace(rest)); err == nil && ap.Addr().IsLoopback() && ap.Port() != 0 {
				out <- ap.String()
				sent = true
			}
		}
	}
	_, _ = io.Copy(io.Discard, r)
}

// redact removes the fork URL (may contain an API key) from error text.
func redact(err error, forkURL string) error {
	if err == nil || !strings.Contains(err.Error(), forkURL) {
		return err
	}
	if e, ok := txerrors.As(err); ok {
		return txerrors.New(e.Kind, e.Code, e.Message)
	}
	return errors.New(strings.ReplaceAll(err.Error(), forkURL, "<fork-url>"))
}

// boundedBuffer keeps the first max bytes written (process diagnostics).
type boundedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
