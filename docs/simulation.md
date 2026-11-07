# Transaction Simulation

TxShield executes a transaction against real chain state **without signing or
broadcasting it**, and reports what happened: success or revert, gas, logs, a
call trace, asset transfers, and the sender's balance changes.

> A successful simulation is not proof of safety. State can change before
> inclusion, and malicious contracts can detect simulation and behave
> differently. TxShield always reports the exact block it simulated against.

Code: [`internal/simulator`](../internal/simulator),
[`internal/evm`](../internal/evm).

## Backends

| Backend | How | Completeness | Use when |
|---|---|---|---|
| `anvil` (default) | Private Anvil fork at the pinned block, sender impersonated, tx mined locally | `full` when trace and balance reads succeed | Normal operation |
| `rpc-trace` | Upstream `debug_traceCall` (callTracer + logs), falls back to `eth_call` | at most `partial` (no post-state, so no balance diffs) | Anvil cannot run |
| none | Static analysis only | `none` | Offline mode |

## Anvil backend

### Lifecycle

- A fixed pool of workers (`Workers`, default 2). Each owns one Anvil process,
  started lazily on first use:
  `anvil --host 127.0.0.1 --port 0 --no-cors --fork-url <relay> --fork-block-number <n> --no-storage-caching`
- `--port 0`: Anvil binds a free port itself and TxShield reads the address
  from its `Listening on` line, so no other process can take the port first.
- `<relay>` is `http://127.0.0.1:<port>/fork/<token>`, an in-process
  loopback relay to the real RPC endpoint. Anvil only accepts its fork
  endpoint as an argument, and arguments are visible to every local user, so
  the provider URL (and its API key) never reaches Anvil. The relay refuses
  methods that send or sign transactions or change node state, keeps a pooled
  keep-alive connection set to the provider (reused across forks), and never
  echoes upstream errors.
- Every job **re-forks** the worker (`anvil_reset`) at its own block, which
  discards the previous job's state. Cold start 50-100 ms; warm job ~26 ms
  against a local upstream ([benchmarks](benchmarks.md#simulation)).
- A worker that hits any infrastructure error or timeout is killed and
  restarted on next use. A worker whose process exited (crash, OOM kill) is
  restarted rather than re-forked, so a stale port is never reused.
- `--no-storage-caching` keeps fork state off disk (read-only containers, no
  cross-request persistence).

### One simulation

1. Resolve the block once on the upstream (`ResolveBlock`) so the fork,
   contract checks, and balance reads all use the same state.
2. Re-fork, then verify the fork's `eth_chainId` equals the transaction's
   chain ID (refused as `unsupported` on mismatch).
3. `anvil_setNextBlockBaseFeePerGas 0` and send with `gasPrice 0`, so native
   balance changes contain only value movements, not fees.
4. `anvil_impersonateAccount(from)`. No key exists anywhere.
5. `eth_estimateGas` for the estimate; gas limit = caller's `gas`, otherwise
   min(block gas limit, 30M).
6. `eth_sendTransaction` on the **local** node; poll the receipt (Anvil mines
   asynchronously).
7. `debug_traceTransaction` with `callTracer`, converted to a bounded call
   tree (5,000 frames, 4 KiB of input/output per frame).
8. Parse logs: ERC-20/721 `Transfer`/`Approval`, `ApprovalForAll`, ERC-1155
   `TransferSingle`/`TransferBatch`, WETH `Deposit`/`Withdrawal`. Native value
   moves come from the trace, excluding reverted frames.
9. Balance diffs for the sender: native, plus every token the sender sent or
   received (ERC-20 and ERC-721 `balanceOf`, ERC-1155 `balanceOf(owner,id)`),
   read at the fork block and after execution.

### Outcomes and errors

| Situation | Result |
|---|---|
| Executed | `status: success` |
| EVM revert | `status: reverted`, `revertReason` decoded (`Error(string)`, `Panic(uint256)`, custom error selector) |
| Rejected before execution (e.g. insufficient funds) | `status: reverted`, reason `rejected before execution: ...` |
| RPC down, Anvil failed to start, timeout, chain mismatch | **error** (`unavailable` / `timeout` / `unsupported`). The analyzer reports `status: error` and says it *"says nothing about whether the transaction would succeed"* |
| Trace or some balance reads failed | `completeness: partial` with `incompleteReasons` |

`notes` explain environment differences, for example the zero gas price, or a
fee cap below the block's base fee (which would delay inclusion).

## Why TxShield never broadcasts

- **Upstream allowlist.** Upstream (operator) endpoints are reached only
  through a client that permits read methods (`eth_call`, `eth_getCode`,
  `debug_traceCall`, ...). `eth_sendRawTransaction`, `eth_sendTransaction`,
  `eth_sign*`, `personal_*`, and `anvil_`/`hardhat_`/`evm_` methods are
  refused before any network I/O (unit-tested with a recording fake node).
- **Local sends only.** Sending is allowed only on clients dialed with
  `DialLocal`, which accepts loopback IP addresses only, i.e. TxShield's own
  Anvil.
- **Anvil does not forward.** Anvil fork mode executes locally and uses the
  upstream only for state reads.
- **Tested.** The integration test snapshots the chain (block number, victim
  nonce, token balance), runs many simulations including concurrent ones, and
  asserts nothing changed.

## RPC client

Hand-written HTTP JSON-RPC client (go-ethereum's `rpc` package pulls in
WebSocket, OpenTelemetry, and gopsutil):

- Retries only transient failures (network errors, HTTP 429/5xx, JSON-RPC
  `-32005`), with exponential backoff and full jitter (3 attempts, 200 ms base,
  2 s cap). JSON-RPC error answers such as reverts are never retried.
- Circuit breaker per endpoint: 5 consecutive infrastructure failures open it
  for 30 s, then a single half-open trial.
- Response size cap (32 MiB upstream, 64 MiB local), redirects refused,
  connection pooling, no implicit proxy.
- URLs (which often embed API keys) are redacted from every error and log.
- **HTTP(S) only.** WebSocket endpoints are not supported.

## Contract inspector

`evm.Inspector` reports, per address at the pinned block:

- Code presence, size, and keccak hash.
- EIP-7702 delegated accounts, reported as *not* contracts (they are user
  wallets).
- Proxies: EIP-1167 clones (bytecode pattern), and the EIP-1967
  implementation, EIP-1967 beacon (via `implementation()`), EIP-1822, and
  legacy OpenZeppelin slots.
- Standards:
  - ERC-721 and ERC-1155 via ERC-165. The contract must also return false for
    `0xffffffff`, or its claims are ignored.
  - ERC-20 by heuristic: `totalSupply`, `balanceOf`, and `decimals` all answer.

Results at pinned blocks are cached (LRU, 4,096 entries). Verification status
and names are not fetched (no paid services).

## Test fixtures

[`contracts/fixtures`](../contracts/fixtures) are deliberately minimal,
dependency-free Solidity contracts:

- **Benign:** test ERC-20/721, a 1:1 exchange, an EIP-1967 proxy, an EIP-1167
  cloner.
- **Malicious:** a fake-airdrop drainer, an arbitrary-call forwarder, a
  re-entrant vault plus attacker, a delegatecall backdoor, and reverting
  functions.

`tests/integration/anvil_test.go` compiles them with Forge, deploys them on a
local Anvil chain, sets up a "phished" victim, and runs the simulators, the
inspector, the full analyzer, and the CLI against them. No mainnet RPC is
used.

## Benchmarks

Methodology:
```
go test -tags integration -run '^$' -bench 'AnvilSimulate$' -benchtime 50x -count 3 ./tests/integration/
go test -tags integration -run '^$' -bench AnvilSimulateWorkers -benchtime 100x ./tests/integration/
go test -tags integration -run TestAnvilColdStart -v ./tests/integration/
```
Both run against a local Anvil "upstream", so they measure TxShield and Anvil
overhead only. Real deployments add upstream RPC latency for every uncached
state read during the fork.

Results, including throughput with 1, 2, and 4 workers and the loopback
connection-churn caveat, are in [benchmarks.md](benchmarks.md#simulation).

## Limitations

- **Block time.** The simulated block uses Anvil's clock (close to wall-clock
  time), not the next real block's timestamp. Time-sensitive contracts can
  behave differently.
- **Fees.** Zeroing them changes `tx.gasprice` and `block.basefee` as seen by
  contracts. Code that branches on them can behave differently.
- **Simulation detection.** Contracts can detect simulation (e.g. via
  `block.coinbase` or gas left). Static rules (approvals, embedded transfers,
  reputation) do not depend on simulation.
- **Process arguments.** The fork RPC URL is passed on Anvil's command line,
  so it is visible to other local processes (`ps`) on the same host.
- **Balance diffs are sender-only.** Other parties' changes appear only as
  transfers.
- **No state overrides yet.** E.g. "simulate as if the allowance were already
  set" is not supported.
- **Transaction hashes.** Historical replay by hash is not implemented
  (planned with the scanner).
