# Benchmarks

All numbers on this page were measured on one machine and are reproducible
with the commands shown. They describe TxShield's own overhead. They are not
production capacity figures: real deployments add upstream RPC latency to
every simulation and to every contract inspection.

**Machine:** Apple M4 (4 performance + 6 efficiency cores), 16 GB RAM,
macOS (darwin/arm64), Go 1.26.2, Anvil 1.8.5. Measured 2026-11-07 on an
otherwise idle machine. Ranges are min-max across the repeated runs (`-count`).

## How to reproduce

```bash
# Decoder, rules, offline analysis, API (no network)
go test -run '^$' -bench . -benchmem -count 5 ./internal/decoder/ ./internal/security/rules/ ./internal/analyzer/
go test -run '^$' -bench BenchmarkAPIAnalyzeParallel -benchmem -count 5 -cpu 1,2,4,10 ./internal/api/

# Simulation (needs Foundry; starts a local Anvil chain as the "upstream")
go test -tags integration -run '^$' -bench 'AnvilSimulate$' -benchtime 50x -count 3 ./tests/integration/
go test -tags integration -run '^$' -bench AnvilSimulateWorkers -benchtime 100x ./tests/integration/
go test -tags integration -run TestAnvilColdStart -v ./tests/integration/
```

On macOS, let TCP TIME_WAIT sockets drain (about 30 s) between simulation
benchmark runs; see [Simulation](#simulation) for why.

## What each benchmark measures

| Benchmark | Scope | Input |
|---|---|---|
| `BenchmarkDecode*` (`internal/decoder`) | Calldata decoding only, including nested calls and the re-encoding check | Built in `fuzz_test.go` |
| `BenchmarkRules*` (`internal/security/rules`) | All 29 rules on a prepared analysis context | ERC-20 transfer; drainer with simulated outflows |
| `BenchmarkAnalyze*` (`internal/analyzer`) | Full offline analysis: decode, approval extraction, reputation, rules, scoring, report | Security scenario fixtures (`tests/fixtures/scenarios`) |
| `BenchmarkAPIAnalyzeParallel` (`internal/api`) | `POST /api/v1/analyze` through the full middleware chain (request ID, auth, rate limiter disabled, body limit, JSON) with `b.RunParallel`; offline engine, no RPC | Unlimited `approve` to a blocklisted spender |
| `BenchmarkAnvilSimulate` (`tests/integration`) | One warm simulation: `anvil_reset` re-fork through the fork relay, impersonation, execution, receipt polling, `debug_traceTransaction`, log and balance diffs | ERC-20 transfer; drainer `claim()` |
| `BenchmarkAnvilSimulateWorkers` | Simulation throughput with 1, 2, 4 workers under parallel load (queueing included) | ERC-20 transfer |
| `TestAnvilColdStart` | First simulation on a new worker: process launch, fork, simulate | ERC-20 transfer |

In `ns/op` for parallel benchmarks, the time is wall-clock divided by total
operations, so lower means more throughput.

## Results

### Decoder

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| ERC-20 `transfer` | 1,138 - 1,265 | 1,304 | 28 |
| Universal Router: V3 swap + unwrap | 6,375 - 6,589 | 12,276 | 173 |
| Multicall3 `aggregate3` with 50 `approve` calls | 173,267 - 175,094 | 347,416 | 4,456 |
| Unknown selector, 256-byte args | 594 - 631 | 1,584 | 8 |

These include the element-budget walk added in this release (see
[threat model](threat-model.md), ABI allocation bombs), which added about
3-6% over the previous numbers.

### Rules and offline analysis

| Benchmark | Before tuning | After tuning | B/op (after) | allocs/op (after) |
|---|---|---|---|---|
| Rules, ERC-20 transfer | 29 - 31 µs | 14.8 - 15.8 µs | 8,760 | 73 |
| Rules, drainer with simulation | ~45 µs | 44.7 - 44.9 µs | 38,170 | 511 |
| Analyze, unlimited approval to blocklisted spender | 57 - 68 µs | 41.8 - 42.9 µs | 34,840 | 368 |
| Analyze, drainer with simulation | 57 - 68 µs | 39.7 - 40.5 µs | 54,650 | 493 |
| Analyze, Universal Router swap | 57 - 68 µs | 48.7 - 51.0 µs | 41,570 | 518 |

### API under parallel load (offline engine)

| GOMAXPROCS | Before tuning | After tuning | Approx. requests/s (after) |
|---|---|---|---|
| 1 | ~99 µs | 50.9 - 51.6 µs | ~19,600 |
| 2 | ~55 µs | 29.3 - 29.9 µs | ~34,000 |
| 4 | 43 - 51 µs | 20.0 - 21.5 µs | ~48,000 |
| 10 | 68 - 70 µs | 34.4 - 35.6 µs | ~29,000 |
| 10, `GOGC=400` | n/a | 12.4 - 13.6 µs | ~77,000 |

**What changed.** The first profile at 10 cores showed about 44% of CPU in
the Go scheduler and timers (`runtime.lock2`, `usleep`, `pthread_*`). The rule
engine started two goroutines and one timeout timer per rule (29 rules per
analysis), and the reputation aggregator always started 8 workers. Now:

- rules run in order on one worker goroutine supervised by one reusable
  timer. A rule that exceeds its budget is reported as timed out and a fresh
  worker continues with the next rule, so isolation is unchanged (tested in
  `TestEngineIsolation` and `TestEngineRecoversAfterEachTimeout`);
- in-memory reputation providers are queried inline; only I/O-backed
  providers use the worker pool, sized `min(8, lookups)`.

**Remaining scaling limit.** At 10 cores the remaining time is the Go heap
(`mheap.allocSpan`, `madvise`, heap lock), driven by garbage collection: each
request allocates about 54 KB, and the benchmark's live heap is tiny, so the
default `GOGC=100` triggers collections constantly. The `GOGC=400` row shows
that the code itself scales past 4 cores. A real server has a larger live heap
(connection pools, caches), so collections are less frequent; if profiling
shows GC dominating, raise `GOGC` and set `GOMEMLIMIT` below the container
memory limit. The 10-core row also includes the M4's 6 efficiency cores.

### Simulation

Against a local Anvil "upstream" (no network latency):

| Measurement | Result |
|---|---|
| Warm simulation, ERC-20 transfer | 25.9 - 26.8 ms |
| Warm simulation, drainer `claim()` (3 tokens + NFT + ETH) | 28.3 - 38.3 ms |
| Cold start (process launch + fork + simulate), 5 runs | 52 - 103 ms |
| Parallel load, 1 worker | 26.8 ms/op (~37 simulations/s) |
| Parallel load, 2 workers | 13.9 ms/op (~72 simulations/s) |
| Parallel load, 4 workers | 7.2 ms/op (~138 simulations/s) |

Throughput scales close to linearly with workers, because each worker is a
separate Anvil process. Each worker uses one Anvil process (tens of MB of RSS
plus fork state), so size `TXSHIELD_SIMULATION_MAX_CONCURRENT` to memory as
well as CPU.

The previous measurement of the warm transfer, before the fork relay
existed, was 25.0 - 26.0 ms. The difference of under 1 ms is within
run-to-run noise: the relay added no measurable latency.

**Connection churn.** Anvil opens about 25-30 new connections to its fork
endpoint on every `anvil_reset` and closes them on the next one. With the
fork relay those connections stay on loopback, and the relay keeps a pooled
keep-alive connection set to the real provider, so TLS connections to the
provider are reused across simulations. The loopback sockets still pass
through TIME_WAIT. On macOS (16,384 ephemeral ports, 30 s TIME_WAIT) that
caps sustained simulation to roughly 18 per second on one host; bursts above
that work until the ports run out ("Can't assign requested address"). Linux
reuses TIME_WAIT ports for loopback connections by default
(`net.ipv4.tcp_tw_reuse=2`), so containers are not affected.

## Not measured

- Simulation against real remote RPC providers (latency depends on the
  provider, region, and plan; most of a real simulation's time is upstream
  state reads).
- Postgres write throughput under load.
- Memory use of Anvil workers under sustained load.
- Linux; all numbers above are from macOS on Apple silicon.
