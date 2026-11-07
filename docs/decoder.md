# Transaction Decoder

Package `internal/decoder` turns calldata into a structured call tree
(`models.DecodedCall`). It is offline (no RPC), deterministic, and never fails
on unrecognized or malformed calldata.

> Recognizing a function says nothing about whether calling it is safe.
> The decoder reports *what the calldata says*; the rules engine ([docs](security-rules.md))
> decides what is risky.

## Contract

| Input | Result |
|---|---|
| `to` set, no data | `kind: native_transfer` |
| no `to`, data | `kind: contract_creation`, init code size and keccak hash; init code itself is not analyzed |
| data shorter than 4 bytes | `kind: unknown`, warning (target's fallback would run) |
| unknown selector | `kind: unknown`, `selector`, `rawData` |
| known selector, arguments decode | `kind: contract_call`, `method`, `signature`, `standard`, `params`, `source` |
| known selector, arguments do not decode | `kind: contract_call`, no `method`, `candidates`, `rawData`, warning |
| canonical re-encoding differs | warning: trailing bytes (shown, up to 64) or non-canonical encoding |

`Decode` returns an error only for an invalid/oversized user ABI or a
cancelled context.

### Standards are interfaces, not identities

`standard` means "this calldata matches that interface". A
`uniswap-v2-router` call may target a fork, or a malicious contract that copied
the selector. When identical signatures belong to several standards, they are
joined with `|`:

- `approve(address,uint256)`, `transferFrom(address,address,uint256)` → `erc20|erc721`
  (parameter named `amountOrTokenId`; the standard is resolved from chain state
  in later phases)
- `setApprovalForAll(address,bool)` → `erc721|erc1155`

### Parameter rendering (stable API)

| ABI type | JSON value |
|---|---|
| `uintN` / `intN` (all widths) | decimal string |
| `address` | EIP-55 checksummed string |
| `bytes`, `bytesN`, `function` | `0x` hex string |
| `bool` | boolean |
| `string` | string (**untrusted**: consumers must escape; the CLI strips control characters) |
| arrays | JSON array |
| tuples | array of `{name, type, value}` |

Parameters TxShield computes itself (for example `pathDecoded` for Uniswap V3
paths) have `type: "derived"`.

## Supported signatures (built-in)

| Standard | Functions |
|---|---|
| ERC-20 | `transfer`, `approve`*, `transferFrom`*, `increaseAllowance`, `decreaseAllowance` |
| ERC-721 | `safeTransferFrom` (3 and 4 args), `approve`*, `transferFrom`*, `setApprovalForAll`* |
| ERC-1155 | `safeTransferFrom`, `safeBatchTransferFrom`, `setApprovalForAll`* |
| EIP-2612 / DAI permit | `permit` (both variants) |
| Permit2 | `approve`, `permit` (single, batch), `transferFrom` (single, batch), `permitTransferFrom` (single, batch), `lockdown`, `invalidateNonces` |
| WETH | `deposit`, `withdraw` |
| Uniswap V2 router | 9 swap variants, `addLiquidity(ETH)`, `removeLiquidity(ETH)` |
| Uniswap V3 SwapRouter | `exactInput(Single)`, `exactOutput(Single)`, `unwrapWETH9`, `sweepToken`, `refundETH` |
| Uniswap SwapRouter02 | deadline-less `exact*`, V2-style swaps, `unwrapWETH9`, `sweepToken` |
| Uniswap Universal Router | `execute` (with/without deadline) + command decoding |
| Multicall | `multicall(bytes[])`, `multicall(uint256,bytes[])`, `multicall(bytes32,bytes[])` |
| Multicall3 | `aggregate`, `tryAggregate`, `blockAndAggregate`, `tryBlockAndAggregate`, `aggregate3`, `aggregate3Value` |
| Ownable | `transferOwnership`, `renounceOwnership`, `acceptOwnership` |
| Proxy admin | `upgradeTo`, `upgradeToAndCall`, `changeAdmin`, ProxyAdmin `upgrade`, `upgradeAndCall` |
| Gnosis Safe | `execTransaction` |

\* shared signature, see above. `internal/decoder/registry_test.go` pins 35 of
these against well-known mainnet selectors.

## Nested calls

| Container | Children |
|---|---|
| `multicall(...bytes[])` | each entry decoded against the same target, `callType: self` |
| Multicall3 | each `(target, [allowFailure], [value], callData)`, `callType: call`, value attached |
| Universal Router `execute` | one child per command, `callType: router_command`; the allow-revert flag (0x80) produces a warning |
| Safe `execTransaction` | inner call; `operation=1` yields `callType: delegatecall` and a warning |
| `upgradeToAndCall` / `upgradeAndCall` | init data as `callType: delegatecall` against the proxy |

Universal Router command types `0x00`-`0x0e` are decoded (V3/V2 swaps, Permit2
permit/transfer, wrap/unwrap, sweep, transfer, pay portion, balance check).
Types `0x10` and above differ between router versions and are reported as
unrecognized with raw input instead of being guessed.

A user-supplied ABI applies only to the top-level target, including its
self-multicall children, never to other contracts reached through Multicall3,
Safe, or similar containers.

## Limits

| Limit | Default | Behavior when reached |
|---|---|---|
| Nesting depth | 4 | deeper children not decoded; warning on root |
| Total decoded calls | 256 | remaining children skipped; warning on root |
| User ABI size | 512 KiB (API), 4 MiB (CLI) | `payload_too_large` |
| Calldata size | `TXSHIELD_MAX_CALLDATA_BYTES` (128 KiB API), 1 MiB CLI | validation error |

ABI decoding of attacker-controlled bytes runs under `recover`; a panic inside
the ABI library is turned into a decode failure for that candidate.

## CLI

```bash
txshield decode --to 0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD --data 0x3593564c...
txshield decode --data - --json < calldata.txt
txshield decode --to 0xContract --abi ./Contract.abi.json --data 0x...
```

Exit codes: `0` decoded, `2` invalid input (bad hex, bad address, bad ABI), `1` other failure.

## Testing

- Unit tests: every call kind, every nested container, limits, user ABI
  precedence and scoping, rendering of all ABI type families, cancellation.
- Fuzzing: `FuzzDecode` (arbitrary calldata) and `FuzzDecodeKnownSelector`
  (random arguments behind every registered selector). Invariant: no error, no
  panic, JSON-serializable result.

## Benchmarks

Methodology: `go test -run=^$ -bench=. -benchmem -count=5 ./internal/decoder/`
on an idle machine; numbers are the range across the 5 runs. Inputs are built
in the benchmark functions in `internal/decoder/fuzz_test.go`.

Current results and the machine they were measured on are in
[benchmarks.md](benchmarks.md#decoder).

Roughly half the per-call cost is the canonical re-encoding check; it is kept
because it detects smuggled trailing data.
