package decoder

// Standard identifiers. A standard here means "interface-compatible with",
// not "deployed by": many forks reuse Uniswap's router interface, and any
// contract can implement an ERC-20 selector. Recognizing a selector says
// nothing about whether the call is safe.
const (
	StdERC20         = "erc20"
	StdERC20or721    = "erc20|erc721"
	StdERC721        = "erc721"
	StdERC721or1155  = "erc721|erc1155"
	StdERC1155       = "erc1155"
	StdEIP2612       = "eip2612-permit"
	StdDAIPermit     = "dai-permit"
	StdPermit2       = "permit2"
	StdWETH          = "weth"
	StdUniV2Router   = "uniswap-v2-router"
	StdUniV3Router   = "uniswap-v3-router"
	StdUniRouter02   = "uniswap-swaprouter02"
	StdUniversal     = "uniswap-universal-router"
	StdMulticall     = "multicall"
	StdMulticall3    = "multicall3"
	StdOwnable       = "ownable"
	StdProxy         = "proxy-upgrade"
	StdSafe          = "gnosis-safe"
	StdRouterCommand = "uniswap-universal-router-command"
)

// Flash-loan related standards.
const (
	StdFlashLoan = "flash-loan"
	StdUniV2Pair = "uniswap-v2-pair"
)

const (
	permitDetails = "(address token, uint160 amount, uint48 expiration, uint48 nonce)"
	permitSingle  = "(" + permitDetails + " details, address spender, uint256 sigDeadline)"
	permitBatch   = "(" + permitDetails + "[] details, address spender, uint256 sigDeadline)"
)

var builtinSpecs = []spec{
	// --- ERC-20 / ERC-721 / ERC-1155 ---
	{standard: StdERC20, sig: "transfer(address to, uint256 amount)"},
	{standard: StdERC20or721, sig: "approve(address spender, uint256 amountOrTokenId)"},
	{standard: StdERC20or721, sig: "transferFrom(address from, address to, uint256 amountOrTokenId)"},
	{standard: StdERC20, sig: "increaseAllowance(address spender, uint256 addedValue)"},
	{standard: StdERC20, sig: "decreaseAllowance(address spender, uint256 subtractedValue)"},
	{standard: StdERC721, sig: "safeTransferFrom(address from, address to, uint256 tokenId)"},
	{standard: StdERC721, sig: "safeTransferFrom(address from, address to, uint256 tokenId, bytes data)"},
	{standard: StdERC721or1155, sig: "setApprovalForAll(address operator, bool approved)"},
	{standard: StdERC1155, sig: "safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes data)"},
	{standard: StdERC1155, sig: "safeBatchTransferFrom(address from, address to, uint256[] ids, uint256[] amounts, bytes data)"},

	// --- Signature-based approvals ---
	{standard: StdEIP2612, sig: "permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)"},
	{standard: StdDAIPermit, sig: "permit(address holder, address spender, uint256 nonce, uint256 expiry, bool allowed, uint8 v, bytes32 r, bytes32 s)"},
	{standard: StdPermit2, sig: "approve(address token, address spender, uint160 amount, uint48 expiration)"},
	{standard: StdPermit2, sig: "permit(address owner, " + permitSingle + " permitSingle, bytes signature)"},
	{standard: StdPermit2, sig: "permit(address owner, " + permitBatch + " permitBatch, bytes signature)"},
	{standard: StdPermit2, sig: "transferFrom(address from, address to, uint160 amount, address token)"},
	{standard: StdPermit2, sig: "transferFrom((address from, address to, uint160 amount, address token)[] transferDetails)"},
	{standard: StdPermit2, sig: "permitTransferFrom(((address token, uint256 amount) permitted, uint256 nonce, uint256 deadline) permit, (address to, uint256 requestedAmount) transferDetails, address owner, bytes signature)"},
	{standard: StdPermit2, sig: "permitTransferFrom(((address token, uint256 amount)[] permitted, uint256 nonce, uint256 deadline) permit, (address to, uint256 requestedAmount)[] transferDetails, address owner, bytes signature)"},
	{standard: StdPermit2, sig: "lockdown((address token, address spender)[] approvals)"},
	{standard: StdPermit2, sig: "invalidateNonces(address token, address spender, uint48 newNonce)"},

	// --- WETH ---
	{standard: StdWETH, sig: "deposit()"},
	{standard: StdWETH, sig: "withdraw(uint256 amount)"},

	// --- Uniswap V2 router (and interface-compatible forks) ---
	{standard: StdUniV2Router, sig: "swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)"},
	{standard: StdUniV2Router, sig: "swapTokensForExactTokens(uint256 amountOut, uint256 amountInMax, address[] path, address to, uint256 deadline)"},
	{standard: StdUniV2Router, sig: "swapExactETHForTokens(uint256 amountOutMin, address[] path, address to, uint256 deadline)"},
	{standard: StdUniV2Router, sig: "swapTokensForExactETH(uint256 amountOut, uint256 amountInMax, address[] path, address to, uint256 deadline)"},
	{standard: StdUniV2Router, sig: "swapExactTokensForETH(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)"},
	{standard: StdUniV2Router, sig: "swapETHForExactTokens(uint256 amountOut, address[] path, address to, uint256 deadline)"},
	{standard: StdUniV2Router, sig: "swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)"},
	{standard: StdUniV2Router, sig: "swapExactETHForTokensSupportingFeeOnTransferTokens(uint256 amountOutMin, address[] path, address to, uint256 deadline)"},
	{standard: StdUniV2Router, sig: "swapExactTokensForETHSupportingFeeOnTransferTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)"},
	{standard: StdUniV2Router, sig: "addLiquidity(address tokenA, address tokenB, uint256 amountADesired, uint256 amountBDesired, uint256 amountAMin, uint256 amountBMin, address to, uint256 deadline)"},
	{standard: StdUniV2Router, sig: "addLiquidityETH(address token, uint256 amountTokenDesired, uint256 amountTokenMin, uint256 amountETHMin, address to, uint256 deadline)"},
	{standard: StdUniV2Router, sig: "removeLiquidity(address tokenA, address tokenB, uint256 liquidity, uint256 amountAMin, uint256 amountBMin, address to, uint256 deadline)"},
	{standard: StdUniV2Router, sig: "removeLiquidityETH(address token, uint256 liquidity, uint256 amountTokenMin, uint256 amountETHMin, address to, uint256 deadline)"},

	// --- Uniswap V3 SwapRouter ---
	{standard: StdUniV3Router, sig: "exactInputSingle((address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96) params)"},
	{standard: StdUniV3Router, sig: "exactInput((bytes path, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum) params)"},
	{standard: StdUniV3Router, sig: "exactOutputSingle((address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 deadline, uint256 amountOut, uint256 amountInMaximum, uint160 sqrtPriceLimitX96) params)"},
	{standard: StdUniV3Router, sig: "exactOutput((bytes path, address recipient, uint256 deadline, uint256 amountOut, uint256 amountInMaximum) params)"},
	{standard: StdUniV3Router, sig: "unwrapWETH9(uint256 amountMinimum, address recipient)"},
	{standard: StdUniV3Router, sig: "sweepToken(address token, uint256 amountMinimum, address recipient)"},
	{standard: StdUniV3Router, sig: "refundETH()"},

	// --- Uniswap SwapRouter02 (no deadline in params) ---
	{standard: StdUniRouter02, sig: "exactInputSingle((address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96) params)"},
	{standard: StdUniRouter02, sig: "exactInput((bytes path, address recipient, uint256 amountIn, uint256 amountOutMinimum) params)"},
	{standard: StdUniRouter02, sig: "exactOutputSingle((address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 amountOut, uint256 amountInMaximum, uint160 sqrtPriceLimitX96) params)"},
	{standard: StdUniRouter02, sig: "exactOutput((bytes path, address recipient, uint256 amountOut, uint256 amountInMaximum) params)"},
	{standard: StdUniRouter02, sig: "swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to)"},
	{standard: StdUniRouter02, sig: "swapTokensForExactTokens(uint256 amountOut, uint256 amountInMax, address[] path, address to)"},
	{standard: StdUniRouter02, sig: "unwrapWETH9(uint256 amountMinimum)"},
	{standard: StdUniRouter02, sig: "sweepToken(address token, uint256 amountMinimum)"},

	// --- Uniswap Universal Router ---
	{standard: StdUniversal, sig: "execute(bytes commands, bytes[] inputs, uint256 deadline)", nested: NestedUniversalRouter},
	{standard: StdUniversal, sig: "execute(bytes commands, bytes[] inputs)", nested: NestedUniversalRouter},

	// --- Multicall variants ---
	{standard: StdMulticall, sig: "multicall(bytes[] data)", nested: NestedSelfMulticall, argIndex: []int{0}},
	{standard: StdMulticall, sig: "multicall(uint256 deadline, bytes[] data)", nested: NestedSelfMulticall, argIndex: []int{1}},
	{standard: StdMulticall, sig: "multicall(bytes32 previousBlockhash, bytes[] data)", nested: NestedSelfMulticall, argIndex: []int{1}},
	{standard: StdMulticall3, sig: "aggregate((address target, bytes callData)[] calls)", nested: NestedMulticall3, argIndex: []int{0}},
	{standard: StdMulticall3, sig: "tryAggregate(bool requireSuccess, (address target, bytes callData)[] calls)", nested: NestedMulticall3, argIndex: []int{1}},
	{standard: StdMulticall3, sig: "tryBlockAndAggregate(bool requireSuccess, (address target, bytes callData)[] calls)", nested: NestedMulticall3, argIndex: []int{1}},
	{standard: StdMulticall3, sig: "blockAndAggregate((address target, bytes callData)[] calls)", nested: NestedMulticall3, argIndex: []int{0}},
	{standard: StdMulticall3, sig: "aggregate3((address target, bool allowFailure, bytes callData)[] calls)", nested: NestedMulticall3, argIndex: []int{0}},
	{standard: StdMulticall3, sig: "aggregate3Value((address target, bool allowFailure, uint256 value, bytes callData)[] calls)", nested: NestedMulticall3, argIndex: []int{0}},

	// --- Ownership and proxy administration ---
	{standard: StdOwnable, sig: "transferOwnership(address newOwner)"},
	{standard: StdOwnable, sig: "renounceOwnership()"},
	{standard: StdOwnable, sig: "acceptOwnership()"},
	{standard: StdProxy, sig: "upgradeTo(address newImplementation)"},
	{standard: StdProxy, sig: "upgradeToAndCall(address newImplementation, bytes data)", nested: NestedUpgradeAndCall, argIndex: []int{1}},
	{standard: StdProxy, sig: "changeAdmin(address newAdmin)"},
	{standard: StdProxy, sig: "upgrade(address proxy, address implementation)"},
	{standard: StdProxy, sig: "upgradeAndCall(address proxy, address implementation, bytes data)", nested: NestedUpgradeAndCall, argIndex: []int{2}},

	// --- Flash loans (Aave V3, Balancer V2, Uniswap V3 pool, ERC-3156) ---
	{standard: StdFlashLoan, sig: "flashLoanSimple(address receiverAddress, address asset, uint256 amount, bytes params, uint16 referralCode)"},
	{standard: StdFlashLoan, sig: "flashLoan(address receiverAddress, address[] assets, uint256[] amounts, uint256[] interestRateModes, address onBehalfOf, bytes params, uint16 referralCode)"},
	{standard: StdFlashLoan, sig: "flashLoan(address recipient, address[] tokens, uint256[] amounts, bytes userData)"},
	{standard: StdFlashLoan, sig: "flash(address recipient, uint256 amount0, uint256 amount1, bytes data)"},
	{standard: StdFlashLoan, sig: "flashLoan(address receiver, address token, uint256 amount, bytes data)"},
	// Pair-level swap: non-empty data makes it a flash swap.
	{standard: StdUniV2Pair, sig: "swap(uint256 amount0Out, uint256 amount1Out, address to, bytes data)"},

	// --- Gnosis Safe ---
	{standard: StdSafe, sig: "execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures)", nested: NestedSafeExec},
}
