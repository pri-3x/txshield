// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

interface IERC20Min {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

/// @notice 1:1 exchange used as a benign "swap" counterpart (false-positive
/// test: tokens leave the wallet, other tokens come back).
contract SimpleExchange {
    function swap(address tokenIn, address tokenOut, uint256 amountIn) external {
        IERC20Min(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20Min(tokenOut).transfer(msg.sender, amountIn);
    }
}

/// @notice Logic contract behind the proxy fixtures.
contract ProxyLogic {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }
}

/// @notice Minimal EIP-1967 proxy.
contract ERC1967Proxy {
    bytes32 private constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address impl) {
        assembly {
            sstore(IMPL_SLOT, impl)
        }
    }

    fallback() external payable {
        assembly {
            let impl := sload(IMPL_SLOT)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

/// @notice Deploys EIP-1167 minimal proxies.
contract Cloner {
    event Cloned(address clone);

    function clone(address impl) external returns (address instance) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), shl(0x60, impl))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            instance := create(0, ptr, 0x37)
        }
        require(instance != address(0), "clone failed");
        emit Cloned(instance);
    }
}
