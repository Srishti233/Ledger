// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {AuditAnchor} from "../src/AuditAnchor.sol";

/// Usage (local Anvil, test keys only):
///   ANCHORER=0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
///   forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast \
///     --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
/// Without --broadcast it only simulates (this is what CI runs).
contract Deploy is Script {
    function run() external returns (AuditAnchor anchor) {
        address anchorer = vm.envOr("ANCHORER", address(0));
        vm.startBroadcast();
        anchor = new AuditAnchor();
        if (anchorer != address(0)) {
            anchor.setAnchorer(anchorer, true);
        }
        vm.stopBroadcast();
        console2.log("AuditAnchor deployed at", address(anchor));
    }
}
