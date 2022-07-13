//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "src/ArchPaymaster.sol";

contract MyScript is Script {
    function run() external {
        vm.startBroadcast();

        ArchPaymaster t = new ArchPaymaster();

        vm.stopBroadcast();
    }
}
