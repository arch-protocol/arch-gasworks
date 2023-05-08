// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13.0;

import { Script } from "forge-std/Script.sol";
import { Gasworks } from "src/Gasworks.sol";

contract MyScript is Script {
    function run() external {
        vm.startBroadcast();

        new Gasworks(
            0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d, 
            0x1c0c05a2aA31692e5dc9511b04F651db9E4d8320, 
            0x2B13D2b9407D5776B0BB63c8cd144978B6B7cE58
        );

        vm.stopBroadcast();
    }
}
