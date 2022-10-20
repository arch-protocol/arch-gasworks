// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/Gasworks.sol";

contract MyScript is Script {
    function run() external {
        vm.startBroadcast();

        Gasworks gasworks = Gasworks(0x6C158DDF5362129e4aDcCC7817bEe25998B677F5);

        gasworks.setTokens(0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174);
        gasworks.setTokens(0xBcD2C5C78000504EFBC1cE6489dfcaC71835406A);

        vm.stopBroadcast();
    }
}
