pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/PermitSwap.sol";

contract MyScript is Script {
    function run() external {
        vm.startBroadcast();

        PermitSwap t = new PermitSwap();

        vm.stopBroadcast();
    }
}
