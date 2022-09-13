pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/Gasworks.sol";

contract MyScript is Script {
    function run() external {
        vm.startBroadcast();

        new Gasworks(0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d);

        vm.stopBroadcast();
    }
}
