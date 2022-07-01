pragma solidity ^0.8.13;

import "forge-std/Script.sol";
// import "../src/CaptureTheFlag.sol";

contract MyScript is Script {
    function run() external {
        vm.startBroadcast();

        // CaptureTheFlag t = new CaptureTheFlag(0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0);

        vm.stopBroadcast();
    }
}
