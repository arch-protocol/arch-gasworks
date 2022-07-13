pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/PermitSwapGasless.sol";
import {MockERC20} from "solmate/test/utils/mocks/MockERC20.sol";


contract MyScript is Script {
    function run() external {
        vm.startBroadcast();

        PermitSwapGasless t = new PermitSwapGasless(0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d);

        vm.stopBroadcast();
    }
}
