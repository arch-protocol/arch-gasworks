pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/PermitSwap.sol";
import {MockERC20} from "solmate/test/utils/mocks/MockERC20.sol";


contract MyScript is Script {
    function run() external {
        vm.startBroadcast();

        PermitSwap t = new PermitSwap();

        vm.stopBroadcast();
    }
}
