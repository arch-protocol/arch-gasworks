pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/PermitSwapGasless.sol";
import {MockERC20} from "solmate/test/utils/mocks/MockERC20.sol";


contract MyScript is Script {
    function run() external {
        vm.startBroadcast();

        PermitSwapGasless t = new PermitSwapGasless(0x95bD8D42f30351685e96C62EDdc0d0613bf9a87A, 0xa85233C63b9Ee964Add6F2cffe00Fd84eb32338f);

        vm.stopBroadcast();
    }
}
