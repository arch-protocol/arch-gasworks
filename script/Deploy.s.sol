pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/PermitSwap.sol";
import {MockERC20} from "solmate/test/utils/mocks/MockERC20.sol";


contract MyScript is Script {
    function run() external {
        vm.startBroadcast();

        MockERC20 web3 = new MockERC20("Arch Web3 Token", "WEB3", 18);

        MockERC20 usdc = new MockERC20("Circle USD Coin", "USDC", 6);

        usdc.mint(0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f, 1e8);

        PermitSwap t = new PermitSwap(address(web3));

        vm.stopBroadcast();
    }
}
