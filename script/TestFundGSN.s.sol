pragma solidity ^0.8.13;

import "forge-std/Script.sol";


contract MyScript is Script {
    function run() external {
        vm.startBroadcast();

        address payable relayHub = payable(0x04Cd8B3e384e7bBB01109bc8b6708fCAeD5e9eB0);
        address payable stakeManager = payable(0xE7Df3511F5135Ff492c6f9E2072d4eA53E992B8d);
        address payable penalizer = payable(0x6D396Ef29C3f4873e9861978f299bdE458116eB8);
        
        relayHub.send(10 ether);

        vm.stopBroadcast();
    }
}
