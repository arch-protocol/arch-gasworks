// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import { Script } from "forge-std/Script.sol";
import { Gasworks } from "src/Gasworks.sol";

contract DeployGasworks is Script {
    function run() external {
        vm.createSelectFork("polygon");
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // All addresses are on Polygon Mainnet
        Gasworks gasworks = new Gasworks(
            0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d, // Biconomy Forwarder
            0xdCB99117Ba207b996EE3c49eE6F8c0f1d371867A // TradeIssuerV3
        );

        gasworks.setTokens(0xBcD2C5C78000504EFBC1cE6489dfcaC71835406A); // WEB3
        gasworks.setTokens(0x9a41E03fEF7f16f552C6FbA37fFA7590fb1Ec0c4); // CHAIN
        gasworks.setTokens(0x027aF1E12a5869eD329bE4c05617AD528E997D5A); // AEDY
        gasworks.setTokens(0xAb1B1680f6037006e337764547fb82d17606c187); // ADDY
        gasworks.setTokens(0xAfb6E8331355faE99C8E8953bB4c6Dc5d11E9F3c); // AAGG
        gasworks.setTokens(0xa5a979Aa7F55798e99f91Abe815c114A09164beb); // AMOD updated
        gasworks.setTokens(0xF401E2c1ce8F252947b60BFB92578f84217A1545); // ABAL
        gasworks.setTokens(0xC4ea087fc2cB3a1D9ff86c676F03abE4F3EE906F); // WEB3V2
        gasworks.setTokens(0x70A13201Df2364B634cb5Aac8d735Db3A654b30c); // CHAINV2
        gasworks.setTokens(0xdE2925D582fc8711a0E93271c12615Bdd043Ed1C); // ABDY
        gasworks.setTokens(0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174); // USDC.e
        gasworks.setTokens(0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359); // USDC
        gasworks.setTokens(0xc2132D05D31c914a87C6611C10748AEb04B58e8F); // USDT
        gasworks.setTokens(0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063); // DAI
        gasworks.setTokens(0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6); // WBTC
        gasworks.setTokens(0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270); // WMATIC
        gasworks.setTokens(0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619); // WETH
        
        gasworks.transferOwnership(0xe560EfD37a77486aa0ecAed4203365BDe5363dbB); // Arch Safe Address

        vm.stopBroadcast();
    }
}
