// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21.0;

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
            0x1c0c05a2aA31692e5dc9511b04F651db9E4d8320, // ExchangeIssuanceZeroEx
            0x2B13D2b9407D5776B0BB63c8cd144978B6B7cE58  // TradeIssuerV2
        );

        gasworks.setTokens(0x6cA9C8914a14D63a6700556127D09e7721ff7D3b); // AP60
        gasworks.setTokens(0xAb1B1680f6037006e337764547fb82d17606c187); // ADDY
        gasworks.setTokens(0x9a41E03fEF7f16f552C6FbA37fFA7590fb1Ec0c4); // CHAIN
        gasworks.setTokens(0xBcD2C5C78000504EFBC1cE6489dfcaC71835406A); // WEB3
        gasworks.setTokens(0x8F0d5660929cA6ac394c5c41f59497629b1dbc23); // AMOD
        gasworks.setTokens(0xF401E2c1ce8F252947b60BFB92578f84217A1545); // ABAL
        gasworks.setTokens(0xAfb6E8331355faE99C8E8953bB4c6Dc5d11E9F3c); // AAGG
        gasworks.setTokens(0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174); // USDC
        gasworks.setTokens(0x027aF1E12a5869eD329bE4c05617AD528E997D5A); // AEDY
        gasworks.setTokens(0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270); // WMATIC
        gasworks.setTokens(0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619); // WETH
        gasworks.setTokens(0xc2132D05D31c914a87C6611C10748AEb04B58e8F); // USDT
        gasworks.setTokens(0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6); // WBTC

        gasworks.transferOwnership(0x2f91966dF1722691DA79a69Be6435378A1c3b3Bf); // Arch-dev-Max wallet
        // gasworks.transferOwnership(0xe560EfD37a77486aa0ecAed4203365BDe5363dbB); // Arch Safe Address

        vm.stopBroadcast();
    }
}
