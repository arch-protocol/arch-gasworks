// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21.0;

import { Test } from "forge-std/Test.sol";
import { Conversor } from "test/utils/HexUtils.sol";
import { ITradeIssuerV2 } from "chambers-peripherals/src/interfaces/ITradeIssuerV2.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";

contract ArchUtils is Test {
    // ChainId
    uint256 public constant ETH_CHAIN_ID = 1;
    uint256 public constant POLYGON_CHAIN_ID = 137;
    // Mainnet
    address public constant ETH_WEB3 = 0xe8e8486228753E01Dbc222dA262Aa706Bd67e601;
    address public constant ETH_CHAIN = 0x0d20e86AbAb680C038Ac8bBDc1446585e67f8951;
    address public constant ETH_AEDY = 0x103bb3EBc6F61b3DB2d6e01e54eF7D9899A2E16B;
    address public constant ETH_ADDY = 0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF;
    address public constant ETH_USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address public constant ETH_USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address public constant ETH_DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address public constant ETH_WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;
    address public constant ETH_WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address public constant ETH_TRADE_ISSUER_V2 = 0xbbCA2AcBd87Ce7A5e01fb56914d41F6a7e5C5A56;
    address public constant ETH_ISSUER_WIZARD = 0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449;
    address public constant ETH_EXCHANGE_ISSUANCE = 0x90F765F63E7DC5aE97d6c576BF693FB6AF41C129;
    address public constant ETH_BICONOMY_FORWARDER = 0x84a0856b038eaAd1cC7E297cF34A7e72685A8693;
    address public constant ETH_UNISWAP_PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    // Polygon
    address public constant POLYGON_WEB3 = 0xBcD2C5C78000504EFBC1cE6489dfcaC71835406A;
    address public constant POLYGON_CHAIN = 0x9a41E03fEF7f16f552C6FbA37fFA7590fb1Ec0c4;
    address public constant POLYGON_AEDY = 0x027aF1E12a5869eD329bE4c05617AD528E997D5A;
    address public constant POLYGON_ADDY = 0xAb1B1680f6037006e337764547fb82d17606c187;
    address public constant POLYGON_AAGG = 0xAfb6E8331355faE99C8E8953bB4c6Dc5d11E9F3c;
    address public constant POLYGON_AMOD = 0x8F0d5660929cA6ac394c5c41f59497629b1dbc23;
    address public constant POLYGON_ABAL = 0xF401E2c1ce8F252947b60BFB92578f84217A1545;
    address public constant POLYGON_AP60 = 0x6cA9C8914a14D63a6700556127D09e7721ff7D3b;
    address public constant POLYGON_USDC = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174;
    address public constant POLYGON_USDT = 0xc2132D05D31c914a87C6611C10748AEb04B58e8F;
    address public constant POLYGON_DAI = 0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063;
    address public constant POLYGON_WBTC = 0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6;
    address public constant POLYGON_WMATIC = 0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270;
    address public constant POLYGON_TRADE_ISSUER_V2 = 0x2B13D2b9407D5776B0BB63c8cd144978B6B7cE58;
    address public constant POLYGON_ISSUER_WIZARD = 0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449;
    address public constant POLYGON_EXCHANGE_ISSUANCE = 0x1c0c05a2aA31692e5dc9511b04F651db9E4d8320;
    address public constant POLYGON_BICONOMY_FORWARDER = 0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d;
    address public constant POLYGON_UNISWAP_PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    address public constant POLYGON_ZERO_EX = 0xDef1C0ded9bec7F1a1670819833240f027b25EfF;
    address public constant POLYGON_GASWORKS_PERMIT2 = 0x0655cC722c21604d0cfc46d67455629250c1E7b7;
    address public constant POLYGON_GASWORKS_PERMIT1 = 0x17268491Dc7abA4160E5594DE5cFEF9D0eE48181;
    // Utils
    uint256 public constant ALICE_PRIVATE_KEY = 0xa11ce000000b0b;
    address public ALICE = vm.addr(ALICE_PRIVATE_KEY);

    function addLabbels() public {
      vm.label(ETH_WEB3, "WEB3");
      vm.label(ETH_CHAIN, "CHAIN");
      vm.label(ETH_AEDY, "AEDY");
      vm.label(ETH_ADDY, "ADDY");
      vm.label(ETH_USDC, "USDC");
      vm.label(ETH_USDT, "USDT");
      vm.label(ETH_DAI, "DAI");
      vm.label(ETH_WBTC, "WBTC");
      vm.label(ETH_WETH, "WETH");
      vm.label(ETH_TRADE_ISSUER_V2, "TradeIssuerV2");
      vm.label(ETH_ISSUER_WIZARD, "IssuerWizard");
      vm.label(ETH_EXCHANGE_ISSUANCE, "ExchangeIssuance");
      vm.label(ETH_BICONOMY_FORWARDER, "BiconomyForwarder");
      vm.label(ETH_UNISWAP_PERMIT2, "UniswapPermit2");
      vm.label(POLYGON_WEB3, "WEB3");
      vm.label(POLYGON_CHAIN, "CHAIN");
      vm.label(POLYGON_AEDY, "AEDY");
      vm.label(POLYGON_ADDY, "ADDY");
      vm.label(POLYGON_AAGG, "AAGG");
      vm.label(POLYGON_AMOD, "AMOD");
      vm.label(POLYGON_ABAL, "ABAL");
      vm.label(POLYGON_AP60, "AP60");
      vm.label(POLYGON_USDC, "USDC");
      vm.label(POLYGON_USDT, "USDT");
      vm.label(POLYGON_DAI, "DAI");
      vm.label(POLYGON_WBTC, "WBTC");
      vm.label(POLYGON_WMATIC, "WMATIC");
      vm.label(POLYGON_TRADE_ISSUER_V2, "TradeIssuerV2");
      vm.label(POLYGON_ISSUER_WIZARD, "IssuerWizard");
      vm.label(POLYGON_EXCHANGE_ISSUANCE, "ExchangeIssuance");
      vm.label(POLYGON_BICONOMY_FORWARDER, "BiconomyForwarder");
      vm.label(POLYGON_UNISWAP_PERMIT2, "UniswapPermit2");
      vm.label(POLYGON_ZERO_EX, "ZeroEx");
      vm.label(POLYGON_GASWORKS_PERMIT2, "GasworksV2");
      vm.label(POLYGON_GASWORKS_PERMIT1, "GasworksV1");
      vm.label(ALICE, "Alice");
    }

    function fetchMintQuote(address archToken, uint256 archTokenAmount, address inputToken)
        public
        returns (ITradeIssuerV2.ContractCallInstruction[] memory, uint256)
    {
        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(archTokenAmount));
        inputs[3] = Conversor.iToHex(abi.encode(archToken));
        inputs[4] = Conversor.iToHex(abi.encode(inputToken));
        inputs[5] = Conversor.iToHex(abi.encode(true));
        bytes memory response = vm.ffi(inputs);
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _maxPayAmount
        ) = abi.decode(response, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        return (_contractCallInstructions, _maxPayAmount);
    }

    function fetchRedeemQuote(address archToken, uint256 archTokenAmount, address outputToken)
        public
        returns (ITradeIssuerV2.ContractCallInstruction[] memory, uint256)
    {
        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(archTokenAmount));
        inputs[3] = Conversor.iToHex(abi.encode(archToken));
        inputs[4] = Conversor.iToHex(abi.encode(outputToken));
        inputs[5] = Conversor.iToHex(abi.encode(false));
        bytes memory response = vm.ffi(inputs);
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _minReceiveAmount
        ) = abi.decode(response, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        return (_contractCallInstructions, _minReceiveAmount);
    }

    function getSwapCallsFromContractCalls(
        ITradeIssuerV2.ContractCallInstruction[] memory contractCallInstructions
    ) public pure returns (IGasworks.SwapCallInstruction[] memory) {
        IGasworks.SwapCallInstruction[] memory swapCallInstructions =
            new IGasworks.SwapCallInstruction[](contractCallInstructions.length);

        for (uint256 i = 0; i < contractCallInstructions.length;) {
            IGasworks.SwapCallInstruction memory instruction = IGasworks.SwapCallInstruction(
                address(contractCallInstructions[i]._sellToken),
                contractCallInstructions[i]._sellAmount,
                address(contractCallInstructions[i]._buyToken),
                contractCallInstructions[i]._minBuyAmount,
                contractCallInstructions[i]._target,
                contractCallInstructions[i]._allowanceTarget,
                contractCallInstructions[i]._callData
            );

            swapCallInstructions[i] = instruction;
            unchecked {
                ++i;
            }
        }
        return swapCallInstructions;
    }

    function deployGasworks(uint256 chainId) public returns (Gasworks) {
        if (chainId == 137) {
            Gasworks polygonGasworks = new Gasworks(
                POLYGON_BICONOMY_FORWARDER,
                POLYGON_EXCHANGE_ISSUANCE,
                POLYGON_TRADE_ISSUER_V2
            );
            polygonGasworks.setTokens(POLYGON_WEB3);
            polygonGasworks.setTokens(POLYGON_CHAIN);
            polygonGasworks.setTokens(POLYGON_AEDY);
            polygonGasworks.setTokens(POLYGON_ADDY);
            polygonGasworks.setTokens(POLYGON_AAGG);
            polygonGasworks.setTokens(POLYGON_AMOD);
            polygonGasworks.setTokens(POLYGON_ABAL);
            polygonGasworks.setTokens(POLYGON_AP60);
            polygonGasworks.setTokens(POLYGON_USDC);
            polygonGasworks.setTokens(POLYGON_USDT);
            polygonGasworks.setTokens(POLYGON_DAI);
            polygonGasworks.setTokens(POLYGON_WBTC);
            polygonGasworks.setTokens(POLYGON_WMATIC);
            return polygonGasworks;
        }
        Gasworks ethereumGasworks = new Gasworks(
          ETH_BICONOMY_FORWARDER,
          ETH_EXCHANGE_ISSUANCE,
          ETH_TRADE_ISSUER_V2
      );
        ethereumGasworks.setTokens(ETH_WEB3);
        ethereumGasworks.setTokens(ETH_CHAIN);
        ethereumGasworks.setTokens(ETH_AEDY);
        ethereumGasworks.setTokens(ETH_ADDY);
        ethereumGasworks.setTokens(ETH_USDC);
        ethereumGasworks.setTokens(ETH_USDT);
        ethereumGasworks.setTokens(ETH_DAI);
        ethereumGasworks.setTokens(ETH_WBTC);
        ethereumGasworks.setTokens(ETH_WETH);
        return ethereumGasworks;
    }
}
