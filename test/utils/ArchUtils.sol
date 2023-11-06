// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import { Test } from "forge-std/Test.sol";
import "forge-std/StdJson.sol";
import { Conversor } from "test/utils/HexUtils.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { ITradeIssuerV2 } from "chambers-peripherals/src/interfaces/ITradeIssuerV2.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { console } from "forge-std/console.sol";

contract ArchUtils is Test {
    using stdJson for string;

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
    address public constant ETH_LIDO_wstETH = 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0;
    address public constant ETH_RPOOL_rETH = 0xae78736Cd615f374D3085123A210448E74Fc6393;
    address public constant ETH_FRAX_sfrxETH = 0xac3E018457B222d93114458476f3E3416Abbe38F;
    address public constant ETH_YEARN_yvWETH = 0xa258C4606Ca8206D8aA700cE2143D7db854D168c;
    address public constant ETH_YEARN_yvDAI = 0xdA816459F1AB5631232FE5e97a05BBBb94970c95;
    address public constant ETH_YEARN_yvUSDC = 0xa354F35829Ae975e850e23e9615b11Da1B3dC4DE;
    address public constant ETH_YEARN_yvUSDT = 0x3B27F92C0e212C671EA351827EDF93DB27cc0c65;
    address public constant ETH_YEARN_yvLINKN = 0x671a912C10bba0CFA74Cfc2d6Fba9BA1ed9530B2;
    address public constant ETH_UNIV3_LP_WETH_WEB3 = 0x6147C54106dc2e3d7f5d4b5aFD2804F2D30dB0b5;
    address public constant ETH_UNIV3_LP_WETH_CHAIN = 0xBb9300f467BA73a35002dDEDd27B1BF1210822a4;
    address public constant ETH_UNIV3_LP_USDC_ADDY = 0x43c1E1BFFaB26715abC107aFA50cffA0Dfe72648;
    address public constant ETH_UNIV3_LP_WETH_AEDY = 0x247027635f32a25c7F93212CB9db91419BbB10f2;

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
    address public constant POLYGON_UNIV2_LP_WETH_WEB3 = 0xee875eF94641C33280B7F35c39b639F7F07481ca;
    address public constant POLYGON_UNIV3_LP_WETH_WEB3 = 0x39BAAC62266AF129F24104Bc8b1800350563EdB9;
    address public constant POLYGON_UNIV3_LP_WETH_CHAIN = 0x538b2B1aCF51b6C9A620F57de8619F9B428EBf9D;
    address public constant POLYGON_UNIV3_LP_USDC_ADDY = 0xC9621a0667fA6fE5BCb81B5E1ecCa7810c52FF8B;
    address public constant POLYGON_UNIV3_LP_WETH_AEDY = 0xefbA86413285584582cBEb556E1b89914b67eD02;
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
        vm.label(ETH_LIDO_wstETH, "wstETH");
        vm.label(ETH_RPOOL_rETH, "rETH");
        vm.label(ETH_FRAX_sfrxETH, "sfrxETH");
        vm.label(ETH_YEARN_yvWETH, "yvETH");
        vm.label(ETH_YEARN_yvDAI, "yvDAI");
        vm.label(ETH_YEARN_yvUSDC, "yvUSDC");
        vm.label(ETH_YEARN_yvUSDT, "yvUSDT");
        vm.label(ETH_YEARN_yvLINKN, "yvLINK");
        vm.label(ETH_UNIV3_LP_WETH_WEB3, "UNIV3 WETH/WEB3");
        vm.label(ETH_UNIV3_LP_WETH_CHAIN, "UNIV3 WETH/CHAIN");
        vm.label(ETH_UNIV3_LP_USDC_ADDY, "UNIV3 WETH/ADDY");
        vm.label(ETH_UNIV3_LP_WETH_AEDY, "UNIV3 WETH/AEDY");
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
        vm.label(POLYGON_UNIV2_LP_WETH_WEB3, "UNIV2 WETH/WEB3");
        vm.label(POLYGON_UNIV3_LP_WETH_WEB3, "UNIV3 WETH/WEB3");
        vm.label(POLYGON_UNIV3_LP_WETH_CHAIN, "UNIV3 WETH/CHAIN");
        vm.label(POLYGON_UNIV3_LP_USDC_ADDY, "UNIV3 WETH/ADDY");
        vm.label(POLYGON_UNIV3_LP_WETH_AEDY, "UNIV3 WETH/AEDY");
        vm.label(ALICE, "Alice");
    }

    function fetchSwapQuote(uint256 networkId,
    uint256 sellAmount, address sellToken, address buyToken)
        public
        returns (IGasworks.SwapData memory swapData)
    {
        string[] memory inputs = new string[](5);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(sellAmount));
        inputs[3] = Conversor.iToHex(abi.encode(sellToken));
        inputs[4] = Conversor.iToHex(abi.encode(buyToken));
        bytes memory response = vm.ffi(inputs);
        (
            address swapAllowanceTarget,
            address payable swapTarget,
            bytes memory swapCallData,
            uint256 nativeTokenAmount,
            uint256 buyAmount
        ) = abi.decode(response, (address, address, bytes, uint256, uint256));
        swapData = IGasworks.SwapData(
            buyToken, buyAmount, nativeTokenAmount, swapTarget, swapAllowanceTarget, swapCallData
        );

        logSwapQuoteAsJson(
          networkId,
          sellToken,
          sellAmount,
          buyToken,
          buyAmount,
          nativeTokenAmount,
          swapTarget,
          swapAllowanceTarget,
          swapCallData
        );

        return swapData;
    }

    /**
     * Fetches a Mint quote from the backend and prints a JSON-readable format of it. Used to create tests
     */
    function fetchMintQuote(
        uint256 networkId,
        address archToken,
        uint256 archTokenAmount,
        address inputToken
    ) public returns (ITradeIssuerV2.ContractCallInstruction[] memory, uint256) {
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

        logMintQuoteAsJson(
            networkId,
            archToken,
            archTokenAmount,
            inputToken,
            _contractCallInstructions,
            _maxPayAmount
        );

        return (_contractCallInstructions, _maxPayAmount);
    }

    function fetchRedeemQuote(
        uint256 networkId,
        address archToken,
        uint256 archTokenAmount,
        address outputToken
    ) public returns (ITradeIssuerV2.ContractCallInstruction[] memory, uint256) {
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

        logRedeemQuoteAsJson(
            networkId,
            archToken,
            archTokenAmount,
            outputToken,
            _contractCallInstructions,
            _minReceiveAmount
        );

        return (_contractCallInstructions, _minReceiveAmount);
    }

    /**
     * Transforms ITradeIssuerV2.ContractCallInstruction into IGasworks.SwapCallInstruction
     */
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

    /**
     * Deploys a new Gasworks contract and allows all tokens used in arch
     */
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

    /**
     * Logs a contract call instruction in console in a readable format
     */
    function logContractCallInstruction(
        ITradeIssuerV2.ContractCallInstruction memory callInstruction
    ) public view {
        console.log("Sell token: ", address(callInstruction._sellToken));
        console.log("Sell amount: ", callInstruction._sellAmount);
        console.log("Buy token: ", address(callInstruction._buyToken));
        console.log("Buy amount: ", callInstruction._minBuyAmount);
        console.log("Target: ", callInstruction._target);
        console.log("Allowance target: ", callInstruction._allowanceTarget);
        console.log("Call data: ");
        console.logBytes(callInstruction._callData);
    }

    /**
     * Logs a swap quote in console in a readable format. Used for debug.
     */
    function logSwapQuote(
      uint256 networkId,
      address sellToken,
      uint256 sellAmount,
      address buyToken,
      uint256 buyAmount,
      uint256 nativeTokenAmount,
      address swapTarget,
      address swapAllowanceTarget,
      bytes memory swapCallData
    ) public view {
        console.log("---------- Swap request ----------");
        console.log(string.concat("Network Id: ", vm.toString(networkId)));
        console.log(string.concat("BlockNumber: ", vm.toString(block.number)));
        console.log(string.concat("Sell Token: ", vm.toString(sellToken)));
        console.log(string.concat("Sell Amount: ", vm.toString(sellAmount)));
        console.log(string.concat("Buy Token: ", vm.toString(buyToken)));
        console.log("---------- Backend response ----------");
        console.log(string.concat("Buy Amount: ", vm.toString(buyAmount)));
        console.log(string.concat("Native Token Amount: ", vm.toString(nativeTokenAmount)));
        console.log(string.concat("Swap Target: ", vm.toString(swapTarget)));
        console.log(string.concat("Swap Allowance Target: ", vm.toString(swapAllowanceTarget)));
        console.log(string.concat("Swap CallData: ", vm.toString(swapCallData)));
    }

    /**
     * Logs a mint quote in console in a readable format. Used for debug.
     */
    function logMintQuote(
        address archToken,
        uint256 archTokenAmount,
        address inputToken,
        ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
        uint256 _maxPayAmount
    ) public view {
        console.log("---------- Mint request ----------");
        console.log("Block number: ", block.number);
        console.log("Mint token: ", archToken);
        console.log("Mint aomunt: ", archTokenAmount);
        console.log("Input token: ", inputToken);
        console.log("---------- Backend response ----------");
        console.log("Max pay amount: ", _maxPayAmount);
        for (uint256 i = 0; i < _contractCallInstructions.length; i++) {
            console.log("Contract call instruction #", i);
            logContractCallInstruction(_contractCallInstructions[i]);
        }
    }

    /**
     * Logs a redeem quote in console in a readable format. Used for debug.
     */
    function logRedeemQuote(
        address archToken,
        uint256 archTokenAmount,
        address outputToken,
        ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
        uint256 _MinReceiveAmount
    ) public view {
        console.log("---------- Redeem request ----------");
        console.log("Block number: ", block.number);
        console.log("Redeem token: ", archToken);
        console.log("Redeem aomunt: ", archTokenAmount);
        console.log("Output token: ", outputToken);
        console.log("---------- Backend response ----------");
        console.log("Min receive amount: ", _MinReceiveAmount);
        for (uint256 i = 0; i < _contractCallInstructions.length; i++) {
            console.log("Contract call instruction #", i);
            logContractCallInstruction(_contractCallInstructions[i]);
        }
    }

    /**
     * Logs a contract call instruction in console in a JSON-readable format
     */
    function logContractCallInstructionAsJson(
        ITradeIssuerV2.ContractCallInstruction memory callInstruction,
        bool logLastComma
    ) public view {
        console.log("    {");
        console.log(
            string.concat("      \"target\": \"", vm.toString(callInstruction._target), "\",")
        );
        console.log(
            string.concat(
                "      \"allowanceTarget\": \"",
                vm.toString(callInstruction._allowanceTarget),
                "\","
            )
        );
        console.log(
            string.concat(
                "      \"sellToken\": \"", vm.toString(address(callInstruction._sellToken)), "\","
            )
        );
        console.log(
            string.concat("      \"sellAmount\": ", vm.toString(callInstruction._sellAmount), ",")
        );
        console.log(
            string.concat(
                "      \"buyToken\": \"", vm.toString(address(callInstruction._buyToken)), "\","
            )
        );
        console.log(
            string.concat(
                "      \"minBuyAmount\": ", vm.toString(callInstruction._minBuyAmount), ","
            )
        );
        console.log(
            string.concat("      \"callData\": \"", vm.toString(callInstruction._callData), "\"")
        );
        if (logLastComma) {
            console.log("    },");
        } else {
            console.log("    }");
        }
    }

    /**
     * Logs a full swap quote in console in a JSON-readable format. Used to create new tests.
     */
    function logSwapQuoteAsJson(
      uint256 networkId,
      address sellToken,
      uint256 sellAmount,
      address buyToken,
      uint256 buyAmount,
      uint256 nativeTokenAmount,
      address swapTarget,
      address swapAllowanceTarget,
      bytes memory swapCallData
    ) public view {
        console.log("{");
        console.log(string.concat("  \"networkId\": ", vm.toString(networkId), ","));
        console.log(string.concat("  \"blockNumber\": ", vm.toString(block.number), ","));
        console.log(string.concat("  \"sellToken\": \"", vm.toString(sellToken), "\","));
        console.log(string.concat("  \"sellAmount\": ", vm.toString(sellAmount), ","));
        console.log(string.concat("  \"buyToken\": \"", vm.toString(buyToken), "\","));
        console.log(string.concat("  \"buyAmount\": ", vm.toString(buyAmount), ","));
        console.log(string.concat("  \"nativeTokenAmount\": ", vm.toString(nativeTokenAmount), ","));
        console.log(string.concat("  \"swapTarget\": \"", vm.toString(swapTarget), "\","));
        console.log(string.concat("  \"swapAllowanceTarget\": \"", vm.toString(swapAllowanceTarget), "\","));
        console.log(string.concat("  \"swapCallData\": \"", vm.toString(swapCallData), "\""));
        console.log("}");
    }

    /**
     * Logs a full mint quote in console in a JSON-readable format. Used to create new tests.
     */
    function logMintQuoteAsJson(
        uint256 networkId,
        address archToken,
        uint256 archTokenAmount,
        address inputToken,
        ITradeIssuerV2.ContractCallInstruction[] memory contractCallInstructions,
        uint256 maxPayAmount
    ) public view {
        console.log("{");
        console.log(string.concat("  \"networkId\": ", vm.toString(networkId), ","));
        console.log(string.concat("  \"blockNumber\": ", vm.toString(block.number), ","));
        console.log(string.concat("  \"archToken\": \"", vm.toString(archToken), "\","));
        console.log(string.concat("  \"archTokenAmount\": ", vm.toString(archTokenAmount), ","));
        console.log(string.concat("  \"inputToken\": \"", vm.toString(inputToken), "\","));
        console.log(string.concat("  \"maxPayAmount\": ", vm.toString(maxPayAmount), ","));
        console.log("  \"callInstructions\": [");
        for (uint256 i = 0; i < contractCallInstructions.length; i++) {
            if (i != contractCallInstructions.length - 1) {
                logContractCallInstructionAsJson(contractCallInstructions[i], true);
            } else {
                logContractCallInstructionAsJson(contractCallInstructions[i], false);
            }
        }
        console.log("  ]");
        console.log("}");
    }

    function logRedeemQuoteAsJson(
        uint256 networkId,
        address archToken,
        uint256 archTokenAmount,
        address outputToken,
        ITradeIssuerV2.ContractCallInstruction[] memory contractCallInstructions,
        uint256 minReceiveAmount
    ) public view {
        console.log("{");
        console.log(string.concat("  \"networkId\": ", vm.toString(networkId), ","));
        console.log(string.concat("  \"blockNumber\": ", vm.toString(block.number), ","));
        console.log(string.concat("  \"archToken\": \"", vm.toString(archToken), "\","));
        console.log(string.concat("  \"archTokenAmount\": ", vm.toString(archTokenAmount), ","));
        console.log(string.concat("  \"outputToken\": \"", vm.toString(outputToken), "\","));
        console.log(string.concat("  \"minReceiveAmount\": ", vm.toString(minReceiveAmount), ","));
        console.log("  \"callInstructions\": [");
        for (uint256 i = 0; i < contractCallInstructions.length; i++) {
            if (i != contractCallInstructions.length - 1) {
                logContractCallInstructionAsJson(contractCallInstructions[i], true);
            } else {
                logContractCallInstructionAsJson(contractCallInstructions[i], false);
            }
        }
        console.log("  ]");
        console.log("}");
    }

    /**
     * Intermediate struct needed to decode a contract call instruction form a JSON file
     */
    struct DecodedCallInstruction {
        address _allowanceTarget;
        address _buyToken;
        bytes _callData;
        uint256 _minBuyAmount;
        uint256 _sellAmount;
        address _sellToken;
        address payable _target;
    }

    /**
     * Reads a contract call instruction from a JSON file and returns
     * an ITradeIssuerV2.ContractCallInstruction[] array
     */
    function parseContractCallInstructions(string memory json)
        public
        pure
        returns (ITradeIssuerV2.ContractCallInstruction[] memory)
    {
        bytes memory callInstructionsInJson = json.parseRaw(".callInstructions");
        DecodedCallInstruction[] memory decodedCalls =
            abi.decode(callInstructionsInJson, (DecodedCallInstruction[]));

        ITradeIssuerV2.ContractCallInstruction[] memory instructions =
            new ITradeIssuerV2.ContractCallInstruction[](decodedCalls.length);

        for (uint256 i = 0; i < decodedCalls.length; ++i) {
            DecodedCallInstruction memory decodedCall = decodedCalls[i];
            instructions[i] = ITradeIssuerV2.ContractCallInstruction({
                _target: payable(decodedCall._target),
                _allowanceTarget: decodedCall._allowanceTarget,
                _sellToken: IERC20(decodedCall._sellToken),
                _sellAmount: decodedCall._sellAmount,
                _buyToken: IERC20(decodedCall._buyToken),
                _minBuyAmount: decodedCall._minBuyAmount,
                _callData: decodedCall._callData
            });
        }

        return instructions;
    }

    /**
     * Reads a mint quote from a JSON file and returns all params in the quote
     * plus an ITradeIssuerV2.ContractCallInstruction[] array
     */
    function parseMintQuoteFromJson(string memory json)
        public
        pure
        returns (
            uint256 networkId,
            uint256 blockNumber,
            address archToken,
            uint256 archTokenAmount,
            address inputToken,
            uint256 maxPayAmount,
            ITradeIssuerV2.ContractCallInstruction[] memory callInstrictions
        )
    {
        bytes memory _networkId = json.parseRaw(".networkId");
        networkId = abi.decode(_networkId, (uint256));
        bytes memory _blockNumber = json.parseRaw(".blockNumber");
        blockNumber = abi.decode(_blockNumber, (uint256));
        bytes memory _archToken = json.parseRaw(".archToken");
        archToken = abi.decode(_archToken, (address));
        bytes memory _archTokenAmount = json.parseRaw(".archTokenAmount");
        archTokenAmount = abi.decode(_archTokenAmount, (uint256));
        bytes memory _inputToken = json.parseRaw(".inputToken");
        inputToken = abi.decode(_inputToken, (address));
        bytes memory _maxPayAmount = json.parseRaw(".maxPayAmount");
        maxPayAmount = abi.decode(_maxPayAmount, (uint256));

        callInstrictions = parseContractCallInstructions(json);

        return (
            networkId,
            blockNumber,
            archToken,
            archTokenAmount,
            inputToken,
            maxPayAmount,
            callInstrictions
        );
    }

    /**
     * Reads a redeem quote from a JSON file and returns all params in the quote
     * plus an ITradeIssuerV2.ContractCallInstruction[] array
     */
    function parseRedeemQuoteFromJson(string memory json)
        public
        pure
        returns (
            uint256 networkId,
            uint256 blockNumber,
            address archToken,
            uint256 archTokenAmount,
            address outputToken,
            uint256 minReceiveAmount,
            ITradeIssuerV2.ContractCallInstruction[] memory callInstrictions
        )
    {
        bytes memory _networkId = json.parseRaw(".networkId");
        networkId = abi.decode(_networkId, (uint256));
        bytes memory _blockNumber = json.parseRaw(".blockNumber");
        blockNumber = abi.decode(_blockNumber, (uint256));
        bytes memory _archToken = json.parseRaw(".archToken");
        archToken = abi.decode(_archToken, (address));
        bytes memory _archTokenAmount = json.parseRaw(".archTokenAmount");
        archTokenAmount = abi.decode(_archTokenAmount, (uint256));
        bytes memory _outputToken = json.parseRaw(".outputToken");
        outputToken = abi.decode(_outputToken, (address));
        bytes memory _minReceiveAmount = json.parseRaw(".minReceiveAmount");
        minReceiveAmount = abi.decode(_minReceiveAmount, (uint256));

        callInstrictions = parseContractCallInstructions(json);

        return (
            networkId,
            blockNumber,
            archToken,
            archTokenAmount,
            outputToken,
            minReceiveAmount,
            callInstrictions
        );
    }

    /**
     * Reads a swap quote from a JSON file and returns all params in the quote
     */
    function parseSwapQuoteFromJson(string memory json)
        public
        pure
        returns (
            uint256 networkId,
            uint256 blockNumber,
            address sellToken,
            uint256 sellAmount,
            address buyToken,
            uint256 buyAmount,
            uint256 nativeTokenAmount,
            address swapTarget,
            address swapAllowanceTarget,
            bytes memory swapCallData
        )
    {
        bytes memory _networkId = json.parseRaw(".networkId");
        networkId = abi.decode(_networkId, (uint256));
        bytes memory _blockNumber = json.parseRaw(".blockNumber");
        blockNumber = abi.decode(_blockNumber, (uint256));
        bytes memory _sellToken = json.parseRaw(".sellToken");
        sellToken = abi.decode(_sellToken, (address));
        bytes memory _sellAmount = json.parseRaw(".sellAmount");
        sellAmount = abi.decode(_sellAmount, (uint256));
        bytes memory _buyToken = json.parseRaw(".buyToken");
        buyToken = abi.decode(_buyToken, (address));
        bytes memory _buyAmount = json.parseRaw(".buyAmount");
        buyAmount = abi.decode(_buyAmount, (uint256));
        bytes memory _nativeTokenAmount = json.parseRaw(".nativeTokenAmount");
        nativeTokenAmount = abi.decode(_nativeTokenAmount, (uint256));
        bytes memory _swapTarget = json.parseRaw(".swapTarget");
        swapTarget = abi.decode(_swapTarget, (address));
        bytes memory _swapAllowanceTarget = json.parseRaw(".swapAllowanceTarget");
        swapAllowanceTarget = abi.decode(_swapAllowanceTarget, (address));
        bytes memory _swapCallData = json.parseRaw(".swapCallData");
        swapCallData = abi.decode(_swapCallData, (bytes));

        return (
            networkId,
            blockNumber,
            sellToken,
            sellAmount,
            buyToken,
            buyAmount,
            nativeTokenAmount,
            swapTarget,
            swapAllowanceTarget,
            swapCallData
        );
    }
}
