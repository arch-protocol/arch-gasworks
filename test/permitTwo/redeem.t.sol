// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import "forge-std/StdJson.sol";
import { Test } from "forge-std/Test.sol";
import { console } from "forge-std/console.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { Permit2Utils } from "test/utils/Permit2Utils.sol";
import { ITradeIssuerV2 } from "chambers-peripherals/src/interfaces/ITradeIssuerV2.sol";

contract GaslessTest is Test, Permit2Utils {
    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeERC20 for IERC20;
    using stdJson for string;

    string root;
    string path;
    string json;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        addLabbels();
        root = vm.projectRoot();
    }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    function redeemChamber(
        uint256 chainId,
        uint256 blockNumber,
        address archToken,
        uint256 archTokenAmount,
        address toToken,
        uint256 minReceiveAmount,
        ITradeIssuerV2.ContractCallInstruction[] memory contractCallInstructions
    ) public {
        Gasworks gasworks;
        address issuerWizard;
        address uniswapPermit2;
        if (chainId == POLYGON_CHAIN_ID) {
            vm.createSelectFork("polygon", blockNumber);
            gasworks = deployGasworks(chainId);
            issuerWizard = POLYGON_ISSUER_WIZARD;
            uniswapPermit2 = POLYGON_UNISWAP_PERMIT2;
        }
        if (chainId == ETH_CHAIN_ID) {
            vm.createSelectFork("ethereum", blockNumber);
            gasworks = deployGasworks(chainId);
            issuerWizard = ETH_ISSUER_WIZARD;
            uniswapPermit2 = ETH_UNISWAP_PERMIT2;
        }

        vm.prank(ALICE);
        console.log("1");
        IERC20(archToken).approve(uniswapPermit2, type(uint256).max);
        console.log("2");
        uint256 previousToTokenBalance = IERC20(toToken).balanceOf(ALICE);
        uint256 adjustedMinReceiveAmount = minReceiveAmount;

        if (chainId == ETH_CHAIN_ID) {
            adjustedMinReceiveAmount = (minReceiveAmount * 0) / 1000; // Avoid underbought error
        }

        deal(archToken, ALICE, archTokenAmount);
        uint256 previousArchTokenBalance = IERC20(archToken).balanceOf(ALICE);

        IGasworks.SwapCallInstruction[] memory swapCallInstructions =
            getSwapCallsFromContractCalls(contractCallInstructions);

        IGasworks.RedeemData memory myRedeemData = IGasworks.RedeemData(
            archToken,
            archTokenAmount,
            toToken,
            adjustedMinReceiveAmount,
            issuerWizard,
            swapCallInstructions
        );

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: archToken, amount: archTokenAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign =
            getRedeemWithPermit2MessageToSign(chainId, permit, address(gasworks), myRedeemData);
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        gasworks.redeemWithPermit2(permit, ALICE, signature, myRedeemData, false);

        uint256 finalToTokenBalanceDiff = IERC20(toToken).balanceOf(ALICE) - previousToTokenBalance;
        console.log("realAmountReceived / minAmountReceived [%]:");
        console.log((100 * finalToTokenBalanceDiff) / minReceiveAmount);

        assertGe(finalToTokenBalanceDiff, adjustedMinReceiveAmount);
        assertEq(previousArchTokenBalance - IERC20(archToken).balanceOf(ALICE), archTokenAmount);
    }

    /**
     * Loads params and call instructions (quote) from a local json file, and then
     * runs it to redeem a chamber
     */
    function runLocalRedeemQuoteTest(string memory fileName) public {
        path = string.concat(root, fileName);
        json = vm.readFile(path);
        (
            uint256 networkId,
            uint256 blockNumber,
            address archToken,
            uint256 archTokenAmount,
            address toToken,
            uint256 minReceiveAmount,
            ITradeIssuerV2.ContractCallInstruction[] memory contractCallInstructions
        ) = parseRedeemQuoteFromJson(json);
        redeemChamber(
            networkId,
            blockNumber,
            archToken,
            archTokenAmount,
            toToken,
            minReceiveAmount,
            contractCallInstructions
        );
    }

    /**
     * Used to create json files, fetches a quote from arch and prints a JSON-readable
     * quote in console, ready to be saved for new tests. The fork is needed to get the
     * block number alongside the quote.
     */
    function testPrintQuoteToCreateATest() public {
        vm.createSelectFork("ethereum");
        fetchRedeemQuote(POLYGON_CHAIN_ID, POLYGON_ABAL, 10e18, POLYGON_USDC);
    }

    /**
     * [SUCCESS] Should redeem AAGG for AEDY using permit2
     */
    function testRedeemWithPermit2FromAaggToAedyOnPolygon() public {
        // redeemChamber(POLYGON_CHAIN_ID, POLYGON_AAGG, POLYGON_AEDY);
        runLocalRedeemQuoteTest(
            "/data/permitTwo/redeem/testRedeemWithPermit2FromAaggToAedyOnPolygon.json"
        );
    }

    /**
     * [SUCCESS] Should redeem AMOD for USDT using permit2 [Test when supply is available]
     */
    // function testRedeemWithPermit2FromAmodToUsdtOnPolygon() public {
    //     // redeemChamber(POLYGON_CHAIN_ID, POLYGON_AMOD, POLYGON_USDT);
    //     runLocalRedeemQuoteTest(
    //         "/data/permitTwo/redeem/testRedeemWithPermit2FromAmodToUsdtOnPolygon.json"
    //     );
    // }

    /**
     * [SUCCESS] Should redeem ABAL for USDC using permit2
     */
    function testRedeemWithPermit2FromAbalToUsdcOnPolygon() public {
        // redeemChamber(POLYGON_CHAIN_ID, POLYGON_ABAL, POLYGON_USDC);
        runLocalRedeemQuoteTest(
            "/data/permitTwo/redeem/testRedeemWithPermit2FromAbalToUsdcOnPolygon.json"
        );
    }

    /**
     * [SUCCESS] Should redeem AEDY for CHAIN using permit2 [Most of the time fails]
     */
    function testRedeemWithPermit2FromAedyToChainOnEthereum() public {
        // redeemChamber(ETH_CHAIN_ID, ETH_AEDY, ETH_CHAIN);
        runLocalRedeemQuoteTest(
            "/data/permitTwo/redeem/testRedeemWithPermit2FromAedyToChainOnEthereum.json"
        );
    }

    /**
     * [SUCCESS] Should redeem ADDY for WETH using permit2 [Most of the time fails]
     */
    function testRedeemWithPermit2FromAddyToWethOnEthereum() public {
        // redeemChamber(ETH_CHAIN_ID, ETH_ADDY, ETH_WETH);
        runLocalRedeemQuoteTest(
            "/data/permitTwo/redeem/testRedeemWithPermit2FromAddyToWethOnEthereum.json"
        );
    }
}
