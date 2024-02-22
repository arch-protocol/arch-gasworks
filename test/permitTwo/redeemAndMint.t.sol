// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import "forge-std/StdJson.sol";
import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { Permit2Utils } from "test/utils/Permit2Utils.sol";
import { ITradeIssuerV3 } from "chambers-peripherals/src/interfaces/ITradeIssuerV3.sol";
import { console } from "forge-std/console.sol";

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
                            AUX FUNCT
    //////////////////////////////////////////////////////////////*/

    /**
     * Redeem and Mint a chamber with trade issuer
     */
    function redeemAndMint(
        uint256 chainId,
        uint256 blockNumber,
        address fromToken,
        uint256 fromTokenAmount,
        address toToken,
        uint256 toTokenAmount,
        address issuerWizard,
        ITradeIssuerV3.ContractCallInstruction[] memory contractCallInstructions
    ) public {
        Gasworks gasworks;
        address uniswapPermit2;
        if (chainId == POLYGON_CHAIN_ID) {
            vm.createSelectFork("polygon", blockNumber);
            gasworks = deployGasworks(chainId);
            uniswapPermit2 = POLYGON_UNISWAP_PERMIT2;
        }
        if (chainId == ETH_CHAIN_ID) {
            vm.createSelectFork("ethereum", blockNumber);
            gasworks = deployGasworks(chainId);
            uniswapPermit2 = ETH_UNISWAP_PERMIT2;
        }

        vm.prank(ALICE);
        IERC20(fromToken).approve(uniswapPermit2, type(uint256).max);

        deal(fromToken, ALICE, fromTokenAmount);

        IGasworks.SwapCallInstruction[] memory swapCallInstructions =
            getSwapCallsFromContractCalls(contractCallInstructions);

        IGasworks.RedeemAndMintData memory myRedeemAndMintData = IGasworks.RedeemAndMintData(
            fromToken, fromTokenAmount, toToken, toTokenAmount, issuerWizard, swapCallInstructions
        );

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: fromToken, amount: fromTokenAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getRedeemAndMintWithPermit2MessageToSign(
            chainId, permit, address(gasworks), myRedeemAndMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        uint256 previousFromTokenBalance = IERC20(fromToken).balanceOf(ALICE);
        uint256 previousToTokenBalance = IERC20(toToken).balanceOf(ALICE);

        gasworks.redeemAndMintWithPermit2(permit, ALICE, signature, myRedeemAndMintData);

        assertEq(previousFromTokenBalance - IERC20(fromToken).balanceOf(ALICE), fromTokenAmount);
        assertEq(IERC20(toToken).balanceOf(ALICE) - previousToTokenBalance, toTokenAmount);
    }

    /**
     * Loads params and call instructions (quote) from a local json file, and then
     * runs it to redeem mint a chamber
     */
    function runLocalRedeemAndMintQuoteTest(string memory fileName) public {
        path = string.concat(root, fileName);
        json = vm.readFile(path);
        (
            uint256 chainId,
            uint256 blockNumber,
            address fromToken,
            uint256 fromTokenAmount,
            address toToken,
            uint256 toTokenAmount,
            address issuerWizard,
            ITradeIssuerV3.ContractCallInstruction[] memory contractCallInstructions
        ) = parseRedeemAndMintQuoteFromJson(json);
        redeemAndMint(
            chainId,
            blockNumber,
            fromToken,
            fromTokenAmount,
            toToken,
            toTokenAmount,
            issuerWizard,
            contractCallInstructions
        );
    }

    /**
     * Used to create json files, fetches a quote from arch and prints a JSON-readable
     * quote in console, ready to be saved for new tests. The fork is needed to get the
     * block number alongside the quote.
     */
    function printQuoteToCreateATest() public {
        vm.createSelectFork("polygon");
        fetchRedeemAndMintQuote(POLYGON_CHAIN_ID, POLYGON_AAGG, 50e18, POLYGON_AMOD);
    }

    /*//////////////////////////////////////////////////////////////
                            SUCCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should redeem AAGG and mint ABAL
     */
    function testRedeemAndMintFromAaggToAbal() public {
        runLocalRedeemAndMintQuoteTest(
            "/data/permitTwo/redeemAndMint/testRedeemAndMintFromAaggToAbal.json"
        );
    }

    /**
     * [SUCCESS] Should redeem AAGG and mint ABAL
     */
    function testRedeemAndMintFromAaggToAmod() public {
        runLocalRedeemAndMintQuoteTest(
            "/data/permitTwo/redeemAndMint/testRedeemAndMintFromAaggToAmod.json"
        );
    }

    /**
     * [SUCCESS] Should redeem ABAL and mint AAGG
     */
    function testRedeemAndMintFromAbalToAagg() public {
        runLocalRedeemAndMintQuoteTest(
            "/data/permitTwo/redeemAndMint/testRedeemAndMintFromAbalToAagg.json"
        );
    }

    /**
     * [SUCCESS] Should redeem ABAL and mint AMOD
     */
    function testRedeemAndMintFromAbalToAmod() public {
        runLocalRedeemAndMintQuoteTest(
            "/data/permitTwo/redeemAndMint/testRedeemAndMintFromAbalToAmod.json"
        );
    }

    /**
     * [SUCCESS] Should redeem AMOD and mint AAGG
     */
    function testRedeemAndMintFromAmodToAagg() public {
        runLocalRedeemAndMintQuoteTest(
            "/data/permitTwo/redeemAndMint/testRedeemAndMintFromAmodToAagg.json"
        );
    }

    /**
     * [SUCCESS] Should redeem AMOD and mint ABAL
     */
    function testRedeemAndMintFromAmodToAbal() public {
        runLocalRedeemAndMintQuoteTest(
            "/data/permitTwo/redeemAndMint/testRedeemAndMintFromAmodToAbal.json"
        );
    }
}
