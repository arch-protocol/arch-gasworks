// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/StdJson.sol";
import { Test } from "forge-std/Test.sol";
import { GasworksV2 } from "src/GasworksV2.sol";
import { IGasworksV2 } from "src/interfaces/IGasworksV2.sol";
import { SafeERC20 } from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { Permit2Utils } from "test/utils/Permit2Utils.sol";
import { ITradeIssuerV3, IERC20 } from "chambers-peripherals/src/interfaces/ITradeIssuerV3.sol";
import { InvalidNonce, SignatureExpired } from "permit2/src/PermitErrors.sol";

import { RedeemData, SwapCallInstruction } from "src/structs/GasworksV2.sol";
import { SignatureVerification } from "permit2/src/libraries/SignatureVerification.sol";

contract GasworksV2Test is Test, Permit2Utils {
    using SafeERC20 for IERC20;
    using stdJson for string;

    string root;
    string path;
    string json;

    // Revert tests variables
    RedeemData internal revertTestsRedeemData;
    IGasworksV2 internal revertTestsGasworks;
    address internal revertTestsRedeemToken;
    uint256 internal revertTestsRedeemAmount;
    address internal revertTestsOutputToken;
    uint256 internal revertTestsMinReceiveAmount;
    uint256 internal revertTestsChainId;

    /*//////////////////////////////////////////////////////////////
                            SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        addLabbels();
        root = vm.projectRoot();
        setUpRevertTestQuote();
    }

    /*//////////////////////////////////////////////////////////////
                        REVERT AUX FUNCTION
    //////////////////////////////////////////////////////////////*/

    /**
     * Saves a single quote in global variables, to use across all revert tests,
     * and therefore, avoid code duplication. You can change the JSON file quote
     * to test the revert tests with a different quote or asset
     */
    function setUpRevertTestQuote() public {
        path = string.concat(root, "/data/permitTwo/redeem/testRedeemFromAbalToUsdce.json");
        json = vm.readFile(path);
        (
            uint256 chainId,
            uint256 blockNumber,
            address archToken,
            uint256 archTokenAmount,
            address outputToken,
            uint256 minReceiveAmount,
            ITradeIssuerV3.ContractCallInstruction[] memory contractCallInstructions
        ) = parseRedeemQuoteFromJson(json);

        SwapCallInstruction[] memory swapCallInstructions =
            getSwapCallsFromContractCalls(contractCallInstructions);

        revertTestsRedeemData = RedeemData(
            archToken,
            archTokenAmount,
            outputToken,
            minReceiveAmount,
            POLYGON_ISSUER_WIZARD,
            swapCallInstructions
        );
        revertTestsRedeemToken = archToken;
        revertTestsRedeemAmount = archTokenAmount;
        revertTestsOutputToken = outputToken;
        revertTestsMinReceiveAmount = minReceiveAmount;
        revertTestsChainId = chainId;

        vm.createSelectFork("polygon", blockNumber);
        revertTestsGasworks = deployGasworksV2();
    }

    /*//////////////////////////////////////////////////////////////
                        REVERT CASES
    //////////////////////////////////////////////////////////////*/

    /**
     * [REVERT] Should revert because the call to the TradeIssuer failed
     */
    function testCannotRedeemTradeIssuerCallFailed() public {
        vm.prank(ALICE);
        IERC20(revertTestsRedeemToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsRedeemToken, ALICE, revertTestsRedeemAmount); // But give enough balance to redeem

        address invalidIssuer = address(0x1231234);
        RedeemData memory invalidRedeemData = RedeemData(
            revertTestsRedeemData.archToken,
            revertTestsRedeemData.archTokenAmount,
            revertTestsRedeemData.outputToken,
            revertTestsRedeemData.outputTokenMinAmount,
            invalidIssuer,
            revertTestsRedeemData.swapCallInstructions
        );

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsRedeemToken,
                amount: revertTestsRedeemAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getRedeemWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), invalidRedeemData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(ITradeIssuerV3.InvalidWizard.selector);
        revertTestsGasworks.redeemWithPermit2(permit, ALICE, signature, invalidRedeemData, false);
    }

    /**
     * [REVERT] Should revert because the RedeemData is different from the one signed
     */
    function testCannotRedeemModifiedData() public {
        vm.prank(ALICE);
        IERC20(revertTestsRedeemToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsRedeemToken, ALICE, revertTestsRedeemAmount); // But give enough balance to redeem

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsRedeemToken,
                amount: revertTestsRedeemAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getRedeemWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        RedeemData memory modifiedRedeemData = RedeemData(
            revertTestsRedeemData.archToken,
            revertTestsRedeemData.archTokenAmount,
            revertTestsRedeemData.outputToken,
            revertTestsRedeemData.outputTokenMinAmount * 10, // modified data
            revertTestsRedeemData.issuer,
            revertTestsRedeemData.swapCallInstructions
        );

        vm.expectRevert(SignatureVerification.InvalidSigner.selector);
        revertTestsGasworks.redeemWithPermit2(permit, ALICE, signature, modifiedRedeemData, false);
    }

    /**
     * [REVERT] Should revert because allowed amount is less than required amount
     */
    function testCannotRedeemNotEnoughAllowance() public {
        vm.prank(ALICE);
        IERC20(revertTestsRedeemToken).approve(POLYGON_UNISWAP_PERMIT2, 1); // Only allow 1 wei to permit2

        deal(revertTestsRedeemToken, ALICE, revertTestsRedeemAmount); // But give enough balance to redeem

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsRedeemToken,
                amount: revertTestsRedeemAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getRedeemWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        revertTestsGasworks.redeemWithPermit2(
            permit, ALICE, signature, revertTestsRedeemData, false
        );
    }

    /**
     * [REVERT] Should revert because balance is less than required amount
     */
    function testCannotRedeemNotEnoughBalance() public {
        vm.prank(ALICE);
        IERC20(revertTestsRedeemToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max); // Max allowance to permit2

        deal(revertTestsRedeemToken, ALICE, revertTestsRedeemAmount - 1); // Not enough balance

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsRedeemToken,
                amount: revertTestsRedeemAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getRedeemWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        revertTestsGasworks.redeemWithPermit2(
            permit, ALICE, signature, revertTestsRedeemData, false
        );
    }

    /**
     * [REVERT] Should revert because the signature length is invalid
     */
    function testCannotRedeemIncorrectSignatureLength() public {
        vm.prank(ALICE);
        IERC20(revertTestsRedeemToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsRedeemToken, ALICE, revertTestsRedeemAmount);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsRedeemToken,
                amount: revertTestsRedeemAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getRedeemWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);
        bytes memory invalidSignature = bytes.concat(signature, bytes1(uint8(0)));
        assertEq(invalidSignature.length, 66);

        vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
        revertTestsGasworks.redeemWithPermit2(
            permit, ALICE, invalidSignature, revertTestsRedeemData, false
        );
    }

    /**
     * [REVERT] Should revert because the signer of the permit
     * is not the owner of the tokens
     */
    function testCannotRedeemIncorrectSigner() public {
        uint256 INVALID_SIGNER_PRIVATE_KEY = 0xb0b0000d3ad;

        vm.prank(ALICE);
        IERC20(revertTestsRedeemToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsRedeemToken, ALICE, revertTestsRedeemAmount);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsRedeemToken,
                amount: revertTestsRedeemAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getRedeemWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemData
        );
        bytes memory signature = signMessage(INVALID_SIGNER_PRIVATE_KEY, msgToSign);

        vm.expectRevert();
        revertTestsGasworks.redeemWithPermit2(
            permit, ALICE, signature, revertTestsRedeemData, false
        );
    }

    /**
     * [REVERT] Should revert because the spender is not the one specified in the signature
     */
    function testCannotRedeemIncorrectSpender() public {
        vm.prank(ALICE);
        IERC20(revertTestsRedeemToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsRedeemToken, ALICE, 3 * revertTestsRedeemAmount); // Give enough to redeem 3 times

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsRedeemToken,
                amount: revertTestsRedeemAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        address INVALID_SPENDER = address(0xb0b0000d3ad);
        bytes32 msgToSign = getRedeemWithPermit2MessageToSign(
            revertTestsChainId, permit, address(INVALID_SPENDER), revertTestsRedeemData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(SignatureVerification.InvalidSigner.selector);
        revertTestsGasworks.redeemWithPermit2(
            permit, ALICE, signature, revertTestsRedeemData, false
        );
    }

    /**
     * [REVERT] Should revert because the signature is expired
     */
    function testCannotRedeemSignatureExpired() public {
        vm.prank(ALICE);
        IERC20(revertTestsRedeemToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsRedeemToken, ALICE, revertTestsRedeemAmount);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = 2 ** 255 - 1;

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsRedeemToken,
                amount: revertTestsRedeemAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getRedeemWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.warp(2 ** 255 + 1);

        vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, permit.deadline));
        revertTestsGasworks.redeemWithPermit2(
            permit, ALICE, signature, revertTestsRedeemData, false
        );
    }

    /**
     * [REVERT] Should revert because the nonce was used twice and should only be used once [replay attack]
     */
    function testCannotRedeemInvalidNonce() public {
        vm.prank(ALICE);
        IERC20(revertTestsRedeemToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsRedeemToken, ALICE, 3 * revertTestsRedeemAmount); // Give enough to redeem 3 times

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsRedeemToken,
                amount: revertTestsRedeemAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getRedeemWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        revertTestsGasworks.redeemWithPermit2(
            permit, ALICE, signature, revertTestsRedeemData, false
        );

        vm.expectRevert(InvalidNonce.selector);
        revertTestsGasworks.redeemWithPermit2(
            permit, ALICE, signature, revertTestsRedeemData, false
        );
    }

    /**
     * [REVERT] Should revert because base token is not permitted
     */
    function testCannotRedeemInvalidRedeemToken() public {
        address invalidRedeemToken = address(0x123123);
        RedeemData memory invalidRedeemData = RedeemData(
            invalidRedeemToken,
            revertTestsRedeemData.archTokenAmount,
            revertTestsRedeemData.outputToken,
            revertTestsRedeemData.outputTokenMinAmount,
            revertTestsRedeemData.issuer,
            revertTestsRedeemData.swapCallInstructions
        );

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: invalidRedeemToken,
                amount: revertTestsRedeemAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getRedeemWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), invalidRedeemData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(
            abi.encodeWithSelector(IGasworksV2.InvalidToken.selector, invalidRedeemToken)
        );
        revertTestsGasworks.redeemWithPermit2(permit, ALICE, signature, invalidRedeemData, false);
    }

    /**
     * [REVERT] Should revert because redeem token is not allowed
     */
    function testCannotRedeemInvalidOutputToken() public {
        address invalidOutputToken = address(0x123123);
        RedeemData memory invalidRedeemData = RedeemData(
            revertTestsRedeemData.archToken,
            revertTestsRedeemData.archTokenAmount,
            invalidOutputToken,
            revertTestsRedeemData.outputTokenMinAmount,
            revertTestsRedeemData.issuer,
            revertTestsRedeemData.swapCallInstructions
        );

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsRedeemToken,
                amount: revertTestsRedeemAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getRedeemWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), invalidRedeemData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(
            abi.encodeWithSelector(IGasworksV2.InvalidToken.selector, invalidOutputToken)
        );
        revertTestsGasworks.redeemWithPermit2(permit, ALICE, signature, invalidRedeemData, false);
    }

    /**
     * [REVERT] Should revert because the redeemData redeem token is different from the permitted one
     */
    function testCannotRedeemPermittedTokenDifferentFromRedeemToken() public {
        address differentPermittedToken = address(0x123123);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: differentPermittedToken,
                amount: revertTestsRedeemAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getRedeemWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(
            abi.encodeWithSelector(IGasworksV2.InvalidToken.selector, revertTestsRedeemToken)
        );
        revertTestsGasworks.redeemWithPermit2(
            permit, ALICE, signature, revertTestsRedeemData, false
        );
    }

    /**
     * [REVERT] Should revert because the redeemData redeem amount is different from the permitted one
     */
    function testCannotRedeemPermittedAmountDifferentFromRedeemTokenAmount() public {
        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsRedeemToken,
                amount: revertTestsRedeemAmount + 1
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getRedeemWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(
            abi.encodeWithSelector(
                IGasworksV2.InvalidRedeemAmount.selector,
                permit.permitted.amount,
                revertTestsRedeemAmount
            )
        );
        revertTestsGasworks.redeemWithPermit2(
            permit, ALICE, signature, revertTestsRedeemData, false
        );
    }

    /**
     * [REVERT] Should revert because the permitted amount is zero
     */
    function testCannotRedeemZeroPermittedAmount() public {
        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: revertTestsRedeemToken, amount: 0 }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getRedeemWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(abi.encodeWithSelector(IGasworksV2.ZeroPermittedAmount.selector));
        revertTestsGasworks.redeemWithPermit2(
            permit, ALICE, signature, revertTestsRedeemData, false
        );
    }

    /*//////////////////////////////////////////////////////////////
                        SUCCESS AUX FUNCTION
    //////////////////////////////////////////////////////////////*/

    function successfulRedeemWithPermit2(
        uint256 chainId,
        uint256 blockNumber,
        address archToken,
        uint256 archTokenAmount,
        address toToken,
        uint256 minReceiveAmount,
        ITradeIssuerV3.ContractCallInstruction[] memory contractCallInstructions
    ) public {
        vm.createSelectFork("polygon", blockNumber);
        GasworksV2 gasworks = deployGasworksV2();

        vm.prank(ALICE);
        IERC20(archToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);
        uint256 previousToTokenBalance = IERC20(toToken).balanceOf(ALICE);

        deal(archToken, ALICE, archTokenAmount);
        uint256 previousArchTokenBalance = IERC20(archToken).balanceOf(ALICE);

        SwapCallInstruction[] memory swapCallInstructions =
            getSwapCallsFromContractCalls(contractCallInstructions);

        RedeemData memory myRedeemData = RedeemData(
            archToken,
            archTokenAmount,
            toToken,
            minReceiveAmount,
            POLYGON_ISSUER_WIZARD,
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

        assertGe(IERC20(toToken).balanceOf(ALICE) - previousToTokenBalance, minReceiveAmount);
        assertEq(previousArchTokenBalance - IERC20(archToken).balanceOf(ALICE), archTokenAmount);
        assertEq(IERC20(archToken).allowance(ALICE, address(gasworks)), 0);
        assertEq(IERC20(archToken).allowance(address(gasworks), POLYGON_TRADE_ISSUER_V3), 0);
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
            ITradeIssuerV3.ContractCallInstruction[] memory contractCallInstructions
        ) = parseRedeemQuoteFromJson(json);
        successfulRedeemWithPermit2(
            networkId,
            blockNumber,
            archToken,
            archTokenAmount,
            toToken,
            minReceiveAmount,
            contractCallInstructions
        );
    }

    /*//////////////////////////////////////////////////////////////
                        SUCCESS CASES
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should redeem AAGG for CHAIN using permit2 [CHAIN -> CHAIN is not swapped]
     */
    function testRedeemWithPermit2FromAaggToChain() public {
        runLocalRedeemQuoteTest("/data/permitTwo/redeem/testRedeemFromAaggToChain.json");
    }

    /**
     * [SUCCESS] Should redeem AAGG for USDC using permit2
     */
    function testRedeemWithPermit2FromAaggToUsdc() public {
        runLocalRedeemQuoteTest("/data/permitTwo/redeem/testRedeemFromAaggToUsdc.json");
    }

    /**
     * [SUCCESS] Should redeem AAGG for USDT using permit2
     */
    function testRedeemWithPermit2FromAaggToUsdt() public {
        runLocalRedeemQuoteTest("/data/permitTwo/redeem/testRedeemFromAaggToUsdt.json");
    }

    /**
     * [SUCCESS] Should redeem ABAL for USDC.e using permit2
     */
    function testRedeemWithPermit2FromAbalToUsdce() public {
        runLocalRedeemQuoteTest("/data/permitTwo/redeem/testRedeemFromAbalToUsdce.json");
    }

    /**
     * [SUCCESS] Should redeem ABDY for AEDY using permit2
     */
    function testRedeemWithPermit2FromAbdyToAedy() public {
        runLocalRedeemQuoteTest("/data/permitTwo/redeem/testRedeemFromAbdyToAedy.json");
    }

    /**
     * [SUCCESS] Should redeem AMOD for USDT using permit2
     */
    function testRedeemWithPermit2FromAmodToUsdt() public {
        runLocalRedeemQuoteTest("/data/permitTwo/redeem/testRedeemFromAmodToUsdt.json");
    }

    /**
     * [SUCCESS] Should redeem ADDY for native MATIC using permit2
     */
    function testRedeemWithPermit2FromAmodToMaticOnPolygon() public {
        path = string.concat(root, "/data/permitTwo/redeem/testRedeemFromAmodToMatic.json");
        json = vm.readFile(path);
        (
            uint256 chainId,
            uint256 blockNumber,
            address archToken,
            uint256 archTokenAmount,
            address toToken,
            uint256 minReceiveAmount,
            ITradeIssuerV3.ContractCallInstruction[] memory contractCallInstructions
        ) = parseRedeemQuoteFromJson(json);

        vm.createSelectFork("polygon", blockNumber);
        GasworksV2 gasworks = deployGasworksV2();

        vm.prank(ALICE);
        IERC20(archToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);
        uint256 previousNativeBalance = ALICE.balance;
        uint256 previousToTokenBalance = IERC20(toToken).balanceOf(ALICE);
        uint256 adjustedMinReceiveAmount = minReceiveAmount;

        if (chainId == ETH_CHAIN_ID) {
            adjustedMinReceiveAmount = (minReceiveAmount * 0) / 1000; // Avoid underbought error
        }

        deal(archToken, ALICE, archTokenAmount);
        uint256 previousArchTokenBalance = IERC20(archToken).balanceOf(ALICE);

        SwapCallInstruction[] memory swapCallInstructions =
            getSwapCallsFromContractCalls(contractCallInstructions);

        RedeemData memory myRedeemData = RedeemData(
            archToken,
            archTokenAmount,
            toToken,
            adjustedMinReceiveAmount,
            POLYGON_ISSUER_WIZARD,
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

        gasworks.redeemWithPermit2(
            permit,
            ALICE,
            signature,
            myRedeemData,
            true // Receive native MATIC
        );

        assertEq(IERC20(toToken).balanceOf(ALICE), previousToTokenBalance); // No changes in WETH
        assertGe(ALICE.balance - previousNativeBalance, adjustedMinReceiveAmount); // Receive ETH
        assertEq(previousArchTokenBalance - IERC20(archToken).balanceOf(ALICE), archTokenAmount);
        assertEq(IERC20(archToken).allowance(ALICE, address(gasworks)), 0);
        assertEq(IERC20(archToken).allowance(address(gasworks), POLYGON_TRADE_ISSUER_V3), 0);
    }
}
