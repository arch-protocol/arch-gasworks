// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import "forge-std/StdJson.sol";
import { Test } from "forge-std/Test.sol";
import { GasworksV2 } from "src/GasworksV2.sol";
import { IGasworksV2 } from "src/interfaces/IGasworksV2.sol";
import { SafeERC20 } from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { Permit2Utils } from "test/utils/Permit2Utils.sol";
import { ITradeIssuerV3, IERC20 } from "chambers-peripherals/src/interfaces/ITradeIssuerV3.sol";
import { RedeemAndMintData, SwapCallInstruction } from "src/structs/GasworksV2.sol";
import { InvalidNonce, SignatureExpired } from "permit2/src/PermitErrors.sol";
import { SignatureVerification } from "permit2/src/libraries/SignatureVerification.sol";

contract GasworksV2Test is Test, Permit2Utils {
    /*//////////////////////////////////////////////////////////////
                            VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeERC20 for IERC20;
    using stdJson for string;

    string root;
    string path;
    string json;

    // Revert tests variables
    RedeemAndMintData internal revertTestsRedeemAndMintData;
    IGasworksV2 internal revertTestsGasworks;
    address internal revertTestsRedeemToken;
    uint256 internal revertTestsRedeemAmount;
    address internal revertTestsMintToken;
    uint256 internal revertTestsMintAmount;
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
        path = string.concat(
            root, "/data/permitTwo/redeemAndMint/testRedeemAndMintFromAaggToAbal.json"
        );
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

        SwapCallInstruction[] memory swapCallInstructions =
            getSwapCallsFromContractCalls(contractCallInstructions);

        revertTestsRedeemAndMintData = RedeemAndMintData(
            fromToken, fromTokenAmount, toToken, toTokenAmount, issuerWizard, swapCallInstructions
        );

        revertTestsRedeemToken = fromToken;
        revertTestsRedeemAmount = fromTokenAmount;
        revertTestsMintToken = toToken;
        revertTestsMintAmount = toTokenAmount;
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
    function testCannotRedeemAndMintTradeIssuerCallFailed() public {
        vm.prank(ALICE);
        IERC20(revertTestsRedeemToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsRedeemToken, ALICE, revertTestsRedeemAmount); // But give enough balance to redeem

        address invalidIssuer = address(0x1231234);
        RedeemAndMintData memory invalidRedeemAndMintData = RedeemAndMintData(
            revertTestsRedeemAndMintData.archTokenToRedeem,
            revertTestsRedeemAndMintData.redeemAmount,
            revertTestsRedeemAndMintData.archTokenToMint,
            revertTestsRedeemAndMintData.mintAmount,
            invalidIssuer,
            revertTestsRedeemAndMintData.swapCallInstructions
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

        bytes32 msgToSign = getRedeemAndMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), invalidRedeemAndMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(ITradeIssuerV3.InvalidWizard.selector);
        revertTestsGasworks.redeemAndMintWithPermit2(
            permit, ALICE, signature, invalidRedeemAndMintData
        );
    }

    /**
     * [REVERT] Should revert because the RedeemAndMintData is different from the one signed
     */
    function testCannotRedeemAndMintModifiedData() public {
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

        bytes32 msgToSign = getRedeemAndMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemAndMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        RedeemAndMintData memory modifiedRedeemAndMintData = RedeemAndMintData(
            revertTestsRedeemAndMintData.archTokenToRedeem,
            revertTestsRedeemAndMintData.redeemAmount,
            revertTestsRedeemAndMintData.archTokenToMint,
            revertTestsRedeemAndMintData.mintAmount * 10, // modified data
            revertTestsRedeemAndMintData.issuer,
            revertTestsRedeemAndMintData.swapCallInstructions
        );

        vm.expectRevert(SignatureVerification.InvalidSigner.selector);
        revertTestsGasworks.redeemAndMintWithPermit2(
            permit, ALICE, signature, modifiedRedeemAndMintData
        );
    }

    /**
     * [REVERT] Should revert because allowed amount is less than required amount
     */
    function testCannotRedeemAndMintNotEnoughAllowance() public {
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

        bytes32 msgToSign = getRedeemAndMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemAndMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        revertTestsGasworks.redeemAndMintWithPermit2(
            permit, ALICE, signature, revertTestsRedeemAndMintData
        );
    }

    /**
     * [REVERT] Should revert because balance is less than required amount
     */
    function testCannotRedeemAndMintNotEnoughBalance() public {
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

        bytes32 msgToSign = getRedeemAndMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemAndMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        revertTestsGasworks.redeemAndMintWithPermit2(
            permit, ALICE, signature, revertTestsRedeemAndMintData
        );
    }

    /**
     * [REVERT] Should revert because the signature length is invalid
     */
    function testCannotRedeemAndMintIncorrectSignatureLength() public {
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

        bytes32 msgToSign = getRedeemAndMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemAndMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);
        bytes memory invalidSignature = bytes.concat(signature, bytes1(uint8(0)));
        assertEq(invalidSignature.length, 66);

        vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
        revertTestsGasworks.redeemAndMintWithPermit2(
            permit, ALICE, invalidSignature, revertTestsRedeemAndMintData
        );
    }

    /**
     * [REVERT] Should revert because the signer of the permit
     * is not the owner of the tokens
     */
    function testCannotRedeemAndMintIncorrectSigner() public {
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

        bytes32 msgToSign = getRedeemAndMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemAndMintData
        );
        bytes memory signature = signMessage(INVALID_SIGNER_PRIVATE_KEY, msgToSign);

        vm.expectRevert();
        revertTestsGasworks.redeemAndMintWithPermit2(
            permit, ALICE, signature, revertTestsRedeemAndMintData
        );
    }

    /**
     * [REVERT] Should revert because the spender is not the one specified in the signature
     */
    function testCannotRedeemAndMintIncorrectSpender() public {
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
        bytes32 msgToSign = getRedeemAndMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(INVALID_SPENDER), revertTestsRedeemAndMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(SignatureVerification.InvalidSigner.selector);
        revertTestsGasworks.redeemAndMintWithPermit2(
            permit, ALICE, signature, revertTestsRedeemAndMintData
        );
    }

    /**
     * [REVERT] Should revert because the signature is expired
     */
    function testCannotRedeemAndMintSignatureExpired() public {
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

        bytes32 msgToSign = getRedeemAndMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemAndMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.warp(2 ** 255 + 1);

        vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, permit.deadline));
        revertTestsGasworks.redeemAndMintWithPermit2(
            permit, ALICE, signature, revertTestsRedeemAndMintData
        );
    }

    /**
     * [REVERT] Should revert because the nonce was used twice and should only be used once [replay attack]
     */
    function testCannotRedeemAndMintInvalidNonce() public {
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

        bytes32 msgToSign = getRedeemAndMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemAndMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        revertTestsGasworks.redeemAndMintWithPermit2(
            permit, ALICE, signature, revertTestsRedeemAndMintData
        );

        vm.expectRevert(InvalidNonce.selector);
        revertTestsGasworks.redeemAndMintWithPermit2(
            permit, ALICE, signature, revertTestsRedeemAndMintData
        );
    }

    /**
     * [REVERT] Should revert because base token is not permitted
     */
    function testCannotRedeemAndMintInvalidRedeemToken() public {
        address invalidRedeemToken = address(0x123123);
        RedeemAndMintData memory invalidRedeemAndMintData = RedeemAndMintData(
            invalidRedeemToken,
            revertTestsRedeemAndMintData.redeemAmount,
            revertTestsRedeemAndMintData.archTokenToMint,
            revertTestsRedeemAndMintData.mintAmount,
            revertTestsRedeemAndMintData.issuer,
            revertTestsRedeemAndMintData.swapCallInstructions
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

        bytes32 msgToSign = getRedeemAndMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), invalidRedeemAndMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(
            abi.encodeWithSelector(IGasworksV2.InvalidToken.selector, invalidRedeemToken)
        );
        revertTestsGasworks.redeemAndMintWithPermit2(
            permit, ALICE, signature, invalidRedeemAndMintData
        );
    }

    /**
     * [REVERT] Should revert because redeem token is not allowed
     */
    function testCannotRedeemAndMintInvalidMintToken() public {
        address invalidMintToken = address(0x123123);
        RedeemAndMintData memory invalidRedeemAndMintData = RedeemAndMintData(
            revertTestsRedeemAndMintData.archTokenToRedeem,
            revertTestsRedeemAndMintData.redeemAmount,
            invalidMintToken,
            revertTestsRedeemAndMintData.mintAmount,
            revertTestsRedeemAndMintData.issuer,
            revertTestsRedeemAndMintData.swapCallInstructions
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

        bytes32 msgToSign = getRedeemAndMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), invalidRedeemAndMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(abi.encodeWithSelector(IGasworksV2.InvalidToken.selector, invalidMintToken));
        revertTestsGasworks.redeemAndMintWithPermit2(
            permit, ALICE, signature, invalidRedeemAndMintData
        );
    }

    /**
     * [REVERT] Should revert because the redeemData redeem token is different from the permitted one
     */
    function testCannotRedeemAndMintPermittedTokenDifferentFromRedeemToken() public {
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

        bytes32 msgToSign = getRedeemAndMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemAndMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(
            abi.encodeWithSelector(IGasworksV2.InvalidToken.selector, revertTestsRedeemToken)
        );
        revertTestsGasworks.redeemAndMintWithPermit2(
            permit, ALICE, signature, revertTestsRedeemAndMintData
        );
    }

    /**
     * [REVERT] Should revert because the redeemData redeem amount is different from the permitted one
     */
    function testCannotRedeemAndMintPermittedAmountDifferentFromRedeemTokenAmount() public {
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

        bytes32 msgToSign = getRedeemAndMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemAndMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(
            abi.encodeWithSelector(
                IGasworksV2.InvalidRedeemAmount.selector,
                permit.permitted.amount,
                revertTestsRedeemAmount
            )
        );
        revertTestsGasworks.redeemAndMintWithPermit2(
            permit, ALICE, signature, revertTestsRedeemAndMintData
        );
    }

    /**
     * [REVERT] Should revert because the permitted amount is zero
     */
    function testCannotRedeemAndMintZeroPermittedAmount() public {
        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: revertTestsRedeemToken, amount: 0 }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getRedeemAndMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsRedeemAndMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(abi.encodeWithSelector(IGasworksV2.ZeroPermittedAmount.selector));
        revertTestsGasworks.redeemAndMintWithPermit2(
            permit, ALICE, signature, revertTestsRedeemAndMintData
        );
    }

    /*//////////////////////////////////////////////////////////////
                        SUCCESS AUX FUNCTION
    //////////////////////////////////////////////////////////////*/

    /**
     * Redeem and Mint a chamber with trade issuer
     */
    function successfulRedeemAndMintWithPermit2(
        uint256 chainId,
        uint256 blockNumber,
        address fromToken,
        uint256 fromTokenAmount,
        address toToken,
        uint256 toTokenAmount,
        address issuerWizard,
        ITradeIssuerV3.ContractCallInstruction[] memory contractCallInstructions
    ) public {
        vm.createSelectFork("polygon", blockNumber);
        GasworksV2 gasworks = deployGasworksV2();

        vm.prank(ALICE);
        IERC20(fromToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(fromToken, ALICE, fromTokenAmount);

        SwapCallInstruction[] memory swapCallInstructions =
            getSwapCallsFromContractCalls(contractCallInstructions);

        RedeemAndMintData memory myRedeemAndMintData = RedeemAndMintData(
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
        assertEq(IERC20(fromToken).allowance(ALICE, address(gasworks)), 0);
        assertEq(IERC20(fromToken).allowance(address(gasworks), POLYGON_TRADE_ISSUER_V3), 0);
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
        successfulRedeemAndMintWithPermit2(
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

    /*//////////////////////////////////////////////////////////////
                        SUCCESS CASES
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
