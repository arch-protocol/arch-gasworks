// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import "forge-std/StdJson.sol";
import { Test } from "forge-std/Test.sol";
import { GasworksV2 } from "src/GasworksV2.sol";
import { IGasworksV2 } from "src/interfaces/IGasworksV2.sol";
import { SigUtils } from "test/utils/SigUtils.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { SignatureVerification } from "permit2/src/libraries/SignatureVerification.sol";
import { InvalidNonce, SignatureExpired } from "permit2/src/PermitErrors.sol";
import { Permit2Utils } from "test/utils/Permit2Utils.sol";
import { SignatureExpired } from "permit2/src/PermitErrors.sol";
import { SwapData } from "src/structs/GasworksV2.sol";
import { console } from "forge-std/console.sol";

contract GasworksV2Test is Test, Permit2Utils {
    /*//////////////////////////////////////////////////////////////
                            VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeTransferLib for IERC20;
    using stdJson for string;

    string root;
    string path;
    string json;

    SwapData internal revertTestsSwapData;
    GasworksV2 internal revertTestsGasworks;
    uint256 internal revertTestsChainId;
    uint256 internal revertTestsBlockNumber;
    address internal revertTestsSellToken;
    uint256 internal revertTestsSellAmount;
    address internal revertTestsUniswapPermit2;

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
        path = string.concat(root, "/data/permitTwo/swap/testSwapFromAedyToAddy.json");
        json = vm.readFile(path);
        (
            uint256 chainId,
            uint256 blockNumber,
            address sellToken,
            uint256 sellAmount,
            address buyToken,
            uint256 buyAmount,
            uint256 nativeTokenAmount,
            address swapTarget,
            address swapAllowanceTarget,
            bytes memory swapCallData
        ) = parseSwapQuoteFromJson(json);

        revertTestsSwapData = SwapData(
            buyToken,
            buyAmount,
            nativeTokenAmount,
            payable(swapTarget),
            swapAllowanceTarget,
            swapCallData
        );
        revertTestsChainId = chainId;
        revertTestsBlockNumber = blockNumber;
        revertTestsSellToken = sellToken;
        revertTestsSellAmount = sellAmount;

        vm.createSelectFork("polygon", blockNumber);
        revertTestsGasworks = deployGasworksV2();
    }

    /*//////////////////////////////////////////////////////////////
                        REVERT CASES
    //////////////////////////////////////////////////////////////*/

    /**
     * [REVERT] Should revert because the swap data signed is not the one passed
     */
    function testCannotSwapWithModifiedData() public {
        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, revertTestsSellAmount); // Give enough balance to swap

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsSellToken,
                amount: revertTestsSellAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getSwapWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsSwapData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        SwapData memory modifiedSwapData = SwapData(
            revertTestsSwapData.buyToken,
            revertTestsSwapData.buyAmount * 10, // Modified data
            revertTestsSwapData.nativeTokenAmount,
            payable(revertTestsSwapData.swapTarget),
            revertTestsSwapData.swapAllowanceTarget,
            revertTestsSwapData.swapCallData
        );

        vm.expectRevert(SignatureVerification.InvalidSigner.selector);
        revertTestsGasworks.swapWithPermit2(permit, ALICE, signature, modifiedSwapData);
    }

    /**
     * [REVERT] Should revert because allowed amount is less than required amount
     */
    function testCannotSwapNotEnoughAllowance() public {
        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(POLYGON_UNISWAP_PERMIT2, 1); // Only allow 1 wei to permit2

        deal(revertTestsSellToken, ALICE, revertTestsSellAmount); // But give enough balance to swap

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsSellToken,
                amount: revertTestsSellAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getSwapWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsSwapData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        revertTestsGasworks.swapWithPermit2(permit, ALICE, signature, revertTestsSwapData);
    }

    /**
     * [REVERT] Should revert because balance is less than required amount
     */
    function testCannotSwapNotEnoughBalance() public {
        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max); // Max allowance to permit2

        deal(revertTestsSellToken, ALICE, 1); // Bot not enough balance [1 wei]

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsSellToken,
                amount: revertTestsSellAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getSwapWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsSwapData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        revertTestsGasworks.swapWithPermit2(permit, ALICE, signature, revertTestsSwapData);
    }

    /**
     * [REVERT] Should revert because the signature length is invalid
     */
    function testCannotSwapIncorrectSignatureLength() public {
        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, revertTestsSellAmount);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsSellToken,
                amount: revertTestsSellAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getSwapWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsSwapData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);
        bytes memory invalidSignature = bytes.concat(signature, bytes1(uint8(0)));
        assertEq(invalidSignature.length, 66);

        vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
        revertTestsGasworks.swapWithPermit2(permit, ALICE, invalidSignature, revertTestsSwapData);
    }

    /**
     * [REVERT] Should revert because the signer of the permit
     * is not the owner of the tokens
     */
    function testCannotSwapIncorrectSigner() public {
        uint256 INVALID_SIGNER_PRIVATE_KEY = 0xb0b0000d3ad;

        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, revertTestsSellAmount);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsSellToken,
                amount: revertTestsSellAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getSwapWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsSwapData
        );
        bytes memory signature = signMessage(INVALID_SIGNER_PRIVATE_KEY, msgToSign);

        vm.expectRevert();
        revertTestsGasworks.swapWithPermit2(permit, ALICE, signature, revertTestsSwapData);
    }

    /**
     * [REVERT] Should revert because the spender is not the one specified in the signature
     */
    function testCannotSwapIncorrectSpender() public {
        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, 3 * revertTestsSellAmount); // Give enough to swap 3 times

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsSellToken,
                amount: revertTestsSellAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        address INVALID_SPENDER = address(0xb0b0000d3ad);
        bytes32 msgToSign = getSwapWithPermit2MessageToSign(
            revertTestsChainId, permit, address(INVALID_SPENDER), revertTestsSwapData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(SignatureVerification.InvalidSigner.selector);
        revertTestsGasworks.swapWithPermit2(permit, ALICE, signature, revertTestsSwapData);
    }

    /**
     * [REVERT] Should revert because the signature is expired
     */
    function testCannotSwapSignatureExpired() public {
        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, revertTestsSellAmount);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = 2 ** 255 - 1;

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsSellToken,
                amount: revertTestsSellAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getSwapWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsSwapData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.warp(2 ** 255 + 1);

        vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, permit.deadline));
        revertTestsGasworks.swapWithPermit2(permit, ALICE, signature, revertTestsSwapData);
    }

    /**
     * [REVERT] Should revert because the nonce was used twice and should only be used once [replay attack]
     */
    function testCannotSwapInvalidNonce() public {
        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, 3 * revertTestsSellAmount); // Give enough to swap 3 times

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsSellToken,
                amount: revertTestsSellAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getSwapWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsSwapData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        revertTestsGasworks.swapWithPermit2(permit, ALICE, signature, revertTestsSwapData);

        vm.expectRevert(InvalidNonce.selector);
        revertTestsGasworks.swapWithPermit2(permit, ALICE, signature, revertTestsSwapData);
    }

    /**
     * [REVERT] Should revert because sell token is not permitted
     */
    function testCannotSwapInvalidSellToken() public {
        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, 3 * revertTestsSellAmount); // Give enough to swap 3 times

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        address invalidSellToken = address(0x123123);

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: invalidSellToken,
                amount: revertTestsSellAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getSwapWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsSwapData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(abi.encodeWithSelector(IGasworksV2.InvalidToken.selector, invalidSellToken));
        revertTestsGasworks.swapWithPermit2(permit, ALICE, signature, revertTestsSwapData);
    }

    /**
     * [REVERT] Should revert because buy token is not permitted
     */
    function testCannotSwapInvalidBuyToken() public {
        address invalidBuyToken = address(0x123123);
        // swapData with invalid buy token
        SwapData memory invalidSwapData = SwapData(
            invalidBuyToken,
            revertTestsSwapData.buyAmount,
            revertTestsSwapData.nativeTokenAmount,
            payable(revertTestsSwapData.swapTarget),
            revertTestsSwapData.swapAllowanceTarget,
            revertTestsSwapData.swapCallData
        );

        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, 3 * revertTestsSellAmount); // Give enough to swap 3 times

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsSellToken,
                amount: revertTestsSellAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getSwapWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), invalidSwapData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(abi.encodeWithSelector(IGasworksV2.InvalidToken.selector, invalidBuyToken));
        revertTestsGasworks.swapWithPermit2(permit, ALICE, signature, invalidSwapData);
    }

    /**
     * [REVERT] Should revert because low level call to swapTarget failed
     */
    function testCannotSwapSwapCallFailed() public {
        SwapData memory corruptedSwapData = SwapData(
            revertTestsSwapData.buyToken,
            revertTestsSwapData.buyAmount,
            revertTestsSwapData.nativeTokenAmount,
            payable(revertTestsSwapData.swapTarget),
            revertTestsSwapData.swapAllowanceTarget,
            bytes("Corrupted quote")
        );

        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, 3 * revertTestsSellAmount); // Give enough to swap 3 times

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsSellToken,
                amount: revertTestsSellAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getSwapWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), corruptedSwapData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(IGasworksV2.SwapCallFailed.selector);
        revertTestsGasworks.swapWithPermit2(permit, ALICE, signature, corruptedSwapData);
    }

    /**
     * [REVERT] Should revert due to underbought, because the sellAmount is too Big
     */
    function testCannotSwapUnderboughtAsset() public {
        uint256 exaggeratedBuyAmount = 2 * revertTestsSwapData.buyAmount;

        SwapData memory invalidSwapData = SwapData(
            revertTestsSwapData.buyToken,
            exaggeratedBuyAmount, // Buy amount is twice {swapCallData} will actually get
            revertTestsSwapData.nativeTokenAmount,
            payable(revertTestsSwapData.swapTarget),
            revertTestsSwapData.swapAllowanceTarget,
            revertTestsSwapData.swapCallData
        );

        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, revertTestsSellAmount); // Give enough to swap 3 times

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsSellToken,
                amount: revertTestsSellAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getSwapWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), invalidSwapData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(
            abi.encodeWithSelector(
                IGasworksV2.Underbought.selector, invalidSwapData.buyToken, exaggeratedBuyAmount
            )
        );
        revertTestsGasworks.swapWithPermit2(permit, ALICE, signature, invalidSwapData);
    }

    /**
     * [REVERT] Should make a swap from USDC to WEB3 using permit2, with a custom private key
     *
     * Analysis of transaction 0xf831f672416ef80156ad14fe78627c92c11c207ee32c9cb56268c83cc0656f3d
     * from a dev wallet using Crypto.com wallet
     *
     * Context: The permit of this transaction was signed using crypto.com mobile wallet. This caused an
     * error on-chain called 'INVALID_SIGNER' when deconstructing the owner in Uniswap's Permit2 call.
     *
     * What we want to prove here, is that the signature made by that wallet is invalid, being the main
     * suspected cause, they don't support EIP712, typed signature.
     *
     * If using the same private key as the transaction above, the same quote and data passed to
     * the function call, and end up getting another signature, then our point is proved.
     *
     * The call only need to pass the Uniswap's permitTransferFrom call, returning the correct owner.
     * Actually, the callData gives an Underbought error, but that's beyond signature validation, so its
     * enough to prove our point.
     */
    function testCannotSwapFromUsdcToWeb3WithCustomPrivateKey() public {
        path =
            string.concat(root, "/data/permitTwo/swap/testSwapFromUsdcToWeb3.CryptoComWallet.json");
        json = vm.readFile(path);
        (
            ,
            uint256 blockNumber,
            address sellToken,
            uint256 sellAmount,
            address buyToken,
            uint256 buyAmount,
            uint256 nativeTokenAmount,
            address swapTarget,
            address swapAllowanceTarget,
            bytes memory swapCallData
        ) = parseSwapQuoteFromJson(json);

        vm.createSelectFork("polygon", blockNumber);
        address gasworksOnChain = 0x0655cC722c21604d0cfc46d67455629250c1E7b7;

        uint256 cryptoComPrivateKey =
            0xde5c798a87be8905675c6bf06e51c9e6806f7bcc58bc4fe33fed8975fa3f9275;
        address cryptoComAddress = vm.addr(cryptoComPrivateKey);
        assertEq(cryptoComAddress, 0x4188585951dD5C0A7a423A021D3Bec38e7Affeff);

        vm.prank(cryptoComAddress);
        SwapData memory swapData = SwapData(
            buyToken,
            buyAmount,
            nativeTokenAmount,
            payable(swapTarget),
            swapAllowanceTarget,
            swapCallData
        );

        uint256 customNonce = 0x0e85d19c42ef30047663fcb3c35c62f570a4c80486baf0825d271b05e7fd831d;
        uint256 customDeadline = 0x655793e6;

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: sellToken, amount: sellAmount }),
            nonce: customNonce,
            deadline: customDeadline
        });

        bytes32 msgToSign = getSwapWithPermit2MessageToSign(
            POLYGON_CHAIN_ID, permit, address(gasworksOnChain), swapData
        );
        bytes memory signature = signMessage(cryptoComPrivateKey, msgToSign);
        // bytes memory signatureOnChain = bytes(
        //     "0xbec4b1ca1e131e555ec7869314d493b90d48a18862136cecef5d5e79cf83b16354050b0716a5ea05dea124993736802fb88d2fd28839821c8c81eb16f3da2fbf1c"
        // );

        // Let's prove that the signature produced by Crypto.com wallet is invalid [Update when assertNotEqual is available / console.log for now]
        // assertFalse(assertEq(signatureOnChain, signature));

        // Now proceed to see that the signature produced by us pass the Uniswap's Permit2 signature validation

        vm.expectRevert(
            abi.encodeWithSelector(IGasworksV2.Underbought.selector, buyToken, buyAmount)
        );
        IGasworksV2(gasworksOnChain).swapWithPermit2(permit, cryptoComAddress, signature, swapData);
    }

    /*//////////////////////////////////////////////////////////////
                        SUCCESS AUX FUNCTION
    //////////////////////////////////////////////////////////////*/

    /**
     * Does a swap using Permit2, with the params (quote) given
     */
    function successfulSwapWithPermit2(
        uint256 chainId,
        uint256 blockNumber,
        address sellToken,
        uint256 sellAmount,
        address buyToken,
        uint256 buyAmount,
        uint256 nativeTokenAmount,
        address swapTarget,
        address swapAllowanceTarget,
        bytes memory swapCallData
    ) public {
        vm.createSelectFork("polygon", blockNumber);
        GasworksV2 gasworks = deployGasworksV2();

        vm.prank(ALICE);
        IERC20(sellToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        SwapData memory swapData = SwapData(
            buyToken,
            buyAmount,
            nativeTokenAmount,
            payable(swapTarget),
            swapAllowanceTarget,
            swapCallData
        );

        deal(sellToken, ALICE, sellAmount);
        uint256 previousSellTokenBalance = IERC20(sellToken).balanceOf(ALICE);
        uint256 previousNativeTokenBalance = ALICE.balance;
        uint256 previousBuyTokenBalance = IERC20(buyToken).balanceOf(ALICE);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: sellToken, amount: sellAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign =
            getSwapWithPermit2MessageToSign(chainId, permit, address(gasworks), swapData);
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        gasworks.swapWithPermit2(permit, ALICE, signature, swapData);

        if (buyToken == POLYGON_WMATIC) {
            assertGe(ALICE.balance - previousNativeTokenBalance, swapData.buyAmount); // Receive MATIC, not WMATIC
        } else {
            assertGe(
                IERC20(buyToken).balanceOf(ALICE) - previousBuyTokenBalance, swapData.buyAmount
            );
        }

        assertEq(previousSellTokenBalance - IERC20(sellToken).balanceOf(ALICE), sellAmount);
        assertEq(IERC20(sellToken).allowance(ALICE, address(gasworks)), 0);
        assertEq(IERC20(sellToken).allowance(address(gasworks), swapAllowanceTarget), 0);
    }

    /**
     * Loads params (quote) from a local json file, and then does a swap
     */
    function runLocalSwapQuoteTest(string memory fileName) public {
        path = string.concat(root, fileName);
        json = vm.readFile(path);
        (
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
        ) = parseSwapQuoteFromJson(json);
        successfulSwapWithPermit2(
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

    /*//////////////////////////////////////////////////////////////
                        SUCCESS CASES
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should execute a swap from ADDY to CHAIN using permit2
     */
    function testSwapWithPermit2FromAddyToChain() public {
        runLocalSwapQuoteTest("/data/permitTwo/swap/testSwapFromAddyToChain.json");
    }

    /**
     * [SUCCESS] Should execute a swap from AEDY to ADDY using permit2
     */
    function testSwapWithPermit2FromAedyToAddy() public {
        runLocalSwapQuoteTest("/data/permitTwo/swap/testSwapFromAedyToAddy.json");
    }

    /**
     * [SUCCESS] Should execute a swap from CHAIN to USDC using permit2
     */
    function testSwapWithPermit2FromChainToUsdc() public {
        runLocalSwapQuoteTest("/data/permitTwo/swap/testSwapFromChainToUsdc.json");
    }

    /**
     * [SUCCESS] Should execute a swap from USDT to AEDY using permit2
     */
    function testSwapWithPermit2FromUsdtToAedy() public {
        runLocalSwapQuoteTest("/data/permitTwo/swap/testSwapFromUsdtToAedy.json");
    }

    /**
     * [SUCCESS] Should execute a swap from USDT to WMATIC using permit2
     */
    function testSwapWithPermit2FromUsdtToMatic() public {
        runLocalSwapQuoteTest("/data/permitTwo/swap/testSwapFromUsdtToMatic.json");
    }

    /**
     * [SUCCESS] Should execute a swap from WEB3 to USDC.e using permit2
     */
    function testSwapWithPermit2FromWeb3ToUsdce() public {
        runLocalSwapQuoteTest("/data/permitTwo/swap/testSwapFromWeb3ToUsdce.json");
    }
}
