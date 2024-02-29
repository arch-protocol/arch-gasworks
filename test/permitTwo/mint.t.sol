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
import { MintData, SwapCallInstruction } from "src/structs/GasworksV2.sol";
import { SignatureVerification } from "permit2/src/libraries/SignatureVerification.sol";
import { InvalidNonce, SignatureExpired } from "permit2/src/PermitErrors.sol";

contract GasworksV2Test is Test, Permit2Utils {
    using SafeERC20 for IERC20;
    using stdJson for string;

    string root;
    string path;
    string json;

    // Revert tests variables
    MintData internal revertTestsMintData;
    GasworksV2 internal revertTestsGasworks;
    address internal revertTestsMintToken;
    address internal revertTestsBaseToken;
    uint256 internal revertTestsMaxPayAmount;
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
        path = string.concat(root, "/data/permitTwo/mint/testMintFromUsdceToAbal.json");
        json = vm.readFile(path);
        (
            uint256 chainId,
            uint256 blockNumber,
            address archToken,
            uint256 archTokenAmount,
            address baseToken,
            uint256 maxPayAmount,
            ITradeIssuerV3.ContractCallInstruction[] memory contractCallInstructions
        ) = parseMintQuoteFromJson(json);

        SwapCallInstruction[] memory swapCallInstructions =
            getSwapCallsFromContractCalls(contractCallInstructions);

        revertTestsMintData = MintData(
            archToken,
            archTokenAmount,
            baseToken,
            maxPayAmount,
            POLYGON_ISSUER_WIZARD,
            swapCallInstructions
        );
        revertTestsMintToken = archToken;
        revertTestsBaseToken = baseToken;
        revertTestsMaxPayAmount = maxPayAmount;
        revertTestsChainId = chainId;

        vm.createSelectFork("polygon", blockNumber);
        revertTestsGasworks = deployGasworksV2();
    }

    /*//////////////////////////////////////////////////////////////
                        REVERT CASES
    //////////////////////////////////////////////////////////////*/

    /**
     * [REVERT] Should revert because the mint data signed is not the one passed
     */
    function testCannotMintWithModifiedData() public {
        vm.prank(ALICE);
        IERC20(revertTestsBaseToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsBaseToken, ALICE, revertTestsMaxPayAmount); // But give enough balance to mint

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsBaseToken,
                amount: revertTestsMaxPayAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        MintData memory modifiedMintData = MintData(
            revertTestsMintData.archToken,
            revertTestsMintData.archTokenAmount + 2, // modified data
            revertTestsMintData.inputToken,
            revertTestsMintData.inputTokenMaxAmount,
            revertTestsMintData.issuer,
            revertTestsMintData.swapCallInstructions
        );

        vm.expectRevert(SignatureVerification.InvalidSigner.selector);
        revertTestsGasworks.mintWithPermit2(permit, ALICE, signature, modifiedMintData);
    }

    /**
     * [REVERT] Should revert because the call to the TradeIssuer failed
     */
    function testCannotMintTradeIssuerCallFailed() public {
        vm.prank(ALICE);
        IERC20(revertTestsBaseToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsBaseToken, ALICE, revertTestsMaxPayAmount); // But give enough balance to mint

        address invalidIssuer = address(0x123123);
        MintData memory invalidMintData = MintData(
            revertTestsMintData.archToken,
            revertTestsMintData.archTokenAmount,
            revertTestsMintData.inputToken,
            revertTestsMintData.inputTokenMaxAmount,
            invalidIssuer,
            revertTestsMintData.swapCallInstructions
        );

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsBaseToken,
                amount: revertTestsMaxPayAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), invalidMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(ITradeIssuerV3.InvalidWizard.selector);
        revertTestsGasworks.mintWithPermit2(permit, ALICE, signature, invalidMintData);
    }

    /**
     * [REVERT] Should revert because allowed amount is less than required amount
     */
    function testCannotMintNotEnoughAllowance() public {
        vm.prank(ALICE);
        IERC20(revertTestsBaseToken).approve(POLYGON_UNISWAP_PERMIT2, 1); // Only allow 1 wei to permit2

        deal(revertTestsBaseToken, ALICE, revertTestsMaxPayAmount); // But give enough balance to mint

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsBaseToken,
                amount: revertTestsMaxPayAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        revertTestsGasworks.mintWithPermit2(permit, ALICE, signature, revertTestsMintData);
    }

    /**
     * [REVERT] Should revert because balance is less than required amount
     */
    function testCannotMintNotEnoughBalance() public {
        vm.prank(ALICE);
        IERC20(revertTestsBaseToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max); // Max allowance to permit2

        deal(revertTestsBaseToken, ALICE, revertTestsMaxPayAmount - 1); // Not enough balance

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsBaseToken,
                amount: revertTestsMaxPayAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        revertTestsGasworks.mintWithPermit2(permit, ALICE, signature, revertTestsMintData);
    }

    /**
     * [REVERT] Should revert because the signature length is invalid
     */
    function testCannotMintIncorrectSignatureLength() public {
        vm.prank(ALICE);
        IERC20(revertTestsBaseToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsBaseToken, ALICE, revertTestsMaxPayAmount);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsBaseToken,
                amount: revertTestsMaxPayAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);
        bytes memory invalidSignature = bytes.concat(signature, bytes1(uint8(0)));
        assertEq(invalidSignature.length, 66);

        vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
        revertTestsGasworks.mintWithPermit2(permit, ALICE, invalidSignature, revertTestsMintData);
    }

    /**
     * [REVERT] Should revert because the signer of the permit
     * is not the owner of the tokens
     */
    function testCannotMintIncorrectSigner() public {
        uint256 INVALID_SIGNER_PRIVATE_KEY = 0xb0b0000d3ad;

        vm.prank(ALICE);
        IERC20(revertTestsBaseToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsBaseToken, ALICE, revertTestsMaxPayAmount);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsBaseToken,
                amount: revertTestsMaxPayAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsMintData
        );
        bytes memory signature = signMessage(INVALID_SIGNER_PRIVATE_KEY, msgToSign);

        vm.expectRevert();
        revertTestsGasworks.mintWithPermit2(permit, ALICE, signature, revertTestsMintData);
    }

    /**
     * [REVERT] Should revert because the spender is not the one specified in the signature
     */
    function testCannotMintIncorrectSpender() public {
        vm.prank(ALICE);
        IERC20(revertTestsBaseToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsBaseToken, ALICE, 3 * revertTestsMaxPayAmount); // Give enough to mint 3 times

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsBaseToken,
                amount: revertTestsMaxPayAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        address INVALID_SPENDER = address(0xb0b0000d3ad);
        bytes32 msgToSign = getMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(INVALID_SPENDER), revertTestsMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(SignatureVerification.InvalidSigner.selector);
        revertTestsGasworks.mintWithPermit2(permit, ALICE, signature, revertTestsMintData);
    }

    /**
     * [REVERT] Should revert because the signature is expired
     */
    function testCannotMintSignatureExpired() public {
        vm.prank(ALICE);
        IERC20(revertTestsBaseToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsBaseToken, ALICE, revertTestsMaxPayAmount);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = 2 ** 255 - 1;

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsBaseToken,
                amount: revertTestsMaxPayAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.warp(2 ** 255 + 1);

        vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, permit.deadline));
        revertTestsGasworks.mintWithPermit2(permit, ALICE, signature, revertTestsMintData);
    }

    /**
     * [REVERT] Should revert because the nonce was used twice and should only be used once [replay attack]
     */
    function testCannotMintInvalidNonce() public {
        vm.prank(ALICE);
        IERC20(revertTestsBaseToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);

        deal(revertTestsBaseToken, ALICE, 3 * revertTestsMaxPayAmount); // Give enough to mint 3 times

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsBaseToken,
                amount: revertTestsMaxPayAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        revertTestsGasworks.mintWithPermit2(permit, ALICE, signature, revertTestsMintData);

        vm.expectRevert(InvalidNonce.selector);
        revertTestsGasworks.mintWithPermit2(permit, ALICE, signature, revertTestsMintData);
    }

    /**
     * [REVERT] Should revert because base token is not allowed
     */
    function testCannotMintInvalidBaseToken() public {
        address invalidBaseToken = address(0x123123);
        MintData memory invalidMintData = MintData(
            revertTestsMintData.archToken,
            revertTestsMintData.archTokenAmount,
            invalidBaseToken,
            revertTestsMintData.inputTokenMaxAmount,
            revertTestsMintData.issuer,
            revertTestsMintData.swapCallInstructions
        );

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: invalidBaseToken,
                amount: revertTestsMaxPayAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), invalidMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(abi.encodeWithSelector(IGasworksV2.InvalidToken.selector, invalidBaseToken));
        revertTestsGasworks.mintWithPermit2(permit, ALICE, signature, invalidMintData);
    }

    /**
     * [REVERT] Should revert because mint token is not permitted
     */
    function testCannotMintInvalidMintToken() public {
        address invalidMintToken = address(0x123123);
        MintData memory invalidMintData = MintData(
            invalidMintToken,
            revertTestsMintData.archTokenAmount,
            revertTestsMintData.inputToken,
            revertTestsMintData.inputTokenMaxAmount,
            revertTestsMintData.issuer,
            revertTestsMintData.swapCallInstructions
        );

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsBaseToken,
                amount: revertTestsMaxPayAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), invalidMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(abi.encodeWithSelector(IGasworksV2.InvalidToken.selector, invalidMintToken));
        revertTestsGasworks.mintWithPermit2(permit, ALICE, signature, invalidMintData);
    }

    /**
     * [REVERT] Should revert because the mintData base token is different from the permitted one
     */
    function testCannotMintPermittedTokenDifferentFromBaseToken() public {
        address differentPermittedToken = address(0x123123);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: differentPermittedToken,
                amount: revertTestsMaxPayAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(
            abi.encodeWithSelector(IGasworksV2.InvalidToken.selector, revertTestsBaseToken)
        );
        revertTestsGasworks.mintWithPermit2(permit, ALICE, signature, revertTestsMintData);
    }

    /**
     * [REVERT] Should revert because the mintData base token amount is different from the permitted one
     */
    function testCannotMintPermittedAmountDifferentFromBaseTokenAmount() public {
        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: revertTestsBaseToken,
                amount: revertTestsMaxPayAmount + 1
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(
            abi.encodeWithSelector(
                IGasworksV2.InvalidBaseTokenAmount.selector,
                permit.permitted.amount,
                revertTestsMaxPayAmount
            )
        );
        revertTestsGasworks.mintWithPermit2(permit, ALICE, signature, revertTestsMintData);
    }

    /**
     * [REVERT] Should revert because the permitted amount is zero
     */
    function testCannotMintZeroPermittedAmount() public {
        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: revertTestsBaseToken, amount: 0 }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign = getMintWithPermit2MessageToSign(
            revertTestsChainId, permit, address(revertTestsGasworks), revertTestsMintData
        );
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(abi.encodeWithSelector(IGasworksV2.ZeroPermittedAmount.selector));
        revertTestsGasworks.mintWithPermit2(permit, ALICE, signature, revertTestsMintData);
    }

    /*//////////////////////////////////////////////////////////////
                        SUCCESS AUX FUNCTION
    //////////////////////////////////////////////////////////////*/

    /**
     * Mints a chamber using Permit2, with the params and call instructions (quote) given
     */
    function successfulMintWithPermit2(
        uint256 chainId,
        uint256 blockNumber,
        address archToken,
        uint256 archTokenAmount,
        address inputToken,
        uint256 maxPayAmount,
        ITradeIssuerV3.ContractCallInstruction[] memory contractCallInstructions
    ) public {
        vm.createSelectFork("polygon", blockNumber);
        GasworksV2 gasworks = deployGasworksV2();

        vm.prank(ALICE);
        IERC20(inputToken).approve(POLYGON_UNISWAP_PERMIT2, type(uint256).max);
        uint256 previousArchTokenBalance = IERC20(archToken).balanceOf(ALICE);

        // workaround for deal() error with USDC
        if (inputToken == POLYGON_USDC) {
            vm.prank(0x7F7214C19A2Ad6c5A7D07d2E187DE1a008a7BEa9); // address with a lot of USDC
            IERC20(inputToken).safeTransfer(ALICE, maxPayAmount);
        } else {
            deal(inputToken, ALICE, maxPayAmount);
        }

        uint256 previousBaseTokenBalance = IERC20(inputToken).balanceOf(ALICE);

        SwapCallInstruction[] memory swapCallInstructions =
            getSwapCallsFromContractCalls(contractCallInstructions);

        MintData memory myMintData = MintData(
            archToken,
            archTokenAmount,
            inputToken,
            maxPayAmount,
            POLYGON_ISSUER_WIZARD,
            swapCallInstructions
        );

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: inputToken, amount: maxPayAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign =
            getMintWithPermit2MessageToSign(chainId, permit, address(gasworks), myMintData);
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        gasworks.mintWithPermit2(permit, ALICE, signature, myMintData);

        assertEq(IERC20(archToken).balanceOf(ALICE) - previousArchTokenBalance, archTokenAmount);
        assertLe(previousBaseTokenBalance - IERC20(inputToken).balanceOf(ALICE), maxPayAmount);
        assertEq(IERC20(archToken).allowance(ALICE, address(gasworks)), 0);
        assertEq(IERC20(archToken).allowance(address(gasworks), POLYGON_TRADE_ISSUER_V3), 0);
    }

    /**
     * Loads params and call instructions (quote) from a local json file, and then
     * runs it to mint a chamber
     */
    function runLocalMintQuoteTest(string memory fileName) public {
        path = string.concat(root, fileName);
        json = vm.readFile(path);
        (
            uint256 chainId,
            uint256 blockNumber,
            address archToken,
            uint256 archTokenAmount,
            address inputToken,
            uint256 maxPayAmount,
            ITradeIssuerV3.ContractCallInstruction[] memory callInstructions
        ) = parseMintQuoteFromJson(json);
        successfulMintWithPermit2(
            chainId,
            blockNumber,
            archToken,
            archTokenAmount,
            inputToken,
            maxPayAmount,
            callInstructions
        );
    }

    /*//////////////////////////////////////////////////////////////
                            SUCCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should execute a mint from CHAIN to AAGG
     */
    function testMintFromChainToAagg() public {
        runLocalMintQuoteTest("/data/permitTwo/mint/testMintFromChainToAagg.json");
    }

    /**
     * [SUCCESS] Should execute a mint from USDC.e to ABAL
     */
    function testMintFromUsdceToAbal() public {
        runLocalMintQuoteTest("/data/permitTwo/mint/testMintFromUsdceToAbal.json");
    }

    /**
     * [SUCCESS] Should execute a mint from USDC to AMOD
     */
    function testMintFromUsdcToAmod() public {
        runLocalMintQuoteTest("/data/permitTwo/mint/testMintFromUsdcToAmod.json");
    }

    /**
     * [SUCCESS] Should execute a mint from USDT to ABDY
     */
    function testMintFromUsdtToAbdy() public {
        runLocalMintQuoteTest("/data/permitTwo/mint/testMintFromUsdtToABDY.json");
    }
}
