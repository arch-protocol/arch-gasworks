// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { SigUtils } from "test/utils/SigUtils.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { Conversor } from "test/utils/HexUtils.sol";
import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { SignatureVerification } from "permit2/src/libraries/SignatureVerification.sol";
import { InvalidNonce, SignatureExpired } from "permit2/src/PermitErrors.sol";
import { Permit2Utils } from "test/utils/Permit2Utils.sol";
import { EIP712 } from "permit2/src/EIP712.sol";
import { DeployPermit2 } from "permit2/test/utils/DeployPermit2.sol";
import { SignatureExpired } from "permit2/src/PermitErrors.sol";
import { WETH } from "solmate/src/tokens/WETH.sol";

contract GaslessTest is Test, Permit2Utils, DeployPermit2 {
    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeTransferLib for ERC20;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        addLabbels();
    }

    /*//////////////////////////////////////////////////////////////
                              REVERT
    //////////////////////////////////////////////////////////////*/

    // /**
    //  * [REVERT] Should revert because the signature length is invalid
    //  */
    // function testCannotSwapWithPermit2IncorrectSigLength() public {
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(USDC), 0, 1e6);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );
    //     bytes memory sigExtra = bytes.concat(signature, bytes1(uint8(0)));
    //     assertEq(sigExtra.length, 66);

    //     vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
    //     gasworks.swapWithPermit2(permit, owner, sigExtra, swapData);
    // }

    // /**
    //  * [REVERT] Should revert because the signature is expired
    //  */
    // function testCannotSwapWithPermit2SignatureExpired() public {
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(USDC), 0, 1e6);
    //     permit.deadline = 2 ** 255 - 1;
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     vm.warp(2 ** 255 + 1);

    //     vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, permit.deadline));
    //     gasworks.swapWithPermit2(permit, owner, signature, swapData);
    // }

    // /**
    //  * [REVERT] Should revert because the nonce was used twice and should only be used once
    //  */
    // function testCannotSwapWithPermit2InvalidNonce() public {
    //     uint256 nonce = 0;
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(USDC), nonce, 1e6);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     gasworks.swapWithPermit2(permit, owner, signature, swapData);

    //     vm.expectRevert(InvalidNonce.selector);
    //     gasworks.swapWithPermit2(permit, owner, signature, swapData);
    // }

    // /**
    //  * [REVERT] Should revert because token is not permitted
    //  */
    // function testCannotSwapWithPermit2InvalidToken() public {
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(0x123123), 0, 1e6);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     vm.expectRevert(abi.encodeWithSelector(IGasworks.InvalidToken.selector, address(0x123123)));
    //     gasworks.swapWithPermit2(permit, owner, signature, swapData);
    // }

    // /**
    //  * [REVERT] Should revert because low level call to swapTarget failed
    //  */
    // function testCannotSwapWithPermit2SwapCallFailed() public {
    //     swapData.swapCallData = bytes("swapCallData");
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(USDC), 0, 1e6);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     vm.expectRevert(IGasworks.SwapCallFailed.selector);
    //     gasworks.swapWithPermit2(permit, owner, signature, swapData);
    // }

    /**
     * [REVERT] Should revert due to underbought, because the sellAmount is too Big
     */
    // function testCannotSwapWithPermit2UnderboughtAsset() public {
    //     swapWithPermit2(POLYGON_CHAIN_ID, 10e18, POLYGON_USDT, POLYGON_WEB3);

    //     vm.expectRevert(
    //         abi.encodeWithSelector(IGasworks.Underbought.selector, POLYGON_WEB3, 10e18)
    //     );
    // }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    function swapWithPermit2(
        uint256 chainId,
        uint256 sellAmount,
        address sellToken,
        address buyToken
    ) public {
        Gasworks gasworks;
        address uniswapPermit2;
        if (chainId == POLYGON_CHAIN_ID) {
            vm.createSelectFork("polygon");
            gasworks = deployGasworks(chainId);
            uniswapPermit2 = POLYGON_UNISWAP_PERMIT2;
        }
        if (chainId == ETH_CHAIN_ID) {
            vm.createSelectFork("ethereum");
            gasworks = deployGasworks(chainId);
            uniswapPermit2 = ETH_UNISWAP_PERMIT2;
        }

        vm.prank(ALICE);
        IERC20(sellToken).approve(uniswapPermit2, type(uint256).max);
        (IGasworks.SwapData memory swapData) = fetchSwapQuote(sellAmount, sellToken, buyToken);

        deal(sellToken, ALICE, sellAmount);
        uint256 previousSellTokenBalance = IERC20(sellToken).balanceOf(ALICE);
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

        assertEq(previousSellTokenBalance - IERC20(sellToken).balanceOf(ALICE), sellAmount);
        assertGe(IERC20(buyToken).balanceOf(ALICE) - previousBuyTokenBalance, swapData.buyAmount);
        assertEq(IERC20(sellToken).allowance(ALICE, address(gasworks)), 0);
    }

    /**
     * [SUCCESS] Should make a swap from USDC to WEB3 using permit2
     */
    function testSwapWithPermit2FromUsdcToWeb3() public {
        swapWithPermit2(POLYGON_CHAIN_ID, 1e6, POLYGON_USDC, POLYGON_WEB3);
    }

    /**
     * [SUCCESS] Should make a swap from AEDY to ADDY using permit2
     */
    function testSwapWithPermit2FromAedyToAddy() public {
        swapWithPermit2(POLYGON_CHAIN_ID, 20e18, POLYGON_AEDY, POLYGON_ADDY);
    }
    /**
     * [SUCCESS] Should make a swap from DAI to CHAIN using permit2
     */

    function testSwapWithPermit2FromDaiToChain() public {
        swapWithPermit2(POLYGON_CHAIN_ID, 200e18, POLYGON_DAI, POLYGON_CHAIN);
    }

    /**
     * [SUCCESS] Should make a swap from USDC to native MATIC with permit2
     */
    function testSwapWithPermit2FromUsdcToNativeMatic() public {
        uint256 sellAmount = 10e6;
        address sellToken = POLYGON_USDC;
        address buyToken = POLYGON_WMATIC;

        vm.createSelectFork("polygon");
        Gasworks gasworks = deployGasworks(POLYGON_CHAIN_ID);
        address uniswapPermit2 = POLYGON_UNISWAP_PERMIT2;

        vm.prank(ALICE);
        IERC20(sellToken).approve(uniswapPermit2, type(uint256).max);
        (IGasworks.SwapData memory swapData) = fetchSwapQuote(sellAmount, sellToken, buyToken);

        deal(sellToken, ALICE, sellAmount);
        uint256 previousSellTokenBalance = IERC20(sellToken).balanceOf(ALICE);
        uint256 previousBuyTokenBalance = IERC20(buyToken).balanceOf(ALICE);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: sellToken, amount: sellAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign =
            getSwapWithPermit2MessageToSign(POLYGON_CHAIN_ID, permit, address(gasworks), swapData);
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        gasworks.swapWithPermit2(permit, ALICE, signature, swapData);

        assertEq(previousSellTokenBalance - IERC20(sellToken).balanceOf(ALICE), sellAmount);
        assertEq(IERC20(sellToken).allowance(ALICE, address(gasworks)), 0);
        assertGe(previousBuyTokenBalance - IERC20(buyToken).balanceOf(ALICE), 0);
        assertGe(ALICE.balance, swapData.buyAmount); // Receive MATIC, not WMATIC
    }
}
