// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import "forge-std/StdJson.sol";
import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { SigUtils } from "test/utils/SigUtils.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { Conversor } from "test/utils/HexUtils.sol";
import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";
import { WETH } from "solmate/src/tokens/WETH.sol";
import { Permit2Utils } from "test/utils/Permit2Utils.sol";
import { DeployPermit2 } from "permit2/test/utils/DeployPermit2.sol";

contract GaslessTest is Test, Permit2Utils, DeployPermit2 {
    using SafeTransferLib for ERC20;
    using stdJson for string;

    string root;
    string path;
    string json;

    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/

    Gasworks internal gasworks;
    SigUtils internal sigUtils;
    IGasworks.SwapData internal swapData;
    ERC20 internal constant USDC = ERC20(POLYGON_USDC);
    uint256 internal constant SELL_AMOUNT = 1e6;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        addLabbels();
        root = vm.projectRoot();
        path = string.concat(root, "/data/permitOne/swap/testSwapUsdcToWeb3.json");
        json = vm.readFile(path);
        (
            uint256 chainId,
            uint256 blockNumber,
            ,
            ,
            address buyToken,
            uint256 buyAmount,
            uint256 nativeTokenAmount,
            address swapTarget,
            address swapAllowanceTarget,
            bytes memory swapCallData
        ) = parseSwapQuoteFromJson(json);

        swapData = IGasworks.SwapData(
            buyToken,
            buyAmount,
            nativeTokenAmount,
            payable(swapTarget),
            swapAllowanceTarget,
            swapCallData
        );

        vm.createSelectFork("polygon", blockNumber);
        gasworks = deployGasworks(chainId);
        sigUtils = new SigUtils(USDC.DOMAIN_SEPARATOR());

        deal(POLYGON_USDC, ALICE, SELL_AMOUNT);
    }

    /*//////////////////////////////////////////////////////////////
                              REVERT
    //////////////////////////////////////////////////////////////*/

    /**
     * [REVERT] Should revert because the permit is expired
     */
    function testCannotSwapWithExpiredPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: SELL_AMOUNT,
            nonce: USDC.nonces(ALICE),
            deadline: 2 ** 255 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.warp(2 ** 255 + 1); // fast forwards one second past the deadline

        vm.expectRevert("Permit: permit is expired");
        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                SELL_AMOUNT,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            swapData
        );
    }

    /**
     * [REVERT] Should revert because the signer of the permit
     * is not the owner of the tokens
     */
    function testCannotSwapWithInvalidSigner() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: SELL_AMOUNT,
            nonce: USDC.nonces(ALICE),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xB0B, digest); // 0xB0B signs but 0xA11CE is owner

        vm.expectRevert("Permit: invalid signature");
        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                SELL_AMOUNT,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            swapData
        );
    }

    /**
     * [REVERT] Should revert because the nonce is invalid
     */
    function testCannotSwapWithInvalidNonce() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: SELL_AMOUNT,
            nonce: 1, // set nonce to 1 instead of 0
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.expectRevert("Permit: invalid signature");
        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                SELL_AMOUNT,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            swapData
        );
    }

    /**
     * [REVERT] Should revert because allowed amount is less than required amount
     */
    function testCannotSwapWithInvalidAllowance() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: SELL_AMOUNT / 2, // Insuffitient allowance
            nonce: 0,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                SELL_AMOUNT,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            swapData
        );
    }

    /**
     * [REVERT] Should revert because balance is less than required amount
     */
    function testCannotSwapWithInvalidBalance() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: 2 * SELL_AMOUNT,
            nonce: 0,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                2 * SELL_AMOUNT, // Alice only has (1 * SELL_AMOUNT)
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            swapData
        );
    }

    /**
     * [REVERT] Should revert because amount bought is less than required amount
     */
    function testCannotSwapWithUnderboughtAsset() public {
        swapData.buyAmount = 1000 ether; // set buy amount to 1000 ether
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: SELL_AMOUNT,
            nonce: 0,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.expectRevert(
            abi.encodeWithSelector(IGasworks.Underbought.selector, swapData.buyToken, 1000 ether)
        );
        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                SELL_AMOUNT,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            swapData
        );
    }

    /**
     * [REVERT] Should revert because low level call to swapTarget failed
     */
    function testCannotSwapWithSwapCallFailed() public {
        swapData.swapCallData = bytes("swapCallData");
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: SELL_AMOUNT,
            nonce: 0,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.expectRevert(IGasworks.SwapCallFailed.selector);
        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                SELL_AMOUNT,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            swapData
        );
    }

    /**
     * [REVERT] Should revert because token is not permitted
     */
    function testCannotSwapWithInvalidToken() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: SELL_AMOUNT,
            nonce: USDC.nonces(ALICE),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.expectRevert(abi.encodeWithSelector(IGasworks.InvalidToken.selector, address(0x123123)));
        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(0x123123),
                SELL_AMOUNT,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            swapData
        );
    }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should make a success swap with permit with a limited amount allowed
     */
    function testSwapWithLimitedPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: SELL_AMOUNT,
            nonce: USDC.nonces(ALICE),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                SELL_AMOUNT,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            swapData
        );

        assertEq(USDC.balanceOf(ALICE), 0);
        assertEq(USDC.balanceOf(address(gasworks)), 0);
        assertEq(USDC.allowance(ALICE, address(gasworks)), 0);
        assertEq(USDC.nonces(ALICE), 1);
        assertGe(ERC20(swapData.buyToken).balanceOf(ALICE), swapData.buyAmount);
    }

    /**
     * [SUCCESS] Should make a success swap with permit with max amount allowed
     */
    function testSwapWithMaxPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: type(uint256).max,
            nonce: USDC.nonces(ALICE),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                SELL_AMOUNT,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            swapData
        );

        assertEq(USDC.balanceOf(ALICE), 0);
        assertEq(USDC.balanceOf(address(gasworks)), 0);

        assertEq(USDC.allowance(ALICE, address(gasworks)), type(uint256).max - SELL_AMOUNT);
        assertEq(USDC.nonces(ALICE), 1);
        assertGe(ERC20(swapData.buyToken).balanceOf(ALICE), swapData.buyAmount);
    }

    /**
     * [SUCCESS] Should make a success swap to native token with permit with max amount allowed
     */
    function testSwapToNativeTokenWithLimitedPermit() public {
        path = string.concat(root, "/data/permitOne/swap/testSwapUsdcToNativeMatic.json");
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

        swapData = IGasworks.SwapData(
            buyToken,
            buyAmount,
            nativeTokenAmount,
            payable(swapTarget),
            swapAllowanceTarget,
            swapCallData
        );

        vm.createSelectFork("polygon", blockNumber);
        gasworks = deployGasworks(chainId);
        sigUtils = new SigUtils(ERC20(sellToken).DOMAIN_SEPARATOR());

        deal(sellToken, ALICE, sellAmount);

        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: sellAmount,
            nonce: ERC20(sellToken).nonces(ALICE),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(ERC20(sellToken)),
                sellAmount,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            swapData
        );

        assertEq(ERC20(sellToken).balanceOf(ALICE), 0);
        assertEq(ERC20(sellToken).balanceOf(address(gasworks)), 0);
        assertEq(ERC20(sellToken).allowance(ALICE, address(gasworks)), 0);
        assertEq(ERC20(sellToken).nonces(ALICE), 1);
        assertGe(ALICE.balance, swapData.buyAmount);
    }
}
