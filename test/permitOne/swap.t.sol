// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { SigUtils } from "test/utils/SigUtils.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { Conversor } from "test/utils/HexUtils.sol";
import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";
import { WETH } from "solmate/src/tokens/WETH.sol";

contract GaslessTest is Test {
    using SafeTransferLib for ERC20;

    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/

    Gasworks internal gasworks;
    ERC20 internal constant USDC = ERC20(0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174);
    ERC20 internal constant WEB3 = ERC20(0xBcD2C5C78000504EFBC1cE6489dfcaC71835406A);
    WETH public constant WMATIC = WETH(payable(0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270));
    SigUtils internal sigUtils;

    uint256 internal ownerPrivateKey;
    address internal owner;
    IGasworks.SwapData internal swapData;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        vm.createSelectFork("polygon");
        gasworks = new Gasworks(
            0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d,
            0x1c0c05a2aA31692e5dc9511b04F651db9E4d8320,
            0x2B13D2b9407D5776B0BB63c8cd144978B6B7cE58
        );
        gasworks.setTokens(address(USDC));
        gasworks.setTokens(address(WEB3));
        gasworks.setTokens(address(WMATIC));
        sigUtils = new SigUtils(USDC.DOMAIN_SEPARATOR());

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        vm.prank(0xe7804c37c13166fF0b37F5aE0BB07A3aEbb6e245);
        USDC.safeTransfer(owner, 1e6);

        string[] memory inputs = new string[](5);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(1e6));
        inputs[3] = Conversor.iToHex(abi.encode(address(USDC)));
        inputs[4] = Conversor.iToHex(abi.encode(address(WEB3)));
        bytes memory res = vm.ffi(inputs);
        (
            address spender,
            address payable swapTarget,
            bytes memory quote,
            uint256 value,
            uint256 buyAmount
        ) = abi.decode(res, (address, address, bytes, uint256, uint256));
        swapData = IGasworks.SwapData(address(WEB3), buyAmount, value, swapTarget, spender, quote);
    }

    /*//////////////////////////////////////////////////////////////
                              REVERT
    //////////////////////////////////////////////////////////////*/

    /**
     * [REVERT] Should revert because the permit is expired
     */
    function testCannotSwapWithExpiredPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(gasworks),
            value: 1e18,
            nonce: USDC.nonces(owner),
            deadline: 2 ** 255 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.warp(2 ** 255 + 1); // fast forwards one second past the deadline

        vm.expectRevert("Permit: permit is expired");
        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                1e18,
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
            owner: owner,
            spender: address(gasworks),
            value: 1e18,
            nonce: USDC.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xB0B, digest); // 0xB0B signs but 0xA11CE is owner

        vm.expectRevert("Permit: invalid signature");
        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                1e18,
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
            owner: owner,
            spender: address(gasworks),
            value: 1e18,
            nonce: 1, // set nonce to 1 instead of 0
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert("Permit: invalid signature");
        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                1e18,
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
            owner: owner,
            spender: address(gasworks),
            value: swapData.buyAmount, // sets allowance of 0.5 tokens
            nonce: 0,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                1e18,
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
            owner: owner,
            spender: address(gasworks),
            value: 2e18,
            nonce: 0,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                2e18, // owner was only minted 1 USDC
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
            owner: owner,
            spender: address(gasworks),
            value: 1e6,
            nonce: 0,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert(
            abi.encodeWithSelector(IGasworks.Underbought.selector, address(WEB3), 1000 ether)
        );
        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                1e6,
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
            owner: owner,
            spender: address(gasworks),
            value: 1e6,
            nonce: 0,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert(IGasworks.SwapCallFailed.selector);
        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                1e6,
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
            owner: owner,
            spender: address(gasworks),
            value: 1e6,
            nonce: USDC.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert(abi.encodeWithSelector(IGasworks.InvalidToken.selector, address(0x123123)));
        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(0x123123),
                1e6,
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
            owner: owner,
            spender: address(gasworks),
            value: 1e6,
            nonce: USDC.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                1e6,
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

        assertEq(USDC.balanceOf(owner), 0);
        assertEq(USDC.balanceOf(address(gasworks)), 0);
        assertEq(USDC.allowance(owner, address(gasworks)), 0);
        assertEq(USDC.nonces(owner), 1);
        assertGe(WEB3.balanceOf(owner), swapData.buyAmount);
    }

    /**
     * [SUCCESS] Should make a success swap with permit with max amount allowed
     */
    function testSwapWithMaxPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(gasworks),
            value: type(uint256).max,
            nonce: USDC.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                1e6,
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

        assertEq(USDC.balanceOf(owner), 0);
        assertEq(USDC.balanceOf(address(gasworks)), 0);

        assertEq(USDC.allowance(owner, address(gasworks)), type(uint256).max - 1e6);
        assertEq(USDC.nonces(owner), 1);
        assertGe(WEB3.balanceOf(owner), swapData.buyAmount);
    }

    /**
     * [SUCCESS] Should make a success swap to native token with permit with max amount allowed
     */
    function testSwapToNativeTokenWithLimitedPermit() public {
        string[] memory inputs = new string[](5);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(1e6));
        inputs[3] = Conversor.iToHex(abi.encode(address(USDC)));
        inputs[4] = Conversor.iToHex(abi.encode(address(WMATIC)));
        bytes memory res = vm.ffi(inputs);
        (
            address spender,
            address payable swapTarget,
            bytes memory quote,
            uint256 value,
            uint256 buyAmount
        ) = abi.decode(res, (address, address, bytes, uint256, uint256));
        swapData = IGasworks.SwapData(address(WMATIC), buyAmount, value, swapTarget, spender, quote);
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(gasworks),
            value: 1e6,
            nonce: USDC.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        gasworks.swapWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                1e6,
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

        assertEq(USDC.balanceOf(owner), 0);
        assertEq(USDC.balanceOf(address(gasworks)), 0);
        assertEq(USDC.allowance(owner, address(gasworks)), 0);
        assertEq(USDC.nonces(owner), 1);
        assertGe(owner.balance, swapData.buyAmount);
    }
}
