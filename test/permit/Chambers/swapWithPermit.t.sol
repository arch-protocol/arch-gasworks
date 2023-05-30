// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { SigUtils } from "test/utils/SigUtils.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { Conversor } from "test/utils/HexUtils.sol";
import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";

contract GaslessTest is Test {
    using SafeTransferLib for ERC20;

    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/

    Gasworks internal gasworks;
    ERC20 internal constant ADDY = ERC20(0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF);
    ERC20 internal constant WEB3 = ERC20(0xe8e8486228753E01Dbc222dA262Aa706Bd67e601);
    SigUtils internal sigUtils;

    uint256 internal ownerPrivateKey;
    address internal owner;
    IGasworks.SwapData internal swapData;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        gasworks = new Gasworks(
            0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d, 
            0x1c0c05a2aA31692e5dc9511b04F651db9E4d8320,
            0x2B13D2b9407D5776B0BB63c8cd144978B6B7cE58
        );
        gasworks.setTokens(address(ADDY));
        gasworks.setTokens(address(WEB3));
        sigUtils = new SigUtils(ADDY.DOMAIN_SEPARATOR());

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        vm.prank(0x0cC2CaeD31490B546c741BD93dbba8Ab387f7F2c);
        ADDY.safeTransfer(owner, 100 ether);

        string[] memory inputs = new string[](5);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-eth-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(1 ether));
        inputs[3] = Conversor.iToHex(abi.encode(address(ADDY)));
        inputs[4] = Conversor.iToHex(abi.encode(address(WEB3)));
        bytes memory res = vm.ffi(inputs);
        (
            address spender,
            address payable swapTarget,
            bytes memory quote,
            uint256 value,
            uint256 buyAmount
        ) = abi.decode(res, (address, address, bytes, uint256, uint256));
        swapData = IGasworks.SwapData(address(WEB3), spender, swapTarget, quote, value, buyAmount);
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
            nonce: ADDY.nonces(owner),
            deadline: 2 ** 255 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.warp(2 ** 255 + 1); // fast forwards one second past the deadline

        vm.expectRevert("PERMIT_DEADLINE_EXPIRED");
        gasworks.swapWithPermit(
            IGasworks.PermitData(
                address(ADDY),
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
            nonce: ADDY.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xB0B, digest); // 0xB0B signs but 0xA11CE is owner

        vm.expectRevert("INVALID_SIGNER");
        gasworks.swapWithPermit(
            IGasworks.PermitData(
                address(ADDY),
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

        vm.expectRevert("INVALID_SIGNER");
        gasworks.swapWithPermit(
            IGasworks.PermitData(
                address(ADDY),
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
            value: 1, // sets allowance of 0.5 tokens
            nonce: 0,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        gasworks.swapWithPermit(
            IGasworks.PermitData(
                address(ADDY),
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
            value: 2000e18,
            nonce: 0,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        gasworks.swapWithPermit(
            IGasworks.PermitData(
                address(ADDY),
                20000e18, // owner was only minted 1 ADDY
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
            value: 1e18,
            nonce: 0,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert(
            abi.encodeWithSelector(IGasworks.Underbought.selector, address(WEB3), 1000 ether)
        );
        gasworks.swapWithPermit(
            IGasworks.PermitData(
                address(ADDY),
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
     * [REVERT] Should revert because low level call to swapTarget failed
     */
    function testCannotSwapWithSwapCallFailed() public {
        swapData.swapCallData = bytes("swapCallData");
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(gasworks),
            value: 1e18,
            nonce: 0,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert(IGasworks.SwapCallFailed.selector);
        gasworks.swapWithPermit(
            IGasworks.PermitData(
                address(ADDY),
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
     * [REVERT] Should revert because token is not permitted
     */
    function testCannotSwapWithInvalidToken() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(gasworks),
            value: 1e18,
            nonce: ADDY.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert(abi.encodeWithSelector(IGasworks.InvalidToken.selector, address(0x123123)));
        gasworks.swapWithPermit(
            IGasworks.PermitData(
                address(0x123123),
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
            value: 1e18,
            nonce: ADDY.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        gasworks.swapWithPermit(
            IGasworks.PermitData(
                address(ADDY),
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

        assertEq(ADDY.balanceOf(owner), 99 ether);
        assertEq(ADDY.balanceOf(address(gasworks)), 0);
        assertEq(ADDY.allowance(owner, address(gasworks)), 0);
        assertEq(ADDY.nonces(owner), 1);
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
            nonce: ADDY.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        gasworks.swapWithPermit(
            IGasworks.PermitData(
                address(ADDY),
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

        assertEq(ADDY.balanceOf(owner), 99 ether);
        assertEq(ADDY.balanceOf(address(gasworks)), 0);
        assertEq(ADDY.allowance(owner, address(gasworks)), type(uint256).max);
        assertEq(ADDY.nonces(owner), 1);
        assertGe(WEB3.balanceOf(owner), swapData.buyAmount);
    }
}
