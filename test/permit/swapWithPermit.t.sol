// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import {Test} from "forge-std/Test.sol";
import {Gasworks} from "src/Gasworks.sol";
import {SigUtils} from "test/utils/SigUtils.sol";
import {ERC20} from "solmate/src/tokens/ERC20.sol";
import {Conversor} from "test/utils/HexUtils.sol";
import {SafeTransferLib} from "solmate/src/utils/SafeTransferLib.sol";

contract GaslessTest is Test {
    using SafeTransferLib for ERC20;

    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/

    address internal immutable usdcAddress = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174;
    address internal immutable web3Address = 0xBcD2C5C78000504EFBC1cE6489dfcaC71835406A;
    address private constant biconomyForwarder = 0x86C80a8aa58e0A4fa09A69624c31Ab2a6CAD56b8;

    Gasworks internal gasworks;
    ERC20 internal usdc;
    ERC20 internal web3;
    SigUtils internal sigUtils;

    uint256 internal ownerPrivateKey;
    address internal owner;
    Gasworks.SwapData internal swapData;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        usdc = ERC20(0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174);
        web3 = ERC20(0xBcD2C5C78000504EFBC1cE6489dfcaC71835406A);
        gasworks = new Gasworks(0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d);
        gasworks.setTokens(address(usdc));
        gasworks.setTokens(address(web3));
        sigUtils = new SigUtils(usdc.DOMAIN_SEPARATOR());

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        vm.prank(0xe7804c37c13166fF0b37F5aE0BB07A3aEbb6e245);
        usdc.safeTransfer(owner, 1e6);

        vm.deal(biconomyForwarder, 10 ether);

        string[] memory inputs = new string[](3);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(1e6));
        bytes memory res = vm.ffi(inputs);
        (address spender, address payable swapTarget, bytes memory quote, uint256 value, uint256 buyAmount) =
            abi.decode(res, (address, address, bytes, uint256, uint256));
        swapData = Gasworks.SwapData(web3Address, spender, swapTarget, quote, value, buyAmount);
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
            nonce: usdc.nonces(owner),
            deadline: 2 ** 255 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.warp(2 ** 255 + 1); // fast forwards one second past the deadline

        vm.expectRevert("Permit: permit is expired");
        vm.prank(biconomyForwarder);
        gasworks.swapWithPermit(
            Gasworks.PermitData(
                address(usdc), 1e18, permit.owner, permit.spender, permit.value, permit.deadline, v, r, s
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
            nonce: usdc.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xB0B, digest); // 0xB0B signs but 0xA11CE is owner

        vm.expectRevert("Permit: invalid signature");
        vm.prank(biconomyForwarder);
        gasworks.swapWithPermit(
            Gasworks.PermitData(
                address(usdc), 1e18, permit.owner, permit.spender, permit.value, permit.deadline, v, r, s
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
        vm.prank(biconomyForwarder);
        gasworks.swapWithPermit(
            Gasworks.PermitData(
                address(usdc), 1e18, permit.owner, permit.spender, permit.value, permit.deadline, v, r, s
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
        vm.prank(biconomyForwarder);
        gasworks.swapWithPermit(
            Gasworks.PermitData(
                address(usdc), 1e18, permit.owner, permit.spender, permit.value, permit.deadline, v, r, s
            ),
            swapData
        );
    }

    /**
     * [REVERT] Should revert because balance is less than required amount
     */
    function testCannotSwapWithInvalidBalance() public {
        SigUtils.Permit memory permit =
            SigUtils.Permit({owner: owner, spender: address(gasworks), value: 2e18, nonce: 0, deadline: 2 ** 256 - 1});

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        vm.prank(biconomyForwarder);
        gasworks.swapWithPermit(
            Gasworks.PermitData(
                address(usdc),
                2e18, // owner was only minted 1 usdc
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
     * [SUCCESS] Should make a success gasworks with permit with a limited amount allowed
     */
    function testSwapWithLimitedPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(gasworks),
            value: 1e6,
            nonce: usdc.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.prank(biconomyForwarder);
        gasworks.swapWithPermit(
            Gasworks.PermitData(
                address(usdc), 1e6, permit.owner, permit.spender, permit.value, permit.deadline, v, r, s
            ),
            swapData
        );

        assertEq(usdc.balanceOf(owner), 0);
        assertEq(usdc.balanceOf(address(gasworks)), 0);
        assertEq(usdc.allowance(owner, address(gasworks)), 0);
        assertEq(usdc.nonces(owner), 1);
        assertGe(web3.balanceOf(owner), swapData.buyAmount);
    }

    /**
     * [SUCCESS] Should make a success gasworks with permit with max amount allowed
     */
    function testSwapWithMaxPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(gasworks),
            value: type(uint256).max,
            nonce: usdc.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.prank(biconomyForwarder);
        gasworks.swapWithPermit(
            Gasworks.PermitData(
                address(usdc), 1e6, permit.owner, permit.spender, permit.value, permit.deadline, v, r, s
            ),
            swapData
        );

        assertEq(usdc.balanceOf(owner), 0);
        assertEq(usdc.balanceOf(address(gasworks)), 0);

        assertEq(usdc.allowance(owner, address(gasworks)), type(uint256).max - 1e6);
        assertEq(usdc.nonces(owner), 1);
        assertGe(web3.balanceOf(owner), swapData.buyAmount);
    }
}
