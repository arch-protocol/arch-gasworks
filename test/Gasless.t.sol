pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import "forge-std/console2.sol";

import "../src/PermitSwapGasless.sol";
import {SigUtils} from "./utils/SigUtils.sol";
import "solmate/tokens/ERC20.sol";
import "./utils/HexUtils.sol";

contract GaslessTest is Test {
    ///                                                          ///
    ///                           SETUP                          ///
    ///                                                          ///

    PermitSwapGasless internal swap;
    ERC20 internal usdc;
    ERC20 internal web3;
    SigUtils internal sigUtils;

    uint256 internal ownerPrivateKey;
    address internal owner;
    PermitSwapGasless.SwapData internal swapData;

    function setUp() public {
        usdc = ERC20(0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174);
        web3 = ERC20(0xBcD2C5C78000504EFBC1cE6489dfcaC71835406A);
        swap = new PermitSwapGasless(0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d);
        sigUtils = new SigUtils(usdc.DOMAIN_SEPARATOR());

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        vm.prank(0xF977814e90dA44bFA03b6295A0616a897441aceC);
        usdc.transfer(owner, 1e6);

        // vm.deal(address(swap), 10 ether);

        vm.deal(owner, 10 ether);

        string[] memory inputs = new string[](3);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(1e6));
        bytes memory res = vm.ffi(inputs);
        (address spender, address payable swapTarget, bytes memory quote, uint256 value) = abi.decode(res, (address, address, bytes, uint256));
        swapData = PermitSwapGasless.SwapData(usdc, web3, spender, swapTarget, quote, value);
    }

    ///                                                          ///
    ///                           Swap                           ///
    ///                                                          ///

    function test_Swap() public {
        vm.prank(owner);
        usdc.approve(address(swap), 1e6);

        vm.prank(owner);
        swap.swapNormal(address(usdc), 1e6, swapData);

        assertEq(usdc.balanceOf(owner), 0);
        assertEq(usdc.balanceOf(address(swap)), 0);
        assertGe(web3.balanceOf(owner), 5e17);
    }   

    function testFail_ContractNotApproved() public {
        vm.prank(owner);
        swap.swapNormal(address(usdc), 1e6, swapData);
    }

    ///                                                          ///
    ///                       SWAP w/ PERMIT                     ///
    ///                                                          ///

    function test_SwapWithLimitedPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(swap),
            value: 1e6,
            nonce: usdc.nonces(owner),
            deadline: 2**256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.prank(owner);
        swap.swapWithPermit(PermitSwapGasless.PermitData(
            address(usdc),
            1e6,
            permit.owner,
            permit.spender,
            permit.value,
            permit.deadline,
            v,
            r,
            s
        ), swapData);

        assertEq(usdc.balanceOf(owner), 0);
        assertEq(usdc.balanceOf(address(swap)), 0);
        assertEq(usdc.allowance(owner, address(swap)), 0);
        assertEq(usdc.nonces(owner), 1);
        assertGe(web3.balanceOf(owner), 5e17);
    }

    function test_SwapWithMaxPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(swap),
            value: type(uint256).max,
            nonce: usdc.nonces(owner),
            deadline: 2**256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.prank(owner);
        swap.swapWithPermit(PermitSwapGasless.PermitData(
            address(usdc),
            1e6,
            permit.owner,
            permit.spender,
            permit.value,
            permit.deadline,
            v,
            r,
            s
        ), swapData);

        assertEq(usdc.balanceOf(owner), 0);
        assertEq(usdc.balanceOf(address(swap)), 0);

        assertEq(usdc.allowance(owner, address(swap)), type(uint256).max - 1e6);
        assertEq(usdc.nonces(owner), 1);
        assertGe(web3.balanceOf(owner), 5e17);
    }

    function testRevert_ExpiredPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(swap),
            value: 1e18,
            nonce: usdc.nonces(owner),
            deadline: 2**255 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.warp(2**255 + 1); // fast forwards one second past the deadline

        vm.expectRevert("Permit: permit is expired");
        swap.swapWithPermit(PermitSwapGasless.PermitData(
            address(usdc),
            1e18,
            permit.owner,
            permit.spender,
            permit.value,
            permit.deadline,
            v,
            r,
            s
        ), swapData);
    }

    function testRevert_InvalidSigner() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(swap),
            value: 1e18,
            nonce: usdc.nonces(owner),
            deadline: 2**256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xB0B, digest); // 0xB0B signs but 0xA11CE is owner

        vm.expectRevert("Permit: invalid signature");
        swap.swapWithPermit(PermitSwapGasless.PermitData(
            address(usdc),
            1e18,
            permit.owner,
            permit.spender,
            permit.value,
            permit.deadline,
            v,
            r,
            s
        ), swapData);
    }

    function testRevert_InvalidNonce() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(swap),
            value: 1e18,
            nonce: 1, // set nonce to 1 instead of 0
            deadline: 2**256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert("Permit: invalid signature");
        swap.swapWithPermit(PermitSwapGasless.PermitData(
            address(usdc),
            1e18,
            permit.owner,
            permit.spender,
            permit.value,
            permit.deadline,
            v,
            r,
            s
        ), swapData);
    }

    function testFail_InvalidAllowance() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(swap),
            value: 5e17, // sets allowance of 0.5 tokens
            nonce: 0,
            deadline: 2**256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        swap.swapWithPermit(PermitSwapGasless.PermitData(
            address(usdc),
            1e18,
            permit.owner,
            permit.spender,
            permit.value,
            permit.deadline,
            v,
            r,
            s
        ), swapData);
    }

    function testFail_InvalidBalance() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(swap),
            value: 2e18,
            nonce: 0,
            deadline: 2**256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        swap.swapWithPermit(PermitSwapGasless.PermitData(
            address(usdc),
            2e18, // owner was only minted 1 usdc
            permit.owner,
            permit.spender,
            permit.value,
            permit.deadline,
            v,
            r,
            s
        ), swapData);
    }
}
