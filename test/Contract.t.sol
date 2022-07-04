pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";

import "../src/PermitSwap.sol";
import {MockERC20} from "solmate/test/utils/mocks/MockERC20.sol";
import {SigUtils} from "./utils/SigUtils.sol";

contract DepositTest is Test {
    ///                                                          ///
    ///                           SETUP                          ///
    ///                                                          ///

    PermitSwap internal deposit;
    MockERC20 internal token;
    MockERC20 internal web3;
    SigUtils internal sigUtils;

    uint256 internal ownerPrivateKey;
    address internal owner;

    function setUp() public {
        token = new MockERC20("Mock Token", "MOCK", 18);
        web3 = new MockERC20("Arch Web3 Token", "WEB3", 18);
        deposit = new PermitSwap(address(web3));
        sigUtils = new SigUtils(token.DOMAIN_SEPARATOR());

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        token.mint(owner, 1e18);
    }

    ///                                                          ///
    ///                           DEPOSIT                        ///
    ///                                                          ///

    function test_Deposit() public {
        vm.prank(owner);
        token.approve(address(deposit), 1e18);

        vm.prank(owner);
        deposit.deposit(address(token), 1e18, 1e18);

        assertEq(token.balanceOf(owner), 0);
        assertEq(token.balanceOf(address(deposit)), 1e18);
    }

    function testFail_ContractNotApproved() public {
        vm.prank(owner);
        deposit.deposit(address(token), 1e18, 1e18);
    }

    ///                                                          ///
    ///                       DEPOSIT w/ PERMIT                  ///
    ///                                                          ///

    function test_DepositWithLimitedPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(deposit),
            value: 1e18,
            nonce: token.nonces(owner),
            deadline: 1 days
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        deposit.depositWithPermit(PermitSwap.PermitData(
            address(token),
            1e18,
            permit.owner,
            permit.spender,
            permit.value,
            permit.deadline,
            v,
            r,
            s),
            1e18
        );

        assertEq(token.balanceOf(owner), 0);
        assertEq(token.balanceOf(address(deposit)), 1e18);
        assertEq(web3.balanceOf(owner), 1e18);

        assertEq(token.allowance(owner, address(deposit)), 0);
        assertEq(token.nonces(owner), 1);

    }
}