// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "src/CaptureTheFlag.sol";

contract FlagTest is Test {
    CaptureTheFlag t;
    address alice = address(0x123);

    function setUp() public {
        t = new CaptureTheFlag(0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0);
        vm.label(alice, "Alice");
    }

    function testCapture() public {
        vm.prank(alice);
        t.captureTheFlag();
        assertEq(t.currentHolder(), alice);
    }
}
