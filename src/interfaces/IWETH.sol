// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.9;
pragma experimental "ABIEncoderV2";

import "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
interface IWETH is IERC20 {
    function deposit() external payable;
    function withdraw(uint) external;
}