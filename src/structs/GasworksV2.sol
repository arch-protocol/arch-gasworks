// SPDX-License-Identifier: Apache License 2.0
pragma solidity ^0.8.21;

import { IChamber } from "chambers/interfaces/IChamber.sol";
import { ITradeIssuerV3, IERC20 } from "chambers-peripherals/src/interfaces/ITradeIssuerV3.sol";
import { IIssuerWizard } from "chambers/interfaces/IIssuerWizard.sol";

struct SwapData {
    // The `buyTokenAddress` field from the API response.
    address buyToken;
    // The `buyAmount` field from the API response.
    uint256 buyAmount;
    // The `value` field from the API response.
    uint256 nativeTokenAmount;
    // The `to` field from the API response.
    address payable swapTarget;
    // The `allowanceTarget` field from the API response.
    address swapAllowanceTarget;
    // The `data` field from the API response.
    bytes swapCallData;
}

struct MintData {
    // The address of the chamber to mint
    address archToken;
    // The amount of Chamber to mint
    uint256 archTokenAmount;
    // The address of the token used to mint
    address inputToken;
    // Maximum amount of baseToken to use to mint
    uint256 inputTokenMaxAmount;
    // The address of the issuer wizard that will mint the Chamber
    address issuer;
    // Intructions to pass the TradeIssuer
    SwapCallInstruction[] swapCallInstructions;
}

struct RedeemData {
    // The address of the chamber to redeem
    address archToken;
    // The amount of Chamber to redeem
    uint256 archTokenAmount;
    // The address of the token used to mint
    address outputToken;
    // Min amount of baseToken to receive after redemption
    uint256 outputTokenMinAmount;
    // The address of the issuer wizard that will mint the Chamber
    address issuer;
    // Intructions to pass the TradeIssuer
    SwapCallInstruction[] swapCallInstructions;
}

struct RedeemAndMintData {
    // The address of the chamber to redeem
    address archTokenToRedeem;
    // The amount of Chamber to redeem
    uint256 redeemAmount;
    // The address of the token to mint
    address archTokenToMint;
    // The amount of Chamber to mint
    uint256 mintAmount;
    // The address of the issuer wizard that will mint the Chamber
    address issuer;
    // Intructions to pass the TradeIssuer
    SwapCallInstruction[] swapCallInstructions;
}

struct SwapCallInstruction {
    address sellToken;
    uint256 sellAmount;
    address buyToken;
    uint256 minBuyAmount;
    address swapTarget;
    address swapAllowanceTarget;
    bytes swapCallData;
}
