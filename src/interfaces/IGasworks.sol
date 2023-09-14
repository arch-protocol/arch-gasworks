/**
 *     SPDX-License-Identifier: Apache License 2.0
 *
 *     Copyright 2023 Smash Works Inc.
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 *             %@@@@@
 *          @@@@@@@@@@@
 *        #@@@@@     @@@           @@                   @@
 *       @@@@@@       @@@         @@@@                  @@
 *      @@@@@@         @@        @@  @@    @@@@@ @@@@@  @@@*@@
 *     .@@@@@          @@@      @@@@@@@@   @@    @@     @@  @@
 *     @@@@@(       (((((      @@@    @@@  @@    @@@@@  @@  @@
 *    @@@@@@   (((((((
 *    @@@@@#(((((((
 *    @@@@@(((((
 *      @@@((
 */

pragma solidity ^0.8.17.0;

import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { ISetToken } from "./ISetToken.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { ITradeIssuerV2 } from "chambers-peripherals/src/interfaces/ITradeIssuerV2.sol";
import { IChamber } from "chambers/interfaces/IChamber.sol";
import { IIssuerWizard } from "chambers/interfaces/IIssuerWizard.sol";
import { ITradeIssuerV2 } from "chambers-peripherals/src/interfaces/ITradeIssuerV2.sol";

interface IGasworks {
    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    // Permit1
    struct PermitData {
        // The address of the token to which we want to sign a permit for
        address _tokenContract;
        // The amount of tokens we want to send to the contract
        uint256 _amount;
        // The owner of the tokens
        address _owner;
        // The contract that will spend our tokens
        address _spender;
        // The amount of the token we want to permit the contract to use
        uint256 _value;
        // The date until which the permit is accepted
        uint256 _deadline;
        // The signature of the owner
        uint8 _v;
        bytes32 _r;
        bytes32 _s;
    }

    struct MintSetData {
        // Address of the SetToken to be issued
        ISetToken _setToken;
        // Amount of SetTokens to issue
        uint256 _amountSetToken;
        // Maximum amount of input tokens to be used to issue SetTokens.
        uint256 _maxAmountInputToken;
        // The encoded 0x transactions to execute
        bytes[] _componentQuotes;
        // The address of the issuance module for the SetToken
        address _issuanceModule;
        // Is the SetToken using debt issuance?
        bool _isDebtIssuance;
    }

    struct MintChamberData {
        // The address of the chamber to mint
        IChamber _chamber;
        // The address of the issuer wizard that will mint the Chamber
        IIssuerWizard _issuerWizard;
        // The address of the token used to mint
        IERC20 _baseToken;
        // Maximum amount of baseToken to use to mint
        uint256 _maxPayAmount;
        // The amount of Chamber to mint
        uint256 _mintAmount;
    }

    // Permit2
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

    struct SwapCallInstruction {
        address sellToken;
        uint256 sellAmount;
        address buyToken;
        uint256 minBuyAmount;
        address swapTarget;
        address swapAllowanceTarget;
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

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event Withdrawn(address token, uint256 amount);

    event SwapWithPermit(
        address buyToken, uint256 buyAmount, address sellToken, uint256 sellAmount
    );

    event MintWithPermit2(
        address tokenMinted, uint256 amountMinted, address tokenPaid, uint256 amountPaid
    );

    event RedeemWithPermit2(
        address tokenRedeemed, uint256 amountRedeemed, address tokenBought, uint256 amountBought
    );

    event MintWithPermit(
        address tokenMinted, uint256 amountMinted, address tokenPaid, uint256 amountPaid
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidToken(address token);

    error ZeroBalance(address token);

    error SwapCallFailed();

    error Underbought(address token, uint256 amountToBuy);

    error TransferFailed(address recipient, uint256 amount, bytes returnData);

    /*//////////////////////////////////////////////////////////////
                                FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setTrustedForwarder(address forwarder) external;

    function setTokens(address token) external;

    function swapWithPermit(PermitData calldata permit, SwapData calldata swapData) external;

    function mintWithPermit(PermitData calldata permit, MintSetData calldata mintData) external;

    function mintChamberWithPermit(
        PermitData calldata permit,
        MintChamberData calldata mintChamberData,
        ITradeIssuerV2.ContractCallInstruction[] memory contractCallInstructions
    ) external;

    function swapWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        address owner,
        bytes calldata signature,
        SwapData calldata swapData
    ) external;

    function mintWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        address owner,
        bytes calldata signature,
        MintData calldata mintData
    ) external;

    function redeemWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        address owner,
        bytes calldata signature,
        RedeemData calldata redeemData,
        bool toNative
    ) external;

    function withdrawTokenBalance(ERC20 token) external;
}
