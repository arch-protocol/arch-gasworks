/**
 *     SPDX-License-Identifier: Apache License 2.0
 *
 *     Copyright 2024 Smash Works Inc.
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
pragma solidity ^0.8.21;

import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { SwapData, MintData, RedeemData, RedeemAndMintData } from "../structs/GasworksV2.sol";

interface IGasworksV2 {
    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event SwapWithPermit2(
        address sellToken, uint256 sellAmount, address buyToken, uint256 buyTokenAmountReceived
    );

    event MintWithPermit2(
        address mintToken, uint256 mintAmount, address baseToken, uint256 baseTokenAmountUsed
    );

    event RedeemWithPermit2(
        address indexed redeemToken,
        uint256 redeemAmount,
        address indexed outputToken,
        uint256 outputTokenAmountReceived
    );

    event RedeemAndMintWithPermit2(
        address redeemToken, uint256 redeemAmount, address mintToken, uint256 mintAmount
    );

    event Withdrawn(address token, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidToken(address token);

    error InvalidBaseTokenAmount(uint256 permittedAmount, uint256 mintDataAmount);

    error InvalidRedeemAmount(uint256 permittedAmount, uint256 redeemDataAmount);

    error ZeroTokenBalance(address token);

    error ZeroPermittedAmount();

    error SwapCallFailed();

    error Underbought(address token, uint256 amountToBuy);

    error TransferFailed(address recipient, uint256 amount, bytes returnData);

    error InvalidMaticReceived(address sender, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                                FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function addAllowedToken(address token) external;

    function removeAllowedToken(address token) external;

    function isAllowedToken(address token) external view returns (bool);

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

    function redeemAndMintWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        address owner,
        bytes calldata signature,
        RedeemAndMintData calldata redeemAndMintData
    ) external;

    function withdrawTokenBalance(address token) external;
}
