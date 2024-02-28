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

import { SafeERC20 } from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import { Owned } from "solmate/src/auth/Owned.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { ITradeIssuerV3, IERC20 } from "chambers-peripherals/src/interfaces/ITradeIssuerV3.sol";
import { IChamber } from "chambers/interfaces/IChamber.sol";
import { IIssuerWizard } from "chambers/interfaces/IIssuerWizard.sol";
import { WETH } from "solmate/src/tokens/WETH.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";
import { IGasworksV2 } from "./interfaces/IGasworksV2.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {
    SwapData,
    MintData,
    RedeemData,
    RedeemAndMintData,
    SwapCallInstruction
} from "./structs/GasworksV2.sol";

contract GasworksV2 is IGasworksV2, Owned {
    /*//////////////////////////////////////////////////////////////
                            LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using Address for address payable;
    using SafeERC20 for IERC20;
    using EnumerableSet for EnumerableSet.AddressSet;

    /*//////////////////////////////////////////////////////////////
                                PEMRMIT CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes private constant TOKEN_PERMISSIONS_TYPE = "TokenPermissions(address token,uint256 amount)";

    bytes private constant SWAP_DATA_TYPE =
        "SwapData(address buyToken,uint256 buyAmount,uint256 nativeTokenAmount,address swapTarget,address swapAllowanceTarget)";
    bytes32 private constant SWAP_DATA_TYPE_HASH = keccak256(SWAP_DATA_TYPE);

    string internal constant PERMIT2_SWAP_DATA_TYPE =
        string(abi.encodePacked("SwapData witness)", SWAP_DATA_TYPE, TOKEN_PERMISSIONS_TYPE));

    bytes private constant SWAP_CALL_INSTRUCTION_TYPE =
        "SwapCallInstruction(address sellToken,uint256 sellAmount,address buyToken,uint256 minBuyAmount,address swapTarget,address swapAllowanceTarget)";
    bytes32 private constant SWAP_CALL_INSTRUCTION_TYPE_HASH = keccak256(SWAP_CALL_INSTRUCTION_TYPE);
    bytes private constant MINT_DATA_TYPE =
        "MintData(address archToken,uint256 archTokenAmount,address inputToken,uint256 inputTokenMaxAmount,address issuer,SwapCallInstruction[] swapCallInstructions)";
    string internal constant PERMIT2_MINT_DATA_TYPE = string(
        abi.encodePacked(
            "MintData witness)", MINT_DATA_TYPE, SWAP_CALL_INSTRUCTION_TYPE, TOKEN_PERMISSIONS_TYPE
        )
    );
    bytes32 internal constant PERMIT_WITNESS_TRANSFERFROM_HASH = keccak256(
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,MintData witness)MintData(address archToken,uint256 archTokenAmount,address inputToken,uint256 inputTokenMaxAmount,address issuer,SwapCallInstruction[] swapCallInstructions)SwapCallInstruction(address sellToken,uint256 sellAmount,address buyToken,uint256 minBuyAmount,address swapTarget,address swapAllowanceTarget)TokenPermissions(address token,uint256 amount)"
    );
    bytes32 internal constant MINT_DATA_TYPE_HASH =
        keccak256(abi.encodePacked(MINT_DATA_TYPE, SWAP_CALL_INSTRUCTION_TYPE));

    bytes private constant REDEEM_DATA_TYPE =
        "RedeemData(address archToken,uint256 archTokenAmount,address outputToken,uint256 outputTokenMinAmount,address issuer,SwapCallInstruction[] swapCallInstructions)";
    bytes32 private constant REDEEM_DATA_TYPE_HASH =
        keccak256(abi.encodePacked(REDEEM_DATA_TYPE, SWAP_CALL_INSTRUCTION_TYPE));
    string internal constant PERMIT2_REDEEM_DATA_TYPE = string(
        abi.encodePacked(
            "RedeemData witness)",
            REDEEM_DATA_TYPE,
            SWAP_CALL_INSTRUCTION_TYPE,
            TOKEN_PERMISSIONS_TYPE
        )
    );

    bytes private constant REDEEM_AND_MINT_DATA_TYPE =
        "RedeemAndMintData(address archTokenToRedeem,uint256 redeemAmount,address archTokenToMint,uint256 mintAmount,address issuer,SwapCallInstruction[] swapCallInstructions)";
    bytes32 private constant REDEEM_AND_MINT_DATA_TYPE_HASH =
        keccak256(abi.encodePacked(REDEEM_AND_MINT_DATA_TYPE, SWAP_CALL_INSTRUCTION_TYPE));
    string internal constant PERMIT2_REDEEM_AND_MINT_DATA_TYPE = string(
        abi.encodePacked(
            "RedeemAndMintData witness)",
            REDEEM_AND_MINT_DATA_TYPE,
            SWAP_CALL_INSTRUCTION_TYPE,
            TOKEN_PERMISSIONS_TYPE
        )
    );

    /*//////////////////////////////////////////////////////////////
                            STATE
    //////////////////////////////////////////////////////////////*/

    ISignatureTransfer public immutable signatureTransfer;
    ITradeIssuerV3 public immutable tradeIssuer;

    WETH private constant WMATIC = WETH(payable(0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270));

    EnumerableSet.AddressSet private allowedTokens;

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _signatureTransfer, address _tradeIssuer) Owned(msg.sender) {
        signatureTransfer = ISignatureTransfer(_signatureTransfer);
        tradeIssuer = ITradeIssuerV3(_tradeIssuer);
    }

    /*//////////////////////////////////////////////////////////////
                            EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    receive() external payable {
        if (msg.sender != address(WMATIC)) {
            revert InvalidMaticReceived(msg.sender, msg.value);
        }
    }

    function addAllowedToken(address token) public onlyOwner {
        allowedTokens.add(token);
    }

    function removeAllowedToken(address token) public onlyOwner {
        allowedTokens.remove(token);
    }

    function isAllowedToken(address token) public view returns (bool) {
        return allowedTokens.contains(token);
    }

    /**
     * Swaps an exact amount of ERC20 tokens for a given amount of ERC20 tokens.
     * Transfers the bought tokens to the owner. Uses a permit for the token
     * transfer (through Permit2).
     *
     * @param permit2    Permit2 data of the ERC20 token used
     * @param owner      Owner of the tokens to transfer
     * @param signature  Signature of the owner of the tokens
     * @param swapData   Data of the swap to perform
     */
    function swapWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        address owner,
        bytes calldata signature,
        SwapData calldata swapData
    ) external {
        if (permit2.permitted.amount == 0) revert ZeroPermittedAmount();
        if (!isAllowedToken(permit2.permitted.token)) revert InvalidToken(permit2.permitted.token);
        if (!isAllowedToken(swapData.buyToken)) revert InvalidToken(swapData.buyToken);

        ISignatureTransfer.SignatureTransferDetails memory transferDetails = ISignatureTransfer
            .SignatureTransferDetails({ to: address(this), requestedAmount: permit2.permitted.amount });

        bytes32 witness = _calculateSwapDataTypeWitness(swapData);

        signatureTransfer.permitWitnessTransferFrom(
            permit2, transferDetails, owner, witness, PERMIT2_SWAP_DATA_TYPE, signature
        );

        _swapAndTransfer(
            swapData, IERC20(permit2.permitted.token), transferDetails.requestedAmount, owner
        );
    }

    /**
     * Mints an exact amount of Chamber from a given amount of input ERC20 tokens.
     * Transfers the minted tokens to the owner. Uses a permit for the token
     * transfer (through Permit2)
     *
     * @param permit2    Permit2 data of the ERC20 token used
     * @param owner      Owner of the tokens to transfer
     * @param signature  Signature of the owner of the tokens
     * @param mintData   Data of the chamber mint to perform
     */
    function mintWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        address owner,
        bytes calldata signature,
        MintData calldata mintData
    ) external {
        if (permit2.permitted.amount == 0) revert ZeroPermittedAmount();
        if (!isAllowedToken(mintData.inputToken)) {
            revert InvalidToken(address(mintData.inputToken));
        }
        if (!isAllowedToken(address(mintData.archToken))) {
            revert InvalidToken(address(mintData.archToken));
        }
        if (permit2.permitted.token != address(mintData.inputToken)) {
            revert InvalidToken(address(mintData.inputToken));
        }
        if (permit2.permitted.amount != mintData.inputTokenMaxAmount) {
            revert InvalidBaseTokenAmount(permit2.permitted.amount, mintData.inputTokenMaxAmount);
        }

        ISignatureTransfer.SignatureTransferDetails memory transferDetails = ISignatureTransfer
            .SignatureTransferDetails({ to: address(this), requestedAmount: permit2.permitted.amount });

        (
            ITradeIssuerV3.ContractCallInstruction[] memory contractCallInstructions,
            bytes32 concatenatedHashedSwapCallInstructions
        ) = _hashSwapCallInstructionAndConvertToTraderIssuerCallInstruction(
            mintData.swapCallInstructions
        );

        bytes32 witness =
            _calculateMintDataTypeWitness(mintData, concatenatedHashedSwapCallInstructions);

        signatureTransfer.permitWitnessTransferFrom(
            permit2, transferDetails, owner, witness, PERMIT2_MINT_DATA_TYPE, signature
        );

        IERC20 inputToken = IERC20(permit2.permitted.token);

        uint256 currentTradeIssuerAllowance =
            inputToken.allowance(address(this), address(tradeIssuer));
        if (currentTradeIssuerAllowance < mintData.inputTokenMaxAmount) {
            inputToken.safeIncreaseAllowance(
                address(tradeIssuer), mintData.inputTokenMaxAmount - currentTradeIssuerAllowance
            );
        }

        uint256 inputTokenUsed = tradeIssuer.mintFromToken(
            contractCallInstructions,
            IChamber(mintData.archToken),
            IIssuerWizard(mintData.issuer),
            IERC20(mintData.inputToken),
            mintData.inputTokenMaxAmount,
            mintData.archTokenAmount
        );

        currentTradeIssuerAllowance = inputToken.allowance(address(this), address(tradeIssuer));
        inputToken.safeDecreaseAllowance(address(tradeIssuer), currentTradeIssuerAllowance);

        IERC20(mintData.archToken).safeTransfer(owner, mintData.archTokenAmount);

        emit MintWithPermit2(
            mintData.archToken, mintData.archTokenAmount, permit2.permitted.token, inputTokenUsed
        );
    }

    /**
     * Redeems an exact amount of Chamber to a given amount of ERC20 tokens.
     * Using a permit for the Chamber token (through Permit2).
     *
     * @param permit2     Permit2 data of the ERC20 token used
     * @param owner       Owner of the tokens to transfer
     * @param signature   Signature of the owner of the tokens
     * @param redeemData  Data of the chamber redeem to perform
     * @param toNative    True if output is native token
     */
    function redeemWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        address owner,
        bytes calldata signature,
        RedeemData calldata redeemData,
        bool toNative
    ) external {
        if (permit2.permitted.amount == 0) revert ZeroPermittedAmount();
        if (!isAllowedToken(redeemData.archToken)) revert InvalidToken(redeemData.archToken);
        if (!isAllowedToken(redeemData.outputToken)) revert InvalidToken(redeemData.outputToken);
        if (permit2.permitted.token != redeemData.archToken) {
            revert InvalidToken(redeemData.archToken);
        }
        if (permit2.permitted.amount != redeemData.archTokenAmount) {
            revert InvalidRedeemAmount(permit2.permitted.amount, redeemData.archTokenAmount);
        }

        ISignatureTransfer.SignatureTransferDetails memory transferDetails = ISignatureTransfer
            .SignatureTransferDetails({ to: address(this), requestedAmount: permit2.permitted.amount });

        (
            ITradeIssuerV3.ContractCallInstruction[] memory contractCallInstructions,
            bytes32 concatenatedHashedSwapCallInstructions
        ) = _hashSwapCallInstructionAndConvertToTraderIssuerCallInstruction(
            redeemData.swapCallInstructions
        );

        bytes32 witness =
            _calculateRedeemDataTypeWitness(redeemData, concatenatedHashedSwapCallInstructions);

        signatureTransfer.permitWitnessTransferFrom(
            permit2, transferDetails, owner, witness, PERMIT2_REDEEM_DATA_TYPE, signature
        );

        IERC20 redeemToken = IERC20(permit2.permitted.token);
        IERC20 outputToken = IERC20(address(redeemData.outputToken));

        uint256 currentTradeIssuerAllowance =
            redeemToken.allowance(address(this), address(tradeIssuer));
        if (currentTradeIssuerAllowance < redeemData.archTokenAmount) {
            redeemToken.safeIncreaseAllowance(
                address(tradeIssuer), redeemData.archTokenAmount - currentTradeIssuerAllowance
            );
        }

        uint256 outputTokenReceived = tradeIssuer.redeemToToken(
            contractCallInstructions,
            IChamber(redeemData.archToken),
            IIssuerWizard(redeemData.issuer),
            IERC20(redeemData.outputToken),
            redeemData.outputTokenMinAmount,
            redeemData.archTokenAmount
        );

        currentTradeIssuerAllowance = redeemToken.allowance(address(this), address(tradeIssuer));
        redeemToken.safeDecreaseAllowance(address(tradeIssuer), currentTradeIssuerAllowance);

        if (toNative) {
            WETH(payable(address(outputToken))).withdraw(outputTokenReceived);
            payable(owner).sendValue(outputTokenReceived);
        } else {
            outputToken.safeTransfer(owner, outputTokenReceived);
        }

        emit RedeemWithPermit2(
            redeemData.archToken,
            redeemData.archTokenAmount,
            redeemData.outputToken,
            outputTokenReceived
        );
    }

    /**
     * Redeems a Chamber and mints another Chamber using a permit2.
     * The minted amount is transferred to the owner. Using a permit
     * for the redeem chamber token transfer (through Permit2).
     *
     * @param permit2             Permit2 data of the ERC20 token used
     * @param owner               Owner of the tokens to transfer
     * @param signature           Signature of the owner of the tokens
     * @param redeemAndMintData   Data of the chamber redeem and mint to perform
     */
    function redeemAndMintWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        address owner,
        bytes calldata signature,
        RedeemAndMintData calldata redeemAndMintData
    ) external {
        if (permit2.permitted.amount == 0) revert ZeroPermittedAmount();
        if (!isAllowedToken(redeemAndMintData.archTokenToRedeem)) {
            revert InvalidToken(redeemAndMintData.archTokenToRedeem);
        }
        if (!isAllowedToken(redeemAndMintData.archTokenToMint)) {
            revert InvalidToken(redeemAndMintData.archTokenToMint);
        }
        if (permit2.permitted.token != redeemAndMintData.archTokenToRedeem) {
            revert InvalidToken(redeemAndMintData.archTokenToRedeem);
        }
        if (permit2.permitted.amount != redeemAndMintData.redeemAmount) {
            revert InvalidRedeemAmount(permit2.permitted.amount, redeemAndMintData.redeemAmount);
        }

        ISignatureTransfer.SignatureTransferDetails memory transferDetails = ISignatureTransfer
            .SignatureTransferDetails({ to: address(this), requestedAmount: permit2.permitted.amount });

        (
            ITradeIssuerV3.ContractCallInstruction[] memory contractCallInstructions,
            bytes32 concatenatedHashedSwapCallInstructions
        ) = _hashSwapCallInstructionAndConvertToTraderIssuerCallInstruction(
            redeemAndMintData.swapCallInstructions
        );

        bytes32 witness = _calculateRedeemAndMintDataTypeWitness(
            redeemAndMintData, concatenatedHashedSwapCallInstructions
        );

        signatureTransfer.permitWitnessTransferFrom(
            permit2, transferDetails, owner, witness, PERMIT2_REDEEM_AND_MINT_DATA_TYPE, signature
        );

        IERC20 redeemToken = IERC20(permit2.permitted.token);
        IERC20 mintToken = IERC20(redeemAndMintData.archTokenToMint);

        uint256 currentTradeIssuerAllowance =
            redeemToken.allowance(address(this), address(tradeIssuer));
        if (currentTradeIssuerAllowance < redeemAndMintData.redeemAmount) {
            redeemToken.safeIncreaseAllowance(
                address(tradeIssuer), redeemAndMintData.redeemAmount - currentTradeIssuerAllowance
            );
        }

        tradeIssuer.redeemAndMint(
            IChamber(redeemAndMintData.archTokenToRedeem),
            redeemAndMintData.redeemAmount,
            IChamber(redeemAndMintData.archTokenToMint),
            redeemAndMintData.mintAmount,
            IIssuerWizard(redeemAndMintData.issuer),
            contractCallInstructions
        );

        currentTradeIssuerAllowance = redeemToken.allowance(address(this), address(tradeIssuer));
        redeemToken.safeDecreaseAllowance(address(tradeIssuer), currentTradeIssuerAllowance);

        mintToken.safeTransfer(owner, mintToken.balanceOf(address(this)));

        emit RedeemAndMintWithPermit2(
            redeemAndMintData.archTokenToRedeem,
            redeemAndMintData.redeemAmount,
            redeemAndMintData.archTokenToMint,
            redeemAndMintData.mintAmount
        );
    }

    /**
     * Withdraws all the balance of a given ERC20 token to the owner of the contract
     *
     * @param token  Token to withdraw the balance from
     */
    function withdrawTokenBalance(address token) external onlyOwner {
        IERC20 withdrawToken = IERC20(token);
        uint256 balance = withdrawToken.balanceOf(address(this));
        if (balance == 0) revert ZeroTokenBalance(address(token));
        withdrawToken.safeTransfer(owner, balance);
    }

    /*//////////////////////////////////////////////////////////////
                            INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * Performs a low-level call to swapTarget to perform a swap between two tokens
     *
     * @param swapData    Swap data of the trade to perform
     * @param sellToken   ERC20 token to sell
     * @param sellAmount  Amount of sellToken to sell
     * @param owner       Owner of the tokens to transfer
     */
    function _swapAndTransfer(
        SwapData calldata swapData,
        IERC20 sellToken,
        uint256 sellAmount,
        address owner
    ) internal {
        IERC20 buyToken = IERC20(swapData.buyToken);

        uint256 currentAllowance = sellToken.allowance(address(this), swapData.swapAllowanceTarget);
        if (currentAllowance < sellAmount) {
            sellToken.safeIncreaseAllowance(
                swapData.swapAllowanceTarget, (sellAmount - currentAllowance)
            );
        }

        uint256 beforeSwapBuyTokenBalance = buyToken.balanceOf(address(this));

        (bool success,) =
            swapData.swapTarget.call{ value: swapData.nativeTokenAmount }(swapData.swapCallData);
        if (!success) revert SwapCallFailed();

        uint256 buyTokenAmountReceived =
            buyToken.balanceOf(address(this)) - beforeSwapBuyTokenBalance;

        if (buyTokenAmountReceived < swapData.buyAmount) {
            revert Underbought(address(buyToken), swapData.buyAmount);
        }

        currentAllowance = sellToken.allowance(address(this), swapData.swapAllowanceTarget);
        sellToken.safeDecreaseAllowance(swapData.swapAllowanceTarget, currentAllowance);

        bytes memory returnData;

        if (swapData.buyToken == address(WMATIC)) {
            WMATIC.withdraw(buyTokenAmountReceived);
            (success, returnData) = owner.call{ value: (buyTokenAmountReceived) }("");
            if (!success) revert TransferFailed(owner, buyTokenAmountReceived, returnData);
        } else {
            buyToken.safeTransfer(owner, buyTokenAmountReceived);
        }

        emit SwapWithPermit2(
            address(sellToken), sellAmount, address(buyToken), buyTokenAmountReceived
        );
    }

    /**
     * Calculates the EIP-712 bytes32 hash of a swapData struct.
     *
     * @param swapData  IGasworksV2.SwapData
     */
    function _calculateSwapDataTypeWitness(SwapData memory swapData)
        internal
        pure
        returns (bytes32 witness)
    {
        witness = keccak256(
            abi.encode(
                SWAP_DATA_TYPE_HASH,
                swapData.buyToken,
                swapData.buyAmount,
                swapData.nativeTokenAmount,
                swapData.swapTarget,
                swapData.swapAllowanceTarget
            )
        );
    }

    /**
     * Cast IGasworksV2.SwapCallInstructions to ITradeIssuerV3.ContractCallInstructions, and also
     * returns the EIP-712 hashed swapCallInstructions
     *
     * @param swapCallInstructions  Mint or Redeem swap call instructions array
     */
    function _hashSwapCallInstructionAndConvertToTraderIssuerCallInstruction(
        SwapCallInstruction[] memory swapCallInstructions
    )
        internal
        pure
        returns (
            ITradeIssuerV3.ContractCallInstruction[] memory contractCallInstructions,
            bytes32 concatenatedHashedSwapCallInstructions
        )
    {
        bytes32[] memory instructionHashes = new bytes32[](swapCallInstructions.length);
        contractCallInstructions =
            new ITradeIssuerV3.ContractCallInstruction[](swapCallInstructions.length);

        for (uint256 i = 0; i < swapCallInstructions.length;) {
            contractCallInstructions[i] = ITradeIssuerV3.ContractCallInstruction(
                payable(swapCallInstructions[i].swapTarget),
                swapCallInstructions[i].swapAllowanceTarget,
                IERC20(swapCallInstructions[i].sellToken),
                swapCallInstructions[i].sellAmount,
                IERC20(swapCallInstructions[i].buyToken),
                swapCallInstructions[i].minBuyAmount,
                swapCallInstructions[i].swapCallData
            );

            instructionHashes[i] = keccak256(
                abi.encode(
                    SWAP_CALL_INSTRUCTION_TYPE_HASH,
                    swapCallInstructions[i].sellToken,
                    swapCallInstructions[i].sellAmount,
                    swapCallInstructions[i].buyToken,
                    swapCallInstructions[i].minBuyAmount,
                    swapCallInstructions[i].swapTarget,
                    swapCallInstructions[i].swapAllowanceTarget
                )
            );

            unchecked {
                ++i;
            }
        }

        concatenatedHashedSwapCallInstructions = keccak256(abi.encodePacked(instructionHashes));

        return (contractCallInstructions, concatenatedHashedSwapCallInstructions);
    }

    /**
     * Calculate the EIP-712 bytes32 hash of a mintData struct. The swapCallInstructions is passed to avoid
     * a double for loop in the parent function
     *
     * @param mintData                                IGasworksV2.MintData
     * @param concatenatedHashedSwapCallInstructions  Already EIP-712 hashed instructions
     */
    function _calculateMintDataTypeWitness(
        MintData memory mintData,
        bytes32 concatenatedHashedSwapCallInstructions
    ) internal pure returns (bytes32 witness) {
        witness = keccak256(
            abi.encode(
                MINT_DATA_TYPE_HASH,
                mintData.archToken,
                mintData.archTokenAmount,
                mintData.inputToken,
                mintData.inputTokenMaxAmount,
                mintData.issuer,
                concatenatedHashedSwapCallInstructions
            )
        );
        return witness;
    }

    /**
     * Calculate the EIP-712 bytes32 hash of a redeemData struct. The swapCallInstructions is passed to avoid
     * a double for loop in the parent function
     *
     * @param redeemData                              IGasworksV2.RedeemData
     * @param concatenatedHashedSwapCallInstructions  Already EIP-712 hashed instructions
     */
    function _calculateRedeemDataTypeWitness(
        RedeemData memory redeemData,
        bytes32 concatenatedHashedSwapCallInstructions
    ) internal pure returns (bytes32 witness) {
        witness = keccak256(
            abi.encode(
                REDEEM_DATA_TYPE_HASH,
                redeemData.archToken,
                redeemData.archTokenAmount,
                redeemData.outputToken,
                redeemData.outputTokenMinAmount,
                redeemData.issuer,
                concatenatedHashedSwapCallInstructions
            )
        );
        return witness;
    }

    /**
     * Calculate the EIP-712 bytes32 hash of a redeemAndMintData struct. The
     * swapCallInstructions is passed to avoid a double for in the parent function
     *
     * @param redeemAndMintData                       IGasworksV2.RedeemAndMintData
     * @param concatenatedHashedSwapCallInstructions  Already EIP-712 hashed instructions
     */
    function _calculateRedeemAndMintDataTypeWitness(
        RedeemAndMintData memory redeemAndMintData,
        bytes32 concatenatedHashedSwapCallInstructions
    ) internal pure returns (bytes32 witness) {
        witness = keccak256(
            abi.encode(
                REDEEM_AND_MINT_DATA_TYPE_HASH,
                redeemAndMintData.archTokenToRedeem,
                redeemAndMintData.redeemAmount,
                redeemAndMintData.archTokenToMint,
                redeemAndMintData.mintAmount,
                redeemAndMintData.issuer,
                concatenatedHashedSwapCallInstructions
            )
        );
        return witness;
    }
}
