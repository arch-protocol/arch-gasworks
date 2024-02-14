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

import { ERC2771Recipient } from "gsn/ERC2771Recipient.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { ISetToken } from "./interfaces/ISetToken.sol";
import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";
import { SafeERC20 } from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import { IERC20Permit } from
    "openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol";
import { Owned } from "solmate/src/auth/Owned.sol";
import { IExchangeIssuanceZeroEx } from "./interfaces/IExchangeIssuanceZeroEx.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { ITradeIssuerV3 } from "chambers-peripherals/src/interfaces/ITradeIssuerV3.sol";
import { IChamber } from "chambers/interfaces/IChamber.sol";
import { IIssuerWizard } from "chambers/interfaces/IIssuerWizard.sol";
import { WETH } from "solmate/src/tokens/WETH.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";
import { IGasworks } from "./interfaces/IGasworks.sol";

contract Gasworks is IGasworks, ERC2771Recipient, Owned {
    /*//////////////////////////////////////////////////////////////
                              LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using SafeTransferLib for ERC20;
    using SafeTransferLib for ISetToken;
    using Address for address payable;
    using SafeERC20 for IERC20Permit;

    /*//////////////////////////////////////////////////////////////
                                  STORAGE
    //////////////////////////////////////////////////////////////*/

    IExchangeIssuanceZeroEx public immutable exchangeIssuance;
    ISignatureTransfer public immutable signatureTransfer;
    ITradeIssuerV3 public immutable tradeIssuer;

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
    ///

    WETH public constant WMATIC = WETH(payable(0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270));

    mapping(address => bool) public tokens;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _forwarder, address _exchangeIssuance, address _tradeIssuer)
        Owned(_msgSender())
    {
        _setTrustedForwarder(_forwarder);
        exchangeIssuance = IExchangeIssuanceZeroEx(payable(_exchangeIssuance));
        signatureTransfer = ISignatureTransfer(0x000000000022D473030F116dDEE9F6B43aC78BA3);
        tradeIssuer = ITradeIssuerV3(_tradeIssuer);
    }

    /*//////////////////////////////////////////////////////////////
                            EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    receive() external payable { }

    function setTrustedForwarder(address forwarder) external onlyOwner {
        _setTrustedForwarder(forwarder);
    }

    function setTokens(address token) external onlyOwner {
        tokens[token] = true;
    }

    /**
     * Swaps an exact amount of SetTokens in 0x for a given amount of ERC20 tokens.
     * Using a permit for the ERC20 token transfer
     *
     * @param permit              Permit data of the ERC20 token used (USDC)
     * @param swapData            Data of the swap to perform
     */
    function swapWithPermit1(PermitData calldata permit, SwapData calldata swapData) external {
        if (!tokens[permit._tokenContract]) revert InvalidToken(permit._tokenContract);
        if (!tokens[swapData.buyToken]) revert InvalidToken(swapData.buyToken);

        IERC20Permit permitToken = IERC20Permit(permit._tokenContract);
        permitToken.permit(
            permit._owner,
            permit._spender,
            permit._value,
            permit._deadline,
            permit._v,
            permit._r,
            permit._s
        );

        ERC20 token = ERC20(permit._tokenContract);
        token.safeTransferFrom(permit._owner, address(this), permit._amount);

        _fillQuoteInternal(swapData, permit._amount, permit._owner, ERC20(permit._tokenContract));
    }

    /**
     * Issues an exact amount of Chamber tokens for given amount of input ERC20 tokens.
     * Using a permit for the ERC20 token transfer
     * The excess amount of tokens is returned
     *
     * @param permit                        Permit data of the ERC20 token used (USDC)
     * @param mintChamberData               Data of the issuance to perform
     * @param contractCallInstructions      Calls required to get all chamber components
     */
    function mintWithPermit1(
        PermitData calldata permit,
        MintChamberData calldata mintChamberData,
        ITradeIssuerV3.ContractCallInstruction[] memory contractCallInstructions
    ) external {
        if (!tokens[permit._tokenContract]) revert InvalidToken(permit._tokenContract);
        if (!tokens[address(mintChamberData._chamber)]) {
            revert InvalidToken(address(mintChamberData._chamber));
        }

        IERC20Permit permitToken = IERC20Permit(permit._tokenContract);
        permitToken.permit(
            permit._owner,
            permit._spender,
            permit._value,
            permit._deadline,
            permit._v,
            permit._r,
            permit._s
        );

        ERC20 token = ERC20(permit._tokenContract);
        token.safeTransferFrom(permit._owner, address(this), permit._amount);
        uint256 beforeBalance = token.balanceOf(address(this));
        token.safeApprove(address(tradeIssuer), mintChamberData._maxPayAmount);

        tradeIssuer.mintFromToken(
            contractCallInstructions,
            mintChamberData._chamber,
            mintChamberData._issuerWizard,
            mintChamberData._baseToken,
            mintChamberData._maxPayAmount,
            mintChamberData._mintAmount
        );

        uint256 totalPaid = beforeBalance - token.balanceOf(address(this));

        ERC20(address(mintChamberData._chamber)).safeTransfer(
            permit._owner, mintChamberData._mintAmount
        );
        token.safeTransfer(permit._owner, token.balanceOf(address(this)));

        emit MintWithPermit1(
            address(mintChamberData._chamber),
            mintChamberData._mintAmount,
            address(token),
            totalPaid
        );
    }

    /**
     * Swaps an exact amount of SetTokens in 0x for a given amount of ERC20 tokens.
     * Using a permit for the ERC20 token transfer (through Permit2)
     *
     * @param permit2             Permit2 data of the ERC20 token used
     * @param owner               Owner of the tokens to transfer
     * @param signature           Signature of the owner of the tokens
     * @param swapData            Data of the swap to perform
     */
    function swapWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        address owner,
        bytes calldata signature,
        SwapData calldata swapData
    ) external {
        if (!tokens[permit2.permitted.token]) revert InvalidToken(permit2.permitted.token);
        if (!tokens[swapData.buyToken]) revert InvalidToken(swapData.buyToken);

        ISignatureTransfer.SignatureTransferDetails memory transferDetails = ISignatureTransfer
            .SignatureTransferDetails({ to: address(this), requestedAmount: permit2.permitted.amount });

        bytes32 witness = _calculateSwapDataTypeWitness(swapData);

        signatureTransfer.permitWitnessTransferFrom(
            permit2, transferDetails, owner, witness, PERMIT2_SWAP_DATA_TYPE, signature
        );

        _fillQuoteInternal(
            swapData, transferDetails.requestedAmount, owner, ERC20(permit2.permitted.token)
        );
    }

    /**
     * Mints an exact amount of Chamber from a given amount of input ERC20 tokens.
     * Using a permit for the ERC20 token (through Permit2)
     *
     * @param permit2                       Permit2 data of the ERC20 token used
     * @param owner                         Owner of the tokens to transfer
     * @param signature                     Signature of the owner of the tokens
     * @param mintData               Data of the chamber issuance to perform
     */
    function mintWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        address owner,
        bytes calldata signature,
        MintData calldata mintData
    ) external {
        if (!tokens[permit2.permitted.token]) revert InvalidToken(permit2.permitted.token);
        if (!tokens[address(mintData.archToken)]) {
            revert InvalidToken(address(mintData.archToken));
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

        ERC20 token = ERC20(permit2.permitted.token);
        uint256 beforeBalance = token.balanceOf(address(this));

        token.safeApprove(address(tradeIssuer), mintData.inputTokenMaxAmount);

        tradeIssuer.mintFromToken(
            contractCallInstructions,
            IChamber(mintData.archToken),
            IIssuerWizard(mintData.issuer),
            IERC20(mintData.inputToken),
            mintData.inputTokenMaxAmount,
            mintData.archTokenAmount
        );

        uint256 totalPaid = beforeBalance - token.balanceOf(address(this));

        ERC20(mintData.archToken).safeTransfer(owner, mintData.archTokenAmount);
        token.safeTransfer(owner, token.balanceOf(address(this)));

        emit MintWithPermit2(
            mintData.archToken, mintData.archTokenAmount, permit2.permitted.token, totalPaid
        );
    }

    /**
     * Redeems an exact amount of Chamber to a given amount of ERC20 tokens.
     * Using a permit for the Chamber token (through Permit2)
     *
     * @param permit2                       Permit2 data of the ERC20 token used
     * @param owner                         Owner of the tokens to transfer
     * @param signature                     Signature of the owner of the tokens
     * @param redeemData                    Data of the chamber redeem to perform
     * @param toNative                      True if output is native token
     */
    function redeemWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        address owner,
        bytes calldata signature,
        RedeemData calldata redeemData,
        bool toNative
    ) external {
        if (!tokens[permit2.permitted.token]) revert InvalidToken(permit2.permitted.token);
        if (!tokens[address(redeemData.outputToken)]) {
            revert InvalidToken(address(redeemData.outputToken));
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

        ERC20 token = ERC20(permit2.permitted.token);

        token.safeApprove(address(tradeIssuer), redeemData.archTokenAmount);

        tradeIssuer.redeemToToken(
            contractCallInstructions,
            IChamber(redeemData.archToken),
            IIssuerWizard(redeemData.issuer),
            IERC20(redeemData.outputToken),
            redeemData.outputTokenMinAmount,
            redeemData.archTokenAmount
        );
        ERC20 outputToken = ERC20(address(redeemData.outputToken));
        uint256 outputTokenBalance = outputToken.balanceOf(address(this));
        if (toNative) {
            WETH(payable(address(outputToken))).withdraw(outputTokenBalance);
            payable(owner).sendValue(outputTokenBalance);
        } else {
            outputToken.safeTransfer(owner, outputToken.balanceOf(address(this)));
        }

        emit RedeemWithPermit2(
            address(redeemData.archToken),
            redeemData.archTokenAmount,
            address(outputToken),
            outputTokenBalance
        );
    }

    /**
     * Withdraws all the balance of a given ERC20 token to the owner of the contract
     *
     * @param token              Swap data of the trade to perform
     */
    function withdrawTokenBalance(ERC20 token) external onlyOwner {
        uint256 balance = token.balanceOf(address(this));
        if (balance == 0) revert ZeroBalance(address(token));
        token.safeTransfer(owner, balance);
    }

    /*//////////////////////////////////////////////////////////////
                            INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * Performs a low-level call to swapTarget to perform a swap between two tokens
     *
     * @param swap              Swap data of the trade to perform
     * @param sellAmount        Amount of sellToken to sell
     * @param owner             Owner of the tokens to transfer
     * @param sellToken         ERC20 token to sell
     */
    function _fillQuoteInternal(
        SwapData calldata swap,
        uint256 sellAmount,
        address owner,
        ERC20 sellToken
    ) internal {
        bytes memory returnData;
        ERC20 buyToken = ERC20(swap.buyToken);
        uint256 beforeBalance = buyToken.balanceOf(address(this));

        sellToken.safeApprove(swap.swapAllowanceTarget, type(uint256).max);

        (bool success,) = swap.swapTarget.call{ value: swap.nativeTokenAmount }(swap.swapCallData);
        if (!success) revert SwapCallFailed();

        uint256 swapBalance = buyToken.balanceOf(address(this)) - beforeBalance;

        if (swapBalance < swap.buyAmount) {
            revert Underbought(address(buyToken), swap.buyAmount);
        }

        if (swap.buyToken == address(WMATIC)) {
            WMATIC.withdraw(swapBalance);
            (success, returnData) = owner.call{ value: (swapBalance) }("");
            if (!success) revert TransferFailed(owner, swapBalance, returnData);
        } else {
            buyToken.safeTransfer(owner, swapBalance);
        }

        emit SwapWithPermit(swap.buyToken, swap.buyAmount, address(sellToken), sellAmount);
    }

    /**
     * Calculate the EIP-712 bytes32 hash of a swapDAta struct.
     *
     * @param swapData  IGasworks.SwapData
     */
    function _calculateSwapDataTypeWitness(IGasworks.SwapData memory swapData)
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
     * Cast IGasworks.SwapCallInstruction to ITradeIssuerV3.Contract call instruction, and also
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
     * a double for in the parent function
     *
     * @param mintData                                IGasworks.MintData
     * @param concatenatedHashedSwapCallInstructions  Already EIP-712 hashed instructions
     */
    function _calculateMintDataTypeWitness(
        IGasworks.MintData memory mintData,
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
     * a double for in the parent function
     *
     * @param redeemData                              IGasworks.RedeemData
     * @param concatenatedHashedSwapCallInstructions  Already EIP-712 hashed instructions
     */
    function _calculateRedeemDataTypeWitness(
        IGasworks.RedeemData memory redeemData,
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
}
