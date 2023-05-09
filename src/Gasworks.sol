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
    "openzeppelin-contracts/contracts/token/ERC20/extensions/draft-IERC20Permit.sol";
import { Owned } from "solmate/src/auth/Owned.sol";
import { IExchangeIssuanceZeroEx } from "./interfaces/IExchangeIssuanceZeroEx.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { ITradeIssuerV2 } from "chambers-peripherals/src/interfaces/ITradeIssuerV2.sol";
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
    ITradeIssuerV2 public immutable tradeIssuer;

    string private constant SWAPDATA_WITNESS_TYPE_STRING =
        "SwapData witness)SwapData(address buyToken,address spender,address payable swapTarget, bytes swapCallData,uint256 swapValue,uint256 buyAmount)TokenPermissions(address token,uint256 amount)";

    string private constant MINT_SET_WITNESS_TYPE_STRING =
        "MintData witness)MintData(ISetToken _setToken,uint256 _amountSetToken,uint256 _maxAmountInputToken, bytes[] _componentQuotes,address _issuanceModule,bool _isDebtIssuance)TokenPermissions(address token,uint256 amount)";

    string private constant REDEEM_SET_WITNESS_TYPE_STRING =
        "RedeemData witness)RedeemData(ISetToken _setToken,IERC20 _outputToken,uint256 _amountSetToken,uint256 _minOutputReceive, bytes[] _componentQuotes,address _issuanceModule,bool _isDebtIssuance)TokenPermissions(address token,uint256 amount)";

    string private constant MINT_CHAMBER_WITNESS_TYPE_STRING =
        "MintChamberData witness)MintChamberData(IChamber _chamber,IIssuerWizard _issuerWizard,IERC20 _baseToken,uint256 _maxPayAmount,uint256 _mintAmount)TokenPermissions(address token,uint256 amount)";

    string private constant REDEEM_CHAMBER_WITNESS_TYPE_STRING =
        "RedeemChamberData witness)RedeemChamberData(IChamber _chamber,IIssuerWizard _issuerWizard,IERC20 _baseToken,uint256 _minReceiveAmount,uint256 _redeemAmount)TokenPermissions(address token,uint256 amount)";

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
        tradeIssuer = ITradeIssuerV2(_tradeIssuer);
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
     * Using a safePermit for the ERC20 token transfer
     *
     * @param permit              Permit data of the ERC20 token used (USDC)
     * @param swapData            Data of the swap to perform
     */
    function swapWithPermit(PermitData calldata permit, SwapData calldata swapData) external {
        if (!tokens[permit._tokenContract]) revert InvalidToken(permit._tokenContract);
        if (!tokens[swapData.buyToken]) revert InvalidToken(swapData.buyToken);

        IERC20Permit permitToken = IERC20Permit(permit._tokenContract);
        permitToken.safePermit(
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
     * Issues an exact amount of SetTokens for given amount of input ERC20 tokens.
     * Using a safePermit for the ERC20 token transfer
     * The excess amount of tokens is returned in an equivalent amount of ether.
     *
     * @param permit              Permit data of the ERC20 token used (USDC)
     * @param mintData            Data of the issuance to perform
     */
    function mintWithPermit(PermitData calldata permit, MintSetData calldata mintData) external {
        if (!tokens[permit._tokenContract]) revert InvalidToken(permit._tokenContract);
        if (!tokens[address(mintData._setToken)]) revert InvalidToken(address(mintData._setToken));

        IERC20Permit permitToken = IERC20Permit(permit._tokenContract);
        permitToken.safePermit(
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

        token.safeApprove(address(exchangeIssuance), mintData._maxAmountInputToken);

        exchangeIssuance.issueExactSetFromToken(
            mintData._setToken,
            IERC20(permit._tokenContract),
            mintData._amountSetToken,
            mintData._maxAmountInputToken,
            mintData._componentQuotes,
            mintData._issuanceModule,
            mintData._isDebtIssuance
        );

        ERC20(address(mintData._setToken)).safeTransfer(permit._owner, mintData._amountSetToken);

        emit MintWithPermit(
            address(mintData._setToken),
            mintData._amountSetToken,
            address(token),
            permit._amount - token.balanceOf(address(this))
        );

        token.safeTransfer(owner, token.balanceOf(address(this)));
    }

    /**
     * Swaps an exact amount of SetTokens in 0x for a given amount of ERC20 tokens.
     * Using a permit for the ERC20 token transfer (through Permit2)
     *
     * @param permit2             Permit2 data of the ERC20 token used
     * @param transferDetails     Details of the transfer to perform
     * @param owner               Owner of the tokens to transfer
     * @param witness             Payload of data we want to validate (encoded in bytes32)
     * @param signature           Signature of the owner of the tokens
     * @param swapData            Data of the swap to perform
     */
    function swapWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        ISignatureTransfer.SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes32 witness,
        bytes calldata signature,
        SwapData calldata swapData
    ) external {
        if (!tokens[permit2.permitted.token]) revert InvalidToken(permit2.permitted.token);
        if (!tokens[swapData.buyToken]) revert InvalidToken(swapData.buyToken);

        signatureTransfer.permitWitnessTransferFrom(
            permit2, transferDetails, owner, witness, SWAPDATA_WITNESS_TYPE_STRING, signature
        );

        _fillQuoteInternal(
            swapData, transferDetails.requestedAmount, owner, ERC20(permit2.permitted.token)
        );
    }

    /**
     * Issues an exact amount of SetTokens for given amount of input ERC20 tokens.
     * Using a permit for the ERC20 token transfer (through Permit2)
     * The excess amount of tokens is returned in an equivalent amount of ether.
     *
     * @param permit2             Permit2 data of the ERC20 token used
     * @param transferDetails     Details of the transfer to perform
     * @param owner               Owner of the tokens to transfer
     * @param witness             Payload of data we want to validate (encoded in bytes32)
     * @param signature           Signature of the owner of the tokens
     * @param mintData            Data of the issuance to perform
     */
    function mintWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        ISignatureTransfer.SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes32 witness,
        bytes calldata signature,
        MintSetData calldata mintData
    ) external {
        if (!tokens[permit2.permitted.token]) revert InvalidToken(permit2.permitted.token);
        if (!tokens[address(mintData._setToken)]) {
            revert InvalidToken(address(mintData._setToken));
        }

        signatureTransfer.permitWitnessTransferFrom(
            permit2, transferDetails, owner, witness, MINT_SET_WITNESS_TYPE_STRING, signature
        );

        ERC20 token = ERC20(permit2.permitted.token);
        uint256 balanceBefore = token.balanceOf(address(this));

        token.safeApprove(address(exchangeIssuance), mintData._maxAmountInputToken);

        exchangeIssuance.issueExactSetFromToken(
            mintData._setToken,
            IERC20(permit2.permitted.token),
            mintData._amountSetToken,
            mintData._maxAmountInputToken,
            mintData._componentQuotes,
            mintData._issuanceModule,
            mintData._isDebtIssuance
        );

        uint256 amountPaid = balanceBefore - token.balanceOf(address(this));

        ERC20(address(mintData._setToken)).safeTransfer(owner, mintData._amountSetToken);
        token.safeTransfer(owner, token.balanceOf(address(this)));

        emit MintWithPermit2(
            address(mintData._setToken), mintData._amountSetToken, address(token), amountPaid
        );
    }

    /**
     * Redeems an exact amount of SetTokens to a given amount of output ERC20 tokens.
     * Using a permit for the SetToken (through Permit2)
     *
     * @param permit2             Permit2 data of the ERC20 token used
     * @param transferDetails     Details of the transfer to perform
     * @param owner               Owner of the tokens to transfer
     * @param witness             Payload of data we want to validate (encoded in bytes32)
     * @param signature           Signature of the owner of the tokens
     * @param redeemData          Data of the redemption to perform
     */
    function redeemWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        ISignatureTransfer.SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes32 witness,
        bytes calldata signature,
        RedeemSetData calldata redeemData,
        bool toNative
    ) external {
        if (!tokens[address(redeemData._setToken)]) {
            revert InvalidToken(address(redeemData._setToken));
        }
        if (!tokens[address(redeemData._outputToken)]) {
            revert InvalidToken(address(redeemData._outputToken));
        }

        ERC20 outputToken = ERC20(address(redeemData._outputToken));

        signatureTransfer.permitWitnessTransferFrom(
            permit2, transferDetails, owner, witness, REDEEM_SET_WITNESS_TYPE_STRING, signature
        );

        redeemData._setToken.approve(address(exchangeIssuance), redeemData._amountSetToken);

        exchangeIssuance.redeemExactSetForToken(
            redeemData._setToken,
            redeemData._outputToken,
            redeemData._amountSetToken,
            redeemData._minOutputReceive,
            redeemData._componentQuotes,
            redeemData._issuanceModule,
            redeemData._isDebtIssuance
        );

        uint256 outputTokenBalance = outputToken.balanceOf(address(this));
        if (toNative) {
            WETH(payable(address(outputToken))).withdraw(outputTokenBalance);
            payable(owner).sendValue(outputTokenBalance);
        } else {
            outputToken.safeTransfer(owner, outputToken.balanceOf(address(this)));
        }
        ERC20(address(redeemData._setToken)).safeTransfer(
            owner, redeemData._setToken.balanceOf(address(this))
        );

        emit RedeemWithPermit2(
            address(redeemData._setToken),
            redeemData._amountSetToken,
            address(outputToken),
            outputTokenBalance
        );
    }

    /**
     * Mints an exact amount of Chamber from a given amount of input ERC20 tokens.
     * Using a permit for the ERC20 token (through Permit2)
     *
     * @param permit2                       Permit2 data of the ERC20 token used
     * @param transferDetails               Details of the transfer to perform
     * @param owner                         Owner of the tokens to transfer
     * @param witness                       Payload of data we want to validate (encoded in bytes32)
     * @param signature                     Signature of the owner of the tokens
     * @param mintChamberData               Data of the chamber issuance to perform
     * @param contractCallInstructions      Calls required to get all chamber components
     */
    function mintChamberWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        ISignatureTransfer.SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes32 witness,
        bytes calldata signature,
        MintChamberData calldata mintChamberData,
        ITradeIssuerV2.ContractCallInstruction[] memory contractCallInstructions
    ) external {
        if (!tokens[permit2.permitted.token]) revert InvalidToken(permit2.permitted.token);
        if (!tokens[address(mintChamberData._chamber)]) {
            revert InvalidToken(address(mintChamberData._chamber));
        }

        signatureTransfer.permitWitnessTransferFrom(
            permit2, transferDetails, owner, witness, MINT_CHAMBER_WITNESS_TYPE_STRING, signature
        );

        ERC20 token = ERC20(permit2.permitted.token);
        uint256 beforeBalance = token.balanceOf(address(this));

        token.safeApprove(address(tradeIssuer), mintChamberData._maxPayAmount);

        tradeIssuer.mintChamberFromToken(
            contractCallInstructions,
            mintChamberData._chamber,
            mintChamberData._issuerWizard,
            mintChamberData._baseToken,
            mintChamberData._maxPayAmount,
            mintChamberData._mintAmount
        );

        uint256 totalPaid = beforeBalance - token.balanceOf(address(this));

        ERC20(address(mintChamberData._chamber)).safeTransfer(owner, mintChamberData._mintAmount);
        token.safeTransfer(owner, token.balanceOf(address(this)));

        emit MintWithPermit2(
            address(mintChamberData._chamber),
            mintChamberData._mintAmount,
            address(token),
            totalPaid
        );
    }

    /**
     * Redeems an exact amount of Chamber to a given amount of ERC20 tokens.
     * Using a permit for the Chamber token (through Permit2)
     *
     * @param permit2                       Permit2 data of the ERC20 token used
     * @param transferDetails               Details of the transfer to perform
     * @param owner                         Owner of the tokens to transfer
     * @param witness                       Payload of data we want to validate (encoded in bytes32)
     * @param signature                     Signature of the owner of the tokens
     * @param redeemChamberData             Data of the chamber redeem to perform
     * @param contractCallInstructions      Calls required to get all chamber components
     */
    function redeemChamberWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        ISignatureTransfer.SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes32 witness,
        bytes calldata signature,
        RedeemChamberData calldata redeemChamberData,
        ITradeIssuerV2.ContractCallInstruction[] memory contractCallInstructions,
        bool toNative
    ) external {
        if (!tokens[permit2.permitted.token]) revert InvalidToken(permit2.permitted.token);
        if (!tokens[address(redeemChamberData._baseToken)]) {
            revert InvalidToken(address(redeemChamberData._baseToken));
        }

        signatureTransfer.permitWitnessTransferFrom(
            permit2, transferDetails, owner, witness, REDEEM_CHAMBER_WITNESS_TYPE_STRING, signature
        );

        ERC20 token = ERC20(permit2.permitted.token);

        token.safeApprove(address(tradeIssuer), redeemChamberData._redeemAmount);

        tradeIssuer.redeemChamberToToken(
            contractCallInstructions,
            redeemChamberData._chamber,
            redeemChamberData._issuerWizard,
            redeemChamberData._baseToken,
            redeemChamberData._minReceiveAmount,
            redeemChamberData._redeemAmount
        );
        ERC20 baseToken = ERC20(address(redeemChamberData._baseToken));
        uint256 baseTokenBalance = baseToken.balanceOf(address(this));
        if (toNative) {
            WETH(payable(address(baseToken))).withdraw(baseTokenBalance);
            payable(owner).sendValue(baseTokenBalance);
        } else {
            baseToken.safeTransfer(owner, baseToken.balanceOf(address(this)));
        }

        emit RedeemWithPermit2(
            address(redeemChamberData._chamber),
            redeemChamberData._redeemAmount,
            address(baseToken),
            baseTokenBalance
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
        ERC20 buyToken = ERC20(swap.buyToken);
        uint256 beforeBalance = buyToken.balanceOf(address(this));

        sellToken.safeApprove(swap.spender, type(uint256).max);

        (bool success,) = swap.swapTarget.call{ value: swap.swapValue }(swap.swapCallData);
        if (!success) revert SwapCallFailed();

        uint256 swapBalance = buyToken.balanceOf(address(this)) - beforeBalance;

        if (swapBalance < swap.buyAmount) {
            revert Underbought(address(buyToken), swap.buyAmount);
        }

        if (swap.buyToken == address(WMATIC)) {
            WMATIC.withdraw(swapBalance);
            (success,) = owner.call{ value: (swapBalance) }("");
            require(success, "TRANSFER_FAILED");
        } else {
            buyToken.safeTransfer(owner, swapBalance);
        }

        emit SwapWithPermit(swap.buyToken, swap.buyAmount, address(sellToken), sellAmount);
    }
}
