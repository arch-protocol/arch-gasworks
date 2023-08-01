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

    bytes private constant TOKEN_PERMISSIONS_TYPE = "TokenPermissions(address token,uint256 amount)";

    bytes private constant SWAP_DATA_TYPE = "SwapData(address buyToken,address spender,address swapTarget,bytes swapCallData,uint256 swapValue,uint256 buyAmount)";
    string internal constant PERMIT2_SWAP_DATA_TYPE = string(abi.encodePacked("SwapData witness)", SWAP_DATA_TYPE, TOKEN_PERMISSIONS_TYPE));

    bytes private constant CONTRACT_CALL_INSTRUCTION_TYPE = "ContractCallInstruction(address contractTarget, address allowanceTarget, address sellToken, address sellAmount, address buyToken, uint256 minBuyAmount, bytes callData)";
    bytes private constant MINT_CHAMBER_DATA_TYPE = "MintChamberData(address chamber,uint256 chamberAmount,address inputToken,uint256 inputTokenMaxAmount,address issuerWizard,ContractCallInstruction[] tradeIssuerCallInstructions)";
    string internal constant PERMIT2_MINT_CHAMBER_DATA_TYPE = string(abi.encodePacked("MintChamberData witness)", MINT_CHAMBER_DATA_TYPE, CONTRACT_CALL_INSTRUCTION_TYPE, TOKEN_PERMISSIONS_TYPE));
    ///
    
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

    // /**
    //  * Issues an exact amount of Chamber tokens for given amount of input ERC20 tokens.
    //  * Using a safePermit for the ERC20 token transfer
    //  * The excess amount of tokens is returned
    //  *
    //  * @param permit                        Permit data of the ERC20 token used (USDC)
    //  * @param mintChamberData               Data of the issuance to perform
    //  * @param contractCallInstructions      Calls required to get all chamber components
    //  */
    // function mintChamberWithPermit(
    //     PermitData calldata permit,
    //     MintChamberData calldata mintChamberData,
    //     ITradeIssuerV2.ContractCallInstruction[] memory contractCallInstructions
    // ) external {
    //     if (!tokens[permit._tokenContract]) revert InvalidToken(permit._tokenContract);
    //     if (!tokens[address(mintChamberData._chamber)]) {
    //         revert InvalidToken(address(mintChamberData._chamber));
    //     }

    //     IERC20Permit permitToken = IERC20Permit(permit._tokenContract);
    //     permitToken.safePermit(
    //         permit._owner,
    //         permit._spender,
    //         permit._value,
    //         permit._deadline,
    //         permit._v,
    //         permit._r,
    //         permit._s
    //     );

    //     ERC20 token = ERC20(permit._tokenContract);
    //     token.safeTransferFrom(permit._owner, address(this), permit._amount);
    //     uint256 beforeBalance = token.balanceOf(address(this));
    //     token.safeApprove(address(tradeIssuer), mintChamberData._maxPayAmount);

    //     tradeIssuer.mintChamberFromToken(
    //         contractCallInstructions,
    //         mintChamberData._chamber,
    //         mintChamberData._issuerWizard,
    //         mintChamberData._baseToken,
    //         mintChamberData._maxPayAmount,
    //         mintChamberData._mintAmount
    //     );

    //     uint256 totalPaid = beforeBalance - token.balanceOf(address(this));

    //     ERC20(address(mintChamberData._chamber)).safeTransfer(
    //         permit._owner, mintChamberData._mintAmount
    //     );
    //     token.safeTransfer(permit._owner, token.balanceOf(address(this)));

    //     emit MintWithPermit(
    //         address(mintChamberData._chamber),
    //         mintChamberData._mintAmount,
    //         address(token),
    //         totalPaid
    //     );
    // }

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

        bytes32 witness = keccak256(abi.encode(
          keccak256(abi.encodePacked(SWAP_DATA_TYPE)),
          swapData.buyToken,
          swapData.spender,
          swapData.swapTarget,
          keccak256(swapData.swapCallData),
          swapData.swapValue,
          swapData.buyAmount
        ));

        signatureTransfer.permitWitnessTransferFrom(
          permit2,
          transferDetails,
          owner,
          witness,
          PERMIT2_SWAP_DATA_TYPE,
          signature);

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
     * @param mintChamberData               Data of the chamber issuance to perform
     */
    function mintChamberWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        address owner,
        bytes calldata signature,
        MintChamberData calldata mintChamberData
    ) external {
        if (!tokens[permit2.permitted.token]) revert InvalidToken(permit2.permitted.token);
        if (!tokens[address(mintChamberData.chamber)]) {
            revert InvalidToken(address(mintChamberData.chamber));
        }

        ISignatureTransfer.SignatureTransferDetails memory transferDetails = ISignatureTransfer
            .SignatureTransferDetails({ to: address(this), requestedAmount: permit2.permitted.amount });
        
        ITradeIssuerV2.ContractCallInstruction[] memory contractCallInstructions = new ITradeIssuerV2.ContractCallInstruction[](mintChamberData.tradeIssuerCallInstructions.length);
        bytes memory concatenatedHashedTradeIssuerCallInstructions;
        for (uint256 i = 0; i < mintChamberData.tradeIssuerCallInstructions.length;) {
          contractCallInstructions[i] = ITradeIssuerV2.ContractCallInstruction(
            payable(mintChamberData.tradeIssuerCallInstructions[i].contractTarget),
            mintChamberData.tradeIssuerCallInstructions[i].allowanceTarget,
            IERC20(mintChamberData.tradeIssuerCallInstructions[i].sellToken),
            mintChamberData.tradeIssuerCallInstructions[i].sellAmount,
            IERC20(mintChamberData.tradeIssuerCallInstructions[i].buyToken),
            mintChamberData.tradeIssuerCallInstructions[i].minBuyAmount,
            mintChamberData.tradeIssuerCallInstructions[i].callData
          );
          
          bytes32 hashedTradeIssuerCallInstruction = keccak256(abi.encode(
            keccak256(abi.encodePacked(CONTRACT_CALL_INSTRUCTION_TYPE)),
            mintChamberData.tradeIssuerCallInstructions[i].contractTarget,
            mintChamberData.tradeIssuerCallInstructions[i].allowanceTarget,
            mintChamberData.tradeIssuerCallInstructions[i].sellToken,
            mintChamberData.tradeIssuerCallInstructions[i].sellAmount,
            mintChamberData.tradeIssuerCallInstructions[i].buyToken,
            mintChamberData.tradeIssuerCallInstructions[i].minBuyAmount,
            keccak256(mintChamberData.tradeIssuerCallInstructions[i].callData)
          ));

          concatenatedHashedTradeIssuerCallInstructions = bytes.concat(concatenatedHashedTradeIssuerCallInstructions, hashedTradeIssuerCallInstruction);
          unchecked {
            ++i;
          }
        }

        bytes32 witness = keccak256(abi.encode(
          keccak256(abi.encodePacked(MINT_CHAMBER_DATA_TYPE)),
          mintChamberData.chamber,
          mintChamberData.chamberAmount,
          mintChamberData.inputToken,
          mintChamberData.inputTokenMaxAmount,
          mintChamberData.issuerWizard,
          keccak256(concatenatedHashedTradeIssuerCallInstructions)
        ));


        signatureTransfer.permitWitnessTransferFrom(
          permit2,
          transferDetails,
          owner,
          witness,
          PERMIT2_MINT_CHAMBER_DATA_TYPE,
          signature
        );

        ERC20 token = ERC20(permit2.permitted.token);
        uint256 beforeBalance = token.balanceOf(address(this));

        token.safeApprove(address(tradeIssuer), mintChamberData.inputTokenMaxAmount);

        tradeIssuer.mintChamberFromToken(
            contractCallInstructions,
            IChamber(mintChamberData.chamber),
            IIssuerWizard(mintChamberData.issuerWizard),
            IERC20(mintChamberData.inputToken),
            mintChamberData.inputTokenMaxAmount,
            mintChamberData.chamberAmount
        );

        uint256 totalPaid = beforeBalance - token.balanceOf(address(this));

        ERC20(mintChamberData.chamber).safeTransfer(owner, mintChamberData.chamberAmount);
        token.safeTransfer(owner, token.balanceOf(address(this)));

        emit MintWithPermit2(
            mintChamberData.chamber,
            mintChamberData.chamberAmount,
            permit2.permitted.token,
            totalPaid
        );
    }

    /**
     * Redeems an exact amount of Chamber to a given amount of ERC20 tokens.
     * Using a permit for the Chamber token (through Permit2)
     *
     * @param permit2                       Permit2 data of the ERC20 token used
     * @param owner                         Owner of the tokens to transfer
     * @param signature                     Signature of the owner of the tokens
     * @param redeemChamberData             Data of the chamber redeem to perform
     * @param contractCallInstructions      Calls required to get all chamber components
     */
    function redeemChamberWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit2,
        address owner,
        bytes calldata signature,
        RedeemChamberData calldata redeemChamberData,
        ITradeIssuerV2.ContractCallInstruction[] memory contractCallInstructions,
        bool toNative
    ) external {
        if (!tokens[permit2.permitted.token]) revert InvalidToken(permit2.permitted.token);
        if (!tokens[address(redeemChamberData._baseToken)]) {
            revert InvalidToken(address(redeemChamberData._baseToken));
        }

        ISignatureTransfer.SignatureTransferDetails memory transferDetails = ISignatureTransfer
            .SignatureTransferDetails({ to: address(this), requestedAmount: permit2.permitted.amount });

        signatureTransfer.permitTransferFrom(permit2, transferDetails, owner, signature);

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
        bytes memory returnData;
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
            (success, returnData) = owner.call{ value: (swapBalance) }("");
            if (!success) revert TransferFailed(owner, swapBalance, returnData);
        } else {
            buyToken.safeTransfer(owner, swapBalance);
        }

        emit SwapWithPermit(swap.buyToken, swap.buyAmount, address(sellToken), sellAmount);
    }
}
