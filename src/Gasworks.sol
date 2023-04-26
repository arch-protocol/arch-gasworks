// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.17.0;

import {ERC2771Recipient} from "gsn/ERC2771Recipient.sol";
import {ERC20} from "solmate/src/tokens/ERC20.sol";
import {ISetToken} from "./interfaces/ISetToken.sol";
import {SafeTransferLib} from "solmate/src/utils/SafeTransferLib.sol";
import {Owned} from "solmate/src/auth/Owned.sol";
import {IExchangeIssuanceZeroEx} from "./interfaces/IExchangeIssuanceZeroEx.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {ITradeIssuerV2} from "chambers-peripherals/src/interfaces/ITradeIssuerV2.sol";
import {IChamber} from "chambers/interfaces/IChamber.sol";
import {IIssuerWizard} from "chambers/interfaces/IIssuerWizard.sol";

contract Gasworks is ERC2771Recipient, Owned {
    using SafeTransferLib for ERC20;
    using SafeTransferLib for IERC20;
    using SafeTransferLib for ISetToken;

    IExchangeIssuanceZeroEx private immutable exchangeIssuance;
    ISignatureTransfer public immutable signatureTransfer;
    ITradeIssuerV2 private immutable tradeIssuer;

    string private constant SWAPDATA_WITNESS_TYPE_STRING =
        "SwapData witness)SwapData(address buyToken,address spender,address payable swapTarget, bytes swapCallData,uint256 swapValue,uint256 buyAmount)TokenPermissions(address token,uint256 amount)";

    string private constant MINTDATA_WITNESS_TYPE_STRING =
        "MintData witness)MintData(ISetToken _setToken,uint256 _amountSetToken,uint256 _maxAmountInputToken, bytes[] _componentQuotes,address _issuanceModule,bool _isDebtIssuance)TokenPermissions(address token,uint256 amount)";

    string private constant REDEEMDATA_WITNESS_TYPE_STRING =
        "RedeemData witness)RedeemData(ISetToken _setToken,IERC20 _outputToken,uint256 _amountSetToken,uint256 _minOutputReceive, bytes[] _componentQuotes,address _issuanceModule,bool _isDebtIssuance)TokenPermissions(address token,uint256 amount)";

    string private constant MINT_CHAMBER_WITNESS_TYPE_STRING =
        "MintChamberData witness)MintChamberData(ContractCallInstruction[] _contractCallInstructions,IChamber _chamber,IIssuerWizard _issuerWizard,IERC20 _baseToken,uint256 _maxPayAmount,uint256 _mintAmount)ContractCallInstruction(address _target,address _allowanceTarget,IERC20 _sellToken,uint256 _sellAmount,IERC20 _buyToken,uint256 _minBuyAmount,bytes _calldata)TokenPermissions(address token,uint256 amount)";

    event Received(address sender, address tokenContract, uint256 amount, address messageSender);
    event Swap(address buyToken, uint256 buyAmount, address sellToken, uint256 sellAmount);
    event Sent(address receiver, address tokenContract, uint256 amount);

    mapping(address => bool) public tokens;

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

    struct SwapData {
        // The `buyTokenAddress` field from the API response.
        address buyToken;
        // The `allowanceTarget` field from the API response.
        address spender;
        // The `to` field from the API response.
        address payable swapTarget;
        // The `data` field from the API response.
        bytes swapCallData;
        // The `value` field from the API response.
        uint256 swapValue;
        // The `buyAmount` field from the API response.
        uint256 buyAmount;
    }

    struct MintData {
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
        // The encoded transactions to execute
        ITradeIssuerV2.ContractCallInstruction[] _contractCallInstructions;
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

    struct RedeemData {
        // Address of the SetToken to be redeemed
        ISetToken _setToken;
        // Address of the token to buy with the SetToken
        IERC20 _outputToken;
        // Amount of SetTokens to issue
        uint256 _amountSetToken;
        // Minimum amount of output tokens to receive
        uint256 _minOutputReceive;
        // The encoded 0x transactions to execute
        bytes[] _componentQuotes;
        // The address of the issuance module for the SetToken
        address _issuanceModule;
        // Is the SetToken using debt issuance?
        bool _isDebtIssuance;
    }

    constructor(address _forwarder) Owned(_msgSender()) {
        _setTrustedForwarder(_forwarder);
        exchangeIssuance = IExchangeIssuanceZeroEx(payable(0x1c0c05a2aA31692e5dc9511b04F651db9E4d8320));
        signatureTransfer = ISignatureTransfer(0x000000000022D473030F116dDEE9F6B43aC78BA3);
        tradeIssuer = ITradeIssuerV2(0xbbCA2AcBd87Ce7A5e01fb56914d41F6a7e5C5A56);
    }

    function setTrustedForwarder(address _forwarder) external onlyOwner {
        _setTrustedForwarder(_forwarder);
    }

    function setTokens(address _token) external onlyOwner {
        tokens[_token] = true;
    }

    function isPermitted(address _token) public view returns (bool) {
        return tokens[_token];
    }

    /**
     * Swaps an exact amount of SetTokens in 0x for a given amount of ERC20 tokens.
     * Using a safePermit for the ERC20 token transfer
     *
     * @param permit              Permit data of the ERC20 token used (USDC)
     * @param swapData            Data of the swap to perform
     */
    function swapWithPermit(PermitData calldata permit, SwapData calldata swapData) external {
        require(isPermitted(permit._tokenContract), "INVALID_SELL_TOKEN");
        require(isPermitted(swapData.buyToken), "INVALID_BUY_TOKEN");

        ERC20 token = ERC20(permit._tokenContract);
        safePermit(token, permit);

        token.safeTransferFrom(permit._owner, address(this), permit._amount);

        emit Received(permit._owner, permit._tokenContract, permit._amount, msg.sender);

        _fillQuoteInternal(swapData, permit._amount, permit._owner, permit._tokenContract);
    }

    /**
     * Issues an exact amount of SetTokens for given amount of input ERC20 tokens.
     * Using a safePermit for the ERC20 token transfer
     * The excess amount of tokens is returned in an equivalent amount of ether.
     *
     * @param permit              Permit data of the ERC20 token used (USDC)
     * @param mintData            Data of the issuance to perform
     */
    function mintWithPermit(PermitData calldata permit, MintData calldata mintData) external {
        require(isPermitted(permit._tokenContract), "INVALID_SELL_TOKEN");
        require(isPermitted(address(mintData._setToken)), "INVALID_TOKEN_TO_MINT");

        ERC20 token = ERC20(permit._tokenContract);
        safePermit(token, permit);

        token.safeTransferFrom(permit._owner, address(this), permit._amount);

        emit Received(permit._owner, permit._tokenContract, permit._amount, msg.sender);

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
        token.safeTransfer(owner, token.balanceOf(address(this)));
    }

    /**
     * Swaps an exact amount of SetTokens in 0x for a given amount of ERC20 tokens.
     * Using a permit for the ERC20 token transfer (through Permit2)
     *
     * @param permit              Permit data of the ERC20 token used
     * @param transferDetails     Details of the transfer to perform
     * @param owner               Owner of the tokens to transfer
     * @param witness             Payload of data we want to validate (encoded in bytes32)
     * @param signature           Signature of the owner of the tokens
     * @param swapData            Data of the swap to perform
     */
    function swapWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit,
        ISignatureTransfer.SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes32 witness,
        bytes calldata signature,
        SwapData calldata swapData
    ) external {
        require(isPermitted(permit.permitted.token), "INVALID_SELL_TOKEN");
        require(isPermitted(swapData.buyToken), "INVALID_BUY_TOKEN");

        signatureTransfer.permitWitnessTransferFrom(
            permit, transferDetails, owner, witness, SWAPDATA_WITNESS_TYPE_STRING, signature
        );

        emit Received(owner, transferDetails.to, transferDetails.requestedAmount, msg.sender);

        _fillQuoteInternal(swapData, transferDetails.requestedAmount, owner, permit.permitted.token);
    }

    /**
     * Issues an exact amount of SetTokens for given amount of input ERC20 tokens.
     * Using a permit for the ERC20 token transfer (through Permit2)
     * The excess amount of tokens is returned in an equivalent amount of ether.
     *
     * @param permit              Permit data of the ERC20 token used
     * @param transferDetails     Details of the transfer to perform
     * @param owner               Owner of the tokens to transfer
     * @param witness             Payload of data we want to validate (encoded in bytes32)
     * @param signature           Signature of the owner of the tokens
     * @param mintData            Data of the issuance to perform
     */
    function mintWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit,
        ISignatureTransfer.SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes32 witness,
        bytes calldata signature,
        MintData calldata mintData
    ) external {
        require(isPermitted(permit.permitted.token), "INVALID_SELL_TOKEN");
        require(isPermitted(address(mintData._setToken)), "INVALID_BUY_TOKEN");

        signatureTransfer.permitWitnessTransferFrom(
            permit, transferDetails, owner, witness, MINTDATA_WITNESS_TYPE_STRING, signature
        );

        ERC20 token = ERC20(permit.permitted.token);

        emit Received(owner, permit.permitted.token, permit.permitted.amount, msg.sender);

        token.safeApprove(address(exchangeIssuance), mintData._maxAmountInputToken);

        exchangeIssuance.issueExactSetFromToken(
            mintData._setToken,
            IERC20(permit.permitted.token),
            mintData._amountSetToken,
            mintData._maxAmountInputToken,
            mintData._componentQuotes,
            mintData._issuanceModule,
            mintData._isDebtIssuance
        );

        ERC20(address(mintData._setToken)).safeTransfer(owner, mintData._amountSetToken);
        token.safeTransfer(owner, token.balanceOf(address(this)));
    }

    /**
     * Redeems an exact amount of SetTokens to a given amount of output ERC20 tokens.
     * Using a permit for the SetToken (through Permit2)
     *
     * @param permit              Permit data of the ERC20 token used
     * @param transferDetails     Details of the transfer to perform
     * @param owner               Owner of the tokens to transfer
     * @param witness             Payload of data we want to validate (encoded in bytes32)
     * @param signature           Signature of the owner of the tokens
     * @param redeemData          Data of the redemption to perform
     */
    function redeemWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit,
        ISignatureTransfer.SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes32 witness,
        bytes calldata signature,
        RedeemData calldata redeemData
    ) external {
        require(isPermitted(address(redeemData._outputToken)), "INVALID_BUY_TOKEN");
        require(isPermitted(address(redeemData._setToken)), "INVALID_SELL_TOKEN");
        ERC20 outputToken = ERC20(address(redeemData._outputToken));

        signatureTransfer.permitWitnessTransferFrom(
            permit, transferDetails, owner, witness, REDEEMDATA_WITNESS_TYPE_STRING, signature
        );

        emit Received(owner, address(redeemData._setToken), redeemData._amountSetToken, msg.sender);

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

        outputToken.safeTransfer(owner, outputToken.balanceOf(address(this)));
        ERC20(address(redeemData._setToken)).safeTransfer(owner, redeemData._setToken.balanceOf(address(this)));
    }

    function mintChamberWithPermit2(
        ISignatureTransfer.PermitTransferFrom memory permit,
        ISignatureTransfer.SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes32 witness,
        bytes calldata signature,
        MintChamberData calldata mintChamberData,
        Permit2 permit2
    ) external {
        require(isPermitted(permit.permitted.token), "INVALID_SELL_TOKEN");
        require(isPermitted(address(mintChamberData._chamber)), "INVALID_BUY_TOKEN");

        permit2.permitWitnessTransferFrom(
            permit, transferDetails, owner, witness, MINT_CHAMBER_WITNESS_TYPE_STRING, signature
        );

        ERC20 token = ERC20(permit.permitted.token);

        emit Received(owner, permit.permitted.token, permit.permitted.amount, msg.sender);

        token.safeApprove(address(exchangeIssuance), mintChamberData._maxPayAmount);

        tradeIssuer.mintChamberFromToken(
            mintChamberData._contractCallInstructions,
            mintChamberData._chamber,
            mintChamberData._issuerWizard,
            mintChamberData._baseToken,
            mintChamberData._maxPayAmount,
            mintChamberData._mintAmount
        );

        ERC20(address(mintChamberData._chamber)).safeTransfer(owner, mintChamberData._mintAmount);
        token.safeTransfer(owner, token.balanceOf(address(this)));
    }

    function redeemChamberWithPermit2() external {
        // TODO
    }

    function _fillQuoteInternal(SwapData calldata swap, uint256 sellAmount, address _owner, address _sellToken)
        internal
    {
        ERC20 sellToken = ERC20(_sellToken);
        ERC20 buyToken = ERC20(swap.buyToken);
        uint256 beforeBalance = buyToken.balanceOf(address(this));

        sellToken.safeApprove(swap.spender, type(uint256).max);

        (bool success,) = swap.swapTarget.call{value: swap.swapValue}(swap.swapCallData);
        require(success, "SWAP_CALL_FAILED");

        emit Swap(swap.buyToken, swap.buyAmount, _sellToken, sellAmount);

        uint256 swapBalance = buyToken.balanceOf(address(this)) - beforeBalance;

        require(swapBalance >= swap.buyAmount, "UNDERBOUGHT");
        buyToken.safeTransfer(_owner, swapBalance);

        emit Sent(address(this), swap.buyToken, swap.buyAmount);
    }

    function safePermit(ERC20 token, PermitData calldata permit) internal {
        uint256 nonceBefore = token.nonces(permit._owner);
        token.permit(permit._owner, permit._spender, permit._value, permit._deadline, permit._v, permit._r, permit._s);
        uint256 nonceAfter = token.nonces(permit._owner);
        require(nonceAfter == nonceBefore + 1, "SafeERC20: permit did not succeed");
    }

    function withdrawTokenBalance(address _token) external onlyOwner {
        ERC20 token = ERC20(_token);
        uint256 balance = token.balanceOf(address(this));
        require(balance > 0, "ZERO_BALANCE");
        token.safeTransfer(owner, balance);
    }
}
