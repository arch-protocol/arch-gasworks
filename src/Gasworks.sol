// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.13;

import "gsn/ERC2771Recipient.sol";
import "solmate/tokens/ERC20.sol";
import "solmate/utils/SafeTransferLib.sol";
import "solmate/auth/Owned.sol";
import "./interfaces/IExchangeIssuanceZeroEx.sol";

contract Gasworks is ERC2771Recipient, Owned {
    using SafeTransferLib for ERC20;
    using SafeTransferLib for ISetToken;

    address private constant biconomyForwarder = 0x86C80a8aa58e0A4fa09A69624c31Ab2a6CAD56b8;
    IExchangeIssuanceZeroEx private immutable exchangeIssuance;

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

    modifier isBiconomy() virtual {
        require(msg.sender == biconomyForwarder, "UNAUTHORIZED");

        _;
    }

    constructor(address _forwarder) Owned(_msgSender()) {
        _setTrustedForwarder(_forwarder);
        exchangeIssuance = IExchangeIssuanceZeroEx(payable(0x1c0c05a2aA31692e5dc9511b04F651db9E4d8320));
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
     * Method must be called by BiconomyForwarder
     *
     * @param permit              Permit data of the ERC20 token used (USDC)
     * @param swapData            Data of the swap to perform
     */
    function swapWithPermit(PermitData calldata permit, SwapData calldata swapData) external isBiconomy {
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
     * Method must be called by BiconomyForwarder
     *
     * @param permit              Permit data of the ERC20 token used (USDC)
     * @param mintData            Data of the issuance to perform
     */
    function mintWithPermit(PermitData calldata permit, MintData calldata mintData) external isBiconomy {
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

        mintData._setToken.transfer(permit._owner, mintData._amountSetToken);
        token.safeTransfer(permit._owner, token.balanceOf(address(this))); 
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
