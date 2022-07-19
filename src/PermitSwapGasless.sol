// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "gsn/ERC2771Recipient.sol";
import "solmate/tokens/ERC20.sol";
import "solmate/utils/SafeTransferLib.sol";
import "solmate/auth/Owned.sol";

contract PermitSwapGasless is ERC2771Recipient, Owned {
    using SafeTransferLib for ERC20;

    event Received(address sender, address tokenContract, uint256 amount);
    event Swap(
        address buyToken,
        uint256 buyAmount,
        address sellToken,
        uint256 sellAmount
    );
    event Sent(address receiver, address tokenContract, uint256 amount);
    struct PermitData {
        // The address of the token to which we want to sign a permit for
        address _tokenContract;
        // The amount of the token we want to permit the contract to use
        uint256 _amount;
        // The owner of the tokens
        address _owner;
        // The contract that will spend our tokens
        address _spender;
        // The value of the tokens?
        uint256 _value;
        // The date until which the permit is accepted
        uint256 _deadline;
        // The signature of the owner
        uint8 _v;
        bytes32 _r;
        bytes32 _s;
    }

    struct SwapData {
        // The `sellTokenAddress` field from the API response.
        address sellToken;
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

    constructor(address _forwarder) Owned(msg.sender) {
        _setTrustedForwarder(_forwarder);
    }

    function setTrustedForwarder(address _forwarder) external onlyOwner {
        _setTrustedForwarder(_forwarder);
    }

    function swapNormal(
        address _tokenContract,
        uint256 _amount,
        SwapData calldata data
    ) external {
        ERC20(_tokenContract).safeTransferFrom(
            msg.sender,
            address(this),
            _amount
        );

        emit Received(msg.sender, _tokenContract, _amount);

        _fillQuoteInternal(data, _amount);
    }

    function swapWithPermit(
        PermitData calldata permit,
        SwapData calldata swapData
    ) external {
        ERC20(permit._tokenContract).permit(
            permit._owner,
            permit._spender,
            permit._value,
            permit._deadline,
            permit._v,
            permit._r,
            permit._s
        );

        ERC20(permit._tokenContract).safeTransferFrom(
            permit._owner,
            address(this),
            permit._amount
        );

        emit Received(permit._owner, permit._tokenContract, permit._amount);

        _fillQuoteInternal(swapData, permit._amount);
    }

    function _fillQuoteInternal(SwapData calldata swap, uint256 sellAmount)
        internal
    {
        ERC20 sellToken = ERC20(swap.sellToken);
        ERC20 buyToken = ERC20(swap.buyToken);

        sellToken.safeApprove(swap.spender, type(uint256).max);

        // Call the encoded swap function call on the contract at `swapTarget`,
        // passing along any ETH attached to this function call to cover protocol fees.
        (bool success, ) = swap.swapTarget.call{value: msg.value}(
            swap.swapCallData
        );
        require(success, "SWAP_CALL_FAILED");

        emit Swap(swap.buyToken, swap.buyAmount, swap.sellToken, sellAmount);

        // Refund any unspent protocol fees to the sender.
        (bool s, ) = payable(msg.sender).call{value: address(this).balance}("");
        require(s, "REFUND_FAILED");

        buyToken.safeTransfer(msg.sender, swap.buyAmount);

        emit Sent(address(this), swap.buyToken, swap.buyAmount);
    }
}
