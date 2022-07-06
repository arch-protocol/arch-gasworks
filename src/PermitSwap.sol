// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import "solmate/tokens/ERC20.sol";
contract PermitSwap {

    event TokenDeposit(address user, address tokenContract, uint256 amount);
    struct PermitData {
        address _tokenContract;
        uint256 _amount;
        address _owner;
        address _spender;
        uint256 _value;
        uint256 _deadline;
        uint8 _v;
        bytes32 _r;
        bytes32 _s;
    }

    struct SwapData {
        // The `sellTokenAddress` field from the API response.
        IERC20 sellToken;
        // The `buyTokenAddress` field from the API response.
        IERC20 buyToken;
        // The `allowanceTarget` field from the API response.
        address spender;
        // The `to` field from the API response.
        address payable swapTarget;
        // The `data` field from the API response.
        bytes swapCallData;
    }

    constructor() {
        // _setTrustedForwarder(forwarder);
    }

    function swapNormal(address _tokenContract, uint256 _amount, SwapData calldata data) external {
        ERC20(_tokenContract).transferFrom(msg.sender, address(this), _amount);

        emit TokenDeposit(msg.sender, _tokenContract, _amount);

        _fillQuoteInternal(data);
    }

    function swapWithPermit(PermitData calldata permit, SwapData calldata swapData) external {
        ERC20(permit._tokenContract).permit(
            permit._owner,
            permit._spender,
            permit._value,
            permit._deadline,
            permit._v,
            permit._r,
            permit._s
        );

        ERC20(permit._tokenContract).transferFrom(permit._owner, address(this), permit._amount);

        emit TokenDeposit(permit._owner, permit._tokenContract, permit._amount);

        _fillQuoteInternal(swapData);
    }

    function _fillQuoteInternal(SwapData calldata swap) internal {
        require(swap.sellToken.approve(swap.spender, type(uint256).max));
        // Call the encoded swap function call on the contract at `swapTarget`,
        // passing along any ETH attached to this function call to cover protocol fees.
        (bool success, ) = swap.swapTarget.call{value: msg.value}(swap.swapCallData);
        require(success, "SWAP_CALL_FAILED");
        // Refund any unspent protocol fees to the sender.
        payable(msg.sender).transfer(address(this).balance);

        swap.buyToken.transfer(msg.sender, swap.buyToken.balanceOf(address(this)));
    }
}
