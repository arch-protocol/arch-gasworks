// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "@opengsn/BaseRelayRecipient.sol";
import "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import "solmate/tokens/ERC20.sol";
import {IWETH} from "./interfaces/IWETH.sol";

contract PermitSwap is BaseRelayRecipient {

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

    string public override versionRecipient = "2.2.0";

    function deposit(address _tokenContract, uint256 _amount) external {
        ERC20(_tokenContract).transferFrom(msg.sender, address(this), _amount);

        emit TokenDeposit(msg.sender, _tokenContract, _amount);
    }

    function depositWithPermit(PermitData calldata permitData) external {
        ERC20(permitData._tokenContract).permit(
            permitData._owner,
            permitData._spender,
            permitData._value,
            permitData._deadline,
            permitData._v,
            permitData._r,
            permitData._s
        );

        ERC20(permitData._tokenContract).transferFrom(permitData._owner, address(this), permitData._amount);

        emit TokenDeposit(permitData._owner, permitData._tokenContract, permitData._amount);
        // _fillQuoteInternal(swapData);
    }

    function _fillQuoteInternal(SwapData calldata swapData) internal {
        require(swapData.sellToken.approve(swapData.spender, type(uint256).max));
        // Call the encoded swap function call on the contract at `swapTarget`,
        // passing along any ETH attached to this function call to cover protocol fees.
        (bool success, ) = swapData.swapTarget.call{value: msg.value}(swapData.swapCallData);
        require(success, "SWAP_CALL_FAILED");
        // Refund any unspent protocol fees to the sender.
        payable(_msgSender()).transfer(address(this).balance);

        swapData.buyToken.transfer(_msgSender(), swapData.buyToken.balanceOf(address(this)));
    }
}
