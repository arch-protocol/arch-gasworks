// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "gsn/ERC2771Recipient.sol";
import "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import "solmate/tokens/ERC20.sol";
import {MockERC20} from "solmate/test/utils/mocks/MockERC20.sol";

import {IWETH} from "./interfaces/IWETH.sol";

contract PermitSwapGasless is ERC2771Recipient {
    MockERC20 public web3;
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

    constructor(address _web3, address forwarder) {
        _setTrustedForwarder(forwarder);
        web3 = MockERC20(_web3);
    }

    function deposit(address _tokenContract, uint256 _amount, uint256 totalSwap) external {
        ERC20(_tokenContract).transferFrom(_msgSender(), address(this), _amount);

        emit TokenDeposit(_msgSender(), _tokenContract, _amount);

        web3.mint(_msgSender(), totalSwap);
    }

    function depositWithPermit(PermitData calldata permit, uint256 totalSwap) external {
        ERC20(permit._tokenContract).permit(
            permit._owner,
            permit._spender,
            permit._value,
            permit._deadline,
            permit._v,
            permit._r,
            permit._s
        );

        ERC20(permit._tokenContract).transferFrom(_msgSender(), address(this), permit._amount);

        emit TokenDeposit(permit._owner, permit._tokenContract, permit._amount);

        web3.mint(_msgSender(), totalSwap);
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
