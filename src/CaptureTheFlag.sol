// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "@opengsn/BaseRelayRecipient.sol";

contract CaptureTheFlag is BaseRelayRecipient {
    event FlagCaptured(address previousHolder, address currentHolder);

    constructor(address forwarder) {
        _setTrustedForwarder(forwarder);
    }

    string public override versionRecipient = "2.2.0";

    address public currentHolder = address(0);

    function captureTheFlag() external {
        address previousHolder = currentHolder;

        currentHolder = _msgSender();

        emit FlagCaptured(previousHolder, currentHolder);
    }

    // Swaps ERC20->ERC20 tokens held by this contract using a 0x-API quote.
    function fillQuote(
        // The `sellTokenAddress` field from the API response.
        IERC20 sellToken,
        // The `buyTokenAddress` field from the API response.
        IERC20 buyToken,
        // The `allowanceTarget` field from the API response.
        address spender,
        // The `to` field from the API response.
        address payable swapTarget,
        // The `data` field from the API response.
        bytes calldata swapCallData
    )
        external
        payable
        onlyOwner // Must attach ETH equal to the `value` field from the API response.
    {
        // ...

        // Give `spender` an infinite allowance to spend this contract's `sellToken`.
        // Note that for some tokens (e.g., USDT, KNC), you must first reset any existing
        // allowance to 0 before being able to update it.
        require(sellToken.approve(spender, uint256(-1)));
        // Call the encoded swap function call on the contract at `swapTarget`,
        // passing along any ETH attached to this function call to cover protocol fees.
        (bool success, ) = swapTarget.call{value: msg.value}(swapCallData);
        require(success, "SWAP_CALL_FAILED");
        // Refund any unspent protocol fees to the sender.
        msg.sender.transfer(address(this).balance);

        // ...
    }
}
