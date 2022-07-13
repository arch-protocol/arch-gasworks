//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;

import "gsn/BasePaymaster.sol";

contract ArchPaymaster is BasePaymaster {
	address public ourTarget;   // The target contract we are willing to pay for

	// allow the owner to set ourTarget
	event TargetSet(address target);
	function setTarget(address target) external onlyOwner {
		ourTarget = target;
		emit TargetSet(target);
	}

	event PreRelayed(uint);
	event PostRelayed(uint);


	function _preRelayedCall(
		GsnTypes.RelayRequest calldata relayRequest,
		bytes calldata signature,
		bytes calldata approvalData,
		uint256 maxPossibleGas
	) internal override virtual
	returns (bytes memory context, bool) {
		_verifyForwarder(relayRequest);
		(signature, approvalData, maxPossibleGas);
		
		require(relayRequest.request.to == ourTarget);
		emit PreRelayed(block.timestamp);
                return (abi.encode(block.timestamp), false);
	}

	function _postRelayedCall(
		bytes calldata context,
		bool success,
		uint256 gasUseWithoutPost,
		GsnTypes.RelayData calldata relayData
	) internal override virtual {
                (context, success, gasUseWithoutPost, relayData);
		emit PostRelayed(abi.decode(context, (uint)));
	}

  function versionPaymaster() external virtual view override returns (string memory) {
    return "2.0.3";
  }

}