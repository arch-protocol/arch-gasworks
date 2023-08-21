// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21.0;

import { Test } from "forge-std/Test.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

contract Permit2Utils is Test {
    bytes32 public constant _PERMIT_TRANSFER_FROM_TYPEHASH = keccak256(
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );

    function defaultERC20PermitTransfer(address token0, uint256 nonce, uint256 requestedAmount)
        internal
        pure
        returns (ISignatureTransfer.PermitTransferFrom memory)
    {
        return ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: token0, amount: requestedAmount }),
            nonce: nonce,
            deadline: 2 ** 256 - 1
        });
    }

    function getSignature(
        ISignatureTransfer.PermitTransferFrom memory permit,
        uint256 privateKey,
        bytes32 domainSeparator,
        bytes32 tokenPermissionsHash,
        address caller
    ) internal pure returns (bytes memory signature) {
        bytes32 tokenPermissions = keccak256(abi.encode(tokenPermissionsHash, permit.permitted));
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        _PERMIT_TRANSFER_FROM_TYPEHASH,
                        tokenPermissions,
                        caller,
                        permit.nonce,
                        permit.deadline
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        return bytes.concat(r, s, bytes1(v));
    }
}
