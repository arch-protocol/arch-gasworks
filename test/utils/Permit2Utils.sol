// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21.0;

import { ArchUtils } from "./ArchUtils.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { FoundryRandom } from "foundry-random/FoundryRandom.sol";

contract Permit2Utils is ArchUtils {
    // Uniswap's Permit2 EIP712 Domain
    bytes public constant PERMIT2_EIP712_DOMAIN_TYPE =
        "EIP712Domain(string name,uint256 chainId,address verifyingContract)";
    bytes32 public constant PERMIT2_EIP712_DOMAIN_TYPEHASH = keccak256(PERMIT2_EIP712_DOMAIN_TYPE);
    bytes32 public constant PERMIT2_CONTRACT_NAME_HASH = keccak256(bytes("Permit2"));
    // TokenPermissions, PermitTransferFrom, PermitWitnessTransferFrom
    bytes public constant TOKEN_PERMISSIONS_TYPE = "TokenPermissions(address token,uint256 amount)";
    bytes32 public constant TOKEN_PERMISSIONS_TYPEHASH = keccak256(TOKEN_PERMISSIONS_TYPE);
    bytes public constant PERMIT_TRANSFER_FROM_TYPE =
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)";
    bytes32 public constant PERMIT_TRANSFER_FROM_TYPEHASH =
        keccak256(abi.encodePacked(PERMIT_TRANSFER_FROM_TYPE, TOKEN_PERMISSIONS_TYPE));
    bytes internal constant PERMIT_WITNESS_TRANSFER_FROM_TYPE =
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,";

    // SwapCallInstruction
    bytes private constant SWAP_CALL_INSTRUCTION_TYPE =
        "SwapCallInstruction(address sellToken,uint256 sellAmount,address buyToken,uint256 minBuyAmount,address swapTarget,address swapAllowanceTarget)";
    bytes32 public constant SWAP_CALL_INSTRUCTION_TYPE_HASH =
        keccak256(abi.encodePacked(SWAP_CALL_INSTRUCTION_TYPE));
    // MintData
    bytes public constant MINT_DATA_TYPE =
        "MintData(address archToken,uint256 archTokenAmount,address inputToken,uint256 inputTokenMaxAmount,address issuer,SwapCallInstruction[] swapCallInstructions)";
    bytes32 public constant MINT_DATA_TYPE_HASH =
        keccak256(abi.encodePacked(MINT_DATA_TYPE, SWAP_CALL_INSTRUCTION_TYPE));
    bytes public constant PERMIT2_MINT_DATA_TYPE = abi.encodePacked(
        "MintData witness)", MINT_DATA_TYPE, SWAP_CALL_INSTRUCTION_TYPE, TOKEN_PERMISSIONS_TYPE
    );
    bytes32 public constant PERMIT2_TRANSFERFROM_MINT_DATA_TYPE_HASH =
        keccak256(abi.encodePacked(PERMIT_WITNESS_TRANSFER_FROM_TYPE, PERMIT2_MINT_DATA_TYPE));
    // RedeemData
    bytes public constant REDEEM_DATA_TYPE =
        "RedeemData(address archToken,uint256 archTokenAmount,address outputToken,uint256 outputTokenMinAmount,address issuer,SwapCallInstruction[] swapCallInstructions)";
    bytes32 public constant REDEEM_DATA_TYPE_HASH =
        keccak256(abi.encodePacked(REDEEM_DATA_TYPE, SWAP_CALL_INSTRUCTION_TYPE));
    bytes public constant PERMIT2_REDEEM_DATA_TYPE = abi.encodePacked(
        "RedeemData witness)", REDEEM_DATA_TYPE, SWAP_CALL_INSTRUCTION_TYPE, TOKEN_PERMISSIONS_TYPE
    );
    bytes32 public constant PERMIT2_TRANSFERFROM_REDEEM_DATA_TYPE_HASH =
        keccak256(abi.encodePacked(PERMIT_WITNESS_TRANSFER_FROM_TYPE, PERMIT2_REDEEM_DATA_TYPE));

    function getDomainSeparatorHashed(uint256 chainId, address permit2Address)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                PERMIT2_EIP712_DOMAIN_TYPEHASH, PERMIT2_CONTRACT_NAME_HASH, chainId, permit2Address
            )
        );
    }

    function getTokenPermissionsHahed(ISignatureTransfer.PermitTransferFrom memory permit)
        public
        pure
        returns (bytes32 tokenPermissionsHashed)
    {
        tokenPermissionsHashed = keccak256(
            abi.encode(TOKEN_PERMISSIONS_TYPEHASH, permit.permitted.token, permit.permitted.amount)
        );
        return tokenPermissionsHashed;
    }

    function getSwapCallIntructionHashed(
        IGasworks.SwapCallInstruction[] memory swapCallInstructions
    ) public pure returns (bytes32 swapCallInstructionsHash) {
        bytes32[] memory instructionsHashes = new bytes32[](swapCallInstructions.length);
        for (uint256 i = 0; i < swapCallInstructions.length; i++) {
            instructionsHashes[i] = keccak256(
                abi.encode(
                    SWAP_CALL_INSTRUCTION_TYPE_HASH,
                    swapCallInstructions[i].sellToken,
                    swapCallInstructions[i].sellAmount,
                    swapCallInstructions[i].buyToken,
                    swapCallInstructions[i].minBuyAmount,
                    swapCallInstructions[i].swapTarget,
                    swapCallInstructions[i].swapAllowanceTarget
                )
            );
        }
        swapCallInstructionsHash = keccak256(abi.encodePacked(instructionsHashes));
        return swapCallInstructionsHash;
    }

    function getMintWitnessHashed(IGasworks.MintData memory mintData)
        public
        pure
        returns (bytes32 witnessHash)
    {
        bytes32 swapCallInstructionsHash =
            getSwapCallIntructionHashed(mintData.swapCallInstructions);
        witnessHash = keccak256(
            abi.encode(
                MINT_DATA_TYPE_HASH,
                mintData.archToken,
                mintData.archTokenAmount,
                mintData.inputToken,
                mintData.inputTokenMaxAmount,
                mintData.issuer,
                swapCallInstructionsHash
            )
        );
        return witnessHash;
    }

    function getRedeemWitnessHashed(IGasworks.RedeemData memory redeemData)
        public
        pure
        returns (bytes32 witnessHash)
    {
        bytes32 swapCallInstructionsHash =
            getSwapCallIntructionHashed(redeemData.swapCallInstructions);
        witnessHash = keccak256(
            abi.encode(
                REDEEM_DATA_TYPE_HASH,
                redeemData.archToken,
                redeemData.archTokenAmount,
                redeemData.outputToken,
                redeemData.outputTokenMinAmount,
                redeemData.issuer,
                swapCallInstructionsHash
            )
        );
        return witnessHash;
    }

    function getMintWithPermit2MessageToSign(
        uint256 chainId,
        ISignatureTransfer.PermitTransferFrom memory permit,
        address spender,
        IGasworks.MintData memory mintData
    ) public pure returns (bytes32 messageHashed) {
        bytes32 domainSeparatorHashed;
        if (chainId == 137) {
          domainSeparatorHashed = getDomainSeparatorHashed(chainId, POLYGON_UNISWAP_PERMIT2);
        }
        if (chainId == 1) {
          domainSeparatorHashed = getDomainSeparatorHashed(chainId, POLYGON_UNISWAP_PERMIT2);
        }
        bytes32 tokenPermissions = getTokenPermissionsHahed(permit);
        bytes32 witnessHash = getMintWitnessHashed(mintData);
        bytes32 permitWitnessTransferFromHash = keccak256(
            abi.encode(
                PERMIT2_TRANSFERFROM_MINT_DATA_TYPE_HASH,
                tokenPermissions,
                spender,
                permit.nonce,
                permit.deadline,
                witnessHash
            )
        );
        messageHashed = keccak256(
            abi.encodePacked("\x19\x01", domainSeparatorHashed, permitWitnessTransferFromHash)
        );
        return messageHashed;
    }

    function getRedeemWithPermit2MessageToSign(
        uint256 chainId,
        ISignatureTransfer.PermitTransferFrom memory permit,
        address spender,
        IGasworks.RedeemData memory redeemData
    ) public pure returns (bytes32 messageHashed) {
        bytes32 domainSeparatorHashed;
        if (chainId == 137) {
          domainSeparatorHashed = getDomainSeparatorHashed(chainId, POLYGON_UNISWAP_PERMIT2);
        }
        if (chainId == 1) {
          domainSeparatorHashed = getDomainSeparatorHashed(chainId, POLYGON_UNISWAP_PERMIT2);
        }
        bytes32 tokenPermissions = getTokenPermissionsHahed(permit);
        bytes32 witnessHash = getRedeemWitnessHashed(redeemData);
        bytes32 permitWitnessTransferFromHash = keccak256(
            abi.encode(
                PERMIT2_TRANSFERFROM_REDEEM_DATA_TYPE_HASH,
                tokenPermissions,
                spender,
                permit.nonce,
                permit.deadline,
                witnessHash
            )
        );
        messageHashed = keccak256(
            abi.encodePacked("\x19\x01", domainSeparatorHashed, permitWitnessTransferFromHash)
        );
        return messageHashed;
    }

    function signMessage(uint256 privateKey, bytes32 message)
        public
        pure
        returns (bytes memory signature)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, message);
        signature = bytes.concat(r, s, bytes1(v));
        return signature;
    }

    function getRandomNonce() public returns (uint256 randomNonce) {
        FoundryRandom random = new FoundryRandom();
        randomNonce = random.randomNumber(type(uint256).max);
        return randomNonce;
    }

    function getFiveMinutesDeadlineFromNow() public view returns (uint256 deadline) {
        deadline = block.timestamp + 300;
        return deadline;
    }

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

    function getSignatureWithoutWitness(
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
                        PERMIT_TRANSFER_FROM_TYPEHASH,
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
