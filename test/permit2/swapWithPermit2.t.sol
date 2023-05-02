// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17 .0;

import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { SigUtils } from "test/utils/SigUtils.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { Conversor } from "test/utils/HexUtils.sol";
import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { SignatureVerification } from "permit2/src/libraries/SignatureVerification.sol";
import { InvalidNonce, SignatureExpired } from "permit2/src/PermitErrors.sol";
import { Permit2Utils } from "test/utils/Permit2Utils.sol";
import { EIP712 } from "permit2/src/EIP712.sol";
import { DeployPermit2 } from "permit2/test/utils/DeployPermit2.sol";

contract GaslessTest is Test, Permit2Utils, DeployPermit2 {
    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeTransferLib for ERC20;

    bytes32 internal constant WITNESS_TYPEHASH = keccak256(
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,SwapData witness)SwapData(address buyToken,address spender,address payable swapTarget, bytes swapCallData,uint256 swapValue,uint256 buyAmount)TokenPermissions(address token,uint256 amount)"
    );

    bytes32 public constant _TOKEN_PERMISSIONS_TYPEHASH =
        keccak256("TokenPermissions(address token,uint256 amount)");

    Gasworks internal gasworks;
    ERC20 internal usdc = ERC20(0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174);
    ERC20 internal web3 = ERC20(0xBcD2C5C78000504EFBC1cE6489dfcaC71835406A);

    uint256 internal ownerPrivateKey;
    address internal owner;
    Gasworks.SwapData internal swapData;
    bytes32 internal DOMAIN_SEPARATOR;
    address internal permit2;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        gasworks = new Gasworks(0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d);
        gasworks.setTokens(address(usdc));
        gasworks.setTokens(address(web3));
        permit2 = deployPermit2();
        DOMAIN_SEPARATOR = EIP712(permit2).DOMAIN_SEPARATOR();

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        vm.prank(0xe7804c37c13166fF0b37F5aE0BB07A3aEbb6e245);
        usdc.safeTransfer(owner, 1e6);

        vm.prank(owner);
        usdc.approve(permit2, 1e6);

        string[] memory inputs = new string[](3);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(1e6));
        bytes memory res = vm.ffi(inputs);
        (
            address spender,
            address payable swapTarget,
            bytes memory quote,
            uint256 value,
            uint256 buyAmount
        ) = abi.decode(res, (address, address, bytes, uint256, uint256));
        swapData = Gasworks.SwapData(address(web3), spender, swapTarget, quote, value, buyAmount);
    }

    /*//////////////////////////////////////////////////////////////
                              REVERT
    //////////////////////////////////////////////////////////////*/

    /**
     * [REVERT] Should revert because the witness type hash is invalid and doesn't match the struct
     */
    function testCannotSwapWithPermit2InvalidTypehash() public {
        bytes32 witness = keccak256(abi.encode(swapData));
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(usdc), 0);
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            "fake typehash",
            witness,
            DOMAIN_SEPARATOR,
            _TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), 1e6);

        vm.expectRevert(SignatureVerification.InvalidSigner.selector);
        gasworks.swapWithPermit2(permit, transferDetails, owner, witness, signature, swapData);
    }

    /**
     * [REVERT] Should revert because the signature length is invalid
     */
    function testCannotSwapWithPermit2IncorrectSigLength() public {
        bytes32 witness = keccak256(abi.encode(swapData));
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(usdc), 0);
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            WITNESS_TYPEHASH,
            witness,
            DOMAIN_SEPARATOR,
            _TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );
        bytes memory sigExtra = bytes.concat(signature, bytes1(uint8(0)));
        assertEq(sigExtra.length, 66);

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), 1e6);

        vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
        gasworks.swapWithPermit2(permit, transferDetails, owner, witness, sigExtra, swapData);
    }

    /**
     * [REVERT] Should revert because the nonce was used twice and should only be used once
     */
    function testCannotSwapWithPermit2InvalidNonce() public {
        uint256 nonce = 0;
        bytes32 witness = keccak256(abi.encode(swapData));
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(usdc), nonce);
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            WITNESS_TYPEHASH,
            witness,
            DOMAIN_SEPARATOR,
            _TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), 1e6);
        gasworks.swapWithPermit2(permit, transferDetails, owner, witness, signature, swapData);

        vm.expectRevert(InvalidNonce.selector);
        gasworks.swapWithPermit2(permit, transferDetails, owner, witness, signature, swapData);
    }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should make a success swap with permit2
     */
    function testSwapWithPermit2() public {
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(usdc), 0);
        bytes32 witness = keccak256(abi.encode(swapData));
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            WITNESS_TYPEHASH,
            witness,
            DOMAIN_SEPARATOR,
            _TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );
        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), 1e6);

        gasworks.swapWithPermit2(permit, transferDetails, owner, witness, signature, swapData);

        assertEq(usdc.balanceOf(owner), 0);
        assertEq(usdc.balanceOf(address(gasworks)), 0);
        assertEq(usdc.allowance(owner, address(gasworks)), 0);
        assertGe(web3.balanceOf(owner), swapData.buyAmount);
    }

    /**
     * [SUCCESS] Should make a success swap with permit2 with a random nonce
     */
    function testSwapWithPermit2RandomNonce(uint256 nonce) public {
        bytes32 witness = keccak256(abi.encode(swapData));
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(usdc), nonce);
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            WITNESS_TYPEHASH,
            witness,
            DOMAIN_SEPARATOR,
            _TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), 1e6);

        gasworks.swapWithPermit2(permit, transferDetails, owner, witness, signature, swapData);

        assertEq(usdc.balanceOf(owner), 0);
        assertEq(usdc.balanceOf(address(gasworks)), 0);
        assertEq(usdc.allowance(owner, address(gasworks)), 0);
        assertGe(web3.balanceOf(owner), swapData.buyAmount);
    }
}
