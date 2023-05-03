// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { ISetToken } from "src/interfaces/ISetToken.sol";
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
    using SafeTransferLib for ISetToken;

    bytes32 constant WITNESS_TYPEHASH = keccak256(
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,MintData witness)MintData(ISetToken _setToken,uint256 _amountSetToken,uint256 _maxAmountInputToken, bytes[] _componentQuotes,address _issuanceModule,bool _isDebtIssuance)TokenPermissions(address token,uint256 amount)"
    );

    bytes32 public constant TOKEN_PERMISSIONS_TYPEHASH =
        keccak256("TokenPermissions(address token,uint256 amount)");

    address internal constant DEBT_MODULE = 0xf2dC2f456b98Af9A6bEEa072AF152a7b0EaA40C9;
    bool internal constant IS_DEBT_ISSUANCE = true;

    Gasworks internal gasworks;
    ERC20 internal constant USDC = ERC20(0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174);
    ISetToken internal constant AP60 = ISetToken(0x6cA9C8914a14D63a6700556127D09e7721ff7D3b);

    uint256 internal ownerPrivateKey;
    address internal owner;
    Gasworks.MintSetData internal mintData;
    bytes32 internal DOMAIN_SEPARATOR;
    address internal permit2;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        gasworks = new Gasworks(0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d);
        gasworks.setTokens(address(USDC));
        gasworks.setTokens(address(AP60));
        permit2 = deployPermit2();
        DOMAIN_SEPARATOR = EIP712(permit2).DOMAIN_SEPARATOR();

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        vm.prank(0xe7804c37c13166fF0b37F5aE0BB07A3aEbb6e245);
        USDC.safeTransfer(owner, 150e6);

        uint256 amountToMint = 10e18;

        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(amountToMint));
        inputs[3] = Conversor.iToHex(abi.encode(address(AP60)));
        inputs[4] = Conversor.iToHex(abi.encode(address(USDC)));
        inputs[5] = Conversor.iToHex(abi.encode(true));
        bytes memory res = vm.ffi(inputs);
        (bytes[] memory quotes, uint256 _maxAmountInputToken) = abi.decode(res, (bytes[], uint256));
        mintData = Gasworks.MintSetData(
            AP60, amountToMint, _maxAmountInputToken, quotes, DEBT_MODULE, IS_DEBT_ISSUANCE
        );

        vm.prank(owner);
        USDC.approve(permit2, mintData._maxAmountInputToken);
    }

    /*//////////////////////////////////////////////////////////////
                              REVERT
    //////////////////////////////////////////////////////////////*/

    /**
     * [REVERT] Should revert because the witness type hash is invalid and doesn't match the struct
     */
    function testCannotMintWithPermit2InvalidTypehash() public {
        bytes32 witness = keccak256(abi.encode(mintData));
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(USDC), 0);
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            "fake typehash",
            witness,
            DOMAIN_SEPARATOR,
            TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), mintData._maxAmountInputToken);

        vm.expectRevert(SignatureVerification.InvalidSigner.selector);
        gasworks.mintWithPermit2(permit, transferDetails, owner, witness, signature, mintData);
    }

    /**
     * [REVERT] Should revert because the signature length is invalid
     */
    function testCannotMintWithPermit2IncorrectSigLength() public {
        bytes32 witness = keccak256(abi.encode(mintData));
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(USDC), 0);
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            WITNESS_TYPEHASH,
            witness,
            DOMAIN_SEPARATOR,
            TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );
        bytes memory sigExtra = bytes.concat(signature, bytes1(uint8(0)));
        assertEq(sigExtra.length, 66);

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), mintData._maxAmountInputToken);

        vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
        gasworks.mintWithPermit2(permit, transferDetails, owner, witness, sigExtra, mintData);
    }

    /**
     * [REVERT] Should revert because the nonce was used twice and should only be used once
     */
    function testCannotMintWithPermit2InvalidNonce() public {
        uint256 nonce = 0;
        bytes32 witness = keccak256(abi.encode(mintData));
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(USDC), nonce);
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            WITNESS_TYPEHASH,
            witness,
            DOMAIN_SEPARATOR,
            TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), mintData._maxAmountInputToken);
        gasworks.mintWithPermit2(permit, transferDetails, owner, witness, signature, mintData);

        vm.expectRevert(InvalidNonce.selector);
        gasworks.mintWithPermit2(permit, transferDetails, owner, witness, signature, mintData);
    }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should make a success mint with permit2
     */
    function testMintWithPermit2() public {
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(USDC), 0);
        bytes32 witness = keccak256(abi.encode(mintData));
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            WITNESS_TYPEHASH,
            witness,
            DOMAIN_SEPARATOR,
            TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), mintData._maxAmountInputToken);

        gasworks.mintWithPermit2(permit, transferDetails, owner, witness, signature, mintData);

        assertEq(USDC.balanceOf(address(gasworks)), 0);
        assertEq(USDC.allowance(owner, address(gasworks)), 0);
        assertGe(AP60.balanceOf(owner), mintData._amountSetToken);
    }

    /**
     * [SUCCESS] Should make a success mint with permit2 with a random nonce
     */
    function testMintWithPermit2RandomNonce(uint256 nonce) public {
        bytes32 witness = keccak256(abi.encode(mintData));
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(USDC), nonce);
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            WITNESS_TYPEHASH,
            witness,
            DOMAIN_SEPARATOR,
            TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), mintData._maxAmountInputToken);

        gasworks.mintWithPermit2(permit, transferDetails, owner, witness, signature, mintData);

        assertEq(USDC.balanceOf(address(gasworks)), 0);
        assertEq(USDC.allowance(owner, address(gasworks)), 0);
        assertGe(AP60.balanceOf(owner), mintData._amountSetToken);
    }
}
