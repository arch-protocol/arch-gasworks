// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import {Test} from "forge-std/Test.sol";
import {Gasworks} from "src/Gasworks.sol";
import {ISetToken} from "src/interfaces/ISetToken.sol";
import {SigUtils} from "test/utils/SigUtils.sol";
import {ERC20} from "solmate/src/tokens/ERC20.sol";
import {Conversor} from "test/utils/HexUtils.sol";
import {SafeTransferLib} from "solmate/src/utils/SafeTransferLib.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {PermitSignature} from "permit2/test/utils/PermitSignature.sol";
import {Permit2} from "permit2/src/Permit2.sol";
import {TokenProvider} from "permit2/test/utils/TokenProvider.sol";
import {SignatureVerification} from "permit2/src/libraries/SignatureVerification.sol";
import {InvalidNonce, SignatureExpired} from "permit2/src/PermitErrors.sol";
import {Permit2Utils} from "test/utils/Permit2Utils.sol";

contract GaslessTest is Test, PermitSignature, TokenProvider, Permit2Utils {
    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeTransferLib for ERC20;
    using SafeTransferLib for ISetToken;

    string constant WITNESS_TYPE_STRING =
        "MintData witness)MintData(ISetToken _setToken,uint256 _amountSetToken,uint256 _maxAmountInputToken, bytes[] _componentQuotes,address _issuanceModule,bool _isDebtIssuance)TokenPermissions(address token,uint256 amount)";

    bytes32 constant FULL_EXAMPLE_WITNESS_TYPEHASH = keccak256(
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,MintData witness)MintData(ISetToken _setToken,uint256 _amountSetToken,uint256 _maxAmountInputToken, bytes[] _componentQuotes,address _issuanceModule,bool _isDebtIssuance)TokenPermissions(address token,uint256 amount)"
    );

    address internal constant usdcAddress = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174;
    address internal constant AP60Address = 0x6cA9C8914a14D63a6700556127D09e7721ff7D3b;
    address internal constant debtModule = 0xf2dC2f456b98Af9A6bEEa072AF152a7b0EaA40C9;
    bool internal constant _isDebtIssuance = true;

    Gasworks internal gasworks;
    ERC20 internal constant usdc = ERC20(usdcAddress);
    ISetToken internal constant AP60 = ISetToken(AP60Address);

    uint256 internal ownerPrivateKey;
    address internal owner;
    Gasworks.MintData internal mintData;
    bytes32 internal DOMAIN_SEPARATOR;
    Permit2 internal permit2;

    function setUp() public {
        gasworks = new Gasworks(0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d);
        gasworks.setTokens(address(usdc));
        gasworks.setTokens(address(AP60));
        permit2 = Permit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);
        DOMAIN_SEPARATOR = permit2.DOMAIN_SEPARATOR();

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        vm.prank(0xe7804c37c13166fF0b37F5aE0BB07A3aEbb6e245);
        usdc.safeTransfer(owner, 150e6);

        uint256 amountToMint = 10e18;

        string[] memory inputs = new string[](5);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(amountToMint));
        inputs[3] = Conversor.iToHex(abi.encode(AP60Address));
        inputs[4] = Conversor.iToHex(abi.encode(true));
        bytes memory res = vm.ffi(inputs);
        (bytes[] memory quotes, uint256 _maxAmountInputToken) = abi.decode(res, (bytes[], uint256));
        mintData = Gasworks.MintData(AP60, amountToMint, _maxAmountInputToken, quotes, debtModule, _isDebtIssuance);

        vm.prank(owner);
        usdc.approve(address(permit2), mintData._maxAmountInputToken);
    }

    /*//////////////////////////////////////////////////////////////
                              REVERT
    //////////////////////////////////////////////////////////////*/

    function testCannotMintWithPermit2InvalidType() public {
        bytes32 witness = keccak256(abi.encode(mintData));
        ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitWitnessTransfer(address(usdc), 0);
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            FULL_EXAMPLE_WITNESS_TYPEHASH,
            witness,
            DOMAIN_SEPARATOR,
            _TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), mintData._maxAmountInputToken);

        vm.expectRevert(SignatureVerification.InvalidSigner.selector);
        permit2.permitWitnessTransferFrom(permit, transferDetails, owner, witness, "fake typedef", signature);
    }

    function testCannotSwapWithPermit2InvalidTypehash() public {
        bytes32 witness = keccak256(abi.encode(mintData));
        ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(usdc), 0);
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
            getTransferDetails(address(gasworks), mintData._maxAmountInputToken);

        vm.expectRevert(SignatureVerification.InvalidSigner.selector);
        gasworks.mintWithPermit2(permit, transferDetails, owner, witness, signature, mintData, permit2);
    }

    function testCannotSwapWithPermit2IncorrectSigLength() public {
        bytes32 witness = keccak256(abi.encode(mintData));
        ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(usdc), 0);
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            FULL_EXAMPLE_WITNESS_TYPEHASH,
            witness,
            DOMAIN_SEPARATOR,
            _TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );
        bytes memory sigExtra = bytes.concat(signature, bytes1(uint8(0)));
        assertEq(sigExtra.length, 66);

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), mintData._maxAmountInputToken);

        vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
        gasworks.mintWithPermit2(permit, transferDetails, owner, witness, sigExtra, mintData, permit2);
    }

    function testCannotSwapWithPermit2InvalidNonce() public {
        uint256 nonce = 0;
        bytes32 witness = keccak256(abi.encode(mintData));
        ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(usdc), nonce);
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            FULL_EXAMPLE_WITNESS_TYPEHASH,
            witness,
            DOMAIN_SEPARATOR,
            _TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), mintData._maxAmountInputToken);
        gasworks.mintWithPermit2(permit, transferDetails, owner, witness, signature, mintData, permit2);

        vm.expectRevert(InvalidNonce.selector);
        gasworks.mintWithPermit2(permit, transferDetails, owner, witness, signature, mintData, permit2);
    }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    function testMintWithPermit2() public {
        ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(usdc), 0);
        bytes32 witness = keccak256(abi.encode(mintData));
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            FULL_EXAMPLE_WITNESS_TYPEHASH,
            witness,
            DOMAIN_SEPARATOR,
            _TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), mintData._maxAmountInputToken);

        gasworks.mintWithPermit2(permit, transferDetails, owner, witness, signature, mintData, permit2);

        assertEq(usdc.balanceOf(address(gasworks)), 0);
        assertEq(usdc.allowance(owner, address(gasworks)), 0);
        assertGe(AP60.balanceOf(owner), mintData._amountSetToken);
    }

    function testMintWithPermit2RandomNonce(uint256 nonce) public {
        bytes32 witness = keccak256(abi.encode(mintData));
        ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(usdc), nonce);
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            FULL_EXAMPLE_WITNESS_TYPEHASH,
            witness,
            DOMAIN_SEPARATOR,
            _TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), mintData._maxAmountInputToken);

        gasworks.mintWithPermit2(permit, transferDetails, owner, witness, signature, mintData, permit2);

        assertEq(usdc.balanceOf(address(gasworks)), 0);
        assertEq(usdc.allowance(owner, address(gasworks)), 0);
        assertGe(AP60.balanceOf(owner), mintData._amountSetToken);
    }
}
