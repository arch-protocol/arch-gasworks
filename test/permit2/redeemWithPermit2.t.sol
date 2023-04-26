// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import {Test} from "forge-std/Test.sol";
import {Gasworks} from "src/Gasworks.sol";
import {ISetToken} from "src/interfaces/ISetToken.sol";
import {SigUtils} from "test/utils/SigUtils.sol";
import {Conversor} from "test/utils/HexUtils.sol";
import {SafeTransferLib} from "solmate/src/utils/SafeTransferLib.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {SignatureVerification} from "permit2/src/libraries/SignatureVerification.sol";
import {InvalidNonce, SignatureExpired} from "permit2/src/PermitErrors.sol";
import {Permit2Utils} from "test/utils/Permit2Utils.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {EIP712} from "permit2/src/EIP712.sol";
import {DeployPermit2} from "permit2/test/utils/DeployPermit2.sol";

contract GaslessTest is Test, Permit2Utils, DeployPermit2 {
    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeTransferLib for IERC20;
    using SafeTransferLib for ISetToken;

    bytes32 constant FULL_EXAMPLE_WITNESS_TYPEHASH = keccak256(
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,RedeemData witness)RedeemData(ISetToken _setToken,IERC20 _outputToken,uint256 _amountSetToken,uint256 _minOutputReceive, bytes[] _componentQuotes,address _issuanceModule,bool _isDebtIssuance)TokenPermissions(address token,uint256 amount)"
    );

    bytes32 public constant _TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");

    address internal constant usdcAddress = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174;
    address internal constant AP60Address = 0x6cA9C8914a14D63a6700556127D09e7721ff7D3b;
    address internal constant debtModule = 0xf2dC2f456b98Af9A6bEEa072AF152a7b0EaA40C9;
    bool internal constant _isDebtIssuance = true;

    Gasworks internal gasworks;
    IERC20 internal constant usdc = IERC20(usdcAddress);
    ISetToken internal constant AP60 = ISetToken(AP60Address);

    uint256 internal ownerPrivateKey;
    address internal owner;
    Gasworks.RedeemData internal redeemData;
    bytes32 internal DOMAIN_SEPARATOR;
    address internal permit2;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        gasworks = new Gasworks(0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d);
        gasworks.setTokens(address(usdc));
        gasworks.setTokens(address(AP60));
        permit2 = deployPermit2();
        DOMAIN_SEPARATOR = EIP712(permit2).DOMAIN_SEPARATOR();

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        vm.prank(0x3797C03Ad704f4f0A5B0FB4391a39a0919926461);
        AP60.transfer(owner, 30e18);

        uint256 setAmount = 1e18;

        string[] memory inputs = new string[](5);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(setAmount));
        inputs[3] = Conversor.iToHex(abi.encode(AP60Address));
        inputs[4] = Conversor.iToHex(abi.encode(false));
        bytes memory res = vm.ffi(inputs);
        (bytes[] memory quotes, uint256 _minOutputReceive) = abi.decode(res, (bytes[], uint256));
        redeemData = Gasworks.RedeemData(AP60, usdc, setAmount, _minOutputReceive, quotes, debtModule, _isDebtIssuance);

        vm.prank(owner);
        AP60.approve(permit2, type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                              REVERT
    //////////////////////////////////////////////////////////////*/

    /**
     * [REVERT] Should revert because the witness type hash is invalid and doesn't match the struct
     */
    function testCannotRedeemWithPermit2InvalidTypehash() public {
        bytes32 witness = keccak256(abi.encode(redeemData));
        ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(AP60), 0);
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
            getTransferDetails(address(gasworks), redeemData._amountSetToken);

        vm.expectRevert(SignatureVerification.InvalidSigner.selector);
        gasworks.redeemWithPermit2(permit, transferDetails, owner, witness, signature, redeemData);
    }

    /**
     * [REVERT] Should revert because the signature length is invalid
     */
    function testCannotRedeemWithPermit2IncorrectSigLength() public {
        bytes32 witness = keccak256(abi.encode(redeemData));
        ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(AP60), 0);
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
            getTransferDetails(address(gasworks), redeemData._amountSetToken);

        vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
        gasworks.redeemWithPermit2(permit, transferDetails, owner, witness, sigExtra, redeemData);
    }

    /**
     * [REVERT] Should revert because the nonce was used twice and should only be used once
     */
    function testCannotRedeemWithPermit2InvalidNonce() public {
        uint256 nonce = 0;
        bytes32 witness = keccak256(abi.encode(redeemData));
        ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(AP60), nonce);
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
            getTransferDetails(address(gasworks), redeemData._amountSetToken);
        gasworks.redeemWithPermit2(permit, transferDetails, owner, witness, signature, redeemData);

        vm.expectRevert(InvalidNonce.selector);
        gasworks.redeemWithPermit2(permit, transferDetails, owner, witness, signature, redeemData);
    }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should make a success redeem with permit2
     */
    function testRedeemWithPermit2() public {
        ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(AP60), 0);
        bytes32 witness = keccak256(abi.encode(redeemData));
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
            getTransferDetails(address(gasworks), redeemData._amountSetToken);

        gasworks.redeemWithPermit2(permit, transferDetails, owner, witness, signature, redeemData);

        assertEq(usdc.balanceOf(address(gasworks)), 0);
        assertEq(usdc.allowance(owner, address(gasworks)), 0);
        assertGe(AP60.balanceOf(owner), redeemData._amountSetToken);
    }

    /**
     * [SUCCESS] Should make a success redeem with permit2 with a random nonce
     */
    function testRedeemWithPermit2RandomNonce(uint256 nonce) public {
        ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(AP60), nonce);
        bytes32 witness = keccak256(abi.encode(redeemData));
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
            getTransferDetails(address(gasworks), redeemData._amountSetToken);

        gasworks.redeemWithPermit2(permit, transferDetails, owner, witness, signature, redeemData);

        assertEq(usdc.balanceOf(address(gasworks)), 0);
        assertEq(usdc.allowance(owner, address(gasworks)), 0);
        assertGe(AP60.balanceOf(owner), redeemData._amountSetToken);
    }
}
