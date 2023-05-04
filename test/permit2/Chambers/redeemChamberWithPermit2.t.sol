// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import { Conversor } from "test/utils/HexUtils.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { SignatureVerification } from "permit2/src/libraries/SignatureVerification.sol";
import { InvalidNonce, SignatureExpired } from "permit2/src/PermitErrors.sol";
import { Permit2Utils } from "test/utils/Permit2Utils.sol";
import { ChamberTestUtils } from "chambers-peripherals/test/utils/ChamberTestUtils.sol";
import { ITradeIssuerV2 } from "chambers-peripherals/src/interfaces/ITradeIssuerV2.sol";
import { IChamber } from "chambers/interfaces/IChamber.sol";
import { IIssuerWizard } from "chambers/interfaces/IIssuerWizard.sol";
import { EIP712 } from "permit2/src/EIP712.sol";
import { DeployPermit2 } from "permit2/test/utils/DeployPermit2.sol";
import { WETH } from "solmate/src/tokens/WETH.sol";

contract GaslessTest is Test, Permit2Utils, ChamberTestUtils, DeployPermit2 {
    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeERC20 for IERC20;

    bytes32 internal constant WITNESS_TYPEHASH = keccak256(
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,RedeemChamberData witness)RedeemChamberData(IChamber _chamber,IIssuerWizard _issuerWizard,IERC20 _baseToken,uint256 _minReceiveAmount,uint256 _redeemAmount)TokenPermissions(address token,uint256 amount)"
    );

    bytes32 internal constant TOKEN_PERMISSIONS_TYPEHASH =
        keccak256("TokenPermissions(address token,uint256 amount)");

    Gasworks internal gasworks;
    IERC20 internal constant USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IChamber internal constant ADDY = IChamber(0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF);
    WETH public constant WRAPPED_ETH = WETH(payable(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2));

    uint256 internal ownerPrivateKey;
    address internal owner;
    IGasworks.RedeemChamberData internal redeemData;
    bytes32 internal domainSeparator;
    address internal permit2;
    bytes internal res;
    uint256 internal nonce = 0;
    uint256 internal amountToRedeem = 1e18;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        gasworks = new Gasworks(
            0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d, 
            0x1c0c05a2aA31692e5dc9511b04F651db9E4d8320, 
            0xbbCA2AcBd87Ce7A5e01fb56914d41F6a7e5C5A56
        );
        gasworks.setTokens(address(USDC));
        gasworks.setTokens(address(ADDY));
        gasworks.setTokens(address(WRAPPED_ETH));
        permit2 = deployPermit2();
        domainSeparator = EIP712(permit2).DOMAIN_SEPARATOR();

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(amountToRedeem));
        inputs[3] = Conversor.iToHex(abi.encode(address(ADDY)));
        inputs[4] = Conversor.iToHex(abi.encode(address(USDC)));
        inputs[5] = Conversor.iToHex(abi.encode(false));
        res = vm.ffi(inputs);

        vm.prank(0x0cC2CaeD31490B546c741BD93dbba8Ab387f7F2c);
        IERC20(address(ADDY)).safeTransfer(owner, 150e18);

        vm.prank(owner);
        IERC20(address(ADDY)).approve(permit2, type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                              REVERT
    //////////////////////////////////////////////////////////////*/

    /**
     * [REVERT] Should revert because the witness type hash is invalid and doesn't match the struct
     */
    function testCannotRedeemChamberWithPermit2InvalidTypehash() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _minOutputReceive
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        redeemData = IGasworks.RedeemChamberData(
            ADDY,
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            USDC,
            _minOutputReceive,
            amountToRedeem
        );
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(ADDY), nonce);
        bytes32 witness = keccak256(abi.encode(redeemData));
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            "fake typehash",
            witness,
            domainSeparator,
            TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), amountToRedeem);

        vm.expectRevert(SignatureVerification.InvalidSigner.selector);
        gasworks.redeemChamberWithPermit2(
            permit,
            transferDetails,
            owner,
            witness,
            signature,
            redeemData,
            _contractCallInstructions,
            false
        );
    }

    /**
     * [REVERT] Should revert because the signature length is invalid
     */
    function testCannotRedeemChamberWithPermit2InvalidSignatureLength() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _minOutputReceive
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        redeemData = IGasworks.RedeemChamberData(
            ADDY,
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            USDC,
            _minOutputReceive,
            amountToRedeem
        );
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(ADDY), nonce);
        bytes32 witness = keccak256(abi.encode(redeemData));
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            WITNESS_TYPEHASH,
            witness,
            domainSeparator,
            TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );
        bytes memory sigExtra = bytes.concat(signature, bytes1(uint8(0)));
        assertEq(sigExtra.length, 66);

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), amountToRedeem);

        vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
        gasworks.redeemChamberWithPermit2(
            permit,
            transferDetails,
            owner,
            witness,
            sigExtra,
            redeemData,
            _contractCallInstructions,
            false
        );
    }

    /**
     * [REVERT] Should revert because the nonce was used twice and should only be used once
     */
    function testCannotRedeemChamberWithPermit2InvalidNonce() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _minOutputReceive
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        redeemData = IGasworks.RedeemChamberData(
            ADDY,
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            USDC,
            _minOutputReceive,
            amountToRedeem
        );
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(ADDY), nonce);
        bytes32 witness = keccak256(abi.encode(redeemData));
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            WITNESS_TYPEHASH,
            witness,
            domainSeparator,
            TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), amountToRedeem);

        gasworks.redeemChamberWithPermit2(
            permit,
            transferDetails,
            owner,
            witness,
            signature,
            redeemData,
            _contractCallInstructions,
            false
        );

        vm.expectRevert(InvalidNonce.selector);
        gasworks.redeemChamberWithPermit2(
            permit,
            transferDetails,
            owner,
            witness,
            signature,
            redeemData,
            _contractCallInstructions,
            false
        );
    }

    /**
     * [REVERT] Should revert because the signature is expired
     */
    function testCannotRedeemChamberWithPermit2SignatureExpired() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _minOutputReceive
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        redeemData = IGasworks.RedeemChamberData(
            ADDY,
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            USDC,
            _minOutputReceive,
            amountToRedeem
        );
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(ADDY), nonce);
        permit.deadline = 2 ** 255 - 1;
        bytes32 witness = keccak256(abi.encode(redeemData));
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            WITNESS_TYPEHASH,
            witness,
            domainSeparator,
            TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), amountToRedeem);

        vm.warp(2 ** 255 + 1);

        vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, permit.deadline));
        gasworks.redeemChamberWithPermit2(
            permit,
            transferDetails,
            owner,
            witness,
            signature,
            redeemData,
            _contractCallInstructions,
            false
        );
    }

    /**
     * [REVERT] Should revert because the redeemData is invalid
     */
    function testCannotRedeemChamberWithPermit2InvalidRedeemData() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _minOutputReceive
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        redeemData = IGasworks.RedeemChamberData(
            ADDY,
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            USDC,
            _minOutputReceive,
            amountToRedeem
        );
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(ADDY), nonce);
        bytes32 witness = keccak256(abi.encode(redeemData));
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            WITNESS_TYPEHASH,
            witness,
            domainSeparator,
            TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), amountToRedeem);

        redeemData = IGasworks.RedeemChamberData(
            ADDY,
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            USDC,
            _minOutputReceive,
            amountToRedeem + 1
        );

        vm.expectRevert();
        gasworks.redeemChamberWithPermit2(
            permit,
            transferDetails,
            owner,
            witness,
            signature,
            redeemData,
            _contractCallInstructions,
            false
        );
    }

    /**
     * [REVERT] Should revert because the buyToken is not permitted
     */
    function testCannotRedeemChamberWithPermit2InvalidBuyToken() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _minOutputReceive
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        redeemData = IGasworks.RedeemChamberData(
            ADDY,
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            IERC20(0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063),
            _minOutputReceive,
            amountToRedeem
        );
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(ADDY), nonce);
        bytes32 witness = keccak256(abi.encode(redeemData));
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            WITNESS_TYPEHASH,
            witness,
            domainSeparator,
            TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), amountToRedeem);

        vm.expectRevert(
            abi.encodeWithSelector(
                IGasworks.InvalidToken.selector, 0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063
            )
        );
        gasworks.redeemChamberWithPermit2(
            permit,
            transferDetails,
            owner,
            witness,
            signature,
            redeemData,
            _contractCallInstructions,
            false
        );
    }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should make a redeem of ADDY to USDC with permit2
     */
    function testRedeemChamberWithPermit2() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _minOutputReceive
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        redeemData = IGasworks.RedeemChamberData(
            ADDY,
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            USDC,
            _minOutputReceive,
            amountToRedeem
        );
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(ADDY), nonce);
        bytes32 witness = keccak256(abi.encode(redeemData));
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            WITNESS_TYPEHASH,
            witness,
            domainSeparator,
            TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), amountToRedeem);

        gasworks.redeemChamberWithPermit2(
            permit,
            transferDetails,
            owner,
            witness,
            signature,
            redeemData,
            _contractCallInstructions,
            false
        );
        assertGe(USDC.balanceOf(owner), _minOutputReceive);
    }

    /**
     * [SUCCESS] Should make a redeem of ADDY to ETH with permit2
     */
    function testRedeemChamberWithPermit2ToNative() public {
        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(amountToRedeem));
        inputs[3] = Conversor.iToHex(abi.encode(address(ADDY)));
        inputs[4] = Conversor.iToHex(abi.encode(address(WRAPPED_ETH)));
        inputs[5] = Conversor.iToHex(abi.encode(false));
        res = vm.ffi(inputs);
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _minOutputReceive
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        redeemData = IGasworks.RedeemChamberData(
            ADDY,
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            IERC20(address(WRAPPED_ETH)),
            _minOutputReceive,
            amountToRedeem
        );

        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(ADDY), nonce);
        bytes32 witness = keccak256(abi.encode(redeemData));
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            WITNESS_TYPEHASH,
            witness,
            domainSeparator,
            TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), amountToRedeem);

        gasworks.redeemChamberWithPermit2(
            permit,
            transferDetails,
            owner,
            witness,
            signature,
            redeemData,
            _contractCallInstructions,
            true
        );
        assertGe(owner.balance, _minOutputReceive);
    }

    /**
     * [SUCCESS] Should make a redeem of ADDY to WETH with permit2
     */
    function testRedeemChamberWithPermit2ToWrappedNative() public {
        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(amountToRedeem));
        inputs[3] = Conversor.iToHex(abi.encode(address(ADDY)));
        inputs[4] = Conversor.iToHex(abi.encode(address(WRAPPED_ETH)));
        inputs[5] = Conversor.iToHex(abi.encode(false));
        res = vm.ffi(inputs);
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _minOutputReceive
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        redeemData = IGasworks.RedeemChamberData(
            ADDY,
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            IERC20(address(WRAPPED_ETH)),
            _minOutputReceive,
            amountToRedeem
        );

        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(ADDY), nonce);
        bytes32 witness = keccak256(abi.encode(redeemData));
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            WITNESS_TYPEHASH,
            witness,
            domainSeparator,
            TOKEN_PERMISSIONS_TYPEHASH,
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), amountToRedeem);

        gasworks.redeemChamberWithPermit2(
            permit,
            transferDetails,
            owner,
            witness,
            signature,
            redeemData,
            _contractCallInstructions,
            false
        );
        assertGe(WRAPPED_ETH.balanceOf(owner), _minOutputReceive);
    }
}
