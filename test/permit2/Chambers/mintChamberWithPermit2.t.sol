// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
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

contract GaslessTest is Test, Permit2Utils, ChamberTestUtils, DeployPermit2 {
    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeERC20 for IERC20;

    bytes32 internal constant TOKEN_PERMISSIONS_TYPEHASH =
        keccak256("TokenPermissions(address token,uint256 amount)");

    Gasworks internal gasworks;
    IERC20 internal constant USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IChamber internal constant ADDY = IChamber(0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF);

    uint256 internal ownerPrivateKey;
    address internal owner;
    IGasworks.MintChamberData internal mintData;
    bytes32 internal domainSeparator;
    address internal permit2;
    bytes internal res;
    uint256 internal amountToMint = 100e18;

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
        permit2 = deployPermit2();
        domainSeparator = EIP712(permit2).DOMAIN_SEPARATOR();

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(amountToMint));
        inputs[3] = Conversor.iToHex(abi.encode(address(ADDY)));
        inputs[4] = Conversor.iToHex(abi.encode(address(USDC)));
        inputs[5] = Conversor.iToHex(abi.encode(true));
        res = vm.ffi(inputs);

        deal(address(USDC), owner, 1500e6);

        vm.prank(owner);
        USDC.approve(permit2, type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                              REVERT
    //////////////////////////////////////////////////////////////*/

    /**
     * [REVERT] Should revert because the signature length is invalid
     */
    function testCannotMintChamberWithPermit2InvalidSignatureLength() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _maxPayAmount
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        mintData = IGasworks.MintChamberData(
            ADDY,
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            USDC,
            _maxPayAmount,
            amountToMint
        );

        uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(USDC), currentNonce, _maxPayAmount);
        bytes memory signature = getSignature(
            permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
        );
        bytes memory sigExtra = bytes.concat(signature, bytes1(uint8(0)));
        assertEq(sigExtra.length, 66);

        vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
        gasworks.mintChamberWithPermit2(
            permit, owner, sigExtra, mintData, _contractCallInstructions
        );
    }

    /**
     * [REVERT] Should revert because the nonce was used twice and should only be used once
     */
    function testCannotMintChamberWithPermit2InvalidNonce() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _maxPayAmount
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        mintData = IGasworks.MintChamberData(
            ADDY,
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            USDC,
            _maxPayAmount,
            amountToMint
        );

        uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(USDC), currentNonce, _maxPayAmount);
        bytes memory signature = getSignature(
            permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
        );

        gasworks.mintChamberWithPermit2(
            permit, owner, signature, mintData, _contractCallInstructions
        );

        vm.expectRevert(InvalidNonce.selector);
        gasworks.mintChamberWithPermit2(
            permit, owner, signature, mintData, _contractCallInstructions
        );
    }

    /**
     * [REVERT] Should revert because the signature is expired
     */
    function testCannotMintChamberWithPermit2SignatureExpired() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _maxPayAmount
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        mintData = IGasworks.MintChamberData(
            ADDY,
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            USDC,
            _maxPayAmount,
            amountToMint
        );

        uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(USDC), currentNonce, _maxPayAmount);
        permit.deadline = 2 ** 255 - 1;
        bytes memory signature = getSignature(
            permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
        );

        vm.warp(2 ** 255 + 1);

        vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, permit.deadline));
        gasworks.mintChamberWithPermit2(
            permit, owner, signature, mintData, _contractCallInstructions
        );
    }

    /**
     * [REVERT] Should revert because the mintData is invalid
     */
    function testCannotMintChamberWithPermit2InvalidPayload() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _maxPayAmount
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        mintData = IGasworks.MintChamberData(
            ADDY,
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            USDC,
            _maxPayAmount,
            amountToMint
        );

        _contractCallInstructions[0]._callData = bytes("bad data");

        uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(USDC), currentNonce, _maxPayAmount);
        bytes memory signature = getSignature(
            permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
        );

        vm.expectRevert();
        gasworks.mintChamberWithPermit2(
            permit, owner, signature, mintData, _contractCallInstructions
        );
    }

    /**
     * [REVERT] Should revert because sellToken is not permitted
     */
    function testCannotMintChamberWithPermit2InvalidToken() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _maxPayAmount
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        mintData = IGasworks.MintChamberData(
            ADDY,
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            USDC,
            _maxPayAmount,
            amountToMint
        );

        uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063, currentNonce, 1e1);
        bytes memory signature = getSignature(
            permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                IGasworks.InvalidToken.selector, 0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063
            )
        );
        gasworks.mintChamberWithPermit2(
            permit, owner, signature, mintData, _contractCallInstructions
        );
    }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should make a mint of ADDY with USDC using permit2
     */
    function testMintChamberWithPermit2() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _maxPayAmount
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        mintData = IGasworks.MintChamberData(
            ADDY,
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            USDC,
            _maxPayAmount,
            amountToMint
        );

        uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(USDC), currentNonce, _maxPayAmount);
        bytes memory signature = getSignature(
            permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
        );

        gasworks.mintChamberWithPermit2(
            permit, owner, signature, mintData, _contractCallInstructions
        );

        assertEq(IERC20(address(ADDY)).balanceOf(owner), amountToMint);
    }
}
