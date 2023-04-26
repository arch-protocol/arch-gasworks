// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import {Test} from "forge-std/Test.sol";
import {Gasworks} from "src/Gasworks.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {Conversor} from "test/utils/HexUtils.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {PermitSignature} from "permit2/test/utils/PermitSignature.sol";
import {Permit2} from "permit2/src/Permit2.sol";
import {TokenProvider} from "permit2/test/utils/TokenProvider.sol";
import {SignatureVerification} from "permit2/src/libraries/SignatureVerification.sol";
import {InvalidNonce, SignatureExpired} from "permit2/src/PermitErrors.sol";
import {Permit2Utils} from "test/utils/Permit2Utils.sol";
import {ChamberTestUtils} from "chambers-peripherals/test/utils/ChamberTestUtils.sol";
import {ITradeIssuerV2} from "chambers-peripherals/src/interfaces/ITradeIssuerV2.sol";
import {IChamber} from "chambers/interfaces/IChamber.sol";
import {IIssuerWizard} from "chambers/interfaces/IIssuerWizard.sol";

contract GaslessTest is Test, PermitSignature, TokenProvider, Permit2Utils, ChamberTestUtils {
    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeERC20 for IERC20;

    string private constant WITNESS_TYPE_STRING =
        "MintChamberData witness)MintChamberData(ContractCallInstruction[] _contractCallInstructions,IChamber _chamber,IIssuerWizard _issuerWizard,IERC20 _baseToken,uint256 _maxPayAmount,uint256 _mintAmount)ContractCallInstruction(address _target,address _allowanceTarget,IERC20 _sellToken,uint256 _sellAmount,IERC20 _buyToken,uint256 _minBuyAmount,bytes _calldata)TokenPermissions(address token,uint256 amount)";

    bytes32 constant FULL_EXAMPLE_WITNESS_TYPEHASH = keccak256(
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,MintChamberData witness)MintChamberData(ContractCallInstruction[] _contractCallInstructions,IChamber _chamber,IIssuerWizard _issuerWizard,IERC20 _baseToken,uint256 _maxPayAmount,uint256 _mintAmount)ContractCallInstruction(address _target,address _allowanceTarget,IERC20 _sellToken,uint256 _sellAmount,IERC20 _buyToken,uint256 _minBuyAmount,bytes _calldata)TokenPermissions(address token,uint256 amount)"
    );

    address internal constant usdcAddress = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant ADDYAddress = 0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF;

    Gasworks internal gasworks;
    IERC20 internal constant usdc = IERC20(usdcAddress);
    IChamber internal constant ADDY = IChamber(ADDYAddress);

    uint256 internal ownerPrivateKey;
    address internal owner;
    Gasworks.MintChamberData internal mintData;
    bytes32 internal DOMAIN_SEPARATOR;
    Permit2 internal permit2;
    IIssuerWizard internal issuerWizard;

    function setUp() public {
        gasworks = new Gasworks(0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d);
        gasworks.setTokens(address(usdc));
        gasworks.setTokens(address(ADDY));
        permit2 = Permit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);
        DOMAIN_SEPARATOR = permit2.DOMAIN_SEPARATOR();
        issuerWizard = IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449);

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        vm.prank(0x0A59649758aa4d66E25f08Dd01271e891fe52199);
        usdc.safeTransfer(owner, 150e6);

        uint256 amountToMint = 10e18;

        string[] memory inputs = new string[](5);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(amountToMint));
        inputs[3] = Conversor.iToHex(abi.encode(ADDYAddress));
        inputs[4] = Conversor.iToHex(abi.encode(true));
        bytes memory res = vm.ffi(inputs);
        (ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions, uint256 _maxPayAmount) =
            abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        mintData =
            Gasworks.MintChamberData(_contractCallInstructions, ADDY, issuerWizard, usdc, _maxPayAmount, amountToMint);

        vm.prank(owner);
        usdc.approve(address(permit2), mintData._maxPayAmount);
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
            getTransferDetails(address(gasworks), mintData._maxPayAmount);

        gasworks.mintChamberWithPermit2(permit, transferDetails, owner, witness, signature, mintData, permit2);

        assertEq(usdc.balanceOf(address(gasworks)), 0);
        assertEq(usdc.allowance(owner, address(gasworks)), 0);
        assertGe(IERC20(ADDYAddress).balanceOf(owner), mintData._mintAmount);
    }
}
