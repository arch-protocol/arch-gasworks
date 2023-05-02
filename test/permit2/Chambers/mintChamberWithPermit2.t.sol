// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import {Test} from "forge-std/Test.sol";
import {Gasworks} from "src/Gasworks.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {Conversor} from "test/utils/HexUtils.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {SignatureVerification} from "permit2/src/libraries/SignatureVerification.sol";
import {InvalidNonce, SignatureExpired} from "permit2/src/PermitErrors.sol";
import {Permit2Utils} from "test/utils/Permit2Utils.sol";
import {ChamberTestUtils} from "chambers-peripherals/test/utils/ChamberTestUtils.sol";
import {ITradeIssuerV2} from "chambers-peripherals/src/interfaces/ITradeIssuerV2.sol";
import {IChamber} from "chambers/interfaces/IChamber.sol";
import {IIssuerWizard} from "chambers/interfaces/IIssuerWizard.sol";
import {EIP712} from "permit2/src/EIP712.sol";
import {DeployPermit2} from "permit2/test/utils/DeployPermit2.sol";

contract GaslessTest is Test, Permit2Utils, ChamberTestUtils, DeployPermit2 {
    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeERC20 for IERC20;

    Gasworks internal gasworks;
    IERC20 internal constant usdc = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IChamber internal constant ADDY = IChamber(0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF);

    uint256 internal ownerPrivateKey;
    address internal owner;
    Gasworks.MintChamberData internal mintData;
    bytes32 internal DOMAIN_SEPARATOR;
    address internal permit2;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        gasworks = new Gasworks(0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d);
        gasworks.setTokens(address(usdc));
        gasworks.setTokens(address(ADDY));
        permit2 = deployPermit2();
        DOMAIN_SEPARATOR = EIP712(permit2).DOMAIN_SEPARATOR();

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        vm.prank(0x0A59649758aa4d66E25f08Dd01271e891fe52199);
        usdc.safeTransfer(owner, 150e6);

        vm.prank(owner);
        usdc.approve(permit2, type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should make a mint of ADDY with USDC using permit2
     */
    function testMintChamberWithPermit2() public {
        uint256 amountToMint = 10e18;
        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(amountToMint));
        inputs[3] = Conversor.iToHex(abi.encode(address(ADDY)));
        inputs[4] = Conversor.iToHex(abi.encode(address(usdc)));
        inputs[5] = Conversor.iToHex(abi.encode(true));
        bytes memory res = vm.ffi(inputs);
        (ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions, uint256 _maxPayAmount) =
            abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        mintData = Gasworks.MintChamberData(
            ADDY, IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449), usdc, _maxPayAmount, amountToMint
        );

        ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(usdc), 0);
        bytes32 witness = keccak256(abi.encode(mintData));
        bytes memory signature = getSignature(
            permit,
            ownerPrivateKey,
            keccak256(
                "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,MintChamberData witness)MintChamberData(IChamber _chamber,IIssuerWizard _issuerWizard,IERC20 _baseToken,uint256 _maxPayAmount,uint256 _mintAmount)TokenPermissions(address token,uint256 amount)"
            ),
            witness,
            DOMAIN_SEPARATOR,
            keccak256("TokenPermissions(address token,uint256 amount)"),
            address(gasworks)
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), mintData._maxPayAmount);

        gasworks.mintChamberWithPermit2(
            permit, transferDetails, owner, witness, signature, mintData, _contractCallInstructions
        );

        assertEq(IERC20(address(ADDY)).balanceOf(owner), amountToMint);
    }
}
