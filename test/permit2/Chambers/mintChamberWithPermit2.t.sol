// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import { Test } from "forge-std/Test.sol";
import { console } from "forge-std/console.sol";
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
    address internal constant usdcAddressOnEthereum = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant addyAdderssOnEthereum = 0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF;
    address internal constant issuerWizardAddress = 0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449;
    address internal constant tradeIssuerV2OnEthereum = 0xbbCA2AcBd87Ce7A5e01fb56914d41F6a7e5C5A56;

    ERC20 internal constant USDC = ERC20(usdcAddressOnEthereum);
    IChamber internal constant ADDY = IChamber(addyAdderssOnEthereum);

    uint256 internal ownerPrivateKey;
    address internal owner;

    bytes32 internal domainSeparator;
    address internal permit2;
    // bytes internal res;
    uint256 internal amountToMint = 10e18;
    bytes res;

    //Permit2 witness types
    bytes internal constant TOKEN_PERMISSIONS_TYPE =
        "TokenPermissions(address token,uint256 amount)";
    bytes internal constant PERMIT_WITNESS_TRANSFER_FROM_TYPE =
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,";
    // MintChamber
    bytes private constant SWAP_CALL_INSTRUCTION_TYPE =
        "SwapCallInstruction(address sellToken,uint256 sellAmount,address buyToken,uint256 minBuyAmount,address swapTarget,address swapAllowanceTarget,bytes swapCallData)";

    bytes private constant MINT_DATA_TYPE =
        "MintData(address archToken,uint256 archTokenAmount,address inputToken,uint256 inputTokenMaxAmount,address issuer,SwapCallInstruction[] swapCallInstructions)";
    string internal constant PERMIT2_MINT_DATA_TYPE = string(
        abi.encodePacked(
            "MintData witness)", MINT_DATA_TYPE, SWAP_CALL_INSTRUCTION_TYPE, TOKEN_PERMISSIONS_TYPE
        )
    );

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        gasworks = new Gasworks(
            0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d, 
            0x1c0c05a2aA31692e5dc9511b04F651db9E4d8320, 
            tradeIssuerV2OnEthereum
        );
        gasworks.setTokens(usdcAddressOnEthereum);
        gasworks.setTokens(addyAdderssOnEthereum);
        permit2 = deployPermit2();
        domainSeparator = EIP712(permit2).DOMAIN_SEPARATOR();

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        deal(usdcAddressOnEthereum, owner, 10000e6);

        vm.prank(owner);
        USDC.approve(permit2, type(uint256).max);

        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(amountToMint));
        inputs[3] = Conversor.iToHex(abi.encode(addyAdderssOnEthereum));
        inputs[4] = Conversor.iToHex(abi.encode(usdcAddressOnEthereum));
        inputs[5] = Conversor.iToHex(abi.encode(true));
        res = vm.ffi(inputs);

        vm.label(0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF, "yvUSDC");
        vm.label(0x3B27F92C0e212C671EA351827EDF93DB27cc0c65, "yvUSDT");
        vm.label(0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF, "yvDAI");
        vm.label(usdcAddressOnEthereum, "USDC");
        vm.label(0xdAC17F958D2ee523a2206206994597C13D831ec7, "USDT");
        vm.label(0x6B175474E89094C44Da98b954EedeAC495271d0F, "DAI");
        vm.label(addyAdderssOnEthereum, "ADDY");
        vm.label(issuerWizardAddress, "IssuerWizard");
        vm.label(tradeIssuerV2OnEthereum, "TraderIssuerV2");
    }

    // /*//////////////////////////////////////////////////////////////
    //                           REVERT
    // //////////////////////////////////////////////////////////////*/

    // /**
    //  * [REVERT] Should revert because the signature length is invalid
    //  */
    // function testCannotMintChamberWithPermit2InvalidSignatureLength() public {
    //     (
    //         ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
    //         uint256 _maxPayAmount
    //     ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
    //     mintData = IGasworks.MintData(
    //         ADDY,
    //         IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
    //         USDC,
    //         _maxPayAmount,
    //         amountToMint
    //     );

    //     uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(USDC), currentNonce, _maxPayAmount);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );
    //     bytes memory sigExtra = bytes.concat(signature, bytes1(uint8(0)));
    //     assertEq(sigExtra.length, 66);

    //     vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
    //     gasworks.mintChamberWithPermit2(
    //         permit, owner, sigExtra, mintData, _contractCallInstructions
    //     );
    // }

    // /**
    //  * [REVERT] Should revert because the nonce was used twice and should only be used once
    //  */
    // function testCannotMintChamberWithPermit2InvalidNonce() public {
    //     (
    //         ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
    //         uint256 _maxPayAmount
    //     ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
    //     mintData = IGasworks.MintData(
    //         ADDY,
    //         IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
    //         USDC,
    //         _maxPayAmount,
    //         amountToMint
    //     );

    //     uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(USDC), currentNonce, _maxPayAmount);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     gasworks.mintChamberWithPermit2(
    //         permit, owner, signature, mintData, _contractCallInstructions
    //     );

    //     vm.expectRevert(InvalidNonce.selector);
    //     gasworks.mintChamberWithPermit2(
    //         permit, owner, signature, mintData, _contractCallInstructions
    //     );
    // }

    // /**
    //  * [REVERT] Should revert because the signature is expired
    //  */
    // function testCannotMintChamberWithPermit2SignatureExpired() public {
    //     (
    //         ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
    //         uint256 _maxPayAmount
    //     ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
    //     mintData = IGasworks.MintData(
    //         ADDY,
    //         IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
    //         USDC,
    //         _maxPayAmount,
    //         amountToMint
    //     );

    //     uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(USDC), currentNonce, _maxPayAmount);
    //     permit.deadline = 2 ** 255 - 1;
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     vm.warp(2 ** 255 + 1);

    //     vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, permit.deadline));
    //     gasworks.mintChamberWithPermit2(
    //         permit, owner, signature, mintData, _contractCallInstructions
    //     );
    // }

    // /**
    //  * [REVERT] Should revert because the mintData is invalid
    //  */
    // function testCannotMintChamberWithPermit2InvalidPayload() public {
    //     (
    //         ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
    //         uint256 _maxPayAmount
    //     ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
    //     mintData = IGasworks.MintData(
    //         ADDY,
    //         IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
    //         USDC,
    //         _maxPayAmount,
    //         amountToMint
    //     );

    //     _contractCallInstructions[0]._callData = bytes("bad data");

    //     uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(USDC), currentNonce, _maxPayAmount);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     vm.expectRevert();
    //     gasworks.mintChamberWithPermit2(
    //         permit, owner, signature, mintData, _contractCallInstructions
    //     );
    // }

    // /**
    //  * [REVERT] Should revert because sellToken is not permitted
    //  */
    // function testCannotMintChamberWithPermit2InvalidToken() public {
    //     (
    //         ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
    //         uint256 _maxPayAmount
    //     ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
    //     mintData = IGasworks.MintData(
    //         ADDY,
    //         IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
    //         USDC,
    //         _maxPayAmount,
    //         amountToMint
    //     );

    //     uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063, currentNonce, 1e1);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     vm.expectRevert(
    //         abi.encodeWithSelector(
    //             IGasworks.InvalidToken.selector, 0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063
    //         )
    //     );
    //     gasworks.mintChamberWithPermit2(
    //         permit, owner, signature, mintData, _contractCallInstructions
    //     );
    // }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should make a mint of ADDY with USDC using permit2
     */
    function testMintChamberWithPermit2() public {
        IGasworks.MintData memory mintData;

        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _maxPayAmount
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));

        IGasworks.SwapCallInstruction[] memory swapCallInstructions =
            new IGasworks.SwapCallInstruction[](_contractCallInstructions.length);

        for (uint256 i = 0; i < _contractCallInstructions.length;) {
            IGasworks.SwapCallInstruction memory instruction = IGasworks.SwapCallInstruction(
                address(_contractCallInstructions[i]._sellToken),
                _contractCallInstructions[i]._sellAmount,
                address(_contractCallInstructions[i]._buyToken),
                _contractCallInstructions[i]._minBuyAmount,
                _contractCallInstructions[i]._target,
                _contractCallInstructions[i]._allowanceTarget,
                _contractCallInstructions[i]._callData
            );

            swapCallInstructions[i] = instruction;
            unchecked {
                ++i;
            }
        }

        mintData = IGasworks.MintData(
            addyAdderssOnEthereum,
            amountToMint,
            usdcAddressOnEthereum,
            _maxPayAmount,
            address(issuerWizardAddress),
            swapCallInstructions
        );

        uint256 currentNonce = USDC.nonces(owner);

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: usdcAddressOnEthereum,
                amount: _maxPayAmount
            }),
            nonce: currentNonce,
            deadline: block.timestamp + 100
        });

        bytes memory concatenatedHashedSwapCallInstructions;
        for (uint256 i = 0; i < mintData.swapCallInstructions.length;) {
            bytes32 hashedSwapCallInstruction = keccak256(
                abi.encode(
                    keccak256(abi.encodePacked(SWAP_CALL_INSTRUCTION_TYPE)),
                    mintData.swapCallInstructions[i].sellToken,
                    mintData.swapCallInstructions[i].sellAmount,
                    mintData.swapCallInstructions[i].buyToken,
                    mintData.swapCallInstructions[i].minBuyAmount,
                    mintData.swapCallInstructions[i].swapTarget,
                    mintData.swapCallInstructions[i].swapAllowanceTarget,
                    keccak256(mintData.swapCallInstructions[i].swapCallData)
                )
            );

            concatenatedHashedSwapCallInstructions =
                bytes.concat(concatenatedHashedSwapCallInstructions, hashedSwapCallInstruction);
            unchecked {
                ++i;
            }
        }

        bytes32 witness = keccak256(
            abi.encode(
                keccak256(abi.encodePacked(MINT_DATA_TYPE)),
                mintData.archToken,
                mintData.archTokenAmount,
                mintData.inputToken,
                mintData.inputTokenMaxAmount,
                mintData.issuer,
                keccak256(concatenatedHashedSwapCallInstructions)
            )
        );

        // bytes32 domainSeparator = keccak256(abi.encode(TYPE_HASH, NAME_HASH, block.chainid, usdcAddressOnEthereum));
        bytes32 tokenPermissions =
            keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, permit.permitted));
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        keccak256(
                            abi.encodePacked(
                                PERMIT_WITNESS_TRANSFER_FROM_TYPE, PERMIT2_MINT_DATA_TYPE
                            )
                        ),
                        tokenPermissions,
                        address(gasworks),
                        permit.nonce,
                        permit.deadline,
                        witness
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, msgHash);
        bytes memory signature = bytes.concat(r, s, bytes1(v));

        gasworks.mintWithPermit2(permit, owner, signature, mintData);

        assertEq(IERC20(addyAdderssOnEthereum).balanceOf(owner), amountToMint);
    }
}
