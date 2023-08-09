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
import { WETH } from "solmate/src/tokens/WETH.sol";

contract GaslessTest is Test, Permit2Utils, ChamberTestUtils, DeployPermit2 {
    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeERC20 for IERC20;

    bytes32 internal constant TOKEN_PERMISSIONS_TYPEHASH =
        keccak256("TokenPermissions(address token,uint256 amount)");

    address internal constant usdcAddressOnEthereum = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant addyAddressOnEthereum = 0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF;
    address internal constant issuerWizardAddress = 0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449;
    address internal constant tradeIssuerV2OnEthereum = 0xbbCA2AcBd87Ce7A5e01fb56914d41F6a7e5C5A56;

    Gasworks internal gasworks;
    IERC20 internal constant USDC = IERC20(usdcAddressOnEthereum);
    IChamber internal constant ADDY = IChamber(addyAddressOnEthereum);
    WETH public constant WRAPPED_ETH = WETH(payable(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2));

    uint256 internal ownerPrivateKey;
    address internal owner;
    bytes32 internal domainSeparator;
    address internal permit2;
    bytes internal res;
    uint256 internal amountToRedeem = 10e18;

    //Permit2 witness types
    bytes internal constant TOKEN_PERMISSIONS_TYPE =
        "TokenPermissions(address token,uint256 amount)";
    bytes internal constant PERMIT_WITNESS_TRANSFER_FROM_TYPE =
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,";
    // RedeemChamber
    bytes private constant SWAP_CALL_INSTRUCTION_TYPE =
        "SwapCallInstruction(address sellToken,uint256 sellAmount,address buyToken,uint256 minBuyAmount,address swapTarget,address swapAllowanceTarget,bytes swapCallData)";
    bytes private constant REDEEM_DATA_TYPE =
        "RedeemData(address archToken,uint256 archTokenAmount,address outputToken,uint256 outputTokenMinAmount,address issuer,SwapCallInstruction[] swapCallInstructions)";
    string internal constant PERMIT2_REDEEM_DATA_TYPE = string(
        abi.encodePacked(
            "RedeemData witness)",
            REDEEM_DATA_TYPE,
            SWAP_CALL_INSTRUCTION_TYPE,
            TOKEN_PERMISSIONS_TYPE
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
        gasworks.setTokens(address(USDC));
        gasworks.setTokens(address(ADDY));
        gasworks.setTokens(address(WRAPPED_ETH));
        permit2 = deployPermit2();
        domainSeparator = EIP712(permit2).DOMAIN_SEPARATOR();

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        deal(address(ADDY), owner, amountToRedeem);
        vm.prank(owner);
        IERC20(address(ADDY)).approve(permit2, type(uint256).max);

        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(amountToRedeem));
        inputs[3] = Conversor.iToHex(abi.encode(address(ADDY)));
        inputs[4] = Conversor.iToHex(abi.encode(address(USDC)));
        inputs[5] = Conversor.iToHex(abi.encode(false));
        res = vm.ffi(inputs);

        vm.label(0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF, "yvUSDC");
        vm.label(0x3B27F92C0e212C671EA351827EDF93DB27cc0c65, "yvUSDT");
        vm.label(0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF, "yvDAI");
        vm.label(usdcAddressOnEthereum, "USDC");
        vm.label(0xdAC17F958D2ee523a2206206994597C13D831ec7, "USDT");
        vm.label(0x6B175474E89094C44Da98b954EedeAC495271d0F, "DAI");
        vm.label(addyAddressOnEthereum, "ADDY");
        vm.label(issuerWizardAddress, "IssuerWizard");
        vm.label(tradeIssuerV2OnEthereum, "TraderIssuerV2");
    }

    // /*//////////////////////////////////////////////////////////////
    //                           REVERT
    // //////////////////////////////////////////////////////////////*/

    // /**
    //  * [REVERT] Should revert because the signature length is invalid
    //  */
    // function testCannotRedeemChamberWithPermit2InvalidSignatureLength() public {
    //     (
    //         ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
    //         uint256 _minOutputReceive
    //     ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
    //     redeemData = IGasworks.RedeemData(
    //         ADDY,
    //         IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
    //         USDC,
    //         _minOutputReceive,
    //         amountToRedeem
    //     );
    //     uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(ADDY), currentNonce, amountToRedeem);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );
    //     bytes memory sigExtra = bytes.concat(signature, bytes1(uint8(0)));
    //     assertEq(sigExtra.length, 66);

    //     vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
    //     gasworks.redeemChamberWithPermit2(
    //         permit, owner, sigExtra, redeemData, _contractCallInstructions, false
    //     );
    // }

    // /**
    //  * [REVERT] Should revert because the nonce was used twice and should only be used once
    //  */
    // function testCannotRedeemChamberWithPermit2InvalidNonce() public {
    //     (
    //         ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
    //         uint256 _minOutputReceive
    //     ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
    //     redeemData = IGasworks.RedeemData(
    //         ADDY,
    //         IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
    //         USDC,
    //         _minOutputReceive,
    //         amountToRedeem
    //     );
    //     uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(ADDY), currentNonce, amountToRedeem);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     gasworks.redeemChamberWithPermit2(
    //         permit, owner, signature, redeemData, _contractCallInstructions, false
    //     );

    //     vm.expectRevert(InvalidNonce.selector);
    //     gasworks.redeemChamberWithPermit2(
    //         permit, owner, signature, redeemData, _contractCallInstructions, false
    //     );
    // }

    // /**
    //  * [REVERT] Should revert because the signature is expired
    //  */
    // function testCannotRedeemChamberWithPermit2SignatureExpired() public {
    //     (
    //         ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
    //         uint256 _minOutputReceive
    //     ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
    //     redeemData = IGasworks.RedeemData(
    //         ADDY,
    //         IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
    //         USDC,
    //         _minOutputReceive,
    //         amountToRedeem
    //     );
    //     uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(ADDY), currentNonce, amountToRedeem);
    //     permit.deadline = 2 ** 255 - 1;
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     vm.warp(2 ** 255 + 1);

    //     vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, permit.deadline));
    //     gasworks.redeemChamberWithPermit2(
    //         permit, owner, signature, redeemData, _contractCallInstructions, false
    //     );
    // }

    // /**
    //  * [REVERT] Should revert because the redeemData is invalid
    //  */
    // function testCannotRedeemChamberWithPermit2InvalidRedeemData() public {
    //     (
    //         ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
    //         uint256 _minOutputReceive
    //     ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
    //     redeemData = IGasworks.RedeemData(
    //         ADDY,
    //         IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
    //         USDC,
    //         _minOutputReceive,
    //         amountToRedeem
    //     );
    //     uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(ADDY), currentNonce, amountToRedeem);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     redeemData = IGasworks.RedeemData(
    //         ADDY,
    //         IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
    //         USDC,
    //         _minOutputReceive,
    //         amountToRedeem + 1
    //     );

    //     vm.expectRevert();
    //     gasworks.redeemChamberWithPermit2(
    //         permit, owner, signature, redeemData, _contractCallInstructions, false
    //     );
    // }

    // /**
    //  * [REVERT] Should revert because the buyToken is not permitted
    //  */
    // function testCannotRedeemChamberWithPermit2InvalidBuyToken() public {
    //     (
    //         ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
    //         uint256 _minOutputReceive
    //     ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
    //     redeemData = IGasworks.RedeemData(
    //         ADDY,
    //         IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
    //         IERC20(0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063),
    //         _minOutputReceive,
    //         amountToRedeem
    //     );
    //     uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(ADDY), currentNonce, amountToRedeem);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     vm.expectRevert(
    //         abi.encodeWithSelector(
    //             IGasworks.InvalidToken.selector, 0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063
    //         )
    //     );
    //     gasworks.redeemChamberWithPermit2(
    //         permit, owner, signature, redeemData, _contractCallInstructions, false
    //     );
    // }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should make a redeem of ADDY to USDC with permit2
     */
    function testRedeemChamberWithPermit2() public {
        IGasworks.RedeemData memory redeemData;

        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _minOutputReceive
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

        redeemData = IGasworks.RedeemData(
            addyAddressOnEthereum,
            amountToRedeem,
            usdcAddressOnEthereum,
            _minOutputReceive,
            issuerWizardAddress,
            swapCallInstructions
        );

        uint256 currentNonce = ERC20(address(USDC)).nonces(owner);

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: addyAddressOnEthereum,
                amount: amountToRedeem
            }),
            nonce: currentNonce,
            deadline: block.timestamp + 100
        });

        bytes memory concatenatedHashedSwapCallInstructions;
        for (uint256 i = 0; i < redeemData.swapCallInstructions.length;) {
            bytes32 hashedSwapCallInstruction = keccak256(
                abi.encode(
                    keccak256(abi.encodePacked(SWAP_CALL_INSTRUCTION_TYPE)),
                    redeemData.swapCallInstructions[i].sellToken,
                    redeemData.swapCallInstructions[i].sellAmount,
                    redeemData.swapCallInstructions[i].buyToken,
                    redeemData.swapCallInstructions[i].minBuyAmount,
                    redeemData.swapCallInstructions[i].swapTarget,
                    redeemData.swapCallInstructions[i].swapAllowanceTarget,
                    keccak256(redeemData.swapCallInstructions[i].swapCallData)
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
                keccak256(abi.encodePacked(REDEEM_DATA_TYPE)),
                redeemData.archToken,
                redeemData.archTokenAmount,
                redeemData.outputToken,
                redeemData.outputTokenMinAmount,
                redeemData.issuer,
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
                                PERMIT_WITNESS_TRANSFER_FROM_TYPE, PERMIT2_REDEEM_DATA_TYPE
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

        gasworks.redeemWithPermit2(permit, owner, signature, redeemData, false);
        assertGe(USDC.balanceOf(owner), _minOutputReceive);
    }

    // /**
    //  * [SUCCESS] Should make a redeem of ADDY to ETH with permit2
    //  */
    // function testRedeemChamberWithPermit2ToNative() public {
    //     string[] memory inputs = new string[](6);
    //     inputs[0] = "node";
    //     inputs[1] = "scripts/fetch-arch-quote.js";
    //     inputs[2] = Conversor.iToHex(abi.encode(amountToRedeem));
    //     inputs[3] = Conversor.iToHex(abi.encode(address(ADDY)));
    //     inputs[4] = Conversor.iToHex(abi.encode(address(WRAPPED_ETH)));
    //     inputs[5] = Conversor.iToHex(abi.encode(false));
    //     res = vm.ffi(inputs);
    //     (
    //         ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
    //         uint256 _minOutputReceive
    //     ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
    //     redeemData = IGasworks.RedeemData(
    //         ADDY,
    //         IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
    //         IERC20(address(WRAPPED_ETH)),
    //         _minOutputReceive,
    //         amountToRedeem
    //     );

    //     uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(ADDY), currentNonce, amountToRedeem);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     gasworks.redeemChamberWithPermit2(
    //         permit, owner, signature, redeemData, _contractCallInstructions, true
    //     );
    //     assertGe(owner.balance, _minOutputReceive);
    // }

    // /**
    //  * [SUCCESS] Should make a redeem of ADDY to WETH with permit2
    //  */
    // function testRedeemChamberWithPermit2ToWrappedNative() public {
    //     string[] memory inputs = new string[](6);
    //     inputs[0] = "node";
    //     inputs[1] = "scripts/fetch-arch-quote.js";
    //     inputs[2] = Conversor.iToHex(abi.encode(amountToRedeem));
    //     inputs[3] = Conversor.iToHex(abi.encode(address(ADDY)));
    //     inputs[4] = Conversor.iToHex(abi.encode(address(WRAPPED_ETH)));
    //     inputs[5] = Conversor.iToHex(abi.encode(false));
    //     res = vm.ffi(inputs);
    //     (
    //         ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
    //         uint256 _minOutputReceive
    //     ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
    //     redeemData = IGasworks.RedeemData(
    //         ADDY,
    //         IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
    //         IERC20(address(WRAPPED_ETH)),
    //         _minOutputReceive,
    //         amountToRedeem
    //     );

    //     uint256 currentNonce = ERC20(address(USDC)).nonces(owner);
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(ADDY), currentNonce, amountToRedeem);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     gasworks.redeemChamberWithPermit2(
    //         permit, owner, signature, redeemData, _contractCallInstructions, false
    //     );
    //     assertGe(WRAPPED_ETH.balanceOf(owner), _minOutputReceive);
    // }
}
