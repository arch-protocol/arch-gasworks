// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { SigUtils } from "test/utils/SigUtils.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { Conversor } from "test/utils/HexUtils.sol";
import { ITradeIssuerV2 } from "chambers-peripherals/src/interfaces/ITradeIssuerV2.sol";
import { IChamber } from "chambers/interfaces/IChamber.sol";
import { IIssuerWizard } from "chambers/interfaces/IIssuerWizard.sol";
import { EIP712 } from "permit2/src/EIP712.sol";
import { WETH } from "solmate/src/tokens/WETH.sol";
import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

contract GaslessTest is Test {
    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeTransferLib for ERC20;

    Gasworks internal gasworks;
    ERC20 internal constant USDC = ERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    ERC20 internal constant ADDY = ERC20(0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF);
    WETH public constant WRAPPED_ETH = WETH(payable(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2));
    SigUtils internal sigUtils;
    uint256 internal ownerPrivateKey;
    address internal owner;
    IGasworks.RedeemChamberData internal redeemData;
    bytes internal res;
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
        sigUtils = new SigUtils(ADDY.DOMAIN_SEPARATOR());

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
        ADDY.safeTransfer(owner, 150e18);
    }

    /*//////////////////////////////////////////////////////////////
                              REVERT
    //////////////////////////////////////////////////////////////*/

    /**
     * [REVERT] Should revert because the nonce was used twice and should only be used once
     */
    function testCannotRedeemChamberWithPermitInvalidNonce() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _minOutputReceive
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        redeemData = IGasworks.RedeemChamberData(
            IChamber(address(ADDY)),
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            IERC20(address(USDC)),
            _minOutputReceive,
            amountToRedeem
        );
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(gasworks),
            value: 1e18,
            nonce: 1, // set nonce to 1 instead of 0
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert("INVALID_SIGNER");
        gasworks.redeemChamberWithPermit(
            IGasworks.PermitData(
                address(ADDY),
                1e18,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            redeemData,
            _contractCallInstructions,
            false
        );
    }

    /**
     * [REVERT] Should revert because the signature is expired
     */
    function testCannotRedeemChamberWithPermitSignatureExpired() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _minOutputReceive
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        redeemData = IGasworks.RedeemChamberData(
            IChamber(address(ADDY)),
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            IERC20(address(USDC)),
            _minOutputReceive,
            amountToRedeem
        );

        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(gasworks),
            value: 1e18,
            nonce: ADDY.nonces(owner),
            deadline: 2 ** 255 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.warp(2 ** 255 + 1);

        vm.expectRevert("PERMIT_DEADLINE_EXPIRED");
        gasworks.redeemChamberWithPermit(
            IGasworks.PermitData(
                address(ADDY),
                1e18,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            redeemData,
            _contractCallInstructions,
            false
        );
    }

    /**
     * [REVERT] Should revert because the redeemData is invalid
     */
    function testCannotRedeemChamberWithPermitInvalidRedeemData() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _minOutputReceive
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        redeemData = IGasworks.RedeemChamberData(
            IChamber(address(ADDY)),
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            IERC20(address(USDC)),
            _minOutputReceive,
            amountToRedeem
        );

        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(gasworks),
            value: 1e18,
            nonce: ADDY.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        redeemData = IGasworks.RedeemChamberData(
            IChamber(address(ADDY)),
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            IERC20(address(USDC)),
            _minOutputReceive,
            amountToRedeem + 1
        );

        vm.expectRevert();
        gasworks.redeemChamberWithPermit(
            IGasworks.PermitData(
                address(ADDY),
                1e18,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            redeemData,
            _contractCallInstructions,
            false
        );
    }

    /**
     * [REVERT] Should revert because the buyToken is not permitted
     */
    function testCannotRedeemChamberWithPermitInvalidBuyToken() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _minOutputReceive
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        redeemData = IGasworks.RedeemChamberData(
            IChamber(address(ADDY)),
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            IERC20(0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063),
            _minOutputReceive,
            amountToRedeem
        );
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(gasworks),
            value: 1e18,
            nonce: ADDY.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert(abi.encodeWithSelector(IGasworks.InvalidToken.selector, address(0x123123)));
        gasworks.redeemChamberWithPermit(
            IGasworks.PermitData(
                address(0x123123),
                1e18,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
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
    function testRedeemChamberWithPermit() public {
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _minOutputReceive
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
        redeemData = IGasworks.RedeemChamberData(
            IChamber(address(ADDY)),
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            IERC20(address(USDC)),
            _minOutputReceive,
            amountToRedeem
        );

        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(gasworks),
            value: 1e18,
            nonce: ADDY.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        gasworks.redeemChamberWithPermit(
            IGasworks.PermitData(
                address(ADDY),
                1e18,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
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
            IChamber(address(ADDY)),
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            IERC20(address(WRAPPED_ETH)),
            _minOutputReceive,
            amountToRedeem
        );

        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(gasworks),
            value: 1e18,
            nonce: ADDY.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        gasworks.redeemChamberWithPermit(
            IGasworks.PermitData(
                address(ADDY),
                1e18,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
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
            IChamber(address(ADDY)),
            IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
            IERC20(address(WRAPPED_ETH)),
            _minOutputReceive,
            amountToRedeem
        );

        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(gasworks),
            value: 1e18,
            nonce: ADDY.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        gasworks.redeemChamberWithPermit(
            IGasworks.PermitData(
                address(ADDY),
                1e18,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            redeemData,
            _contractCallInstructions,
            false
        );
        assertGe(WRAPPED_ETH.balanceOf(owner), _minOutputReceive);
    }
}
