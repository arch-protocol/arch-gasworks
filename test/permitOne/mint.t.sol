// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import "forge-std/StdJson.sol";
import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import { Conversor } from "test/utils/HexUtils.sol";
import { ITradeIssuerV3 } from "chambers-peripherals/src/interfaces/ITradeIssuerV3.sol";
import { IChamber } from "chambers/interfaces/IChamber.sol";
import { IIssuerWizard } from "chambers/interfaces/IIssuerWizard.sol";
import { SigUtils } from "test/utils/SigUtils.sol";
import { IERC20Permit } from
    "openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol";
import { Permit2Utils } from "test/utils/Permit2Utils.sol";
import { DeployPermit2 } from "permit2/test/utils/DeployPermit2.sol";

contract GaslessTest is Test, Permit2Utils, DeployPermit2 {
    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeERC20 for IERC20;
    using stdJson for string;

    string root;
    string path;
    string json;

    IERC20 internal USDC;
    IChamber internal constant AAGG = IChamber(POLYGON_AAGG);

    Gasworks internal gasworks;
    SigUtils internal sigUtils;

    IGasworks.MintChamberData internal mintData;
    ITradeIssuerV3.ContractCallInstruction[] internal contractCallInstructions;
    uint256 internal MINT_AMOUNT;
    uint256 internal MAX_PAY_AMOUNT;
    uint256 internal nonce;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        addLabbels();
        root = vm.projectRoot();
        path = string.concat(root, "/data/permitOne/mint/testMintAaggWithUsdcE.json");
        json = vm.readFile(path);
        (
            uint256 chainId,
            uint256 blockNumber,
            address archToken,
            uint256 archTokenAmount,
            address fromToken,
            uint256 maxPayAmount,
            ITradeIssuerV3.ContractCallInstruction[] memory callInstrictions
        ) = parseMintQuoteFromJson(json);

        USDC = IERC20(fromToken);
        MINT_AMOUNT = archTokenAmount;
        MAX_PAY_AMOUNT = maxPayAmount;

        mintData = IGasworks.MintChamberData(
            IChamber(archToken),
            IIssuerWizard(POLYGON_ISSUER_WIZARD),
            IERC20(fromToken),
            maxPayAmount,
            archTokenAmount
        );
        contractCallInstructions = callInstrictions;
        

        vm.createSelectFork("polygon", blockNumber);
        gasworks = deployGasworks(chainId);
        sigUtils = new SigUtils(ERC20(address(USDC)).DOMAIN_SEPARATOR());

        deal(address(USDC), ALICE, maxPayAmount);
        nonce = IERC20Permit(address(USDC)).nonces(ALICE);
    }

    /*//////////////////////////////////////////////////////////////
                              REVERT
    //////////////////////////////////////////////////////////////*/

    /**
     * [REVERT] Should revert because the permit is expired
     */
    function testCannotMintWithExpiredPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: MAX_PAY_AMOUNT,
            nonce: nonce,
            deadline: 2 ** 255 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.warp(2 ** 255 + 1); // fast forwards one second past the deadline

        vm.expectRevert("Permit: permit is expired");
        gasworks.mintWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                MAX_PAY_AMOUNT,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            mintData,
            contractCallInstructions
        );
    }

    /**
     * [REVERT] Should revert because the signer of the permit
     * is not the owner of the tokens
     */
    function testCannotMintWithInvalidSigner() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: MAX_PAY_AMOUNT,
            nonce: nonce,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xB0B, digest); // 0xB0B signs but 0xA11CE is owner

        vm.expectRevert("Permit: invalid signature");
        gasworks.mintWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                MAX_PAY_AMOUNT,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            mintData,
            contractCallInstructions
        );
    }

    /**
     * [REVERT] Should revert because the nonce is invalid
     */
    function testCannotMintWithInvalidNonce() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: MAX_PAY_AMOUNT,
            nonce: 1, // set nonce to 1 instead of 0
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.expectRevert("Permit: invalid signature");
        gasworks.mintWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                MAX_PAY_AMOUNT,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            mintData,
            contractCallInstructions
        );
    }

    /**
     * [REVERT] Should revert because allowed amount is less than required amount
     */
    function testCannotMintWithInvalidAllowance() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: MAX_PAY_AMOUNT / 10, // Permit for less amount
            nonce: 0,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        gasworks.mintWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                MAX_PAY_AMOUNT,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            mintData,
            contractCallInstructions
        );
    }

    /**
     * [REVERT] Should revert because balance is less than required amount
     */
    function testCannotMintWithInvalidBalance() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: 10 * MAX_PAY_AMOUNT,
            nonce: 0,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        gasworks.mintWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                10 * MAX_PAY_AMOUNT, // More balance than owned
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            mintData,
            contractCallInstructions
        );
    }

    /**
     * [REVERT] Should revert because one contractInstruction is invalid
     */
    function testCannotMintWithInvalidPayload() public {
        contractCallInstructions[0]._callData = bytes("bad data");

        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: mintData._maxPayAmount,
            nonce: nonce,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.expectRevert();
        gasworks.mintWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                mintData._maxPayAmount,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            mintData,
            contractCallInstructions
        );
    }

    /**
     * [REVERT] Should revert because token is not permitted
     */
    function testCannotMintWithInvalidToken() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: MAX_PAY_AMOUNT,
            nonce: nonce,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.expectRevert(abi.encodeWithSelector(IGasworks.InvalidToken.selector, address(0x123123)));
        gasworks.mintWithPermit1(
            IGasworks.PermitData(
                address(0x123123),
                MAX_PAY_AMOUNT,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            mintData,
            contractCallInstructions
        );
    }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should make a mint of AAGG with USDC using EIP2612 permit
     */
    function testMintChamberWithMaxPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: MAX_PAY_AMOUNT,
            nonce: nonce,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        gasworks.mintWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                MAX_PAY_AMOUNT,
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            mintData,
            contractCallInstructions
        );

        assertEq(USDC.balanceOf(address(gasworks)), 0);
        assertEq(USDC.allowance(ALICE, address(gasworks)), 0);
        assertEq(IERC20Permit(address(USDC)).nonces(ALICE), 1);
        assertEq(IERC20(address(AAGG)).balanceOf(ALICE), MINT_AMOUNT);
    }
}
