// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import "forge-std/StdJson.sol";
import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { ISetToken } from "src/interfaces/ISetToken.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { SigUtils } from "test/utils/SigUtils.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { Conversor } from "test/utils/HexUtils.sol";
import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";
import { IERC20Permit } from
    "openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol";
import { ITradeIssuerV2 } from "chambers-peripherals/src/interfaces/ITradeIssuerV2.sol";
import { ChamberTestUtils } from "chambers-peripherals/test/utils/ChamberTestUtils.sol";
import { Permit2Utils } from "test/utils/Permit2Utils.sol";
import { DeployPermit2 } from "permit2/test/utils/DeployPermit2.sol";

contract GaslessTest is Test, ChamberTestUtils, Permit2Utils, DeployPermit2 {
    using SafeTransferLib for ERC20;
    using SafeTransferLib for ISetToken;
    using stdJson for string;

    string root;
    string path;
    string json;

    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    Gasworks internal gasworks;
    SigUtils internal sigUtils;
    ERC20 internal constant USDC = ERC20(POLYGON_USDC);
    ISetToken internal constant AP60 = ISetToken(POLYGON_AP60);

    IGasworks.MintSetData internal mintData;
    uint256 internal MINT_AMOUNT = 10e18;
    uint256 internal MAX_PAY_AMOUNT;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        addLabbels();
        root = vm.projectRoot();
        path = string.concat(root, "/data/permitOne/mint/testMintAp60WithUsdc.json");
        json = vm.readFile(path);
        (
            uint256 chainId,
            uint256 blockNumber,
            ,
            ,
            ,
            uint256 maxPayAmount,
            ITradeIssuerV2.ContractCallInstruction[] memory callInstrictions
        ) = parseMintQuoteFromJson(json);

        bytes[] memory componentQuotes = new bytes[](callInstrictions.length);
        for (uint256 i = 0; i < callInstrictions.length; i++) {
            componentQuotes[i] = callInstrictions[i]._callData;
        }

        mintData = IGasworks.MintSetData(
            AP60,
            MINT_AMOUNT,
            maxPayAmount,
            componentQuotes,
            POLYGON_DEBT_MODULE,
            true // Is debt issuance
        );

        MAX_PAY_AMOUNT = maxPayAmount;

        vm.createSelectFork("polygon", blockNumber);
        gasworks = deployGasworks(chainId);
        sigUtils = new SigUtils(USDC.DOMAIN_SEPARATOR());

        deal(POLYGON_USDC, ALICE, maxPayAmount);
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
            nonce: USDC.nonces(ALICE),
            deadline: 2 ** 255 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.warp(2 ** 255 + 1); // fast forwards one second past the deadline

        vm.expectRevert("Permit: permit is expired");
        gasworks.mintSetProtocolWithPermit1(
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
            mintData
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
            nonce: USDC.nonces(ALICE),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xB0B, digest); // 0xB0B signs but 0xA11CE is owner

        vm.expectRevert("Permit: invalid signature");
        gasworks.mintSetProtocolWithPermit1(
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
            mintData
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
            nonce: USDC.nonces(ALICE) + 1, // Invalid nonce
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.expectRevert("Permit: invalid signature");
        gasworks.mintSetProtocolWithPermit1(
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
            mintData
        );
    }

    /**
     * [REVERT] Should revert because allowed amount is less than required amount
     */
    function testCannotMintWithInvalidAllowance() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: MAX_PAY_AMOUNT - 1,
            nonce: USDC.nonces(ALICE),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        gasworks.mintSetProtocolWithPermit1(
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
            mintData
        );
    }

    /**
     * [REVERT] Should revert because balance is less than required amount
     */
    function testCannotMintWithInvalidBalance() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: MAX_PAY_AMOUNT + 1,
            nonce: USDC.nonces(ALICE),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        gasworks.mintSetProtocolWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                MAX_PAY_AMOUNT + 1, // 1 wei more than balance
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                v,
                r,
                s
            ),
            mintData
        );
    }

    /**
     * [REVERT] Should revert because mintData is invalid
     */
    function testCannotMintWithInvalidPayload() public {
        mintData._componentQuotes[0] = bytes("bad quote");
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: MAX_PAY_AMOUNT,
            nonce: USDC.nonces(ALICE),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.expectRevert();
        gasworks.mintSetProtocolWithPermit1(
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
            mintData
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
            nonce: USDC.nonces(ALICE),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        vm.expectRevert(abi.encodeWithSelector(IGasworks.InvalidToken.selector, address(0x123123)));
        gasworks.mintSetProtocolWithPermit1(
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
            mintData
        );
    }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should make a success mint with permit with a limited amount allowed
     */
    function testMintWithLimitedPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: MAX_PAY_AMOUNT,
            nonce: USDC.nonces(ALICE),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        gasworks.mintSetProtocolWithPermit1(
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
            mintData
        );

        assertEq(USDC.balanceOf(address(gasworks)), 0);
        assertEq(USDC.allowance(ALICE, address(gasworks)), 0);
        assertEq(USDC.nonces(ALICE), 1);
        assertGe(AP60.balanceOf(ALICE), mintData._amountSetToken);
    }

    /**
     * [SUCCESS] Should make a success mint with permit with max amount allowed
     */
    function testMintWithMaxPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: ALICE,
            spender: address(gasworks),
            value: type(uint256).max,
            nonce: USDC.nonces(ALICE),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PRIVATE_KEY, digest);

        gasworks.mintSetProtocolWithPermit1(
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
            mintData
        );

        assertEq(USDC.balanceOf(address(gasworks)), 0);
        assertEq(
            USDC.allowance(ALICE, address(gasworks)),
            type(uint256).max - mintData._maxAmountInputToken
        );
        assertEq(USDC.nonces(ALICE), 1);
        assertGe(AP60.balanceOf(ALICE), mintData._amountSetToken);
    }
}
