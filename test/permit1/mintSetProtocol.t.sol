// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { ISetToken } from "src/interfaces/ISetToken.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { SigUtils } from "test/utils/SigUtils.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { Conversor } from "test/utils/HexUtils.sol";
import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";

contract GaslessTest is Test {
    using SafeTransferLib for ERC20;
    using SafeTransferLib for ISetToken;

    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/

    address internal constant DEBT_MODULE = 0xf2dC2f456b98Af9A6bEEa072AF152a7b0EaA40C9;
    bool internal constant IS_DEBT_ISSUANCE = true;

    Gasworks internal gasworks;
    ERC20 internal constant USDC = ERC20(0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174);
    ISetToken internal constant AP60 = ISetToken(0x6cA9C8914a14D63a6700556127D09e7721ff7D3b);
    SigUtils internal sigUtils;

    uint256 internal ownerPrivateKey;
    address internal owner;
    IGasworks.MintSetData internal mintData;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        vm.createSelectFork("polygon");
        gasworks = new Gasworks(
            0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d,
            0x1c0c05a2aA31692e5dc9511b04F651db9E4d8320,
            0x2B13D2b9407D5776B0BB63c8cd144978B6B7cE58
        );
        gasworks.setTokens(address(USDC));
        gasworks.setTokens(address(AP60));
        sigUtils = new SigUtils(USDC.DOMAIN_SEPARATOR());

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        vm.prank(0xe7804c37c13166fF0b37F5aE0BB07A3aEbb6e245);
        USDC.safeTransfer(owner, 150e6);

        uint256 amountToMint = 10e18;
        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(amountToMint));
        inputs[3] = Conversor.iToHex(abi.encode(address(AP60)));
        inputs[4] = Conversor.iToHex(abi.encode(address(USDC)));
        inputs[5] = Conversor.iToHex(abi.encode(true));
        bytes memory res = vm.ffi(inputs);
        (bytes[] memory quotes, uint256 _maxAmountInputToken) = abi.decode(res, (bytes[], uint256));
        mintData = IGasworks.MintSetData(
            AP60, amountToMint, _maxAmountInputToken, quotes, DEBT_MODULE, IS_DEBT_ISSUANCE
        );
    }

    /*//////////////////////////////////////////////////////////////
                              REVERT
    //////////////////////////////////////////////////////////////*/

    /**
     * [REVERT] Should revert because the permit is expired
     */
    function testCannotMintWithExpiredPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(gasworks),
            value: 1e18,
            nonce: USDC.nonces(owner),
            deadline: 2 ** 255 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.warp(2 ** 255 + 1); // fast forwards one second past the deadline

        vm.expectRevert("Permit: permit is expired");
        gasworks.mintSetProtocolWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                1e18,
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
            owner: owner,
            spender: address(gasworks),
            value: 1e18,
            nonce: USDC.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xB0B, digest); // 0xB0B signs but 0xA11CE is owner

        vm.expectRevert("Permit: invalid signature");
        gasworks.mintSetProtocolWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                1e18,
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
            owner: owner,
            spender: address(gasworks),
            value: 1e18,
            nonce: 1, // set nonce to 1 instead of 0
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert("Permit: invalid signature");
        gasworks.mintSetProtocolWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                1e18,
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
            owner: owner,
            spender: address(gasworks),
            value: 5e5,
            nonce: 0,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        gasworks.mintSetProtocolWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                1e18,
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
            owner: owner,
            spender: address(gasworks),
            value: 2e18,
            nonce: 0,
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        gasworks.mintSetProtocolWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                2e18, // owner was only minted 1 USDC
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
            owner: owner,
            spender: address(gasworks),
            value: mintData._maxAmountInputToken,
            nonce: USDC.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert();
        gasworks.mintSetProtocolWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                mintData._maxAmountInputToken,
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
            owner: owner,
            spender: address(gasworks),
            value: 1e6,
            nonce: USDC.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.expectRevert(abi.encodeWithSelector(IGasworks.InvalidToken.selector, address(0x123123)));
        gasworks.mintSetProtocolWithPermit1(
            IGasworks.PermitData(
                address(0x123123),
                1e6,
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
            owner: owner,
            spender: address(gasworks),
            value: mintData._maxAmountInputToken,
            nonce: USDC.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        gasworks.mintSetProtocolWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                mintData._maxAmountInputToken,
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
        assertEq(USDC.allowance(owner, address(gasworks)), 0);
        assertEq(USDC.nonces(owner), 1);
        assertGe(AP60.balanceOf(owner), mintData._amountSetToken);
    }

    /**
     * [SUCCESS] Should make a success mint with permit with max amount allowed
     */
    function testMintWithMaxPermit() public {
        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: owner,
            spender: address(gasworks),
            value: type(uint256).max,
            nonce: USDC.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        gasworks.mintSetProtocolWithPermit1(
            IGasworks.PermitData(
                address(USDC),
                mintData._maxAmountInputToken,
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
            USDC.allowance(owner, address(gasworks)),
            type(uint256).max - mintData._maxAmountInputToken
        );
        assertEq(USDC.nonces(owner), 1);
        assertGe(AP60.balanceOf(owner), mintData._amountSetToken);
    }
}
