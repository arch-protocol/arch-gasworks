// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { ISetToken } from "src/interfaces/ISetToken.sol";
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

    address private constant biconomyForwarder = 0x86C80a8aa58e0A4fa09A69624c31Ab2a6CAD56b8;

    address internal constant usdcAddress = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174;
    address internal constant ap60Address = 0x6cA9C8914a14D63a6700556127D09e7721ff7D3b;
    address internal constant debtModule = 0xf2dC2f456b98Af9A6bEEa072AF152a7b0EaA40C9;
    bool internal constant isDebtIssuance = true;

    Gasworks internal gasworks;
    ERC20 internal constant usdc = ERC20(usdcAddress);
    ISetToken internal constant AP60 = ISetToken(ap60Address);
    SigUtils internal sigUtils;

    uint256 internal ownerPrivateKey;
    address internal owner;
    Gasworks.MintData internal mintData;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        gasworks = new Gasworks(0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d);
        gasworks.setTokens(address(usdc));
        gasworks.setTokens(address(AP60));
        sigUtils = new SigUtils(usdc.DOMAIN_SEPARATOR());

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        vm.prank(0xe7804c37c13166fF0b37F5aE0BB07A3aEbb6e245);
        usdc.safeTransfer(owner, 150e6);

        vm.deal(biconomyForwarder, 10 ether);
        uint256 amountToMint = 10e18;

        string[] memory inputs = new string[](5);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(amountToMint));
        inputs[3] = Conversor.iToHex(abi.encode(ap60Address));
        inputs[4] = Conversor.iToHex(abi.encode(true));
        bytes memory res = vm.ffi(inputs);
        (bytes[] memory quotes, uint256 _maxAmountInputToken) = abi.decode(res, (bytes[], uint256));
        mintData = Gasworks.MintData(
            AP60, amountToMint, _maxAmountInputToken, quotes, debtModule, isDebtIssuance
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
            nonce: usdc.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.prank(biconomyForwarder);
        gasworks.mintWithPermit(
            Gasworks.PermitData(
                address(usdc),
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

        assertEq(usdc.balanceOf(address(gasworks)), 0);
        assertEq(usdc.allowance(owner, address(gasworks)), 0);
        assertEq(usdc.nonces(owner), 1);
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
            nonce: usdc.nonces(owner),
            deadline: 2 ** 256 - 1
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        vm.prank(biconomyForwarder);
        gasworks.mintWithPermit(
            Gasworks.PermitData(
                address(usdc),
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

        assertEq(usdc.balanceOf(address(gasworks)), 0);
        assertEq(
            usdc.allowance(owner, address(gasworks)),
            type(uint256).max - mintData._maxAmountInputToken
        );
        assertEq(usdc.nonces(owner), 1);
        assertGe(AP60.balanceOf(owner), mintData._amountSetToken);
    }
}
