// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import {Test} from "forge-std/Test.sol";
import {Gasworks} from "src/Gasworks.sol";
import {SigUtils} from "test/utils/SigUtils.sol";
import {ERC20} from "solmate/src/tokens/ERC20.sol";
import {Conversor} from "test/utils/HexUtils.sol";
import {SafeTransferLib} from "solmate/src/utils/SafeTransferLib.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {PermitSignature} from "permit2/test/utils/PermitSignature.sol";
import {Permit2} from "permit2/src/Permit2.sol";
import {TokenProvider} from "permit2/test/utils/TokenProvider.sol";

contract GaslessTest is Test, PermitSignature, TokenProvider {
    ///                                                          ///
    ///                           SETUP                          ///
    ///                                                          ///
    using SafeTransferLib for ERC20;

    string constant WITNESS_TYPE_STRING =
        "SwapData witness)SwapData(address buyToken,address spender,address payable swapTarget, bytes swapCallData,uint256 swapValue,uint256 buyAmount)TokenPermissions(address token,uint256 amount)";

    bytes32 constant FULL_EXAMPLE_WITNESS_TYPEHASH = keccak256(
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,SwapData witness)SwapData(address buyToken,address spender,address payable swapTarget, bytes swapCallData,uint256 swapValue,uint256 buyAmount)TokenPermissions(address token,uint256 amount)"
    );

    address internal immutable usdcAddress = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174;
    address internal immutable web3Address = 0xBcD2C5C78000504EFBC1cE6489dfcaC71835406A;
    address private constant biconomyForwarder = 0x86C80a8aa58e0A4fa09A69624c31Ab2a6CAD56b8;

    Gasworks internal swap;
    ERC20 internal usdc;
    ERC20 internal web3;
    SigUtils internal sigUtils;

    uint256 internal ownerPrivateKey;
    address internal owner;
    Gasworks.SwapData internal swapData;
    bytes32 DOMAIN_SEPARATOR;
    Permit2 permit2;

    function setUp() public {
        usdc = ERC20(0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174);
        web3 = ERC20(0xBcD2C5C78000504EFBC1cE6489dfcaC71835406A);
        swap = new Gasworks(0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d);
        swap.setTokens(address(usdc));
        swap.setTokens(address(web3));
        permit2 = Permit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);
        DOMAIN_SEPARATOR = permit2.DOMAIN_SEPARATOR();

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        vm.prank(0xe7804c37c13166fF0b37F5aE0BB07A3aEbb6e245);
        usdc.safeTransfer(owner, 1e6);

        vm.deal(biconomyForwarder, 10 ether);

        vm.prank(owner);
        usdc.approve(address(permit2), 1e6);

        string[] memory inputs = new string[](3);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(1e6));
        bytes memory res = vm.ffi(inputs);
        (address spender, address payable swapTarget, bytes memory quote, uint256 value, uint256 buyAmount) =
            abi.decode(res, (address, address, bytes, uint256, uint256));
        swapData = Gasworks.SwapData(web3Address, spender, swapTarget, quote, value, buyAmount);
    }

    ///                                                          ///
    ///                          UTILS                           ///
    ///                                                          ///

    function getTransferDetails(address to, uint256 amount)
        private
        pure
        returns (ISignatureTransfer.SignatureTransferDetails memory)
    {
        return ISignatureTransfer.SignatureTransferDetails({to: to, requestedAmount: amount});
    }

    ///                                                          ///
    ///                        SUCCESS                           ///
    ///                                                          ///

    function testSwapWithPermit2() public {
        ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(usdc), 0);
        bytes32 witness = keccak256(
            abi.encode(
                FULL_EXAMPLE_WITNESS_TYPEHASH,
                swapData.buyToken,
                swapData.spender,
                swapData.swapTarget,
                swapData.swapCallData,
                swapData.swapValue,
                swapData.buyAmount
            )
        );
        bytes32 tokenPermissions = keccak256(abi.encode(_TOKEN_PERMISSIONS_TYPEHASH, permit.permitted));

        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        FULL_EXAMPLE_WITNESS_TYPEHASH,
                        tokenPermissions,
                        address(swap),
                        permit.nonce,
                        permit.deadline,
                        witness
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, msgHash);
        bytes memory sig = bytes.concat(r, s, bytes1(v));
        ISignatureTransfer.SignatureTransferDetails memory transferDetails = getTransferDetails(address(swap), 1e6);

        swap.swapWithPermit2(permit, transferDetails, owner, witness, sig, swapData, permit2);

        assertEq(usdc.balanceOf(owner), 0);
        assertEq(usdc.balanceOf(address(swap)), 0);
        assertEq(usdc.allowance(owner, address(swap)), 0);
        assertGe(web3.balanceOf(owner), swapData.buyAmount);
    }
}
