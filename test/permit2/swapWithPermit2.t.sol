// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21.0;

import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { SigUtils } from "test/utils/SigUtils.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { Conversor } from "test/utils/HexUtils.sol";
import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { SignatureVerification } from "permit2/src/libraries/SignatureVerification.sol";
import { InvalidNonce, SignatureExpired } from "permit2/src/PermitErrors.sol";
import { Permit2Utils } from "test/utils/Permit2Utils.sol";
import { EIP712 } from "permit2/src/EIP712.sol";
import { DeployPermit2 } from "permit2/test/utils/DeployPermit2.sol";
import { SignatureExpired } from "permit2/src/PermitErrors.sol";
import { WETH } from "solmate/src/tokens/WETH.sol";

contract GaslessTest is Test, Permit2Utils, DeployPermit2 {
    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeTransferLib for ERC20;

    bytes32 public constant TOKEN_PERMISSIONS_TYPEHASH =
        keccak256("TokenPermissions(address token,uint256 amount)");

    Gasworks internal gasworks;
    ERC20 internal constant USDC = ERC20(0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174);
    ERC20 internal constant WEB3 = ERC20(0xBcD2C5C78000504EFBC1cE6489dfcaC71835406A);
    WETH public constant WMATIC = WETH(payable(0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270));

    uint256 internal ownerPrivateKey;
    address internal owner;
    IGasworks.SwapData internal swapData;
    bytes32 internal domainSeparator;
    address internal permit2;

    //Permit2 witness types
    bytes internal constant TOKEN_PERMISSIONS_TYPE =
        "TokenPermissions(address token,uint256 amount)";
    bytes internal constant PERMIT_WITNESS_TRANSFER_FROM_TYPE =
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,";
    // Swap
    bytes private constant SWAP_DATA_TYPE =
        "SwapData(address buyToken,uint256 buyAmount,uint256 nativeTokenAmount,address swapTarget,address swapAllowanceTarget,bytes swapCallData)";
    bytes internal constant PERMIT2_SWAP_DATA_TYPE =
        abi.encodePacked("SwapData witness)", SWAP_DATA_TYPE, TOKEN_PERMISSIONS_TYPE);

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        gasworks = new Gasworks(
            0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d, 
            0x1c0c05a2aA31692e5dc9511b04F651db9E4d8320,
            0x2B13D2b9407D5776B0BB63c8cd144978B6B7cE58
        );
        gasworks.setTokens(address(USDC));
        gasworks.setTokens(address(WEB3));
        gasworks.setTokens(address(WMATIC));
        permit2 = deployPermit2();
        domainSeparator = EIP712(permit2).DOMAIN_SEPARATOR();

        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);

        deal(address(USDC), owner, 1e6);

        vm.prank(owner);
        USDC.approve(permit2, 1e6);

        string[] memory inputs = new string[](4);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(1e6));
        inputs[3] = Conversor.iToHex(abi.encode(address(WEB3)));
        bytes memory res = vm.ffi(inputs);
        (
            address spender,
            address payable swapTarget,
            bytes memory quote,
            uint256 value,
            uint256 buyAmount
        ) = abi.decode(res, (address, address, bytes, uint256, uint256));
        swapData = IGasworks.SwapData(address(WEB3), buyAmount, value, swapTarget, spender, quote);
    }

    /*//////////////////////////////////////////////////////////////
                              REVERT
    //////////////////////////////////////////////////////////////*/

    // /**
    //  * [REVERT] Should revert because the signature length is invalid
    //  */
    // function testCannotSwapWithPermit2IncorrectSigLength() public {
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(USDC), 0, 1e6);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );
    //     bytes memory sigExtra = bytes.concat(signature, bytes1(uint8(0)));
    //     assertEq(sigExtra.length, 66);

    //     vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
    //     gasworks.swapWithPermit2(permit, owner, sigExtra, swapData);
    // }

    // /**
    //  * [REVERT] Should revert because the signature is expired
    //  */
    // function testCannotSwapWithPermit2SignatureExpired() public {
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(USDC), 0, 1e6);
    //     permit.deadline = 2 ** 255 - 1;
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     vm.warp(2 ** 255 + 1);

    //     vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, permit.deadline));
    //     gasworks.swapWithPermit2(permit, owner, signature, swapData);
    // }

    // /**
    //  * [REVERT] Should revert because the nonce was used twice and should only be used once
    //  */
    // function testCannotSwapWithPermit2InvalidNonce() public {
    //     uint256 nonce = 0;
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(USDC), nonce, 1e6);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     gasworks.swapWithPermit2(permit, owner, signature, swapData);

    //     vm.expectRevert(InvalidNonce.selector);
    //     gasworks.swapWithPermit2(permit, owner, signature, swapData);
    // }

    // /**
    //  * [REVERT] Should revert because token is not permitted
    //  */
    // function testCannotSwapWithPermit2InvalidToken() public {
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(0x123123), 0, 1e6);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     vm.expectRevert(abi.encodeWithSelector(IGasworks.InvalidToken.selector, address(0x123123)));
    //     gasworks.swapWithPermit2(permit, owner, signature, swapData);
    // }

    // /**
    //  * [REVERT] Should revert because low level call to swapTarget failed
    //  */
    // function testCannotSwapWithPermit2SwapCallFailed() public {
    //     swapData.swapCallData = bytes("swapCallData");
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(USDC), 0, 1e6);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     vm.expectRevert(IGasworks.SwapCallFailed.selector);
    //     gasworks.swapWithPermit2(permit, owner, signature, swapData);
    // }

    // /**
    //  * [REVERT] Should revert because amount bought is less than required amount
    //  */
    // function testCannotSwapWithPermit2UnderboughtAsset() public {
    //     swapData.buyAmount = 1000 ether; // set buy amount to 1000 ether
    //     ISignatureTransfer.PermitTransferFrom memory permit =
    //         defaultERC20PermitTransfer(address(USDC), 0, 1e6);
    //     bytes memory signature = getSignature(
    //         permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
    //     );

    //     vm.expectRevert(
    //         abi.encodeWithSelector(IGasworks.Underbought.selector, address(WEB3), 1000 ether)
    //     );
    //     gasworks.swapWithPermit2(permit, owner, signature, swapData);
    // }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should make a success swap with permit2
     */
    function testSwapWithPermit2() public {
        // bytes32 constant NAME_HASH = keccak256("Permit2");
        // bytes32 constant TYPE_HASH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
        // bytes32 constant TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");

        uint256 currentNonce = USDC.nonces(owner);

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: address(USDC), amount: 1e6 }),
            nonce: currentNonce,
            deadline: block.timestamp + 100
        });

        // bytes memory concatenatedHashedQuotes;
        // for (uint256 i = 0; i < swap.swapCallData.length;) {
        //   concatenatedHashedQuotes = bytes.concat(concatenatedHashedQuotes, keccak256(swap.swapCallData[i]));
        //   unchecked {
        //     ++i;
        //   }
        // }

        bytes32 witness = keccak256(
            abi.encode(
                keccak256(abi.encodePacked(SWAP_DATA_TYPE)),
                swapData.buyToken,
                swapData.buyAmount,
                swapData.nativeTokenAmount,
                swapData.swapTarget,
                swapData.swapAllowanceTarget,
                keccak256(swapData.swapCallData)
            )
        );
        // bytes32 domainSeparator = keccak256(abi.encode(TYPE_HASH, NAME_HASH, block.chainid, address(USDC)));
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
                                PERMIT_WITNESS_TRANSFER_FROM_TYPE, PERMIT2_SWAP_DATA_TYPE
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

        // bytes memory signature = getSignature(
        //     permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
        // );

        gasworks.swapWithPermit2(permit, owner, signature, swapData);

        assertEq(USDC.balanceOf(owner), 0);
        assertEq(USDC.balanceOf(address(gasworks)), 0);
        assertEq(USDC.allowance(owner, address(gasworks)), 0);
        assertGe(WEB3.balanceOf(owner), swapData.buyAmount);
    }

    /**
     * [SUCCESS] Should make a success swap to native MATIC with permit2
     */
    function testSwapWToNativeMATICithPermit2() public {
        string[] memory inputs = new string[](4);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(1e6));
        inputs[3] = Conversor.iToHex(abi.encode(address(WMATIC)));
        bytes memory res = vm.ffi(inputs);
        (
            address spender,
            address payable swapTarget,
            bytes memory quote,
            uint256 value,
            uint256 buyAmount
        ) = abi.decode(res, (address, address, bytes, uint256, uint256));
        swapData = IGasworks.SwapData(address(WMATIC), buyAmount, value, swapTarget, spender, quote);
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(USDC), 0, 1e6);
        bytes memory signature = getSignature(
            permit, ownerPrivateKey, domainSeparator, TOKEN_PERMISSIONS_TYPEHASH, address(gasworks)
        );

        gasworks.swapWithPermit2(permit, owner, signature, swapData);

        assertEq(USDC.balanceOf(owner), 0);
        assertEq(USDC.balanceOf(address(gasworks)), 0);
        assertEq(USDC.allowance(owner, address(gasworks)), 0);
        assertGe(owner.balance, swapData.buyAmount);
    }
}
