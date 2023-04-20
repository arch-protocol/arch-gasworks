// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import {Test} from "forge-std/Test.sol";
import {Gasworks} from "src/Gasworks.sol";
import {ISetToken} from "src/interfaces/ISetToken.sol";
import {SigUtils} from "test/utils/SigUtils.sol";
import {ERC20} from "solmate/src/tokens/ERC20.sol";
import {Conversor} from "test/utils/HexUtils.sol";
import {SafeTransferLib} from "solmate/src/utils/SafeTransferLib.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {PermitSignature} from "permit2/test/utils/PermitSignature.sol";
import {Permit2} from "permit2/src/Permit2.sol";
import {TokenProvider} from "permit2/test/utils/TokenProvider.sol";
import {SignatureVerification} from "permit2/src/libraries/SignatureVerification.sol";
import {InvalidNonce, SignatureExpired} from "permit2/src/PermitErrors.sol";

contract GaslessTest is Test, PermitSignature, TokenProvider {
    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeTransferLib for ERC20;
    using SafeTransferLib for ISetToken;

    string constant WITNESS_TYPE_STRING =
        "MintData witness)MintData(ISetToken _setToken,uint256 _amountSetToken,uint256 _maxAmountInputToken, bytes[] _componentQuotes,address _issuanceModule,bool _isDebtIssuance)TokenPermissions(address token,uint256 amount)";

    bytes32 constant FULL_EXAMPLE_WITNESS_TYPEHASH = keccak256(
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,MintData witness)MintData(ISetToken _setToken,uint256 _amountSetToken,uint256 _maxAmountInputToken, bytes[] _componentQuotes,address _issuanceModule,bool _isDebtIssuance)TokenPermissions(address token,uint256 amount)"
    );

    address internal constant usdcAddress = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174;
    address internal constant AP60Address = 0x6cA9C8914a14D63a6700556127D09e7721ff7D3b;
    address internal constant debtModule = 0xf2dC2f456b98Af9A6bEEa072AF152a7b0EaA40C9;
    bool internal constant _isDebtIssuance = true;

    Gasworks internal gasworks;
    ERC20 internal constant usdc = ERC20(usdcAddress);
    ISetToken internal constant AP60 = ISetToken(AP60Address);

    uint256 internal alicePrivateKey;
    address internal alice;
    Gasworks.MintData internal mintData;
    bytes32 internal DOMAIN_SEPARATOR;
    Permit2 internal permit2;

    function setUp() public {
        gasworks = new Gasworks(0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d);
        gasworks.setTokens(address(usdc));
        gasworks.setTokens(address(AP60));
        permit2 = Permit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);
        DOMAIN_SEPARATOR = permit2.DOMAIN_SEPARATOR();

        alicePrivateKey = 0xA11CE;
        alice = vm.addr(alicePrivateKey);

        vm.prank(0xe7804c37c13166fF0b37F5aE0BB07A3aEbb6e245);
        usdc.safeTransfer(alice, 150e6);

        uint256 amountToMint = 10e18;

        string[] memory inputs = new string[](4);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(amountToMint));
        inputs[3] = Conversor.iToHex(abi.encode(AP60Address));
        bytes memory res = vm.ffi(inputs);
        (bytes[] memory quotes, uint256 _maxAmountInputToken) = abi.decode(res, (bytes[], uint256));
        mintData = Gasworks.MintData(AP60, amountToMint, _maxAmountInputToken, quotes, debtModule, _isDebtIssuance);

        vm.prank(alice);
        usdc.approve(address(permit2), mintData._maxAmountInputToken);
    }

    /*//////////////////////////////////////////////////////////////
                              UTILS
    //////////////////////////////////////////////////////////////*/

    function getTransferDetails(address to, uint256 amount)
        private
        pure
        returns (ISignatureTransfer.SignatureTransferDetails memory)
    {
        return ISignatureTransfer.SignatureTransferDetails({to: to, requestedAmount: amount});
    }

    function getSignature(
        ISignatureTransfer.PermitTransferFrom memory permit,
        uint256 privateKey,
        bytes32 typehash,
        bytes32 witness,
        bytes32 domainSeparator
    ) internal returns (bytes memory sig) {
        bytes32 tokenPermissions = keccak256(abi.encode(_TOKEN_PERMISSIONS_TYPEHASH, permit.permitted));

        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(typehash, tokenPermissions, address(gasworks), permit.nonce, permit.deadline, witness)
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        return bytes.concat(r, s, bytes1(v));
    }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    function testMintWithPermit2() public {
        ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(usdc), 0);
        bytes32 witness = keccak256(abi.encode(mintData));
        bytes memory sig =
            getSignature(permit, alicePrivateKey, FULL_EXAMPLE_WITNESS_TYPEHASH, witness, DOMAIN_SEPARATOR);
        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(gasworks), mintData._maxAmountInputToken);

        gasworks.mintWithPermit2(permit, transferDetails, alice, witness, sig, mintData, permit2);

        assertEq(usdc.balanceOf(address(gasworks)), 0);
        assertEq(usdc.allowance(alice, address(gasworks)), 0);
        assertGe(AP60.balanceOf(alice), mintData._amountSetToken);
    }
}
