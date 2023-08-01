// // SPDX-License-Identifier: UNLICENSED
// pragma solidity ^0.8.17.0;

// import { Test } from "forge-std/Test.sol";
// import { Gasworks } from "src/Gasworks.sol";
// import { IGasworks } from "src/interfaces/IGasworks.sol";
// import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
// import { SafeERC20 } from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
// import { Conversor } from "test/utils/HexUtils.sol";
// import { ChamberTestUtils } from "chambers-peripherals/test/utils/ChamberTestUtils.sol";
// import { ITradeIssuerV2 } from "chambers-peripherals/src/interfaces/ITradeIssuerV2.sol";
// import { IChamber } from "chambers/interfaces/IChamber.sol";
// import { IIssuerWizard } from "chambers/interfaces/IIssuerWizard.sol";
// import { SigUtils } from "test/utils/SigUtils.sol";
// import { IERC20Permit } from
//     "openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol";

// contract GaslessTest is Test, ChamberTestUtils {
//     /*//////////////////////////////////////////////////////////////
//                               VARIABLES
//     //////////////////////////////////////////////////////////////*/
//     using SafeERC20 for IERC20;

//     IERC20 internal constant USDC = IERC20(0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174);
//     IChamber internal constant AAGG = IChamber(0xAfb6E8331355faE99C8E8953bB4c6Dc5d11E9F3c);

//     Gasworks internal gasworks;
//     SigUtils internal sigUtils;
//     uint256 internal ownerPrivateKey;
//     address internal owner;

//     IGasworks.MintChamberData internal mintData;
//     bytes internal res;
//     uint256 internal amountToMint = 10e18;
//     uint256 internal nonce;

//     /*//////////////////////////////////////////////////////////////
//                               SET UP
//     //////////////////////////////////////////////////////////////*/
//     function setUp() public {
//         gasworks = new Gasworks(
//             0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d,
//             0x1c0c05a2aA31692e5dc9511b04F651db9E4d8320,
//             0x2B13D2b9407D5776B0BB63c8cd144978B6B7cE58
//         );
//         gasworks.setTokens(address(USDC));
//         gasworks.setTokens(address(AAGG));

//         vm.label(0x2B13D2b9407D5776B0BB63c8cd144978B6B7cE58, "TradeIssuerV2");

//         sigUtils = new SigUtils(IERC20Permit(address(USDC)).DOMAIN_SEPARATOR());

//         ownerPrivateKey = 0xA11CE;
//         owner = vm.addr(ownerPrivateKey);

//         string[] memory inputs = new string[](6);
//         inputs[0] = "node";
//         inputs[1] = "scripts/fetch-arch-quote.js";
//         inputs[2] = Conversor.iToHex(abi.encode(amountToMint));
//         inputs[3] = Conversor.iToHex(abi.encode(address(AAGG)));
//         inputs[4] = Conversor.iToHex(abi.encode(address(USDC)));
//         inputs[5] = Conversor.iToHex(abi.encode(true));
//         res = vm.ffi(inputs);

//         vm.prank(0xe7804c37c13166fF0b37F5aE0BB07A3aEbb6e245);
//         USDC.safeTransfer(owner, 150e6);

//         nonce = IERC20Permit(address(USDC)).nonces(owner);
//     }

//     /*//////////////////////////////////////////////////////////////
//                               REVERT
//     //////////////////////////////////////////////////////////////*/

//     /**
//      * [REVERT] Should revert because the permit is expired
//      */
//     function testCannotMintWithExpiredPermit() public {
//         (
//             ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
//             uint256 _maxPayAmount
//         ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
//         mintData = IGasworks.MintChamberData(
//             AAGG,
//             IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
//             USDC,
//             _maxPayAmount,
//             amountToMint
//         );

//         SigUtils.Permit memory permit = SigUtils.Permit({
//             owner: owner,
//             spender: address(gasworks),
//             value: 1e18,
//             nonce: nonce,
//             deadline: 2 ** 255 - 1
//         });

//         bytes32 digest = sigUtils.getTypedDataHash(permit);

//         (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

//         vm.warp(2 ** 255 + 1); // fast forwards one second past the deadline

//         vm.expectRevert("Permit: permit is expired");
//         gasworks.mintChamberWithPermit(
//             IGasworks.PermitData(
//                 address(USDC),
//                 1e18,
//                 permit.owner,
//                 permit.spender,
//                 permit.value,
//                 permit.deadline,
//                 v,
//                 r,
//                 s
//             ),
//             mintData,
//             _contractCallInstructions
//         );
//     }

//     /**
//      * [REVERT] Should revert because the signer of the permit
//      * is not the owner of the tokens
//      */
//     function testCannotMintWithInvalidSigner() public {
//         (
//             ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
//             uint256 _maxPayAmount
//         ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
//         mintData = IGasworks.MintChamberData(
//             AAGG,
//             IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
//             USDC,
//             _maxPayAmount,
//             amountToMint
//         );

//         SigUtils.Permit memory permit = SigUtils.Permit({
//             owner: owner,
//             spender: address(gasworks),
//             value: 1e18,
//             nonce: nonce,
//             deadline: 2 ** 256 - 1
//         });

//         bytes32 digest = sigUtils.getTypedDataHash(permit);

//         (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xB0B, digest); // 0xB0B signs but 0xA11CE is owner

//         vm.expectRevert("Permit: invalid signature");
//         gasworks.mintChamberWithPermit(
//             IGasworks.PermitData(
//                 address(USDC),
//                 1e18,
//                 permit.owner,
//                 permit.spender,
//                 permit.value,
//                 permit.deadline,
//                 v,
//                 r,
//                 s
//             ),
//             mintData,
//             _contractCallInstructions
//         );
//     }

//     /**
//      * [REVERT] Should revert because the nonce is invalid
//      */
//     function testCannotMintWithInvalidNonce() public {
//         (
//             ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
//             uint256 _maxPayAmount
//         ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
//         mintData = IGasworks.MintChamberData(
//             AAGG,
//             IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
//             USDC,
//             _maxPayAmount,
//             amountToMint
//         );

//         SigUtils.Permit memory permit = SigUtils.Permit({
//             owner: owner,
//             spender: address(gasworks),
//             value: 1e18,
//             nonce: 1, // set nonce to 1 instead of 0
//             deadline: 2 ** 256 - 1
//         });

//         bytes32 digest = sigUtils.getTypedDataHash(permit);

//         (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

//         vm.expectRevert("Permit: invalid signature");
//         gasworks.mintChamberWithPermit(
//             IGasworks.PermitData(
//                 address(USDC),
//                 1e18,
//                 permit.owner,
//                 permit.spender,
//                 permit.value,
//                 permit.deadline,
//                 v,
//                 r,
//                 s
//             ),
//             mintData,
//             _contractCallInstructions
//         );
//     }

//     /**
//      * [REVERT] Should revert because allowed amount is less than required amount
//      */
//     function testCannotMintWithInvalidAllowance() public {
//         (
//             ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
//             uint256 _maxPayAmount
//         ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
//         mintData = IGasworks.MintChamberData(
//             AAGG,
//             IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
//             USDC,
//             _maxPayAmount,
//             amountToMint
//         );

//         SigUtils.Permit memory permit = SigUtils.Permit({
//             owner: owner,
//             spender: address(gasworks),
//             value: 5e5,
//             nonce: 0,
//             deadline: 2 ** 256 - 1
//         });

//         bytes32 digest = sigUtils.getTypedDataHash(permit);

//         (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

//         vm.expectRevert("TRANSFER_FROM_FAILED");
//         gasworks.mintChamberWithPermit(
//             IGasworks.PermitData(
//                 address(USDC),
//                 1e18,
//                 permit.owner,
//                 permit.spender,
//                 permit.value,
//                 permit.deadline,
//                 v,
//                 r,
//                 s
//             ),
//             mintData,
//             _contractCallInstructions
//         );
//     }

//     /**
//      * [REVERT] Should revert because balance is less than required amount
//      */
//     function testCannotMintWithInvalidBalance() public {
//         (
//             ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
//             uint256 _maxPayAmount
//         ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
//         mintData = IGasworks.MintChamberData(
//             AAGG,
//             IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
//             USDC,
//             _maxPayAmount,
//             amountToMint
//         );

//         SigUtils.Permit memory permit = SigUtils.Permit({
//             owner: owner,
//             spender: address(gasworks),
//             value: 2e18,
//             nonce: 0,
//             deadline: 2 ** 256 - 1
//         });

//         bytes32 digest = sigUtils.getTypedDataHash(permit);

//         (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

//         vm.expectRevert("TRANSFER_FROM_FAILED");
//         gasworks.mintChamberWithPermit(
//             IGasworks.PermitData(
//                 address(USDC),
//                 2e18, // owner was only minted 1 USDC
//                 permit.owner,
//                 permit.spender,
//                 permit.value,
//                 permit.deadline,
//                 v,
//                 r,
//                 s
//             ),
//             mintData,
//             _contractCallInstructions
//         );
//     }

//     /**
//      * [REVERT] Should revert because mintData is invalid
//      */
//     function testCannotMintWithInvalidPayload() public {
//         (
//             ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
//             uint256 _maxPayAmount
//         ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
//         mintData = IGasworks.MintChamberData(
//             AAGG,
//             IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
//             USDC,
//             _maxPayAmount,
//             amountToMint
//         );

//         _contractCallInstructions[0]._callData = bytes("bad data");

//         SigUtils.Permit memory permit = SigUtils.Permit({
//             owner: owner,
//             spender: address(gasworks),
//             value: mintData._maxPayAmount,
//             nonce: nonce,
//             deadline: 2 ** 256 - 1
//         });

//         bytes32 digest = sigUtils.getTypedDataHash(permit);

//         (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

//         vm.expectRevert();
//         gasworks.mintChamberWithPermit(
//             IGasworks.PermitData(
//                 address(USDC),
//                 mintData._maxPayAmount,
//                 permit.owner,
//                 permit.spender,
//                 permit.value,
//                 permit.deadline,
//                 v,
//                 r,
//                 s
//             ),
//             mintData,
//             _contractCallInstructions
//         );
//     }

//     /**
//      * [REVERT] Should revert because token is not permitted
//      */
//     function testCannotMintWithInvalidToken() public {
//         (
//             ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
//             uint256 _maxPayAmount
//         ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
//         mintData = IGasworks.MintChamberData(
//             AAGG,
//             IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
//             USDC,
//             _maxPayAmount,
//             amountToMint
//         );

//         SigUtils.Permit memory permit = SigUtils.Permit({
//             owner: owner,
//             spender: address(gasworks),
//             value: 1e6,
//             nonce: nonce,
//             deadline: 2 ** 256 - 1
//         });

//         bytes32 digest = sigUtils.getTypedDataHash(permit);

//         (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

//         vm.expectRevert(abi.encodeWithSelector(IGasworks.InvalidToken.selector, address(0x123123)));
//         gasworks.mintChamberWithPermit(
//             IGasworks.PermitData(
//                 address(0x123123),
//                 1e6,
//                 permit.owner,
//                 permit.spender,
//                 permit.value,
//                 permit.deadline,
//                 v,
//                 r,
//                 s
//             ),
//             mintData,
//             _contractCallInstructions
//         );
//     }

//     /*//////////////////////////////////////////////////////////////
//                               SUCCESS
//     //////////////////////////////////////////////////////////////*/

//     /**
//      * [SUCCESS] Should make a mint of AAGG with USDC using EIP2612 permit
//      */
//     function testMintChamberWithMaxPermit() public {
//         (
//             ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
//             uint256 _maxPayAmount
//         ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));
//         mintData = IGasworks.MintChamberData(
//             AAGG,
//             IIssuerWizard(0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449),
//             USDC,
//             _maxPayAmount,
//             amountToMint
//         );

//         SigUtils.Permit memory permit = SigUtils.Permit({
//             owner: owner,
//             spender: address(gasworks),
//             value: type(uint256).max,
//             nonce: nonce,
//             deadline: 2 ** 256 - 1
//         });

//         bytes32 digest = sigUtils.getTypedDataHash(permit);

//         (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

//         gasworks.mintChamberWithPermit(
//             IGasworks.PermitData(
//                 address(USDC),
//                 mintData._maxPayAmount,
//                 permit.owner,
//                 permit.spender,
//                 permit.value,
//                 permit.deadline,
//                 v,
//                 r,
//                 s
//             ),
//             mintData,
//             _contractCallInstructions
//         );

//         assertEq(USDC.balanceOf(address(gasworks)), 0);
//         assertGe(
//             USDC.allowance(owner, address(gasworks)), type(uint256).max - mintData._maxPayAmount
//         );
//         assertEq(IERC20Permit(address(USDC)).nonces(owner), 1);
//         assertEq(IERC20(address(AAGG)).balanceOf(owner), amountToMint);
//     }
// }
