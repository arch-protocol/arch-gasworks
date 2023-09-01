// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21.0;

import { Test } from "forge-std/Test.sol";
import { console } from "forge-std/console.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import { Conversor } from "test/utils/HexUtils.sol";
import { BytesLib } from "test/utils/BytesLib.sol";
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

contract GaslessTest is Test, Permit2Utils, ChamberTestUtils, DeployPermit2 {
    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeERC20 for IERC20;
    using BytesLib for bytes;

    bytes32 internal constant TOKEN_PERMISSIONS_TYPEHASH =
        keccak256("TokenPermissions(address token,uint256 amount)");

    Gasworks internal gasworks;
    address aedyOnPolygon = 0x027aF1E12a5869eD329bE4c05617AD528E997D5A;
    address aagg = 0xAfb6E8331355faE99C8E8953bB4c6Dc5d11E9F3c;
    address tradeIssuerOnPolygon = 0x2B13D2b9407D5776B0BB63c8cd144978B6B7cE58;
    address exchangeIssuancePolygon = 0x1c0c05a2aA31692e5dc9511b04F651db9E4d8320;
    address biconomyForwarder = 0xdA78a11FD57aF7be2eDD804840eA7f4c2A38801d;

    // address internal constant usdcAddressOnEthereum = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    // address internal constant addyAdderssOnEthereum = 0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF;
    address internal constant issuerWizardAddress = 0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449;
    address internal constant tradeIssuerV2OnEthereum = 0xbbCA2AcBd87Ce7A5e01fb56914d41F6a7e5C5A56;

    // ERC20 internal constant USDC = ERC20(usdcAddressOnEthereum);
    // IChamber internal constant ADDY = IChamber(addyAdderssOnEthereum);

    uint256 internal ownerPrivateKey;
    address internal owner;
    bytes32 domainSeparatorH;
    address internal immutable permit2Address = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    bytes32 internal domainSeparator;
    address internal permit2;
    // bytes internal res;
    uint256 internal amountToMint = 2e18;
    bytes res;

    //Permit2 witness types
    bytes internal constant TOKEN_PERMISSIONS_TYPE =
        "TokenPermissions(address token,uint256 amount)";
    bytes internal constant PERMIT_WITNESS_TRANSFER_FROM_TYPE =
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,";
    
    // MintChamber
    bytes private constant SWAP_CALL_INSTRUCTION_TYPE =
        "SwapCallInstruction(address sellToken,uint256 sellAmount,address buyToken,uint256 minBuyAmount,address swapTarget,address swapAllowanceTarget)";
    bytes32 internal immutable SWAP_CALL_INSTRUCTION_TYPE_HASH= keccak256(abi.encodePacked(SWAP_CALL_INSTRUCTION_TYPE));
    
    bytes private constant MINT_DATA_TYPE =
      "MintData(address archToken,uint256 archTokenAmount,address inputToken,uint256 inputTokenMaxAmount,address issuer,SwapCallInstruction[] swapCallInstructions)";
    // MintData(address archToken,uint256 archTokenAmount,address inputToken,uint256 inputTokenMaxAmount,address issuer,SwapCallInstruction[] swapCallInstructions)SwapCallInstruction(address sellToken,uint256 sellAmount,address buyToken,uint256 minBuyAmount,address swapTarget,address swapAllowanceTarget)
    bytes32 internal immutable MINT_DATA_TYPE_HASH = keccak256(abi.encodePacked(MINT_DATA_TYPE, SWAP_CALL_INSTRUCTION_TYPE));

    bytes internal constant PERMIT2_MINT_DATA_TYPE = abi.encodePacked(
            "MintData witness)", MINT_DATA_TYPE, SWAP_CALL_INSTRUCTION_TYPE, TOKEN_PERMISSIONS_TYPE
        );

    // 'PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,MintData witness)MintData(address archToken,uint256 archTokenAmount,address inputToken,uint256 inputTokenMaxAmount,address issuer,SwapCallInstruction[] swapCallInstructions)SwapCallInstruction(address sellToken,uint256 sellAmount,address buyToken,uint256 minBuyAmount,address swapTarget,address swapAllowanceTarget)TokenPermissions(address token,uint256 amount)'

  // 'PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,MintData witness)MintData(address archToken,uint256 archTokenAmount,address inputToken,uint256 inputTokenMaxAmount,address issuer,SwapCallInstruction[] swapCallInstructions)SwapCallInstruction(address sellToken,uint256 sellAmount,address buyToken,uint256 minBuyAmount,address swapTarget,address swapAllowanceTarget)TokenPermissions(address token,uint256 amount)'
    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        gasworks = new Gasworks(
            biconomyForwarder, 
            exchangeIssuancePolygon, 
            tradeIssuerOnPolygon
        );
        gasworks.setTokens(aedyOnPolygon);
        gasworks.setTokens(aagg);
        permit2 = deployPermit2();
        domainSeparator = EIP712(permit2).DOMAIN_SEPARATOR();
        console.log("Permit2 address");
        console.log(address(permit2));

        ownerPrivateKey = 0xe37ceb1e8c4a104e0192e1d36308350b7f98e1ed966d485bcdce15fec602341b;
        owner = vm.addr(ownerPrivateKey);

        domainSeparatorH = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("Permit2")),
            137,
            permit2Address
          )
        );

        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "scripts/fetch-arch-quote.js";
        inputs[2] = Conversor.iToHex(abi.encode(amountToMint));
        inputs[3] = Conversor.iToHex(abi.encode(aagg));
        inputs[4] = Conversor.iToHex(abi.encode(aedyOnPolygon));
        inputs[5] = Conversor.iToHex(abi.encode(true));
        res = vm.ffi(inputs);

        // vm.label(0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF, "yvUSDC");
        // vm.label(0x3B27F92C0e212C671EA351827EDF93DB27cc0c65, "yvUSDT");
        // vm.label(0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF, "yvDAI");
        // vm.label(usdcAddressOnEthereum, "USDC");
        // vm.label(0xdAC17F958D2ee523a2206206994597C13D831ec7, "USDT");
        // vm.label(0x6B175474E89094C44Da98b954EedeAC495271d0F, "DAI");
        // vm.label(addyAdderssOnEthereum, "ADDY");
        vm.label(issuerWizardAddress, "IssuerWizard");
        vm.label(tradeIssuerV2OnEthereum, "TraderIssuerV2");
        vm.label(aedyOnPolygon, "AEDY (PoS)");
        vm.label(aagg, "AAGG");
    }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    function getMessageToSign(ISignatureTransfer.PermitTransferFrom memory permit, address spender, IGasworks.MintData memory mintData, bytes32 domainSeparatorHashed) public returns (bytes32 msgHash) {
      console.log("domainSeparatorHashed");
      console.logBytes32(domainSeparatorHashed);
      bytes32 tokenPermissions = keccak256(abi.encode(
        TOKEN_PERMISSIONS_TYPEHASH,
        permit.permitted.token,
        permit.permitted.amount
      ));
      console.log("tokenPermissions");
      console.logBytes32(tokenPermissions);
      bytes32[] memory instructionsHashes = new bytes32[](mintData.swapCallInstructions.length);
        for (uint256 i = 0; i < mintData.swapCallInstructions.length; i++) {
            instructionsHashes[i] = keccak256(abi.encode(
                keccak256("SwapCallInstruction(address sellToken,uint256 sellAmount,address buyToken,uint256 minBuyAmount,address swapTarget,address swapAllowanceTarget)"),
                mintData.swapCallInstructions[i].sellToken,
                mintData.swapCallInstructions[i].sellAmount,
                mintData.swapCallInstructions[i].buyToken,
                mintData.swapCallInstructions[i].minBuyAmount,
                mintData.swapCallInstructions[i].swapTarget,
                mintData.swapCallInstructions[i].swapAllowanceTarget
                
            ));
        }
      bytes32 swapCallInstructionsHash = keccak256(abi.encodePacked(instructionsHashes));
      console.log("swapCallInstructionsHash");
      console.logBytes32(swapCallInstructionsHash);
      bytes32 witnessHash = keccak256(abi.encode(
          keccak256("MintData(address archToken,uint256 archTokenAmount,address inputToken,uint256 inputTokenMaxAmount,address issuer,SwapCallInstruction[] swapCallInstructions)SwapCallInstruction(address sellToken,uint256 sellAmount,address buyToken,uint256 minBuyAmount,address swapTarget,address swapAllowanceTarget)"),
          mintData.archToken,
          mintData.archTokenAmount,
          mintData.inputToken,
          mintData.inputTokenMaxAmount,
          mintData.issuer,
          swapCallInstructionsHash
      ));
      console.log("witnessHash");
      console.logBytes32(witnessHash);
      (
          ,
          bytes32 concatenatedHashedSwapCallInstructions
      ) = gasworks.hashSwapCallInstructionAndConvertToTraderIssuerCallInstruction(
          mintData.swapCallInstructions
      );
      bytes32 gasworksWitness = gasworks.calculateMintDataTypeWitness(mintData, concatenatedHashedSwapCallInstructions);
      assertEq(gasworksWitness, witnessHash);
      bytes32 permitWitnessTransferFromHash = keccak256(abi.encode(
          keccak256("PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,MintData witness)MintData(address archToken,uint256 archTokenAmount,address inputToken,uint256 inputTokenMaxAmount,address issuer,SwapCallInstruction[] swapCallInstructions)SwapCallInstruction(address sellToken,uint256 sellAmount,address buyToken,uint256 minBuyAmount,address swapTarget,address swapAllowanceTarget)TokenPermissions(address token,uint256 amount)"),
          tokenPermissions,
          spender,
          permit.nonce,
          permit.deadline,
          witnessHash
      ));
      console.log("permitWitnessTransferFromHash");
      console.logBytes32(permitWitnessTransferFromHash);
      bytes memory message = abi.encodePacked(
          "\x19\x01",
          domainSeparatorHashed,
          permitWitnessTransferFromHash
      );
      msgHash = keccak256(message);
      console.log("msgHash");
      console.logBytes32(msgHash);
      return msgHash;
    }

    function testSignature() public {
      address zeroEx = 0xDef1C0ded9bec7F1a1670819833240f027b25EfF;
      IGasworks.SwapCallInstruction[] memory swapCallInstructions = new IGasworks.SwapCallInstruction[](2);
      
      swapCallInstructions[0] = IGasworks.SwapCallInstruction(
              0x027aF1E12a5869eD329bE4c05617AD528E997D5A,
              0xacafe4865df8f1b,
              0x9a41E03fEF7f16f552C6FbA37fFA7590fb1Ec0c4,
              0x11e56dc11662818e,
              zeroEx,
              zeroEx,
              "0x415565b0000000000000000000000000027af1e12a5869ed329be4c05617ad528e997d5a0000000000000000000000009a41e03fef7f16f552c6fba37ffa7590fb1ec0c40000000000000000000000000000000000000000000000000abd537359d4acf400000000000000000000000000000000000000000000000011de9554065bdefa00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000042000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000038000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000027af1e12a5869ed329be4c05617ad528e997d5a0000000000000000000000009a41e03fef7f16f552c6fba37ffa7590fb1ec0c4000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000003400000000000000000000000000000000000000000000000000000000000000340000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000011de9554065bdefa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000012556e69737761705633000000000000000000000000000000000000000000000000000000000000000abd537359d4acf400000000000000000000000000000000000000000000000011de9554065bdefa000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000e592427a0aece92de3edee1f18e0157c05861564000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000042027af1e12a5869ed329be4c05617ad528e997d5a0001f47ceb23fd6bc0add59e62ac25578270cff1b9f619000bb89a41e03fef7f16f552c6fba37ffa7590fb1ec0c4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000027af1e12a5869ed329be4c05617ad528e997d5a000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000869584cd000000000000000000000000e129fe9fadab28bc0b9420ea6788a6fba8d6c62c00000000000000000000000000000000e142731e7f799447497163251dca468a"
      );

      swapCallInstructions[1] =  IGasworks.SwapCallInstruction(
              0x027aF1E12a5869eD329bE4c05617AD528E997D5A,
              0x5a887f0b5a3ee9c,
              0xBcD2C5C78000504EFBC1cE6489dfcaC71835406A,
              0x256eb8065a85c7aa,
              zeroEx,
              zeroEx,
              "0x415565b0000000000000000000000000027af1e12a5869ed329be4c05617ad528e997d5a000000000000000000000000bcd2c5c78000504efbc1ce6489dfcac71835406a00000000000000000000000000000000000000000000000005a456b9163855f100000000000000000000000000000000000000000000000025606692b53af3ab00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000042000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000038000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000027af1e12a5869ed329be4c05617ad528e997d5a000000000000000000000000bcd2c5c78000504efbc1ce6489dfcac71835406a000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000003400000000000000000000000000000000000000000000000000000000000000340000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000025606692b53af3ab000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000012556e697377617056330000000000000000000000000000000000000000000000000000000000000005a456b9163855f100000000000000000000000000000000000000000000000025606692b53af3ab000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000e592427a0aece92de3edee1f18e0157c05861564000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000042027af1e12a5869ed329be4c05617ad528e997d5a0001f47ceb23fd6bc0add59e62ac25578270cff1b9f619000bb8bcd2c5c78000504efbc1ce6489dfcac71835406a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000027af1e12a5869ed329be4c05617ad528e997d5a000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000869584cd000000000000000000000000e129fe9fadab28bc0b9420ea6788a6fba8d6c62c000000000000000000000000000000008b3c99cec7292025fde891902af1a954"
      );
      
      IGasworks.MintData memory mintData = IGasworks.MintData(
            0xAfb6E8331355faE99C8E8953bB4c6Dc5d11E9F3c,
            0x1e2c81727494ad00,
            0x027aF1E12a5869eD329bE4c05617AD528E997D5A,
            0x1e4d4740c8452824,
            0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449,
            swapCallInstructions
        );


      ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
          permitted: ISignatureTransfer.TokenPermissions({
              token: 0x027aF1E12a5869eD329bE4c05617AD528E997D5A,
              amount: 0x1e4d4740c8452824
          }),
          nonce: 0xe3da1ab5705ff67145d747a7929d7926fbfefe00b990003a2b472db256e495de,
          deadline: 0x64e3b487
      });

      bytes32 msgToSign = getMessageToSign(
        permit,
        0x9BcE588A792f6037eDE2006ECcBe04D1994650e5,
        mintData,
        domainSeparatorH
      );
      (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, msgToSign);
      bytes memory signature = bytes.concat(r, s, bytes1(v));
      console.log("signature");
      console.logBytes(signature);
      console.log('-------------------');
    }

    /**
     * [SUCCESS] Should make a mint of ADDY with USDC using permit2
     */
    function testMintChamberWithPermit2() public {
      address liveGasworksAddr = 0x9BcE588A792f6037eDE2006ECcBe04D1994650e5;
      IGasworks g = IGasworks(liveGasworksAddr);

      uint256 previousBalance = IERC20(aagg).balanceOf(owner);
        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 _maxPayAmount
        ) = abi.decode(res, (ITradeIssuerV2.ContractCallInstruction[], uint256));

        IGasworks.SwapCallInstruction[] memory swapCallInstructions =
            new IGasworks.SwapCallInstruction[](_contractCallInstructions.length);

        for (uint256 i = 0; i < _contractCallInstructions.length;) {
            // bytes memory originalCallData = _contractCallInstructions[i]._callData;
            // bytes memory slicedCallData = originalCallData.slice(2, originalCallData.length - 2);

            IGasworks.SwapCallInstruction memory instruction = IGasworks.SwapCallInstruction(
                address(_contractCallInstructions[i]._sellToken),
                _contractCallInstructions[i]._sellAmount,
                address(_contractCallInstructions[i]._buyToken),
                _contractCallInstructions[i]._minBuyAmount,
                _contractCallInstructions[i]._target,
                _contractCallInstructions[i]._allowanceTarget,
                _contractCallInstructions[i]._callData
            );
            // console.log('STRING');
            // console.log(string(_contractCallInstructions[i]._callData));

            swapCallInstructions[i] = instruction;
            unchecked {
                ++i;
            }
        }

        IGasworks.MintData memory myMintData = IGasworks.MintData(
            aagg,
            amountToMint,
            aedyOnPolygon,
            _maxPayAmount,
            address(issuerWizardAddress),
            swapCallInstructions
        );

        uint256 currentNonce = 0xe3da1ab5705ff67145d747a7929d7926fbfefe00b990003a2b472db256e495de;
        uint256 currentDeadline = 0x64F3079A;

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: aedyOnPolygon,
                amount: _maxPayAmount
            }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 realDomainSeparator = keccak256(abi.encode(
          keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
          keccak256(bytes("Permit2")),
          137,
          0x000000000022D473030F116dDEE9F6B43aC78BA3
          )
        );

        bytes32 msgToSign = getMessageToSign(
          permit,
          liveGasworksAddr, //address(gasworks),
          myMintData,
          realDomainSeparator //EIP712(permit2).DOMAIN_SEPARATOR()
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, msgToSign);
        bytes memory signature = bytes.concat(r, s, bytes1(v));
        console.log("signature");
        console.logBytes(signature);
        console.log('-------------------');
        g.mintWithPermit2(permit, owner, signature, myMintData);

        assertEq(IERC20(aagg).balanceOf(owner) - previousBalance, amountToMint);
    }

    function testRealCall() public {
      address liveGasworksAddr = 0x9BcE588A792f6037eDE2006ECcBe04D1994650e5;
      IGasworks g = IGasworks(liveGasworksAddr);

      ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: 0x027aF1E12a5869eD329bE4c05617AD528E997D5A,
                amount: 0x1e4d4740c8452824
            }),
            nonce: 0xe3da1ab5705ff67145d747a7929d7926fbfefe00b990003a2b472db256e495de,
            deadline: 0x64f312cd
        });

      IGasworks.SwapCallInstruction[] memory swapCallInstructions =
            new IGasworks.SwapCallInstruction[](2);

      IGasworks.SwapCallInstruction memory instruction0 = IGasworks.SwapCallInstruction(
          0x027aF1E12a5869eD329bE4c05617AD528E997D5A,
          0xacdb499fc7ddd62,
          0x9a41E03fEF7f16f552C6FbA37fFA7590fb1Ec0c4,
          0x11e9ed0156b448c4,
          0xDef1C0ded9bec7F1a1670819833240f027b25EfF,
          0xDef1C0ded9bec7F1a1670819833240f027b25EfF,
          abi.encodePacked("0x415565b0000000000000000000000000027af1e12a5869ed329be4c05617ad528e997d5a0000000000000000000000009a41e03fef7f16f552c6fba37ffa7590fb1ec0c40000000000000000000000000000000000000000000000000acdb499fc7ddd5800000000000000000000000000000000000000000000000011e9ed0156b448c400000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000042000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000038000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000027af1e12a5869ed329be4c05617ad528e997d5a0000000000000000000000009a41e03fef7f16f552c6fba37ffa7590fb1ec0c4000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000003400000000000000000000000000000000000000000000000000000000000000340000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000011e9ed0156b448c4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000012556e69737761705633000000000000000000000000000000000000000000000000000000000000000acdb499fc7ddd5800000000000000000000000000000000000000000000000011e9ed0156b448c4000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000e592427a0aece92de3edee1f18e0157c05861564000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000042027af1e12a5869ed329be4c05617ad528e997d5a0001f47ceb23fd6bc0add59e62ac25578270cff1b9f619000bb89a41e03fef7f16f552c6fba37ffa7590fb1ec0c4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000027af1e12a5869ed329be4c05617ad528e997d5a000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000869584cd000000000000000000000000e129fe9fadab28bc0b9420ea6788a6fba8d6c62c0000000000000000000000000000000064a9ba4620972701dd685c09d6f89a3a")
      );

      IGasworks.SwapCallInstruction memory instruction1 = IGasworks.SwapCallInstruction(
          0x027aF1E12a5869eD329bE4c05617AD528E997D5A,
          0x5a9f3f2a6c9ffa8,
          0xBcD2C5C78000504EFBC1cE6489dfcaC71835406A,
          0x2578200842559cb1,
          0xDef1C0ded9bec7F1a1670819833240f027b25EfF,
          0xDef1C0ded9bec7F1a1670819833240f027b25EfF, 
          abi.encodePacked("0x415565b0000000000000000000000000027af1e12a5869ed329be4c05617ad528e997d5a000000000000000000000000bcd2c5c78000504efbc1ce6489dfcac71835406a00000000000000000000000000000000000000000000000005a9f3f2a6c9ff9f0000000000000000000000000000000000000000000000002578200842559cb100000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000042000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000038000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000027af1e12a5869ed329be4c05617ad528e997d5a000000000000000000000000bcd2c5c78000504efbc1ce6489dfcac71835406a00000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000340000000000000000000000000000000000000000000000000000000000000034000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000002578200842559cb1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000012556e697377617056330000000000000000000000000000000000000000000000000000000000000005a9f3f2a6c9ff9f0000000000000000000000000000000000000000000000002578200842559cb1000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000e592427a0aece92de3edee1f18e0157c05861564000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000042027af1e12a5869ed329be4c05617ad528e997d5a0001f47ceb23fd6bc0add59e62ac25578270cff1b9f619000bb8bcd2c5c78000504efbc1ce6489dfcac71835406a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000027af1e12a5869ed329be4c05617ad528e997d5a000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000000000000000000000000000000000000000000000869584cd000000000000000000000000e129fe9fadab28bc0b9420ea6788a6fba8d6c62c000000000000000000000000000000000029d574678a72373fef5abfabeefa4c")
      );

      swapCallInstructions[0] = instruction0;
      swapCallInstructions[1] = instruction1;

      IGasworks.MintData memory customMintData = IGasworks.MintData(
          0xAfb6E8331355faE99C8E8953bB4c6Dc5d11E9F3c,
          0x1e341689a936ea0e,
          0x027aF1E12a5869eD329bE4c05617AD528E997D5A,
          0x1e4d4740c8452824,
          0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449,
          swapCallInstructions
      );

      bytes32 realDomainSeparator = keccak256(abi.encode(
          keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
          keccak256(bytes("Permit2")),
          137,
          0x000000000022D473030F116dDEE9F6B43aC78BA3
          )
      );

      bytes32 msgToSign = getMessageToSign(
          permit,
          liveGasworksAddr,
          customMintData,
          realDomainSeparator
        );
      (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, msgToSign);
      bytes memory signature = bytes.concat(r, s, bytes1(v));

      console.log("signature");
      console.logBytes(signature);
      console.log('-------------------');

      vm.prank(owner);
      g.mintWithPermit2(
        permit,
        liveGasworksAddr,
        signature,
        //abi.encodePacked("0x8d9eb28ac8bae5b28f5a386bd9fbfe87e08ba42a7b9d6e7942846d64adee160c76d5516a1d4d8d6dff32540782cb7f3c2f04010ae98be6d32b7f987a89c133611b"),
        customMintData
      );

    }
}
