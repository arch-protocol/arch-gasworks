// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21.0;

import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { Permit2Utils } from "test/utils/Permit2Utils.sol";
import { ITradeIssuerV2 } from "chambers-peripherals/src/interfaces/ITradeIssuerV2.sol";

contract GaslessTest is Test, Permit2Utils {
    /*//////////////////////////////////////////////////////////////
                              VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public { }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    function redeemChamber(uint256 chainId, address archToken, address toToken) public {
      Gasworks gasworks;
      address issuerWizard;
      address uniswapPermit2;
      if (chainId == POLYGON_CHAIN_ID) {
        vm.createSelectFork("polygon");
        gasworks = deployGasworks(chainId);
        issuerWizard = POLYGON_ISSUER_WIZARD;
        uniswapPermit2 = POLYGON_UNISWAP_PERMIT2;
      }
      if (chainId == ETH_CHAIN_ID) {
        vm.createSelectFork("ethereum");
        gasworks = deployGasworks(chainId);
        issuerWizard = ETH_ISSUER_WIZARD;
        uniswapPermit2 = ETH_UNISWAP_PERMIT2;
      }

      vm.prank(ALICE);
      IERC20(archToken).approve(uniswapPermit2, type(uint256).max);
      uint256 amountToRedeem = 5e18;
      uint256 previousToTokenBalance = IERC20(toToken).balanceOf(ALICE);

      (
          ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
          uint256 minReceiveAmount
      ) = fetchRedeemQuote(archToken, amountToRedeem, toToken);

      deal(archToken, ALICE, amountToRedeem);
      uint256 previousArchTokenBalance = IERC20(archToken).balanceOf(ALICE);
      
      IGasworks.SwapCallInstruction[] memory swapCallInstructions =
          getSwapCallsFromContractCalls(_contractCallInstructions);
      
      IGasworks.RedeemData memory myRedeemData = IGasworks.RedeemData(
          archToken,
          amountToRedeem,
          toToken,
          minReceiveAmount,
          issuerWizard,
          swapCallInstructions
      );

      uint256 currentNonce = getRandomNonce();
      uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

      ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
          permitted: ISignatureTransfer.TokenPermissions({ token: archToken, amount: amountToRedeem }),
          nonce: currentNonce,
          deadline: currentDeadline
      });

      bytes32 msgToSign = getRedeemWithPermit2MessageToSign(
          chainId,
          permit,
          address(gasworks),
          myRedeemData
      );
      bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

      gasworks.redeemWithPermit2(permit, ALICE, signature, myRedeemData, false);

      assertGe(IERC20(toToken).balanceOf(ALICE) - previousToTokenBalance, minReceiveAmount);
      assertEq(previousArchTokenBalance - IERC20(archToken).balanceOf(ALICE), amountToRedeem);
    }

    /**
     * [SUCCESS] Should redeem AAGG for AEDY using permit2
     */
    function testRedeemWithPermit2FromAaggToAedyOnPolygon() public {
        redeemChamber(POLYGON_CHAIN_ID, POLYGON_AAGG, POLYGON_AEDY);
    }

    /**
     * [SUCCESS] Should redeem AMOD for USDT using permit2
     */
    function testRedeemWithPermit2FromAmodToUsdtOnPolygon() public {
        redeemChamber(POLYGON_CHAIN_ID, POLYGON_AMOD, POLYGON_USDT);
    }

    /**
     * [SUCCESS] Should redeem ABAL for USDC using permit2
     */
    function testRedeemWithPermit2FromAbalToUsdcOnPolygon() public {
        redeemChamber(POLYGON_CHAIN_ID, POLYGON_ABAL, POLYGON_USDC);
    }

    /**
     * [SUCCESS] Should redeem AEDY for CHAIN using permit2
     */
    function testRedeemWithPermit2FromAedyToChainOnEthereum() public {
        redeemChamber(ETH_CHAIN_ID, ETH_AEDY, ETH_CHAIN);
    }

    /**
     * [SUCCESS] Should redeem ADDY for WETH using permit2
     */
    function testRedeemWithPermit2FromAddyToWethOnEthereum() public {
        redeemChamber(ETH_CHAIN_ID, ETH_ADDY, ETH_WETH);
    }
}
