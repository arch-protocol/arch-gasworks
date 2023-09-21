// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

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
    function setUp() public {
        addLabbels();
    }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    function mintChamber(uint256 chainId, address archToken, address fromToken) public {
        Gasworks gasworks;
        address issuerWizard;
        address uniswapPermit2;
        if (chainId == POLYGON_CHAIN_ID) {
            vm.createSelectFork("polygon", 47789092);
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
        IERC20(fromToken).approve(uniswapPermit2, type(uint256).max);
        uint256 previousArchTokenBalance = IERC20(archToken).balanceOf(ALICE);
        uint256 amountToMint = 2514538865628034790;

        (
            ITradeIssuerV2.ContractCallInstruction[] memory _contractCallInstructions,
            uint256 maxPayAmount
        ) = fetchMintQuote(archToken, amountToMint, fromToken);

        deal(fromToken, ALICE, maxPayAmount);
        uint256 previousFromTokenBalance = IERC20(fromToken).balanceOf(ALICE);

        IGasworks.SwapCallInstruction[] memory swapCallInstructions =
            getSwapCallsFromContractCalls(_contractCallInstructions);

        IGasworks.MintData memory myMintData = IGasworks.MintData(
            archToken, amountToMint, fromToken, maxPayAmount, issuerWizard, swapCallInstructions
        );

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: fromToken, amount: maxPayAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign =
            getMintWithPermit2MessageToSign(chainId, permit, address(gasworks), myMintData);
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        gasworks.mintWithPermit2(permit, ALICE, signature, myMintData);

        uint256 finalFromTokenBalanceDiff = previousFromTokenBalance - IERC20(fromToken).balanceOf(ALICE);

        assertEq(IERC20(archToken).balanceOf(ALICE) - previousArchTokenBalance, amountToMint);
        assertLe(finalFromTokenBalanceDiff, maxPayAmount);
    }

    /**
     * [SUCCESS] Should make a mint of AAGG with WEB3 using permit2
     */
    function testMintWithPermit2FromWeb3ToAaggOnPolygon() public {
        mintChamber(POLYGON_CHAIN_ID, POLYGON_AAGG, POLYGON_USDC);
    }
}
