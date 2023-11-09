// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import "forge-std/StdJson.sol";
import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { SigUtils } from "test/utils/SigUtils.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
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
    using stdJson for string;

    string root;
    string path;
    string json;

    IGasworks.SwapData internal revertTestsSwapData;
    uint256 revertTestsChainId;
    uint256 revertTestsBlockNumber;
    address revertTestsSellToken;
    uint256 revertTestsSellAmount;
    Gasworks reverTestsGasworks;
    address revertTestsUniswapPermit2;

    /*//////////////////////////////////////////////////////////////
                              SET UP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        addLabbels();
        root = vm.projectRoot();
        setUpRevertTestQuote();
    }

    /**
     * Saves a single quote in global variables, to use across all revert tests,
     * and therefore, avoid code duplication. You can change the JSON file quote
     * to test the revert tests with a different quote or asset
     */
    function setUpRevertTestQuote() public {
      path = string.concat(root, "/data/permitTwo/swap/testSwapWithPermit2FromAedyToAddy.json");
      json = vm.readFile(path);
      (
          uint256 chainId,
          uint256 blockNumber,
          address sellToken,
          uint256 sellAmount,
          address buyToken,
          uint256 buyAmount,
          uint256 nativeTokenAmount,
          address swapTarget,
          address swapAllowanceTarget,
          bytes memory swapCallData
      ) = parseSwapQuoteFromJson(json);

      revertTestsSwapData = IGasworks.SwapData(
          buyToken,
          buyAmount,
          nativeTokenAmount,
          payable(swapTarget),
          swapAllowanceTarget,
          swapCallData
      );
      revertTestsChainId = chainId;
      revertTestsBlockNumber = blockNumber;
      revertTestsSellToken = sellToken;
      revertTestsSellAmount = sellAmount;

      if (chainId == POLYGON_CHAIN_ID) {
          vm.createSelectFork("polygon", blockNumber);
          reverTestsGasworks = deployGasworks(chainId);
          revertTestsUniswapPermit2 = POLYGON_UNISWAP_PERMIT2;
      }
      if (chainId == ETH_CHAIN_ID) {
          vm.createSelectFork("ethereum", blockNumber);
          reverTestsGasworks = deployGasworks(chainId);
          revertTestsUniswapPermit2 = ETH_UNISWAP_PERMIT2;
      }
    }

    /*//////////////////////////////////////////////////////////////
                              REVERT
    //////////////////////////////////////////////////////////////*/

    /**
     * [REVERT] Should revert because allowed amount is less than required amount
     */
    function testCannotSwapWithPermit2NotEnoughAllowance() public {
      vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(revertTestsUniswapPermit2, 1); // Only allow 1 wei to permit2

        deal(revertTestsSellToken, ALICE, revertTestsSellAmount); // But give enough balance to mint
        uint256 previousSellTokenBalance = IERC20(revertTestsSellToken).balanceOf(ALICE);
        uint256 previousBuyTokenBalance = IERC20(revertTestsSwapData.buyToken).balanceOf(ALICE);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: revertTestsSellToken, amount: revertTestsSellAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign =
            getSwapWithPermit2MessageToSign(revertTestsChainId, permit, address(reverTestsGasworks), revertTestsSwapData);
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        reverTestsGasworks.swapWithPermit2(permit, ALICE, signature, revertTestsSwapData);

        assertEq(IERC20(revertTestsSellToken).balanceOf(ALICE), previousSellTokenBalance);
        assertEq(IERC20(revertTestsSwapData.buyToken).balanceOf(ALICE), previousBuyTokenBalance);
    }

    /**
     * [REVERT] Should revert because balance is less than required amount
     */
    function testCannotSwapWithPermit2NotEnoughBalance() public {
        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(revertTestsUniswapPermit2, type(uint256).max); // Max allowance to permit2

        deal(revertTestsSellToken, ALICE, 1); // Bot not enough balance [1 wei]
        uint256 previousSellTokenBalance = IERC20(revertTestsSellToken).balanceOf(ALICE);
        uint256 previousBuyTokenBalance = IERC20(revertTestsSwapData.buyToken).balanceOf(ALICE);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: revertTestsSellToken, amount: revertTestsSellAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign =
            getSwapWithPermit2MessageToSign(revertTestsChainId, permit, address(reverTestsGasworks), revertTestsSwapData);
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert("TRANSFER_FROM_FAILED");
        reverTestsGasworks.swapWithPermit2(permit, ALICE, signature, revertTestsSwapData);

        assertEq(IERC20(revertTestsSellToken).balanceOf(ALICE), previousSellTokenBalance);
        assertEq(IERC20(revertTestsSwapData.buyToken).balanceOf(ALICE), previousBuyTokenBalance);
    }

    /**
     * [REVERT] Should revert because the signature length is invalid
     */
    function testCannotSwapWithPermit2IncorrectSignatureLength() public {
        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(revertTestsUniswapPermit2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, revertTestsSellAmount);
        uint256 previousSellTokenBalance = IERC20(revertTestsSellToken).balanceOf(ALICE);
        uint256 previousBuyTokenBalance = IERC20(revertTestsSwapData.buyToken).balanceOf(ALICE);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: revertTestsSellToken, amount: revertTestsSellAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign =
            getSwapWithPermit2MessageToSign(revertTestsChainId, permit, address(reverTestsGasworks), revertTestsSwapData);
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);
        bytes memory invalidSignature = bytes.concat(signature, bytes1(uint8(0)));
        assertEq(invalidSignature.length, 66);

        vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
        reverTestsGasworks.swapWithPermit2(permit, ALICE, invalidSignature, revertTestsSwapData);

        assertEq(IERC20(revertTestsSellToken).balanceOf(ALICE), previousSellTokenBalance);
        assertEq(IERC20(revertTestsSwapData.buyToken).balanceOf(ALICE), previousBuyTokenBalance);
    }

    /**
     * [REVERT] Should revert because the signer of the permit
     * is not the owner of the tokens
     */
    function testCannotSwapWithPermit2IncorrectSigner() public {
        uint256 INVALID_SIGNER_PRIVATE_KEY = 0xb0b0000d3ad;

        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(revertTestsUniswapPermit2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, revertTestsSellAmount);
        uint256 previousSellTokenBalance = IERC20(revertTestsSellToken).balanceOf(ALICE);
        uint256 previousBuyTokenBalance = IERC20(revertTestsSwapData.buyToken).balanceOf(ALICE);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: revertTestsSellToken, amount: revertTestsSellAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign =
            getSwapWithPermit2MessageToSign(revertTestsChainId, permit, address(reverTestsGasworks), revertTestsSwapData);
        bytes memory signature = signMessage(INVALID_SIGNER_PRIVATE_KEY, msgToSign);

        vm.expectRevert();
        reverTestsGasworks.swapWithPermit2(permit, ALICE, signature, revertTestsSwapData);

        assertEq(IERC20(revertTestsSellToken).balanceOf(ALICE), previousSellTokenBalance);
        assertEq(IERC20(revertTestsSwapData.buyToken).balanceOf(ALICE), previousBuyTokenBalance);
    }

    /**
     * [REVERT] Should revert because the signature is expired
     */
    function testCannotSwapWithPermit2SignatureExpired() public {
        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(revertTestsUniswapPermit2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, revertTestsSellAmount);
        uint256 previousSellTokenBalance = IERC20(revertTestsSellToken).balanceOf(ALICE);
        uint256 previousBuyTokenBalance = IERC20(revertTestsSwapData.buyToken).balanceOf(ALICE);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = 2 ** 255 - 1;

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: revertTestsSellToken, amount: revertTestsSellAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign =
            getSwapWithPermit2MessageToSign(revertTestsChainId, permit, address(reverTestsGasworks), revertTestsSwapData);
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.warp(2 ** 255 + 1);

        vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, permit.deadline));
        reverTestsGasworks.swapWithPermit2(permit, ALICE, signature, revertTestsSwapData);

        assertEq(IERC20(revertTestsSellToken).balanceOf(ALICE), previousSellTokenBalance);
        assertEq(IERC20(revertTestsSwapData.buyToken).balanceOf(ALICE), previousBuyTokenBalance);
    }

    /**
     * [REVERT] Should revert because the nonce was used twice and should only be used once [replay attack]
     */
    function testCannotSwapWithPermit2InvalidNonce() public {
        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(revertTestsUniswapPermit2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, 3 * revertTestsSellAmount); // Give enough to mint 3 times
        uint256 previousSellTokenBalance = IERC20(revertTestsSellToken).balanceOf(ALICE);
        uint256 previousBuyTokenBalance = IERC20(revertTestsSwapData.buyToken).balanceOf(ALICE);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: revertTestsSellToken, amount: revertTestsSellAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign =
            getSwapWithPermit2MessageToSign(revertTestsChainId, permit, address(reverTestsGasworks), revertTestsSwapData);
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        reverTestsGasworks.swapWithPermit2(permit, ALICE, signature, revertTestsSwapData);

        assertEq(previousSellTokenBalance - IERC20(revertTestsSellToken).balanceOf(ALICE), revertTestsSellAmount);
        assertGe(IERC20(revertTestsSwapData.buyToken).balanceOf(ALICE) - previousBuyTokenBalance, revertTestsSwapData.buyAmount);

        vm.expectRevert(InvalidNonce.selector);
        reverTestsGasworks.swapWithPermit2(permit, ALICE, signature, revertTestsSwapData);
    }

    /**
     * [REVERT] Should revert because token is not permitted
     */
    function testCannotSwapWithPermit2InvalidToken() public {
        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(revertTestsUniswapPermit2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, 3 * revertTestsSellAmount); // Give enough to mint 3 times
        uint256 previousSellTokenBalance = IERC20(revertTestsSellToken).balanceOf(ALICE);
        uint256 previousBuyTokenBalance = IERC20(revertTestsSwapData.buyToken).balanceOf(ALICE);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        address invalidToken = address(0x123123);

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: invalidToken, amount: revertTestsSellAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign =
            getSwapWithPermit2MessageToSign(revertTestsChainId, permit, address(reverTestsGasworks), revertTestsSwapData);
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(abi.encodeWithSelector(IGasworks.InvalidToken.selector, invalidToken));
        reverTestsGasworks.swapWithPermit2(permit, ALICE, signature, revertTestsSwapData);

        assertEq(IERC20(revertTestsSellToken).balanceOf(ALICE), previousSellTokenBalance);
        assertEq(IERC20(revertTestsSwapData.buyToken).balanceOf(ALICE), previousBuyTokenBalance);
    }

    /**
     * [REVERT] Should revert because low level call to swapTarget failed
     */
    function testCannotSwapWithPermit2SwapCallFailed() public {
        IGasworks.SwapData memory corruptedSwapData = IGasworks.SwapData(
          revertTestsSwapData.buyToken,
          revertTestsSwapData.buyAmount,
          revertTestsSwapData.nativeTokenAmount,
          payable(revertTestsSwapData.swapTarget),
          revertTestsSwapData.swapAllowanceTarget,
          bytes("Corrupted quote")
        );

        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(revertTestsUniswapPermit2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, 3 * revertTestsSellAmount); // Give enough to mint 3 times
        uint256 previousSellTokenBalance = IERC20(revertTestsSellToken).balanceOf(ALICE);
        uint256 previousBuyTokenBalance = IERC20(corruptedSwapData.buyToken).balanceOf(ALICE);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: revertTestsSellToken, amount: revertTestsSellAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign =
            getSwapWithPermit2MessageToSign(revertTestsChainId, permit, address(reverTestsGasworks), corruptedSwapData);
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(IGasworks.SwapCallFailed.selector);
        reverTestsGasworks.swapWithPermit2(permit, ALICE, signature, corruptedSwapData);

        assertEq(IERC20(revertTestsSellToken).balanceOf(ALICE), previousSellTokenBalance);
        assertEq(IERC20(corruptedSwapData.buyToken).balanceOf(ALICE), previousBuyTokenBalance);
    }

    /**
     * [REVERT] Should revert due to underbought, because the sellAmount is too Big
     */
    function testCannotSwapWithPermit2UnderboughtAsset() public {
        uint256 exaggeratedBuyAmount = 2 * revertTestsSwapData.buyAmount;

        IGasworks.SwapData memory invalidSwapData = IGasworks.SwapData(
          revertTestsSwapData.buyToken,
          exaggeratedBuyAmount, // Buy amount is twice {swapCallData} will actually get
          revertTestsSwapData.nativeTokenAmount,
          payable(revertTestsSwapData.swapTarget),
          revertTestsSwapData.swapAllowanceTarget,
          revertTestsSwapData.swapCallData
        );

        vm.prank(ALICE);
        IERC20(revertTestsSellToken).approve(revertTestsUniswapPermit2, type(uint256).max);

        deal(revertTestsSellToken, ALICE, revertTestsSellAmount); // Give enough to mint 3 times
        uint256 previousSellTokenBalance = IERC20(revertTestsSellToken).balanceOf(ALICE);
        uint256 previousBuyTokenBalance = IERC20(invalidSwapData.buyToken).balanceOf(ALICE);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: revertTestsSellToken, amount: revertTestsSellAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign =
            getSwapWithPermit2MessageToSign(revertTestsChainId, permit, address(reverTestsGasworks), invalidSwapData);
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        vm.expectRevert(abi.encodeWithSelector(IGasworks.Underbought.selector, invalidSwapData.buyToken, exaggeratedBuyAmount));
        reverTestsGasworks.swapWithPermit2(permit, ALICE, signature, invalidSwapData);

        assertEq(IERC20(revertTestsSellToken).balanceOf(ALICE), previousSellTokenBalance);
        assertEq(IERC20(invalidSwapData.buyToken).balanceOf(ALICE), previousBuyTokenBalance);
    }

    /*//////////////////////////////////////////////////////////////
                              AUX FUNCT
    //////////////////////////////////////////////////////////////*/

    /**
     * Does a swap using Permit2, with the params (quote) given
     */
    function swapWithPermit2(
        uint256 chainId,
        uint256 blockNumber,
        address sellToken,
        uint256 sellAmount,
        address buyToken,
        uint256 buyAmount,
        uint256 nativeTokenAmount,
        address swapTarget,
        address swapAllowanceTarget,
        bytes memory swapCallData
    ) public {
        Gasworks gasworks;
        address uniswapPermit2;
        if (chainId == POLYGON_CHAIN_ID) {
            vm.createSelectFork("polygon", blockNumber);
            gasworks = deployGasworks(chainId);
            uniswapPermit2 = POLYGON_UNISWAP_PERMIT2;
        }
        if (chainId == ETH_CHAIN_ID) {
            vm.createSelectFork("ethereum", blockNumber);
            gasworks = deployGasworks(chainId);
            uniswapPermit2 = ETH_UNISWAP_PERMIT2;
        }

        vm.prank(ALICE);
        IERC20(sellToken).approve(uniswapPermit2, type(uint256).max);

        IGasworks.SwapData memory swapData = IGasworks.SwapData(
            buyToken,
            buyAmount,
            nativeTokenAmount,
            payable(swapTarget),
            swapAllowanceTarget,
            swapCallData
        );

        deal(sellToken, ALICE, sellAmount);
        uint256 previousSellTokenBalance = IERC20(sellToken).balanceOf(ALICE);
        uint256 previousBuyTokenBalance = IERC20(buyToken).balanceOf(ALICE);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: sellToken, amount: sellAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign =
            getSwapWithPermit2MessageToSign(chainId, permit, address(gasworks), swapData);
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        gasworks.swapWithPermit2(permit, ALICE, signature, swapData);

        assertEq(previousSellTokenBalance - IERC20(sellToken).balanceOf(ALICE), sellAmount);
        assertGe(IERC20(buyToken).balanceOf(ALICE) - previousBuyTokenBalance, swapData.buyAmount);
        assertEq(IERC20(sellToken).allowance(ALICE, address(gasworks)), 0);
    }

    /**
     * Loads params (quote) from a local json file, and then does a swap
     */
    function runLocalSwapQuoteTest(string memory fileName) public {
        path = string.concat(root, fileName);
        json = vm.readFile(path);
        (
            uint256 networkId,
            uint256 blockNumber,
            address sellToken,
            uint256 sellAmount,
            address buyToken,
            uint256 buyAmount,
            uint256 nativeTokenAmount,
            address swapTarget,
            address swapAllowanceTarget,
            bytes memory swapCallData
        ) = parseSwapQuoteFromJson(json);
        swapWithPermit2(
            networkId,
            blockNumber,
            sellToken,
            sellAmount,
            buyToken,
            buyAmount,
            nativeTokenAmount,
            swapTarget,
            swapAllowanceTarget,
            swapCallData
        );
    }

    /**
     * Used to create json files, fetches a quote from arch and prints a JSON-readable
     * quote in console, ready to be saved for new tests. The fork is needed to get the
     * block number alongside the quote.
     */
    function printQuoteToCreateATest() public {
        vm.createSelectFork("polygon");
        fetchSwapQuote(POLYGON_CHAIN_ID, 10e6, POLYGON_USDC, POLYGON_WMATIC);
    }

    /*//////////////////////////////////////////////////////////////
                              SUCCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should make a swap from USDC to WEB3 using permit2
     */
    function testSwapWithPermit2FromUsdcToWeb3() public {
        // swapWithPermit2(POLYGON_CHAIN_ID, 1e6, POLYGON_USDC, POLYGON_WEB3);
        runLocalSwapQuoteTest("/data/permitTwo/swap/testSwapWithPermit2FromUsdcToWeb3.json");
    }

    /**
     * [SUCCESS] Should make a swap from AEDY to ADDY using permit2
     */
    function testSwapWithPermit2FromAedyToAddy() public {
        runLocalSwapQuoteTest("/data/permitTwo/swap/testSwapWithPermit2FromAedyToAddy.json");
    }

    /**
     * [SUCCESS] Should make a swap from DAI to CHAIN using permit2
     */
    function testSwapWithPermit2FromDaiToChain() public {
        runLocalSwapQuoteTest("/data/permitTwo/swap/testSwapWithPermit2FromDaiToChain.json");
    }

    /**
     * [SUCCESS] Should make a swap from USDC to native MATIC with permit2
     */
    function testSwapWithPermit2FromUsdcToNativeMatic() public {
        path = string.concat(
            root, "/data/permitTwo/swap/testSwapWithPermit2FromUsdcToNativeMatic.json"
        );
        json = vm.readFile(path);
        (
            ,
            uint256 blockNumber,
            address sellToken,
            uint256 sellAmount,
            address buyToken,
            uint256 buyAmount,
            uint256 nativeTokenAmount,
            address swapTarget,
            address swapAllowanceTarget,
            bytes memory swapCallData
        ) = parseSwapQuoteFromJson(json);

        vm.createSelectFork("polygon", blockNumber);
        Gasworks gasworks = deployGasworks(POLYGON_CHAIN_ID);
        address uniswapPermit2 = POLYGON_UNISWAP_PERMIT2;

        vm.prank(ALICE);
        IERC20(sellToken).approve(uniswapPermit2, type(uint256).max);
        IGasworks.SwapData memory swapData = IGasworks.SwapData(
            buyToken,
            buyAmount,
            nativeTokenAmount,
            payable(swapTarget),
            swapAllowanceTarget,
            swapCallData
        );

        deal(sellToken, ALICE, sellAmount);
        uint256 previousSellTokenBalance = IERC20(sellToken).balanceOf(ALICE);
        uint256 previousBuyTokenBalance = IERC20(buyToken).balanceOf(ALICE);

        uint256 currentNonce = getRandomNonce();
        uint256 currentDeadline = getFiveMinutesDeadlineFromNow();

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: sellToken, amount: sellAmount }),
            nonce: currentNonce,
            deadline: currentDeadline
        });

        bytes32 msgToSign =
            getSwapWithPermit2MessageToSign(POLYGON_CHAIN_ID, permit, address(gasworks), swapData);
        bytes memory signature = signMessage(ALICE_PRIVATE_KEY, msgToSign);

        gasworks.swapWithPermit2(permit, ALICE, signature, swapData);

        assertEq(previousSellTokenBalance - IERC20(sellToken).balanceOf(ALICE), sellAmount);
        assertEq(IERC20(sellToken).allowance(ALICE, address(gasworks)), 0);
        assertGe(previousBuyTokenBalance - IERC20(buyToken).balanceOf(ALICE), 0);
        assertGe(ALICE.balance, swapData.buyAmount); // Receive MATIC, not WMATIC
    }
}
