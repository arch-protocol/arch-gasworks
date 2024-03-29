// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17.0;

import "forge-std/StdJson.sol";
import { Test } from "forge-std/Test.sol";
import { Gasworks } from "src/Gasworks.sol";
import { IGasworks } from "src/interfaces/IGasworks.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { Permit2Utils } from "test/utils/Permit2Utils.sol";
import { ITradeIssuerV3 } from "chambers-peripherals/src/interfaces/ITradeIssuerV3.sol";

contract GaslessTest is Test, Permit2Utils {
    /*//////////////////////////////////////////////////////////////
                            VARIABLES
    //////////////////////////////////////////////////////////////*/
    using SafeERC20 for IERC20;
    using stdJson for string;

    string root;
    string path;
    string json;

    /*//////////////////////////////////////////////////////////////
                            SET UP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        addLabbels();
        root = vm.projectRoot();
    }

    /*//////////////////////////////////////////////////////////////
                            AUX FUNCT
    //////////////////////////////////////////////////////////////*/

    /**
     * Mints a chamber using Permit2, with the params and call instructions (quote) given
     */
    function mintChamber(
        uint256 chainId,
        uint256 blockNumber,
        address archToken,
        uint256 archTokenAmount,
        address fromToken,
        uint256 maxPayAmount,
        ITradeIssuerV3.ContractCallInstruction[] memory contractCallInstructions
    ) public {
        Gasworks gasworks;
        address issuerWizard;
        address uniswapPermit2;
        if (chainId == POLYGON_CHAIN_ID) {
            vm.createSelectFork("polygon", blockNumber);
            gasworks = deployGasworks(chainId);
            issuerWizard = POLYGON_ISSUER_WIZARD;
            uniswapPermit2 = POLYGON_UNISWAP_PERMIT2;
        }
        if (chainId == ETH_CHAIN_ID) {
            vm.createSelectFork("ethereum", blockNumber);
            gasworks = deployGasworks(chainId);
            issuerWizard = ETH_ISSUER_WIZARD;
            uniswapPermit2 = ETH_UNISWAP_PERMIT2;
        }

        vm.prank(ALICE);
        IERC20(fromToken).approve(uniswapPermit2, type(uint256).max);
        uint256 previousArchTokenBalance = IERC20(archToken).balanceOf(ALICE);

        deal(fromToken, ALICE, maxPayAmount);
        uint256 previousFromTokenBalance = IERC20(fromToken).balanceOf(ALICE);

        IGasworks.SwapCallInstruction[] memory swapCallInstructions =
            getSwapCallsFromContractCalls(contractCallInstructions);

        IGasworks.MintData memory myMintData = IGasworks.MintData(
            archToken, archTokenAmount, fromToken, maxPayAmount, issuerWizard, swapCallInstructions
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

        assertEq(IERC20(archToken).balanceOf(ALICE) - previousArchTokenBalance, archTokenAmount);
        assertLe(previousFromTokenBalance - IERC20(fromToken).balanceOf(ALICE), maxPayAmount);
    }

    /**
     * Loads params and call instructions (quote) from a local json file, and then
     * runs it to mint a chamber
     */
    function runLocalMintQuoteTest(string memory fileName) public {
        path = string.concat(root, fileName);
        json = vm.readFile(path);
        (
            uint256 networkId,
            uint256 blockNumber,
            address archToken,
            uint256 archTokenAmount,
            address fromToken,
            uint256 maxPayAmount,
            ITradeIssuerV3.ContractCallInstruction[] memory callInstrictions
        ) = parseMintQuoteFromJson(json);
        mintChamber(
            networkId,
            blockNumber,
            archToken,
            archTokenAmount,
            fromToken,
            maxPayAmount,
            callInstrictions
        );
    }

    /**
     * Used to create json files, fetches a quote from arch and prints a JSON-readable
     * quote in console, ready to be saved for new tests. The fork is needed to get the
     * block number alongside the quote.
     */
    function printQuoteToCreateATest() public {
        vm.createSelectFork("polygon");
        fetchMintQuote(POLYGON_CHAIN_ID, POLYGON_AMOD, 100e18, POLYGON_ADDY);
    }

    /*//////////////////////////////////////////////////////////////
                            SUCCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * [SUCCESS] Should make a mint of AAGG with WEB3 using permit2
     */
    function testMintWithPermit2FromWeb3ToAaggOnPolygon() public {
        runLocalMintQuoteTest(
            "/data/permitTwo/mint/testMintWithPermit2FromWeb3ToAaggOnPolygon.json"
        );
    }

    /**
     * [SUCCESS] Should make a mint of AMOD with ADDY using permit2
     */
    function testMintWithPermit2FromAddyToAmodOnPolygon() public {
        runLocalMintQuoteTest(
            "/data/permitTwo/mint/testMintWithPermit2FromAddyToAmodOnPolygon.json"
        );
    }

    /**
     * [SUCCESS] Should make a mint of ABAL with CHAIN using permit2
     */
    function testMintWithPermit2FromChainToAbalOnPolygon() public {
        runLocalMintQuoteTest(
            "/data/permitTwo/mint/testMintWithPermit2FromChainToAbalOnPolygon.json"
        );
    }
}
