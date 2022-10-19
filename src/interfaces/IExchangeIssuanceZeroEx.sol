//    SPDX-License-Identifier: Unlicensed

pragma solidity ^0.8.9;

pragma experimental ABIEncoderV2;

import {Address} from "openzeppelin-contracts/contracts/utils/Address.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {SafeMath} from "openzeppelin-contracts/contracts/utils/math/SafeMath.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/security/ReentrancyGuard.sol";

import {IController} from "./IController.sol";
import {ISetToken} from "./ISetToken.sol";

interface IExchangeIssuanceZeroEx {
    struct IssuanceModuleData {
        bool isAllowed;
        bool isDebtIssuanceModule;
    }

    event ExchangeIssue( // The recipient address of the issued SetTokens
        // The issued SetToken
        // The address of the input asset(ERC20/ETH) used to issue the SetTokens
        // The amount of input tokens used for issuance
        // The amount of SetTokens received by the recipient
        address indexed _recipient,
        ISetToken indexed _setToken,
        IERC20 indexed _inputToken,
        uint256 _amountInputToken,
        uint256 _amountSetIssued
    );

    event ExchangeRedeem( // The recipient adress of the output tokens obtained for redemption
        // The redeemed SetToken
        // The address of output asset(ERC20/ETH) received by the recipient
        // The amount of SetTokens redeemed for output tokens
        // The amount of output tokens received by the recipient
        address indexed _recipient,
        ISetToken indexed _setToken,
        IERC20 indexed _outputToken,
        uint256 _amountSetRedeemed,
        uint256 _amountOutputToken
    );

    function withdrawTokens(IERC20[] calldata _tokens, address payable _to) external payable;

    receive() external payable;

    /* ============ Public Functions ============ */

    /**
     * Runs all the necessary approval functions required for a given ERC20 token.
     * This function can be called when a new token is added to a SetToken during a
     * rebalance.
     *
     * @param _token    Address of the token which needs approval
     * @param _spender  Address of the spender which will be approved to spend token. (Must be a whitlisted issuance module)
     */
    function approveToken(IERC20 _token, address _spender) external;

    /**
     * Runs all the necessary approval functions required for a list of ERC20 tokens.
     *
     * @param _tokens    Addresses of the tokens which need approval
     * @param _spender   Address of the spender which will be approved to spend token. (Must be a whitlisted issuance module)
     */
    function approveTokens(IERC20[] calldata _tokens, address _spender) external;

    /**
     * Runs all the necessary approval functions required before issuing
     * or redeeming a SetToken. This function need to be called only once before the first time
     * this smart contract is used on any particular SetToken.
     *
     * @param _setToken          Address of the SetToken being initialized
     * @param _issuanceModule    Address of the issuance module which will be approved to spend component tokens.
     */
    function approveSetToken(ISetToken _setToken, address _issuanceModule) external;

    /**
     * Issues an exact amount of SetTokens for given amount of input ERC20 tokens.
     * The excess amount of tokens is returned in an equivalent amount of ether.
     *
     * @param _setToken              Address of the SetToken to be issued
     * @param _inputToken            Address of the input token
     * @param _amountSetToken        Amount of SetTokens to issue
     * @param _maxAmountInputToken   Maximum amount of input tokens to be used to issue SetTokens.
     * @param _componentQuotes       The encoded 0x transactions to execute
     *
     * @return totalInputTokenSold   Amount of input token spent for issuance
     */
    function issueExactSetFromToken(
        ISetToken _setToken,
        IERC20 _inputToken,
        uint256 _amountSetToken,
        uint256 _maxAmountInputToken,
        bytes[] memory _componentQuotes,
        address _issuanceModule,
        bool _isDebtIssuance
    )
        external
        returns (uint256);

    /**
     * Issues an exact amount of SetTokens for given amount of ETH.
     * The excess amount of tokens is returned in an equivalent amount of ether.
     *
     * @param _setToken              Address of the SetToken to be issued
     * @param _amountSetToken        Amount of SetTokens to issue
     * @param _componentQuotes       The encoded 0x transactions to execute
     *
     * @return amountEthReturn       Amount of ether returned to the caller
     */
    function issueExactSetFromETH(
        ISetToken _setToken,
        uint256 _amountSetToken,
        bytes[] memory _componentQuotes,
        address _issuanceModule,
        bool _isDebtIssuance
    )
        external
        payable
        returns (uint256);

    /**
     * Redeems an exact amount of SetTokens for an ERC20 token.
     * The SetToken must be approved by the sender to this contract.
     *
     * @param _setToken             Address of the SetToken being redeemed
     * @param _outputToken          Address of output token
     * @param _amountSetToken       Amount SetTokens to redeem
     * @param _minOutputReceive     Minimum amount of output token to receive
     * @param _componentQuotes      The encoded 0x transactions execute (components -> WETH).
     * @param _issuanceModule       Address of issuance Module to use
     * @param _isDebtIssuance       Flag indicating wether given issuance module is a debt issuance module
     *
     * @return outputAmount         Amount of output tokens sent to the caller
     */
    function redeemExactSetForToken(
        ISetToken _setToken,
        IERC20 _outputToken,
        uint256 _amountSetToken,
        uint256 _minOutputReceive,
        bytes[] memory _componentQuotes,
        address _issuanceModule,
        bool _isDebtIssuance
    )
        external
        returns (uint256);

    /**
     * Redeems an exact amount of SetTokens for ETH.
     * The SetToken must be approved by the sender to this contract.
     *
     * @param _setToken             Address of the SetToken being redeemed
     * @param _amountSetToken       Amount SetTokens to redeem
     * @param _minEthReceive        Minimum amount of Eth to receive
     * @param _componentQuotes      The encoded 0x transactions execute
     * @param _issuanceModule       Address of issuance Module to use
     * @param _isDebtIssuance       Flag indicating wether given issuance module is a debt issuance module
     *
     * @return outputAmount         Amount of output tokens sent to the caller
     */
    function redeemExactSetForETH(
        ISetToken _setToken,
        uint256 _amountSetToken,
        uint256 _minEthReceive,
        bytes[] memory _componentQuotes,
        address _issuanceModule,
        bool _isDebtIssuance
    )
        external
        returns (uint256);

    /**
     * Returns component positions required for issuance
     *
     * @param _issuanceModule    Address of issuance Module to use
     * @param _isDebtIssuance    Flag indicating wether given issuance module is a debt issuance module
     * @param _setToken          Set token to issue
     * @param _amountSetToken    Amount of set token to issue
     */
    function getRequiredIssuanceComponents(
        address _issuanceModule,
        bool _isDebtIssuance,
        ISetToken _setToken,
        uint256 _amountSetToken
    )
        external
        view
        returns (address[] memory components, uint256[] memory positions);

    /**
     * Returns component positions required for Redemption
     *
     * @param _issuanceModule    Address of issuance Module to use
     * @param _isDebtIssuance    Flag indicating wether given issuance module is a debt issuance module
     * @param _setToken          Set token to issue
     * @param _amountSetToken    Amount of set token to issue
     */
    function getRequiredRedemptionComponents(
        address _issuanceModule,
        bool _isDebtIssuance,
        ISetToken _setToken,
        uint256 _amountSetToken
    )
        external
        view
        returns (address[] memory components, uint256[] memory positions);
}
