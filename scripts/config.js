// Ethereum
const ethereumIssuerWizard = '0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449';
const ethereumTradeIssuerV3 = '0xB7c045d187985C16856Ce42455dA59e89dB11DC9';

const commonParams = {
  tokenAddress: '',
  basketAmountInWei: '',
  slippagePercentageProportion: 0.05,
  isDebtIssuance: true,
}

const ethereumParams = {
  ...commonParams,
  networkId: 1,
  issuerWizardAddress: ethereumIssuerWizard,
  traderPeripheralAddress: ethereumTradeIssuerV3,
}

// Polygon
const polygonIssuerWizard = '0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449';
const polygonTradeIssuerV3 = '0xdCB99117Ba207b996EE3c49eE6F8c0f1d371867A';

const polygonParams = {
  ...commonParams,
  networkId: 137,
  issuerWizardAddress: polygonIssuerWizard,
  traderPeripheralAddress: polygonTradeIssuerV3,
}

const ETH_AEDY = '0x103bb3EBc6F61b3DB2d6e01e54eF7D9899A2E16B';
const ETH_ADDY = "0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF";
const ETH_WEB3V2 = "0x8F0d5660929cA6ac394c5c41f59497629b1dbc23";
const ETH_CHAINV2 = "0x89c53B02558E4D1c24b9Bf3beD1279871187EF0B";
// Extra tokens [For swap configuration]
const ETH_USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const ETH_USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
const ETH_DAI = "0x6B175474E89094C44Da98b954EedeAC495271d0F";
const ETH_WBTC = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599";
const ETH_WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

const ethereumExtraTokens = {
  [ETH_USDC]: { ...ethereumParams, tokenAddress: ETH_USDC },
  [ETH_USDT]: { ...ethereumParams, tokenAddress: ETH_USDT },
  [ETH_DAI]: { ...ethereumParams, tokenAddress: ETH_DAI },
  [ETH_WBTC]: { ...ethereumParams, tokenAddress: ETH_WBTC },
  [ETH_WETH]: { ...ethereumParams, tokenAddress: ETH_WETH },
}

const POLYGON_AEDY = "0x027aF1E12a5869eD329bE4c05617AD528E997D5A";
const POLYGON_ADDY = "0xAb1B1680f6037006e337764547fb82d17606c187";
const POLYGON_AAGG = "0xAfb6E8331355faE99C8E8953bB4c6Dc5d11E9F3c";
const POLYGON_AMOD = "0xa5a979Aa7F55798e99f91Abe815c114A09164beb";
const POLYGON_ABAL = "0xF401E2c1ce8F252947b60BFB92578f84217A1545";
const POLYGON_WEB3V2 = "0xC4ea087fc2cB3a1D9ff86c676F03abE4F3EE906F";
const POLYGON_CHAINV2 = "0x70A13201Df2364B634cb5Aac8d735Db3A654b30c";
const POLYGON_ABDY = "0xdE2925D582fc8711a0E93271c12615Bdd043Ed1C";
// Extra tokens [For swap configuration]
const POLYGON_USDC_e = "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174";
const POLYGON_USDC = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359";
const POLYGON_USDT = "0xc2132D05D31c914a87C6611C10748AEb04B58e8F";
const POLYGON_DAI = "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063";
const POLYGON_WBTC = "0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6";
const POLYGON_WMATIC = "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270";

const polygonExtraTokens = {
  [POLYGON_USDC_e]: { ...polygonParams, tokenAddress: POLYGON_USDC_e },
  [POLYGON_USDC]: { ...polygonParams, tokenAddress: POLYGON_USDC },
  [POLYGON_USDT]: { ...polygonParams, tokenAddress: POLYGON_USDT },
  [POLYGON_DAI]: { ...polygonParams, tokenAddress: POLYGON_DAI },
  [POLYGON_WBTC]: { ...polygonParams, tokenAddress: POLYGON_WBTC },
  [POLYGON_WMATIC]: { ...polygonParams, tokenAddress: POLYGON_WMATIC },
}


const archTokens = {
  [ETH_AEDY]: { ...ethereumParams, basketAddress: ETH_AEDY },
  [ETH_ADDY]: { ...ethereumParams, basketAddress: ETH_ADDY },
  [ETH_WEB3V2]: { ...ethereumParams, basketAddress: ETH_WEB3V2 },
  [ETH_CHAINV2]: { ...ethereumParams, basketAddress: ETH_CHAINV2},
  ...ethereumExtraTokens,
  [POLYGON_AEDY]: { ...polygonParams, basketAddress: POLYGON_AEDY },
  [POLYGON_ADDY]: { ...polygonParams, basketAddress: POLYGON_ADDY },
  [POLYGON_AAGG]: { ...polygonParams, basketAddress: POLYGON_AAGG },
  [POLYGON_AMOD]: { ...polygonParams, basketAddress: POLYGON_AMOD },
  [POLYGON_ABAL]: { ...polygonParams, basketAddress: POLYGON_ABAL },
  [POLYGON_WEB3V2]: { ...polygonParams, basketAddress: POLYGON_WEB3V2 },
  [POLYGON_CHAINV2]: { ...polygonParams, basketAddress: POLYGON_CHAINV2 },
  [POLYGON_ABDY]: { ...polygonParams, basketAddress: POLYGON_ABDY },
  ...polygonExtraTokens,
}

export {archTokens};