// Ethereum
const issuerWizardOnEthereum = '0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449';
const tradeIssuerV2OnEthereum = '0xbbCA2AcBd87Ce7A5e01fb56914d41F6a7e5C5A56';

// Polygon
const issuerWizard = '0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449';
const tradeIssuerV2 = '0x2b13d2b9407d5776b0bb63c8cd144978b6b7ce58';
const issuanceModule = '0xf2dC2f456b98Af9A6bEEa072AF152a7b0EaA40C9';
const exchangeIssuance = '0x1c0c05a2aA31692e5dc9511b04F651db9E4d8320';

const commonParams = {
  tokenAddress: '',
  basketAmountInWei: '',
  slippagePercentageProportion: 0.05,
  isDebtIssuance: true,
}
const setPolygonParams = {
  ...commonParams,
  issuerWizardAddress: issuanceModule,
  traderPeripheralAddress: exchangeIssuance,
}

const chamberParams = {
  ...commonParams,
  issuerWizardAddress: issuerWizard,
  traderPeripheralAddress: tradeIssuerV2,
}

const ETH_AEDY = '0x103bb3EBc6F61b3DB2d6e01e54eF7D9899A2E16B';
const ETH_ADDY = "0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF";
const POLYGON_AAGG = "0xAfb6E8331355faE99C8E8953bB4c6Dc5d11E9F3c";
const POLYGON_AMOD = "0x8F0d5660929cA6ac394c5c41f59497629b1dbc23";
const POLYGON_ABAL = "0xF401E2c1ce8F252947b60BFB92578f84217A1545";
const POLYGON_AP60 = "0x6cA9C8914a14D63a6700556127D09e7721ff7D3b";

const AEDYTokenParams = {
  ...chamberParams,
  networkId: 1,
  issuerWizardAddress: issuerWizardOnEthereum,
  traderPeripheralAddress: tradeIssuerV2OnEthereum,
  basketAddress: ETH_AEDY,
}

const ADDYTokenParams = {
  ...chamberParams,
  networkId: 1,
  issuerWizardAddress: issuerWizardOnEthereum,
  traderPeripheralAddress: tradeIssuerV2OnEthereum,
  basketAddress: ETH_ADDY,
}

const AAGGTokenParams = {
  ...chamberParams,
  networkId: 137,
  basketAddress: POLYGON_AAGG,
}

const AMODTokenParams = {
  ...chamberParams,
  networkId: 137,
  basketAddress: POLYGON_AMOD,
}

const ABALTokenParams = {
  ...chamberParams,
  networkId: 137,
  basketAddress: POLYGON_ABAL,
}

const AP60TokenParams = {
  ...setPolygonParams,
  networkId: 137,
  basketAddress: POLYGON_AP60,
}

const archTokens = {
  [ETH_AEDY]: AEDYTokenParams,
  [ETH_ADDY]: ADDYTokenParams,
  [POLYGON_AAGG]: AAGGTokenParams,
  [POLYGON_AMOD]: AMODTokenParams,
  [POLYGON_ABAL]: ABALTokenParams,
  [POLYGON_AP60]: AP60TokenParams,
}

export {archTokens};