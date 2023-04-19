const AP60TokenParams = {
  tokenAddress: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
  slippagePercentageProportion: 0.005,
  networkId: 137,
  issuanceModuleAddress: '0xf2dC2f456b98Af9A6bEEa072AF152a7b0EaA40C9',
  isDebtIssuance: true,
  basketAmountInWei: '',
  basketAddress: '0x6cA9C8914a14D63a6700556127D09e7721ff7D3b',
}

const archTokens = {
  "0x6cA9C8914a14D63a6700556127D09e7721ff7D3b": AP60TokenParams,
}

module.exports = {
  archTokens
}