const AP60TokenParams = {
  tokenAddress: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
  slippagePercentageProportion: 0.005,
  networkId: 137,
  issuanceModuleAddress: '0xf2dC2f456b98Af9A6bEEa072AF152a7b0EaA40C9',
  isDebtIssuance: true,
  basketAmountInWei: '',
  basketAddress: '0x6cA9C8914a14D63a6700556127D09e7721ff7D3b',
}

const ADDYTokenParams = {
  tokenAddress: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
  slippagePercentageProportion: 0.05,
  networkId: 1,
  issuanceModuleAddress: '0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449',
  isDebtIssuance: true,
  basketAmountInWei: '',
  basketAddress: '0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF',
}

const AAGGTokenParams = {
  tokenAddress: '0x6b175474e89094c44da98b954eedeac495271d0f',
  slippagePercentageProportion: 0.05,
  networkId: 137,
  issuanceModuleAddress: '0x60F56236CD3C1Ac146BD94F2006a1335BaA4c449',
  isDebtIssuance: true,
  basketAmountInWei: '',
  basketAddress: '0xAfb6E8331355faE99C8E8953bB4c6Dc5d11E9F3c',
}


const archTokens = {
  "0x6cA9C8914a14D63a6700556127D09e7721ff7D3b": AP60TokenParams,
  "0xE15A66b7B8e385CAa6F69FD0d55984B96D7263CF": ADDYTokenParams,
  "0xAfb6E8331355faE99C8E8953bB4c6Dc5d11E9F3c": AAGGTokenParams,
}

module.exports = {
  archTokens
}