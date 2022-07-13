const { ethers } = require("ethers")
const axios = require("axios").default

const API_QUOTE_URL = "https://polygon.api.0x.org/swap/v1/quote"

function createQueryString(params) {
  return Object.entries(params)
    .map(([k, v]) => `${k}=${v}`)
    .join("&")
}

async function main() {

  let qs = createQueryString({
    sellToken: "USDC",
    buyToken: "0xBcD2C5C78000504EFBC1cE6489dfcaC71835406A",
    sellAmount: 1000000,
  })

  let quoteUrl = `${API_QUOTE_URL}?${qs}`
  let response = await axios.get(quoteUrl)
  let quote = response.data
  
  console.log("spender: " + quote.allowanceTarget)
  console.log("swapTarget: " + quote.to)
  console.log("quote data: " + quote.data)
  console.log("value: " + quote.value);
}

main()
