import { ethers } from "ethers";
import {get} from './get.js';
const encoder = new ethers.AbiCoder();

const API_QUOTE_URL = "https://polygon.api.0x.org/swap/v1/quote"

function createQueryString(params) {
  return Object.entries(params)
    .map(([k, v]) => `${k}=${v}`)
    .join("&")
}

async function main(quantity, buyToken) {

  let qty = encoder.decode(["uint256"], quantity)[0]
  const tokenAddress = encoder.decode(["address"], buyToken)[0]

  let qs = createQueryString({
    sellToken: "USDC",
    buyToken: tokenAddress,
    sellAmount: qty,
  })

  let quoteUrl = `${API_QUOTE_URL}?${qs}`
  let response = await get(quoteUrl, { headers: {"0x-api-key": '05f12b06-3c41-440e-9357-6c5155bd4a43'}})
  let quote = response.data

  const encoded = encoder.encode(["address", "address",
    "bytes", "uint256", "uint256"], [quote.allowanceTarget, quote.to, quote.data, quote.value, quote.buyAmount]);
  process.stdout.write(encoded)
}

const args = process.argv.slice(2);

if (args.length != 2) {
  console.log(`please supply the correct parameters:
    quantity buyToken
  `)
  process.exit(1);
}

main(args[0], args[1])

