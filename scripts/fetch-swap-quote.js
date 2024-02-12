import { ethers } from "ethers";
import qs from "qs";
import { get } from './get.js';
import { archTokens } from "./config.js";

const encoder = new ethers.AbiCoder()

async function main(fromTokenAmountInWei, fromTokenAddress, toTokenAddress) {
  const fromAmountInWei = encoder.decode(["uint256"], fromTokenAmountInWei)[0].toString()
  const fromAddress = encoder.decode(["address"], fromTokenAddress)[0]
  const toAddress = encoder.decode(["address"], toTokenAddress)[0]

  const {
    networkId,
    traderPeripheralAddress,
    slippagePercentageProportion,
  } = archTokens[fromAddress];

  const params = {
    networkId,
    fromAddress,
    fromAmountInWei,
    toAddress,
    slippagePercentageProportion,
    recipient: traderPeripheralAddress,
  }

  const baseUrl = "https://dev-api.archfinance.io/exchange/v2/get-quote"
  const quoteUrl = `${baseUrl}?${qs.stringify(params)}`

  try {
    const response = await get(quoteUrl);

    const quote = response.data
    const {
      allowanceTarget,
      target,
      data,
      value,
      toMinAmountInWei,
    } = quote;
    
    const encoded = encoder.encode([
      "address",
      "address",
      "bytes",
      "uint256",
      "uint256"
    ], [
      allowanceTarget,
      target,
      data,
      value,
      toMinAmountInWei,
    ]);

    process.stdout.write(encoded)
  } catch (error) {
    console.log(JSON.stringify(error, null, 2))
  }
}

const args = process.argv.slice(2)

if (args.length != 3) {
  console.log(`please supply the correct encoded parameters: sellAmount sellToken buyToken
  `)
  process.exit(1)
}

main(args[0], args[1], args[2])