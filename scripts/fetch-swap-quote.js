import { ethers } from "ethers";
import { get } from './get.js';
import { archTokens } from "./config.js";

const encoder = new ethers.AbiCoder()

function getQueryString(
  params,
) {
  const queryString = Object.entries(params)
    .map(([key, value]) => {
      if (value !== undefined && value != null) {
        if (Array.isArray(value)) {
          return value.map((v) => `${key}[]=${encodeURIComponent(v)}`).join('&'); 
        }

        return `${key}=${encodeURIComponent(value)}`;
      }
      return '';
    })
    .join('&');
  return queryString;
}

async function main(fromTokenAmountInWei, fromTokenAddress, toTokenAddress, recipientAddress) {
  const fromAmountInWei = encoder.decode(["uint256"], fromTokenAmountInWei)[0].toString()
  const fromAddress = encoder.decode(["address"], fromTokenAddress)[0]
  const toAddress = encoder.decode(["address"], toTokenAddress)[0]

  const {
    networkId,
    traderPeripheralAddress,
    slippagePercentageProportion,
  } = archTokens[fromAddress];

  const recipient = recipientAddress ? encoder.decode(["address"], recipientAddress)[0] : traderPeripheralAddress;

  const params = {
    networkId,
    fromAddress,
    fromAmountInWei,
    toAddress,
    slippagePercentageProportion,
    recipient,
    liquiditySources: ["zero-ex", "uniswap"],
  }

  const baseUrl = "https://dev-api.archfinance.io/exchange/v2/get-quote"
  const quoteUrl = `${baseUrl}?${getQueryString(params)}`

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

if (args.length < 3) {
  console.log(`please supply the correct encoded parameters: sellAmount sellToken buyToken recipient
  `)
  process.exit(1)
}

if (args.length === 3) {
  main(args[0], args[1], args[2])
}

main(args[0], args[1], args[2], args[3])