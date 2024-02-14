import { ethers } from "ethers";
import qs from "qs";
import { get } from './get.js';
import { SignJWT } from "jose";
import { archTokens } from "./config.js";

const encoder = new ethers.AbiCoder()

async function generateJwt(payload) {
  const privateKey = Buffer.from("dev-jwt-secret-key");
  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .sign(privateKey);
  return jwt;
}

async function main(fromTokenAddress, fromTokenAmountInWei, toTokenAddress) {
  const from = encoder.decode(["address"], fromTokenAddress)[0]
  const fromAmount = encoder.decode(["uint256"], fromTokenAmountInWei)[0].toString()
  const toToken = encoder.decode(["address"], toTokenAddress)[0]

  const params = {
    fromTokenAddress: from,
    fromTokenAmountInWei: fromAmount,
    toTokenAddress: toToken,
    mintAmountMultiplier: 0.995, // The greater {fromAmount} the smaller this value gets, otherwise the quotes fails
  }

  const jwt = await generateJwt(params)
  const baseUrl = "https://dev-api.archfinance.io/basket-issuance/portfolio-swap-quote"

  const quoteUrl = `${baseUrl}?${qs.stringify(params)}`

  try {
    const response = await get(quoteUrl, {
      headers: { Authorization: `Bearer ${jwt}` },
    });

    const quote = response.data
    const {
      fromTokenAddress,
      fromTokenAmountInWei,
      toTokenAddress,
      toTokenAmountInWei,
      issuerWizardContractAddress,
      contractCallInstructions,
    } = quote;
    
    const encoded = encoder.encode([
      "address",
      "uint256",
      "address",
      "uint256",
      "address",
      "tuple(address target, address allowanceTarget, address sellToken, uint256 sellAmount, address buyToken, uint256 minBuyAmount, bytes callData)[]",
    ], [
      fromTokenAddress,
      fromTokenAmountInWei,
      toTokenAddress,
      toTokenAmountInWei,
      issuerWizardContractAddress,
      contractCallInstructions,
    ]);

    process.stdout.write(encoded)
  } catch (error) {
    console.log(error)
  }
}

const args = process.argv.slice(2)

if (args.length != 3) {
  console.log(`please supply the correct encoded parameters:
    fromTokenAddress fromTokenAmountInWei toTokenAddress
  `)
  process.exit(1)
}

main(args[0], args[1], args[2])