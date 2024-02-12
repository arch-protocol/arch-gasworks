import { ethers } from "ethers";
import qs from "qs";
import {get} from './get.js';
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

const issuance = '0x0000000000000000000000000000000000000000000000000000000000000001';

async function main(archTokenAmount, targetArchToken, targetToken, operation) {
  const qty = encoder.decode(["uint256"], archTokenAmount)[0]
  const archToken = encoder.decode(["address"], targetArchToken)[0]
  const inputOrOutputToken = encoder.decode(["address"], targetToken)[0]
  const opt = operation === issuance;
  
  archTokens[archToken].basketAmountInWei = qty.toString()
  archTokens[archToken].tokenAddress = inputOrOutputToken

  const jwt = await generateJwt(archTokens[archToken])
  const baseUrl = "https://dev-api.archfinance.io/basket-issuance/"
  const opType = opt ? "issuance" : "redemption"
  const quoteUrl = `${baseUrl}${opType}-components?${qs.stringify(
    archTokens[archToken]
  )}`
  try {
    const response = await get(quoteUrl, {
      headers: { Authorization: `Bearer ${jwt}` },
    });

    const quote = response.data
    const value = opt ? quote.maxAmountInWei : quote.minAmountInWei
    const data = quote.callInstructions ? quote.callInstructions : quote.encodedComponentQuotes
    const encodedType = quote.callInstructions ? "tuple(address target, address allowanceTarget, address sellToken, uint256 sellAmount, address buyToken, uint256 minBuyAmount, bytes callData)[]" : "bytes[]"
    const encoded = encoder.encode([encodedType, "uint256"], [data, value])

    process.stdout.write(encoded)
  } catch (error) {
    console.log(error)
  }

}

const args = process.argv.slice(2)

if (args.length != 4) {
  console.log(`please supply the correct parameters:
    quantity sellToken buyToken operation
  `)
  process.exit(1)
}

main(args[0], args[1], args[2], args[3])