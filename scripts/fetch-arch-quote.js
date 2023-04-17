const { ethers } = require("ethers")
const axios = require("axios").default
const encoder = new ethers.AbiCoder()
const qs = require("qs")
const {
  SignJWT,
} = require('jose');
const { archTokens } = require('../config')

async function generateJwt(payload) {
  const privateKey = Buffer.from("dev-jwt-secret-key");
  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .sign(privateKey);
  return jwt;
}

async function main(quantity, token) {
  const qty = encoder.decode(["uint256"], quantity)[0]
  const tokenAddress = encoder.decode(["address"], token)[0]

  archTokens[tokenAddress].basketAmountInWei = qty.toString()

  const jwt = await generateJwt(archTokens[tokenAddress])
  const quoteUrl = `https://dev-api.archfinance.io/basket-issuance/issuance-components/${tokenAddress}?${qs.stringify(
    archTokens[tokenAddress]
  )}`
  try {
    const response = await axios.get(quoteUrl, {
      headers: { Authorization: `Bearer ${jwt}` },
    })
  
    const quote = response.data
    const value = quote.maxAmountInWei
    encoded = encoder.encode(["bytes[]", "uint256"], [quote.encodedComponentQuotes, value])
  
    process.stdout.write(encoded)
  } catch (error) {
    console.log(error)
  }
  
}

const args = process.argv.slice(2)

if (args.length != 2) {
  console.log(`please supply the correct parameters:
    quantity token
  `)
  process.exit(1)
}

main(args[0], args[1])