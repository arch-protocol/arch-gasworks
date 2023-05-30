const { ethers } = require("ethers")
const axios = require("axios").default
const encoder = new ethers.AbiCoder();

const API_QUOTE_URL = "https://api.0x.org/swap/v1/quote"

function createQueryString(params) {
    return Object.entries(params)
        .map(([k, v]) => `${k}=${v}`)
        .join("&")
}

async function main(quantity, sellToken, buyToken) {

    const qty = encoder.decode(["uint256"], quantity)[0]
    const sellAddress = encoder.decode(["address"], sellToken)[0]
    const buyAddress = encoder.decode(["address"], buyToken)[0]

    const qs = createQueryString({
        sellToken: sellAddress,
        buyToken: buyAddress,
        sellAmount: qty,
    })

    const quoteUrl = `${API_QUOTE_URL}?${qs}`
    const response = await axios.get(quoteUrl)
    const quote = response.data

    encoded = encoder.encode(["address", "address",
        "bytes", "uint256", "uint256"], [quote.allowanceTarget, quote.to, quote.data, quote.value, quote.buyAmount]);
    process.stdout.write(encoded)
}

const args = process.argv.slice(2);

if (args.length != 3) {
    console.log(`please supply the correct parameters:
    quantity sellToken buyToken
  `)
    process.exit(1);
}

main(args[0], args[1], args[2])

