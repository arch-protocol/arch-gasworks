# include .env file and export its env vars
# (-include to ignore error if it does not exist)
-include .env

# deps
install:; forge install
update:; forge update

# Build & test
build  :; forge build
test   :; forge test
test-fork :; forge test --fork-url https://polygon-mainnet.g.alchemy.com/v2/$(ALCHEMY_API_KEY) --ffi -vvv
test-permit :; forge test --match-path "./test/permit/*.sol" --fork-url https://polygon-mainnet.g.alchemy.com/v2/$(ALCHEMY_API_KEY) --ffi
test-permit2-chambers :; forge test --match-path "./test/permit2/Chambers/*.sol" --fork-url https://eth-mainnet.g.alchemy.com/v2/$(ALCHEMY_API_KEY) --ffi
test-permit2-swap :; forge test --match-path "./test/permit2/swapWithPermit2.t.sol" --fork-url https://polygon-mainnet.g.alchemy.com/v2/$(ALCHEMY_API_KEY) --ffi
trace   :; forge test -vvv
clean  :; forge clean
snapshot :; forge snapshot
fmt    :; forge fmt