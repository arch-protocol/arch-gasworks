# include .env file and export its env vars
# (-include to ignore error if it does not exist)
-include .env

# deps
install:; forge install
update:; forge update

# Build & test
build  :; forge build
test-permit1-mint :; forge test --match-path "./test/permit1/mint.t.sol" --ffi -vvv --via-ir
test-permit1-mint-set :; forge test --match-path "./test/permit1/mintSetProtocol.t.sol" --ffi -vvv --via-ir
test-permit1-swap :; forge test --match-path "./test/permit1/swap.t.sol" --ffi -vvv --via-ir
test-permit2-redeem :; forge test --match-path "./test/permit2/redeem.t.sol" --ffi -vvv --via-ir
test-permit2-mint :; forge test --match-path "./test/permit2/mint.t.sol" --ffi -vvv --via-ir
test-permit2-swap :; forge test --match-path "./test/permit2/swap.t.sol" --ffi -vvv --via-ir
trace   :; forge test -vvv
clean  :; forge clean
snapshot :; forge snapshot
fmt    :; forge fmt