# include .env file and export its env vars
# (-include to ignore error if it does not exist)
-include .env

# deps
install:; forge install
update:; forge update

# Build & test
build  :; forge build
test-permit1-mint :; forge test --match-path "./test/permitOne/mint.t.sol" --ffi -vvv --via-ir
test-permit1-mint-set :; forge test --match-path "./test/permitOne/mintSetProtocol.t.sol" --ffi -vvv --via-ir
test-permit1-swap :; forge test --match-path "./test/permitOne/swap.t.sol" --ffi -vvv --via-ir
test-permit2-redeem :; forge test --match-path "./test/permitTwo/redeem.t.sol" --ffi -vvv --via-ir
test-permit2-mint :; forge test --match-path "./test/permitTwo/mint.t.sol" --ffi -vvv --via-ir
test-permit2-swap :; forge test --match-path "./test/permitTwo/swap.t.sol" --ffi -vvv --via-ir
trace   :; forge test -vvv
clean  :; forge clean
snapshot :; forge snapshot
fmt    :; forge fmt