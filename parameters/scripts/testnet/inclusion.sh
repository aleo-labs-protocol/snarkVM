# Generates the inclusion proving and verifying key.

# Inputs: network

cargo run --release --features filesystem --example inclusion testnet -- --nocapture || exit

mv inclusion.metadata ../../src/testnet/resources/credits || exit
mv inclusion.prover.* ~/.aleo/resources || exit
mv inclusion.verifier ../../src/testnet/resources/credits || exit
