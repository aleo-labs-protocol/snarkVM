# Generates the inclusion proving and verifying key.

# Inputs: network

cargo run --release --features filesystem --example inclusion mainnet -- --nocapture || exit

mv inclusion.metadata ../../src/mainnet/resources/credits || exit
mv inclusion.prover.* ~/.aleo/resources || exit
mv inclusion.verifier ../../src/mainnet/resources/credits || exit
