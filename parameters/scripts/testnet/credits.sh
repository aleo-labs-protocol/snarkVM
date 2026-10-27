# Generate proving and verifying keys.

# Inputs: program name

cargo run --release --features filesystem --example setup credits testnet -- --nocapture || exit

mv *.metadata ../../src/testnet/resources/credits || exit
mv *.prover.* ~/.aleo/resources || exit
mv *.verifier ../../src/testnet/resources/credits || exit
