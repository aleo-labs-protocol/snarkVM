# Generate proving and verifying keys.

# Inputs: program name

cargo run --release --features filesystem --example setup credits mainnet -- --nocapture || exit

mv *.metadata ../../src/mainnet/resources/credits || exit
mv *.prover.* ~/.aleo/resources || exit
mv *.verifier ../../src/mainnet/resources/credits || exit
