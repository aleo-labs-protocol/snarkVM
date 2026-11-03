# Generates the translation proving and verifying key.

# Inputs: network

cargo run --release --features filesystem --example translation testnet -- --nocapture || exit

mv translation_credits.metadata ../../src/testnet/resources/credits || exit
mv translation_credits.prover.* ~/.aleo/resources || exit
mv translation_credits.verifier ../../src/testnet/resources/credits || exit
