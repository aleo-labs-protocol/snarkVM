# Generate proving and verifying keys.

# Inputs: program name

cargo run --release --features filesystem --example setup credits canary -- --nocapture || exit

mv *.metadata ../../src/canary/resources/credits || exit
mv *.prover.* ~/.aleo/resources || exit
mv *.verifier ../../src/canary/resources/credits || exit
