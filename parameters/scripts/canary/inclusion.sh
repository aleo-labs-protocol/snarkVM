# Generates the inclusion proving and verifying key.

# Inputs: network

cargo run --release --features filesystem --example inclusion canary -- --nocapture || exit

mv inclusion.metadata ../../src/canary/resources/credits || exit
mv inclusion.prover.* ~/.aleo/resources || exit
mv inclusion.verifier ../../src/canary/resources/credits || exit
