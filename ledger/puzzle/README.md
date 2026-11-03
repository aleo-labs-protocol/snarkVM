# snarkvm-ledger-puzzle

[![Crates.io](https://img.shields.io/crates/v/snarkvm-ledger-puzzle.svg?color=neon)](https://crates.io/crates/snarkvm-ledger-puzzle)
[![Authors](https://img.shields.io/badge/authors-Aleo-orange.svg)](https://aleo.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE.md)

## Benchmarks

`Puzzle::prove` is noisy at Criterion's 10-sample default (the bencher format reports a median, and CI fails at 200%). CI therefore runs it alone with 100 samples, 3s warmup, and 10s measurement. `Puzzle::check_solutions` keeps the cheap default.

```bash
cargo bench --package=snarkvm-ledger-puzzle --bench puzzle --features=setup -- Puzzle::prove \
  --sample-size 100 --warm-up-time 3 --measurement-time 10
```
