# snarkvm-algorithms

[![Crates.io](https://img.shields.io/crates/v/snarkvm-algorithms.svg?color=neon)](https://crates.io/crates/snarkvm-algorithms)
[![Authors](https://img.shields.io/badge/authors-Aleo-orange.svg)](https://aleo.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE.md)

## CUDA tuning

The variable-base BLS12-377 MSM (multi-scalar multiplication) path can use CUDA
when the `cuda` feature is enabled on x86_64. Set `SNARKVM_CUDA_MSM_THRESHOLD`
before starting snarkVM to adjust the dispatch threshold:

```bash
export SNARKVM_CUDA_MSM_THRESHOLD=8192
<your-snarkVM-command>
```

CUDA is attempted only when the MSM input length is greater than the threshold.
The default remains 1024. An unset, invalid, or zero value uses that default.
The value is read once and cached for the lifetime of the process. The best
value depends on the GPU, CPU, and workload; benchmark representative workloads
before changing it. This setting affects performance only and does not change
proof semantics.
