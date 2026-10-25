# snarkvm-algorithms-cuda

[![Crates.io](https://img.shields.io/crates/v/snarkvm-algorithms-cuda.svg?color=neon)](https://crates.io/crates/snarkvm-algorithms-cuda)
[![Authors](https://img.shields.io/badge/authors-Aleo-orange.svg)](https://aleo.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE.md)

## Build Requirements

- Cuda `sm_86` or later
- [Cuda Toolkit (nvcc)](https://docs.nvidia.com/cuda/index.html#installation-guides)

## ADX

This crate and [`blst`](https://crates.io/crates/blst) both build in blst's portable mode. blst's routines then choose
the ADX instructions at run time, from CPUID, so one binary runs on any x86_64 CPU and uses ADX where it exists.

## Build Settings

- `CUDA_ARCH` sets the target architecture, such as `sm_89` or `sm_90`. The default is `sm_86`. A binary built for a
  newer architecture than the GPU fails every kernel launch.
- `NVCC` sets the path to nvcc. The default is `nvcc` on `PATH`. Without nvcc, the kernels are not built, and a build
  with `cuda` fails to link.
- `MAX_LG_DOMAIN`, as a define in `CXXFLAGS`, sets the device pool's size. The default, 23, holds the largest circuit
  the protocol allows, and costs 3 GiB of device memory and 3 GiB of pinned host memory per GPU.

## Runtime Settings

- `SNARKVM_MSM_WBITS` sets the MSM window: 10 to 18, or `auto` for sppark's heuristic. The default, 14, was fitted on an
  H100 at the proof's MSM sizes.
- `SNARKVM_MSM_THREADS` sets the MSM worker threads: 1 to 1024. The default, two per GPU, was fitted on an L4.

A value that does not parse aborts the process at the first device call, so a typo cannot run as the default.

## GPU Failures

A build with `cuda` does not fall back to the CPU. A failed device call panics, and the message carries the CUDA error
code as `[snarkvm-cuda: code=N]`. `snarkvm_algorithms::cuda_error_code` reads it. To use the CPU, build without `cuda`.

## Usage Guide

- Simply enable the `cuda` feature in your command or snarkVM dependency

### Example

```
cd snarkVM/algorithms
cargo bench --bench variable_base --features "cuda"
```

or

```
[dependencies.snarkvm]
version = "<latest_version>"
features = ["cuda"]
```
