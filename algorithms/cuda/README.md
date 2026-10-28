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
  with `cuda` fails to compile `snarkvm-algorithms`, with a message that says so.
- `MAX_LG_DOMAIN`, as a define in `CXXFLAGS`, sets the device pool's size. The default, 23, holds a circuit whose
  constraint, variable and per-matrix non-zero counts are each at most 2^22, and costs 3 GiB of device memory and 3 GiB
  of pinned host memory per GPU.

## GPU Failures

A build with `cuda` does not fall back to the CPU. A failed device call panics, and the message carries the CUDA error
code as `[snarkvm-cuda: code=N]`. `snarkvm_algorithms::cuda_error_code` reads it. To use the CPU, build without `cuda`.
With no usable GPU, every call panics with `cudaErrorNoDevice` (100), and the message says whether the runtime found no
device, could not enumerate them, or found none of compute capability 7.0 or higher.

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
