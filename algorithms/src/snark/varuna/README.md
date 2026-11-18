# snarkvm-algorithms/snark/varuna

`varuna` is a Rust module that implements a
<p align="center">
<b>preprocessing zkSNARK for R1CS</b><br>
with<br>
<b>universal and updatable SRS</b>
</p>

## Overview

A zkSNARK with **preprocessing** achieves succinct verification for arbitrary computations, as opposed to only for structured computations.
Informally, in an offline phase, one can preprocess the desired computation to produce a short summary of it; subsequently, in an online phase, this summary can be used to check any number of arguments relative to this computation.

The preprocessing zkSNARKs in this library rely on a structured reference string (SRS), which contains system parameters required by the argument system to produce/validate arguments.
The SRS in this library is **universal**, which means that it supports (deterministically) preprocessing any computation up to a given size bound.
The SRS is also **updatable**, which means that anyone can contribute a fresh share of randomness to it, which facilitates deployments in the real world.

The construction in this library obtains a preprocessing zkSNARK with a universal and updatable SRS by combining two ingredients:
* an **algebraic holographic proof**
* a **polynomial commitment scheme**

## Keys

The indexer turns each circuit into a proving key and a verifying key.
Both keys use the universal SRS of SonicKZG10 (see `algorithms/src/polycommit/README.md`).

### Proving key

`CircuitProvingKey` has three fields:

- `circuit_verifying_key`: the circuit's verifying key.
- `circuit`: the indexed `Circuit`. It holds the `CircuitInfo`, the sparse A, B and C matrices, and the evaluations of their index polynomials.
  `VarunaSNARK::batch_circuit_setup` prunes the `row_col` evaluations after it commits to them, to make the key smaller.
- `committer_key`: the `CommitterKey` that `SonicKZG10::trim` cuts from the SRS for this circuit.
  It supports the circuit's maximum degree, a hiding bound of 1 and the degree bounds from `AHPForR1CS::get_degree_bounds`.

The committer key is the largest part of the proving key.
In memory, it shares its points with the SRS. Its serialization still writes them all.

### Verifying key

`CircuitVerifyingKey` has three fields:

- `circuit_info`: the `CircuitInfo`. It holds the number of public inputs, the number of public and private variables, the number of constraints and the number of non-zero entries in each of A, B and C.
- `circuit_commitments`: twelve commitments, sorted by label.
  For each matrix `m` in A, B and C, there is one commitment to each of `row_m`, `col_m`, `row_col_m` and `row_col_val_m` (see `AHPForR1CS::index_polynomial_labels_single`).
  The commitments are not hiding.
- `id`: the `CircuitId`, a hash of the circuit's info and matrices.

The PC verifier key is not part of the verifying key. It depends only on the SRS, so every circuit shares it.

### Certificates

A key does not prove by itself that it matches a circuit.
So a deployment carries a `Certificate` with each verifying key, which `VarunaSNARK::prove_vk` makes from the proving key.
`VarunaSNARK::verify_vk` checks a verifying key and its certificate against a circuit:

1. It indexes the circuit again, and compares its `CircuitInfo` and `CircuitId` with the key's.
2. It evaluates the index polynomials at a challenge point from the sponge.
3. It checks a KZG opening of a random combination of the key's commitments at that point.

From `ConsensusVersion::V8`, validators run this check on each function's key in a deployment, and on each record's translation key if the deployment has them (see `Stack::verify_deployment`).

## Profiling

This library marks the regions of code that it times with `tracing` spans. A subscriber with the filter `timing::snarkvm_algorithms::snark::varuna=trace` receives them. See [Timing](../../../../utilities/README.md#timing) for how to print the duration of each span.

## Benchmarks

Benchmarks were run on a machine with an Intel Xeon 6136 CPU running at 3.0 GHz.

### Running time compared to Groth16 

The graphs below compare the running time, in single-thread execution, of Marlin's indexer, prover, and verifier algorithms with the corresponding algorithms of [Groth16][groth16] (the state of the art in preprocessing zkSNARKs for R1CS with circuit-specific SRS) as implemented in [`groth16`](https://github.com/scipr-lab/zexe/tree/master/groth16).
We evaluate Marlin's algorithms when instantiated with the PC scheme from [[CHMMVW20]][marlin] (denoted "M-AHP w/ PC of [[CHMMVW20]][marlin]"), and the PC scheme from [[MBKM19]][sonic] (denoted "M-AHP w/ PC of [[MBKM19]][sonic]").

<p align="center">
<img hspace="20" src="https://user-images.githubusercontent.com/3220730/82859703-52546100-9ecc-11ea-8f9d-ec2fb10f042d.png" width="45%" alt = "Indexer">
<img hspace="20" src="https://user-images.githubusercontent.com/3220730/82859705-52ecf780-9ecc-11ea-84cc-99eda9f13d6a.png" width="45%" alt = "Prover">
</p>
<p align="center">
<img src="https://user-images.githubusercontent.com/3220730/82859701-52546100-9ecc-11ea-8422-877080662073.png" width="45%" alt = "Verifier">
</p>

### Multi-threaded performance

The following graphs compare the running time of Marlin's prover when instantiated with the PC scheme from [[CHMMVW20]][marlin] (left) and the PC scheme from [[MBKM19]][sonic] (right) when executed with a different number of threads.

<p align="center">
<img hspace="20" src="https://user-images.githubusercontent.com/3220730/82859700-51bbca80-9ecc-11ea-9fe1-53a611693dd1.png" width="45%" alt = "Multi-threaded scaling of Marlin AHP with the PC scheme from [CHMMVW20]">
<img hspace="20" src="https://user-images.githubusercontent.com/3220730/82859698-51233400-9ecc-11ea-8a32-37379116e828.png" width="45%" alt = "Multi-threaded scaling of Marlin AHP with the PC scheme from [MBKM19]">
</p>
