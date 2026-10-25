// Copyright (c) 2019-2026 Provable Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Round four's device copies across whole proofs. The tests here hold
//! `SERIAL` and are alone in their process, so the process-wide counters and
//! `fail_retains` move only with them.

#![cfg(all(feature = "cuda", feature = "test", target_arch = "x86_64"))]

use snarkvm_algorithms::{
    crypto_hash::PoseidonSponge,
    snark::varuna::{AHPForR1CS, CircuitProvingKey, TestCircuit, VarunaHidingMode, VarunaSNARK, VarunaVersion},
    srs::{UniversalProver, UniversalVerifier},
    traits::{AlgebraicSponge, SNARK},
};
use snarkvm_algorithms_cuda::device_poly::{Stats, fail_retains, stats};
use snarkvm_curves::bls12_377::{Bls12_377, Fq, Fr};
use snarkvm_utilities::{ToBytes, rand::TestRng};

use std::sync::Mutex;

type FS = PoseidonSponge<Fq, 2, 1>;
type Inst = VarunaSNARK<Bls12_377, FS, VarunaHidingMode>;

const N: usize = 2000;

static SERIAL: Mutex<()> = Mutex::new(());

struct Setup {
    circuit: TestCircuit<Fr>,
    inputs: Vec<Fr>,
    prover: UniversalProver<Bls12_377>,
    verifier: UniversalVerifier<Bls12_377>,
    fs: <FS as AlgebraicSponge<Fq, 2>>::Parameters,
    pk: CircuitProvingKey<Bls12_377, VarunaHidingMode>,
    vk: <Inst as SNARK>::VerifyingKey,
}

fn setup() -> Setup {
    let rng = &mut TestRng::fixed(1);
    let (circuit, inputs) = TestCircuit::gen_rand(1, N, N, rng);
    let srs = Inst::universal_setup(AHPForR1CS::<Fr, VarunaHidingMode>::max_degree(N, N, N).unwrap()).unwrap();
    let (prover, verifier) = (srs.to_universal_prover().unwrap(), srs.to_universal_verifier().unwrap());
    let (pk, vk) = Inst::circuit_setup(&srs, &circuit).unwrap();
    Setup { circuit, inputs, prover, verifier, fs: FS::sample_parameters(), pk, vk }
}

/// A verified proof's bytes and the counters' movement while proving.
fn prove(s: &Setup, version: VarunaVersion) -> (Vec<u8>, Stats) {
    let before = stats();
    let proof = Inst::prove(&s.prover, &s.fs, &s.pk, version, &s.circuit, &mut TestRng::fixed(2)).unwrap();
    let after = stats();
    assert!(Inst::verify(&s.verifier, &s.fs, &s.vk, version, s.inputs.as_slice(), &proof).unwrap(), "{version:?}");
    assert_eq!(after.held_bytes, before.held_bytes, "{version:?}: the proof left device copies behind");
    let moved = Stats {
        retained: after.retained - before.retained,
        retain_failures: after.retain_failures - before.retain_failures,
        device_reads: after.device_reads - before.device_reads,
        host_fallbacks: after.host_fallbacks - before.host_fallbacks,
        device_evals: after.device_evals - before.device_evals,
        downloaded_bytes: after.downloaded_bytes - before.downloaded_bytes,
        held_bytes: 0,
    };
    (proof.to_bytes_le().unwrap(), moved)
}

/// Each proof keeps `a`, `b`, `g` and `lhs` for its three matrices and builds
/// `h_2` on the device. Nothing of round four comes down: `g` is evaluated at
/// gamma on the device, and so are `a`, `b` and `h_2` for the debug assertion.
#[test]
fn a_proof_keeps_round_four_on_the_device() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    if snarkvm_algorithms_cuda::device_count() != 1 {
        return;
    }
    let s = setup();
    for version in [VarunaVersion::V2, VarunaVersion::V3] {
        let (_, moved) = prove(&s, version);
        let evals = if cfg!(debug_assertions) { 3 + 7 } else { 3 };
        assert_eq!(
            moved,
            Stats {
                retained: 4,
                retain_failures: 0,
                // 3 commitments of g, 3 lhs into h_2, h_2's commitment, and 10
                // opening terms: the three g and matrix_sumcheck's six a and b
                // and h_2.
                device_reads: 3 + 3 + 1 + 10,
                host_fallbacks: 0,
                device_evals: evals,
                downloaded_bytes: 0,
                held_bytes: 0,
            },
            "{version:?}"
        );
    }
}

/// Whatever the device cannot hold falls back to the host, and the proof is
/// the same bytes.
#[test]
fn every_fallback_proves_the_same_bytes() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    if snarkvm_algorithms_cuda::device_count() != 1 {
        return;
    }
    let s = setup();
    for version in [VarunaVersion::V2, VarunaVersion::V3] {
        let (want, _) = prove(&s, version);
        // (skip, refuse, retained, failures): every chain refused; one chain
        // refused, so h_2 is built on the host; only h_2 refused.
        for (skip, n, retained, failures) in [(0, u64::MAX, 0, 3), (0, 1, 2, 1), (3, 1, 3, 1)] {
            let _refuse = fail_retains(skip, n);
            let (got, moved) = prove(&s, version);
            assert!(got == want, "{version:?} ({skip}, {n}): the proof differs");
            assert_eq!((moved.retained, moved.retain_failures), (retained, failures), "{version:?} ({skip}, {n})");
            assert!(moved.downloaded_bytes > 0, "{version:?} ({skip}, {n}): the host path downloads");
            assert_eq!(moved.host_fallbacks, 0, "{version:?} ({skip}, {n})");
        }
    }
}
