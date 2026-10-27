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

/*
Performs time measurements on the verification of test circuits with selected batch sizes and parameters.
 - Generate artifacts with:
   cargo bench --bench varuna_verifier --features test,filesystem -- --generate
 - Artifacts are ignored by git. To clean them, run:
   cargo bench --bench varuna_verifier --features test,filesystem -- --clean
 - Obtain time measurements (using previously generated artifacts) with:
   cargo bench --bench varuna_verifier --features test,filesystem
   The --serial feature can be added to deactivate parallelism.
 - Flamegraph (on previously generated artifacts) with:
   cargo flamegraph --bench varuna_verifier --features="test, filesystem, serial"
*/

use snarkvm_algorithms::{
    AlgebraicSponge,
    SNARK,
    crypto_hash::PoseidonSponge,
    snark::varuna::{
        CircuitVerifyingKey,
        Proof,
        TestCircuit,
        VarunaHidingMode,
        VarunaSNARK,
        VarunaVersion,
        ahp::AHPForR1CS,
    },
};
use snarkvm_curves::bls12_377::{Bls12_377, Fq, Fr};
use snarkvm_utilities::{CanonicalDeserialize, CanonicalSerialize, FromBytes, TestRng, ToBytes};

use std::{collections::BTreeMap, env, path::Path, time::Instant};

type VarunaInst = VarunaSNARK<Bls12_377, FS, VarunaHidingMode>;
type FS = PoseidonSponge<Fq, 2, 1>;

fn main() {
    /////////////////////////// User defined

    // How many times `verify_batch` runs when not using `--generate`. Larger values
    // help flamegraph / timing stability.
    let n_samples = 10;

    // Each tuple is: (batch_size, num_constraints, num_variables,
    // num_public_inputs)
    let batches = [(30, 50_000, 25_000, 64), (1, 5_000_000, 5_000_000, 1024)];

    ///////////////////////////

    let generate = env::args().any(|arg| arg == "--generate");
    let clean = env::args().any(|arg| arg == "--clean");
    let artifact_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/snark/varuna_verifier_artifacts");

    if clean {
        if generate {
            panic!(
                "--clean and --generate cannot be used together. Use --generate to generate\\
                the artifacts, --clean to delete them (and end), and neither to use the existing artifacts."
            );
        }
        std::fs::remove_dir_all(&artifact_path).unwrap();
        println!("Artifacts deleted.");
        return;
    }

    if !artifact_path.exists() {
        if !generate {
            panic!("--generate was not passed, but artifacts were not found.");
        }
        std::fs::create_dir(&artifact_path).unwrap();
    }

    let rng = &mut TestRng::default();

    let max_vars = *batches.iter().map(|(_, _, num_variables, _)| num_variables).max().unwrap();
    let max_constraints = *batches.iter().map(|(_, num_constraints, _, _)| num_constraints).max().unwrap();
    let max_density = 2 * max_constraints;

    let max_degree = AHPForR1CS::<Fr, VarunaHidingMode>::max_degree(max_constraints, max_vars, max_density).unwrap();
    let universal_srs = VarunaInst::universal_setup(max_degree).unwrap();
    let universal_prover = &universal_srs.to_universal_prover().unwrap();
    let universal_verifier = &universal_srs.to_universal_verifier().unwrap();
    let fs_parameters = FS::sample_parameters();

    let varuna_version = VarunaVersion::V2;

    let batch_str = batches
        .iter()
        .map(|(batch_size, num_constraints, _, num_public_inputs)| {
            format!("({batch_size} x [{num_public_inputs}, {num_constraints}])")
        })
        .collect::<Vec<_>>()
        .join(" + ");

    println!("Batches: {batch_str}");

    let sanitized_batch_str = batch_str.replace(' ', "_");

    let vk_path = artifact_path.join(format!("vk_{sanitized_batch_str}.bin"));
    let inputs_path = artifact_path.join(format!("inputs_{sanitized_batch_str}.bin"));
    let proof_path = artifact_path.join(format!("proof_{sanitized_batch_str}.bin"));

    if generate {
        println!("Generating artifacts for {batch_str}...");

        let circuits_and_inputs: Vec<_> = batches
            .iter()
            .map(|&batch| {
                let (batch_size, num_constraints, num_variables, num_public_inputs) = batch;
                let (circuit, public_inputs) =
                    TestCircuit::gen_rand(num_public_inputs, num_constraints, num_variables, rng);
                (
                    VarunaInst::circuit_setup(&universal_srs, &circuit).unwrap(),
                    vec![circuit; batch_size],
                    vec![public_inputs; batch_size],
                )
            })
            .collect();

        let pks_to_circuits = circuits_and_inputs
            .iter()
            .map(|((pk, _), circuits, _)| (pk, circuits.as_slice()))
            .collect::<BTreeMap<_, _>>();
        let vks_to_inputs =
            circuits_and_inputs.iter().map(|((_, vk), _, inputs)| (vk, inputs.as_slice())).collect::<BTreeMap<_, _>>();

        let proof =
            VarunaInst::prove_batch(universal_prover, &fs_parameters, varuna_version, &pks_to_circuits, rng).unwrap();

        let vks = vks_to_inputs.keys().map(|vk| (*vk).clone()).collect::<Vec<_>>();
        let inputs = vks_to_inputs.values().cloned().collect::<Vec<_>>();

        let mut vk_buf = Vec::new();
        CanonicalSerialize::serialize_uncompressed(&vks, &mut vk_buf).unwrap();
        std::fs::write(&vk_path, vk_buf).expect("Failed to write verifying keys");
        let mut inputs_buf = Vec::new();
        CanonicalSerialize::serialize_uncompressed(&inputs, &mut inputs_buf).unwrap();
        std::fs::write(&inputs_path, inputs_buf).expect("Failed to write inputs");
        std::fs::write(&proof_path, proof.to_bytes_le().unwrap()).expect("Failed to write proof");
    }

    // Reload from disk so serialization and verification paths are exercised.
    let vks: Vec<CircuitVerifyingKey<Bls12_377>> = CanonicalDeserialize::deserialize_uncompressed(
        &*std::fs::read(&vk_path).expect("Failed to read verifying keys"),
    )
    .unwrap();
    let inputs: Vec<Vec<Vec<Fr>>> =
        CanonicalDeserialize::deserialize_uncompressed(&*std::fs::read(&inputs_path).expect("Failed to read inputs"))
            .unwrap();
    let proof = Proof::<Bls12_377>::read_le(&*std::fs::read(&proof_path).expect("Failed to read proof")).unwrap();
    let vks_to_inputs: BTreeMap<_, _> = vks.iter().zip(inputs.iter()).map(|(vk, inp)| (vk, inp.as_slice())).collect();

    if generate {
        println!("Verifying generated proof for {batch_str}...");
        assert!(
            VarunaInst::verify_batch(universal_verifier, &fs_parameters, varuna_version, &vks_to_inputs, &proof)
                .unwrap()
        );
        println!("Verification successful");
    } else {
        println!("Verifying proof for {batch_str} {n_samples} times...");
        let timer = Instant::now();
        for _ in 0..n_samples {
            assert!(
                VarunaInst::verify_batch(universal_verifier, &fs_parameters, varuna_version, &vks_to_inputs, &proof)
                    .unwrap()
            );
        }
        let elapsed = timer.elapsed().as_micros() as f64 / 1000.0;
        let elapsed_avg = elapsed / n_samples as f64;
        println!("Verification successful in {elapsed:.2} ms ({elapsed_avg:.2} ms per sample)");
    }
}
