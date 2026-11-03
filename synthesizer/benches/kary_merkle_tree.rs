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

#[macro_use]
extern crate criterion;

use snarkvm_algorithms::snark::varuna::VarunaVersion;
use snarkvm_circuit::{AleoV0, Eject, Environment, Inject, Mode, collections::kary_merkle_tree::*};
use snarkvm_console::{
    algorithms::Poseidon8,
    collections::kary_merkle_tree::KaryMerkleTree,
    network::{
        MainnetV0,
        prelude::{Rng, TestRng, Uniform},
    },
    types::Field,
};
use snarkvm_synthesizer_snark::{ProvingKey, UniversalSRS};

use criterion::Criterion;

type CurrentNetwork = MainnetV0;
type CurrentAleo = AleoV0;

type NativePathHasher = Poseidon8<CurrentNetwork>;
type NativeLeafHasher = Poseidon8<CurrentNetwork>;
type CircuitPathHasher = snarkvm_circuit::Poseidon8<AleoV0>;
type CircuitLeafHasher = snarkvm_circuit::Poseidon8<AleoV0>;

const DEPTH: u8 = 7;
const ARITY: u8 = 8;

/// Generates the specified number of random Merkle tree leaves.
macro_rules! generate_leaves {
    ("bits", $num_leaves:expr, $rng:expr) => {{
        use snarkvm_console::network::prelude::ToBits;
        // Generate leaf bits.
        (0..$num_leaves).map(|_| Field::<CurrentNetwork>::rand($rng).to_bits_le()).collect::<Vec<_>>()
    }};
    ("fields", $num_leaves:expr, $rng:expr) => {{
        use rand::SeedableRng;
        use rayon::prelude::*;
        // Generate leaf fields in parallel.
        (0..$num_leaves)
            .map(|_| u64::rand($rng))
            .collect::<Vec<u64>>()
            .into_par_iter()
            .map(|seed| vec![Field::<CurrentNetwork>::rand(&mut rand::rngs::StdRng::seed_from_u64(seed))])
            .collect::<Vec<_>>()
    }};
}

fn batch_prove(c: &mut Criterion) {
    let mut rng = TestRng::default();

    // Start the timer.
    let timer = std::time::Instant::now();

    // Initialize the hashers.
    let native_path_hasher = NativePathHasher::setup("test").unwrap();
    let native_leaf_hasher = NativeLeafHasher::setup("test").unwrap();
    let circuit_path_hasher = CircuitPathHasher::new(Mode::Private, native_path_hasher.clone());
    let circuit_leaf_hasher = CircuitLeafHasher::new(Mode::Private, native_leaf_hasher.clone());

    // Determine the maximum number of leaves.
    let max_num_leaves = (ARITY as u64).pow(DEPTH as u32);
    // Initialize the leaves.
    let leaves = generate_leaves!("fields", max_num_leaves, &mut rng);
    // Initialize the tree.
    let merkle_tree =
        KaryMerkleTree::<_, _, DEPTH, ARITY>::new(&native_leaf_hasher, &native_path_hasher, &leaves).unwrap();

    // Log the current time elapsed.
    println!(" • Synthesized the Merkle tree in: {} secs", timer.elapsed().as_secs());
    let timer = std::time::Instant::now();

    // Construct the assignment closure.
    let generate_assignment = |rng: &mut TestRng| {
        // Construct the circuit.
        CurrentAleo::reset();

        // Select the leaf index to prove.
        let leaf_index = rng.random_range(0..max_num_leaves as usize);
        // Initialize the leaf.
        let merkle_leaf = leaves[leaf_index].clone();
        // Initialize the Merkle path.
        let merkle_path = merkle_tree.prove(leaf_index, &merkle_leaf).unwrap();

        // Uncomment me to enable logging.
        // println!("\t• Proving leaf index: {leaf_index}");

        // Initialize the Merkle path circuit.
        let path = KaryMerklePath::<CurrentAleo, CircuitPathHasher, DEPTH, ARITY>::new(Mode::Private, merkle_path);
        // Initialize the Merkle leaf circuit.
        let leaf: Vec<_> = Inject::new(Mode::Private, merkle_leaf);
        // Initialize the Merkle root circuit.
        let root = <CircuitPathHasher as PathHash<CurrentAleo>>::Hash::new(Mode::Private, *merkle_tree.root());

        // Verify the Merkle path circuit.
        let candidate = path.verify(&circuit_leaf_hasher, &circuit_path_hasher, &root, &leaf);
        assert!(candidate.eject_value());

        // Eject the assignment.
        CurrentAleo::eject_assignment_and_reset()
    };

    // Synthesize a single assignment.
    let assignment = generate_assignment(&mut rng);

    // Log the current time elapsed.
    println!(" • Synthesized the circuit in: {} ms", timer.elapsed().as_millis());
    let timer = std::time::Instant::now();

    // Load the universal srs.
    let universal_srs = UniversalSRS::<CurrentNetwork>::load().unwrap();
    // Construct the proving key.
    let (proving_key, _) = universal_srs.to_circuit_key("KaryMerklePathVerification", &assignment).unwrap();

    // Log the current time elapsed.
    println!(" • Generated the proving key in: {} ms", timer.elapsed().as_millis());
    println!("\t• Number of public & private variables: {:?}", (assignment.num_public(), assignment.num_private()));
    println!("\t• Number of constraints: {}", assignment.num_constraints());
    println!("\t• Number of nonzeros: {:?}", assignment.num_nonzeros());

    // Bench the proof construction.
    for num_assignments in &[1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
        // Reset the timer.
        let timer = std::time::Instant::now();

        // Construct the assignments.
        let assignments =
            [(proving_key.clone(), (0..*num_assignments).map(|_| generate_assignment(&mut rng)).collect::<Vec<_>>())];

        // Log the current time elapsed.
        println!(" • Generated {num_assignments} assignments in: {} ms", timer.elapsed().as_millis());

        let varuna_version = VarunaVersion::V2;
        c.bench_function(&format!("KaryMerkleTree batch prove {num_assignments} assignments"), |b| {
            b.iter(|| {
                let _proof =
                    ProvingKey::prove_batch("ProveKaryMerkleTree", varuna_version, &assignments, &mut rng).unwrap();
            })
        });
    }
}

criterion_group! {
    name = kary_merkle_tree;
    config = Criterion::default().sample_size(10);
    targets = batch_prove
}
criterion_main!(kary_merkle_tree);
