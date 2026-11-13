// Copyright (c) 2019-2025 Provable Inc.
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

use super::*;
use snarkvm_console_algorithms::{BHP512, BHP1024, Keccak256, Poseidon, Sha3_256};
use snarkvm_console_types::prelude::Console;

type CurrentEnvironment = Console;

// Reduced iterations to avoid collisions in shallow trees during testing.
// For production use, use DEPTH≥32 to get billions of positions.
const ITERATIONS: u128 = 5;

macro_rules! run_tests {
    ($rng:expr, [$($i:expr),*]) => {
        $(
            match run_test::<$i, $i>($rng) {
                Ok(_) => {},
                Err(e) => {
                    eprintln!("Test <{}, {}> failed: {:?}", $i, $i, e);
                    panic!("Test failed");
                }
            }
        )*
    };
}
use run_tests;

/// Runs the following test:
/// 1. Construct an empty sparse Merkle tree.
/// 2. Insert key-value pairs.
/// 3. Check that the Merkle proof for every key-value is valid.
/// 4. Update some key-value pairs.
/// 5. Check that the Merkle proof for the updated key-value pairs is valid.
fn check_sparse_kary_merkle_tree<
    KH: KeyHash<Hash = Field<E>>,
    LH: LeafHash<Hash = PH::Hash>,
    PH: PathHash,
    E: Environment,
    const DEPTH: u8,
    const ARITY: u8,
>(
    key_hasher: &KH,
    leaf_hasher: &LH,
    path_hasher: &PH,
    keys: &[KH::Key],
    leaves: &[LH::Leaf],
) -> Result<()> {
    // Ensure keys and leaves have the same length.
    ensure!(keys.len() == leaves.len(), "Keys and leaves must have the same length");

    // Construct an empty sparse Merkle tree.
    let mut merkle_tree =
        SparseKaryMerkleTree::<KH, LH, PH, E, DEPTH, ARITY>::new(key_hasher, leaf_hasher, path_hasher)?;

    // Check that the tree is empty.
    assert_eq!(0, merkle_tree.number_of_leaves());

    // Track the latest leaf for each position (to handle collisions).
    let mut position_to_latest: std::collections::HashMap<Vec<usize>, (KH::Key, LH::Leaf)> =
        std::collections::HashMap::new();

    // Insert key-value pairs.
    for (key, leaf) in keys.iter().zip(leaves.iter()) {
        merkle_tree.update(key, leaf)?;

        // Track which key-leaf pair currently occupies each position.
        let key_hash = key_hasher.hash_key(key)?;
        let position = merkle_tree.compute_path_indices(&key_hash)?;
        position_to_latest.insert(position, (key.clone(), leaf.clone()));
    }

    // Check that each currently-valid key-value pair in the tree verifies.
    // Note: Due to collisions, some keys may have been overwritten.
    for (position, (key, leaf)) in position_to_latest.iter() {
        // Compute a Merkle proof for the key-value pair.
        let proof = merkle_tree.prove(key, leaf)?;

        // Verify the Merkle proof succeeds.
        assert!(
            merkle_tree.verify(&proof, merkle_tree.root(), key, leaf),
            "Verification failed for position {position:?}"
        );
        // Verify the Merkle proof **fails** on an invalid root.
        assert!(!merkle_tree.verify(&proof, &PH::Hash::default(), key, leaf));
    }

    // Update some key-value pairs.
    if !leaves.is_empty() {
        let update_indices = [0, keys.len() / 2, keys.len() - 1];
        for &idx in &update_indices {
            if idx < keys.len() {
                merkle_tree.update(&keys[idx], &leaves[(idx + 1) % leaves.len()])?;
            }
        }

        // Check the updated key-value pairs.
        for &idx in &update_indices {
            if idx < keys.len() {
                let updated_leaf = &leaves[(idx + 1) % leaves.len()];
                let proof = merkle_tree.prove(&keys[idx], updated_leaf)?;
                assert!(merkle_tree.verify(&proof, merkle_tree.root(), &keys[idx], updated_leaf));
            }
        }
    }

    Ok(())
}

#[test]
fn test_sparse_kary_merkle_tree_poseidon2_binary() -> Result<()> {
    fn run_test<const DEPTH: u8, const ARITY: u8>(rng: &mut TestRng) -> Result<()> {
        // Binary case: ARITY = 2
        if ARITY != 2 {
            return Ok(());
        }

        type KH = Poseidon<CurrentEnvironment, 2>;
        type LH = Poseidon<CurrentEnvironment, 4>;
        type PH = Poseidon<CurrentEnvironment, 2>;

        let key_hasher = KH::setup("AleoSparseTreeTest0")?;
        let leaf_hasher = LH::setup("AleoSparseTreeTest1")?;
        let path_hasher = PH::setup("AleoSparseTreeTest2")?;

        let max_leaves = std::cmp::min((ARITY as u128).saturating_pow(DEPTH as u32), 100);

        for i in 0..ITERATIONS {
            // Determine the number of key-value pairs (keep small to avoid collisions in shallow trees).
            let num_pairs = std::cmp::min(rng.gen_range(1..5u128), max_leaves);
            println!("Iteration {i} - Testing a depth {DEPTH} arity {ARITY} tree with {num_pairs} key-value pairs");

            // Generate random keys (field elements).
            let keys = (0..num_pairs).map(|_| Uniform::rand(rng)).collect::<Vec<_>>();

            // Generate random leaves.
            let leaves = (0..num_pairs).map(|_| vec![Uniform::rand(rng)]).collect::<Vec<_>>();

            // Check the sparse Merkle tree.
            check_sparse_kary_merkle_tree::<KH, LH, PH, CurrentEnvironment, DEPTH, ARITY>(
                &key_hasher,
                &leaf_hasher,
                &path_hasher,
                &keys,
                &leaves,
            )?;
        }
        Ok(())
    }

    let mut rng = TestRng::default();

    // Test binary case with various depths.
    // Use deeper trees to avoid collisions with random keys.
    run_test::<16, 2>(&mut rng)?;
    run_test::<24, 2>(&mut rng)?;
    run_test::<32, 2>(&mut rng)?;

    Ok(())
}

#[test]
fn test_sparse_kary_merkle_tree_poseidon2_kary() -> Result<()> {
    fn run_test<const DEPTH: u8, const ARITY: u8>(rng: &mut TestRng) -> Result<()> {
        type KH = Poseidon<CurrentEnvironment, 2>;
        type LH = Poseidon<CurrentEnvironment, 4>;
        type PH = Poseidon<CurrentEnvironment, 2>;

        let key_hasher = KH::setup("AleoSparseTreeTest0")?;
        let leaf_hasher = LH::setup("AleoSparseTreeTest1")?;
        let path_hasher = PH::setup("AleoSparseTreeTest2")?;

        let max_leaves = std::cmp::min((ARITY as u128).saturating_pow(DEPTH as u32), 100);

        for i in 0..ITERATIONS {
            // Determine the number of key-value pairs (keep small to avoid collisions in shallow trees).
            let num_pairs = std::cmp::min(rng.gen_range(1..5u128), max_leaves);
            println!("Iteration {i} - Testing a depth {DEPTH} arity {ARITY} tree with {num_pairs} key-value pairs");

            // Generate random keys (field elements).
            let keys = (0..num_pairs).map(|_| Uniform::rand(rng)).collect::<Vec<_>>();

            // Generate random leaves.
            let leaves = (0..num_pairs).map(|_| vec![Uniform::rand(rng)]).collect::<Vec<_>>();

            // Check the sparse Merkle tree.
            check_sparse_kary_merkle_tree::<KH, LH, PH, CurrentEnvironment, DEPTH, ARITY>(
                &key_hasher,
                &leaf_hasher,
                &path_hasher,
                &keys,
                &leaves,
            )?;
        }
        Ok(())
    }

    let mut rng = TestRng::default();

    // Ensure DEPTH = 0 fails.
    assert!(run_test::<0, 3>(&mut rng).is_err());
    // Ensure ARITY = 1 fails.
    assert!(run_test::<4, 1>(&mut rng).is_err());

    // Test k-ary cases with various depths and arities.
    // Use sufficient depth to avoid collisions: depth D with arity A gives A^D positions.
    run_tests!(&mut rng, [4, 5, 6, 7, 8, 10]);

    // Run some custom depth and arities for good coverage.
    assert!(run_test::<12, 4>(&mut rng).is_ok()); // 4^12 = 16M positions
    assert!(run_test::<8, 8>(&mut rng).is_ok()); // 8^8 = 16M positions
    assert!(run_test::<6, 16>(&mut rng).is_ok()); // 16^6 = 16M positions

    Ok(())
}

#[test]
fn test_sparse_kary_merkle_tree_bhp() -> Result<()> {
    fn run_test<const DEPTH: u8, const ARITY: u8>(rng: &mut TestRng) -> Result<()> {
        type KH = BHP1024<CurrentEnvironment>;
        type LH = BHP1024<CurrentEnvironment>;
        type PH = BHP512<CurrentEnvironment>;

        let key_hasher = KH::setup("AleoSparseTreeTest0")?;
        let leaf_hasher = LH::setup("AleoSparseTreeTest1")?;
        let path_hasher = PH::setup("AleoSparseTreeTest2")?;

        let max_leaves = std::cmp::min((ARITY as u128).saturating_pow(DEPTH as u32), 50);

        for i in 0..ITERATIONS {
            // Determine the number of key-value pairs.
            let num_pairs = std::cmp::min(rng.gen_range(1..10u128), max_leaves);
            println!("Iteration {i} - Testing a depth {DEPTH} arity {ARITY} tree with {num_pairs} key-value pairs");

            // Generate random keys (bit vectors).
            let keys =
                (0..num_pairs).map(|_| Field::<CurrentEnvironment>::rand(rng).to_bits_le()).collect::<Vec<Vec<bool>>>();

            // Generate random leaves.
            let leaves =
                (0..num_pairs).map(|_| Field::<CurrentEnvironment>::rand(rng).to_bits_le()).collect::<Vec<Vec<bool>>>();

            // Check the sparse Merkle tree.
            check_sparse_kary_merkle_tree::<KH, LH, PH, CurrentEnvironment, DEPTH, ARITY>(
                &key_hasher,
                &leaf_hasher,
                &path_hasher,
                &keys,
                &leaves,
            )?;
        }
        Ok(())
    }

    let mut rng = TestRng::default();

    // Ensure DEPTH = 0 fails.
    assert!(run_test::<0, 2>(&mut rng).is_err());
    // Ensure ARITY = 1 fails.
    assert!(run_test::<4, 1>(&mut rng).is_err());

    // Test various depths and arities with sufficient space to avoid collisions.
    run_tests!(&mut rng, [4, 5, 6, 7, 8]);
    assert!(run_test::<10, 4>(&mut rng).is_ok());

    Ok(())
}

#[test]
fn test_sparse_kary_merkle_tree_keccak() -> Result<()> {
    fn run_test<const DEPTH: u8, const ARITY: u8>(rng: &mut TestRng) -> Result<()> {
        type KH = Poseidon<CurrentEnvironment, 2>;
        type LH = Keccak256;
        type PH = Keccak256;

        let key_hasher = KH::setup("AleoSparseTreeTest0")?;
        let leaf_hasher = Keccak256::default();
        let path_hasher = Keccak256::default();

        let max_leaves = std::cmp::min((ARITY as u128).saturating_pow(DEPTH as u32), 50);

        for i in 0..ITERATIONS {
            // Determine the number of key-value pairs.
            let num_pairs = std::cmp::min(rng.gen_range(1..10u128), max_leaves);
            println!("Iteration {i} - Testing a depth {DEPTH} arity {ARITY} tree with {num_pairs} key-value pairs");

            // Generate random keys.
            let keys = (0..num_pairs).map(|_| Field::<CurrentEnvironment>::rand(rng)).collect::<Vec<_>>();

            // Generate random leaves.
            let leaves =
                (0..num_pairs).map(|_| Field::<CurrentEnvironment>::rand(rng).to_bits_le()).collect::<Vec<Vec<bool>>>();

            // Check the sparse Merkle tree.
            check_sparse_kary_merkle_tree::<KH, LH, PH, CurrentEnvironment, DEPTH, ARITY>(
                &key_hasher,
                &leaf_hasher,
                &path_hasher,
                &keys,
                &leaves,
            )?;
        }
        Ok(())
    }

    let mut rng = TestRng::default();

    // Ensure DEPTH = 0 fails.
    assert!(run_test::<0, 2>(&mut rng).is_err());
    // Ensure ARITY = 1 fails.
    assert!(run_test::<4, 1>(&mut rng).is_err());

    // Test various depths and arities with sufficient space to avoid collisions.
    run_tests!(&mut rng, [4, 5, 6, 7, 8]);
    match run_test::<10, 4>(&mut rng) {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("Test failed: {e:?}");
            Err(e)
        }
    }
}

#[test]
fn test_sparse_kary_merkle_tree_sha3() -> Result<()> {
    fn run_test<const DEPTH: u8, const ARITY: u8>(rng: &mut TestRng) -> Result<()> {
        type KH = Poseidon<CurrentEnvironment, 2>;
        type LH = Sha3_256;
        type PH = Sha3_256;

        let key_hasher = KH::setup("AleoSparseTreeTest0")?;
        let leaf_hasher = Sha3_256::default();
        let path_hasher = Sha3_256::default();

        let max_leaves = std::cmp::min((ARITY as u128).saturating_pow(DEPTH as u32), 50);

        for i in 0..ITERATIONS {
            // Determine the number of key-value pairs.
            let num_pairs = std::cmp::min(rng.gen_range(1..10u128), max_leaves);
            println!("Iteration {i} - Testing a depth {DEPTH} arity {ARITY} tree with {num_pairs} key-value pairs");

            // Generate random keys.
            let keys = (0..num_pairs).map(|_| Field::<CurrentEnvironment>::rand(rng)).collect::<Vec<_>>();

            // Generate random leaves.
            let leaves =
                (0..num_pairs).map(|_| Field::<CurrentEnvironment>::rand(rng).to_bits_le()).collect::<Vec<Vec<bool>>>();

            // Check the sparse Merkle tree.
            check_sparse_kary_merkle_tree::<KH, LH, PH, CurrentEnvironment, DEPTH, ARITY>(
                &key_hasher,
                &leaf_hasher,
                &path_hasher,
                &keys,
                &leaves,
            )?;
        }
        Ok(())
    }

    let mut rng = TestRng::default();

    // Ensure DEPTH = 0 fails.
    assert!(run_test::<0, 2>(&mut rng).is_err());
    // Ensure ARITY = 1 fails.
    assert!(run_test::<4, 1>(&mut rng).is_err());

    // Test various depths and arities with sufficient space to avoid collisions.
    run_tests!(&mut rng, [4, 5, 6, 7, 8]);
    assert!(run_test::<10, 4>(&mut rng).is_ok());

    Ok(())
}

/// Test collision resistance by ensuring different keys produce different paths.
#[test]
fn test_collision_resistance() -> Result<()> {
    type KH = Poseidon<CurrentEnvironment, 2>;
    type LH = Poseidon<CurrentEnvironment, 4>;
    type PH = Poseidon<CurrentEnvironment, 2>;

    let mut rng = TestRng::default();

    let key_hasher = KH::setup("AleoSparseTreeTest0")?;
    let leaf_hasher = LH::setup("AleoSparseTreeTest1")?;
    let path_hasher = PH::setup("AleoSparseTreeTest2")?;

    let mut merkle_tree =
        SparseKaryMerkleTree::<KH, LH, PH, CurrentEnvironment, 32, 4>::new(&key_hasher, &leaf_hasher, &path_hasher)?;

    // Generate many random key-value pairs.
    // With DEPTH=32, ARITY=4, we have 4^32 ≈ 2^64 positions - no collisions expected.
    let num_pairs = 100;
    let mut key_hashes = std::collections::HashSet::new();

    for _ in 0..num_pairs {
        let key: Field<CurrentEnvironment> = Uniform::rand(&mut rng);
        let leaf = vec![Uniform::rand(&mut rng)];

        // Hash the key.
        let key_hash = key_hasher.hash_key(&key)?;

        // Ensure no collision.
        assert!(key_hashes.insert(key_hash), "Key hash collision detected!");

        // Insert into tree.
        merkle_tree.update(&key, &leaf)?;

        // Verify the proof.
        let proof = merkle_tree.prove(&key, &leaf)?;
        assert!(merkle_tree.verify(&proof, merkle_tree.root(), &key, &leaf));
    }

    Ok(())
}
