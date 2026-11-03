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

use super::*;
use snarkvm_console_algorithms::{BHP512, BHP1024, Keccak256, Poseidon, Sha3_256};
use snarkvm_console_types::prelude::Console;

type CurrentEnvironment = Console;

const ITERATIONS: u128 = 10;

macro_rules! run_tests {
    ($rng:expr, [$($i:expr),*]) => {
        $( assert!(run_test::<$i, $i>($rng).is_ok()); )*
    };
}

/// Runs the following test:
/// 1. Construct the Merkle tree for the leaves.
/// 2. Check that the Merkle proof for every leaf is valid.
fn check_kary_merkle_tree<LH: LeafHash<Hash = PH::Hash>, PH: PathHash, const DEPTH: u8, const ARITY: u8>(
    leaf_hasher: &LH,
    path_hasher: &PH,
    leaves: &[LH::Leaf],
) -> Result<()> {
    // Construct the Merkle tree for the given leaves.
    let merkle_tree = KaryMerkleTree::<LH, PH, DEPTH, ARITY>::new(leaf_hasher, path_hasher, leaves)?;
    assert_eq!(leaves.len(), merkle_tree.number_of_leaves);

    // Check each leaf in the Merkle tree.
    if !leaves.is_empty() {
        for (leaf_index, leaf) in leaves.iter().enumerate() {
            // Compute a Merkle proof for the leaf.
            let proof = merkle_tree.prove(leaf_index, leaf)?;

            // Verify the Merkle proof succeeds.
            assert!(proof.verify(leaf_hasher, path_hasher, merkle_tree.root(), leaf));
            // Verify the Merkle proof **fails** on an invalid root.
            assert!(!proof.verify(leaf_hasher, path_hasher, &PH::Hash::default(), leaf));
        }
    }
    Ok(())
}

/// Runs the following test:
/// 1. Construct a depth-2 arity-3 Merkle tree with 9 leaves.
/// 2. Checks that every node hash and the Merkle root is correct.
fn check_merkle_tree_depth_2_arity_3<LH: LeafHash<Hash = PH::Hash>, PH: PathHash>(
    leaf_hasher: &LH,
    path_hasher: &PH,
    leaves: &[LH::Leaf],
) -> Result<()> {
    assert_eq!(9, leaves.len(), "Depth-2 test requires 9 leaves");

    // Construct the Merkle tree for the given leaves.
    let merkle_tree = KaryMerkleTree::<LH, PH, 2, 3>::new(leaf_hasher, path_hasher, leaves)?;
    assert_eq!(13, merkle_tree.tree.len());
    assert_eq!(9, merkle_tree.number_of_leaves);

    // Depth 2.
    let expected_leaf0 = LeafHash::hash_leaf(leaf_hasher, &leaves[0])?;
    let expected_leaf1 = LeafHash::hash_leaf(leaf_hasher, &leaves[1])?;
    let expected_leaf2 = LeafHash::hash_leaf(leaf_hasher, &leaves[2])?;
    let expected_leaf3 = LeafHash::hash_leaf(leaf_hasher, &leaves[3])?;
    let expected_leaf4 = LeafHash::hash_leaf(leaf_hasher, &leaves[4])?;
    let expected_leaf5 = LeafHash::hash_leaf(leaf_hasher, &leaves[5])?;
    let expected_leaf6 = LeafHash::hash_leaf(leaf_hasher, &leaves[6])?;
    let expected_leaf7 = LeafHash::hash_leaf(leaf_hasher, &leaves[7])?;
    let expected_leaf8 = LeafHash::hash_leaf(leaf_hasher, &leaves[8])?;
    assert_eq!(expected_leaf0, merkle_tree.tree[4]);
    assert_eq!(expected_leaf1, merkle_tree.tree[5]);
    assert_eq!(expected_leaf2, merkle_tree.tree[6]);
    assert_eq!(expected_leaf3, merkle_tree.tree[7]);
    assert_eq!(expected_leaf4, merkle_tree.tree[8]);
    assert_eq!(expected_leaf5, merkle_tree.tree[9]);
    assert_eq!(expected_leaf6, merkle_tree.tree[10]);
    assert_eq!(expected_leaf7, merkle_tree.tree[11]);
    assert_eq!(expected_leaf8, merkle_tree.tree[12]);

    // Depth 1.
    let expected_left = PathHash::hash_children(path_hasher, &[expected_leaf0, expected_leaf1, expected_leaf2])?;
    let expected_middle = PathHash::hash_children(path_hasher, &[expected_leaf3, expected_leaf4, expected_leaf5])?;
    let expected_right = PathHash::hash_children(path_hasher, &[expected_leaf6, expected_leaf7, expected_leaf8])?;
    assert_eq!(expected_left, merkle_tree.tree[1]);
    assert_eq!(expected_middle, merkle_tree.tree[2]);
    assert_eq!(expected_right, merkle_tree.tree[3]);

    // Depth 0.
    let expected_root = PathHash::hash_children(path_hasher, &[expected_left, expected_middle, expected_right])?;
    assert_eq!(expected_root, merkle_tree.tree[0]);
    assert_eq!(expected_root, *merkle_tree.root());
    Ok(())
}

/// Runs the following test:
/// 1. Construct a depth-3 Merkle tree with 10 leaves (leaving 17 leaves empty).
/// 2. Checks that every node hash and the Merkle root is correct.
fn check_merkle_tree_depth_3_arity_3_padded<LH: LeafHash<Hash = PH::Hash>, PH: PathHash>(
    leaf_hasher: &LH,
    path_hasher: &PH,
    leaves: &[LH::Leaf],
    additional_leaves: &[LH::Leaf],
) -> Result<()> {
    assert_eq!(9, leaves.len(), "Padded depth-3 test requires 9 leaves (out of 27)");
    assert_eq!(1, additional_leaves.len(), "Padded depth-3 test requires 1 additional leaf");

    const ARITY: u8 = 3;

    // Construct the Merkle tree for the given leaves.
    let merkle_tree = KaryMerkleTree::<LH, PH, 3, ARITY>::new(leaf_hasher, path_hasher, leaves)?;
    assert_eq!(13, merkle_tree.tree.len());
    assert_eq!(9, merkle_tree.number_of_leaves);

    // Depth 3.
    let expected_leaf0 = LeafHash::hash_leaf(leaf_hasher, &leaves[0])?;
    let expected_leaf1 = LeafHash::hash_leaf(leaf_hasher, &leaves[1])?;
    let expected_leaf2 = LeafHash::hash_leaf(leaf_hasher, &leaves[2])?;
    let expected_leaf3 = LeafHash::hash_leaf(leaf_hasher, &leaves[3])?;
    let expected_leaf4 = LeafHash::hash_leaf(leaf_hasher, &leaves[4])?;
    let expected_leaf5 = LeafHash::hash_leaf(leaf_hasher, &leaves[5])?;
    let expected_leaf6 = LeafHash::hash_leaf(leaf_hasher, &leaves[6])?;
    let expected_leaf7 = LeafHash::hash_leaf(leaf_hasher, &leaves[7])?;
    let expected_leaf8 = LeafHash::hash_leaf(leaf_hasher, &leaves[8])?;
    assert_eq!(expected_leaf0, merkle_tree.tree[4]);
    assert_eq!(expected_leaf1, merkle_tree.tree[5]);
    assert_eq!(expected_leaf2, merkle_tree.tree[6]);
    assert_eq!(expected_leaf3, merkle_tree.tree[7]);
    assert_eq!(expected_leaf4, merkle_tree.tree[8]);
    assert_eq!(expected_leaf5, merkle_tree.tree[9]);
    assert_eq!(expected_leaf6, merkle_tree.tree[10]);
    assert_eq!(expected_leaf7, merkle_tree.tree[11]);
    assert_eq!(expected_leaf8, merkle_tree.tree[12]);

    // Depth 2.
    let expected_left0 = PathHash::hash_children(path_hasher, &[expected_leaf0, expected_leaf1, expected_leaf2])?;
    let expected_middle0 = PathHash::hash_children(path_hasher, &[expected_leaf3, expected_leaf4, expected_leaf5])?;
    let expected_right0 = PathHash::hash_children(path_hasher, &[expected_leaf6, expected_leaf7, expected_leaf8])?;
    assert_eq!(expected_left0, merkle_tree.tree[1]);
    assert_eq!(expected_middle0, merkle_tree.tree[2]);
    assert_eq!(expected_right0, merkle_tree.tree[3]);

    // Depth 1.
    let expected_left = PathHash::hash_children(path_hasher, &[expected_left0, expected_middle0, expected_right0])?;
    let expected_middle = path_hasher.hash_empty::<ARITY>()?;
    let expected_right = path_hasher.hash_empty::<ARITY>()?;
    assert_eq!(expected_left, merkle_tree.tree[0]);

    // Depth 0.
    let expected_root = PathHash::hash_children(path_hasher, &[expected_left, expected_middle, expected_right])?;
    assert_eq!(expected_root, *merkle_tree.root());

    // ------------------------------------------------------------------------------------------ //
    // Check that the Merkle tree can be updated with the additional leaf.
    // ------------------------------------------------------------------------------------------ //

    // TODO (raychu86): Use the append functionality properly.
    let leaves = [leaves, additional_leaves].concat();

    // Construct the Merkle tree for the given leaves.
    let merkle_tree = KaryMerkleTree::<LH, PH, 3, ARITY>::new(leaf_hasher, path_hasher, &leaves)?;
    assert_eq!(25, merkle_tree.tree.len());
    assert_eq!(10, merkle_tree.number_of_leaves);

    // Depth 3.
    let expected_leaf0 = LeafHash::hash_leaf(leaf_hasher, &leaves[0])?;
    let expected_leaf1 = LeafHash::hash_leaf(leaf_hasher, &leaves[1])?;
    let expected_leaf2 = LeafHash::hash_leaf(leaf_hasher, &leaves[2])?;
    let expected_leaf3 = LeafHash::hash_leaf(leaf_hasher, &leaves[3])?;
    let expected_leaf4 = LeafHash::hash_leaf(leaf_hasher, &leaves[4])?;
    let expected_leaf5 = LeafHash::hash_leaf(leaf_hasher, &leaves[5])?;
    let expected_leaf6 = LeafHash::hash_leaf(leaf_hasher, &leaves[6])?;
    let expected_leaf7 = LeafHash::hash_leaf(leaf_hasher, &leaves[7])?;
    let expected_leaf8 = LeafHash::hash_leaf(leaf_hasher, &leaves[8])?;
    let expected_leaf9 = LeafHash::hash_leaf(leaf_hasher, &leaves[9])?;
    assert_eq!(expected_leaf0, merkle_tree.tree[13]);
    assert_eq!(expected_leaf1, merkle_tree.tree[14]);
    assert_eq!(expected_leaf2, merkle_tree.tree[15]);
    assert_eq!(expected_leaf3, merkle_tree.tree[16]);
    assert_eq!(expected_leaf4, merkle_tree.tree[17]);
    assert_eq!(expected_leaf5, merkle_tree.tree[18]);
    assert_eq!(expected_leaf6, merkle_tree.tree[19]);
    assert_eq!(expected_leaf7, merkle_tree.tree[20]);
    assert_eq!(expected_leaf8, merkle_tree.tree[21]);
    assert_eq!(expected_leaf9, merkle_tree.tree[22]);
    for i in 23..25 {
        assert_eq!(path_hasher.hash_empty::<ARITY>()?, merkle_tree.tree[i]);
    }

    // Depth 2.
    let expected_left0 = PathHash::hash_children(path_hasher, &[expected_leaf0, expected_leaf1, expected_leaf2])?;
    let expected_middle0 = PathHash::hash_children(path_hasher, &[expected_leaf3, expected_leaf4, expected_leaf5])?;
    let expected_right0 = PathHash::hash_children(path_hasher, &[expected_leaf6, expected_leaf7, expected_leaf8])?;
    assert_eq!(expected_left0, merkle_tree.tree[4]);
    assert_eq!(expected_middle0, merkle_tree.tree[5]);
    assert_eq!(expected_right0, merkle_tree.tree[6]);

    let expected_left1 = PathHash::hash_children(path_hasher, &[
        expected_leaf9,
        path_hasher.hash_empty::<ARITY>()?,
        path_hasher.hash_empty::<ARITY>()?,
    ])?;
    let expected_middle1 = PathHash::hash_children(path_hasher, &[
        path_hasher.hash_empty::<ARITY>()?,
        path_hasher.hash_empty::<ARITY>()?,
        path_hasher.hash_empty::<ARITY>()?,
    ])?;
    let expected_right1 = PathHash::hash_children(path_hasher, &[
        path_hasher.hash_empty::<ARITY>()?,
        path_hasher.hash_empty::<ARITY>()?,
        path_hasher.hash_empty::<ARITY>()?,
    ])?;
    assert_eq!(expected_left1, merkle_tree.tree[7]);
    assert_eq!(expected_middle1, merkle_tree.tree[8]);
    assert_eq!(expected_right1, merkle_tree.tree[9]);

    let expected_left2 = PathHash::hash_children(path_hasher, &[
        path_hasher.hash_empty::<ARITY>()?,
        path_hasher.hash_empty::<ARITY>()?,
        path_hasher.hash_empty::<ARITY>()?,
    ])?;
    let expected_middle2 = PathHash::hash_children(path_hasher, &[
        path_hasher.hash_empty::<ARITY>()?,
        path_hasher.hash_empty::<ARITY>()?,
        path_hasher.hash_empty::<ARITY>()?,
    ])?;
    let expected_right2 = PathHash::hash_children(path_hasher, &[
        path_hasher.hash_empty::<ARITY>()?,
        path_hasher.hash_empty::<ARITY>()?,
        path_hasher.hash_empty::<ARITY>()?,
    ])?;
    assert_eq!(expected_left2, merkle_tree.tree[10]);
    assert_eq!(expected_middle2, merkle_tree.tree[11]);
    assert_eq!(expected_right2, merkle_tree.tree[12]);

    // Depth 1.
    let expected_left = PathHash::hash_children(path_hasher, &[expected_left0, expected_middle0, expected_right0])?;
    let expected_middle = PathHash::hash_children(path_hasher, &[expected_left1, expected_middle1, expected_right1])?;
    let expected_right = PathHash::hash_children(path_hasher, &[expected_left2, expected_middle2, expected_right2])?;
    assert_eq!(expected_left, merkle_tree.tree[1]);
    assert_eq!(expected_middle, merkle_tree.tree[2]);
    assert_eq!(expected_right, merkle_tree.tree[3]);

    // Depth 0.
    let expected_root = PathHash::hash_children(path_hasher, &[expected_left, expected_middle, expected_right])?;
    assert_eq!(expected_root, *merkle_tree.root());

    Ok(())
}

#[test]
fn test_kary_merkle_tree_bhp() -> Result<()> {
    fn run_test<const DEPTH: u8, const ARITY: u8>(rng: &mut TestRng) -> Result<()> {
        type LH = BHP1024<CurrentEnvironment>;
        type PH = BHP512<CurrentEnvironment>;

        let leaf_hasher = LH::setup("AleoMerkleTreeTest0")?;
        let path_hasher = PH::setup("AleoMerkleTreeTest1")?;

        let max_leaves = (ARITY as u128).saturating_pow(DEPTH as u32);

        for i in 0..ITERATIONS {
            // Determine the number of leaves.
            let num_leaves = rng.random_range(0..100u128).min(max_leaves);
            println!("Iteration {i} - Testing a depth {DEPTH} arity {ARITY} tree with {num_leaves} leaves");

            // Check the Merkle tree.
            check_kary_merkle_tree::<LH, PH, DEPTH, ARITY>(
                &leaf_hasher,
                &path_hasher,
                &(0..num_leaves)
                    .map(|_| Field::<CurrentEnvironment>::rand(rng).to_bits_le())
                    .collect::<Vec<Vec<bool>>>(),
            )?;
        }
        Ok(())
    }

    let mut rng = TestRng::default();

    // Ensure DEPTH = 0 fails.
    assert!(run_test::<0, 2>(&mut rng).is_err());
    // Ensure ARITY = 1 fails.
    assert!(run_test::<1, 1>(&mut rng).is_err());
    // Spot check important depths and arity.
    run_tests!(&mut rng, [2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 18]);
    // Run some custom depth and arities.
    assert!(run_test::<32, 4>(&mut rng).is_ok());
    assert!(run_test::<32, 14>(&mut rng).is_ok());

    // Limit the size of depth and arity combinations to prevent overflows.
    assert!(run_test::<32, 16>(&mut rng).is_err());
    assert!(run_test::<48, 48>(&mut rng).is_err());
    Ok(())
}

#[test]
fn test_kary_merkle_tree_poseidon() -> Result<()> {
    fn run_test<const DEPTH: u8, const ARITY: u8>(rng: &mut TestRng) -> Result<()> {
        type LH = Poseidon<CurrentEnvironment, 4>;
        type PH = Poseidon<CurrentEnvironment, 2>;

        let leaf_hasher = LH::setup("AleoMerkleTreeTest0")?;
        let path_hasher = PH::setup("AleoMerkleTreeTest1")?;

        let max_leaves = (ARITY as u128).saturating_pow(DEPTH as u32);

        for i in 0..ITERATIONS {
            // Determine the number of leaves.
            let num_leaves = rng.random_range(0..100u128).min(max_leaves);
            println!("Iteration {i} - Testing a depth {DEPTH} arity {ARITY} tree with {num_leaves} leaves");

            // Check the Merkle tree.
            check_kary_merkle_tree::<LH, PH, DEPTH, ARITY>(
                &leaf_hasher,
                &path_hasher,
                &(0..num_leaves).map(|_| vec![Uniform::rand(rng)]).collect::<Vec<_>>(),
            )?;
        }
        Ok(())
    }

    let mut rng = TestRng::default();

    // Ensure DEPTH = 0 fails.
    assert!(run_test::<0, 2>(&mut rng).is_err());
    // Ensure ARITY = 1 fails.
    assert!(run_test::<1, 1>(&mut rng).is_err());
    // Spot check important depths and arity.
    run_tests!(&mut rng, [2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 18]);
    // Run some custom depth and arities.
    assert!(run_test::<32, 4>(&mut rng).is_ok());
    assert!(run_test::<32, 14>(&mut rng).is_ok());

    // Limit the size of depth and arity combinations to prevent overflows.
    assert!(run_test::<32, 16>(&mut rng).is_err());
    assert!(run_test::<48, 48>(&mut rng).is_err());
    Ok(())
}

#[test]
fn test_kary_merkle_tree_keccak() -> Result<()> {
    fn run_test<const DEPTH: u8, const ARITY: u8>(rng: &mut TestRng) -> Result<()> {
        type LH = Keccak256;
        type PH = Keccak256;

        let leaf_hasher = Keccak256::default();
        let path_hasher = Keccak256::default();

        let max_leaves = (ARITY as u128).saturating_pow(DEPTH as u32);

        for i in 0..ITERATIONS {
            // Determine the number of leaves.
            let num_leaves = rng.random_range(0..10_000u128).min(max_leaves);
            println!("Iteration {i} - Testing a depth {DEPTH} arity {ARITY} tree with {num_leaves} leaves");

            // Check the Merkle tree.
            check_kary_merkle_tree::<LH, PH, DEPTH, ARITY>(
                &leaf_hasher,
                &path_hasher,
                &(0..num_leaves)
                    .map(|_| Field::<CurrentEnvironment>::rand(rng).to_bits_le())
                    .collect::<Vec<Vec<bool>>>(),
            )?;
        }
        Ok(())
    }

    let mut rng = TestRng::default();

    // Ensure DEPTH = 0 fails.
    assert!(run_test::<0, 2>(&mut rng).is_err());
    // Ensure ARITY = 1 fails.
    assert!(run_test::<1, 1>(&mut rng).is_err());
    // Spot check important depths and arity.
    run_tests!(&mut rng, [2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 18]);
    // Run some custom depth and arities.
    assert!(run_test::<32, 4>(&mut rng).is_ok());
    assert!(run_test::<32, 14>(&mut rng).is_ok());

    // Limit the size of depth and arity combinations to prevent overflows.
    assert!(run_test::<32, 16>(&mut rng).is_err());
    assert!(run_test::<48, 48>(&mut rng).is_err());
    Ok(())
}

#[test]
fn test_kary_merkle_tree_sha3() -> Result<()> {
    fn run_test<const DEPTH: u8, const ARITY: u8>(rng: &mut TestRng) -> Result<()> {
        type LH = Sha3_256;
        type PH = Sha3_256;

        let leaf_hasher = Sha3_256::default();
        let path_hasher = Sha3_256::default();

        let max_leaves = (ARITY as u128).saturating_pow(DEPTH as u32);

        for i in 0..ITERATIONS {
            // Determine the number of leaves.
            let num_leaves = rng.random_range(0..10_000u128).min(max_leaves);
            println!("Iteration {i} - Testing a depth {DEPTH} arity {ARITY} tree with {num_leaves} leaves");

            // Check the Merkle tree.
            check_kary_merkle_tree::<LH, PH, DEPTH, ARITY>(
                &leaf_hasher,
                &path_hasher,
                &(0..num_leaves)
                    .map(|_| Field::<CurrentEnvironment>::rand(rng).to_bits_le())
                    .collect::<Vec<Vec<bool>>>(),
            )?;
        }
        Ok(())
    }

    let mut rng = TestRng::default();

    // Ensure DEPTH = 0 fails.
    assert!(run_test::<0, 2>(&mut rng).is_err());
    // Ensure ARITY = 1 fails.
    assert!(run_test::<1, 1>(&mut rng).is_err());
    // Spot check important depths and arity.
    run_tests!(&mut rng, [2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 18]);
    // Run some custom depth and arities.
    assert!(run_test::<32, 4>(&mut rng).is_ok());
    assert!(run_test::<32, 14>(&mut rng).is_ok());

    // Limit the size of depth and arity combinations to prevent overflows.
    assert!(run_test::<32, 16>(&mut rng).is_err());
    assert!(run_test::<48, 48>(&mut rng).is_err());
    Ok(())
}

#[test]
fn test_merkle_tree_depth_2_arity_3_bhp() -> Result<()> {
    type LH = BHP1024<CurrentEnvironment>;
    type PH = BHP512<CurrentEnvironment>;

    let leaf_hasher = LH::setup("AleoMerkleTreeTest0")?;
    let path_hasher = PH::setup("AleoMerkleTreeTest1")?;

    let mut rng = TestRng::default();

    // Check the depth-2 arity-3 Merkle tree.
    check_merkle_tree_depth_2_arity_3::<LH, PH>(
        &leaf_hasher,
        &path_hasher,
        &(0..9).map(|_| Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le()).collect::<Vec<Vec<bool>>>(),
    )
}

#[test]
fn test_merkle_tree_depth_2_arity_3_poseidon() -> Result<()> {
    type LH = Poseidon<CurrentEnvironment, 4>;
    type PH = Poseidon<CurrentEnvironment, 3>;

    let leaf_hasher = LH::setup("AleoMerkleTreeTest0")?;
    let path_hasher = PH::setup("AleoMerkleTreeTest1")?;

    let mut rng = TestRng::default();

    // Check the depth-2 arity-3 Merkle tree.
    check_merkle_tree_depth_2_arity_3::<LH, PH>(
        &leaf_hasher,
        &path_hasher,
        &(0..9).map(|_| vec![Uniform::rand(&mut rng)]).collect::<Vec<_>>(),
    )
}

#[test]
fn test_merkle_tree_depth_2_arity_3_keccak() -> Result<()> {
    type LH = Keccak256;
    type PH = Keccak256;

    let leaf_hasher = Keccak256::default();
    let path_hasher = Keccak256::default();

    let mut rng = TestRng::default();

    // Check the depth-2 arity-3 Merkle tree.
    check_merkle_tree_depth_2_arity_3::<LH, PH>(
        &leaf_hasher,
        &path_hasher,
        &(0..9).map(|_| Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le()).collect::<Vec<Vec<bool>>>(),
    )
}

#[test]
fn test_merkle_tree_depth_2_arity_3_sha3() -> Result<()> {
    type LH = Sha3_256;
    type PH = Sha3_256;

    let leaf_hasher = Sha3_256::default();
    let path_hasher = Sha3_256::default();

    let mut rng = TestRng::default();

    // Check the depth-2 arity-3 Merkle tree.
    check_merkle_tree_depth_2_arity_3::<LH, PH>(
        &leaf_hasher,
        &path_hasher,
        &(0..9).map(|_| Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le()).collect::<Vec<Vec<bool>>>(),
    )
}

#[test]
fn test_merkle_tree_depth_3_arity_3_padded_bhp() -> Result<()> {
    type LH = BHP1024<CurrentEnvironment>;
    type PH = BHP512<CurrentEnvironment>;

    let leaf_hasher = LH::setup("AleoMerkleTreeTest0")?;
    let path_hasher = PH::setup("AleoMerkleTreeTest1")?;

    let mut rng = TestRng::default();

    // Check the depth-2 arity-3 Merkle tree.
    check_merkle_tree_depth_3_arity_3_padded::<LH, PH>(
        &leaf_hasher,
        &path_hasher,
        &(0..9).map(|_| Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le()).collect::<Vec<Vec<bool>>>(),
        &(0..1).map(|_| Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le()).collect::<Vec<Vec<bool>>>(),
    )
}

#[test]
fn test_merkle_tree_depth_3_arity_3_poseidon() -> Result<()> {
    type LH = Poseidon<CurrentEnvironment, 4>;
    type PH = Poseidon<CurrentEnvironment, 3>;

    let leaf_hasher = LH::setup("AleoMerkleTreeTest0")?;
    let path_hasher = PH::setup("AleoMerkleTreeTest1")?;

    let mut rng = TestRng::default();

    // Check the depth-3 arity-3 Merkle tree.
    check_merkle_tree_depth_3_arity_3_padded::<LH, PH>(
        &leaf_hasher,
        &path_hasher,
        &(0..9).map(|_| vec![Uniform::rand(&mut rng)]).collect::<Vec<_>>(),
        &(0..1).map(|_| vec![Uniform::rand(&mut rng)]).collect::<Vec<_>>(),
    )
}

#[test]
fn test_merkle_tree_depth_3_arity_3_keccak() -> Result<()> {
    type LH = Keccak256;
    type PH = Keccak256;

    let leaf_hasher = Keccak256::default();
    let path_hasher = Keccak256::default();

    let mut rng = TestRng::default();

    // Check the depth-3 arity-3 Merkle tree.
    check_merkle_tree_depth_3_arity_3_padded::<LH, PH>(
        &leaf_hasher,
        &path_hasher,
        &(0..9).map(|_| vec![Uniform::rand(&mut rng)]).collect::<Vec<_>>(),
        &(0..1).map(|_| vec![Uniform::rand(&mut rng)]).collect::<Vec<_>>(),
    )
}

#[test]
fn test_merkle_tree_depth_3_arity_3_sha3() -> Result<()> {
    type LH = Sha3_256;
    type PH = Sha3_256;

    let leaf_hasher = Sha3_256::default();
    let path_hasher = Sha3_256::default();

    let mut rng = TestRng::default();

    // Check the depth-3 arity-3 Merkle tree.
    check_merkle_tree_depth_3_arity_3_padded::<LH, PH>(
        &leaf_hasher,
        &path_hasher,
        &(0..9).map(|_| vec![Uniform::rand(&mut rng)]).collect::<Vec<_>>(),
        &(0..1).map(|_| vec![Uniform::rand(&mut rng)]).collect::<Vec<_>>(),
    )
}

#[test]
fn test_kary_merkle_tree_size_is_within_bounds() -> Result<()> {
    fn run_test<const DEPTH: u8, const ARITY: u8>(num_leaves: u128, rng: &mut TestRng) -> Result<()> {
        type LH = BHP1024<CurrentEnvironment>;
        type PH = BHP512<CurrentEnvironment>;

        println!("Testing a depth {DEPTH} arity {ARITY} tree with {num_leaves} leaves");
        // Check the Merkle tree.
        check_kary_merkle_tree::<LH, PH, DEPTH, ARITY>(
            &LH::setup("AleoMerkleTreeTest0")?,
            &PH::setup("AleoMerkleTreeTest1")?,
            &(0..num_leaves).map(|_| Field::<CurrentEnvironment>::rand(rng).to_bits_le()).collect::<Vec<Vec<bool>>>(),
        )
    }

    let mut rng = TestRng::default();

    // Ensure DEPTH = 0 fails.
    assert!(run_test::<0, 2>(0, &mut rng).is_err());
    // Ensure ARITY = 1 fails.
    assert!(run_test::<1, 1>(1, &mut rng).is_err());
    // Ensure DEPTH = 2, ARITY = 2 with more than 4 leaves fails.
    assert!(run_test::<2, 2>(4, &mut rng).is_ok());
    for num_leaves in 5..100 {
        assert!(run_test::<2, 2>(num_leaves, &mut rng).is_err());
    }
    // Ensure DEPTH = 4, ARITY = 3 with more than 81 leaves fails.
    assert!(run_test::<4, 3>(81, &mut rng).is_ok());
    for num_leaves in 82..1000 {
        assert!(run_test::<4, 3>(num_leaves, &mut rng).is_err());
    }
    Ok(())
}
