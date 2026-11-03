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
use snarkvm_console_algorithms::{BHP512, BHP1024, Poseidon};
use snarkvm_console_types::prelude::Console;

use indexmap::IndexMap;

type CurrentEnvironment = Console;

const ITERATIONS: u128 = 10;

/// Runs the following test:
/// 1. Construct the Merkle tree for the leaves.
/// 2. Check that the Merkle proof for every leaf is valid.
/// 3. Update leaves in the Merkle tree.
/// 4. Check that the Merkle proof for every leaf is valid.
fn check_merkle_tree<E: Environment, LH: LeafHash<Hash = PH::Hash>, PH: PathHash<Hash = Field<E>>, const DEPTH: u8>(
    leaf_hasher: &LH,
    path_hasher: &PH,
    leaves: &[LH::Leaf],
    updates: &BTreeMap<usize, LH::Leaf>,
    rng: &mut TestRng,
) -> Result<()> {
    // Construct the Merkle tree for the given leaves.
    let mut merkle_tree = MerkleTree::<E, LH, PH, DEPTH>::new(leaf_hasher, path_hasher, leaves)?;
    assert_eq!(leaves.len(), merkle_tree.number_of_leaves);

    // Check each leaf in the Merkle tree.
    for (leaf_index, leaf) in leaves.iter().enumerate() {
        // Compute a Merkle proof for the leaf.
        let proof = merkle_tree.prove(leaf_index, leaf)?;
        // Verify the Merkle proof succeeds.
        assert!(proof.verify(leaf_hasher, path_hasher, merkle_tree.root(), leaf));
        // Verify the Merkle proof **fails** on an invalid root.
        assert!(!proof.verify(leaf_hasher, path_hasher, &PH::Hash::zero(), leaf));
        assert!(!proof.verify(leaf_hasher, path_hasher, &PH::Hash::one(), leaf));
        assert!(!proof.verify(leaf_hasher, path_hasher, &PH::Hash::rand(rng), leaf));
    }

    // If additional leaves are provided, check that the Merkle tree is consistent with them.
    if !updates.is_empty() {
        // Update the leaves of the Merkle tree.
        merkle_tree.update_many(updates)?;
        // Check each additional leaf in the Merkle tree.
        for (leaf_index, leaf) in updates {
            // Compute a Merkle proof for the leaf.
            let proof = merkle_tree.prove(*leaf_index, leaf)?;
            // Verify the Merkle proof succeeds.
            assert!(proof.verify(leaf_hasher, path_hasher, merkle_tree.root(), leaf));
            // Verify the Merkle proof **fails** on an invalid root.
            assert!(!proof.verify(leaf_hasher, path_hasher, &PH::Hash::zero(), leaf));
            assert!(!proof.verify(leaf_hasher, path_hasher, &PH::Hash::one(), leaf));
            assert!(!proof.verify(leaf_hasher, path_hasher, &PH::Hash::rand(rng), leaf));
        }
    }
    Ok(())
}

/// Runs the following test:
/// 1. Construct a Merkle tree of a given depth with a given number of leaves.
/// 2. Apply the updates to the Merkle tree.
/// 3. Construct a new Merkle tree with the only the updated leaves.
/// 4. Check that the Merkle root of the new Merkle tree is the same as the Merkle root of the original Merkle tree.
fn check_updated_merkle_tree_is_consistent<
    E: Environment,
    LH: LeafHash<Hash = PH::Hash>,
    PH: PathHash<Hash = Field<E>>,
    const DEPTH: u8,
>(
    leaf_hasher: &LH,
    path_hasher: &PH,
    leaves: Vec<LH::Leaf>,
    updates: BTreeMap<usize, LH::Leaf>,
) -> Result<()> {
    // Construct the Merkle tree for the given leaves.
    let mut merkle_tree = MerkleTree::<E, LH, PH, DEPTH>::new(leaf_hasher, path_hasher, &leaves)?;
    assert_eq!(leaves.len(), merkle_tree.number_of_leaves);

    // Construct an index map to track the leaves.
    let mut leaf_map: IndexMap<usize, LH::Leaf> = leaves.into_iter().enumerate().collect::<IndexMap<usize, LH::Leaf>>();

    // Apply the updates to the Merkle tree.
    merkle_tree.update_many(&updates)?;

    // Add the updated leaves to the index map.
    for (index, leaf) in updates {
        leaf_map.insert(index, leaf);
    }

    // Get the updated leaves.
    let updated_leaves = leaf_map.values().cloned().collect::<Vec<LH::Leaf>>();

    // Construct a new Merkle tree with the updated leaves.
    let updated_merkle_tree = MerkleTree::<E, LH, PH, DEPTH>::new(leaf_hasher, path_hasher, &updated_leaves)?;

    // Check that the Merkle root of the new Merkle tree is the same as the Merkle root of the original Merkle tree.
    assert_eq!(merkle_tree.root(), updated_merkle_tree.root());
    Ok(())
}

/// Runs the following test:
/// 1. Construct a depth-3 Merkle tree with 4 leaves (leaving 4 leaves empty).
/// 2. Checks that every node hash and the Merkle root is correct.
/// 3. Updates a leaf in the Merkle tree.
/// 4. Checks that every node hash and the Merkle root is correct.
fn check_merkle_tree_depth_3_single_update<
    E: Environment,
    LH: LeafHash<Hash = PH::Hash>,
    PH: PathHash<Hash = Field<E>>,
>(
    leaf_hasher: &LH,
    path_hasher: &PH,
    leaves: &[LH::Leaf],
    updates: &BTreeMap<usize, LH::Leaf>,
) -> Result<()> {
    assert_eq!(4, leaves.len(), "Padded depth-3 test requires 4 leaves (out of 8)");
    assert_eq!(1, updates.len(), "Padded depth-3 test requires 1 update");

    // Construct the Merkle tree for the given leaves.
    let mut merkle_tree = MerkleTree::<E, LH, PH, 3>::new(leaf_hasher, path_hasher, leaves)?;
    assert_eq!(7, merkle_tree.tree.len());
    assert_eq!(4, merkle_tree.number_of_leaves);

    // Depth 3.
    let expected_leaf0 = LeafHash::hash_leaf(leaf_hasher, &leaves[0])?;
    let expected_leaf1 = LeafHash::hash_leaf(leaf_hasher, &leaves[1])?;
    let expected_leaf2 = LeafHash::hash_leaf(leaf_hasher, &leaves[2])?;
    let expected_leaf3 = LeafHash::hash_leaf(leaf_hasher, &leaves[3])?;
    assert_eq!(expected_leaf0, merkle_tree.tree[3]);
    assert_eq!(expected_leaf1, merkle_tree.tree[4]);
    assert_eq!(expected_leaf2, merkle_tree.tree[5]);
    assert_eq!(expected_leaf3, merkle_tree.tree[6]);

    // Depth 2.
    let expected_left = PathHash::hash_children(path_hasher, &expected_leaf0, &expected_leaf1)?;
    let expected_right = PathHash::hash_children(path_hasher, &expected_leaf2, &expected_leaf3)?;
    assert_eq!(expected_left, merkle_tree.tree[1]);
    assert_eq!(expected_right, merkle_tree.tree[2]);

    // Depth 1.
    let expected_left = PathHash::hash_children(path_hasher, &expected_left, &expected_right)?;
    let expected_right = path_hasher.hash_empty()?;
    assert_eq!(expected_left, merkle_tree.tree[0]);

    // Depth 0.
    let expected_root = PathHash::hash_children(path_hasher, &expected_left, &expected_right)?;
    assert_eq!(expected_root, *merkle_tree.root());

    // ------------------------------------------------------------------------------------------ //
    // Check that the Merkle tree can be updated in place with the new leaf.
    // ------------------------------------------------------------------------------------------ //

    // Update the Merkle tree.
    let (leaf_index, leaf) = &updates.first_key_value().unwrap();
    merkle_tree.update_many(updates)?;
    assert_eq!(7, merkle_tree.tree.len());
    assert_eq!(4, merkle_tree.number_of_leaves);

    // Depth 3.
    let expected_leaf0 = match **leaf_index == 0 {
        true => LeafHash::hash_leaf(leaf_hasher, leaf)?,
        false => LeafHash::hash_leaf(leaf_hasher, &leaves[0])?,
    };
    let expected_leaf1 = match **leaf_index == 1 {
        true => LeafHash::hash_leaf(leaf_hasher, leaf)?,
        false => LeafHash::hash_leaf(leaf_hasher, &leaves[1])?,
    };
    let expected_leaf2 = match **leaf_index == 2 {
        true => LeafHash::hash_leaf(leaf_hasher, leaf)?,
        false => LeafHash::hash_leaf(leaf_hasher, &leaves[2])?,
    };
    let expected_leaf3 = match **leaf_index == 3 {
        true => LeafHash::hash_leaf(leaf_hasher, leaf)?,
        false => LeafHash::hash_leaf(leaf_hasher, &leaves[3])?,
    };
    assert_eq!(expected_leaf0, merkle_tree.tree[3]);
    assert_eq!(expected_leaf1, merkle_tree.tree[4]);
    assert_eq!(expected_leaf2, merkle_tree.tree[5]);
    assert_eq!(expected_leaf3, merkle_tree.tree[6]);

    // Depth 2.
    let expected_left = PathHash::hash_children(path_hasher, &expected_leaf0, &expected_leaf1)?;
    let expected_right = PathHash::hash_children(path_hasher, &expected_leaf2, &expected_leaf3)?;
    assert_eq!(expected_left, merkle_tree.tree[1]);
    assert_eq!(expected_right, merkle_tree.tree[2]);

    // Depth 1.
    let expected_left = PathHash::hash_children(path_hasher, &expected_left, &expected_right)?;
    let expected_right = path_hasher.hash_empty()?;
    assert_eq!(expected_left, merkle_tree.tree[0]);

    // Depth 0.
    let expected_root = PathHash::hash_children(path_hasher, &expected_left, &expected_right)?;
    assert_eq!(expected_root, *merkle_tree.root());
    Ok(())
}

#[test]
fn test_merkle_tree_bhp() -> Result<()> {
    fn run_test<const DEPTH: u8>(rng: &mut TestRng) -> Result<()> {
        type LH = BHP1024<CurrentEnvironment>;
        type PH = BHP512<CurrentEnvironment>;

        let leaf_hasher = LH::setup("AleoMerkleTreeTest0")?;
        let path_hasher = PH::setup("AleoMerkleTreeTest1")?;

        for i in 0..ITERATIONS {
            for j in 0..ITERATIONS {
                // Determine the leaves and additional leaves.
                let num_leaves = core::cmp::min(2u128.pow(DEPTH as u32), i);
                let num_updates = core::cmp::min(num_leaves, core::cmp::min(2u128.pow(DEPTH as u32) - num_leaves, j));

                // Check the Merkle tree.
                check_merkle_tree::<CurrentEnvironment, LH, PH, DEPTH>(
                    &leaf_hasher,
                    &path_hasher,
                    &(0..num_leaves)
                        .map(|_| Field::<CurrentEnvironment>::rand(rng).to_bits_le())
                        .collect::<Vec<Vec<bool>>>(),
                    &(0..num_updates)
                        .rev()
                        .map(|i| ((i % num_leaves) as usize, Field::<CurrentEnvironment>::rand(rng).to_bits_le()))
                        .collect::<BTreeMap<usize, Vec<bool>>>(),
                    rng,
                )?;
            }
        }
        Ok(())
    }

    let mut rng = TestRng::default();

    // Ensure DEPTH = 0 fails.
    assert!(run_test::<0>(&mut rng).is_err());
    // Spot check important depths.
    run_tests!(&mut rng, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 31, 32, 64]);
    Ok(())
}

#[test]
fn test_merkle_tree_poseidon() -> Result<()> {
    fn run_test<const DEPTH: u8>(rng: &mut TestRng) -> Result<()> {
        type LH = Poseidon<CurrentEnvironment, 4>;
        type PH = Poseidon<CurrentEnvironment, 2>;

        let leaf_hasher = LH::setup("AleoMerkleTreeTest0")?;
        let path_hasher = PH::setup("AleoMerkleTreeTest1")?;

        for i in 0..ITERATIONS {
            for j in 0..ITERATIONS {
                // Determine the leaves and additional leaves.
                let num_leaves = core::cmp::min(2u128.pow(DEPTH as u32), i);
                let num_additional_leaves =
                    core::cmp::min(num_leaves, core::cmp::min(2u128.pow(DEPTH as u32) - num_leaves, j));

                // Check the Merkle tree.
                check_merkle_tree::<CurrentEnvironment, LH, PH, DEPTH>(
                    &leaf_hasher,
                    &path_hasher,
                    &(0..num_leaves).map(|_| vec![Uniform::rand(rng)]).collect::<Vec<_>>(),
                    &(0..num_additional_leaves)
                        .rev()
                        .map(|i| ((i % num_leaves) as usize, vec![Uniform::rand(rng)]))
                        .collect::<BTreeMap<_, _>>(),
                    rng,
                )?;
            }
        }
        Ok(())
    }

    let mut rng = TestRng::default();

    // Ensure DEPTH = 0 fails.
    assert!(run_test::<0>(&mut rng).is_err());
    // Spot check important depths.
    run_tests!(&mut rng, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 31, 32, 64]);
    Ok(())
}

#[test]
fn test_merkle_tree_bhp_update_many_is_consistent() -> Result<()> {
    fn run_test<const DEPTH: u8>(rng: &mut TestRng) -> Result<()> {
        type LH = BHP1024<CurrentEnvironment>;
        type PH = BHP512<CurrentEnvironment>;

        let leaf_hasher = LH::setup("AleoMerkleTreeTest0")?;
        let path_hasher = PH::setup("AleoMerkleTreeTest1")?;

        for _ in 0..ITERATIONS {
            // Determine the leaves and additional leaves.
            let num_leaves = 2u128.pow(DEPTH as u32);

            // Construct the random updates.
            let updates = (0..num_leaves)
                .map(|_| {
                    let index: u128 = Uniform::rand(rng);
                    ((index % num_leaves) as usize, Field::<CurrentEnvironment>::rand(rng).to_bits_le())
                })
                .collect::<BTreeMap<usize, Vec<bool>>>();

            // Check the Merkle tree.
            check_updated_merkle_tree_is_consistent::<CurrentEnvironment, LH, PH, DEPTH>(
                &leaf_hasher,
                &path_hasher,
                (0..num_leaves)
                    .map(|_| Field::<CurrentEnvironment>::rand(rng).to_bits_le())
                    .collect::<Vec<Vec<bool>>>(),
                updates,
            )?;
        }
        Ok(())
    }

    let mut rng = TestRng::default();

    // Ensure DEPTH = 0 fails.
    assert!(run_test::<0>(&mut rng).is_err());
    // Spot check important depths.
    run_tests!(&mut rng, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    Ok(())
}

#[test]
fn test_merkle_tree_poseidon_update_many_is_consistent() -> Result<()> {
    fn run_test<const DEPTH: u8>(rng: &mut TestRng) -> Result<()> {
        type LH = Poseidon<CurrentEnvironment, 4>;
        type PH = Poseidon<CurrentEnvironment, 2>;

        let leaf_hasher = LH::setup("AleoMerkleTreeTest0")?;
        let path_hasher = PH::setup("AleoMerkleTreeTest1")?;

        for _ in 0..ITERATIONS {
            // Determine the leaves and additional leaves.
            let num_leaves = 2u128.pow(DEPTH as u32);

            // Construct the random updates.
            let updates = (0..num_leaves)
                .map(|_| {
                    let index: u128 = Uniform::rand(rng);
                    ((index % num_leaves) as usize, vec![Uniform::rand(rng)])
                })
                .collect::<BTreeMap<usize, Vec<_>>>();

            // Check the Merkle tree.
            check_updated_merkle_tree_is_consistent::<CurrentEnvironment, LH, PH, DEPTH>(
                &leaf_hasher,
                &path_hasher,
                (0..num_leaves).map(|_| vec![Uniform::rand(rng)]).collect::<Vec<Vec<_>>>(),
                updates,
            )?;
        }
        Ok(())
    }

    let mut rng = TestRng::default();

    // Ensure DEPTH = 0 fails.
    assert!(run_test::<0>(&mut rng).is_err());
    // Spot check important depths.
    run_tests!(&mut rng, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    Ok(())
}

#[test]
fn test_merkle_tree_bhp_update_and_update_many_match() -> Result<()> {
    fn run_test<const DEPTH: u8>(rng: &mut TestRng) -> Result<()> {
        type LH = BHP1024<CurrentEnvironment>;
        type PH = BHP512<CurrentEnvironment>;

        let leaf_hasher = LH::setup("AleoMerkleTreeTest0")?;
        let path_hasher = PH::setup("AleoMerkleTreeTest1")?;

        for _ in 0..ITERATIONS {
            // Determine the leaves and additional leaves.
            let num_leaves = core::cmp::min(2u128.pow(DEPTH as u32), 256);

            // Construct the leaves.
            let leaves = (0..num_leaves)
                .map(|_| Field::<CurrentEnvironment>::rand(rng).to_bits_le())
                .collect::<Vec<Vec<bool>>>();

            // Construct the updates.
            let single_updates = (0..num_leaves)
                .map(|_| {
                    let index: u128 = Uniform::rand(rng);
                    ((index % num_leaves) as usize, Field::<CurrentEnvironment>::rand(rng).to_bits_le())
                })
                .collect::<Vec<(usize, Vec<bool>)>>();

            // Construct the batch updates from the single updates.
            let batch_updates = single_updates.iter().cloned().collect::<BTreeMap<usize, Vec<bool>>>();

            // Initialize a Merkle tree for the single updates.
            let mut single_merkle_tree =
                MerkleTree::<CurrentEnvironment, LH, PH, DEPTH>::new(&leaf_hasher, &path_hasher, &leaves)?;
            // Update the Merkle tree with the single updates.
            for (index, leaf) in single_updates {
                single_merkle_tree.update(index, &leaf)?;
            }

            // Initialize a Merkle tree for the batch updates.
            let mut batch_merkle_tree =
                MerkleTree::<CurrentEnvironment, LH, PH, DEPTH>::new(&leaf_hasher, &path_hasher, &leaves)?;
            // Update the Merkle tree with the batch updates.
            batch_merkle_tree.update_many(&batch_updates)?;

            // Check that the roots of the two Merkle trees match.
            assert_eq!(single_merkle_tree.root(), batch_merkle_tree.root());
        }
        Ok(())
    }

    let mut rng = TestRng::default();

    // Ensure DEPTH = 0 fails.
    assert!(run_test::<0>(&mut rng).is_err());
    // Spot check important depths.
    run_tests!(&mut rng, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 31, 32, 64]);
    Ok(())
}

#[test]
fn test_merkle_tree_poseidon_update_and_update_many_match() -> Result<()> {
    fn run_test<const DEPTH: u8>(rng: &mut TestRng) -> Result<()> {
        type LH = Poseidon<CurrentEnvironment, 4>;
        type PH = Poseidon<CurrentEnvironment, 2>;

        let leaf_hasher = LH::setup("AleoMerkleTreeTest0")?;
        let path_hasher = PH::setup("AleoMerkleTreeTest1")?;

        for _ in 0..ITERATIONS {
            // Determine the number of leaves.
            let num_leaves = core::cmp::min(2u128.pow(DEPTH as u32), 256);

            // Construct the leaves.
            let leaves = (0..num_leaves).map(|_| vec![Uniform::rand(rng)]).collect::<Vec<_>>();

            // Construct the updates.
            let single_updates = (0..num_leaves)
                .map(|_| {
                    let index: u128 = Uniform::rand(rng);
                    ((index % num_leaves) as usize, vec![Uniform::rand(rng)])
                })
                .collect::<Vec<(usize, Vec<_>)>>();

            // Construct the batch updates for the single updates.
            let batch_updates = single_updates.iter().cloned().collect::<BTreeMap<usize, Vec<_>>>();

            // Initialize a Merkle tree for the single updates.
            let mut single_merkle_tree =
                MerkleTree::<CurrentEnvironment, LH, PH, DEPTH>::new(&leaf_hasher, &path_hasher, &leaves)?;
            // Update the Merkle tree with the single updates.
            for (index, leaf) in single_updates {
                single_merkle_tree.update(index, &leaf)?;
            }

            // Initialize a Merkle tree for the batch updates.
            let mut batch_merkle_tree =
                MerkleTree::<CurrentEnvironment, LH, PH, DEPTH>::new(&leaf_hasher, &path_hasher, &leaves)?;
            // Update the Merkle tree with the batch updates.
            batch_merkle_tree.update_many(&batch_updates)?;

            // Check that the roots of the two Merkle trees match.
            assert_eq!(single_merkle_tree.root(), batch_merkle_tree.root());
        }
        Ok(())
    }

    let mut rng = TestRng::default();

    // Ensure DEPTH = 0 fails.
    assert!(run_test::<0>(&mut rng).is_err());
    // Spot check important depths.
    run_tests!(&mut rng, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 31, 32, 64]);
    Ok(())
}

#[test]
fn test_merkle_tree_depth_3_poseidon() -> Result<()> {
    type LH = Poseidon<CurrentEnvironment, 4>;
    type PH = Poseidon<CurrentEnvironment, 2>;

    let leaf_hasher = LH::setup("AleoMerkleTreeTest0")?;
    let path_hasher = PH::setup("AleoMerkleTreeTest1")?;

    let mut rng = TestRng::default();

    // Check the depth-3 Merkle tree.
    check_merkle_tree_depth_3_single_update::<CurrentEnvironment, LH, PH>(
        &leaf_hasher,
        &path_hasher,
        &(0..4).map(|_| vec![Uniform::rand(&mut rng)]).collect::<Vec<_>>(),
        &[(0, vec![Uniform::rand(&mut rng)])].into(),
    )
}

#[test]
fn test_merkle_tree_depth_3_bhp() -> Result<()> {
    type LH = BHP1024<CurrentEnvironment>;
    type PH = BHP512<CurrentEnvironment>;

    let leaf_hasher = LH::setup("AleoMerkleTreeTest0")?;
    let path_hasher = PH::setup("AleoMerkleTreeTest1")?;

    let mut rng = TestRng::default();

    // Check the depth-3 Merkle tree.
    check_merkle_tree_depth_3_single_update::<CurrentEnvironment, LH, PH>(
        &leaf_hasher,
        &path_hasher,
        &(0..4).map(|_| Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le()).collect::<Vec<Vec<bool>>>(),
        &[(0, Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le())].into(),
    )
}

/// Use `cargo test profiler --features timer` to run this test.
#[ignore]
#[test]
fn test_profiler() -> Result<()> {
    const DEPTH: u8 = 32;
    const NUM_LEAVES: &[usize] = &[1000, 10000];

    /// Generates the specified number of random Merkle tree leaves.
    macro_rules! generate_leaves {
        ($num_leaves:expr, $rng:expr) => {{ (0..$num_leaves).map(|_| Field::<CurrentEnvironment>::rand($rng).to_bits_le()).collect::<Vec<_>>() }};
    }

    type LH = BHP1024<CurrentEnvironment>;
    type PH = BHP512<CurrentEnvironment>;

    let leaf_hasher = LH::setup("AleoMerkleTreeTest0")?;
    let path_hasher = PH::setup("AleoMerkleTreeTest1")?;

    let mut rng = TestRng::default();

    for num_leaves in NUM_LEAVES {
        // New
        let leaves = generate_leaves!(*num_leaves, &mut rng);
        let mut merkle_tree =
            MerkleTree::<CurrentEnvironment, LH, PH, DEPTH>::new(&leaf_hasher, &path_hasher, &leaves)?;

        // Update
        generate_leaves!(1, &mut rng)
            .into_iter()
            .map(|leaf| {
                let index = usize::try_from(rng.random::<u64>()).unwrap();
                (index % num_leaves, leaf)
            })
            .for_each(|(index, leaf)| {
                merkle_tree.update_many(&[(index, leaf)].into()).unwrap();
            });
    }

    bail!("\n\nRemember to #[ignore] this test!\n\n")
}
