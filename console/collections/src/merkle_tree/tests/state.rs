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

type CurrentEnvironment = Console;

const DEPTH: u8 = 8;

/// Runs the following test:
/// 1. Construct a Merkle tree for the given leaves.
/// 2. Round-trip its state through bincode, and recreate the tree from it.
/// 3. Check that the recreated tree is equivalent to the original one.
fn check_state_round_trip<
    E: Environment,
    LH: LeafHash<Hash = PH::Hash>,
    PH: PathHash<Hash = Field<E>>,
    const DEPTH: u8,
>(
    leaf_hasher: &LH,
    path_hasher: &PH,
    leaves: &[LH::Leaf],
) -> Result<()> {
    let merkle_tree = MerkleTree::<E, LH, PH, DEPTH>::new(leaf_hasher, path_hasher, leaves)?;

    // Round-trip the state of the tree.
    let serialized = bincode::serialize(&merkle_tree.to_state())?;
    let state: MerkleTreeState<E> = bincode::deserialize(&serialized)?;
    let recreated = MerkleTree::<E, LH, PH, DEPTH>::from_state(leaf_hasher, path_hasher, state)?;

    // Ensure the recreated tree matches the original one.
    assert_eq!(merkle_tree.root(), recreated.root());
    assert_eq!(merkle_tree.tree(), recreated.tree());
    assert_eq!(merkle_tree.number_of_leaves, recreated.number_of_leaves);
    assert_eq!(merkle_tree.empty_hash, recreated.empty_hash);

    // Ensure the recreated tree is usable, i.e. its hashers are functional.
    for (leaf_index, leaf) in leaves.iter().enumerate() {
        let proof = recreated.prove(leaf_index, leaf)?;
        assert!(proof.verify(leaf_hasher, path_hasher, recreated.root(), leaf));
    }

    // Taking ownership must be indistinguishable on the wire; it exists only so that the state can
    // outlive the borrow, not to describe the tree differently.
    let serialized_owned = bincode::serialize(&merkle_tree.to_state().into_owned())?;
    assert_eq!(serialized, serialized_owned);

    // ...and it must recreate the same tree.
    let owned_state: MerkleTreeState<E> = bincode::deserialize(&serialized_owned)?;
    let from_owned = MerkleTree::<E, LH, PH, DEPTH>::from_state(leaf_hasher, path_hasher, owned_state)?;
    assert_eq!(recreated.root(), from_owned.root());
    assert_eq!(recreated.tree(), from_owned.tree());

    // An owned state borrows nothing, so it may be used after the tree it came from is gone.
    let outliving_state = merkle_tree.to_state().into_owned();
    drop(merkle_tree);
    let from_outliving = MerkleTree::<E, LH, PH, DEPTH>::from_state(leaf_hasher, path_hasher, outliving_state)?;
    assert_eq!(recreated.root(), from_outliving.root());

    // Taking ownership of an already-owned state is a no-op.
    let twice_owned = from_outliving.to_state().into_owned().into_owned();
    assert_eq!(serialized, bincode::serialize(&twice_owned)?);

    Ok(())
}

#[test]
fn test_state_round_trip_bhp() -> Result<()> {
    let mut rng = TestRng::default();

    let leaf_hasher = BHP1024::<CurrentEnvironment>::setup("MerkleTreeTest0")?;
    let path_hasher = BHP512::<CurrentEnvironment>::setup("MerkleTreeTest1")?;

    // Check a range of tree sizes, including the empty tree and both parities.
    for num_leaves in [0, 1, 2, 3, 4, 7, 8, 100] {
        let leaves: Vec<Vec<bool>> =
            (0..num_leaves).map(|_| Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le()).collect();
        check_state_round_trip::<CurrentEnvironment, _, _, DEPTH>(&leaf_hasher, &path_hasher, &leaves)?;
    }

    Ok(())
}

#[test]
fn test_state_round_trip_poseidon() -> Result<()> {
    let mut rng = TestRng::default();

    let leaf_hasher = Poseidon::<CurrentEnvironment, 4>::setup("MerkleTreeTest0")?;
    let path_hasher = Poseidon::<CurrentEnvironment, 2>::setup("MerkleTreeTest1")?;

    for num_leaves in [0, 1, 2, 3, 4, 7, 8, 100] {
        let leaves: Vec<Vec<Field<CurrentEnvironment>>> =
            (0..num_leaves).map(|_| vec![Field::<CurrentEnvironment>::rand(&mut rng)]).collect();
        check_state_round_trip::<CurrentEnvironment, _, _, DEPTH>(&leaf_hasher, &path_hasher, &leaves)?;
    }

    Ok(())
}

#[test]
fn test_state_round_trip_after_append() -> Result<()> {
    let mut rng = TestRng::default();

    let leaf_hasher = BHP1024::<CurrentEnvironment>::setup("MerkleTreeTest0")?;
    let path_hasher = BHP512::<CurrentEnvironment>::setup("MerkleTreeTest1")?;

    // Grow the tree one leaf at a time, round-tripping the state at every size, as
    // `append` maintains the tree size invariant that `from_state` checks.
    let mut merkle_tree = MerkleTree::<CurrentEnvironment, _, _, DEPTH>::new(&leaf_hasher, &path_hasher, &[])?;
    for _ in 0..20 {
        let leaf = Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le();
        merkle_tree.append(&[leaf])?;

        let serialized = bincode::serialize(&merkle_tree.to_state())?;
        let state: MerkleTreeState<CurrentEnvironment> = bincode::deserialize(&serialized)?;
        let recreated = MerkleTree::<CurrentEnvironment, _, _, DEPTH>::from_state(&leaf_hasher, &path_hasher, state)?;

        assert_eq!(merkle_tree.root(), recreated.root());
        assert_eq!(merkle_tree.tree(), recreated.tree());
    }

    Ok(())
}

#[test]
fn test_state_does_not_contain_the_hashers() -> Result<()> {
    let mut rng = TestRng::default();

    let leaf_hasher = BHP1024::<CurrentEnvironment>::setup("MerkleTreeTest0")?;
    let path_hasher = BHP512::<CurrentEnvironment>::setup("MerkleTreeTest1")?;

    // The BHP hashers hold tens of MiBs of precomputed bases, and deserializing a single
    // group element costs a subgroup check; including them in the payload used to make
    // loading a cached tree take minutes, regardless of how small the tree was.
    let leaf_hasher_size = bincode::serialize(&leaf_hasher)?.len();
    let path_hasher_size = bincode::serialize(&path_hasher)?.len();

    let leaves: Vec<Vec<bool>> = (0..10).map(|_| Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le()).collect();
    let merkle_tree = MerkleTree::<CurrentEnvironment, _, _, DEPTH>::new(&leaf_hasher, &path_hasher, &leaves)?;

    // Ensure the payload is a small multiple of the tree's own contents, which also rules
    // out either hasher having snuck into it.
    let size = bincode::serialize(&merkle_tree.to_state())?.len();
    let tree_size = merkle_tree.tree().len() * Field::<CurrentEnvironment>::size_in_bytes();
    assert!(size < 2 * tree_size, "the cached state ({size} B) is disproportionate to the tree ({tree_size} B)");
    assert!(size < leaf_hasher_size.min(path_hasher_size));

    Ok(())
}

#[test]
fn test_state_rejects_a_mismatched_path_hasher() -> Result<()> {
    let mut rng = TestRng::default();

    let leaf_hasher = BHP1024::<CurrentEnvironment>::setup("MerkleTreeTest0")?;
    let path_hasher = BHP512::<CurrentEnvironment>::setup("MerkleTreeTest1")?;
    // A path hasher set up with a different domain produces a different empty hash.
    let other_path_hasher = BHP512::<CurrentEnvironment>::setup("MerkleTreeTest2")?;

    let leaves: Vec<Vec<bool>> = (0..10).map(|_| Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le()).collect();
    let merkle_tree = MerkleTree::<CurrentEnvironment, _, _, DEPTH>::new(&leaf_hasher, &path_hasher, &leaves)?;

    assert!(
        MerkleTree::<CurrentEnvironment, _, _, DEPTH>::from_state(
            &leaf_hasher,
            &other_path_hasher,
            merkle_tree.to_state()
        )
        .is_err()
    );

    Ok(())
}

#[test]
fn test_state_rejects_a_corrupted_tree() -> Result<()> {
    let mut rng = TestRng::default();

    let leaf_hasher = BHP1024::<CurrentEnvironment>::setup("MerkleTreeTest0")?;
    let path_hasher = BHP512::<CurrentEnvironment>::setup("MerkleTreeTest1")?;

    let leaves: Vec<Vec<bool>> = (0..10).map(|_| Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le()).collect();
    let merkle_tree = MerkleTree::<CurrentEnvironment, _, _, DEPTH>::new(&leaf_hasher, &path_hasher, &leaves)?;

    // A tampered topmost node no longer hashes up to the cached root.
    let mut state = merkle_tree.to_state();
    state.tree.to_mut()[0] = Field::<CurrentEnvironment>::rand(&mut rng);
    assert!(MerkleTree::<CurrentEnvironment, _, _, DEPTH>::from_state(&leaf_hasher, &path_hasher, state).is_err());

    // A truncated tree no longer matches the expected size for its number of leaves.
    let mut state = merkle_tree.to_state();
    state.tree.to_mut().pop();
    assert!(MerkleTree::<CurrentEnvironment, _, _, DEPTH>::from_state(&leaf_hasher, &path_hasher, state).is_err());

    Ok(())
}
