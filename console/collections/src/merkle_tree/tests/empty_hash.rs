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
use snarkvm_console_algorithms::{BHP512, BHP1024, Poseidon2};
use snarkvm_console_types::prelude::Console;

type CurrentEnvironment = Console;

/// The value a hasher must keep giving, computed the long way round.
fn uncached<E: Environment, PH: PathHash<Hash = Field<E>>>(path_hasher: &PH) -> Result<Field<E>> {
    path_hasher.hash_children(&Field::<E>::zero(), &Field::<E>::zero())
}

/// Remembering the empty hash must not change it, however many times it is asked for.
///
/// `BHP::merkle_empty_hash` and `Poseidon::merkle_empty_hash` spell out the encoding
/// `hash_children` uses, for two zero children; this is what catches the two drifting.
#[test]
fn test_cached_empty_hash_matches_the_computed_one() -> Result<()> {
    let bhp = BHP512::<CurrentEnvironment>::setup("AleoMerkleTree0")?;
    let expected = uncached(&bhp)?;
    // The first call fills the cell, the second reads it; both give the same hash.
    assert_eq!(expected, bhp.hash_empty()?);
    assert_eq!(expected, bhp.hash_empty()?);

    let psd = Poseidon2::<CurrentEnvironment>::setup("AleoMerkleTree0")?;
    let expected = uncached(&psd)?;
    assert_eq!(expected, psd.hash_empty()?);
    assert_eq!(expected, psd.hash_empty()?);
    Ok(())
}

/// Two hashers of the same type set up with different domains have different empty
/// hashes, so each must answer with its own.
///
/// This is the whole reason the cell hangs off the instance: a `static` inside a
/// generic item is one cell shared by every monomorphisation of that item, which
/// here would be one cell for every `BHP512<Console>` in the process, and whichever
/// domain got there first would answer for all of them.
#[test]
fn test_empty_hash_is_keyed_by_the_instance_not_the_type() -> Result<()> {
    let first = BHP512::<CurrentEnvironment>::setup("AleoMerkleTree0")?;
    let second = BHP512::<CurrentEnvironment>::setup("AleoMerkleTree1")?;
    assert_ne!(uncached(&first)?, uncached(&second)?, "the domains must give different empty hashes");

    // Fill the first hasher's cell, then check that the second is unaffected.
    assert_eq!(uncached(&first)?, first.hash_empty()?);
    assert_eq!(uncached(&second)?, second.hash_empty()?);
    assert_eq!(uncached(&first)?, first.hash_empty()?);

    let first = Poseidon2::<CurrentEnvironment>::setup("AleoMerkleTree0")?;
    let second = Poseidon2::<CurrentEnvironment>::setup("AleoMerkleTree1")?;
    assert_ne!(uncached(&first)?, uncached(&second)?, "the domains must give different empty hashes");
    assert_eq!(uncached(&first)?, first.hash_empty()?);
    assert_eq!(uncached(&second)?, second.hash_empty()?);
    assert_eq!(uncached(&first)?, first.hash_empty()?);
    Ok(())
}

/// Whether a hasher has been asked for its empty hash says nothing about the hasher, so
/// a warm one must still equal a cold one set up the same way.
#[test]
fn test_warm_hasher_equals_cold_hasher() -> Result<()> {
    let cold = BHP512::<CurrentEnvironment>::setup("AleoMerkleTree0")?;
    let warm = BHP512::<CurrentEnvironment>::setup("AleoMerkleTree0")?;
    warm.hash_empty()?;
    assert_eq!(cold, warm);

    let cold = Poseidon2::<CurrentEnvironment>::setup("AleoMerkleTree0")?;
    let warm = Poseidon2::<CurrentEnvironment>::setup("AleoMerkleTree0")?;
    warm.hash_empty()?;
    assert_eq!(cold, warm);
    Ok(())
}

/// A tree built with a hasher that has already answered once must be the same tree.
#[test]
fn test_tree_is_unchanged_by_a_warm_hasher() -> Result<()> {
    const DEPTH: u8 = 5;
    let mut rng = TestRng::default();
    let leaves: Vec<_> = (0..4).map(|_| Field::<CurrentEnvironment>::rand(&mut rng).to_bits_le()).collect();

    let cold = BHP512::<CurrentEnvironment>::setup("AleoMerkleTree0")?;
    let leaf_hasher = BHP1024::<CurrentEnvironment>::setup("AleoMerkleTree0")?;
    let from_cold = MerkleTree::<CurrentEnvironment, _, _, DEPTH>::new(&leaf_hasher, &cold, &leaves)?;

    let warm = BHP512::<CurrentEnvironment>::setup("AleoMerkleTree0")?;
    warm.hash_empty()?;
    let from_warm = MerkleTree::<CurrentEnvironment, _, _, DEPTH>::new(&leaf_hasher, &warm, &leaves)?;

    assert_eq!(from_cold.root(), from_warm.root());
    assert_eq!(from_cold.tree(), from_warm.tree());
    Ok(())
}
