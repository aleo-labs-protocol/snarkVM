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

mod helpers;
pub use helpers::{BooleanHash, KeyHash, LeafHash, PathHash};

mod verify;

#[cfg(test)]
use snarkvm_circuit_types::environment::assert_scope;

use snarkvm_circuit_types::{Boolean, Field, U64, environment::prelude::*};

pub struct SparseKaryMerklePath<E: Environment, PH: PathHash<E>, const DEPTH: u8, const ARITY: u8> {
    /// The key hash for the path (determines the path through the tree).
    key_hash: Field<E>,
    /// The `siblings` contains a list of sibling hashes from the leaf to the root.
    siblings: Vec<Vec<PH::Hash>>,
}

impl<E: Environment, PH: PathHash<E>, const DEPTH: u8, const ARITY: u8> Inject
    for SparseKaryMerklePath<E, PH, DEPTH, ARITY>
{
    type Primitive = console::sparse_kary_merkle_tree::SparseKaryMerklePath<E::Network, PH::Primitive, DEPTH, ARITY>;

    /// Initializes a Merkle path from the given mode and native Merkle path.
    fn new(mode: Mode, merkle_path: Self::Primitive) -> Self {
        // Initialize the key hash.
        let key_hash = Field::new(mode, *merkle_path.key_hash());
        // Initialize the Merkle path siblings.
        let siblings: Vec<Vec<_>> = merkle_path
            .siblings()
            .iter()
            .map(|nodes| nodes.iter().map(|node| Inject::new(mode, *node)).collect())
            .collect();

        // Ensure the Merkle path has the correct arity.
        for sibling in &siblings {
            if sibling.len() != ARITY.saturating_sub(1) as usize {
                return E::halt("Merkle path is not the correct arity");
            }
        }
        // Ensure the Merkle path is the correct depth.
        match siblings.len() == DEPTH as usize {
            // Return the Merkle path.
            true => Self { key_hash, siblings },
            false => E::halt("Merkle path is not the correct depth"),
        }
    }
}

impl<E: Environment, PH: PathHash<E>, const DEPTH: u8, const ARITY: u8> Eject
    for SparseKaryMerklePath<E, PH, DEPTH, ARITY>
{
    type Primitive = console::sparse_kary_merkle_tree::SparseKaryMerklePath<E::Network, PH::Primitive, DEPTH, ARITY>;

    /// Ejects the mode of the Merkle path.
    fn eject_mode(&self) -> Mode {
        (&self.key_hash, &self.siblings).eject_mode()
    }

    /// Ejects the Merkle path.
    fn eject_value(&self) -> Self::Primitive {
        match Self::Primitive::try_from((self.key_hash.eject_value(), self.siblings.eject_value())) {
            Ok(merkle_path) => merkle_path,
            Err(error) => E::halt(format!("Failed to eject the Merkle path: {error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_algorithms::Poseidon2;
    use snarkvm_circuit_network::AleoV0 as Circuit;
    use snarkvm_utilities::{TestRng, Uniform};

    use anyhow::Result;

    const ITERATIONS: u128 = 100;

    fn check_new<const DEPTH: u8, const ARITY: u8>(
        mode: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) -> Result<()> {
        let mut rng = TestRng::default();

        type PH = Poseidon2<Circuit>;

        type NativeKH = console::algorithms::Poseidon2<<Circuit as Environment>::Network>;
        type NativeLH = console::algorithms::Poseidon2<<Circuit as Environment>::Network>;
        type NativePH = console::algorithms::Poseidon2<<Circuit as Environment>::Network>;

        let key_hasher = NativeKH::setup("AleoSparsePathTest0")?;
        let leaf_hasher = NativeLH::setup("AleoSparsePathTest1")?;
        let path_hasher = NativePH::setup("AleoSparsePathTest2")?;

        for i in 0..ITERATIONS {
            // Determine the number of key-value pairs.
            let num_pairs = core::cmp::min((ARITY as u128).pow(DEPTH as u32), i + 1);

            // Generate random keys (field elements).
            let keys = (0..num_pairs)
                .map(|_| console::Field::<<Circuit as Environment>::Network>::rand(&mut rng))
                .collect::<Vec<_>>();

            // Generate random leaves.
            let leaves = (0..num_pairs)
                .map(|_| vec![console::Field::<<Circuit as Environment>::Network>::rand(&mut rng)])
                .collect::<Vec<_>>();

            // Compute the sparse Merkle tree.
            let mut merkle_tree = console::sparse_kary_merkle_tree::SparseKaryMerkleTree::<
                NativeKH,
                NativeLH,
                NativePH,
                <Circuit as Environment>::Network,
                DEPTH,
                ARITY,
            >::new(&key_hasher, &leaf_hasher, &path_hasher)?;

            // Insert key-value pairs.
            for (key, leaf) in keys.iter().zip(leaves.iter()) {
                merkle_tree.update(key, leaf)?;
            }

            for (key, leaf) in keys.iter().zip(leaves.iter()) {
                // Compute the Merkle path.
                let merkle_path = merkle_tree.prove(key, leaf)?;

                Circuit::scope(format!("New {mode}"), || {
                    let candidate = SparseKaryMerklePath::<Circuit, PH, DEPTH, ARITY>::new(mode, merkle_path.clone());
                    assert_eq!(merkle_path, candidate.eject_value());
                    assert_scope!(num_constants, num_public, num_private, num_constraints);
                });
                Circuit::reset();
            }
        }
        Ok(())
    }

    #[test]
    fn test_new_constant() -> Result<()> {
        // Depth 8, Arity 4: Each path level has 3 siblings (ARITY - 1).
        // Total siblings: 8 * 3 = 24 field elements.
        // Plus 1 field for the key hash = 25 field elements.
        check_new::<8, 4>(Mode::Constant, 25, 0, 0, 0)
    }

    #[test]
    fn test_new_public() -> Result<()> {
        check_new::<8, 4>(Mode::Public, 0, 25, 0, 0)
    }

    #[test]
    fn test_new_private() -> Result<()> {
        check_new::<8, 4>(Mode::Private, 0, 0, 25, 0)
    }
}
