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

impl<E: Environment, PH: PathHash<E>, const DEPTH: u8, const ARITY: u8> KaryMerklePath<E, PH, DEPTH, ARITY> {
    /// Returns `true` if the Merkle path is valid for the given root and leaf.
    #[must_use = "This method returns a Boolean circuit variable which should be handled"]
    pub fn verify<LH: LeafHash<Hash = PH::Hash>>(
        &self,
        leaf_hasher: &LH,
        path_hasher: &PH,
        root: &PH::Hash,
        leaf: &LH::Leaf,
    ) -> Boolean<E> {
        // Ensure the leaf index is within the tree depth.
        if (*self.leaf_index.eject_value() as u128) >= (ARITY as u128).pow(DEPTH as u32) {
            E::halt("Found an out of bounds Merkle leaf index")
        }
        // Ensure the path length matches the expected depth.
        else if self.siblings.len() != DEPTH as usize {
            E::halt("Found an incorrect Merkle path length")
        }

        // Ensure the Merkle path has the correct arity.
        for sibling in &self.siblings {
            if sibling.len() != ARITY.saturating_sub(1) as usize {
                return E::halt("Merkle path is not the correct depth");
            }
        }

        // Initialize a tracker for the current hash, by computing the leaf hash to start.
        let mut current_hash = leaf_hasher.hash_leaf(leaf);

        let arity = U64::<E>::new(Mode::Constant, console::U64::new(ARITY as u64));

        let indicator_indexes = (0..DEPTH).map(|i| {
            let index = U16::<E>::new(Mode::Constant, console::U16::new(i as u16));
            &self.leaf_index / (arity.clone().pow(index)) % arity.clone()
        });

        // Initialize the zero index.
        let zero_index = U64::<E>::zero();
        // Initialize the last index.
        let last_index = U64::<E>::new(Mode::Constant, console::U64::new(ARITY.saturating_sub(1) as u64));

        // Check levels between leaf level and root.
        for (indicator_index, sibling_hashes) in indicator_indexes.zip_eq(&self.siblings) {
            // Assemble the children based on the ternary results.
            let mut children = Vec::with_capacity(sibling_hashes.len() + 1);

            // Add the first child.
            let first_child =
                PH::Hash::ternary(&indicator_index.is_equal(&zero_index), &current_hash, &sibling_hashes[0]);

            children.push(first_child);

            // Calculate the middle children.
            for i in 1..sibling_hashes.len() {
                // Index of the current sibling
                let index = U64::<E>::new(Mode::Constant, console::U64::new(i as u64));

                // When the index is less than the indicator index, use the current index. Otherwise, use the previous index.
                let option_a = PH::Hash::ternary(
                    &index.is_less_than(&indicator_index),
                    &sibling_hashes[i],
                    &sibling_hashes[i - 1],
                );

                // When the index is equal to the indicator index, use the current hash.
                let option_b = PH::Hash::ternary(&index.is_equal(&indicator_index), &current_hash, &option_a);

                // Push the final option to the children
                children.push(option_b);
            }

            // Add the last child.
            let last_child = PH::Hash::ternary(
                &indicator_index.is_equal(&last_index),
                &current_hash,
                sibling_hashes.last().unwrap(),
            );

            children.push(last_child);

            // Update the current hash for the next level.
            current_hash = path_hasher.hash_children(&children);
        }

        // Ensure the final hash matches the given root.
        root.is_equal(&current_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_algorithms::{BHP512, BHP1024, Keccak256, Poseidon2, Poseidon4, Sha3_256};
    use snarkvm_circuit_types::environment::Circuit;
    use snarkvm_utilities::{TestRng, Uniform};

    use anyhow::Result;

    const ITERATIONS: u128 = 10;
    const DOMAIN: &str = "MerkleTreeCircuit0";

    macro_rules! check_verify {
        ($lh:ident, $ph:ident, $mode:ident, $depth:expr, $arity:expr, $num_inputs:expr, ($num_constants:expr, $num_public:expr, $num_private:expr, $num_constraints:expr)) => {{
            // Initialize the leaf hasher.
            let native_leaf_hasher =
                snarkvm_console_algorithms::$lh::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
            let circuit_leaf_hasher = $lh::<Circuit>::constant(native_leaf_hasher.clone());

            let mut rng = TestRng::default();

            // Initialize the path hasher.
            let native_path_hasher =
                snarkvm_console_algorithms::$ph::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
            let circuit_path_hasher = $ph::<Circuit>::constant(native_path_hasher.clone());

            for i in 0..ITERATIONS {
                // Determine the number of leaves.
                let num_leaves = core::cmp::min(($arity as u128).pow($depth as u32), i);
                // Compute the leaves.
                let leaves = (0..num_leaves)
                    .map(|_| (0..$num_inputs).map(|_| Uniform::rand(&mut rng)).collect::<Vec<_>>())
                    .collect::<Vec<_>>();
                // Compute the Merkle tree.
                let merkle_tree = console::kary_merkle_tree::KaryMerkleTree::<_, _, $depth, $arity>::new(
                    &native_leaf_hasher,
                    &native_path_hasher,
                    &leaves,
                )?;

                for (index, merkle_leaf) in leaves.iter().enumerate() {
                    // Compute the Merkle path.
                    let merkle_path = merkle_tree.prove(index, merkle_leaf)?;

                    // Initialize the Merkle path.
                    let path =
                        KaryMerklePath::<Circuit, $ph<Circuit>, $depth, $arity>::new(Mode::$mode, merkle_path.clone());

                    assert_eq!(merkle_path, path.eject_value());
                    // Initialize the Merkle root.
                    let root = Field::new(Mode::$mode, *merkle_tree.root());
                    // Initialize the Merkle leaf.
                    let leaf: Vec<_> = Inject::new(Mode::$mode, merkle_leaf.clone());

                    Circuit::scope(format!("Verify {}", Mode::$mode), || {
                        let candidate = path.verify(&circuit_leaf_hasher, &circuit_path_hasher, &root, &leaf);
                        assert!(candidate.eject_value());
                        assert_scope!($num_constants, $num_public, $num_private, $num_constraints);
                    });
                    Circuit::reset();

                    // Initialize an incorrect Merkle root.
                    let incorrect_root = root.clone() + Field::one();

                    Circuit::scope(format!("Verify (Incorrect Root) {}", Mode::$mode), || {
                        let candidate = path.verify(&circuit_leaf_hasher, &circuit_path_hasher, &incorrect_root, &leaf);
                        assert!(!candidate.eject_value());
                        assert_scope!($num_constants, $num_public, $num_private, $num_constraints);
                    });
                    Circuit::reset();

                    // Initialize an incorrect Merkle leaf.
                    let mut incorrect_leaf = leaf.clone();
                    let mut incorrect_value = Uniform::rand(&mut rng);
                    while incorrect_value == incorrect_leaf[0].eject_value() {
                        incorrect_value = Uniform::rand(&mut rng);
                    }
                    incorrect_leaf[0] = Inject::new(Mode::$mode, incorrect_value);

                    Circuit::scope(format!("Verify (Incorrect Leaf) {}", Mode::$mode), || {
                        let candidate = path.verify(&circuit_leaf_hasher, &circuit_path_hasher, &root, &incorrect_leaf);
                        assert!(!candidate.eject_value());
                        assert_scope!($num_constants, $num_public, $num_private, $num_constraints);
                    });
                    Circuit::reset();
                }
            }
            Ok(())
        }};
    }

    macro_rules! check_verify_keccak {
        ($lh:ident, $ph:ident, $mode:ident, $depth:expr, $arity:expr, $num_inputs:expr, ($num_constants:expr, $num_public:expr, $num_private:expr, $num_constraints:expr)) => {{
            // Initialize the leaf hasher.
            let native_leaf_hasher = snarkvm_console_algorithms::$lh::default();
            let circuit_leaf_hasher = $lh::<Circuit>::new();

            let mut rng = TestRng::default();

            // Initialize the path hasher.
            let native_path_hasher = snarkvm_console_algorithms::$ph::default();
            let circuit_path_hasher = $ph::<Circuit>::new();

            for i in 0..ITERATIONS {
                // Determine the number of leaves.
                let num_leaves = core::cmp::min(($arity as u128).pow($depth as u32), i);
                // Compute the leaves.
                let leaves = (0..num_leaves)
                    .map(|_| (0..$num_inputs).map(|_| Uniform::rand(&mut rng)).collect::<Vec<_>>())
                    .collect::<Vec<_>>();
                // Compute the Merkle tree.
                let merkle_tree = console::kary_merkle_tree::KaryMerkleTree::<_, _, $depth, $arity>::new(
                    &native_leaf_hasher,
                    &native_path_hasher,
                    &leaves,
                )?;

                for (index, merkle_leaf) in leaves.iter().enumerate() {
                    // Compute the Merkle path.
                    let merkle_path = merkle_tree.prove(index, merkle_leaf)?;

                    // Initialize the Merkle path.
                    let path =
                        KaryMerklePath::<Circuit, $ph<Circuit>, $depth, $arity>::new(Mode::$mode, merkle_path.clone());

                    assert_eq!(merkle_path, path.eject_value());
                    // Initialize the Merkle root.
                    let root = <$ph<Circuit> as PathHash<Circuit>>::Hash::new(Mode::$mode, *merkle_tree.root());
                    // Initialize the Merkle leaf.
                    let leaf: Vec<_> = Inject::new(Mode::$mode, merkle_leaf.clone());

                    Circuit::scope(format!("Verify {}", Mode::$mode), || {
                        let candidate = path.verify(&circuit_leaf_hasher, &circuit_path_hasher, &root, &leaf);
                        assert!(candidate.eject_value());
                        assert_scope!($num_constants, $num_public, $num_private, $num_constraints);
                    });
                    Circuit::reset();

                    // Initialize an incorrect Merkle root.
                    let incorrect_root =
                        <$ph<Circuit> as PathHash<Circuit>>::Hash::new(Mode::$mode, Default::default());

                    Circuit::scope(format!("Verify (Incorrect Root) {}", Mode::$mode), || {
                        let candidate = path.verify(&circuit_leaf_hasher, &circuit_path_hasher, &incorrect_root, &leaf);
                        assert!(!candidate.eject_value());
                        assert_scope!($num_constants, $num_public, $num_private, $num_constraints);
                    });
                    Circuit::reset();

                    // Initialize an incorrect Merkle leaf.
                    let mut incorrect_leaf = leaf.clone();
                    let mut incorrect_value = Uniform::rand(&mut rng);
                    while incorrect_value == incorrect_leaf[0].eject_value() {
                        incorrect_value = Uniform::rand(&mut rng);
                    }
                    incorrect_leaf[0] = Inject::new(Mode::$mode, incorrect_value);

                    Circuit::scope(format!("Verify (Incorrect Leaf) {}", Mode::$mode), || {
                        let candidate = path.verify(&circuit_leaf_hasher, &circuit_path_hasher, &root, &incorrect_leaf);
                        assert!(!candidate.eject_value());
                        assert_scope!($num_constants, $num_public, $num_private, $num_constraints);
                    });
                    Circuit::reset();
                }
            }
            Ok(())
        }};
    }

    #[test]
    fn test_verify_bhp512_constant() -> Result<()> {
        check_verify!(BHP1024, BHP512, Constant, 10, 4, 1024, (39234, 0, 0, 0))
    }

    #[test]
    fn test_verify_bhp512_public() -> Result<()> {
        check_verify!(BHP1024, BHP512, Public, 10, 4, 1024, (9465, 0, 53876, 54056))
    }

    #[test]
    fn test_verify_bhp512_private() -> Result<()> {
        check_verify!(BHP1024, BHP512, Private, 10, 4, 1024, (9465, 0, 53876, 54056))
    }

    #[test]
    fn test_verify_poseidon2_constant() -> Result<()> {
        check_verify!(Poseidon4, Poseidon2, Constant, 10, 4, 4, (3584, 0, 0, 0))
    }

    #[test]
    fn test_verify_poseidon2_public() -> Result<()> {
        check_verify!(Poseidon4, Poseidon2, Public, 10, 4, 4, (4843, 0, 14152, 14232))
    }

    #[test]
    fn test_verify_poseidon2_private() -> Result<()> {
        check_verify!(Poseidon4, Poseidon2, Private, 10, 4, 4, (4843, 0, 14152, 14232))
    }

    #[test]
    fn test_verify_keccak256_constant() -> Result<()> {
        check_verify_keccak!(Keccak256, Keccak256, Constant, 10, 4, 256, (6388, 0, 0, 0))
    }

    #[test]
    fn test_verify_keccak256_public() -> Result<()> {
        check_verify_keccak!(Keccak256, Keccak256, Public, 10, 4, 256, (7648, 0, 1696439, 1696519))
    }

    #[test]
    fn test_verify_keccak256_private() -> Result<()> {
        check_verify_keccak!(Keccak256, Keccak256, Private, 10, 4, 256, (7648, 0, 1696439, 1696519))
    }

    #[test]
    fn test_verify_sha3_256_constant() -> Result<()> {
        check_verify_keccak!(Sha3_256, Sha3_256, Constant, 10, 4, 256, (6388, 0, 0, 0))
    }

    #[test]
    fn test_verify_sha3_256_public() -> Result<()> {
        check_verify_keccak!(Sha3_256, Sha3_256, Public, 10, 4, 256, (7648, 0, 1696439, 1696519))
    }

    #[test]
    fn test_verify_sha3_256_private() -> Result<()> {
        check_verify_keccak!(Sha3_256, Sha3_256, Private, 10, 4, 256, (7648, 0, 1696439, 1696519))
    }
}
