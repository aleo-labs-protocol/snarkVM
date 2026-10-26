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

impl<E: Environment, const DEPTH: u8> MerklePath<E, DEPTH> {
    /// Returns `true` if the Merkle path is valid for the given root and leaf.
    ///
    /// Note: The circuit only constrains the lower `DEPTH` bits of the leaf index. The check that the leaf index
    /// is less than `2^DEPTH` runs outside the circuit, so a prover can set the upper bits freely.
    /// Callers that use the leaf index beyond this verification must constrain bits `DEPTH..64` to zero.
    #[must_use = "This method returns a Boolean circuit variable which should be handled"]
    pub fn verify<LH: LeafHash<E, Hash = PH::Hash>, PH: PathHash<E, Hash = Field<E>>>(
        &self,
        leaf_hasher: &LH,
        path_hasher: &PH,
        root: &PH::Hash,
        leaf: &LH::Leaf,
    ) -> Boolean<E> {
        // Ensure the leaf index is within the tree depth.
        if (*self.leaf_index.eject_value() as u128) >= (1u128 << DEPTH) {
            E::halt("Found an out of bounds Merkle leaf index")
        }
        // Ensure the path length matches the expected depth.
        else if self.siblings.len() != DEPTH as usize {
            E::halt("Found an incorrect Merkle path length")
        }

        // Initialize a tracker for the current hash, by computing the leaf hash to start.
        let mut current_hash = leaf_hasher.hash_leaf(leaf);

        // Compute the ordering of the current hash and sibling hash on each level.
        // If the indicator bit is `true`, then the ordering is (current_hash, sibling_hash).
        // If the indicator bit is `false`, then the ordering is (sibling_hash, current_hash).
        let indicators = self.leaf_index.to_bits_le().into_iter().take(DEPTH as usize).map(|b| !b);

        // Check levels between leaf level and root.
        for (indicator, sibling_hash) in indicators.zip_eq(&self.siblings) {
            // Construct the ordering of the left & right child hash for this level.
            let left = Field::ternary(&indicator, &current_hash, sibling_hash);
            let right = Field::ternary(&indicator, sibling_hash, &current_hash);

            // Update the current hash for the next level.
            current_hash = path_hasher.hash_children(&left, &right);
        }

        // Determine whether the final hash matches the given root or not.
        root.is_equal(&current_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_algorithms::{BHP512, BHP1024, Poseidon2, Poseidon4};
    use snarkvm_circuit_types::environment::Circuit;
    use snarkvm_utilities::{TestRng, Uniform};

    use anyhow::Result;

    const ITERATIONS: u128 = 10;
    const DOMAIN: &str = "MerkleTreeCircuit0";

    macro_rules! check_verify {
        ($lh:ident, $ph:ident, $mode:ident, $depth:expr, $num_inputs:expr, ($num_constants:expr, $num_public:expr, $num_private:expr, $num_constraints:expr)) => {{
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
                let num_leaves = core::cmp::min(2u128.pow($depth as u32), i);
                // Compute the leaves.
                let leaves = (0..num_leaves)
                    .map(|_| (0..$num_inputs).map(|_| Uniform::rand(&mut rng)).collect::<Vec<_>>())
                    .collect::<Vec<_>>();
                // Compute the Merkle tree.
                let merkle_tree = console::merkle_tree::MerkleTree::<_, _, _, $depth>::new(
                    &native_leaf_hasher,
                    &native_path_hasher,
                    &leaves,
                )?;

                for (index, merkle_leaf) in leaves.iter().enumerate() {
                    // Compute the Merkle path.
                    let merkle_path = merkle_tree.prove(index, merkle_leaf)?;

                    // Initialize the Merkle path.
                    let path = MerklePath::<Circuit, $depth>::new(Mode::$mode, merkle_path.clone());
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

    #[test]
    fn test_verify_bhp512_constant() -> Result<()> {
        check_verify!(BHP1024, BHP512, Constant, 32, 1024, (52960, 0, 0, 0))
    }

    #[test]
    fn test_verify_bhp512_public() -> Result<()> {
        check_verify!(BHP1024, BHP512, Public, 32, 1024, (13501, 0, 61938, 62066))
    }

    #[test]
    fn test_verify_bhp512_private() -> Result<()> {
        check_verify!(BHP1024, BHP512, Private, 32, 1024, (13501, 0, 61938, 62066))
    }

    #[test]
    fn test_verify_poseidon2_constant() -> Result<()> {
        check_verify!(Poseidon4, Poseidon2, Constant, 32, 4, (34, 0, 0, 0))
    }

    #[test]
    fn test_verify_poseidon2_public() -> Result<()> {
        check_verify!(Poseidon4, Poseidon2, Public, 32, 4, (33, 0, 18046, 18046))
    }

    #[test]
    fn test_verify_poseidon2_private() -> Result<()> {
        check_verify!(Poseidon4, Poseidon2, Private, 32, 4, (33, 0, 18046, 18046))
    }
}
