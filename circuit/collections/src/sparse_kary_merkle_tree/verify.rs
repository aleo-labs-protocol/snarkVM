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

impl<E: Environment, PH: PathHash<E>, const DEPTH: u8, const ARITY: u8> SparseKaryMerklePath<E, PH, DEPTH, ARITY> {
    /// Returns `true` if the Merkle path is valid for the given root, key, and leaf.
    /// This is designed to be R1CS-efficient by minimizing the number of constraints.
    pub fn verify<KH: KeyHash<E, Hash = Field<E>>, LH: LeafHash<Hash = PH::Hash>>(
        &self,
        key_hasher: &KH,
        leaf_hasher: &LH,
        path_hasher: &PH,
        root: &PH::Hash,
        key: &KH::Key,
        leaf: &LH::Leaf,
    ) -> Boolean<E> {
        // Hash the key.
        let key_hash = key_hasher.hash_key(key);

        // Ensure the key hash matches the one in the path.
        // This is critical for collision resistance.
        let key_matches = self.key_hash.is_equal(&key_hash);

        // Ensure the Merkle path has the correct arity and depth.
        for sibling in &self.siblings {
            if sibling.len() != ARITY.saturating_sub(1) as usize {
                return E::halt("Merkle path is not the correct arity");
            }
        }
        if self.siblings.len() != DEPTH as usize {
            return E::halt("Merkle path is not the correct depth");
        }

        // Initialize a tracker for the current hash, by computing the leaf hash to start.
        let mut current_hash = leaf_hasher.hash_leaf(leaf);

        // Compute the arity as a constant.
        let arity = U64::<E>::new(Mode::Constant, console::U64::new(ARITY as u64));

        // Compute the number of bits needed per level to represent the arity.
        let bits_per_level = ARITY.next_power_of_two().trailing_zeros() as usize;

        // Get the key hash as bits.
        let mut key_bits = Vec::with_capacity(256);
        self.key_hash.write_bits_le(&mut key_bits);

        // Compute the indicator indices from the key hash bits.
        // This determines which position the current hash should be in at each level.
        let indicator_indexes = (0..DEPTH).map(|depth| {
            let start_bit = (depth as usize) * bits_per_level;
            let end_bit = std::cmp::min(start_bit + bits_per_level, key_bits.len());

            // Convert bits to index using bit decomposition.
            let mut index = U64::<E>::zero();
            for (i, bit) in key_bits[start_bit..end_bit].iter().enumerate() {
                // index = index + bit * 2^i
                let power_of_two = U64::<E>::new(Mode::Constant, console::U64::new(1u64 << i));
                let bit_value = U64::<E>::ternary(bit, &power_of_two, &U64::<E>::zero());
                index = &index + &bit_value;
            }

            // Take modulo arity to ensure the index is within bounds.
            &index % &arity
        });

        // Initialize the zero index.
        let zero_index = U64::<E>::zero();
        // Initialize the last index.
        let last_index = U64::<E>::new(Mode::Constant, console::U64::new(ARITY.saturating_sub(1) as u64));

        // Check levels between leaf level and root.
        // This is the most R1CS-intensive part, so we optimize carefully.
        // Iterate from leaf to root (reverse order).
        for (indicator_index, sibling_hashes) in indicator_indexes.rev().zip_eq(self.siblings.iter().rev()) {
            // Assemble the children based on the indicator index using ternary operations.
            // We need to construct a vector of ARITY children where:
            // - At position `indicator_index`, we place `current_hash`
            // - At all other positions, we place the corresponding sibling
            let mut children = Vec::with_capacity(ARITY as usize);

            // Add the first child.
            // If indicator_index == 0, use current_hash; otherwise, use sibling_hashes[0].
            let first_child =
                PH::Hash::ternary(&indicator_index.is_equal(&zero_index), &current_hash, &sibling_hashes[0]);
            children.push(first_child);

            // Calculate the middle children.
            // For each position i in [1, ARITY-2], we need to determine:
            // - If i < indicator_index: use sibling_hashes[i]
            // - If i == indicator_index: use current_hash
            // - If i > indicator_index: use sibling_hashes[i-1]
            for i in 1..(ARITY as usize - 1) {
                let index = U64::<E>::new(Mode::Constant, console::U64::new(i as u64));

                // When the index is less than the indicator index, use sibling_hashes[i].
                // When the index is greater, use sibling_hashes[i-1] (shifted).
                let option_a = PH::Hash::ternary(
                    &index.is_less_than(&indicator_index),
                    &sibling_hashes[i],
                    &sibling_hashes[i - 1],
                );

                // When the index equals the indicator index, use the current hash.
                let option_b = PH::Hash::ternary(&index.is_equal(&indicator_index), &current_hash, &option_a);

                children.push(option_b);
            }

            // Add the last child.
            // If indicator_index == ARITY-1, use current_hash; otherwise, use the last sibling.
            let last_child = PH::Hash::ternary(
                &indicator_index.is_equal(&last_index),
                &current_hash,
                sibling_hashes.last().unwrap(),
            );
            children.push(last_child);

            // Update the current hash for the next level by hashing all children.
            current_hash = path_hasher.hash_children(&children);
        }

        // The final check: key matches AND computed root equals expected root.
        key_matches & current_hash.is_equal(root)
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
    const DOMAIN: &str = "SparseTreeCircuit0";

    macro_rules! check_verify {
        ($kh:ident, $lh:ident, $ph:ident, $mode:ident, $depth:expr, $arity:expr, ($num_constants:expr, $num_public:expr, $num_private:expr, $num_constraints:expr)) => {{
            // Initialize the key hasher.
            let native_key_hasher = console::algorithms::$kh::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
            let circuit_key_hasher = $kh::<Circuit>::constant(native_key_hasher.clone());

            // Initialize the leaf hasher.
            let native_leaf_hasher = console::algorithms::$lh::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
            let circuit_leaf_hasher = $lh::<Circuit>::constant(native_leaf_hasher.clone());

            // Initialize the path hasher.
            let native_path_hasher = console::algorithms::$ph::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
            let circuit_path_hasher = $ph::<Circuit>::constant(native_path_hasher.clone());

            let mut rng = TestRng::default();

            for i in 0..ITERATIONS {
                // Set the number of key-value pairs.
                let num_pairs = i + 1;

                // Generate random keys (field elements).
                let keys = (0..num_pairs).map(|_| Uniform::rand(&mut rng)).collect::<Vec<_>>();

                // Generate random leaves.
                let leaves = (0..num_pairs).map(|_| vec![Uniform::rand(&mut rng)]).collect::<Vec<_>>();

                // Compute the sparse Merkle tree.
                let mut merkle_tree = console::sparse_kary_merkle_tree::SparseKaryMerkleTree::<
                    _,
                    _,
                    _,
                    <Circuit as Environment>::Network,
                    $depth,
                    $arity,
                >::new(&native_key_hasher, &native_leaf_hasher, &native_path_hasher)?;

                // Insert key-value pairs.
                for (key, leaf) in keys.iter().zip_eq(leaves.iter()) {
                    merkle_tree.update(key, leaf)?;
                }

                // Verify each key-value pair.
                for (key, merkle_leaf) in keys.iter().zip_eq(leaves.iter()) {
                    // Compute the Merkle path.
                    let merkle_path = merkle_tree.prove(key, merkle_leaf)?;
                    // Initialize the Merkle path.
                    let path = SparseKaryMerklePath::<Circuit, $ph<Circuit>, $depth, $arity>::new(
                        Mode::$mode,
                        merkle_path.clone(),
                    );
                    assert_eq!(merkle_path, path.eject_value());

                    // Initialize the Merkle root.
                    let root = Field::new(Mode::$mode, *merkle_tree.root());
                    // Initialize the key.
                    let circuit_key = Field::new(Mode::$mode, *key);
                    // Initialize the Merkle leaf.
                    let leaf: Vec<_> = Inject::new(Mode::$mode, merkle_leaf.clone());

                    Circuit::scope(format!("Verify {}", Mode::$mode), || {
                        let candidate = path.verify(
                            &circuit_key_hasher,
                            &circuit_leaf_hasher,
                            &circuit_path_hasher,
                            &root,
                            &circuit_key,
                            &leaf,
                        );
                        assert!(candidate.eject_value());
                        assert_scope!($num_constants, $num_public, $num_private, $num_constraints);
                    });
                    Circuit::reset();

                    // Initialize an incorrect Merkle root.
                    let incorrect_root = root.clone() + Field::one();

                    Circuit::scope(format!("Verify (Incorrect Root) {}", Mode::$mode), || {
                        let candidate = path.verify(
                            &circuit_key_hasher,
                            &circuit_leaf_hasher,
                            &circuit_path_hasher,
                            &incorrect_root,
                            &circuit_key,
                            &leaf,
                        );
                        assert!(!candidate.eject_value());
                    });
                    Circuit::reset();

                    // Initialize an incorrect key.
                    let mut incorrect_key_value = Uniform::rand(&mut rng);
                    while incorrect_key_value == *key {
                        incorrect_key_value = Uniform::rand(&mut rng);
                    }
                    let incorrect_key = Field::new(Mode::$mode, incorrect_key_value);

                    Circuit::scope(format!("Verify (Incorrect Key) {}", Mode::$mode), || {
                        let candidate = path.verify(
                            &circuit_key_hasher,
                            &circuit_leaf_hasher,
                            &circuit_path_hasher,
                            &root,
                            &incorrect_key,
                            &leaf,
                        );
                        assert!(!candidate.eject_value());
                    });
                    Circuit::reset();
                }
            }
            Ok(())
        }};
        ($kh:ident, $lh:ident, $ph:ident, $mode:ident, $depth:expr, $arity:expr, $num_key_bits:expr, $num_input_bits:expr, ($num_constants:expr, $num_public:expr, $num_private:expr, $num_constraints:expr)) => {{
            // Initialize the key hasher.
            let native_key_hasher = console::algorithms::$kh::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
            let circuit_key_hasher = $kh::<Circuit>::constant(native_key_hasher.clone());

            // Initialize the leaf hasher.
            let native_leaf_hasher = console::algorithms::$lh::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
            let circuit_leaf_hasher = $lh::<Circuit>::constant(native_leaf_hasher.clone());

            // Initialize the path hasher.
            let native_path_hasher = console::algorithms::$ph::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
            let circuit_path_hasher = $ph::<Circuit>::constant(native_path_hasher.clone());

            let mut rng = TestRng::default();

            for i in 0..ITERATIONS {
                // Set the number of key-value pairs.
                let num_pairs = i + 1;

                // Generate random keys.
                let keys = (0..num_pairs)
                    .map(|_| (0..$num_key_bits).map(|_| Uniform::rand(&mut rng)).collect::<Vec<_>>())
                    .collect::<Vec<_>>();

                // Generate random leaves.
                let leaves = (0..num_pairs)
                    .map(|_| (0..$num_input_bits).map(|_| Uniform::rand(&mut rng)).collect::<Vec<_>>())
                    .collect::<Vec<_>>();

                // Compute the sparse Merkle tree.
                let mut merkle_tree = console::sparse_kary_merkle_tree::SparseKaryMerkleTree::<
                    _,
                    _,
                    _,
                    <Circuit as Environment>::Network,
                    $depth,
                    $arity,
                >::new(&native_key_hasher, &native_leaf_hasher, &native_path_hasher)?;

                // Insert key-value pairs.
                for (key, leaf) in keys.iter().zip_eq(leaves.iter()) {
                    merkle_tree.update(key, leaf)?;
                }

                // Verify each key-value pair.
                for (key, merkle_leaf) in keys.iter().zip_eq(leaves.iter()) {
                    // Compute the Merkle path.
                    let merkle_path = merkle_tree.prove(key, merkle_leaf)?;
                    // Initialize the Merkle path.
                    let path = SparseKaryMerklePath::<Circuit, $ph<Circuit>, $depth, $arity>::new(
                        Mode::$mode,
                        merkle_path.clone(),
                    );
                    assert_eq!(merkle_path, path.eject_value());

                    // Initialize the Merkle root.
                    let root = Field::new(Mode::$mode, *merkle_tree.root());
                    // Initialize the key.
                    let circuit_key = Inject::new(Mode::$mode, key.clone());
                    // Initialize the Merkle leaf.
                    let leaf: Vec<_> = Inject::new(Mode::$mode, merkle_leaf.clone());

                    Circuit::scope(format!("Verify {}", Mode::$mode), || {
                        let candidate = path.verify(
                            &circuit_key_hasher,
                            &circuit_leaf_hasher,
                            &circuit_path_hasher,
                            &root,
                            &circuit_key,
                            &leaf,
                        );
                        assert!(candidate.eject_value());
                        assert_scope!($num_constants, $num_public, $num_private, $num_constraints);
                    });
                    Circuit::reset();

                    // Initialize an incorrect Merkle root.
                    let incorrect_root = root.clone() + Field::one();

                    Circuit::scope(format!("Verify (Incorrect Root) {}", Mode::$mode), || {
                        let candidate = path.verify(
                            &circuit_key_hasher,
                            &circuit_leaf_hasher,
                            &circuit_path_hasher,
                            &incorrect_root,
                            &circuit_key,
                            &leaf,
                        );
                        assert!(!candidate.eject_value());
                    });
                    Circuit::reset();

                    // Initialize an incorrect key.
                    let incorrect_key_value = (0..$num_key_bits).map(|_| Uniform::rand(&mut rng)).collect::<Vec<_>>();
                    ensure!(incorrect_key_value != *key, "Incorrect key should differ from the original key");
                    let incorrect_key = Inject::new(Mode::$mode, incorrect_key_value);

                    Circuit::scope(format!("Verify (Incorrect Key) {}", Mode::$mode), || {
                        let candidate = path.verify(
                            &circuit_key_hasher,
                            &circuit_leaf_hasher,
                            &circuit_path_hasher,
                            &root,
                            &incorrect_key,
                            &leaf,
                        );
                        assert!(!candidate.eject_value());
                    });
                    Circuit::reset();
                }
            }
            Ok(())
        }};
        ($kh:ident, $lh:ident, $ph:ident, $mode:ident, $depth:expr, $arity:expr, $num_input_bits:expr, ($num_constants:expr, $num_public:expr, $num_private:expr, $num_constraints:expr)) => {{
            // Initialize the key hasher.
            let native_key_hasher = console::algorithms::$kh::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
            let circuit_key_hasher = $kh::<Circuit>::constant(native_key_hasher.clone());

            // Initialize the leaf hasher.
            let native_leaf_hasher = console::algorithms::$lh::default();
            let circuit_leaf_hasher = $lh::new();

            // Initialize the path hasher.
            let native_path_hasher = console::algorithms::$ph::default();
            let circuit_path_hasher = $ph::new();

            let mut rng = TestRng::default();

            for i in 0..ITERATIONS {
                // Set the number of key-value pairs.
                let num_pairs = i + 1;

                // Generate random keys (field elements).
                let keys = (0..num_pairs).map(|_| Uniform::rand(&mut rng)).collect::<Vec<_>>();

                // Generate random leaves.
                let leaves = (0..num_pairs)
                    .map(|_| (0..$num_input_bits).map(|_| Uniform::rand(&mut rng)).collect::<Vec<_>>())
                    .collect::<Vec<_>>();

                // Compute the sparse Merkle tree.
                let mut merkle_tree = console::sparse_kary_merkle_tree::SparseKaryMerkleTree::<
                    _,
                    _,
                    _,
                    <Circuit as Environment>::Network,
                    $depth,
                    $arity,
                >::new(&native_key_hasher, &native_leaf_hasher, &native_path_hasher)?;

                // Insert key-value pairs.
                for (key, leaf) in keys.iter().zip_eq(leaves.iter()) {
                    merkle_tree.update(key, leaf)?;
                }

                // Verify each key-value pair.
                for (key, merkle_leaf) in keys.iter().zip_eq(leaves.iter()) {
                    // Compute the Merkle path.
                    let merkle_path = merkle_tree.prove(key, merkle_leaf)?;
                    // Initialize the Merkle path.
                    let path = SparseKaryMerklePath::<Circuit, $ph<Circuit>, $depth, $arity>::new(
                        Mode::$mode,
                        merkle_path.clone(),
                    );
                    assert_eq!(merkle_path, path.eject_value());

                    // Initialize the Merkle root.
                    let root = Inject::new(Mode::$mode, *merkle_tree.root());
                    // Initialize the key.
                    let circuit_key = Inject::new(Mode::$mode, key.clone());
                    // Initialize the Merkle leaf.
                    let leaf: Vec<_> = Inject::new(Mode::$mode, merkle_leaf.clone());

                    Circuit::scope(format!("Verify {}", Mode::$mode), || {
                        let candidate = path.verify(
                            &circuit_key_hasher,
                            &circuit_leaf_hasher,
                            &circuit_path_hasher,
                            &root,
                            &circuit_key,
                            &leaf,
                        );
                        assert!(candidate.eject_value());
                        assert_scope!($num_constants, $num_public, $num_private, $num_constraints);
                    });
                    Circuit::reset();

                    // Initialize an incorrect Merkle root.
                    let incorrect_root = Default::default();

                    Circuit::scope(format!("Verify (Incorrect Root) {}", Mode::$mode), || {
                        let candidate = path.verify(
                            &circuit_key_hasher,
                            &circuit_leaf_hasher,
                            &circuit_path_hasher,
                            &incorrect_root,
                            &circuit_key,
                            &leaf,
                        );
                        assert!(!candidate.eject_value());
                    });
                    Circuit::reset();

                    // Initialize an incorrect key.
                    let mut incorrect_key_value = Uniform::rand(&mut rng);
                    while incorrect_key_value == *key {
                        incorrect_key_value = Uniform::rand(&mut rng);
                    }
                    let incorrect_key = Field::new(Mode::$mode, incorrect_key_value);

                    Circuit::scope(format!("Verify (Incorrect Key) {}", Mode::$mode), || {
                        let candidate = path.verify(
                            &circuit_key_hasher,
                            &circuit_leaf_hasher,
                            &circuit_path_hasher,
                            &root,
                            &incorrect_key,
                            &leaf,
                        );
                        assert!(!candidate.eject_value());
                    });
                    Circuit::reset();
                }
            }
            Ok(())
        }};
    }

    #[test]
    fn test_verify_poseidon2_constant() -> Result<()> {
        check_verify!(Poseidon2, Poseidon2, Poseidon2, Constant, 8, 4, (5593, 0, 0, 0))
    }

    #[test]
    fn test_verify_poseidon2_public() -> Result<()> {
        check_verify!(Poseidon2, Poseidon2, Poseidon2, Public, 8, 4, (5322, 0, 11280, 11338))
    }

    #[test]
    fn test_verify_poseidon2_private() -> Result<()> {
        check_verify!(Poseidon2, Poseidon2, Poseidon2, Private, 8, 4, (5322, 0, 11280, 11338))
    }

    #[test]
    fn test_verify_bhp512_constant() -> Result<()> {
        check_verify!(BHP1024, BHP1024, BHP512, Constant, 8, 4, 256, 256, (34189, 0, 0, 0))
    }

    #[test]
    fn test_verify_bhp512_public() -> Result<()> {
        check_verify!(BHP1024, BHP1024, BHP512, Public, 8, 4, 256, 256, (9498, 0, 42582, 42720))
    }

    #[test]
    fn test_verify_bhp512_private() -> Result<()> {
        check_verify!(BHP1024, BHP1024, BHP512, Private, 8, 4, 256, 256, (9498, 0, 42582, 42720))
    }

    #[test]
    fn test_verify_keccak256_constant() -> Result<()> {
        check_verify!(Poseidon2, Keccak256, Keccak256, Constant, 6, 4, 256, (6091, 0, 0, 0))
    }

    #[test]
    fn test_verify_keccak256_public() -> Result<()> {
        check_verify!(Poseidon2, Keccak256, Keccak256, Public, 6, 4, 256, (5825, 0, 1078790, 1078834))
    }

    #[test]
    fn test_verify_keccak256_private() -> Result<()> {
        check_verify!(Poseidon2, Keccak256, Keccak256, Private, 6, 4, 256, (5825, 0, 1078790, 1078834))
    }

    #[test]
    fn test_verify_sha3_256_constant() -> Result<()> {
        check_verify!(Poseidon2, Sha3_256, Sha3_256, Constant, 6, 4, 256, (6091, 0, 0, 0))
    }

    #[test]
    fn test_verify_sha3_256_public() -> Result<()> {
        check_verify!(Poseidon2, Sha3_256, Sha3_256, Public, 6, 4, 256, (5825, 0, 1078790, 1078834))
    }

    #[test]
    fn test_verify_sha3_256_private() -> Result<()> {
        check_verify!(Poseidon2, Sha3_256, Sha3_256, Private, 6, 4, 256, (5825, 0, 1078790, 1078834))
    }

    #[test]
    fn test_verify_poseidon2_works() -> Result<()> {
        let mut rng = TestRng::default();

        let native_key_hasher = console::algorithms::Poseidon2::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
        let circuit_key_hasher = Poseidon2::<Circuit>::constant(native_key_hasher.clone());

        let native_leaf_hasher = console::algorithms::Poseidon4::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
        let circuit_leaf_hasher = Poseidon4::<Circuit>::constant(native_leaf_hasher.clone());

        let native_path_hasher = console::algorithms::Poseidon2::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
        let circuit_path_hasher = Poseidon2::<Circuit>::constant(native_path_hasher.clone());

        // Test with a single key-value pair
        let key = Uniform::rand(&mut rng);
        let leaf = vec![Uniform::rand(&mut rng)];

        let mut merkle_tree = console::sparse_kary_merkle_tree::SparseKaryMerkleTree::<
            _,
            _,
            _,
            <Circuit as Environment>::Network,
            16,
            4,
        >::new(&native_key_hasher, &native_leaf_hasher, &native_path_hasher)?;

        merkle_tree.update(&key, &leaf)?;
        let merkle_path = merkle_tree.prove(&key, &leaf)?;
        assert!(merkle_path.verify(
            &native_key_hasher,
            &native_leaf_hasher,
            &native_path_hasher,
            merkle_tree.root(),
            &key,
            &leaf
        ));

        let path = SparseKaryMerklePath::<Circuit, Poseidon2<Circuit>, 16, 4>::new(Mode::Private, merkle_path.clone());
        let root = Field::new(Mode::Public, *merkle_tree.root());
        let circuit_key = Field::new(Mode::Private, key);
        let circuit_leaf: Vec<_> = Inject::new(Mode::Private, leaf.clone());

        Circuit::scope("Verify sparse merkle path", || {
            let candidate = path.verify(
                &circuit_key_hasher,
                &circuit_leaf_hasher,
                &circuit_path_hasher,
                &root,
                &circuit_key,
                &circuit_leaf,
            );
            assert!(candidate.eject_value(), "Verification should succeed");

            // Check that the number of constraints is reasonable.
            let count = Circuit::count();
            println!("Constraint count: {count:?}");
        });

        Ok(())
    }
}
