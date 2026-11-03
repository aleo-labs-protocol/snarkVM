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
use snarkvm_circuit_algorithms::{BHP, Hash, Poseidon};

/// A trait for a key hash function in circuits.
pub trait KeyHash<E: Environment> {
    type Hash: Clone + Default + Inject + Eject + ToBits<Boolean = Boolean<E>>;
    type Key: Clone;
    type Primitive: console::sparse_kary_merkle_tree::KeyHash;

    /// Returns the hash of the given key.
    fn hash_key(&self, key: &Self::Key) -> Self::Hash;
}

impl<E: Environment, const RATE: usize> KeyHash<E> for Poseidon<E, RATE> {
    type Hash = Field<E>;
    type Key = Field<E>;
    type Primitive = console::algorithms::Poseidon<E::Network, RATE>;

    /// Returns the hash of the given key.
    fn hash_key(&self, key: &Self::Key) -> Self::Hash {
        // Prepend the key with a `2field` element.
        let input = [Field::<E>::one() + Field::<E>::one(), key.clone()];
        // Hash the input.
        Hash::hash(self, &input)
    }
}

impl<E: Environment, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> KeyHash<E> for BHP<E, NUM_WINDOWS, WINDOW_SIZE> {
    type Hash = Field<E>;
    type Key = Vec<Boolean<E>>;
    type Primitive = console::algorithms::BHP<E::Network, NUM_WINDOWS, WINDOW_SIZE>;

    /// Returns the hash of the given key.
    fn hash_key(&self, key: &Self::Key) -> Self::Hash {
        let mut input = Vec::with_capacity(2 + key.len());
        // Prepend the key with a `true` & `false` bit.
        input.push(Boolean::constant(true));
        input.push(Boolean::constant(false));
        input.extend_from_slice(key);
        // Hash the input.
        Hash::hash(self, &input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_algorithms::{BHP1024, Poseidon2};
    use snarkvm_circuit_types::environment::Circuit;
    use snarkvm_utilities::{TestRng, Uniform};

    use anyhow::Result;

    const ITERATIONS: u64 = 10;
    const DOMAIN: &str = "SparseTreeCircuit0";

    macro_rules! check_hash_key {
        // For bit-based keys (e.g., BHP with Vec<bool>)
        ($native:ident, $circuit:ident, $mode:ident, $num_inputs:expr, ($num_constants:expr, $num_public:expr, $num_private:expr, $num_constraints:expr)) => {{
            let mut rng = TestRng::default();

            for i in 0..ITERATIONS {
                // Sample a random input.
                let input = (0..$num_inputs).map(|_| Uniform::rand(&mut rng)).collect::<Vec<_>>();

                // Compute the expected hash.
                let expected = console::sparse_kary_merkle_tree::KeyHash::hash_key(&$native, &input)?;

                // Prepare the circuit input.
                let circuit_input: Vec<_> = Inject::new(Mode::$mode, input);

                Circuit::scope(format!("KeyHash {i}"), || {
                    // Perform the hash operation.
                    let candidate = $circuit.hash_key(&circuit_input);
                    // Verify it matches console output.
                    assert_eq!(expected, candidate.eject_value());
                    // Check the number of variables and constraints.
                    assert_scope!($num_constants, $num_public, $num_private, $num_constraints);
                });
                Circuit::reset();
            }
            Ok::<_, anyhow::Error>(())
        }};
        // For field-based keys (e.g., Poseidon with Field<E>)
        ($native:ident, $circuit:ident, $mode:ident, ($num_constants:expr, $num_public:expr, $num_private:expr, $num_constraints:expr)) => {{
            let mut rng = TestRng::default();

            for i in 0..ITERATIONS {
                // Sample a random field element.
                let key = Uniform::rand(&mut rng);

                // Compute the expected hash.
                let expected = console::sparse_kary_merkle_tree::KeyHash::hash_key(&$native, &key)?;

                // Prepare the circuit input.
                let circuit_key = Field::new(Mode::$mode, key);

                Circuit::scope(format!("KeyHash {i}"), || {
                    // Perform the hash operation.
                    let candidate = $circuit.hash_key(&circuit_key);
                    // Verify it matches console output.
                    assert_eq!(expected, candidate.eject_value());
                    // Check the number of variables and constraints.
                    assert_scope!($num_constants, $num_public, $num_private, $num_constraints);
                });
                Circuit::reset();
            }
            Ok::<_, anyhow::Error>(())
        }};
    }

    #[test]
    fn test_hash_key_bhp1024_constant() -> Result<()> {
        let native = snarkvm_console_algorithms::BHP1024::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
        let circuit = BHP1024::<Circuit>::constant(native.clone());
        check_hash_key!(native, circuit, Constant, 1024, (1791, 0, 0, 0))
    }

    #[test]
    fn test_hash_key_bhp1024_public() -> Result<()> {
        let native = snarkvm_console_algorithms::BHP1024::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
        let circuit = BHP1024::<Circuit>::constant(native.clone());
        check_hash_key!(native, circuit, Public, 1024, (413, 0, 1744, 1744))
    }

    #[test]
    fn test_hash_key_bhp1024_private() -> Result<()> {
        let native = snarkvm_console_algorithms::BHP1024::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
        let circuit = BHP1024::<Circuit>::constant(native.clone());
        check_hash_key!(native, circuit, Private, 1024, (413, 0, 1744, 1744))
    }

    #[test]
    fn test_hash_key_poseidon2_constant() -> Result<()> {
        let native = snarkvm_console_algorithms::Poseidon2::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
        let circuit = Poseidon2::<Circuit>::constant(native.clone());
        check_hash_key!(native, circuit, Constant, (1, 0, 0, 0))
    }

    #[test]
    fn test_hash_key_poseidon2_public() -> Result<()> {
        let native = snarkvm_console_algorithms::Poseidon2::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
        let circuit = Poseidon2::<Circuit>::constant(native.clone());
        check_hash_key!(native, circuit, Public, (1, 0, 265, 265))
    }

    #[test]
    fn test_hash_key_poseidon2_private() -> Result<()> {
        let native = snarkvm_console_algorithms::Poseidon2::<<Circuit as Environment>::Network>::setup(DOMAIN)?;
        let circuit = Poseidon2::<Circuit>::constant(native.clone());
        check_hash_key!(native, circuit, Private, (1, 0, 265, 265))
    }
}
