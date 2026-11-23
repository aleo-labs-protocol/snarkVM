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

mod commit;
mod commit_uncompressed;
mod hash;
mod hash_uncompressed;

#[cfg(test)]
use snarkvm_circuit_types::environment::assert_scope;

use crate::{Commit, CommitUncompressed, Hash, HashUncompressed};
use snarkvm_circuit_types::prelude::*;

/// Pedersen64 is an *additively-homomorphic* collision-resistant hash function that takes up to a 64-bit input.
pub type Pedersen64<E> = Pedersen<E, 64>;
/// Pedersen128 is an *additively-homomorphic* collision-resistant hash function that takes up to a 128-bit input.
pub type Pedersen128<E> = Pedersen<E, 128>;

/// Pedersen is a collision-resistant hash function that takes a variable-length input.
/// The Pedersen hash function does *not* behave like a random oracle, see Poseidon for one.
pub struct Pedersen<E: Environment, const NUM_BITS: u8> {
    /// The base window for the Pedersen hash.
    base_window: Vec<Group<E>>,
    /// The random base window for the Pedersen commitment.
    random_base: Vec<Group<E>>,
}

impl<E: Environment, const NUM_BITS: u8> Inject for Pedersen<E, NUM_BITS> {
    type Primitive = console::Pedersen<E::Network, NUM_BITS>;

    /// Initializes a new instance of Pedersen with the given Pedersen variant.
    fn new(_mode: Mode, pedersen: Self::Primitive) -> Self {
        // Initialize the base window.
        let base_window = Vec::constant(pedersen.base_window().iter().copied().collect());
        assert_eq!(base_window.len(), NUM_BITS as usize);

        // Initialize the random base.
        let random_base = Vec::constant(pedersen.random_base_window().iter().copied().collect());
        assert_eq!(random_base.len(), E::ScalarField::size_in_bits());

        Self { base_window, random_base }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_types::environment::Circuit;

    const ITERATIONS: u64 = 10;
    const MESSAGE: &str = "PedersenCircuit0";
    const NUM_BITS_MULTIPLIER: u8 = 8;

    fn check_setup<const NUM_BITS: u8>(num_constants: u64, num_public: u64, num_private: u64, num_constraints: u64) {
        for _ in 0..ITERATIONS {
            // Initialize the native Pedersen hash.
            let native = console::Pedersen::<<Circuit as Environment>::Network, NUM_BITS>::setup(MESSAGE);

            Circuit::scope("Pedersen::setup", || {
                // Perform the setup operation.
                let circuit = Pedersen::<Circuit, NUM_BITS>::constant(native.clone());
                assert_scope!(num_constants, num_public, num_private, num_constraints);

                // Check for equivalency of the bases.
                native.base_window().iter().zip_eq(circuit.base_window.iter()).for_each(|(expected, candidate)| {
                    assert_eq!(*expected, candidate.eject_value());
                });

                // Check for equality of the random base.
                native.random_base_window().iter().zip_eq(circuit.random_base.iter()).for_each(
                    |(expected, candidate)| {
                        assert_eq!(*expected, candidate.eject_value());
                    },
                );
            });
        }
    }

    #[test]
    fn test_setup_constant() {
        // Set the number of windows, and modulate the window size.
        check_setup::<NUM_BITS_MULTIPLIER>(2590, 0, 0, 0);
        check_setup::<{ 2 * NUM_BITS_MULTIPLIER }>(2670, 0, 0, 0);
        check_setup::<{ 3 * NUM_BITS_MULTIPLIER }>(2750, 0, 0, 0);
        check_setup::<{ 4 * NUM_BITS_MULTIPLIER }>(2830, 0, 0, 0);
        check_setup::<{ 5 * NUM_BITS_MULTIPLIER }>(2910, 0, 0, 0);
    }
}
