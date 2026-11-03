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

mod hash_uncompressed;

#[cfg(test)]
use snarkvm_circuit_types::environment::assert_scope;

use crate::HashUncompressed;
use snarkvm_circuit_types::prelude::*;

/// The BHP chunk size (this implementation is for a 3-bit BHP).
const BHP_CHUNK_SIZE: usize = 3;

/// The x-coordinate and y-coordinate of each base on the Montgomery curve.
type BaseLookups<E> = (Vec<Field<E>>, Vec<Field<E>>);

/// BHP is a collision-resistant hash function that takes a variable-length input.
/// The BHP hasher is used to process one internal iteration of the BHP hash function.
pub struct BHPHasher<E: Environment, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> {
    /// The bases for the BHP hash.
    bases: Vec<Vec<BaseLookups<E>>>,
    /// The random base for the BHP commitment.
    random_base: Vec<Group<E>>,
}

impl<E: Environment, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> BHPHasher<E, NUM_WINDOWS, WINDOW_SIZE> {
    /// The BHP lookup size per iteration.
    const BHP_LOOKUP_SIZE: usize = 4;
    /// The maximum number of input bits.
    const MAX_BITS: usize = NUM_WINDOWS as usize * WINDOW_SIZE as usize * BHP_CHUNK_SIZE;
    /// The minimum number of input bits (at least one window).
    const MIN_BITS: usize = WINDOW_SIZE as usize * BHP_CHUNK_SIZE;

    #[cfg(test)]
    /// Returns the bases.
    pub(crate) fn bases(&self) -> &Vec<Vec<BaseLookups<E>>> {
        &self.bases
    }

    /// Returns the random base window.
    pub(crate) fn random_base(&self) -> &Vec<Group<E>> {
        &self.random_base
    }
}

impl<E: Environment, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> Inject for BHPHasher<E, NUM_WINDOWS, WINDOW_SIZE> {
    type Primitive = console::BHP<E::Network, NUM_WINDOWS, WINDOW_SIZE>;

    /// Initializes a new instance of a BHP circuit with the given BHP variant.
    fn new(_mode: Mode, bhp: Self::Primitive) -> Self {
        // Compute the bases.
        let bases = bhp
            .bases()
            .iter()
            .take(NUM_WINDOWS as usize)
            .map(|window| {
                // Construct the window with the base.
                let mut powers = Vec::with_capacity(WINDOW_SIZE as usize);
                for base in window.iter().take(WINDOW_SIZE as usize) {
                    let base =
                        if base.is_zero() { E::halt("BHP base point is the identity") } else { Group::constant(*base) };
                    let mut x_bases = Vec::with_capacity(Self::BHP_LOOKUP_SIZE);
                    let mut y_bases = Vec::with_capacity(Self::BHP_LOOKUP_SIZE);
                    let mut accumulator = base.clone();
                    for _ in 0..Self::BHP_LOOKUP_SIZE {
                        // Convert each base from twisted Edwards point into a Montgomery point.
                        let x = (Field::one() + accumulator.to_y_coordinate())
                            / (Field::one() - accumulator.to_y_coordinate());
                        let y = &x / accumulator.to_x_coordinate();

                        x_bases.push(x);
                        y_bases.push(y);
                        accumulator += &base;
                    }
                    powers.push((x_bases, y_bases));
                }
                powers
            })
            .collect::<Vec<Vec<BaseLookups<E>>>>();
        assert_eq!(bases.len(), NUM_WINDOWS as usize, "Incorrect number of BHP windows ({})", bases.len());
        bases.iter().for_each(|window| assert_eq!(window.len(), WINDOW_SIZE as usize));

        // Initialize the random base.
        let random_base = if bhp.random_base().iter().any(|base| base.is_zero()) {
            E::halt("BHP random base point is the identity")
        } else {
            Vec::constant(bhp.random_base().iter().copied().collect())
        };
        assert_eq!(random_base.len(), console::Scalar::<E::Network>::size_in_bits());

        Self { bases, random_base }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_types::environment::{Circuit, Eject};

    use anyhow::Result;

    const ITERATIONS: usize = 10;
    const MESSAGE: &str = "BHPCircuit0";

    #[test]
    fn test_setup_constant() -> Result<()> {
        for _ in 0..ITERATIONS {
            let native = console::BHP::<<Circuit as Environment>::Network, 8, 32>::setup(MESSAGE)?;
            let circuit = BHPHasher::<Circuit, 8, 32>::new(Mode::Constant, native.clone());

            native.bases().iter().zip(circuit.bases.iter()).for_each(|(native_bases, circuit_bases)| {
                native_bases.iter().zip(circuit_bases).for_each(|(native_base, circuit_base_lookups)| {
                    // Check the first circuit base (when converted back to twisted Edwards) matches the native one.
                    let (circuit_x, circuit_y) = {
                        let (x_bases, y_bases) = circuit_base_lookups;
                        // Convert the Montgomery point to a twisted Edwards point.
                        let edwards_x = &x_bases[0] / &y_bases[0]; // 1 constraint
                        let edwards_y = (&x_bases[0] - Field::one()) / (&x_bases[0] + Field::one());
                        (edwards_x, edwards_y)
                    };
                    assert_eq!(native_base.to_x_coordinate(), circuit_x.eject_value());
                    assert_eq!(native_base.to_y_coordinate(), circuit_y.eject_value());
                })
            });
        }
        Ok(())
    }
}
