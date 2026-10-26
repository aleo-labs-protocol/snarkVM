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
mod tests;

use crate::Blake2Xs;
use snarkvm_console_types::prelude::*;
use snarkvm_utilities::BigInteger;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The BHP chunk size (this implementation is for a 3-bit BHP).
pub(super) const BHP_CHUNK_SIZE: usize = 3;
pub(super) const BHP_LOOKUP_SIZE: usize = 1 << BHP_CHUNK_SIZE;

/// The amount of chunks (i.e. bit triplets) to preprocess together in the lookup table.
// The value 4 results in a total lookup size of ~0.13 GB and a x4 speedup in hash_uncompressed.
// Switching to 5 would increase the lookup size to an excessive ~0.8 GB lookup for a x5 speedup.
pub(super) const BHP_NUM_COMBINED_CHUNKS: usize = 4;

/// BHP is a collision-resistant hash function that takes a variable-length input.
/// The BHP hasher is used to process one internal iteration of the BHP hash function.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(bound = "E: Serialize + DeserializeOwned")]
pub struct BHPHasher<E: Environment, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> {
    /// The bases for the BHP hash.
    bases: Arc<Vec<Vec<Group<E>>>>,
    /// The bases lookup table for the BHP hash.
    bases_lookup: Arc<Vec<Vec<[Group<E>; BHP_LOOKUP_SIZE]>>>,
    /// The preprocessed combinations of elements in the bases lookup table.
    // For each group of BHP_NUM_COMBINED_CHUNKS contiguous
    // BHP_LOOKUP_SIZE-element tuples in `bases_lookup`, this contains
    // all possible BHP_LOOKUP_SIZE^BHP_NUM_COMBINED_CHUNKS cross-tuple sums.
    combined_bases_lookup: Arc<[Vec<Vec<Group<E>>>]>,
    /// The random base for the BHP commitment.
    random_base: Arc<Vec<Group<E>>>,
}

impl<E: Environment, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> BHPHasher<E, NUM_WINDOWS, WINDOW_SIZE> {
    /// The maximum number of input bits.
    const MAX_BITS: usize = NUM_WINDOWS as usize * WINDOW_SIZE as usize * BHP_CHUNK_SIZE;
    /// The minimum number of input bits (at least one window).
    const MIN_BITS: usize = WINDOW_SIZE as usize * BHP_CHUNK_SIZE;

    /// Largest absolute value of one window sum, `4 * (16^window_size - 1) / 15`.
    ///
    /// Chunk `j` contributes a coefficient in `{±1, ±2, ±3, ±4}` times `16^j`.
    /// Returns an error when that sum does not fit in `E::BigInteger`.
    fn window_sum_bound(window_size: u8) -> Result<E::BigInteger> {
        let mut place = E::BigInteger::from(1_u64);
        let mut sum = E::BigInteger::from(0_u64);
        for index in 0..u32::from(window_size) {
            let mut term = place;
            term.muln(2);
            ensure!(term > place, "BHP window sum exceeds the integer width");
            ensure!(!sum.add_nocarry(&term), "BHP window sum exceeds the integer width");
            if index + 1 < u32::from(window_size) {
                let previous = place;
                place.muln(4);
                ensure!(place > previous, "BHP window sum exceeds the integer width");
            }
        }
        Ok(sum)
    }

    /// Initializes a new instance of BHP with the given domain.
    pub fn setup(domain: &str) -> Result<Self> {
        #[cfg(feature = "dev-print")]
        let timer = std::time::Instant::now();

        // Chunk `j` contributes a coefficient in {±1, ±2, ±3, ±4} times `16^j`.
        // The absolute value of one window is at most `4 * (16^WINDOW_SIZE - 1) / 15`.
        // Incomplete Montgomery addition divides by a difference of x-coordinates.
        // The division is defined when that bound is below the group order and no base is the identity.
        let window_sum = Self::window_sum_bound(WINDOW_SIZE)?;
        ensure!(window_sum < E::Scalar::modulus(), "BHP window sum must be below the group order");

        // Compute the bases.
        let bases = (0..NUM_WINDOWS)
            .map(|index| {
                // Construct an indexed message to attempt to sample a base.
                let (generator, _, _) = Blake2Xs::hash_to_curve::<E::Affine>(&format!(
                    "Aleo.BHP.{NUM_WINDOWS}.{WINDOW_SIZE}.{domain}.{index}"
                ));
                let mut base = Group::<E>::new(generator);
                // Compute the generators for the sampled base.
                let mut powers = Vec::with_capacity(WINDOW_SIZE as usize);
                for _ in 0..WINDOW_SIZE {
                    powers.push(base);
                    for _ in 0..4 {
                        base = base.double();
                    }
                }
                powers
            })
            .collect::<Vec<Vec<Group<E>>>>();
        ensure!(bases.len() == NUM_WINDOWS as usize, "Incorrect number of BHP windows ({})", bases.len());
        for window in &bases {
            ensure!(window.len() == WINDOW_SIZE as usize, "Incorrect BHP window size ({})", window.len());
            // Hash-to-curve clears the cofactor and resamples the identity.
            // A stored identity has no Montgomery coordinates.
            for base in window {
                ensure!(!base.is_zero(), "BHP base point is the identity");
            }
        }

        // Compute the bases lookup.
        let bases_lookup = cfg_iter!(bases)
            .map(|window| {
                window
                    .iter()
                    .map(|g| {
                        let mut lookup = [Group::<E>::zero(); BHP_LOOKUP_SIZE];
                        for (i, element) in lookup.iter_mut().enumerate().take(BHP_LOOKUP_SIZE) {
                            *element = *g;
                            if (i & 0x01) != 0 {
                                *element += g;
                            }
                            if (i & 0x02) != 0 {
                                *element += g.double();
                            }
                            if (i & 0x04) != 0 {
                                *element = element.neg();
                            }
                        }
                        lookup
                    })
                    .collect()
            })
            .collect::<Vec<Vec<[Group<E>; BHP_LOOKUP_SIZE]>>>();
        ensure!(bases_lookup.len() == NUM_WINDOWS as usize, "Incorrect number of BHP lookups ({})", bases_lookup.len());
        for window in &bases_lookup {
            ensure!(window.len() == WINDOW_SIZE as usize, "Incorrect BHP lookup window size ({})", window.len());
        }

        // Compute the preprocessed sums of contiguous base-element tuples. For
        // instance, for BHP_NUM_COMBINED_CHUNKS = 2, if the first two three-bit
        // groups of the input are mapped to (P1_0, ..., P1_7) and (P2_0, ...,
        // P2_7), respectively, this code computes the vector
        // [
        //     P1_0 + P2_0, P1_0 + P2_1, ..., P1_0 + P2_7,
        //     P1_1 + P2_0, P1_1 + P2_1, ..., P1_1 + P2_7,
        //     ...,
        //     P1_7 + P2_0, P1_7 + P2_1, ..., P1_7 + P2_7
        // ]
        // corresponding to the first six bits of the input. Note that bases
        // lookup must still be kept around since the ending bits of an input
        // could end in the middle of any preprocessed combined chunk.
        let combined_bases_lookup: Arc<[Vec<Vec<Group<E>>>]> = cfg_iter!(bases_lookup)
            .map(|window| {
                window
                    .chunks_exact(BHP_NUM_COMBINED_CHUNKS)
                    .map(|chunks| {
                        chunks.iter().fold(vec![Group::<E>::zero()], |prev_sums, new_terms| {
                            prev_sums
                                .iter()
                                .flat_map(|prev_sum| new_terms.iter().map(|new_term| *prev_sum + *new_term))
                                .collect::<Vec<Group<E>>>()
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
            .into();

        // Next, compute the random base.
        let (generator, _, _) =
            Blake2Xs::hash_to_curve::<E::Affine>(&format!("Aleo.BHP.{NUM_WINDOWS}.{WINDOW_SIZE}.{domain}.Randomizer"));
        let mut base_power = Group::<E>::new(generator);
        let mut random_base = Vec::with_capacity(Scalar::<E>::size_in_bits());
        for _ in 0..Scalar::<E>::size_in_bits() {
            random_base.push(base_power);
            base_power = base_power.double();
        }
        ensure!(
            random_base.len() == Scalar::<E>::size_in_bits(),
            "Incorrect number of BHP random base powers ({})",
            random_base.len()
        );
        for base in &random_base {
            ensure!(!base.is_zero(), "BHP random base point is the identity");
        }

        #[cfg(feature = "dev-print")]
        {
            // Display the setup time and approximate hasher size.

            let elapsed = timer.elapsed().as_micros() as f64 / 1000.0;

            println!(
                " • BHP hasher setup (NUM_WINDOWS = {NUM_WINDOWS}, WINDOW_SIZE = {WINDOW_SIZE}, NUM_COMBINED_CHUNKS = {BHP_NUM_COMBINED_CHUNKS}, DOMAIN = '{domain}'): {elapsed:.2} ms"
            );

            // The number of group elements stored in the hasher is
            //    N (basis elements)
            //  + N * 8 (lookup for basis elements)
            //  + NUM_W * (W_SIZE // C) * 8^C (combined lookup for basis elements)
            //  + S (random base)
            // where
            //  - NUM_W = NUM_WINDOWS,
            //  - W_SIZE = WINDOW_SIZE,
            //  - N = number of basis elements = NUM_W * W_SIZE,
            //  - C = BHP_NUM_COMBINED_CHUNKS

            let num_els_bases: usize = bases.iter().map(|v| v.len()).sum();
            let num_els_bases_lookup: usize =
                bases_lookup.iter().map(|vs| vs.iter().map(|v| v.len()).sum::<usize>()).sum();
            let num_els_combined_bases_lookup: usize =
                combined_bases_lookup.iter().map(|vs| vs.iter().map(|v| v.len()).sum::<usize>()).sum();
            let num_els_random_base = random_base.len();

            let bytes = (num_els_bases + num_els_bases_lookup + num_els_combined_bases_lookup + num_els_random_base)
                * std::mem::size_of::<Group<E>>();

            println!("   Approximate BHP hasher size: {bytes} B");
        }

        Ok(Self {
            bases: Arc::new(bases),
            bases_lookup: Arc::new(bases_lookup),
            combined_bases_lookup,
            random_base: Arc::new(random_base),
        })
    }

    /// Returns the bases.
    pub fn bases(&self) -> &Arc<Vec<Vec<Group<E>>>> {
        &self.bases
    }

    /// Returns the random base window.
    pub fn random_base(&self) -> &Arc<Vec<Group<E>>> {
        &self.random_base
    }
}
