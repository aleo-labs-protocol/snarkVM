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

use std::borrow::Cow;

impl<E: Environment, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> HashUncompressed
    for BHPHasher<E, NUM_WINDOWS, WINDOW_SIZE>
{
    type Input = bool;
    type Output = Group<E>;

    /// Returns the BHP hash of the given input as an affine group element.
    ///
    /// This uncompressed variant of the BHP hash function is provided to support
    /// the BHP commitment scheme, as it is typically not used by applications.
    fn hash_uncompressed(&self, input: &[Self::Input]) -> Result<Self::Output> {
        // Ensure the input size is at least the window size.
        ensure!(
            input.len() > Self::MIN_BITS,
            "Inputs to this BHP must be greater than {} bits (window size: {WINDOW_SIZE}, num windows: {NUM_WINDOWS}), actual bits: {}",
            Self::MIN_BITS,
            input.len()
        );
        // Ensure the input size is within the parameter size,
        ensure!(
            input.len() <= Self::MAX_BITS,
            "Inputs to this BHP cannot exceed {} bits, found {}",
            Self::MAX_BITS,
            input.len()
        );

        // Pad the input to a multiple of `BHP_CHUNK_SIZE` for hashing.
        let input = if input.len() % BHP_CHUNK_SIZE != 0 {
            let padding = BHP_CHUNK_SIZE - (input.len() % BHP_CHUNK_SIZE);
            let mut padded_input = vec![false; input.len() + padding];
            padded_input[..input.len()].copy_from_slice(input);
            ensure!(padded_input.len().is_multiple_of(BHP_CHUNK_SIZE), "Input must be a multiple of {BHP_CHUNK_SIZE}");
            Cow::Owned(padded_input)
        } else {
            Cow::Borrowed(input)
        };

        // Compute sum of h_i^{sum of (1-2*c_{i,j,2})*(1+c_{i,j,0}+2*c_{i,j,1})*2^{4*(j-1)} for all j in segment}
        // for all i (described in section 5.4.1.7 in the Zcash protocol specification) in batched form: the summand
        // resulting from each group of BHP_NUM_COMBINED_CHUNKS = 4 bit triplets (c_{i,j,0}, c_{i,j,1}, c_{i,j,2})
        // has already been precomputed in `combined_bases_lookup`.
        let sum = input
            .chunks(WINDOW_SIZE as usize * BHP_CHUNK_SIZE)
            .zip(self.combined_bases_lookup.iter())
            .zip(self.bases_lookup.iter())
            .flat_map(|((window_bits, combined_bases), bases)| {
                // The number of full BHP_CHUNK_SIZE-bit chunks in the window.
                // The preprocessed points corresponding to these will be looked
                // up in combined_bases.
                let num_combined_bases = window_bits.len() / (BHP_CHUNK_SIZE * BHP_NUM_COMBINED_CHUNKS);
                // The number of bits in the window belonging to full chunks.
                let num_combined_bits = num_combined_bases * BHP_CHUNK_SIZE * BHP_NUM_COMBINED_CHUNKS;

                let combined = window_bits[..num_combined_bits]
                    .chunks_exact(BHP_CHUNK_SIZE * BHP_NUM_COMBINED_CHUNKS)
                    .zip(combined_bases)
                    .map(|(combined_chunks_bits, combined_base)| {
                        // Reconstruct the index as the integer represented by the bits of the combined chunks
                        // in a suitable order.
                        let index = combined_chunks_bits.chunks_exact(BHP_CHUNK_SIZE).fold(0, |idx, chunk_bits| {
                            (idx << BHP_CHUNK_SIZE)
                                | (chunk_bits[0] as usize)
                                | (chunk_bits[1] as usize) << 1
                                | (chunk_bits[2] as usize) << 2
                        });

                        combined_base[index]
                    });

                // Trailing bits outside the last BHP_NUM_COMBINED_CHUNKS-chunk
                // result in lookups `bases` table.
                let base_offset = num_combined_bases * BHP_NUM_COMBINED_CHUNKS;
                let trailing = &window_bits[num_combined_bits..];
                let remainder =
                    trailing.chunks_exact(BHP_CHUNK_SIZE).enumerate().map(move |(triplet_index, chunk_bits)| {
                        let idx =
                            (chunk_bits[0] as usize) | (chunk_bits[1] as usize) << 1 | (chunk_bits[2] as usize) << 2;
                        bases[base_offset + triplet_index][idx]
                    });

                combined.chain(remainder)
            })
            .sum();

        Ok(sum)
    }
}
