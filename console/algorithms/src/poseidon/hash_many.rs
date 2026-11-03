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

impl<E: Environment, const RATE: usize> HashMany for Poseidon<E, RATE> {
    type Input = Field<E>;
    type Output = Field<E>;

    /// Returns the cryptographic hash for a list of field elements as input,
    /// and returns the specified number of field elements as output.
    #[inline]
    fn hash_many(&self, input: &[Self::Input], num_outputs: u16) -> Vec<Self::Output> {
        // Construct the preimage: [ DOMAIN || LENGTH(INPUT) || [0; RATE-2] || INPUT ].
        let mut preimage = Vec::with_capacity(RATE + input.len());
        preimage.push(self.domain);
        preimage.push(Field::<E>::from_u128(input.len() as u128));
        preimage.resize(RATE, Field::<E>::zero()); // Pad up to RATE.
        preimage.extend_from_slice(input);

        let mut sponge = PoseidonSponge::<E, RATE, CAPACITY>::new(&self.rounds);
        sponge.absorb(&preimage);
        sponge.squeeze(num_outputs).into_vec()
    }
}
