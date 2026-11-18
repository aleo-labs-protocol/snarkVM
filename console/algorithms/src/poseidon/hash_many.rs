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
        // The preimage is [ DOMAIN || LENGTH(INPUT) || [0; RATE-2] || INPUT ]. Its first block depends only on the
        // domain and the input length, so for lengths below `PREFIX_STATES` the state after it is cached.
        let new_sponge = || match &self.sparse_rounds {
            Some(sparse_rounds) => PoseidonSponge::<E, RATE, CAPACITY>::with_sparse_rounds(sparse_rounds),
            None => PoseidonSponge::<E, RATE, CAPACITY>::new(&self.parameters),
        };
        let first_block_state = || new_sponge().permuted_block(&self.first_block(input.len()));
        let state = match self.prefix_states.get(input.len()) {
            Some(cell) => *cell.get_or_init(first_block_state),
            None => first_block_state(),
        };
        // After the first block, an empty input leaves only squeezing, which starts from the permuted state.
        // Any other input continues absorbing into it.
        let mode = if input.is_empty() {
            DuplexSpongeMode::Squeezing { next_squeeze_index: 0 }
        } else {
            DuplexSpongeMode::Absorbing { next_absorb_index: 0 }
        };
        let mut sponge = new_sponge().with_state(state, mode);
        sponge.absorb(input);
        sponge.squeeze(num_outputs).into_vec()
    }
}
