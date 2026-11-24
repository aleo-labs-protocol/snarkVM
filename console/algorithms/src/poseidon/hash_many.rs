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

use smallvec::SmallVec;

impl<E: Environment, const RATE: usize> HashMany for Poseidon<E, RATE> {
    type Input = Field<E>;
    type Output = Field<E>;

    /// Returns the cryptographic hash for a list of field elements as input,
    /// and returns the specified number of field elements as output.
    #[inline]
    fn hash_many(&self, input: &[Self::Input], num_outputs: u16) -> Vec<Self::Output> {
        let state = self.first_block_state(input.len());
        // After the first block, an empty input leaves only squeezing, which starts from the permuted state.
        // Any other input continues absorbing into it.
        let mode = if input.is_empty() {
            DuplexSpongeMode::Squeezing { next_squeeze_index: 0 }
        } else {
            DuplexSpongeMode::Absorbing { next_absorb_index: 0 }
        };
        let mut sponge = self.new_sponge().with_state(state, mode);
        sponge.absorb(input);
        sponge.squeeze(num_outputs).into_vec()
    }
}

impl<E: Environment, const RATE: usize> Poseidon<E, RATE> {
    /// Returns a new sponge with the permutation of this instance.
    fn new_sponge(&self) -> PoseidonSponge<E, RATE, CAPACITY> {
        match &self.sparse_rounds {
            Some(sparse_rounds) => PoseidonSponge::<E, RATE, CAPACITY>::with_sparse_rounds(sparse_rounds),
            None => PoseidonSponge::<E, RATE, CAPACITY>::new(&self.parameters),
        }
    }

    /// Returns the sponge state after the first block of `hash_many`'s preimage for an input of `len` elements.
    ///
    /// The preimage is [ DOMAIN || LENGTH(INPUT) || [0; RATE-2] || INPUT ]. Its first block depends only on the
    /// domain and the input length, so for lengths below `PREFIX_STATES` the state after it is cached.
    fn first_block_state(&self, len: usize) -> State<E, RATE, CAPACITY> {
        let first_block_state = || self.new_sponge().permuted_block(&self.first_block(len));
        match self.prefix_states.get(len) {
            Some(cell) => *cell.get_or_init(first_block_state),
            None => first_block_state(),
        }
    }

    /// Returns `self.hash_many(inputs[l], num_outputs)` for each `l`.
    ///
    /// The 8 hashes run in lockstep in AVX-512 IFMA lanes where `hash_many_8_lanes` takes them, and one by one
    /// otherwise. The outputs are the same either way.
    pub fn hash_many_8(&self, inputs: [&[Field<E>]; 8], num_outputs: u16) -> [Vec<Field<E>>; 8] {
        match self.hash_many_8_lanes(inputs, num_outputs) {
            Some(outputs) => outputs,
            None => inputs.map(|input| self.hash_many(input, num_outputs)),
        }
    }

    /// Returns `self.hash(inputs[l])` for each `l`, as `hash_many_8` computes it.
    pub fn hash_8(&self, inputs: [&[Field<E>]; 8]) -> Result<[Field<E>; 8]> {
        Ok(self.hash_many_8(inputs, 1).map(|output| output[0]))
    }

    /// Returns `self.hash_to_scalar(inputs[l])` for each `l`, as `hash_many_8` computes it.
    pub fn hash_to_scalar_8(&self, inputs: [&[Field<E>]; 8]) -> Result<[Scalar<E>; 8]> {
        Ok(self.hash_8(inputs)?.map(|output| Scalar::from_field_lossy(&output)))
    }

    /// Returns `self.hash_many(inputs[l], num_outputs)` for each `l`, with every permutation after the first block
    /// applied to the 8 states at once; or `None` if the inputs differ in length, the hashes take no permutation
    /// after the first block, this instance has no sparse partial rounds, or the field's `poseidon_permute_8`
    /// declines, as it does on a CPU without AVX-512 IFMA.
    #[doc(hidden)]
    pub fn hash_many_8_lanes(&self, inputs: [&[Field<E>]; 8], num_outputs: u16) -> Option<[Vec<Field<E>>; 8]> {
        let sparse_rounds = self.sparse_rounds.as_ref()?;
        let (len, num_outputs) = (inputs[0].len(), num_outputs as usize);
        if inputs.iter().any(|input| input.len() != len) {
            return None;
        }
        // A hash permutes after each block of its input, and before each block of its output but the first.
        let input_blocks = len.div_ceil(RATE);
        if num_outputs == 0 || input_blocks + num_outputs.div_ceil(RATE) == 1 {
            return None;
        }

        // `state[j][l]` is element `j` of the sponge state of `inputs[l]`.
        let mut state: SmallVec<[[E::Field; 8]; 10]> = self.first_block_state(len).iter().map(|x| [**x; 8]).collect();
        for block in 0..input_blocks {
            let start = block * RATE;
            for (j, lanes) in state[CAPACITY..].iter_mut().enumerate().take(len - start) {
                for (x, input) in lanes.iter_mut().zip_eq(&inputs) {
                    *x += *input[start + j];
                }
            }
            E::Field::poseidon_permute_8(sparse_rounds, &mut state)?;
        }

        let mut outputs: [Vec<Field<E>>; 8] = std::array::from_fn(|_| Vec::with_capacity(num_outputs));
        loop {
            let block = RATE.min(num_outputs - outputs[0].len());
            for lanes in &state[CAPACITY..CAPACITY + block] {
                for (output, x) in outputs.iter_mut().zip_eq(lanes) {
                    output.push(Field::new(*x));
                }
            }
            if outputs[0].len() == num_outputs {
                return Some(outputs);
            }
            E::Field::poseidon_permute_8(sparse_rounds, &mut state)?;
        }
    }
}
