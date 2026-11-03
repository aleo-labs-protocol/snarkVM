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

use crate::poseidon::{
    State,
    helpers::{AlgebraicSponge, DuplexSpongeMode, PoseidonRounds, SparseMatrix},
};
use snarkvm_console_types::{Field, prelude::*};

use smallvec::SmallVec;
use std::{ops::DerefMut, sync::Arc};

/// A duplex sponge based using the Poseidon permutation.
///
/// This implementation of Poseidon is entirely from Fractal's implementation in [COS20][cos]
/// with small syntax changes.
///
/// [cos]: https://eprint.iacr.org/2019/1076
#[derive(Clone, Debug)]
pub struct PoseidonSponge<E: Environment, const RATE: usize, const CAPACITY: usize> {
    /// The rounds of the permutation.
    rounds: Arc<PoseidonRounds<E::Field>>,
    /// Current sponge's state (current elements in the permutation block)
    state: State<E, RATE, CAPACITY>,
    /// Current mode (whether its absorbing or squeezing)
    pub(in crate::poseidon) mode: DuplexSpongeMode,
}

impl<E: Environment, const RATE: usize, const CAPACITY: usize> AlgebraicSponge<E, RATE, CAPACITY>
    for PoseidonSponge<E, RATE, CAPACITY>
{
    type Parameters = Arc<PoseidonRounds<E::Field>>;

    fn new(rounds: &Self::Parameters) -> Self {
        Self {
            rounds: rounds.clone(),
            state: State::default(),
            mode: DuplexSpongeMode::Absorbing { next_absorb_index: 0 },
        }
    }

    fn absorb(&mut self, input: &[Field<E>]) {
        if !input.is_empty() {
            match self.mode {
                DuplexSpongeMode::Absorbing { mut next_absorb_index } => {
                    if next_absorb_index == RATE {
                        self.permute();
                        next_absorb_index = 0;
                    }
                    self.absorb_internal(next_absorb_index, input);
                }
                DuplexSpongeMode::Squeezing { next_squeeze_index: _ } => {
                    self.permute();
                    self.absorb_internal(0, input);
                }
            }
        }
    }

    fn squeeze(&mut self, num_elements: u16) -> SmallVec<[Field<E>; 10]> {
        if num_elements == 0 {
            return SmallVec::new();
        }
        let mut output = if num_elements <= 10 {
            smallvec::smallvec_inline![Field::<E>::zero(); 10]
        } else {
            smallvec::smallvec![Field::<E>::zero(); num_elements as usize]
        };

        match self.mode {
            DuplexSpongeMode::Absorbing { next_absorb_index: _ } => {
                self.permute();
                self.squeeze_internal(0, &mut output[..num_elements as usize]);
            }
            DuplexSpongeMode::Squeezing { mut next_squeeze_index } => {
                if next_squeeze_index == RATE {
                    self.permute();
                    next_squeeze_index = 0;
                }
                self.squeeze_internal(next_squeeze_index, &mut output[..num_elements as usize]);
            }
        }

        output.truncate(num_elements as usize);
        output
    }
}

impl<E: Environment, const RATE: usize, const CAPACITY: usize> PoseidonSponge<E, RATE, CAPACITY> {
    /// Applies a full round: its constants, the S-box on every element, and the MDS matrix.
    #[inline]
    fn full_round(&mut self, ark: &[E::Field], mds: &[Vec<E::Field>]) {
        for (elem, constant) in self.state.iter_mut().zip(ark) {
            let e = elem.deref_mut();
            *e += constant;
            *e = e.pow([self.rounds.alpha]);
        }
        self.apply_dense(mds);
    }

    /// Multiplies the state by a dense matrix.
    #[inline]
    fn apply_dense(&mut self, matrix: &[Vec<E::Field>]) {
        let mut new_state = State::default();
        let curr_state: Vec<<E as Environment>::Field> = self.state.iter().map(|e| *e.deref()).collect::<Vec<_>>();
        new_state.iter_mut().zip(matrix).for_each(|(new_elem, row)| {
            *new_elem = Field::new(E::Field::sum_of_products(curr_state.as_slice(), row));
        });
        self.state = new_state;
    }

    /// Multiplies the state by a sparse matrix: a dense first row and column, the identity elsewhere.
    #[inline]
    fn apply_sparse(&mut self, matrix: &SparseMatrix<E::Field>) {
        let curr_state: Vec<<E as Environment>::Field> = self.state.iter().map(|e| *e.deref()).collect::<Vec<_>>();
        let first = curr_state[0];
        for (elem, weight) in self.state.iter_mut().skip(1).zip(&matrix.column) {
            *elem.deref_mut() += first * weight;
        }
        *self.state[0].deref_mut() = E::Field::sum_of_products(curr_state.as_slice(), &matrix.row);
    }

    #[inline]
    fn permute(&mut self) {
        let rounds = self.rounds.clone();
        for ark in &rounds.first_full_ark {
            self.full_round(ark, &rounds.mds);
        }
        // A partial round adds one constant and applies the S-box to the first element only.
        for (round, constant) in rounds.partial_ark.iter().enumerate() {
            let first = self.state[0].deref_mut();
            *first += constant;
            *first = first.pow([rounds.alpha]);
            match rounds.partial_sparse.get(round) {
                Some(matrix) => self.apply_sparse(matrix),
                None => self.apply_dense(&rounds.last_partial_mds),
            }
        }
        for ark in &rounds.last_full_ark {
            self.full_round(ark, &rounds.mds);
        }
    }

    /// Absorbs everything in elements, this does not end in an absorption.
    #[inline]
    fn absorb_internal(&mut self, mut rate_start: usize, input: &[Field<E>]) {
        if !input.is_empty() {
            let first_chunk_size = std::cmp::min(RATE - rate_start, input.len());
            let num_elements_remaining = input.len() - first_chunk_size;
            let (first_chunk, rest_chunk) = input.split_at(first_chunk_size);
            let rest_chunks = rest_chunk.chunks(RATE);
            // The total number of chunks is `elements[num_elements_remaining..].len() / RATE`, plus 1
            // for the remainder.
            let total_num_chunks = 1 + // 1 for the first chunk
                // We add all the chunks that are perfectly divisible by `RATE`
                (num_elements_remaining / RATE) +
                // And also add 1 if the last chunk is non-empty
                // (i.e. if `num_elements_remaining` is not a multiple of `RATE`)
                usize::from(!num_elements_remaining.is_multiple_of(RATE));

            // Absorb the input elements, `RATE` elements at a time, except for the first chunk, which
            // is of size `RATE - rate_start`.
            for (i, chunk) in std::iter::once(first_chunk).chain(rest_chunks).enumerate() {
                for (element, state_elem) in chunk.iter().zip(&mut self.state.rate_state_mut()[rate_start..]) {
                    *state_elem += element;
                }
                // Are we in the last chunk?
                // If so, let's wrap up.
                if i == total_num_chunks - 1 {
                    self.mode = DuplexSpongeMode::Absorbing { next_absorb_index: rate_start + chunk.len() };
                    return;
                } else {
                    self.permute();
                }
                rate_start = 0;
            }
        }
    }

    /// Squeeze |output| many elements. This does not end in a squeeze
    #[inline]
    fn squeeze_internal(&mut self, mut rate_start: usize, output: &mut [Field<E>]) {
        let output_size = output.len();
        if output_size != 0 {
            let first_chunk_size = std::cmp::min(RATE - rate_start, output.len());
            let num_output_remaining = output.len() - first_chunk_size;
            let (first_chunk, rest_chunk) = output.split_at_mut(first_chunk_size);
            assert_eq!(rest_chunk.len(), num_output_remaining);
            let rest_chunks = rest_chunk.chunks_mut(RATE);
            // The total number of chunks is `output[num_output_remaining..].len() / RATE`, plus 1
            // for the remainder.
            let total_num_chunks = 1 + // 1 for the first chunk
                // We add all the chunks that are perfectly divisible by `RATE`
                (num_output_remaining / RATE) +
                // And also add 1 if the last chunk is non-empty
                // (i.e. if `num_output_remaining` is not a multiple of `RATE`)
                usize::from(!num_output_remaining.is_multiple_of(RATE));

            // Absorb the input output, `RATE` output at a time, except for the first chunk, which
            // is of size `RATE - rate_start`.
            for (i, chunk) in std::iter::once(first_chunk).chain(rest_chunks).enumerate() {
                let range = rate_start..(rate_start + chunk.len());
                debug_assert_eq!(
                    chunk.len(),
                    self.state.rate_state(range.clone()).len(),
                    "Failed to squeeze {output_size} at rate {RATE} & rate_start {rate_start}"
                );
                chunk.copy_from_slice(self.state.rate_state(range));
                // Are we in the last chunk?
                // If so, let's wrap up.
                if i == total_num_chunks - 1 {
                    self.mode = DuplexSpongeMode::Squeezing { next_squeeze_index: (rate_start + chunk.len()) };
                    return;
                } else {
                    self.permute();
                }
                rate_start = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_types::environment::Console;
    use snarkvm_fields::{PoseidonDefaultField, PoseidonParameters};

    type CurrentEnvironment = Console;
    type F = <CurrentEnvironment as Environment>::Field;

    const ITERATIONS: usize = 100;

    /// The permutation as the parameters define it: every round adds all of its constants and
    /// multiplies by the MDS matrix.
    fn reference_permute<const RATE: usize>(
        parameters: &PoseidonParameters<F, RATE, 1>,
        state: &mut State<CurrentEnvironment, RATE, 1>,
    ) {
        let full_rounds_over_2 = parameters.full_rounds / 2;
        let partial_rounds = full_rounds_over_2..full_rounds_over_2 + parameters.partial_rounds;
        for round in 0..parameters.full_rounds + parameters.partial_rounds {
            for (elem, constant) in state.iter_mut().zip(&parameters.ark[round]) {
                *elem.deref_mut() += constant;
            }
            for (index, elem) in state.iter_mut().enumerate() {
                if index == 0 || !partial_rounds.contains(&round) {
                    let e = elem.deref_mut();
                    *e = e.pow([parameters.alpha]);
                }
            }
            let current: Vec<F> = state.iter().map(|e| *e.deref()).collect();
            for (elem, row) in state.iter_mut().zip(&parameters.mds) {
                *elem = Field::new(F::sum_of_products(&current, row));
            }
        }
    }

    fn check_rate<const RATE: usize>(rng: &mut TestRng) {
        let parameters = F::default_poseidon_parameters::<RATE>().unwrap();
        let rounds = Arc::new(PoseidonRounds::new(&parameters).unwrap());
        for _ in 0..ITERATIONS {
            let mut sponge = PoseidonSponge::<CurrentEnvironment, RATE, 1>::new(&rounds);
            sponge.state.iter_mut().for_each(|elem| *elem = Uniform::rand(rng));
            let mut expected = sponge.state;
            reference_permute(&parameters, &mut expected);
            sponge.permute();
            assert!(sponge.state.iter().eq(expected.iter()), "rate {RATE}: the permutation changed");
        }
    }

    #[test]
    fn test_permutation_matches_reference_rounds() {
        let rng = &mut TestRng::default();
        check_rate::<2>(rng);
        check_rate::<3>(rng);
        check_rate::<4>(rng);
        check_rate::<5>(rng);
        check_rate::<6>(rng);
        check_rate::<7>(rng);
        check_rate::<8>(rng);
    }
}
