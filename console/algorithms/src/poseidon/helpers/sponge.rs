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
    helpers::{AlgebraicSponge, DuplexSpongeMode},
};
use snarkvm_console_types::{Field, prelude::*};
use snarkvm_fields::{PoseidonParameters, PoseidonSparseRounds};

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
    /// Sponge Parameters
    parameters: Arc<PoseidonParameters<E::Field, RATE, CAPACITY>>,
    /// The partial rounds of `parameters` in sparse form. If `None`, every round multiplies the
    /// state by the MDS matrix.
    sparse_rounds: Option<Arc<PoseidonSparseRounds<E::Field, RATE>>>,
    /// Current sponge's state (current elements in the permutation block)
    state: State<E, RATE, CAPACITY>,
    /// Current mode (whether its absorbing or squeezing)
    pub(in crate::poseidon) mode: DuplexSpongeMode,
}

impl<E: Environment, const RATE: usize, const CAPACITY: usize> AlgebraicSponge<E, RATE, CAPACITY>
    for PoseidonSponge<E, RATE, CAPACITY>
{
    type Parameters = Arc<PoseidonParameters<E::Field, RATE, CAPACITY>>;

    fn new(parameters: &Self::Parameters) -> Self {
        Self {
            parameters: parameters.clone(),
            sparse_rounds: None,
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

impl<E: Environment, const RATE: usize> PoseidonSponge<E, RATE, 1> {
    /// Initializes a new sponge with the parameters of `sparse_rounds` and their partial rounds in
    /// that sparse form.
    pub(in crate::poseidon) fn with_sparse_rounds(sparse_rounds: &Arc<PoseidonSparseRounds<E::Field, RATE>>) -> Self {
        Self { sparse_rounds: Some(sparse_rounds.clone()), ..Self::new(sparse_rounds.parameters()) }
    }
}

impl<E: Environment, const RATE: usize, const CAPACITY: usize> PoseidonSponge<E, RATE, CAPACITY> {
    #[inline]
    fn apply_ark(&mut self, round_number: usize) {
        for (state_elem, ark_elem) in self.state.iter_mut().zip(&self.parameters.ark[round_number]) {
            *state_elem += Field::<E>::new(*ark_elem);
        }
    }

    #[inline]
    fn apply_s_box(&mut self, is_full_round: bool) {
        // Full rounds apply the S Box (x^alpha) to every element of state
        if is_full_round {
            for elem in self.state.iter_mut() {
                let e = elem.deref_mut();
                *e = e.pow([self.parameters.alpha]);
            }
        }
        // Partial rounds apply the S Box (x^alpha) to just the first element of state
        else {
            let e = self.state[0].deref_mut();
            *e = e.pow([self.parameters.alpha]);
        }
    }

    #[inline]
    fn apply_mds(&mut self) {
        let mut new_state = State::default();
        let curr_state: Vec<<E as Environment>::Field> = self.state.iter().map(|e| *e.deref()).collect::<Vec<_>>();
        new_state.iter_mut().zip(&self.parameters.mds).for_each(|(new_elem, mds_row)| {
            *new_elem = Field::new(E::Field::sum_of_products(curr_state.as_slice(), mds_row));
        });
        self.state = new_state;
    }

    #[inline]
    fn permute(&mut self) {
        match &self.sparse_rounds {
            Some(sparse_rounds) => permute_sparse(sparse_rounds, &mut self.state),
            None => self.permute_dense(),
        }
    }

    /// Applies the permutation round by round, with the MDS matrix in every round.
    #[inline]
    fn permute_dense(&mut self) {
        // Determine the partial rounds range bound.
        let partial_rounds = self.parameters.partial_rounds;
        let full_rounds = self.parameters.full_rounds;
        let full_rounds_over_2 = full_rounds / 2;
        let partial_round_range = full_rounds_over_2..(full_rounds_over_2 + partial_rounds);

        // Iterate through all rounds to permute.
        for i in 0..(partial_rounds + full_rounds) {
            let is_full_round = !partial_round_range.contains(&i);
            self.apply_ark(i);
            self.apply_s_box(is_full_round);
            self.apply_mds();
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

/// Applies the permutation of the parameters of `sparse_rounds` to `state`, with the partial rounds
/// in their sparse form.
#[inline]
fn permute_sparse<E: Environment, const RATE: usize, const CAPACITY: usize>(
    sparse_rounds: &PoseidonSparseRounds<E::Field, RATE>,
    state: &mut State<E, RATE, CAPACITY>,
) {
    let parameters = sparse_rounds.parameters();
    let first_partial_round = parameters.full_rounds / 2;
    let last_partial_round = first_partial_round + parameters.partial_rounds;
    let num_rounds = parameters.full_rounds + parameters.partial_rounds;

    let mut current: SmallVec<[E::Field; 10]> = state.iter().map(|elem| *elem.deref()).collect();
    let mut next = current.clone();
    let mut full_round = |current: &mut SmallVec<[E::Field; 10]>, ark: &[E::Field], matrix: &[Vec<E::Field>]| {
        for (x, c) in current.iter_mut().zip_eq(ark) {
            *x += c;
            *x = x.pow([parameters.alpha]);
        }
        for (x, row) in next.iter_mut().zip_eq(matrix) {
            *x = E::Field::sum_of_products(current, row);
        }
        std::mem::swap(current, &mut next);
    };

    for round in 0..first_partial_round {
        let matrix = if round + 1 == first_partial_round { sparse_rounds.first_matrix() } else { &parameters.mds };
        full_round(&mut current, &parameters.ark[round], matrix);
    }
    for round in sparse_rounds.rounds() {
        current[0] += round.constant();
        current[0] = current[0].pow([parameters.alpha]);
        let first = E::Field::sum_of_products(&current, round.row());
        // The full rounds check with `zip_eq` that the state has `RATE + 1` elements, so it is not
        // empty.
        let (head, tail) = current.split_first_mut().unwrap();
        for (x, c) in tail.iter_mut().zip_eq(round.column()) {
            *x += *c * *head;
        }
        *head = first;
    }
    for round in last_partial_round..num_rounds {
        let ark = if round == last_partial_round { sparse_rounds.last_ark() } else { &parameters.ark[round] };
        full_round(&mut current, ark, &parameters.mds);
    }

    for (elem, value) in state.iter_mut().zip_eq(current) {
        *elem = Field::new(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_types::environment::Console;
    use snarkvm_fields::PoseidonDefaultField;

    type CurrentEnvironment = Console;
    type F = <CurrentEnvironment as Environment>::Field;

    /// Checks that `chain` permutations of `state` give the same state with `permute` as with
    /// `permute_dense`.
    fn check_state<const RATE: usize>(sparse_rounds: &Arc<PoseidonSparseRounds<F, RATE>>, state: &[F], chain: usize) {
        let mut sparse = PoseidonSponge::<CurrentEnvironment, RATE, 1>::with_sparse_rounds(sparse_rounds);
        assert!(Arc::ptr_eq(&sparse.parameters, sparse_rounds.parameters()));
        for (x, y) in sparse.state.iter_mut().zip_eq(state) {
            *x = Field::new(*y);
        }
        let mut dense = sparse.clone();
        for _ in 0..chain {
            sparse.permute();
            dense.permute_dense();
        }
        assert_eq!(sparse.state.iter().collect_vec(), dense.state.iter().collect_vec(), "{chain} from {state:?}");
    }

    /// Checks the sparse permutation of `parameters` against the dense one on states of 0, 1 and
    /// p - 1, on random states, and on chains of permutations.
    fn check_parameters<const RATE: usize>(parameters: PoseidonParameters<F, RATE, 1>, rng: &mut TestRng) {
        let sparse_rounds = Arc::new(PoseidonSparseRounds::new(&Arc::new(parameters)).unwrap());
        let width = RATE + 1;
        let edges = [F::zero(), F::one(), -F::one()];
        if width <= 5 {
            for state in (0..width).map(|_| edges).multi_cartesian_product() {
                check_state(&sparse_rounds, &state, 1);
            }
        } else {
            for (a, b) in edges.into_iter().cartesian_product(edges) {
                for i in 0..width {
                    let state = (0..width).map(|j| if i == j { b } else { a }).collect_vec();
                    check_state(&sparse_rounds, &state, 1);
                }
            }
        }
        for _ in 0..100 {
            let state = (0..width).map(|_| F::rand(rng)).collect_vec();
            check_state(&sparse_rounds, &state, 1);
        }
        for chain in [2, 5, 200] {
            let state = (0..width).map(|_| F::rand(rng)).collect_vec();
            check_state(&sparse_rounds, &state, chain);
        }
    }

    /// Returns parameters with the given rounds and `alpha`, random round constants, and the MDS
    /// matrix of the default parameters of `RATE`.
    fn parameters_with_rounds<const RATE: usize>(
        full_rounds: usize,
        partial_rounds: usize,
        alpha: u64,
        rng: &mut TestRng,
    ) -> PoseidonParameters<F, RATE, 1> {
        let ark = (0..full_rounds + partial_rounds).map(|_| (0..RATE + 1).map(|_| F::rand(rng)).collect()).collect();
        let mds = F::default_poseidon_parameters::<RATE>().unwrap().mds;
        PoseidonParameters { full_rounds, partial_rounds, alpha, ark, mds }
    }

    #[test]
    fn test_sparse_permutation() {
        let rng = &mut TestRng::default();
        check_parameters(F::default_poseidon_parameters::<2>().unwrap(), rng);
        check_parameters(F::default_poseidon_parameters::<3>().unwrap(), rng);
        check_parameters(F::default_poseidon_parameters::<4>().unwrap(), rng);
        check_parameters(F::default_poseidon_parameters::<5>().unwrap(), rng);
        check_parameters(F::default_poseidon_parameters::<6>().unwrap(), rng);
        check_parameters(F::default_poseidon_parameters::<7>().unwrap(), rng);
        check_parameters(F::default_poseidon_parameters::<8>().unwrap(), rng);
    }

    #[test]
    fn test_sparse_permutation_round_counts() {
        let rng = &mut TestRng::default();
        for (full_rounds, partial_rounds) in [(2, 1), (2, 2), (3, 1), (3, 4), (4, 1), (5, 3), (6, 5), (8, 31), (10, 40)]
        {
            for alpha in [3, 5, 17] {
                check_parameters(parameters_with_rounds::<2>(full_rounds, partial_rounds, alpha, rng), rng);
                check_parameters(parameters_with_rounds::<4>(full_rounds, partial_rounds, alpha, rng), rng);
            }
        }
    }

    #[test]
    fn test_sparse_permutation_random_matrix() {
        let rng = &mut TestRng::default();
        for _ in 0..5 {
            let mut parameters = parameters_with_rounds::<2>(8, 31, 17, rng);
            parameters.mds = (0..3).map(|_| (0..3).map(|_| F::rand(rng)).collect()).collect();
            check_parameters(parameters, rng);
        }
    }
}
