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

use crate::{AlgebraicSponge, DuplexSpongeMode, nonnative_params::*};
use snarkvm_fields::{FieldParameters, PoseidonParameters, PrimeField, ToConstraintField};
use snarkvm_utilities::{BigInteger, FromBits, ToBits};

use itertools::Itertools;
use smallvec::SmallVec;
use std::{
    any::Any,
    iter::Peekable,
    ops::{Index, IndexMut},
    sync::{Arc, PoisonError, RwLock},
};

#[derive(Copy, Clone, Debug)]
pub struct State<F: PrimeField, const RATE: usize, const CAPACITY: usize> {
    capacity_state: [F; CAPACITY],
    rate_state: [F; RATE],
}

impl<F: PrimeField, const RATE: usize, const CAPACITY: usize> Default for State<F, RATE, CAPACITY> {
    fn default() -> Self {
        Self { capacity_state: [F::zero(); CAPACITY], rate_state: [F::zero(); RATE] }
    }
}

impl<F: PrimeField, const RATE: usize, const CAPACITY: usize> State<F, RATE, CAPACITY> {
    /// Returns an immutable iterator over the state.
    pub fn iter(&self) -> impl Iterator<Item = &F> + Clone {
        self.capacity_state.iter().chain(self.rate_state.iter())
    }

    /// Returns a mutable iterator over the state.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut F> {
        self.capacity_state.iter_mut().chain(self.rate_state.iter_mut())
    }
}

impl<F: PrimeField, const RATE: usize, const CAPACITY: usize> Index<usize> for State<F, RATE, CAPACITY> {
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        assert!(index < RATE + CAPACITY, "Index out of bounds: index is {} but length is {}", index, RATE + CAPACITY);
        if index < CAPACITY { &self.capacity_state[index] } else { &self.rate_state[index - CAPACITY] }
    }
}

impl<F: PrimeField, const RATE: usize, const CAPACITY: usize> IndexMut<usize> for State<F, RATE, CAPACITY> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        assert!(index < RATE + CAPACITY, "Index out of bounds: index is {} but length is {}", index, RATE + CAPACITY);
        if index < CAPACITY { &mut self.capacity_state[index] } else { &mut self.rate_state[index - CAPACITY] }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poseidon<F: PrimeField, const RATE: usize> {
    parameters: Arc<PoseidonParameters<F, RATE, 1>>,
}

impl<F: PrimeField, const RATE: usize> Poseidon<F, RATE> {
    /// Initializes a new instance of the cryptographic hash function.
    pub fn setup() -> Self {
        Self { parameters: Arc::new(F::default_poseidon_parameters::<RATE>().unwrap()) }
    }

    /// Evaluate the cryptographic hash function over a list of field elements
    /// as input.
    pub fn evaluate(&self, input: &[F]) -> F {
        self.evaluate_many(input, 1)[0]
    }

    /// Evaluate the cryptographic hash function over a list of field elements
    /// as input, and returns the specified number of field elements as
    /// output.
    pub fn evaluate_many(&self, input: &[F], num_outputs: usize) -> Vec<F> {
        let mut sponge = PoseidonSponge::<F, RATE, 1>::new_with_parameters(&self.parameters);
        sponge.absorb_native_field_elements(input);
        sponge.squeeze_native_field_elements(num_outputs).to_vec()
    }

    /// Evaluate the cryptographic hash function over a non-fixed-length vector,
    /// in which the length also needs to be hashed.
    pub fn evaluate_with_len(&self, input: &[F]) -> F {
        self.evaluate(&[vec![F::from(input.len() as u128)], input.to_vec()].concat())
    }

    pub fn parameters(&self) -> &Arc<PoseidonParameters<F, RATE, 1>> {
        &self.parameters
    }
}

/// A duplex sponge based using the Poseidon permutation.
///
/// This implementation of Poseidon is entirely from Fractal's implementation in
/// [COS20][cos] with small syntax changes.
///
/// [cos]: https://eprint.iacr.org/2019/1076
#[derive(Clone, Debug)]
pub struct PoseidonSponge<F: PrimeField, const RATE: usize, const CAPACITY: usize> {
    /// Sponge Parameters
    parameters: Arc<PoseidonParameters<F, RATE, CAPACITY>>,
    /// Current sponge's state (current elements in the permutation block)
    state: State<F, RATE, CAPACITY>,
    /// Current mode (whether its absorbing or squeezing)
    pub mode: DuplexSpongeMode,
    /// A persistent lookup table used when compressing elements.
    adjustment_factor_lookup_table: Arc<[F]>,
    /// The partial rounds of `parameters` in sparse form, or `None` if they
    /// have none.
    partial_rounds: Option<Arc<PartialRounds<F>>>,
}

impl<F: PrimeField, const RATE: usize> AlgebraicSponge<F, RATE> for PoseidonSponge<F, RATE, 1> {
    type Parameters = Arc<PoseidonParameters<F, RATE, 1>>;

    fn sample_parameters() -> Self::Parameters {
        Arc::new(F::default_poseidon_parameters::<RATE>().unwrap())
    }

    fn new_with_parameters(parameters: &Self::Parameters) -> Self {
        Self {
            parameters: parameters.clone(),
            state: State::default(),
            mode: DuplexSpongeMode::Absorbing { next_absorb_index: 0 },
            adjustment_factor_lookup_table: {
                let capacity = F::size_in_bits() - 1;
                let mut table = Vec::<F>::with_capacity(capacity);

                let mut cur = F::one();
                for _ in 0..capacity {
                    table.push(cur);
                    cur.double_in_place();
                }

                table.into()
            },
            partial_rounds: PartialRounds::cached(parameters),
        }
    }

    /// Takes in field elements.
    fn absorb_native_field_elements<T: ToConstraintField<F>>(&mut self, elements: &[T]) {
        let input = elements.iter().flat_map(|e| e.to_field_elements().unwrap()).collect::<Vec<_>>();
        if !input.is_empty() {
            match self.mode {
                DuplexSpongeMode::Absorbing { mut next_absorb_index } => {
                    if next_absorb_index == RATE {
                        self.permute();
                        next_absorb_index = 0;
                    }
                    self.absorb_internal(next_absorb_index, &input);
                }
                DuplexSpongeMode::Squeezing { next_squeeze_index: _ } => {
                    self.permute();
                    self.absorb_internal(0, &input);
                }
            }
        }
    }

    /// Takes in field elements.
    fn absorb_nonnative_field_elements<Target: PrimeField>(&mut self, elements: impl IntoIterator<Item = Target>) {
        Self::push_elements_to_sponge(self, elements, OptimizationType::Weight);
    }

    fn squeeze_nonnative_field_elements<Target: PrimeField>(&mut self, num: usize) -> SmallVec<[Target; 10]> {
        self.get_fe(num, false)
    }

    fn squeeze_native_field_elements(&mut self, num_elements: usize) -> SmallVec<[F; 10]> {
        if num_elements == 0 {
            return SmallVec::<[F; 10]>::new();
        }
        let mut output = if num_elements <= 10 {
            smallvec::smallvec_inline![F::zero(); 10]
        } else {
            smallvec::smallvec![F::zero(); num_elements]
        };

        match self.mode {
            DuplexSpongeMode::Absorbing { next_absorb_index: _ } => {
                self.permute();
                self.squeeze_internal(0, &mut output[..num_elements]);
            }
            DuplexSpongeMode::Squeezing { mut next_squeeze_index } => {
                if next_squeeze_index == RATE {
                    self.permute();
                    next_squeeze_index = 0;
                }
                self.squeeze_internal(next_squeeze_index, &mut output[..num_elements]);
            }
        }

        output.truncate(num_elements);
        output
    }

    /// Takes out field elements of 168 bits.
    fn squeeze_short_nonnative_field_elements<Target: PrimeField>(&mut self, num: usize) -> SmallVec<[Target; 10]> {
        self.get_fe(num, true)
    }
}

impl<F: PrimeField, const RATE: usize> PoseidonSponge<F, RATE, 1> {
    #[inline]
    fn apply_ark(&mut self, round_number: usize) {
        for (state_elem, ark_elem) in self.state.iter_mut().zip(&self.parameters.ark[round_number]) {
            *state_elem += ark_elem;
        }
    }

    #[inline]
    fn apply_s_box(&mut self, is_full_round: bool) {
        let pow_alpha_in_place = pow_alpha_in_place(self.parameters.alpha);

        if is_full_round {
            self.state.iter_mut().for_each(pow_alpha_in_place);
        } else {
            pow_alpha_in_place(&mut self.state[0]);
        }
    }

    #[inline]
    fn apply_mds(&mut self) {
        let mut new_state = State::default();
        let curr_state: Vec<F> = self.state.iter().copied().collect::<Vec<_>>();
        new_state.iter_mut().zip(&self.parameters.mds).for_each(|(new_elem, mds_row)| {
            *new_elem = F::sum_of_products(&curr_state, mds_row);
        });
        self.state = new_state;
    }

    #[inline]
    fn permute(&mut self) {
        match &self.partial_rounds {
            Some(partial_rounds) => permute_sparse(&self.parameters, partial_rounds, &mut self.state),
            None => self.permute_dense(),
        }
    }

    /// Applies the permutation round by round, with the MDS matrix in every
    /// round.
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
    fn absorb_internal(&mut self, mut rate_start: usize, input: &[F]) {
        if !input.is_empty() {
            let first_chunk_size = std::cmp::min(RATE - rate_start, input.len());
            let num_elements_remaining = input.len() - first_chunk_size;
            let (first_chunk, rest_chunk) = input.split_at(first_chunk_size);
            let rest_chunks = rest_chunk.chunks(RATE);
            // The total number of chunks is `elements[num_elements_remaining..].len() /
            // RATE`, plus 1 for the remainder.
            let total_num_chunks = 1 + // 1 for the first chunk
                // We add all the chunks that are perfectly divisible by `RATE`
                (num_elements_remaining / RATE) +
                // And also add 1 if the last chunk is non-empty
                // (i.e. if `num_elements_remaining` is not a multiple of `RATE`)
                usize::from(!num_elements_remaining.is_multiple_of(RATE));

            // Absorb the input elements, `RATE` elements at a time, except for the first
            // chunk, which is of size `RATE - rate_start`.
            for (i, chunk) in std::iter::once(first_chunk).chain(rest_chunks).enumerate() {
                for (element, state_elem) in chunk.iter().zip(&mut self.state.rate_state[rate_start..]) {
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
    fn squeeze_internal(&mut self, mut rate_start: usize, output: &mut [F]) {
        let output_size = output.len();
        if output_size != 0 {
            let first_chunk_size = std::cmp::min(RATE - rate_start, output.len());
            let num_output_remaining = output.len() - first_chunk_size;
            let (first_chunk, rest_chunk) = output.split_at_mut(first_chunk_size);
            assert_eq!(rest_chunk.len(), num_output_remaining);
            let rest_chunks = rest_chunk.chunks_mut(RATE);
            // The total number of chunks is `output[num_output_remaining..].len() / RATE`,
            // plus 1 for the remainder.
            let total_num_chunks = 1 + // 1 for the first chunk
                // We add all the chunks that are perfectly divisible by `RATE`
                (num_output_remaining / RATE) +
                // And also add 1 if the last chunk is non-empty
                // (i.e. if `num_output_remaining` is not a multiple of `RATE`)
                usize::from(!num_output_remaining.is_multiple_of(RATE));

            // Absorb the input output, `RATE` output at a time, except for the first chunk,
            // which is of size `RATE - rate_start`.
            for (i, chunk) in std::iter::once(first_chunk).chain(rest_chunks).enumerate() {
                let range = rate_start..(rate_start + chunk.len());
                debug_assert_eq!(
                    chunk.len(),
                    self.state.rate_state[range.clone()].len(),
                    "failed with squeeze {output_size} at rate {RATE} and rate_start {rate_start}"
                );
                chunk.copy_from_slice(&self.state.rate_state[range]);
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

    /// Compress every two elements if possible.
    /// Provides a vector of (limb, num_of_additions), both of which are F.
    pub fn compress_elements<TargetField: PrimeField, I: Iterator<Item = (F, F)>>(
        &self,
        mut src_limbs: Peekable<I>,
        ty: OptimizationType,
    ) -> Vec<F> {
        let capacity = F::size_in_bits() - 1;
        let mut dest_limbs = Vec::<F>::new();

        let params = get_params(TargetField::size_in_bits(), F::size_in_bits(), ty);

        // Prepare a reusable vector to be used in overhead calculation.
        let mut num_bits = Vec::new();

        while let Some(first) = src_limbs.next() {
            let second = src_limbs.peek();

            let first_max_bits_per_limb = params.bits_per_limb + crate::overhead!(first.1 + F::one(), &mut num_bits);
            let second_max_bits_per_limb = if let Some(second) = second {
                params.bits_per_limb + crate::overhead!(second.1 + F::one(), &mut num_bits)
            } else {
                0
            };

            if let Some(second) = second {
                if first_max_bits_per_limb + second_max_bits_per_limb <= capacity {
                    let adjustment_factor = &self.adjustment_factor_lookup_table[second_max_bits_per_limb];

                    dest_limbs.push(first.0 * adjustment_factor + second.0);
                    src_limbs.next();
                } else {
                    dest_limbs.push(first.0);
                }
            } else {
                dest_limbs.push(first.0);
            }
        }

        dest_limbs
    }

    /// Convert a `TargetField` element into limbs (not constraints)
    /// This is an internal function that would be reused by a number of other
    /// functions
    pub fn get_limbs_representations<TargetField: PrimeField>(
        elem: &TargetField,
        optimization_type: OptimizationType,
    ) -> SmallVec<[F; 10]> {
        Self::get_limbs_representations_from_big_integer::<TargetField>(&elem.to_bigint(), optimization_type)
    }

    /// Obtain the limbs directly from a big int
    pub fn get_limbs_representations_from_big_integer<TargetField: PrimeField>(
        elem: &<TargetField as PrimeField>::BigInteger,
        optimization_type: OptimizationType,
    ) -> SmallVec<[F; 10]> {
        let params = get_params(TargetField::size_in_bits(), F::size_in_bits(), optimization_type);

        // Prepare a reusable vector for the BE bits.
        let mut cur_bits = Vec::new();
        // Push the lower limbs first
        let mut limbs: SmallVec<[F; 10]> = SmallVec::new();
        let mut cur = *elem;
        for _ in 0..params.num_limbs {
            cur.write_bits_be(&mut cur_bits); // `write_bits_be` is big endian
            let cur_mod_r =
                <F as PrimeField>::BigInteger::from_bits_be(&cur_bits[cur_bits.len() - params.bits_per_limb..])
                    .unwrap(); // therefore, the lowest `bits_per_non_top_limb` bits is what we want.
            limbs.push(F::from_bigint(cur_mod_r).unwrap());
            cur.divn(params.bits_per_limb as u32);
            // Clear the vector after every iteration so its allocation can be reused.
            cur_bits.clear();
        }

        // then we reverse, so that the limbs are ``big limb first''
        limbs.reverse();

        limbs
    }

    /// Push elements to sponge, treated in the non-native field
    /// representations.
    pub fn push_elements_to_sponge<TargetField: PrimeField>(
        &mut self,
        src: impl IntoIterator<Item = TargetField>,
        ty: OptimizationType,
    ) {
        let src_limbs = src
            .into_iter()
            .flat_map(|elem| {
                let limbs = Self::get_limbs_representations(&elem, ty);
                limbs.into_iter().map(|limb| (limb, F::one()))
                // specifically set to one, since most gadgets in the constraint
                // world would not have zero noise (due to the relatively weak
                // normal form testing in `alloc`)
            })
            .peekable();

        let dest_limbs = self.compress_elements::<TargetField, _>(src_limbs, ty);
        self.absorb_native_field_elements(&dest_limbs);
    }

    /// obtain random bits from hashchain.
    /// not guaranteed to be uniformly distributed, should only be used in
    /// certain situations.
    pub fn get_bits(&mut self, num_bits: usize) -> Vec<bool> {
        let bits_per_element = F::size_in_bits() - 1;
        let num_elements = num_bits.div_ceil(bits_per_element);

        let src_elements = self.squeeze_native_field_elements(num_elements);
        let mut dest_bits = Vec::<bool>::with_capacity(num_elements * bits_per_element);

        let skip = (F::Parameters::REPR_SHAVE_BITS + 1) as usize;
        for elem in src_elements.iter() {
            // discard the highest bit
            let elem_bits = elem.to_bigint().to_bits_be();
            dest_bits.extend_from_slice(&elem_bits[skip..]);
        }
        dest_bits.truncate(num_bits);

        dest_bits
    }

    /// obtain random field elements from hashchain.
    /// not guaranteed to be uniformly distributed, should only be used in
    /// certain situations.
    pub fn get_fe<TargetField: PrimeField>(
        &mut self,
        num_elements: usize,
        outputs_short_elements: bool,
    ) -> SmallVec<[TargetField; 10]> {
        let num_bits_per_nonnative = if outputs_short_elements {
            168
        } else {
            TargetField::size_in_bits() - 1 // also omit the highest bit
        };
        let bits = self.get_bits(num_bits_per_nonnative * num_elements);

        let mut lookup_table = Vec::<TargetField>::with_capacity(num_bits_per_nonnative);
        let mut cur = TargetField::one();
        for _ in 0..num_bits_per_nonnative {
            lookup_table.push(cur);
            cur.double_in_place();
        }

        let dest_elements = bits
            .chunks_exact(num_bits_per_nonnative)
            .map(|per_nonnative_bits| {
                // technically, this can be done via BigInteger::from_bits; here, we use this
                // method for consistency with the gadget counterpart
                let mut res = TargetField::zero();

                for (i, bit) in per_nonnative_bits.iter().rev().enumerate() {
                    if *bit {
                        res += &lookup_table[i];
                    }
                }
                res
            })
            .collect::<SmallVec<_>>();
        debug_assert_eq!(dest_elements.len(), num_elements);

        dest_elements
    }
}

/// The partial rounds of a Poseidon permutation, rewritten as in the appendix
/// on efficient partial rounds of [GKRRS19][poseidon], so that each partial
/// round adds one round constant and multiplies the state by a sparse matrix.
///
/// The permutation equals the dense one when the last full round before the
/// partial rounds multiplies by `first_matrix` in place of the MDS matrix, and
/// the first full round after them adds `last_ark` in place of its round
/// constants.
///
/// [poseidon]: https://eprint.iacr.org/2019/458
#[derive(Debug)]
struct PartialRounds<F: PrimeField> {
    /// The matrix of the last full round before the partial rounds.
    first_matrix: Vec<Vec<F>>,
    /// The partial rounds, in order.
    rounds: Vec<PartialRound<F>>,
    /// The round constants of the first full round after the partial rounds.
    last_ark: Vec<F>,
}

/// A partial round: add `constant` to the first state element, apply the S-box
/// to it, and multiply the state by the matrix whose first row is `row`, whose
/// first column below the first row is `column`, and which is the identity
/// elsewhere.
#[derive(Debug)]
struct PartialRound<F: PrimeField> {
    constant: F,
    row: Vec<F>,
    column: Vec<F>,
}

/// The partial rounds of the most recent parameter sets that sponges were
/// created with, oldest first. Each entry is a `CacheEntry` of its field and
/// rate.
static PARTIAL_ROUNDS_CACHE: RwLock<Vec<Arc<dyn Any + Send + Sync>>> = RwLock::new(Vec::new());

/// The number of parameter sets in `PARTIAL_ROUNDS_CACHE`.
const PARTIAL_ROUNDS_CACHE_SIZE: usize = 16;

/// A parameter set and its partial rounds. The entry holds the parameters, so
/// their address is not reused while the entry is in the cache.
type CacheEntry<F, const RATE: usize> = (Arc<PoseidonParameters<F, RATE, 1>>, Option<Arc<PartialRounds<F>>>);

impl<F: PrimeField> PartialRounds<F> {
    /// Returns the partial rounds of `parameters` from `PARTIAL_ROUNDS_CACHE`,
    /// computing and caching them if they are not there.
    fn cached<const RATE: usize>(parameters: &Arc<PoseidonParameters<F, RATE, 1>>) -> Option<Arc<Self>> {
        let lookup = |entries: &[Arc<dyn Any + Send + Sync>]| {
            entries.iter().rev().find_map(|entry| {
                let (cached_parameters, partial_rounds) = entry.downcast_ref::<CacheEntry<F, RATE>>()?;
                (Arc::ptr_eq(cached_parameters, parameters) || cached_parameters == parameters)
                    .then(|| partial_rounds.clone())
            })
        };
        if let Some(partial_rounds) = lookup(&PARTIAL_ROUNDS_CACHE.read().unwrap_or_else(PoisonError::into_inner)) {
            return partial_rounds;
        }
        let partial_rounds = Self::new(parameters).map(Arc::new);
        let mut entries = PARTIAL_ROUNDS_CACHE.write().unwrap_or_else(PoisonError::into_inner);
        if lookup(&entries).is_none() {
            if entries.len() == PARTIAL_ROUNDS_CACHE_SIZE {
                entries.remove(0);
            }
            let entry: CacheEntry<F, RATE> = (parameters.clone(), partial_rounds.clone());
            entries.push(Arc::new(entry));
        }
        partial_rounds
    }

    /// Returns the partial rounds of `parameters`, or `None` if the parameters
    /// have no partial rounds, no full round before them, a round
    /// constant or MDS row whose length is not the state width, or an MDS
    /// matrix whose lower-right block of width `RATE` is singular.
    fn new<const RATE: usize>(parameters: &PoseidonParameters<F, RATE, 1>) -> Option<Self> {
        let width = RATE + 1;
        let PoseidonParameters { full_rounds, partial_rounds, ark, mds, .. } = parameters;
        let first_partial_round = full_rounds / 2;
        let last_partial_round = first_partial_round + partial_rounds;
        if first_partial_round == 0
            || *partial_rounds == 0
            || ark.len() < full_rounds + partial_rounds
            || ark.iter().take(full_rounds + partial_rounds).any(|row| row.len() != width)
            || mds.len() != width
            || mds.iter().any(|row| row.len() != width)
        {
            return None;
        }
        let dot = |a: &[F], b: &[F]| a.iter().zip_eq(b).map(|(a, b)| *a * b).sum::<F>();
        let mds_hat = mds[1..].iter().map(|row| row[1..].to_vec()).collect::<Vec<_>>();
        let mds_hat_inverse = invert(&mds_hat)?;

        // In a partial round, the round constants of every state element but the
        // first commute with the S-box, so they move through the MDS matrix into
        // the next round's constants.
        let mut constants = Vec::with_capacity(*partial_rounds);
        let mut carry = vec![F::zero(); width];
        for round_constants in &ark[first_partial_round..last_partial_round] {
            let mut sum = round_constants.iter().zip_eq(&carry).map(|(a, b)| *a + b).collect::<Vec<_>>();
            constants.push(sum[0]);
            sum[0] = F::zero();
            carry = mds.iter().map(|row| dot(row, &sum)).collect();
        }
        let last_ark = ark[last_partial_round].iter().zip_eq(&carry).map(|(a, b)| *a + b).collect();

        // From the last partial round to the first, diag(1, X) times the MDS
        // matrix is the round's sparse matrix times diag(1, X * mds_hat), with
        // X = I in the last round. Each diag(1, X * mds_hat) commutes with the
        // constant and the S-box of its round, so it moves into the round before,
        // and diag(1, mds_hat^partial_rounds) multiplies the MDS matrix of the last
        // full round. In the iteration for the k-th partial round from the end,
        // `row` is mds[0][1..] times mds_hat^-k, `column` is mds_hat^(k-1) times
        // the first column of mds below its first row, and `lower_rows` is
        // mds_hat^k times mds[1..].
        let mut rows = Vec::with_capacity(*partial_rounds);
        let mut columns = Vec::with_capacity(*partial_rounds);
        let mut row = mds[0][1..].to_vec();
        let mut column = mds[1..].iter().map(|row| row[0]).collect::<Vec<_>>();
        let mut lower_rows = mds[1..].to_vec();
        for _ in 0..*partial_rounds {
            row = (0..RATE).map(|j| row.iter().zip_eq(&mds_hat_inverse).map(|(a, b)| *a * b[j]).sum()).collect();
            rows.push(std::iter::once(mds[0][0]).chain(row.iter().copied()).collect::<Vec<_>>());
            let next_column = mds_hat.iter().map(|mds_hat_row| dot(mds_hat_row, &column)).collect();
            columns.push(std::mem::replace(&mut column, next_column));
            lower_rows = mds_hat
                .iter()
                .map(|mds_hat_row| {
                    (0..width).map(|j| mds_hat_row.iter().zip_eq(&lower_rows).map(|(a, b)| *a * b[j]).sum()).collect()
                })
                .collect();
        }
        let first_matrix = std::iter::once(mds[0].clone()).chain(lower_rows).collect();
        let rounds = constants
            .into_iter()
            .zip_eq(rows.into_iter().rev())
            .zip_eq(columns.into_iter().rev())
            .map(|((constant, row), column)| PartialRound { constant, row, column })
            .collect();

        Some(Self { first_matrix, rounds, last_ark })
    }
}

/// Returns the inverse of the square matrix `matrix`, or `None` if it is
/// singular.
fn invert<F: PrimeField>(matrix: &[Vec<F>]) -> Option<Vec<Vec<F>>> {
    let n = matrix.len();
    let mut matrix = matrix.to_vec();
    let mut inverse = (0..n)
        .map(|i| (0..n).map(|j| if i == j { F::one() } else { F::zero() }).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    for column in 0..n {
        let pivot = (column..n).find(|&row| !matrix[row][column].is_zero())?;
        matrix.swap(column, pivot);
        inverse.swap(column, pivot);
        let scale = matrix[column][column].inverse()?;
        matrix[column].iter_mut().chain(inverse[column].iter_mut()).for_each(|x| *x *= scale);
        let (pivot_row, pivot_inverse_row) = (matrix[column].clone(), inverse[column].clone());
        for row in (0..n).filter(|&row| row != column) {
            let factor = matrix[row][column];
            for (x, y) in matrix[row].iter_mut().zip_eq(&pivot_row) {
                *x -= factor * y;
            }
            for (x, y) in inverse[row].iter_mut().zip_eq(&pivot_inverse_row) {
                *x -= factor * y;
            }
        }
    }
    Some(inverse)
}

/// Applies the permutation of `parameters` to `state`, with the partial rounds
/// in the sparse form `partial_rounds` of the same parameters.
#[inline]
fn permute_sparse<F: PrimeField, const RATE: usize>(
    parameters: &PoseidonParameters<F, RATE, 1>,
    partial_rounds: &PartialRounds<F>,
    state: &mut State<F, RATE, 1>,
) {
    let pow_alpha_in_place = pow_alpha_in_place::<F>(parameters.alpha);
    let first_partial_round = parameters.full_rounds / 2;
    let last_partial_round = first_partial_round + parameters.partial_rounds;
    let num_rounds = parameters.full_rounds + parameters.partial_rounds;

    let mut current: SmallVec<[F; 10]> = state.iter().copied().collect();
    let mut next = current.clone();
    let mut full_round = |current: &mut SmallVec<[F; 10]>, ark: &[F], matrix: &[Vec<F>]| {
        for (x, c) in current.iter_mut().zip_eq(ark) {
            *x += c;
            pow_alpha_in_place(x);
        }
        for (x, row) in next.iter_mut().zip_eq(matrix) {
            *x = F::sum_of_products(current, row);
        }
        std::mem::swap(current, &mut next);
    };

    for round in 0..first_partial_round {
        let matrix = if round + 1 == first_partial_round { &partial_rounds.first_matrix } else { &parameters.mds };
        full_round(&mut current, &parameters.ark[round], matrix);
    }
    for round in &partial_rounds.rounds {
        current[0] += round.constant;
        pow_alpha_in_place(&mut current[0]);
        let first = F::sum_of_products(&current, &round.row);
        // The state has RATE + 1 elements, so it is not empty.
        let (head, tail) = current.split_first_mut().unwrap();
        for (x, c) in tail.iter_mut().zip_eq(&round.column) {
            *x += *c * *head;
        }
        *head = first;
    }
    for round in last_partial_round..num_rounds {
        let ark = if round == last_partial_round { &partial_rounds.last_ark } else { &parameters.ark[round] };
        full_round(&mut current, ark, &parameters.mds);
    }

    for (x, y) in state.iter_mut().zip_eq(current) {
        *x = y;
    }
}

/// Returns the S-box function for the exponent `alpha`.
///
/// # Panics
///
/// Panics if `alpha` is not 3, 5 or 17.
fn pow_alpha_in_place<F: PrimeField>(alpha: u64) -> fn(&mut F) {
    match alpha {
        3 => pow_3_in_place,
        5 => pow_5_in_place,
        17 => pow_17_in_place,
        alpha => panic!("No optimized S-box for alpha = {alpha}"),
    }
}

// S-box functions to raise state elements to the values of alpha present in the
// codebase: 3, 5 and 17. These are more performant than the general pow
// function.
#[inline]
fn pow_3_in_place<F: PrimeField>(val: &mut F) {
    let val_copy = *val;
    val.square_in_place();
    val.mul_assign(val_copy);
}

#[inline]
fn pow_5_in_place<F: PrimeField>(val: &mut F) {
    let val_copy = *val;
    val.square_in_place();
    val.square_in_place();
    val.mul_assign(val_copy);
}

#[inline]
fn pow_17_in_place<F: PrimeField>(val: &mut F) {
    let val_copy = *val;
    val.square_in_place();
    val.square_in_place();
    val.square_in_place();
    val.square_in_place();
    val.mul_assign(val_copy);
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_curves::bls12_377::{Fq, Fr};
    use snarkvm_fields::{One, PoseidonDefaultField, Zero};
    use snarkvm_utilities::{TestRng, Uniform};

    use serial_test::serial;

    /// Returns a sponge of `parameters` whose state is `state`.
    fn sponge_with_state<F: PrimeField, const RATE: usize>(
        parameters: &Arc<PoseidonParameters<F, RATE, 1>>,
        state: &[F],
    ) -> PoseidonSponge<F, RATE, 1> {
        let mut sponge = PoseidonSponge::new_with_parameters(parameters);
        for (x, y) in sponge.state.iter_mut().zip_eq(state) {
            *x = *y;
        }
        sponge
    }

    /// Checks that `chain` permutations of `state` give the same state with
    /// `permute` as with `permute_dense`.
    fn check_state<F: PrimeField, const RATE: usize>(
        parameters: &Arc<PoseidonParameters<F, RATE, 1>>,
        state: &[F],
        chain: usize,
    ) {
        let mut sparse = sponge_with_state(parameters, state);
        let mut dense = sparse.clone();
        for _ in 0..chain {
            sparse.permute();
            dense.permute_dense();
        }
        assert_eq!(sparse.state.iter().collect_vec(), dense.state.iter().collect_vec(), "{chain} from {state:?}");
    }

    /// Checks the sparse permutation of `parameters` against the dense one on
    /// states of 0, 1 and p - 1, on random states, and on chains of
    /// permutations.
    fn check_parameters<F: PrimeField, const RATE: usize>(
        parameters: PoseidonParameters<F, RATE, 1>,
        rng: &mut TestRng,
    ) {
        let parameters = Arc::new(parameters);
        assert!(PoseidonSponge::new_with_parameters(&parameters).partial_rounds.is_some());
        let width = RATE + 1;
        let edges = [F::zero(), F::one(), -F::one()];
        if width <= 5 {
            for state in (0..width).map(|_| edges).multi_cartesian_product() {
                check_state(&parameters, &state, 1);
            }
        } else {
            for (a, b) in edges.into_iter().cartesian_product(edges) {
                for i in 0..width {
                    let state = (0..width).map(|j| if i == j { b } else { a }).collect_vec();
                    check_state(&parameters, &state, 1);
                }
            }
        }
        for _ in 0..100 {
            let state = (0..width).map(|_| F::rand(rng)).collect_vec();
            check_state(&parameters, &state, 1);
        }
        for chain in [2, 5, 200] {
            let state = (0..width).map(|_| F::rand(rng)).collect_vec();
            check_state(&parameters, &state, chain);
        }
    }

    /// Returns parameters with the given rounds and `alpha`, random round
    /// constants, and the MDS matrix of the default parameters of `F` and
    /// `RATE`, or a random matrix if there are none.
    fn parameters_with_rounds<F: PrimeField, const RATE: usize>(
        full_rounds: usize,
        partial_rounds: usize,
        alpha: u64,
        rng: &mut TestRng,
    ) -> PoseidonParameters<F, RATE, 1> {
        let ark = (0..full_rounds + partial_rounds).map(|_| (0..RATE + 1).map(|_| F::rand(rng)).collect()).collect();
        let mds = F::default_poseidon_parameters::<RATE>()
            .map(|parameters| parameters.mds)
            .unwrap_or_else(|_| (0..RATE + 1).map(|_| (0..RATE + 1).map(|_| F::rand(rng)).collect()).collect());
        PoseidonParameters { full_rounds, partial_rounds, alpha, ark, mds }
    }

    #[test]
    #[serial]
    fn test_sparse_permutation_fq() {
        let rng = &mut TestRng::default();
        check_parameters(Fq::default_poseidon_parameters::<2>().unwrap(), rng);
        check_parameters(Fq::default_poseidon_parameters::<3>().unwrap(), rng);
        check_parameters(Fq::default_poseidon_parameters::<4>().unwrap(), rng);
        check_parameters(Fq::default_poseidon_parameters::<5>().unwrap(), rng);
        check_parameters(Fq::default_poseidon_parameters::<6>().unwrap(), rng);
        check_parameters(Fq::default_poseidon_parameters::<7>().unwrap(), rng);
        check_parameters(Fq::default_poseidon_parameters::<8>().unwrap(), rng);
    }

    #[test]
    #[serial]
    fn test_sparse_permutation_fr() {
        let rng = &mut TestRng::default();
        check_parameters(Fr::default_poseidon_parameters::<2>().unwrap(), rng);
        check_parameters(Fr::default_poseidon_parameters::<3>().unwrap(), rng);
        check_parameters(Fr::default_poseidon_parameters::<4>().unwrap(), rng);
        check_parameters(Fr::default_poseidon_parameters::<5>().unwrap(), rng);
        check_parameters(Fr::default_poseidon_parameters::<6>().unwrap(), rng);
        check_parameters(Fr::default_poseidon_parameters::<7>().unwrap(), rng);
        check_parameters(Fr::default_poseidon_parameters::<8>().unwrap(), rng);
    }

    #[test]
    #[serial]
    fn test_sparse_permutation_round_counts() {
        let rng = &mut TestRng::default();
        for (full_rounds, partial_rounds) in [(2, 1), (2, 2), (3, 1), (3, 4), (4, 1), (5, 3), (6, 5), (8, 31), (10, 40)]
        {
            for alpha in [3, 5, 17] {
                check_parameters(parameters_with_rounds::<Fq, 2>(full_rounds, partial_rounds, alpha, rng), rng);
                check_parameters(parameters_with_rounds::<Fr, 1>(full_rounds, partial_rounds, alpha, rng), rng);
                check_parameters(parameters_with_rounds::<Fr, 4>(full_rounds, partial_rounds, alpha, rng), rng);
            }
        }
    }

    #[test]
    #[serial]
    fn test_sparse_permutation_random_matrix() {
        let rng = &mut TestRng::default();
        for _ in 0..5 {
            let mut parameters = parameters_with_rounds::<Fq, 2>(8, 31, 17, rng);
            parameters.mds = (0..3).map(|_| (0..3).map(|_| Fq::rand(rng)).collect()).collect();
            check_parameters(parameters, rng);
        }
    }

    #[test]
    #[serial]
    fn test_sparse_permutation_fallback() {
        let rng = &mut TestRng::default();
        let default = parameters_with_rounds::<Fq, 2>(8, 31, 17, rng);
        let mut singular = default.clone();
        singular.mds[2] = vec![Fq::rand(rng), singular.mds[1][1], singular.mds[1][2]];
        let mut short_ark = default.clone();
        short_ark.ark.pop();
        let mut long_ark_row = default.clone();
        long_ark_row.ark[38].push(Fq::one());
        let mut short_mds_row = default.clone();
        short_mds_row.mds[1].pop();
        let mut extra_mds_row = default.clone();
        extra_mds_row.mds.push(vec![Fq::one(); 3]);
        let cases = [
            parameters_with_rounds::<Fq, 2>(0, 31, 17, rng),
            parameters_with_rounds::<Fq, 2>(1, 31, 17, rng),
            parameters_with_rounds::<Fq, 2>(8, 0, 17, rng),
            singular,
            short_ark,
            long_ark_row,
            short_mds_row,
            extra_mds_row,
        ];
        for parameters in cases {
            assert!(PartialRounds::new(&parameters).is_none(), "{parameters:?}");
            assert!(PoseidonSponge::new_with_parameters(&Arc::new(parameters)).partial_rounds.is_none());
        }
        assert!(PartialRounds::new(&default).is_some());
    }

    #[test]
    #[serial]
    fn test_partial_rounds_cache() {
        let parameters = PoseidonSponge::<Fq, 2, 1>::sample_parameters();
        let equal_parameters = PoseidonSponge::<Fq, 2, 1>::sample_parameters();
        assert!(!Arc::ptr_eq(&parameters, &equal_parameters));
        let a = PoseidonSponge::new_with_parameters(&parameters).partial_rounds.unwrap();
        let b = PoseidonSponge::new_with_parameters(&parameters).partial_rounds.unwrap();
        let c = PoseidonSponge::new_with_parameters(&equal_parameters).partial_rounds.unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert!(Arc::ptr_eq(&a, &c));

        // Parameters that differ in one round constant have their own partial rounds.
        let mut other_parameters = (*parameters).clone();
        other_parameters.ark[20][1] += Fq::one();
        let other_parameters = Arc::new(other_parameters);
        let d = PoseidonSponge::new_with_parameters(&other_parameters).partial_rounds.unwrap();
        assert!(!Arc::ptr_eq(&a, &d));
        let rng = &mut TestRng::default();
        let state = (0..3).map(|_| Fq::rand(rng)).collect_vec();
        check_state(&other_parameters, &state, 1);

        // The cache keeps the most recent parameter sets, and recomputes an evicted
        // one. Tests that run concurrently may insert the default parameter sets
        // of a few rates, so only the newest half of these is checked.
        let others = (0..PARTIAL_ROUNDS_CACHE_SIZE)
            .map(|_| Arc::new(parameters_with_rounds::<Fq, 2>(8, 31, 17, rng)))
            .collect_vec();
        let partial_rounds =
            others.iter().map(|p| PoseidonSponge::new_with_parameters(p).partial_rounds.unwrap()).collect_vec();
        for (p, r) in others.iter().zip_eq(&partial_rounds).skip(PARTIAL_ROUNDS_CACHE_SIZE / 2) {
            assert!(Arc::ptr_eq(&PoseidonSponge::new_with_parameters(p).partial_rounds.unwrap(), r));
        }
        let e = PoseidonSponge::new_with_parameters(&parameters).partial_rounds.unwrap();
        assert!(!Arc::ptr_eq(&a, &e));
        check_state(&parameters, &state, 1);
    }

    #[test]
    fn test_invert() {
        let rng = &mut TestRng::default();
        for n in 1..=8 {
            let matrix = (0..n).map(|_| (0..n).map(|_| Fq::rand(rng)).collect_vec()).collect_vec();
            let inverse = invert(&matrix).unwrap();
            for (i, row) in matrix.iter().enumerate() {
                for j in 0..n {
                    let product: Fq = row.iter().zip_eq(&inverse).map(|(a, b)| *a * b[j]).sum();
                    assert_eq!(product, if i == j { Fq::one() } else { Fq::zero() });
                }
            }
            let mut singular = matrix.clone();
            let factor = if n == 1 { Fq::zero() } else { Fq::from(2u8) };
            singular[n - 1] = singular[0].iter().map(|x| *x * factor).collect();
            assert!(invert(&singular).is_none());
        }
        // A zero first pivot needs a row swap.
        let matrix = vec![vec![Fq::zero(), Fq::one()], vec![Fq::one(), Fq::one()]];
        let inverse = invert(&matrix).unwrap();
        assert_eq!(inverse, vec![vec![-Fq::one(), Fq::one()], vec![Fq::one(), Fq::zero()]]);
    }
}
