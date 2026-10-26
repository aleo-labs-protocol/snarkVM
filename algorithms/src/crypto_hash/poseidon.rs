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

use smallvec::SmallVec;
use std::{
    iter::Peekable,
    ops::{Index, IndexMut},
    sync::Arc,
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
        let pow_alpha_in_place: fn(&mut F) = match self.parameters.alpha {
            3 => pow_3_in_place,
            5 => pow_5_in_place,
            17 => pow_17_in_place,
            alpha => panic!("No optimized S-box for alpha = {alpha}"),
        };

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
