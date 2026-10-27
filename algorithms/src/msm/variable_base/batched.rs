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

use snarkvm_curves::{AffineCurve, ProjectiveCurve};
use snarkvm_fields::{Field, One, PrimeField, Zero};
use snarkvm_utilities::{BigInteger, BitIteratorBE, cfg_into_iter};

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

#[cfg(target_arch = "x86_64")]
use crate::{prefetch_slice, prefetch_slice_write};

#[derive(Copy, Clone, Debug)]
pub struct BucketPosition {
    pub bucket_index: u32,
    pub scalar_index: u32,
}

impl Eq for BucketPosition {}

impl PartialEq for BucketPosition {
    fn eq(&self, other: &Self) -> bool {
        self.bucket_index == other.bucket_index
    }
}

impl Ord for BucketPosition {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.bucket_index.cmp(&other.bucket_index)
    }
}

#[allow(clippy::non_canonical_partial_ord_impl)]
impl PartialOrd for BucketPosition {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.bucket_index.partial_cmp(&other.bucket_index)
    }
}

/// Returns a batch size of sufficient size to amortize the cost of an
/// inversion, while attempting to reduce strain to the CPU cache.
#[inline]
const fn batch_size(msm_size: usize) -> usize {
    // These values are determined empirically using performance benchmarks for
    // BLS12-377 on Intel, AMD, and M1 machines. These values are determined by
    // taking the L1 and L2 cache sizes and dividing them by the size of group
    // elements (i.e. 96 bytes).
    //
    // As the algorithm itself requires caching additional values beyond the group
    // elements, the ideal batch size is less than expected, to accommodate
    // those values. In general, it was found that undershooting is better than
    // overshooting this heuristic.
    if cfg!(target_arch = "x86_64") && msm_size < 500_000 {
        // Assumes an L1 cache size of 32KiB. Note that larger cache sizes
        // are not negatively impacted by this value, however smaller L1 cache sizes
        // are.
        300
    } else {
        // Assumes an L2 cache size of 1MiB. Note that larger cache sizes
        // are not negatively impacted by this value, however smaller L2 cache sizes
        // are.
        3000
    }
}

/// If `(j, k)` is the `i`-th entry in `index`, then this method sets
/// `bases[j] = bases[j] + bases[k]`. The state of `bases[k]` becomes
/// unspecified.
#[inline]
fn batch_add_in_place_same_slice<G: AffineCurve>(bases: &mut [G], index: &[(u32, u32)]) {
    let mut inversion_tmp = G::BaseField::one();
    let half = G::BaseField::half();

    #[cfg(target_arch = "x86_64")]
    let mut prefetch_iter = index.iter();
    #[cfg(target_arch = "x86_64")]
    prefetch_iter.next();

    // We run two loops over the data separated by an inversion
    for (idx, idy) in index.iter() {
        #[cfg(target_arch = "x86_64")]
        prefetch_slice!(G, bases, bases, prefetch_iter);

        let (a, b) = if idx < idy {
            let (x, y) = bases.split_at_mut(*idy as usize);
            (&mut x[*idx as usize], &mut y[0])
        } else {
            let (x, y) = bases.split_at_mut(*idx as usize);
            (&mut y[0], &mut x[*idy as usize])
        };
        G::batch_add_loop_1(a, b, &half, &mut inversion_tmp);
    }

    inversion_tmp = inversion_tmp.inverse().unwrap(); // this is always in Fp*

    #[cfg(target_arch = "x86_64")]
    let mut prefetch_iter = index.iter().rev();
    #[cfg(target_arch = "x86_64")]
    prefetch_iter.next();

    for (idx, idy) in index.iter().rev() {
        #[cfg(target_arch = "x86_64")]
        prefetch_slice!(G, bases, bases, prefetch_iter);

        let (a, b) = if idx < idy {
            let (x, y) = bases.split_at_mut(*idy as usize);
            (&mut x[*idx as usize], y[0])
        } else {
            let (x, y) = bases.split_at_mut(*idx as usize);
            (&mut y[0], x[*idy as usize])
        };
        G::batch_add_loop_2(a, b, &mut inversion_tmp);
    }
}

/// If `(j, k)` is the `i`-th entry in `index`, then this method performs one of
/// two actions:
/// * `addition_result[i] = bases[j] + bases[k]`
/// * `addition_result[i] = bases[j];
///
/// It uses `scratch_space` to store intermediate values, and clears it after
/// use.
#[inline]
fn batch_add_write<G: AffineCurve>(
    bases: &[G],
    index: &[(u32, u32)],
    addition_result: &mut Vec<G>,
    scratch_space: &mut Vec<Option<G>>,
) {
    let mut inversion_tmp = G::BaseField::one();
    let half = G::BaseField::half();

    #[cfg(target_arch = "x86_64")]
    let mut prefetch_iter = index.iter();
    #[cfg(target_arch = "x86_64")]
    prefetch_iter.next();

    // We run two loops over the data separated by an inversion
    for (idx, idy) in index.iter() {
        #[cfg(target_arch = "x86_64")]
        prefetch_slice_write!(G, bases, bases, prefetch_iter);

        if *idy == !0u32 {
            addition_result.push(bases[*idx as usize]);
            scratch_space.push(None);
        } else {
            let (mut a, mut b) = (bases[*idx as usize], bases[*idy as usize]);
            G::batch_add_loop_1(&mut a, &mut b, &half, &mut inversion_tmp);
            addition_result.push(a);
            scratch_space.push(Some(b));
        }
    }

    inversion_tmp = inversion_tmp.inverse().unwrap(); // this is always in Fp*

    for (a, op_b) in addition_result.iter_mut().rev().zip(scratch_space.iter().rev()) {
        if let Some(b) = op_b {
            G::batch_add_loop_2(a, *b, &mut inversion_tmp);
        }
    }
    scratch_space.clear();
}

#[inline]
pub(super) fn batch_add<G: AffineCurve>(
    num_buckets: usize,
    bases: &[G],
    bucket_positions: &mut [BucketPosition],
) -> Vec<G> {
    assert!(bases.len() >= bucket_positions.len());
    assert!(!bases.is_empty());

    // Fetch the ideal batch size for the number of bases.
    let batch_size = batch_size(bases.len());

    // Sort the buckets by their bucket index (not scalar index).
    bucket_positions.sort_unstable();

    let mut num_scalars = bucket_positions.len();
    let mut all_ones = true;
    let mut new_scalar_length = 0;
    let mut global_counter = 0;
    let mut local_counter = 1;
    let mut number_of_bases_in_batch = 0;

    let mut instr = Vec::<(u32, u32)>::with_capacity(batch_size);
    let mut new_bases = Vec::with_capacity(bases.len());
    let mut scratch_space = Vec::with_capacity(batch_size / 2);

    // In the first loop, copy the results of the first in-place addition tree to
    // the vector `new_bases`.
    while global_counter < num_scalars {
        let current_bucket = bucket_positions[global_counter].bucket_index;
        while global_counter + 1 < num_scalars && bucket_positions[global_counter + 1].bucket_index == current_bucket {
            global_counter += 1;
            local_counter += 1;
        }
        if current_bucket >= num_buckets as u32 {
            local_counter = 1;
        } else if local_counter > 1 {
            // all ones is false if next len is not 1
            if local_counter > 2 {
                all_ones = false;
            }
            let is_odd = local_counter % 2 == 1;
            let half = local_counter / 2;
            for i in 0..half {
                instr.push((
                    bucket_positions[global_counter - (local_counter - 1) + 2 * i].scalar_index,
                    bucket_positions[global_counter - (local_counter - 1) + 2 * i + 1].scalar_index,
                ));
                bucket_positions[new_scalar_length + i] =
                    BucketPosition { bucket_index: current_bucket, scalar_index: (new_scalar_length + i) as u32 };
            }
            if is_odd {
                instr.push((bucket_positions[global_counter].scalar_index, !0u32));
                bucket_positions[new_scalar_length + half] =
                    BucketPosition { bucket_index: current_bucket, scalar_index: (new_scalar_length + half) as u32 };
            }
            // Reset the local_counter and update state
            new_scalar_length += half + (local_counter % 2);
            number_of_bases_in_batch += half;
            local_counter = 1;

            // When the number of bases in a batch crosses the threshold, perform a batch
            // addition.
            if number_of_bases_in_batch >= batch_size / 2 {
                // We need instructions for copying data in the case of noops.
                // We encode noops/copies as !0u32
                batch_add_write(bases, &instr, &mut new_bases, &mut scratch_space);

                instr.clear();
                number_of_bases_in_batch = 0;
            }
        } else {
            instr.push((bucket_positions[global_counter].scalar_index, !0u32));
            bucket_positions[new_scalar_length] =
                BucketPosition { bucket_index: current_bucket, scalar_index: new_scalar_length as u32 };
            new_scalar_length += 1;
        }
        global_counter += 1;
    }
    if !instr.is_empty() {
        batch_add_write(bases, &instr, &mut new_bases, &mut scratch_space);
        instr.clear();
    }
    global_counter = 0;
    number_of_bases_in_batch = 0;
    local_counter = 1;
    num_scalars = new_scalar_length;
    new_scalar_length = 0;

    // Next, perform all the updates in place.
    while !all_ones {
        all_ones = true;
        while global_counter < num_scalars {
            let current_bucket = bucket_positions[global_counter].bucket_index;
            while global_counter + 1 < num_scalars
                && bucket_positions[global_counter + 1].bucket_index == current_bucket
            {
                global_counter += 1;
                local_counter += 1;
            }
            if current_bucket >= num_buckets as u32 {
                local_counter = 1;
            } else if local_counter > 1 {
                // all ones is false if next len is not 1
                if local_counter != 2 {
                    all_ones = false;
                }
                let is_odd = local_counter % 2 == 1;
                let half = local_counter / 2;
                for i in 0..half {
                    instr.push((
                        bucket_positions[global_counter - (local_counter - 1) + 2 * i].scalar_index,
                        bucket_positions[global_counter - (local_counter - 1) + 2 * i + 1].scalar_index,
                    ));
                    bucket_positions[new_scalar_length + i] =
                        bucket_positions[global_counter - (local_counter - 1) + 2 * i];
                }
                if is_odd {
                    bucket_positions[new_scalar_length + half] = bucket_positions[global_counter];
                }
                // Reset the local_counter and update state
                new_scalar_length += half + (local_counter % 2);
                number_of_bases_in_batch += half;
                local_counter = 1;

                if number_of_bases_in_batch >= batch_size / 2 {
                    batch_add_in_place_same_slice(&mut new_bases, &instr);
                    instr.clear();
                    number_of_bases_in_batch = 0;
                }
            } else {
                bucket_positions[new_scalar_length] = bucket_positions[global_counter];
                new_scalar_length += 1;
            }
            global_counter += 1;
        }
        // If there are any remaining unprocessed instructions, proceed to perform batch
        // addition.
        if !instr.is_empty() {
            batch_add_in_place_same_slice(&mut new_bases, &instr);
            instr.clear();
        }
        global_counter = 0;
        number_of_bases_in_batch = 0;
        local_counter = 1;
        num_scalars = new_scalar_length;
        new_scalar_length = 0;
    }

    let mut res = vec![Zero::zero(); num_buckets];
    for bucket_position in bucket_positions.iter().take(num_scalars) {
        res[bucket_position.bucket_index as usize] = new_bases[bucket_position.scalar_index as usize];
    }
    res
}

#[inline]
fn batched_window<G: AffineCurve>(
    bases: &[G],
    scalars: &[<G::ScalarField as PrimeField>::BigInteger],
    w_start: usize,
    c: usize,
) -> (G::Projective, usize) {
    // We don't need the "zero" bucket, so we only have 2^c - 1 buckets
    let window_size = if !w_start.is_multiple_of(c) { w_start % c } else { c };
    let num_buckets = (1 << window_size) - 1;

    let mut bucket_positions: Vec<_> = scalars
        .iter()
        .enumerate()
        .map(|(scalar_index, &scalar)| {
            let mut scalar = scalar;

            // We right-shift by w_start, thus getting rid of the lower bits.
            scalar.divn(w_start as u32);

            // We mod the remaining bits by the window size.
            let scalar = (scalar.as_ref()[0] % (1 << c)) as i32;

            BucketPosition { bucket_index: (scalar - 1) as u32, scalar_index: scalar_index as u32 }
        })
        .collect();

    let buckets = batch_add(num_buckets, bases, &mut bucket_positions);

    let mut res = G::Projective::zero();
    let mut running_sum = G::Projective::zero();
    for b in buckets.into_iter().rev() {
        running_sum.add_assign_mixed(&b);
        res += &running_sum;
    }

    (res, window_size)
}

pub fn msm<G: AffineCurve>(bases: &[G], scalars: &[<G::ScalarField as PrimeField>::BigInteger]) -> G::Projective {
    // Below 32 bases, each window of the bucket method holds too few points to
    // amortize its batched inversions, and double-and-add is several times
    // faster.
    if bases.len() < 32 {
        let num_bits = G::ScalarField::size_in_bits();
        let bigint_size = <G::ScalarField as PrimeField>::BigInteger::NUM_LIMBS * 64;
        let mut bits =
            scalars.iter().map(|s| BitIteratorBE::new(s.as_ref()).skip(bigint_size - num_bits)).collect::<Vec<_>>();
        let mut sum = G::Projective::zero();

        let mut encountered_one = false;
        for _ in 0..num_bits {
            if encountered_one {
                sum.double_in_place();
            }
            for (bits, base) in bits.iter_mut().zip(bases) {
                if let Some(true) = bits.next() {
                    sum.add_assign_mixed(base);
                    encountered_one = true;
                }
            }
        }
        debug_assert!(bits.iter_mut().all(|b| b.next().is_none()));
        sum
    } else {
        // Determine the bucket size `c` (chosen empirically).
        let c = crate::msm::ln_without_floats(scalars.len()) + 2;

        let num_bits = <G::ScalarField as PrimeField>::size_in_bits();

        // Each window is of size `c`.
        // We divide up the bits 0..num_bits into windows of size `c`, and
        // in parallel process each such window.
        let window_sums: Vec<_> =
            cfg_into_iter!(0..num_bits).step_by(c).map(|w_start| batched_window(bases, scalars, w_start, c)).collect();

        // We store the sum for the lowest window.
        let (lowest, window_sums) = window_sums.split_first().unwrap();

        // We're traversing windows from high to low.
        window_sums.iter().rev().fold(G::Projective::zero(), |mut total, (sum_i, window_size)| {
            total += sum_i;
            for _ in 0..*window_size {
                total.double_in_place();
            }
            total
        }) + lowest.0
    }
}
