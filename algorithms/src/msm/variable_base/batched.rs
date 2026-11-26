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

use std::borrow::Cow;

use snarkvm_curves::{AffineCurve, ProjectiveCurve};
use snarkvm_fields::{Field, One, PrimeField, Zero};
use snarkvm_utilities::{BigInteger, cfg_into_iter};

use itertools::Itertools;

use rayon::prelude::*;

#[cfg(target_arch = "x86_64")]
use crate::{prefetch_slice, prefetch_slice_write};

/// Tag bit in [`BucketPosition::scalar_index`] marking a negated base during
/// the initial read from `bases` in [`batch_add_write`].
///
/// Hazard: During the first reduction pass (`batch_add` -> `batch_add_write`),
/// bit 31 (`SIGN_BIT`) of `BucketPosition::scalar_index` indicates that the
/// base point must be negated, while `NOOP` (`u32::MAX`) marks single-point
/// copies in `instr`. Every slice index into `bases` (including `x86_64` cache
/// prefetches) must mask out `SIGN_BIT` with `SCALAR_INDEX_MASK`, and the
/// number of active bases must stay strictly below `SCALAR_INDEX_MASK as usize`
/// (`2^31 - 1`) so `(scalar_index | SIGN_BIT)` never collides with `NOOP`.
/// Subsequent in-place passes over `new_bases` write untagged indices.
const SIGN_BIT: u32 = 1 << 31;
const SCALAR_INDEX_MASK: u32 = !SIGN_BIT;
const NOOP: u32 = u32::MAX;

/// Window-width bounds for [`best_window_size`].
///
/// With signed digits, an interior window of width `c` allocates `2^(c - 1)`
/// affine buckets (`8,192` buckets at `c = 14` and `16,384` at `c = 15`, or
/// `832 KiB` and `1,664 KiB` for 104-byte `G1Affine` points), bounding
/// per-window bucket memory when windows run in parallel.
const MIN_BUCKET_WINDOW: usize = 5;
const DEFAULT_MAX_BUCKET_WINDOW: usize = 14;
const LARGE_MSM_MAX_BUCKET_WINDOW: usize = 15;

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

#[inline]
fn load_signed_base<G: AffineCurve>(bases: &[G], tagged_index: u32) -> G {
    let base = bases[(tagged_index & SCALAR_INDEX_MASK) as usize];
    if tagged_index & SIGN_BIT != 0 { -base } else { base }
}

/// If `(j, k)` is the `i`-th entry in `index`, then this method performs one of
/// two actions on the signed-tagged indices `j` and `k`:
/// * `addition_result[i] = signed_base(j) + signed_base(k)`
/// * `addition_result[i] = signed_base(j)` when `k == NOOP`
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

        if *idy == NOOP {
            addition_result.push(load_signed_base(bases, *idx));
            scratch_space.push(None);
        } else {
            let (mut a, mut b) = (load_signed_base(bases, *idx), load_signed_base(bases, *idy));
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
    if bucket_positions.is_empty() {
        return vec![Zero::zero(); num_buckets];
    }

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
    let mut new_bases = Vec::with_capacity(bucket_positions.len());
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
                instr.push((bucket_positions[global_counter].scalar_index, NOOP));
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
                // We encode noops/copies as `NOOP`.
                batch_add_write(bases, &instr, &mut new_bases, &mut scratch_space);

                instr.clear();
                number_of_bases_in_batch = 0;
            }
        } else {
            instr.push((bucket_positions[global_counter].scalar_index, NOOP));
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

/// Returns `true` if every bit of `scalar` at or above `num_bits` is zero.
#[inline]
pub(super) fn scalar_fits_in_bits<B: BigInteger>(scalar: &B, num_bits: usize) -> bool {
    let limbs = scalar.as_ref();
    let top_limb = num_bits / 64;
    let rem_bits = num_bits % 64;
    if let Some(&word) = limbs.get(top_limb)
        && (word >> rem_bits) != 0
    {
        return false;
    }
    limbs.iter().skip(top_limb + 1).all(|&w| w == 0)
}

/// Extracts `width` (`<= 16`) bits starting at `bit_offset` from `limbs`,
/// masking every bit at or above `num_bits` to zero.
#[inline]
fn extract_bits(limbs: &[u64], bit_offset: usize, width: usize, num_bits: usize) -> u32 {
    if bit_offset >= num_bits || width == 0 {
        return 0;
    }
    let valid = width.min(num_bits - bit_offset);
    let (limb, shift) = (bit_offset / 64, bit_offset % 64);
    let Some(&low) = limbs.get(limb) else {
        return 0;
    };
    let mut value = low >> shift;
    if shift + valid > 64
        && let Some(&high) = limbs.get(limb + 1)
    {
        value |= high << (64 - shift);
    }
    (value & ((1u64 << valid) - 1)) as u32
}

/// 64-bit word with every `c`-th bit set starting at bit 0, for `c` in
/// `2..=16`.
const BASE_REPEAT: [u64; 17] = {
    let mut table = [0u64; 17];
    let mut c = 2;
    while c <= 16 {
        let mut repeat = 0u64;
        let mut bit = 0;
        while bit < 64 {
            repeat |= 1u64 << bit;
            bit += c;
        }
        table[c] = repeat;
        c += 1;
    }
    table
};

/// First four 64-bit limbs of `sum_{k >= 0} 2^(k * c + c - 1)` for `c` in
/// `2..=16`.
const HALF_PATTERNS: [[u64; 4]; 17] = {
    let mut table = [[0u64; 4]; 17];
    let mut c = 2;
    while c <= 16 {
        let mut limb = 0;
        while limb < 4 {
            let first_bit = (2 * c - 1 - ((64 * limb) % c)) % c;
            table[c][limb] = BASE_REPEAT[c] << first_bit;
            limb += 1;
        }
        c += 1;
    }
    table
};

/// Returns limb `limb` of `sum_{k >= 0} 2^(k * c + c - 1)`.
#[inline]
const fn half_pattern_limb(c: usize, limb: usize) -> u64 {
    if limb < 4 {
        HALF_PATTERNS[c][limb]
    } else {
        let first_bit = (2 * c - 1 - ((64 * limb) % c)) % c;
        BASE_REPEAT[c] << first_bit
    }
}

/// Returns the incoming carry (`0` or `1`) into `window` (`bit_offset = window
/// * c <= num_bits`) under signed base-`2^c` recoding.
///
/// With signed digits bounded above by `2^(c - 1)`, the maximum value of the
/// low `w * c` bits that produces no carry into `window = w` is
/// `sum_{k = 0}^{w - 1} 2^(k * c + c - 1)`. Comparing the low `w * c` bits of
/// `limbs` against that periodic bit pattern decides the carry in at most
/// `limbs.len()` word comparisons.
#[inline]
fn carry_into_window(limbs: &[u64], bit_offset: usize, c: usize) -> u32 {
    if bit_offset == 0 {
        return 0;
    }
    let top_limb = (bit_offset - 1) / 64;
    let used_bits = ((bit_offset - 1) % 64) + 1;
    let mask = u64::MAX >> (64 - used_bits);

    let s_top = limbs.get(top_limb).copied().unwrap_or(0) & mask;
    let p_top = half_pattern_limb(c, top_limb) & mask;
    if s_top != p_top {
        return u32::from(s_top > p_top);
    }
    for limb in (0..top_limb).rev() {
        let s_word = limbs.get(limb).copied().unwrap_or(0);
        let p_word = half_pattern_limb(c, limb);
        if s_word != p_word {
            return u32::from(s_word > p_word);
        }
    }
    0
}

/// Returns the signed base-`2^c` digit of the low `num_bits` bits of `scalar`
/// at `window` (`0 <= window < num_windows`, where `num_windows = num_bits / c
/// + 1`).
///
/// Interior windows (`window + 1 < num_windows`) return a signed digit in
/// `[-(2^(c - 1) - 1), 2^(c - 1)]`, borrowing `2^c` into the next window
/// whenever the unsigned chunk plus incoming carry exceeds `2^(c - 1)`. The top
/// window returns an unsigned digit in `[0, 2^(num_bits % c)]`, absorbing any
/// carry out of the window below it.
///
/// Hazard: `num_windows` must equal `num_bits / c + 1` so `top_bits = num_bits
/// % c` stays strictly below `c`. When `c` divides `num_bits` (such as `c = 11`
/// on a 253-bit scalar field), `top_bits` is `0` and the top window holds `1`
/// bucket solely to absorb a carry out of bit `num_bits - 1`.
#[inline]
fn signed_window_digit<B: BigInteger>(scalar: &B, window: usize, c: usize, num_windows: usize, num_bits: usize) -> i32 {
    let limbs = scalar.as_ref();
    let bit_offset = window * c;
    let carry = carry_into_window(limbs, bit_offset, c);

    if window + 1 == num_windows {
        let top_bits = num_bits % c;
        return (extract_bits(limbs, bit_offset, top_bits, num_bits) + carry) as i32;
    }

    let half = 1u32 << (c - 1);
    let full = 1u32 << c;
    let value = extract_bits(limbs, bit_offset, c, num_bits) + carry;
    if value > half { value as i32 - full as i32 } else { value as i32 }
}

/// Selects the window width `c` that minimizes estimated group-operation cost
/// under signed digits, capping each window's bucket table at `2^13` buckets
/// below `500,000` bases on `x86_64` and `2^14` buckets otherwise.
#[inline]
fn best_window_size(num_scalars: usize, num_bits: usize) -> usize {
    let max_window = if cfg!(target_arch = "x86_64") && num_scalars < 500_000 {
        DEFAULT_MAX_BUCKET_WINDOW
    } else {
        LARGE_MSM_MAX_BUCKET_WINDOW
    };
    let mut best_c = MIN_BUCKET_WINDOW;
    let mut best_cost = u128::MAX;
    for c in MIN_BUCKET_WINDOW..=max_window {
        let num_windows = num_bits / c + 1;
        let top_bits = num_bits % c;
        let total_buckets = ((num_windows - 1) as u128) * (1u128 << (c - 1)) + (1u128 << top_bits);
        // Each base in a window performs at most one batched affine addition
        // (~5M + 1S plus amortized inversion), while each bucket in the
        // running-sum reduction performs one mixed addition plus one projective
        // addition (18M + 9S, roughly 4x one batched affine addition).
        let cost = (num_windows as u128) * (num_scalars as u128) + 4 * total_buckets;
        if cost < best_cost {
            best_cost = cost;
            best_c = c;
        }
    }
    best_c
}

#[inline]
fn batched_window<G: AffineCurve>(
    bases: &[G],
    scalars: &[<G::ScalarField as PrimeField>::BigInteger],
    window: usize,
    c: usize,
    num_windows: usize,
    num_bits: usize,
) -> G::Projective {
    // Signed digits in `[-(2^(c - 1) - 1), 2^(c - 1)]` use `2^(c - 1)` buckets
    // on interior windows; the top window holds `2^(num_bits % c)` buckets.
    let num_buckets = if window + 1 == num_windows { 1usize << (num_bits % c) } else { 1usize << (c - 1) };

    let mut bucket_positions = Vec::with_capacity(scalars.len());
    for (scalar_index, scalar) in scalars.iter().enumerate() {
        let digit = signed_window_digit(scalar, window, c, num_windows, num_bits);
        if digit != 0 {
            let sign_tag = if digit < 0 { SIGN_BIT } else { 0 };
            bucket_positions.push(BucketPosition {
                bucket_index: digit.unsigned_abs() - 1,
                scalar_index: (scalar_index as u32) | sign_tag,
            });
        }
    }
    if bucket_positions.is_empty() {
        return G::Projective::zero();
    }

    let buckets = batch_add(num_buckets, bases, &mut bucket_positions);

    let mut res = G::Projective::zero();
    let mut running_sum = G::Projective::zero();
    for b in buckets.into_iter().rev() {
        running_sum.add_assign_mixed(&b);
        res += &running_sum;
    }

    res
}

/// Computes the bucket MSM over `bases[..scalars.len()]` and `scalars` with an
/// explicit signed window width `c` (`2 <= c <= 16`).
///
/// Panics if `scalars.len() > bases.len()`. Each scalar must be below
/// `2^G::ScalarField::size_in_bits()`.
pub(super) fn bucket_msm_with_window<G: AffineCurve>(
    bases: &[G],
    scalars: &[<G::ScalarField as PrimeField>::BigInteger],
    c: usize,
) -> G::Projective {
    assert!(scalars.len() <= bases.len());
    let n = scalars.len();
    if n == 0 {
        return G::Projective::zero();
    }
    let bases = &bases[..n];
    assert!((2..=16).contains(&c));
    assert!(n < SCALAR_INDEX_MASK as usize);

    let num_bits = <G::ScalarField as PrimeField>::size_in_bits();
    debug_assert!(
        scalars.iter().all(|s| scalar_fits_in_bits(s, num_bits)),
        "MSM scalars must be below 2^size_in_bits()",
    );
    let num_windows = num_bits / c + 1;

    let window_sums: Vec<_> =
        cfg_into_iter!(0..num_windows).map(|w| batched_window(bases, scalars, w, c, num_windows, num_bits)).collect();

    let mut total = G::Projective::zero();
    for sum in window_sums.into_iter().rev() {
        if !total.is_zero() {
            for _ in 0..c {
                total.double_in_place();
            }
        }
        total += &sum;
    }
    total
}

/// The signed-digit window of `straus`.
///
/// Every nonzero digit is odd and below `2^(STRAUS_WINDOW - 1)` in magnitude,
/// so each base needs a table of `2^(STRAUS_WINDOW - 2)` odd multiples.
#[doc(hidden)]
pub const STRAUS_WINDOW: usize = 5;

/// Writes the width-`window` non-adjacent form of the low `num_bits` bits of
/// `scalar` into `digits`, least significant digit first.
///
/// Every nonzero digit is odd and below `2^(window - 1)` in magnitude, and two
/// nonzero digits are at least `window` positions apart. `digits` holds one
/// position more than `num_bits`, for the carry out of the top window.
fn recode_naf<B: BigInteger>(scalar: &B, window: usize, num_bits: usize, digits: &mut [i8]) {
    debug_assert_eq!(digits.len(), num_bits + 1);
    let limbs = scalar.as_ref();
    let half = 1u64 << (window - 1);
    let full = 1u64 << window;
    // The `window` bits of the scalar from bit `i` up, with every bit at or
    // above `num_bits` read as zero.
    let bits_at = |i: usize| -> u64 {
        let (limb, shift) = (i / 64, i % 64);
        let mut value = limbs[limb] >> shift;
        if shift + window > 64 && limb + 1 < limbs.len() {
            value |= limbs[limb + 1] << (64 - shift);
        }
        let width = window.min(num_bits - i);
        value & ((1u64 << width) - 1)
    };
    let mut carry = 0u64;
    let mut i = 0;
    while i < num_bits {
        let value = bits_at(i) + carry;
        if value & 1 == 0 {
            // An even sum means bit `i` equals the carry, so the carry is unchanged.
            digits[i] = 0;
            i += 1;
            continue;
        }
        // `value` is odd, so below `full`.
        if value >= half {
            digits[i] = (value as i64 - full as i64) as i8;
            carry = 1;
        } else {
            digits[i] = value as i8;
            carry = 0;
        }
        // The digits under the rest of the window are zero.
        let end = (i + window).min(num_bits);
        digits[i + 1..end].fill(0);
        i = end;
    }
    digits[num_bits] = carry as i8;
}

/// Computes the MSM over `bases[..scalars.len()]` and `scalars` by Straus's
/// method: one shared doubling per digit position, and for every base a table
/// of odd multiples that a nonzero digit selects from.
///
/// Panics if `scalars.len() > bases.len()`. Each scalar must be below
/// `2^G::ScalarField::size_in_bits()`.
#[doc(hidden)]
pub fn straus<G: AffineCurve, const WINDOW: usize>(
    bases: &[G],
    scalars: &[<G::ScalarField as PrimeField>::BigInteger],
) -> G::Projective {
    const { assert!(WINDOW >= 2 && WINDOW <= 8) };
    let table_len = 1usize << (WINDOW - 2);
    assert!(scalars.len() <= bases.len());
    let n = scalars.len();
    let bases = &bases[..n];

    // Tables: the odd multiples `[1, 3, ..., 2 * table_len - 1] * base`, built
    // from an affine `2 * base` by mixed additions and normalized in one batch.
    let doubles = G::Projective::batch_normalization_into_affine(
        bases.iter().map(|base| base.to_projective().double()).collect(),
    );
    let mut tables = Vec::with_capacity(n * table_len);
    for (base, double) in bases.iter().zip_eq(&doubles) {
        let mut multiple = base.to_projective();
        tables.push(multiple);
        for _ in 1..table_len {
            multiple.add_assign_mixed(double);
            tables.push(multiple);
        }
    }
    let tables = G::Projective::batch_normalization_into_affine(tables);

    // Digits: one row per scalar, most significant position last.
    let num_bits = G::ScalarField::size_in_bits();
    debug_assert!(
        scalars.iter().all(|s| scalar_fits_in_bits(s, num_bits)),
        "MSM scalars must be below 2^size_in_bits()",
    );
    let stride = num_bits + 1;
    let mut digits = vec![0i8; n * stride];
    for (scalar, row) in scalars.iter().zip_eq(digits.chunks_exact_mut(stride)) {
        recode_naf(scalar, WINDOW, num_bits, row);
    }

    let mut sum = G::Projective::zero();
    let mut encountered_nonzero = false;
    for position in (0..stride).rev() {
        if encountered_nonzero {
            sum.double_in_place();
        }
        for (row, table) in digits.chunks_exact(stride).zip_eq(tables.chunks_exact(table_len)) {
            let digit = row[position];
            if digit != 0 {
                let entry = table[usize::from(digit.unsigned_abs()) >> 1];
                if digit > 0 {
                    sum.add_assign_mixed(&entry)
                } else {
                    sum.add_assign_mixed(&-entry)
                }
                encountered_nonzero = true;
            }
        }
    }
    sum
}

/// The fewest bases that `msm` sums by the bucket method. Below it, each window
/// holds too few points to amortize its batched inversions, and the curve's
/// lanes and Straus's method are several times faster.
pub(super) const BUCKET_MIN_BASES: usize = 32;

/// Returns the sum of `base * scalar` through `AffineCurve::msm_lanes`, over
/// the shorter of `bases` and `scalars`, or `None` if the curve has no lane
/// path for them or a scalar is not below the modulus.
fn msm_in_lanes<G: AffineCurve>(
    bases: &[G],
    scalars: &[<G::ScalarField as PrimeField>::BigInteger],
) -> Option<G::Projective> {
    let terms = bases
        .iter()
        .zip(scalars)
        .map(|(base, scalar)| Some((*base, G::ScalarField::from_bigint(*scalar)?)))
        .collect::<Option<Vec<_>>>()?;
    G::msm_lanes(&[&terms])?.into_iter().next()
}

/// Returns the sum of `bases[i] * scalars[i]` over `0..scalars.len()`.
///
/// Panics if `scalars.len() > bases.len()`. Each scalar must be below
/// `2^G::ScalarField::size_in_bits()`; bits at or above `size_in_bits()` are
/// ignored.
///
/// Hazard: for a base outside the prime-order subgroup, the curve's GLV
/// multiplication and its lanes can return another sum than Straus's method,
/// which differs by a point whose order divides the cofactor. So the sum
/// depends on the CPU. A pairing maps that point to one, so a pairing check on
/// the sum does not.
pub fn msm<G: AffineCurve>(bases: &[G], scalars: &[<G::ScalarField as PrimeField>::BigInteger]) -> G::Projective {
    assert!(scalars.len() <= bases.len());
    let n = scalars.len();
    let bases = &bases[..n];
    let num_bits = <G::ScalarField as PrimeField>::size_in_bits();
    debug_assert!(
        scalars.iter().all(|s| scalar_fits_in_bits(s, num_bits)),
        "MSM scalars must be below 2^size_in_bits()",
    );

    if n < BUCKET_MIN_BASES {
        // A zero scalar adds nothing and a unit scalar adds its base, so
        // neither needs a table or a scalar multiplication.
        let one = <G::ScalarField as PrimeField>::BigInteger::from(1u64);
        let mut sum = G::Projective::zero();
        let (bases, scalars) = if scalars.iter().any(|scalar| scalar.is_zero() || *scalar == one) {
            let mut rest = (Vec::with_capacity(n), Vec::with_capacity(n));
            for (base, scalar) in bases.iter().zip_eq(scalars) {
                if *scalar == one {
                    sum.add_assign_mixed(base);
                } else if !scalar.is_zero() {
                    rest.0.push(*base);
                    rest.1.push(*scalar);
                }
            }
            (Cow::Owned(rest.0), Cow::Owned(rest.1))
        } else {
            (Cow::Borrowed(bases), Cow::Borrowed(scalars))
        };
        // One base shares no doublings, so it goes through the curve's own
        // scalar multiplication, GLV on BLS12-377, which halves the doublings.
        if let ([base], [scalar]) = (&*bases, &*scalars)
            && let Some(scalar) = G::ScalarField::from_bigint(*scalar)
        {
            return sum + base.to_projective() * scalar;
        }
        if let Some(in_lanes) = msm_in_lanes(&bases, &scalars) {
            return sum + in_lanes;
        }
        sum + straus::<G, STRAUS_WINDOW>(&bases, &scalars)
    } else {
        let c = best_window_size(n, num_bits);
        bucket_msm_with_window(bases, scalars, c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msm::variable_base::standard;
    use snarkvm_curves::bls12_377::{Fr, G1Affine};
    use snarkvm_utilities::{BigInteger256, BitIteratorBE, TestRng, Uniform};

    fn mask_bigint_low_bits(mut value: BigInteger256, num_bits: usize) -> BigInteger256 {
        for bit in num_bits..256 {
            value.0[bit / 64] &= !(1u64 << (bit % 64));
        }
        value
    }

    fn set_window_bits(target: &mut BigInteger256, bit_offset: usize, chunk: u64, num_bits: usize) {
        for b in 0..16 {
            let pos = bit_offset + b;
            if pos >= num_bits {
                break;
            }
            if (chunk >> b) & 1 == 1 {
                target.0[pos / 64] |= 1u64 << (pos % 64);
            }
        }
    }

    fn naive_low_bits_msm(bases: &[G1Affine], scalars: &[BigInteger256], num_bits: usize) -> G1Affine {
        bases
            .iter()
            .zip_eq(scalars)
            .map(|(base, scalar)| base.mul_bits(BitIteratorBE::new(*scalar).skip(256 - num_bits)))
            .sum::<snarkvm_curves::bls12_377::G1Projective>()
            .to_affine()
    }

    /// Every digit is zero or odd and below `2^(window - 1)` in magnitude, two
    /// nonzero digits are at least `window` apart, and the digits read back as
    /// the scalar.
    #[test]
    fn test_recode_naf() {
        let mut rng = TestRng::default();
        let num_bits = Fr::size_in_bits();
        let two = Fr::from(2u64);
        let mut scalars = vec![Fr::zero(), Fr::one(), -Fr::one(), two.pow([252]), -two.pow([252]), Fr::from(u64::MAX)];
        scalars.extend((0..200).map(|_| Fr::rand(&mut rng)));
        for window in 2..=8 {
            let bound = 1i16 << (window - 1);
            let mut digits = vec![0i8; num_bits + 1];
            for scalar in &scalars {
                recode_naf(&scalar.to_bigint(), window, num_bits, &mut digits);
                let mut last_nonzero = None;
                let mut value = Fr::zero();
                for (i, &digit) in digits.iter().enumerate().rev() {
                    value = value.double()
                        + Fr::from(digit.unsigned_abs() as u64) * if digit < 0 { -Fr::one() } else { Fr::one() };
                    if digit != 0 {
                        assert!(digit % 2 != 0 && i16::from(digit).abs() < bound, "window {window}: digit {digit}");
                        if let Some(next) = last_nonzero {
                            assert!(next - i >= window, "window {window}: digits at {i} and {next}");
                        }
                        last_nonzero = Some(i);
                    }
                }
                assert_eq!(value, *scalar, "window {window}");
            }
        }
    }

    /// Verifies `signed_window_digit` bounds, sequential carry equivalence, and
    /// exact integer reconstruction across all window widths `2..=16` and bit
    /// widths `252, 253, 255, 256` (including `c | num_bits` carry-only top
    /// windows and multi-window tie/ripple chains).
    #[test]
    fn test_signed_window_digit() {
        let mut rng = TestRng::default();
        let one = BigInteger256::from(1u64);

        for num_bits in [252, 253, 255, 256] {
            let all_ones = mask_bigint_low_bits(BigInteger256::new([u64::MAX; 4]), num_bits);
            let mut top_bit = BigInteger256::from(0u64);
            top_bit.0[(num_bits - 1) / 64] |= 1u64 << ((num_bits - 1) % 64);
            let mut top_bit_minus_one = top_bit;
            top_bit_minus_one.sub_noborrow(&one);

            for c in 2..=16 {
                let half = 1u32 << (c - 1);
                let full = 1u32 << c;
                let num_windows = num_bits / c + 1;
                let top_bound = 1i32 << (num_bits % c);

                let mut tie_chain = BigInteger256::from(0u64);
                for w in 0..num_windows {
                    set_window_bits(&mut tie_chain, w * c, u64::from(half), num_bits);
                }
                let mut tie_minus_one = tie_chain;
                let _ = tie_minus_one.sub_noborrow(&one);
                let mut tie_plus_one = tie_chain;
                let _ = tie_plus_one.add_nocarry(&one);
                tie_plus_one = mask_bigint_low_bits(tie_plus_one, num_bits);

                let mut scalars = vec![
                    BigInteger256::from(0u64),
                    one,
                    BigInteger256::from(u64::MAX),
                    mask_bigint_low_bits(Fr::modulus(), num_bits),
                    mask_bigint_low_bits((-Fr::one()).to_bigint(), num_bits),
                    all_ones,
                    top_bit,
                    top_bit_minus_one,
                    tie_chain,
                    tie_minus_one,
                    tie_plus_one,
                ];
                for w in 0..num_windows {
                    if w * c < num_bits {
                        let mut exact_half = BigInteger256::from(0u64);
                        set_window_bits(&mut exact_half, w * c, u64::from(half), num_bits);
                        let mut over_half = exact_half;
                        let _ = over_half.add_nocarry(&one);
                        scalars.push(exact_half);
                        scalars.push(mask_bigint_low_bits(over_half, num_bits));
                    }
                }
                for _ in 0..80 {
                    scalars.push(mask_bigint_low_bits(BigInteger256::rand(&mut rng), num_bits));
                }

                for scalar in &scalars {
                    // Compare against sequential low-to-high carry propagation.
                    let mut carry = 0u32;
                    let mut digits = Vec::with_capacity(num_windows);
                    for w in 0..num_windows {
                        let got = signed_window_digit(scalar, w, c, num_windows, num_bits);
                        let expected = if w + 1 == num_windows {
                            let d = (extract_bits(scalar.as_ref(), w * c, num_bits % c, num_bits) + carry) as i32;
                            assert!((0..=top_bound).contains(&d), "top bound c={c} bits={num_bits}: {d}");
                            d
                        } else {
                            let val = extract_bits(scalar.as_ref(), w * c, c, num_bits) + carry;
                            let d = if val > half {
                                carry = 1;
                                val as i32 - full as i32
                            } else {
                                carry = 0;
                                val as i32
                            };
                            assert!(
                                d >= -(half as i32 - 1) && d <= half as i32,
                                "interior bound c={c} bits={num_bits}: {d}"
                            );
                            d
                        };
                        assert_eq!(got, expected, "c={c} bits={num_bits} w={w} scalar={scalar}");
                        digits.push(got);
                    }

                    // Reconstruct in 320-bit signed arithmetic and compare with `scalar`.
                    let mut acc = [0u64; 5];
                    for &d in digits.iter().rev() {
                        // Multiply `acc` by `2^c`.
                        let mut shift_carry = 0u64;
                        for limb in &mut acc {
                            let next = *limb >> (64 - c);
                            *limb = (*limb << c) | shift_carry;
                            shift_carry = next;
                        }
                        if d >= 0 {
                            let mut add = d as u64;
                            for limb in &mut acc {
                                let (sum, ovf) = limb.overflowing_add(add);
                                *limb = sum;
                                add = u64::from(ovf);
                            }
                        } else {
                            let mut sub = d.unsigned_abs() as u64;
                            for limb in &mut acc {
                                let (diff, borrow) = limb.overflowing_sub(sub);
                                *limb = diff;
                                sub = u64::from(borrow);
                            }
                        }
                    }
                    assert_eq!(acc[4], 0, "overflow limb nonzero for c={c} bits={num_bits}");
                    assert_eq!(&acc[..4], scalar.as_ref(), "reconstruction failed for c={c} bits={num_bits}");
                }
            }
        }

        // Exercise `half_pattern_limb` beyond the 4-limb table (`limb >= 4`) on
        // 377-bit scalars across `c in 2..=16`.
        let num_bits_384 = 377usize;
        let one_384 = snarkvm_utilities::BigInteger384::from(1u64);
        for c in 2..=16 {
            let half = 1u32 << (c - 1);
            let full = 1u32 << c;
            let num_windows = num_bits_384 / c + 1;
            let mut tie_384 = snarkvm_utilities::BigInteger384::from(0u64);
            for w in 0..num_windows {
                for b in 0..c {
                    let pos = w * c + b;
                    if pos < num_bits_384 && ((half >> b) & 1 == 1) {
                        tie_384.0[pos / 64] |= 1u64 << (pos % 64);
                    }
                }
            }
            let mut tie_minus_one = tie_384;
            let _ = tie_minus_one.sub_noborrow(&one_384);
            let mut tie_plus_one = tie_384;
            let _ = tie_plus_one.add_nocarry(&one_384);
            for bit in num_bits_384..384 {
                tie_plus_one.0[bit / 64] &= !(1u64 << (bit % 64));
            }
            for scalar in [tie_384, tie_minus_one, tie_plus_one, snarkvm_utilities::BigInteger384::rand(&mut rng)] {
                let mut s = scalar;
                for bit in num_bits_384..384 {
                    s.0[bit / 64] &= !(1u64 << (bit % 64));
                }
                let mut carry = 0u32;
                for w in 0..num_windows {
                    let got = signed_window_digit(&s, w, c, num_windows, num_bits_384);
                    let expected = if w + 1 == num_windows {
                        (extract_bits(s.as_ref(), w * c, num_bits_384 % c, num_bits_384) + carry) as i32
                    } else {
                        let val = extract_bits(s.as_ref(), w * c, c, num_bits_384) + carry;
                        if val > half {
                            carry = 1;
                            val as i32 - full as i32
                        } else {
                            carry = 0;
                            val as i32
                        }
                    };
                    assert_eq!(got, expected, "384-bit c={c} w={w}");
                }
            }
        }
    }

    #[test]
    fn test_best_window_size() {
        assert_eq!(core::mem::size_of::<G1Affine>(), 104);
        let sizes =
            [32, 48, 64, 128, 256, 512, 1024, 2048, 4096, 10_000, 32_768, 65_536, 100_000, 262_144, 500_000, 1_000_000];
        let mut prev = MIN_BUCKET_WINDOW;
        for n in sizes {
            let c = best_window_size(n, 253);
            assert!((MIN_BUCKET_WINDOW..=LARGE_MSM_MAX_BUCKET_WINDOW).contains(&c), "n={n}: c={c}");
            if cfg!(target_arch = "x86_64") && n < 500_000 {
                assert!(c <= DEFAULT_MAX_BUCKET_WINDOW, "n={n}: c={c}");
            }
            assert!(c >= prev, "window regressed at n={n}: {c} < {prev}");
            prev = c;
        }
        assert_eq!(best_window_size(1usize << 30, 253), LARGE_MSM_MAX_BUCKET_WINDOW);
    }

    /// Differential test of the signed-digit bucket MSM across every window
    /// width `2..=16`, covering top-window carries (including `c = 11` where
    /// `253 % 11 == 0` places the carry in a dedicated 1-bucket top window),
    /// unreduced 253-bit scalars, carry-tie chains, repeated/negated bases,
    /// points at infinity, all-zero scalars, and cancelling sums.
    #[test]
    fn test_bucket_msm_all_windows_and_top_carry() {
        let mut rng = TestRng::default();
        let num_bits = Fr::size_in_bits();
        let two = Fr::from(2u64);
        let one_bi = BigInteger256::from(1u64);

        let modulus = Fr::modulus();
        let mut modulus_plus_one = modulus;
        let _ = modulus_plus_one.add_nocarry(&one_bi);
        let top_253 = BigInteger256::new([u64::MAX, u64::MAX, u64::MAX, (1 << 61) - 1]);

        let msm_size = 40;
        let mut bases = (0..msm_size).map(|_| G1Affine::rand(&mut rng)).collect::<Vec<_>>();
        bases[1] = G1Affine::zero();
        bases[7] = G1Affine::zero();
        bases[13] = bases[12];
        bases[14] = -bases[12];
        bases[16] = bases[15];
        bases[17] = G1Affine::zero();

        for c in 2..=16 {
            let half = 1u32 << (c - 1);
            let neg_one_w0 = BigInteger256::from((1u64 << c) - 1);
            let num_windows = num_bits / c + 1;
            let mut tie_chain = BigInteger256::from(0u64);
            for w in 0..num_windows {
                set_window_bits(&mut tie_chain, w * c, u64::from(half), num_bits);
            }
            let mut tie_minus_one = tie_chain;
            let _ = tie_minus_one.sub_noborrow(&one_bi);
            let mut tie_plus_one = tie_chain;
            let _ = tie_plus_one.add_nocarry(&one_bi);
            tie_plus_one = mask_bigint_low_bits(tie_plus_one, num_bits);

            let fixed = [
                Fr::zero().to_bigint(),
                Fr::one().to_bigint(),
                (-Fr::one()).to_bigint(),
                two.pow([252]).to_bigint(),
                (-two.pow([252])).to_bigint(),
                (two.pow([252]) - Fr::one()).to_bigint(),
                modulus,
                modulus_plus_one,
                top_253,
                tie_chain,
                tie_minus_one,
                tie_plus_one,
            ];

            let mut scalars = (0..msm_size)
                .map(|i| if i < fixed.len() { fixed[i] } else { Fr::rand(&mut rng).to_bigint() })
                .collect::<Vec<_>>();
            // Drive identical, opposite, and infinity bases into window 0 bucket 0 via
            // signed digit `-1` (`2^c - 1`) and `+1` (`1`) so negative doubling,
            // same-bucket cancellation, and negated infinity all execute.
            scalars[12] = neg_one_w0;
            scalars[13] = neg_one_w0;
            scalars[14] = neg_one_w0;
            scalars[15] = one_bi;
            scalars[16] = neg_one_w0;
            scalars[17] = neg_one_w0;

            let expected = naive_low_bits_msm(&bases, &scalars, num_bits);
            let got = bucket_msm_with_window(&bases, &scalars, c).to_affine();
            assert_eq!(got, expected, "window c={c}");
            assert_eq!(standard::msm(&bases, &scalars).to_affine(), expected, "standard window c={c}");
        }

        // Uniform edge vectors on >= 32 bases: all-zero, all-one, all-`2^253 - 1`, and
        // exact cancellation.
        let cancel_bases = (0..36).map(|i| bases[i / 2 * 2]).collect::<Vec<_>>();
        let cancel_scalars = (0..36)
            .scan(Fr::zero(), |state, i| {
                if i % 2 == 0 {
                    *state = Fr::rand(&mut rng);
                    Some(state.to_bigint())
                } else {
                    Some((-*state).to_bigint())
                }
            })
            .collect::<Vec<_>>();

        for c in [2, 5, 11, 14, 15, 16] {
            let zeros = vec![BigInteger256::from(0u64); msm_size];
            assert!(bucket_msm_with_window(&bases, &zeros, c).is_zero(), "all-zero c={c}");

            let ones = vec![one_bi; msm_size];
            assert_eq!(
                bucket_msm_with_window(&bases, &ones, c).to_affine(),
                naive_low_bits_msm(&bases, &ones, num_bits),
                "all-one c={c}"
            );

            let tops = vec![top_253; msm_size];
            assert_eq!(
                bucket_msm_with_window(&bases, &tops, c).to_affine(),
                naive_low_bits_msm(&bases, &tops, num_bits),
                "all-top c={c}"
            );

            assert!(bucket_msm_with_window(&cancel_bases, &cancel_scalars, c).is_zero(), "cancelling c={c}");
        }
    }

    /// Exercises `batched::msm` across the Straus/bucket cutoff, mid-loop batch
    /// flushes on both `x86_64` (`batch_size = 300`, `batch_size / 2 = 150`)
    /// and other targets such as ARM (`batch_size = 3000`, `batch_size / 2
    /// = 1500`), and unequal `(bases.len() > scalars.len())` slices.
    #[test]
    fn test_bucket_msm_sizes_and_batch_boundaries() {
        let mut rng = TestRng::default();
        let max_size = 3601;
        let proj_bases =
            (0..max_size).map(|_| <G1Affine as AffineCurve>::Projective::rand(&mut rng)).collect::<Vec<_>>();
        let mut bases = <G1Affine as AffineCurve>::Projective::batch_normalization_into_affine(proj_bases);
        bases[10] = G1Affine::zero();
        bases[20] = bases[5];
        bases[21] = -bases[5];
        let mut scalars = (0..max_size).map(|_| Fr::rand(&mut rng).to_bigint()).collect::<Vec<_>>();
        scalars[0] = Fr::zero().to_bigint();
        scalars[1] = Fr::one().to_bigint();
        scalars[2] = (-Fr::one()).to_bigint();

        for size in [32, 33, 48, 64, 65, 128, 256, 300, 301, 512, 601, 3001, 3601] {
            let expected = standard::msm(&bases[..size], &scalars[..size]).to_affine();
            let got = msm(&bases[..size], &scalars[..size]).to_affine();
            assert_eq!(got, expected, "size={size}");
        }

        // Populate three negative window-0 buckets of sizes `(3200, 3200, 10)`
        // (`-Fr::from(2)`, `-Fr::from(4)`, `-Fr::from(6)` have low `c` bits
        // `2^c - 1`, `2^c - 3`, `2^c - 5`, giving digits `-1`, `-3`, `-5`) so
        // both `batch_add_write` (`1600 >= 1500` with remaining buckets) and
        // `batch_add_in_place_same_slice` (`800 + 800 = 1600 >= 1500` with a
        // trailing bucket) flush mid-loop and post-loop even when `batch_size`
        // is `3000` (non-x86_64 targets).
        let collide_bases: Vec<_> = bases.iter().copied().cycle().take(6410).collect();
        let mut collide_scalars = Vec::with_capacity(6410);
        collide_scalars.extend(std::iter::repeat_n((-Fr::from(2u64)).to_bigint(), 3200));
        collide_scalars.extend(std::iter::repeat_n((-Fr::from(4u64)).to_bigint(), 3200));
        collide_scalars.extend(std::iter::repeat_n((-Fr::from(6u64)).to_bigint(), 10));
        let expected_collide = standard::msm(&collide_bases, &collide_scalars).to_affine();
        assert_eq!(msm(&collide_bases, &collide_scalars).to_affine(), expected_collide);

        for (num_bases, num_scalars) in [(64, 3), (64, 32), (64, 45)] {
            let expected = standard::msm(&bases[..num_scalars], &scalars[..num_scalars]).to_affine();
            let got = msm(&bases[..num_bases], &scalars[..num_scalars]).to_affine();
            assert_eq!(got, expected, "bases={num_bases}, scalars={num_scalars}");
        }
    }

    #[test]
    fn test_scalar_fits_in_bits_boundaries() {
        assert!(scalar_fits_in_bits(&BigInteger256::from(0u64), 0));
        assert!(!scalar_fits_in_bits(&BigInteger256::from(1u64), 0));
        for num_bits in [1, 63, 64, 65, 128, 129, 192, 252, 253, 255] {
            let max_ok = mask_bigint_low_bits(BigInteger256::new([u64::MAX; 4]), num_bits);
            assert!(scalar_fits_in_bits(&max_ok, num_bits), "max_ok failed at {num_bits}");
            let mut at_bound = BigInteger256::from(0u64);
            at_bound.0[num_bits / 64] = 1u64 << (num_bits % 64);
            assert!(!scalar_fits_in_bits(&at_bound, num_bits), "2^{num_bits} accepted");
            if num_bits / 64 + 1 < 4 {
                let mut higher_limb = BigInteger256::from(0u64);
                higher_limb.0[3] = 1;
                assert!(!scalar_fits_in_bits(&higher_limb, num_bits), "higher limb accepted at {num_bits}");
            }
        }
        assert!(scalar_fits_in_bits(&BigInteger256::new([u64::MAX; 4]), 256));
    }

    #[test]
    #[should_panic]
    fn test_batched_msm_panics_more_scalars_small() {
        let mut rng = TestRng::default();
        let bases = (0..10).map(|_| G1Affine::rand(&mut rng)).collect::<Vec<_>>();
        let scalars = (0..11).map(|_| Fr::rand(&mut rng).to_bigint()).collect::<Vec<_>>();
        let _ = msm(&bases, &scalars);
    }

    #[test]
    #[should_panic]
    fn test_batched_msm_panics_more_scalars_bucket() {
        let mut rng = TestRng::default();
        let bases = (0..32).map(|_| G1Affine::rand(&mut rng)).collect::<Vec<_>>();
        let scalars = (0..33).map(|_| Fr::rand(&mut rng).to_bigint()).collect::<Vec<_>>();
        let _ = msm(&bases, &scalars);
    }

    #[test]
    #[should_panic]
    fn test_straus_panics_more_scalars() {
        let mut rng = TestRng::default();
        let bases = (0..4).map(|_| G1Affine::rand(&mut rng)).collect::<Vec<_>>();
        let scalars = (0..5).map(|_| Fr::rand(&mut rng).to_bigint()).collect::<Vec<_>>();
        let _ = straus::<G1Affine, STRAUS_WINDOW>(&bases, &scalars);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "MSM scalars must be below 2^size_in_bits()")]
    fn test_straus_debug_panics_scalar_above_num_bits() {
        let mut rng = TestRng::default();
        let bases = (0..4).map(|_| G1Affine::rand(&mut rng)).collect::<Vec<_>>();
        let mut scalars = (0..4).map(|_| Fr::rand(&mut rng).to_bigint()).collect::<Vec<_>>();
        scalars[1].0[3] |= 1u64 << 61;
        let _ = straus::<G1Affine, STRAUS_WINDOW>(&bases, &scalars);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "MSM scalars must be below 2^size_in_bits()")]
    fn test_batched_msm_debug_panics_scalar_above_num_bits_small() {
        let mut rng = TestRng::default();
        let bases = (0..4).map(|_| G1Affine::rand(&mut rng)).collect::<Vec<_>>();
        let mut scalars = (0..4).map(|_| Fr::rand(&mut rng).to_bigint()).collect::<Vec<_>>();
        scalars[2].0[3] |= 1u64 << 61;
        let _ = msm(&bases, &scalars);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "MSM scalars must be below 2^size_in_bits()")]
    fn test_batched_msm_debug_panics_scalar_above_num_bits_bucket() {
        let mut rng = TestRng::default();
        let bases = (0..32).map(|_| G1Affine::rand(&mut rng)).collect::<Vec<_>>();
        let mut scalars = (0..32).map(|_| Fr::rand(&mut rng).to_bigint()).collect::<Vec<_>>();
        scalars[31].0[3] |= 1u64 << 61;
        let _ = msm(&bases, &scalars);
    }

    /// Isolates singleton negative buckets, paired negative doublings,
    /// odd-count (`3` and `5`) negative buckets across multi-pass
    /// reductions, opposite-sign `SIGN_BIT` cancellations, negated points
    /// at infinity, and empty slices.
    #[test]
    fn test_signed_bucket_reduction_edge_cases() {
        let mut rng = TestRng::default();
        let num_bits = Fr::size_in_bits();
        let one_bi = BigInteger256::from(1u64);
        let pts = (0..5).map(|_| G1Affine::rand(&mut rng)).collect::<Vec<_>>();
        let inf = G1Affine::zero();

        for c in 2..=16 {
            let neg_one_w0 = BigInteger256::from((1u64 << c) - 1);

            assert!(bucket_msm_with_window::<G1Affine>(&[], &[], c).is_zero());
            assert!(bucket_msm_with_window(&pts, &[], c).is_zero());

            let cases: Vec<(Vec<G1Affine>, Vec<BigInteger256>, &str)> = vec![
                (vec![pts[0]], vec![neg_one_w0], "singleton negative"),
                (vec![pts[0], pts[0]], vec![neg_one_w0, neg_one_w0], "paired negative doubling"),
                (vec![pts[0], pts[1], pts[2]], vec![neg_one_w0; 3], "odd-3 negative bucket"),
                (pts.clone(), vec![neg_one_w0; 5], "odd-5 negative bucket"),
                (vec![pts[0], pts[0]], vec![one_bi, neg_one_w0], "opposite-sign same-bucket cancel"),
                (vec![pts[0], -pts[0]], vec![neg_one_w0, neg_one_w0], "negated-base same-bucket cancel"),
                (vec![inf], vec![neg_one_w0], "singleton negated infinity"),
                (vec![inf, pts[0]], vec![neg_one_w0, neg_one_w0], "infinity plus negative base"),
                (vec![pts[0], inf], vec![neg_one_w0, neg_one_w0], "negative base plus infinity"),
            ];

            for (bases, scalars, label) in cases {
                let expected = naive_low_bits_msm(&bases, &scalars, num_bits);
                let got = bucket_msm_with_window(&bases, &scalars, c).to_affine();
                assert_eq!(got, expected, "{label} (c={c})");
            }
        }
    }
}
