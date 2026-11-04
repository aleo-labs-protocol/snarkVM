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

//! The plan of a batch of G1 MSMs over the lanes of `ifma::glv_mul_8`.

use snarkvm_fields::{One, PrimeField, Zero, ifma};
use snarkvm_utilities::{BitIteratorBE, biginteger::BigInteger256};

use crate::{
    AffineCurve,
    ProjectiveCurve,
    bls12_377::{FqParameters, Fr, G1Affine, G1Projective, g1::Bls12_377G1Parameters},
    traits::ShortWeierstrassParameters,
};

type Parameters = Bls12_377G1Parameters;

/// Runs `ShortWeierstrassParameters::msm_lanes` for G1: drops the zero terms, adds the bases of unit
/// scalars, splits the other terms into calls of `ifma::glv_mul_8`, and sums each lane.
pub(super) fn msm_lanes(msms: &[&[(G1Affine, Fr)]]) -> Option<Vec<G1Projective>> {
    debug_assert!(
        msms.iter().flat_map(|msm| msm.iter()).all(|(base, _)| base.is_in_correct_subgroup_assuming_on_curve()),
        "a base is outside the prime-order subgroup"
    );
    if !ifma::is_supported::<FqParameters>() {
        return None;
    }
    // A zero base or scalar adds nothing.
    let mut msms: Vec<Vec<_>> = msms
        .iter()
        .map(|msm| msm.iter().filter(|(base, scalar)| !base.is_zero() && !scalar.is_zero()).copied().collect())
        .collect();
    if msms.iter().map(Vec::len).sum::<usize>() < MSM_LANES_MIN {
        return None;
    }
    let mut sums = vec![G1Projective::zero(); msms.len()];
    // A unit scalar adds its base, which needs no digits.
    for (msm, sum) in msms.iter_mut().zip(&mut sums) {
        msm.retain(|(base, scalar)| {
            let is_unit = scalar.is_one();
            if is_unit {
                sum.add_assign_mixed(base);
            }
            !is_unit
        });
    }
    for call in lane_calls(&msms) {
        run_lane_call(&call, &mut sums)?;
    }
    Some(sums)
}

/// The fewest terms, over all MSMs of a call, that `msm_lanes` runs in the lanes of
/// `ifma::glv_mul_8`.
const MSM_LANES_MIN: usize = 2;

/// The most terms of one MSM in one call of `ifma::glv_mul_8`; `lane_calls` splits a larger MSM.
const LANE_CALL_MAX_TERMS: usize = 64;

/// An MSM of a call to `ifma::glv_mul_8`: the index of its sum and its terms.
type LaneMsm<'a> = (usize, &'a [(G1Affine, Fr)]);

/// Returns the fewest digit streams per lane with which the MSMs of `call`, at most 8, fit in 8
/// lanes: an MSM of `n` terms has `2 n` streams, and a lane holds the streams of one MSM only.
fn lane_streams(call: &[LaneMsm<'_>]) -> usize {
    debug_assert!(call.len() <= 8);
    let mut streams = 1;
    while call.iter().map(|(_, terms)| (2 * terms.len()).div_ceil(streams)).sum::<usize>() > 8 {
        streams += 1;
    }
    streams
}

/// Splits `msms` into calls of `ifma::glv_mul_8`: for `k` from 0, the `k` largest MSMs one per
/// call and the others 8 at a time, whichever costs least by `ifma::GLV_CALL_COST` and
/// `ifma::GLV_STREAM_COST`. An MSM of more than `LANE_CALL_MAX_TERMS` terms is split first.
fn lane_calls(msms: &[Vec<(G1Affine, Fr)>]) -> Vec<Vec<LaneMsm<'_>>> {
    let mut parts: Vec<LaneMsm<'_>> = msms
        .iter()
        .enumerate()
        .flat_map(|(i, terms)| terms.chunks(LANE_CALL_MAX_TERMS).map(move |chunk| (i, chunk)))
        .collect();
    parts.sort_by_key(|(_, terms)| std::cmp::Reverse(terms.len()));
    let cost = |call: &[LaneMsm<'_>]| ifma::GLV_CALL_COST + ifma::GLV_STREAM_COST * lane_streams(call);
    let total = |k: usize| {
        parts[..k].iter().map(|part| cost(std::slice::from_ref(part))).sum::<usize>()
            + parts[k..].chunks(8).map(cost).sum::<usize>()
    };
    // Without parts the range is empty, and `k = 0` splits nothing.
    let k = (0..parts.len()).min_by_key(|k| total(*k)).unwrap_or(0);
    parts[..k].iter().map(|part| vec![*part]).chain(parts[k..].chunks(8).map(<[_]>::to_vec)).collect()
}

/// A term of a lane, recomputed by the scalar path where the lane's `Z` is zero: a base and its
/// scalar, or a point and a multiple of it that the lane holds as one digit stream, negated if
/// the flag is set.
enum LaneTerm {
    Pair(G1Affine, Fr),
    Half(G1Affine, Fr, bool),
}

/// Adds the sum of each MSM of `call` to `sums` at its index, through one call of
/// `ifma::glv_mul_8`, or returns `None` if `ifma::glv_mul_8` does not run.
///
/// With `s` digit streams per lane, a lane has `s / 2` slots of a base and its endomorphism image,
/// each with the two parts of the base's scalar as `mul_projective` decomposes it, and for an odd
/// `s` one slot of a point with one part: a base, or its image, of a term that the pairs did not
/// take. An MSM of `n` terms takes `ceil(2 n / s)` lanes. A lane whose sum has `Z = 0` is
/// recomputed by `mul_projective` for its pairs and by double-and-add for its parts.
///
/// For a base outside G1 the sum is that of `mul_projective`, `k_1 P + k_2 phi(P)`, which is not
/// `k P`.
fn run_lane_call(call: &[LaneMsm<'_>], sums: &mut [G1Projective]) -> Option<()> {
    let streams = lane_streams(call);
    let (pairs, parts) = (streams / 2, streams % 2);
    let slots = pairs + parts;
    // A slot that a lane does not use holds the generator, whose table meets no excluded case, and
    // zero digits.
    let g = G1Affine::prime_subgroup_generator();
    let mut points = vec![[[g.x, g.y]; 8]; slots];
    let mut windows = vec![[[[0i8; 8]; 2]; GLV_WINDOWS]; slots];
    let mut lane_sums = [None; 8];
    let mut lane_terms: [Vec<LaneTerm>; 8] = Default::default();
    let mut len = 0;
    let mut first = 0;
    for &(sum, terms) in call {
        let lanes = (2 * terms.len()).div_ceil(streams);
        let in_pairs = (lanes * pairs).min(terms.len());
        for (t, (base, scalar)) in terms.iter().enumerate() {
            let (k1, k2, k1_neg, k2_neg) = glv_decompose(scalar);
            if t < in_pairs {
                let (lane, slot) = (first + t % lanes, t / lanes);
                points[slot][lane] = [base.x, base.y];
                len = len.max(signed_windows(&k1.to_bigint(), k1_neg, &mut windows[slot], 0, lane));
                len = len.max(signed_windows(&k2.to_bigint(), !k2_neg, &mut windows[slot], 1, lane));
                lane_terms[lane].push(LaneTerm::Pair(*base, *scalar));
            } else {
                let lane = first + 2 * (t - in_pairs);
                let halves = [(*base, k1, k1_neg), (Parameters::glv_endomorphism(*base), k2, !k2_neg)];
                for (lane, (point, k, negate)) in (lane..).zip(halves) {
                    points[pairs][lane] = [point.x, point.y];
                    len = len.max(signed_windows(&k.to_bigint(), negate, &mut windows[pairs], 0, lane));
                    lane_terms[lane].push(LaneTerm::Half(point, k, negate));
                }
            }
        }
        lane_sums[first..first + lanes].fill(Some(sum));
        first += lanes;
    }
    let digits: Vec<_> = windows.iter().map(|slot| &slot[..len]).collect();
    let out = ifma::glv_mul_8(&points, &Parameters::PHI, &digits)?;
    for ((sum, terms), [x, y, z]) in lane_sums.into_iter().zip(lane_terms).zip(out) {
        let Some(sum) = sum else { continue };
        sums[sum] += &if z.is_zero() {
            terms
                .into_iter()
                .map(|term| match term {
                    LaneTerm::Pair(base, scalar) => Parameters::mul_projective(base.into(), scalar),
                    LaneTerm::Half(point, k, negate) => {
                        let product = point.mul_bits(BitIteratorBE::new_without_leading_zeros(k.to_bigint()));
                        if negate { -product } else { product }
                    }
                })
                .sum()
        } else {
            G1Projective::new(x, y, z)
        };
    }
    Some(())
}

/// The most signed 4-bit windows of a scalar below 2^256.
const GLV_WINDOWS: usize = 65;

/// Returns the two parts of `scalar` and their signs, as `mul_projective` decomposes it:
/// `scalar P = ±k_1 P ± k_2 phi(P)`.
fn glv_decompose(scalar: &Fr) -> (Fr, Fr, bool, bool) {
    scalar.decompose(
        &Parameters::Q1,
        &Parameters::Q2,
        Parameters::B1,
        Parameters::B2,
        Parameters::R128,
        &Parameters::HALF_R,
    )
}

/// Writes the signed 4-bit windows of `k`, negated if `negate`, to `windows[i][half][lane]` for
/// window `i` from the least significant, and returns the number of windows up to the highest
/// nonzero one. Each window is in `[-8, 8]`. `windows` holds at least `GLV_WINDOWS` entries.
fn signed_windows(k: &BigInteger256, negate: bool, windows: &mut [[[i8; 8]; 2]], half: usize, lane: usize) -> usize {
    let mut carry = 0;
    let mut len = 0;
    for (i, window) in windows.iter_mut().enumerate() {
        let w = if i < 64 { (k.0[i / 16] >> (4 * (i % 16)) & 15) as i8 } else { 0 } + carry;
        carry = i8::from(w >= 8);
        let d = w - 16 * carry;
        window[half][lane] = if negate { -d } else { d };
        if d != 0 {
            len = i + 1;
        }
    }
    len
}
