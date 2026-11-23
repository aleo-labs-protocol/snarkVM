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

//! The Montgomery kernel and the reductions, each with the bounds it needs and returns.
//!
//! `mont` multiplies with `vpmadd52luq` and `vpmadd52huq` and divides by 2^52 in each of its 8
//! rounds, so a product leaves it divided by 2^416. `below_2p` and `canonical` reduce a signed
//! value whose limbs have run past 52 bits after lane-wise sums.

use super::layout::{MASK, add, radix_52, splat};
use crate::Fp384Parameters;

use std::arch::x86_64::*;

/// Returns `a b 2^-416 mod p` in each lane, in `[0, p)` with limbs below 2^52.
///
/// Requires limbs below 2^52, odd `p < 2^377` in `p`, `-p^-1 mod 2^52` in `n0` and
/// `a b < 2^416 p`, as for `b < p` and `a < 2^32 p`.
///
/// # Safety
///
/// The CPU supports AVX-512F and AVX-512 IFMA.
#[inline(always)]
pub(super) unsafe fn mont(a: &[__m512i; 8], b: &[__m512i; 8], p: &[__m512i; 8], n0: __m512i) -> [__m512i; 8] {
    // SAFETY: the caller guarantees both target features.
    unsafe {
        let [r] = mont_n([a], [b], p, n0);
        subtract_p_below_2p(&normalize(&r), p)
    }
}

/// Returns an integer below `2 p` congruent to `a[s] b[s] 2^-416` in each lane, with limbs below
/// 2^57, for each `s`, under the requirements of `mont`.
///
/// The rounds of the `N` products are interleaved: each round of one product depends on the round
/// before, so a single product leaves most of the IFMA throughput unused. The 8 rounds are written
/// out by `round!`: as a loop, LLVM keeps the accumulator on the stack.
///
/// # Safety
///
/// The CPU supports AVX-512F and AVX-512 IFMA. This function has no `target_feature`, so that it
/// can be `inline(always)`: as an `inline` hint, LLVM stops inlining it once it has two callers.
#[inline(always)]
pub(super) unsafe fn mont_n<const N: usize>(
    a: [&[__m512i; 8]; N],
    b: [&[__m512i; 8]; N],
    p: &[__m512i; 8],
    n0: __m512i,
) -> [[__m512i; 8]; N] {
    // SAFETY: the caller guarantees both target features.
    unsafe {
        let zero = _mm512_setzero_si512();
        let mut t = [[zero; 9]; N];

        // Adds the low half of `x y` to `lo` and the high half to `hi`.
        macro_rules! madd {
            ($lo:expr, $hi:expr, $x:expr, $y:expr) => {
                $lo = _mm512_madd52lo_epu64($lo, $x, $y);
                $hi = _mm512_madd52hi_epu64($hi, $x, $y);
            };
        }

        // Adds `a b_i` and `m p` to the accumulator `t_0 + t_1 2^52 + ... + t_8 2^416` of each
        // product, with `m` chosen so that the sum is divisible by 2^52, and divides it by 2^52.
        // `t_0` is zero afterwards, and the next round takes it as its top limb. Each limb of the
        // result enters as `t_8`, which a round raises by less than 2^53, and each later round
        // adds less than `2^54 + 2^12`, so the limbs stay below `2^53 + 7 (2^54 + 2^12) < 2^57`.
        macro_rules! round {
            ($i:literal; $t0:literal, $t1:literal, $t2:literal, $t3:literal, $t4:literal, $t5:literal, $t6:literal, $t7:literal, $t8:literal) => {
                for s in 0..N {
                    let (a, t, bi) = (a[s], &mut t[s], b[s][$i]);
                    madd!(t[$t0], t[$t1], a[0], bi);
                    madd!(t[$t1], t[$t2], a[1], bi);
                    madd!(t[$t2], t[$t3], a[2], bi);
                    madd!(t[$t3], t[$t4], a[3], bi);
                    madd!(t[$t4], t[$t5], a[4], bi);
                    madd!(t[$t5], t[$t6], a[5], bi);
                    madd!(t[$t6], t[$t7], a[6], bi);
                    madd!(t[$t7], t[$t8], a[7], bi);
                    let m = _mm512_madd52lo_epu64(zero, t[$t0], n0);
                    madd!(t[$t0], t[$t1], m, p[0]);
                    madd!(t[$t1], t[$t2], m, p[1]);
                    madd!(t[$t2], t[$t3], m, p[2]);
                    madd!(t[$t3], t[$t4], m, p[3]);
                    madd!(t[$t4], t[$t5], m, p[4]);
                    madd!(t[$t5], t[$t6], m, p[5]);
                    madd!(t[$t6], t[$t7], m, p[6]);
                    madd!(t[$t7], t[$t8], m, p[7]);
                    t[$t1] = _mm512_add_epi64(t[$t1], _mm512_srli_epi64::<52>(t[$t0]));
                    t[$t0] = zero;
                }
            };
        }

        round!(0; 0, 1, 2, 3, 4, 5, 6, 7, 8);
        round!(1; 1, 2, 3, 4, 5, 6, 7, 8, 0);
        round!(2; 2, 3, 4, 5, 6, 7, 8, 0, 1);
        round!(3; 3, 4, 5, 6, 7, 8, 0, 1, 2);
        round!(4; 4, 5, 6, 7, 8, 0, 1, 2, 3);
        round!(5; 5, 6, 7, 8, 0, 1, 2, 3, 4);
        round!(6; 6, 7, 8, 0, 1, 2, 3, 4, 5);
        round!(7; 7, 8, 0, 1, 2, 3, 4, 5, 6);

        // The result, below `2 p`, is `t_8 + t_0 2^52 + ... + t_6 2^364`: the last round zeroed
        // `t_7`, its limb at 2^416.
        let mut r = [[zero; 8]; N];
        for (r, t) in r.iter_mut().zip(&t) {
            *r = [t[8], t[0], t[1], t[2], t[3], t[4], t[5], t[6]];
        }
        r
    }
}

/// Returns `x` mod `p` in `[0, p)` with limbs below 2^52, for `x` in `(-64 p, 64 p)` with limbs
/// below 2^62 in absolute value and `2^366 <= p < 2^377`. `offset` and `estimate` hold
/// `canonical_constants(p)` in every lane.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
pub(super) fn canonical(x: &[__m512i; 8], p: &[__m512i; 8], offset: &[__m512i; 8], estimate: __m512i) -> [__m512i; 8] {
    subtract_p_below_2p(&below_2p(x, p, offset, estimate), p)
}

/// Returns `x` mod `p` in `[0, 2 p)` with limbs below 2^52, for `x` in `(-k p, 2^33 p)` with
/// limbs below 2^62 in absolute value and `2^366 <= p < 2^377`, where `offset` holds `k p` in
/// every lane for a `k` at most 2^33, and `estimate` holds `quotient_estimate(p)`;
/// `canonical_vectors` gives both for `k = 64`.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
pub(super) fn below_2p(x: &[__m512i; 8], p: &[__m512i; 8], offset: &[__m512i; 8], estimate: __m512i) -> [__m512i; 8] {
    let zero = _mm512_setzero_si512();
    // `v = x + k p` is in `(0, 2^34 p)`, below 2^411, so its top limb `v_7` is below 2^47. With
    // `e = estimate`, `quotient = floor(v_7 e / 2^52)` is at most `v / p`, since `e <= 2^416 / p`.
    // And `v / p - quotient < 2`, since `v < (v_7 + 1) 2^364`, `2^364 / p <= 1 / 4`,
    // `e > 2^416 / p - 1` and `v_7 / 2^52 < 1 / 32`. So `v - quotient p` is in `[0, 2 p)`. The
    // high half of `quotient p_7` is zero, since `quotient < 2^34` and `p_7 < 2^13`.
    let v = signed_normalize(&add(x, offset));
    let quotient = _mm512_madd52hi_epu64(zero, v[7], estimate);
    let mut r = v;
    for k in 0..8 {
        r[k] = _mm512_sub_epi64(r[k], _mm512_madd52lo_epu64(zero, quotient, p[k]));
        if k < 7 {
            r[k + 1] = _mm512_sub_epi64(r[k + 1], _mm512_madd52hi_epu64(zero, quotient, p[k]));
        }
    }
    signed_normalize(&r)
}

/// Returns the limbs of `64 p` and `floor(2^416 / p)`, for `2^366 <= p < 2^377`.
pub(super) const fn canonical_constants(p: &[u64; 6]) -> ([u64; 8], u64) {
    (radix_52(&shift_left(p, 6)), quotient_estimate(p))
}

/// Returns `canonical_constants(P::MODULUS)` in every lane: the `offset` and `estimate` of
/// `canonical` and `below_2p`.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn canonical_vectors<P: Fp384Parameters>() -> ([__m512i; 8], __m512i) {
    let (offset, estimate) = const { canonical_constants(&P::MODULUS.0) };
    (splat(&offset), _mm512_set1_epi64(estimate as i64))
}

/// Returns `floor(2^416 / p)`, for `2^366 <= p < 2^377`.
pub(super) const fn quotient_estimate(p: &[u64; 6]) -> u64 {
    // Long division of `r = 2^416` by `d = p 2^i` for `i` from 50 down to 0, in 7 words.
    let mut r: [u64; 7] = [0, 0, 0, 0, 0, 0, 1 << 32];
    let mut q = 0;
    let mut i = 51;
    while i > 0 {
        i -= 1;
        let mut d = [0; 7];
        let mut j = 0;
        while j < 7 {
            if j < 6 {
                d[j] = p[j] << i;
            }
            if j > 0 && i > 0 {
                d[j] |= p[j - 1] >> (64 - i);
            }
            j += 1;
        }
        let mut t = [0; 7];
        let mut borrow = 0;
        let mut j = 0;
        while j < 7 {
            let (x, b1) = r[j].overflowing_sub(d[j]);
            let (x, b2) = x.overflowing_sub(borrow);
            t[j] = x;
            borrow = (b1 | b2) as u64;
            j += 1;
        }
        if borrow == 0 {
            r = t;
            q |= 1 << i;
        }
    }
    q
}

/// Returns `x 2^s`, for `x 2^s < 2^384` and `0 < s < 64`.
pub(super) const fn shift_left(x: &[u64; 6], s: u32) -> [u64; 6] {
    let mut y = [0; 6];
    let mut j = 0;
    while j < 6 {
        y[j] = x[j] << s;
        if j > 0 {
            y[j] |= x[j - 1] >> (64 - s);
        }
        j += 1;
    }
    y
}

/// Returns the limbs, below 2^52 but for the top one, of the integers below 2^416 whose limbs are
/// `x`, each below 2^63.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn normalize(x: &[__m512i; 8]) -> [__m512i; 8] {
    let mask = _mm512_set1_epi64(MASK as i64);
    let mut v = *x;
    for k in 0..7 {
        v[k + 1] = _mm512_add_epi64(v[k + 1], _mm512_srli_epi64::<52>(v[k]));
        v[k] = _mm512_and_si512(v[k], mask);
    }
    v
}

/// Returns the limbs, below 2^52 but for the top one, of the integers in `[0, 2^416)` whose
/// limbs are the signed `x`, each below 2^62 in absolute value.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn signed_normalize(x: &[__m512i; 8]) -> [__m512i; 8] {
    let mask = _mm512_set1_epi64(MASK as i64);
    let mut v = *x;
    for k in 0..7 {
        v[k + 1] = _mm512_add_epi64(v[k + 1], _mm512_srai_epi64::<52>(v[k]));
        v[k] = _mm512_and_si512(v[k], mask);
    }
    v
}

/// Returns `x` mod `p` in `[0, p)`, for `x` below `2 p` with limbs below 2^52.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn subtract_p_below_2p(x: &[__m512i; 8], p: &[__m512i; 8]) -> [__m512i; 8] {
    let (zero, mask) = (_mm512_setzero_si512(), _mm512_set1_epi64(MASK as i64));
    let mut d = [zero; 8];
    let mut borrow = zero;
    for k in 0..8 {
        d[k] = _mm512_sub_epi64(_mm512_sub_epi64(x[k], p[k]), borrow);
        borrow = _mm512_srli_epi64::<63>(d[k]);
    }
    let keep = _mm512_cmpneq_epi64_mask(borrow, zero);
    let mut v = [zero; 8];
    for k in 0..8 {
        v[k] = _mm512_mask_blend_epi64(keep, _mm512_and_si512(d[k], mask), x[k]);
    }
    v
}
