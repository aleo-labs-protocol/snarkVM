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

//! The lane layout: moves between `Fp384` words and limbs, lane permutes, and lane-wise sums.
//!
//! A vector group `[__m512i; 8]` holds 8 integers: vector `k` holds limb `k` of each of the 8
//! lanes, in radix 2^52. A word group `[__m512i; 6]` holds 8 integers below 2^384: vector `w`
//! holds word `w` of each lane, in radix 2^64.

use crate::{Fp384, Fp384Parameters, Zero};

use std::arch::x86_64::*;

/// The low 52 bits.
pub(super) const MASK: u64 = (1 << 52) - 1;

/// Returns the radix-2^52 limbs of an integer below 2^416 in `N` words, `N` 6 or 7.
pub(super) const fn radix_52<const N: usize>(x: &[u64; N]) -> [u64; 8] {
    let mut limbs = [0; 8];
    let mut k = 0;
    while k < 8 {
        let (w, s) = (52 * k / 64, 52 * k % 64);
        let mut limb = x[w] >> s;
        if s > 12 && w + 1 < N {
            limb |= x[w + 1] << (64 - s);
        }
        limbs[k] = limb & MASK;
        k += 1;
    }
    limbs
}

/// Returns the vectors whose lanes all hold `x[k]` in vector `k`.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn splat<const N: usize>(x: &[u64; N]) -> [__m512i; N] {
    let mut v = [_mm512_setzero_si512(); N];
    for (v, x) in v.iter_mut().zip(x) {
        *v = _mm512_set1_epi64(*x as i64);
    }
    v
}

/// Returns the limbs of `P::MODULUS` in every lane.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn modulus<P: Fp384Parameters>() -> [__m512i; 8] {
    splat(&const { radix_52(&P::MODULUS.0) })
}

/// Returns the vector whose lane `l` holds `x[l]`.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn vector(x: [u64; 8]) -> __m512i {
    _mm512_set_epi64(
        x[7] as i64,
        x[6] as i64,
        x[5] as i64,
        x[4] as i64,
        x[3] as i64,
        x[2] as i64,
        x[1] as i64,
        x[0] as i64,
    )
}

/// Returns the 8 lanes of `x`.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn to_array(x: __m512i) -> [u64; 8] {
    let mut a = [0; 8];
    // SAFETY: this writes 8 words to `a`, an array of 8 words.
    unsafe { _mm512_storeu_epi64(a.as_mut_ptr().cast(), x) };
    a
}

/// Returns the words of `x[l]` in lane `l`: lane `l` of vector `w` holds word `w` of `x[l]`.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn element_words<P: Fp384Parameters>(x: [&Fp384<P>; 8]) -> [__m512i; 6] {
    let mut v = [_mm512_setzero_si512(); 6];
    for (w, v) in v.iter_mut().enumerate() {
        let word = |l: usize| x[l].0.0[w] as i64;
        *v = _mm512_set_epi64(word(7), word(6), word(5), word(4), word(3), word(2), word(1), word(0));
    }
    v
}

/// Returns the words of `x[start..start + 6]`, as `element_words`, with lanes 6 and 7 zero.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn coefficient_words<P: Fp384Parameters>(x: &[&Fp384<P>; 12], start: usize) -> [__m512i; 6] {
    let zero = Fp384::<P>::zero();
    element_words([x[start], x[start + 1], x[start + 2], x[start + 3], x[start + 4], x[start + 5], &zero, &zero])
}

/// Returns the 8 lanes of `e` and `f` that `index` picks: entry `t` of `index` picks lane `t` of
/// `e` for `t < 8`, and lane `t - 8` of `f` otherwise.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn permute(e: &[__m512i; 8], index: __m512i, f: &[__m512i; 8]) -> [__m512i; 8] {
    let mut v = [_mm512_setzero_si512(); 8];
    for k in 0..8 {
        v[k] = _mm512_permutex2var_epi64(e[k], index, f[k]);
    }
    v
}

/// Returns `x + y`, limb by limb.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn add(x: &[__m512i; 8], y: &[__m512i; 8]) -> [__m512i; 8] {
    let mut v = [_mm512_setzero_si512(); 8];
    for k in 0..8 {
        v[k] = _mm512_add_epi64(x[k], y[k]);
    }
    v
}

/// Returns `x - y`, limb by limb.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn sub(x: &[__m512i; 8], y: &[__m512i; 8]) -> [__m512i; 8] {
    let mut v = [_mm512_setzero_si512(); 8];
    for k in 0..8 {
        v[k] = _mm512_sub_epi64(x[k], y[k]);
    }
    v
}

/// Returns `x` with lanes 0 to 3 and lanes 4 to 7 swapped.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn swap_halves(x: &[__m512i; 8]) -> [__m512i; 8] {
    let mut v = [_mm512_setzero_si512(); 8];
    for k in 0..8 {
        v[k] = _mm512_shuffle_i64x2::<0b01_00_11_10>(x[k], x[k]);
    }
    v
}

/// Returns lanes 0 to 3 of `lo` and lanes 4 to 7 of `hi`.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn blend_halves(lo: &[__m512i; 8], hi: &[__m512i; 8]) -> [__m512i; 8] {
    let mut v = [_mm512_setzero_si512(); 8];
    for k in 0..8 {
        v[k] = _mm512_mask_blend_epi64(0xF0, lo[k], hi[k]);
    }
    v
}

/// Returns lanes 0 to 3 of `x`, with lanes 4 to 7 zero.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn low_half(x: &[__m512i; 8]) -> [__m512i; 8] {
    let mut v = [_mm512_setzero_si512(); 8];
    for k in 0..8 {
        v[k] = _mm512_maskz_mov_epi64(0x0F, x[k]);
    }
    v
}

/// Returns `(lo >> R | hi << L) & MASK`.
#[inline]
#[target_feature(enable = "avx512f")]
fn join<const R: u32, const L: u32>(lo: __m512i, hi: __m512i) -> __m512i {
    let mask = _mm512_set1_epi64(MASK as i64);
    _mm512_ternarylogic_epi64::<0xA8>(_mm512_srli_epi64::<R>(lo), _mm512_slli_epi64::<L>(hi), mask)
}

/// Returns the limbs of the 384-bit integers whose words are `w`.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn limbs(w: &[__m512i; 6]) -> [__m512i; 8] {
    let mask = _mm512_set1_epi64(MASK as i64);
    [
        _mm512_and_si512(w[0], mask),
        join::<52, 12>(w[0], w[1]),
        join::<40, 24>(w[1], w[2]),
        join::<28, 36>(w[2], w[3]),
        join::<16, 48>(w[3], w[4]),
        _mm512_and_si512(_mm512_srli_epi64::<4>(w[4]), mask),
        join::<56, 8>(w[4], w[5]),
        _mm512_srli_epi64::<44>(w[5]),
    ]
}

/// Returns the limbs of `x 2^32` for the 384-bit integers `x` whose words are `w`.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn limbs_shifted_32(w: &[__m512i; 6]) -> [__m512i; 8] {
    let mask = _mm512_set1_epi64(MASK as i64);
    [
        _mm512_and_si512(_mm512_slli_epi64::<32>(w[0]), mask),
        join::<20, 44>(w[0], w[1]),
        _mm512_and_si512(_mm512_srli_epi64::<8>(w[1]), mask),
        join::<60, 4>(w[1], w[2]),
        join::<48, 16>(w[2], w[3]),
        join::<36, 28>(w[3], w[4]),
        join::<24, 40>(w[4], w[5]),
        _mm512_srli_epi64::<12>(w[5]),
    ]
}

/// Returns the words of the integers below 2^384 whose limbs, each below 2^52, are `v`.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn words(v: &[__m512i; 8]) -> [__m512i; 6] {
    [
        _mm512_or_si512(v[0], _mm512_slli_epi64::<52>(v[1])),
        _mm512_or_si512(_mm512_srli_epi64::<12>(v[1]), _mm512_slli_epi64::<40>(v[2])),
        _mm512_or_si512(_mm512_srli_epi64::<24>(v[2]), _mm512_slli_epi64::<28>(v[3])),
        _mm512_or_si512(_mm512_srli_epi64::<36>(v[3]), _mm512_slli_epi64::<16>(v[4])),
        _mm512_ternarylogic_epi64::<0xFE>(
            _mm512_srli_epi64::<48>(v[4]),
            _mm512_slli_epi64::<4>(v[5]),
            _mm512_slli_epi64::<56>(v[6]),
        ),
        _mm512_or_si512(_mm512_srli_epi64::<8>(v[6]), _mm512_slli_epi64::<44>(v[7])),
    ]
}

/// Marks a lane of a `permute_z` or `lane_words` index that is zero.
pub(super) const Z: u64 = 16;

/// Returns the words of `x[index[l]]` in lane `l`, as `element_words`, with lane `l` zero
/// where `index[l]` is `Z`.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn lane_words<P: Fp384Parameters>(x: &[&Fp384<P>; 12], index: [u64; 8]) -> [__m512i; 6] {
    let mut v = [_mm512_setzero_si512(); 6];
    for (w, v) in v.iter_mut().enumerate() {
        let word = |l: usize| x.get(index[l] as usize).map_or(0, |x| x.0.0[w] as i64);
        *v = _mm512_set_epi64(word(7), word(6), word(5), word(4), word(3), word(2), word(1), word(0));
    }
    v
}

/// Returns `permute(e, vector(index), f)` with lane `t` zero where entry `t` of `index` is `Z`.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn permute_z(e: &[__m512i; 8], index: [u64; 8], f: &[__m512i; 8]) -> [__m512i; 8] {
    let mut mask = 0;
    for (t, i) in index.iter().enumerate() {
        mask |= ((*i != Z) as u8) << t;
    }
    let index = vector(index);
    let mut v = [_mm512_setzero_si512(); 8];
    for k in 0..8 {
        v[k] = _mm512_maskz_permutex2var_epi64(mask, e[k], index, f[k]);
    }
    v
}
