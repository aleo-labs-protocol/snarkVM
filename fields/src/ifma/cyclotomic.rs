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

//! The cyclotomic exponentiation chain, held in lanes from the first squaring to the last product.
//!
//! The tower is that of `fp12`, and `2^366 <= p < 2^377`. The element stays in the layout of
//! `CYCLOTOMIC_LANES` for the whole chain: each coefficient is an integer in `[0, 2 p)` congruent
//! to `x 2^416 mod p`, with limbs below 2^52, so `mont` multiplies two of them into a third.
//!
//! Entry: each coefficient enters as `a 2^32`, below `2^32 p`, from `Fp384`'s words, and
//! `below_2p` takes it to `[0, 2 p)`.
//!
//! A squaring: each kernel operand is below `4 p` for `a` and below `18 p` for `b`, so each
//! kernel product is below `72 p^2 < 2^416 p`, and `mont_n` returns it below `2 p` with limbs
//! below 2^57. `square_terms` returns each coefficient in `(-34 p, 24 p)` with limbs below 2^62
//! in absolute value, and `below_2p`, with the offset `64 p`, takes it to `[0, 2 p)`.
//!
//! A product by the base: each kernel operand is a sum of at most 4 coefficients, so it is below
//! `8 p`, each kernel product is below `64 p^2 < 2^416 p`, and `mont` returns it in `[0, p)`.
//! `fp12_recombine` returns each coefficient in `(-64 p, 64 p)`, and `below_2p` takes it to
//! `[0, 2 p)`.
//!
//! Exit: `mont` by `2^384 mod p` returns each coefficient in `[0, p)`: the canonical Montgomery
//! form, bit-identical to the scalar chain.

use super::{
    fp12::{fp12_operand, fp12_product},
    kernel::{below_2p, canonical_vectors, mont, mont_n, normalize, shift_left, signed_normalize},
    layout::{
        MASK,
        Z,
        add,
        lane_words,
        limbs_shifted_32,
        modulus,
        permute,
        permute_z,
        radix_52,
        splat,
        to_array,
        vector,
        words,
    },
};
use crate::{Fp384, Fp384Parameters};

use std::arch::x86_64::*;

/// The coefficients of an Fp12 element in the two vectors of the cyclotomic layout, by their
/// index in the order of `coefficients`.
///
/// Lanes `4 g` to `4 g + 3` hold the pair `(A, B) = (z_{2g}, z_{2g+1})` of Fp2 coefficients of
/// `Fp12::cyclotomic_square`, as `[a_0, a_1, b_0, b_1]`: `z_0 = c0.c0`, `z_1 = c1.c1`,
/// `z_2 = c1.c0`, `z_3 = c0.c2`, `z_4 = c0.c1` and `z_5 = c1.c2`. Lanes 4 to 7 of the second
/// vector are unused. As a `permute_z` index from the 12 coefficients in lanes 0 to 7 and 8 to 11,
/// it also maps that order to this layout.
const CYCLOTOMIC_LANES: [[u64; 8]; 2] = [[0, 1, 8, 9, 6, 7, 4, 5], [2, 3, 10, 11, Z, Z, Z, Z]];

/// The `permute_z` indices from the cyclotomic layout to the Fp6 coefficients `c0` and `c1` in
/// lanes 0 to 5, the operands of `fp12_operand`.
const FP6_LANES: [[u64; 8]; 2] = [[0, 1, 8, 9, 6, 7, Z, Z], [4, 5, 2, 3, 10, 11, Z, Z]];

/// Sets `a` to `a^exp` by the chain of `Fp12::cyclotomic_exp`, as `cyclotomic_exp_fp12`, for
/// `exp` whose highest set bit is bit `top`. Requires `2^366 <= p < 2^377`.
///
/// # Safety
///
/// The CPU supports AVX-512F and AVX-512 IFMA.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(super) unsafe fn cyclotomic_exp_avx512<P: Fp384Parameters>(a: [&mut Fp384<P>; 12], exp: &[u64], top: usize) {
    let p = modulus::<P>();
    let n0 = _mm512_set1_epi64((P::INV & MASK) as i64);
    let (offset, estimate) = canonical_vectors::<P>();
    let p16 = splat(&const { radix_52(&shift_left(&P::MODULUS.0, 4)) });

    let mut a_ref = [&*a[0]; 12];
    for (r, x) in a_ref.iter_mut().zip(&a) {
        *r = &**x;
    }
    let [w0, w1] = [lane_words(&a_ref, CYCLOTOMIC_LANES[0]), lane_words(&a_ref, CYCLOTOMIC_LANES[1])];
    let base = [
        below_2p(&limbs_shifted_32(&w0), &p, &offset, estimate),
        below_2p(&limbs_shifted_32(&w1), &p, &offset, estimate),
    ];
    // SAFETY: this function enables the target feature that `fp6_operands` requires.
    let b = unsafe { fp6_operands(&base) };

    let mut z = base;
    for i in (0..top).rev() {
        z = cyclotomic_square(&z, &p, n0, &p16, &offset, estimate);
        if exp[i / 64] >> (i % 64) & 1 == 1 {
            // SAFETY: this function enables both target features that `fp6_operands` and `fp12_product`
            // require.
            let [c0, c1] = unsafe { fp12_product(&fp6_operands(&z), &b, &p, n0) };
            z = [
                below_2p(&permute_z(&c0, CYCLOTOMIC_LANES[0], &c1), &p, &offset, estimate),
                below_2p(&permute_z(&c0, CYCLOTOMIC_LANES[1], &c1), &p, &offset, estimate),
            ];
        }
    }

    let r = splat(&const { radix_52(&P::R.0) });
    // SAFETY: this function enables both target features that `mont` requires.
    let (c0, c1) = unsafe { (words(&mont(&z[0], &r, &p, n0)), words(&mont(&z[1], &r, &p, n0))) };
    let mut out = [[[0; 8]; 6]; 2];
    for (out, c) in out.iter_mut().zip([c0, c1]) {
        for (out, w) in out.iter_mut().zip(c) {
            *out = to_array(w);
        }
    }
    for (out, lanes) in out.iter().zip(&CYCLOTOMIC_LANES) {
        for (l, k) in lanes.iter().enumerate() {
            if *k == Z {
                continue;
            }
            for (w, a) in a[*k as usize].0.0.iter_mut().enumerate() {
                *a = out[w][l];
            }
        }
    }
}

/// Returns the operands of `fp12_operand` for the element `z` in the cyclotomic layout.
///
/// # Safety
///
/// The CPU supports AVX-512F. This function has no `target_feature`, so that it can be
/// `inline(always)`: as an `inline` hint, LLVM stops inlining it once it has two callers.
#[inline(always)]
unsafe fn fp6_operands(z: &[[__m512i; 8]; 2]) -> [[__m512i; 8]; 6] {
    // SAFETY: the caller guarantees the target feature.
    unsafe { fp12_operand(&permute_z(&z[0], FP6_LANES[0], &z[1]), &permute_z(&z[0], FP6_LANES[1], &z[1])) }
}

/// Returns the cyclotomic square of the element `z`, as `Fp12::cyclotomic_square` computes it, in
/// the cyclotomic layout of `cyclotomic_exp_avx512`.
///
/// `Fp12::cyclotomic_square` takes `t_e = A^2 + u B^2` and `t_o = 2 A B` from each pair `(A, B)`.
/// With `s_X = x_0 + x_1` and `d_X = x_0 - 5 x_1` for an Fp2 element `X`, `mont_n` computes for
/// pair `g` the products
///   `L = [s_A d_A, 2 a_0 a_1, s_B d_B, 2 b_0 b_1, 2 a_0 b_0, 2 a_1 b_1, 2 a_0 b_1, 2 a_1 b_0]`
/// in group `g`, so `A^2 = (L_0 + 2 L_1, L_1)`, `B^2 = (L_2 + 2 L_3, L_3)` and
/// `2 A B = (L_4 - 5 L_5, L_6 + L_7)`. Group 2 multiplies `2 A` by `u B = (-5 b_1, b_0)` instead
/// of `B`, so its last four products give `u t_o` in the same way.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn cyclotomic_square(
    z: &[[__m512i; 8]; 2],
    p: &[__m512i; 8],
    n0: __m512i,
    p16: &[__m512i; 8],
    offset: &[__m512i; 8],
    estimate: __m512i,
) -> [[__m512i; 8]; 2] {
    let [x, y] = z;
    // `sx` holds `[s_A, d_A, s_B, d_B]` of pairs 0 and 1, `dx` twice their coefficients, and `sy`
    // `[s_A, d_A, s_B, d_B, 2 a_0, 2 a_1, 2 b_0, -5 b_1]` of pair 2, with `16 p` added to the
    // lanes that subtract.
    let sx = pair_sums(
        &permute_z(x, [0, 0, 2, 2, 4, 4, 6, 6], x),
        &permute_z(x, [1, 1, 3, 3, 5, 5, 7, 7], x),
        0b1010_1010,
        p16,
    );
    let dx = normalize(&add(x, x));
    let sy = pair_sums(
        &permute_z(y, [0, 0, 2, 2, 0, 1, 2, Z], y),
        &permute_z(y, [1, 1, 3, 3, 0, 1, 2, 3], y),
        0b1000_1010,
        p16,
    );
    let lhs = [
        permute(&sx, vector(SQUARE_LHS[0]), &dx),
        permute(&sx, vector(SQUARE_LHS[1]), &dx),
        permute(&sy, vector(SQUARE_LHS[2]), &sy),
    ];
    let rhs = [
        permute(x, vector(SQUARE_RHS[0]), &sx),
        permute(x, vector(SQUARE_RHS[1]), &sx),
        permute(y, vector(SQUARE_RHS[2]), &sy),
    ];
    // SAFETY: this function enables both target features that `mont_n` requires.
    let l = unsafe { mont_n(lhs.each_ref(), rhs.each_ref(), p, n0) };
    // Pair 0 takes `t_e` and `t_o` from group 0, pair 1 takes `u t_o` and `t_e` from group 2, and
    // pair 2 takes `t_e` and `t_o` from group 1.
    // SAFETY: this function enables the target feature that `square_terms` requires.
    let [t0, t1] = unsafe {
        [
            square_terms(&l[0], &SQUARE_TERMS[0], &l[2], x, SQUARE_NEGATIVE[0]),
            square_terms(&l[1], &SQUARE_TERMS[1], &l[1], y, SQUARE_NEGATIVE[1]),
        ]
    };
    [below_2p(&t0, p, offset, estimate), below_2p(&t1, p, offset, estimate)]
}

/// The lanes of `permute` that make the kernel operands of group `g` of `cyclotomic_square`, from
/// `sx` and `dx` for `a` and from `x` and `sx` for `b` in groups 0 and 1, and from `sy` alone for
/// `a` and from `y` and `sy` for `b` in group 2.
const SQUARE_LHS: [[u64; 8]; 3] = [[0, 8, 2, 10, 8, 9, 8, 9], [4, 12, 6, 14, 12, 13, 12, 13], [0, 4, 2, 6, 4, 5, 4, 5]];
const SQUARE_RHS: [[u64; 8]; 3] = [[9, 1, 11, 3, 2, 3, 3, 2], [13, 5, 15, 7, 6, 7, 7, 6], [9, 1, 11, 3, 15, 2, 2, 15]];

/// The lanes of each vector of the cyclotomic layout where `square_terms` subtracts `2 z`.
const SQUARE_NEGATIVE: [__mmask8; 2] = [0b1100_0011, 0b0000_0011];

/// The `permute_z` indices of the terms `t_0` to `t_3` of `square_terms`, for each vector of the
/// cyclotomic layout. In a pair's 4 lanes, `t_0 + t_1 + 2 t_2 - 5 t_3` is
/// `[L_0 + 2 L_1 - 5 L_3, L_1 + L_2 + 2 L_3, L_4 - 5 L_5, L_6 + L_7]`, which is `(t_e, t_o)` for
/// pairs 0 and 2, and the same with its two halves swapped, `(u t_o, t_e)`, for pair 1.
const SQUARE_TERMS: [[[u64; 8]; 4]; 2] = [
    [[0, 1, 4, 6, 12, 14, 8, 9], [Z, 2, Z, 7, Z, 15, Z, 10], [1, 3, Z, Z, Z, Z, 9, 11], [3, Z, 5, Z, 13, Z, 11, Z]],
    [[0, 1, 4, 6, Z, Z, Z, Z], [Z, 2, Z, 7, Z, Z, Z, Z], [1, 3, Z, Z, Z, Z, Z, Z], [3, Z, 5, Z, Z, Z, Z, Z]],
];

/// Returns `3 t + 2 z` in the lanes outside `negative` and `3 t - 2 z` in those of `negative`, with
/// `t = t_0 + t_1 + 2 t_2 - 5 t_3` and `t_i = permute_z(e, index[i], f)`, as signed limbs.
///
/// # Safety
///
/// The CPU supports AVX-512F. This function has no `target_feature`, so that it can be
/// `inline(always)`: as an `inline` hint, LLVM stops inlining it once it has two callers.
#[inline(always)]
unsafe fn square_terms(
    e: &[__m512i; 8],
    index: &[[u64; 8]; 4],
    f: &[__m512i; 8],
    z: &[__m512i; 8],
    negative: __mmask8,
) -> [__m512i; 8] {
    // SAFETY: the caller guarantees the target feature.
    unsafe {
        let [t0, t1, t2, t3] = [
            permute_z(e, index[0], f),
            permute_z(e, index[1], f),
            permute_z(e, index[2], f),
            permute_z(e, index[3], f),
        ];
        let mut v = [_mm512_setzero_si512(); 8];
        for k in 0..8 {
            let t = _mm512_add_epi64(_mm512_add_epi64(t0[k], t1[k]), _mm512_slli_epi64::<1>(t2[k]));
            let t = _mm512_sub_epi64(t, _mm512_add_epi64(t3[k], _mm512_slli_epi64::<2>(t3[k])));
            let t = _mm512_add_epi64(t, _mm512_slli_epi64::<1>(t));
            let z2 = _mm512_slli_epi64::<1>(z[k]);
            v[k] = _mm512_mask_sub_epi64(_mm512_add_epi64(t, z2), negative, t, z2);
        }
        v
    }
}

/// Returns `e + o` in the lanes outside `k` and `e + 16 p - 5 o` in those of `k`, with limbs below
/// 2^52, for `e` and `o` with limbs below 2^52 and `5 o <= 16 p` in the lanes of `k`. `p16` holds
/// the limbs of `16 p` in every lane.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn pair_sums(e: &[__m512i; 8], o: &[__m512i; 8], k: __mmask8, p16: &[__m512i; 8]) -> [__m512i; 8] {
    let mut v = [_mm512_setzero_si512(); 8];
    for j in 0..8 {
        let five = _mm512_add_epi64(o[j], _mm512_slli_epi64::<2>(o[j]));
        v[j] = _mm512_add_epi64(e[j], _mm512_mask_sub_epi64(o[j], k, p16[j], five));
    }
    signed_normalize(&v)
}
