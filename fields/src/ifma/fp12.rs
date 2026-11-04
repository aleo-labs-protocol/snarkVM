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

//! The Fp12 product, held in lanes from the operand words to the canonical result.
//!
//! The tower is Fp12 = Fp6[w] / (w^2 - v), Fp6 = Fp2[v] / (v^3 - u) and Fp2 = Fp[u] / (u^2 + 5),
//! and `2^366 <= p < 2^377`.
//!
//! Entry: `a` enters as `a 2^32`, below `2^32 p`, and `b` as `b`, below `p`, each from `Fp384`'s
//! words. Every kernel operand is a sum of at most 4 coefficients: below `2^34 p` for `a` and
//! below `4 p` for `b`, so each kernel product is below `2^36 p^2 / 2^416 + p < 2 p`, and `mont`
//! returns it in `[0, p)`.
//!
//! Exit: each coefficient of the result is a signed sum of kernel products with at most 51
//! positive and 57 negative unit terms, so it lies in `(-64 p, 64 p)` with limbs below 2^58 in
//! absolute value. `canonical` takes it to `[0, p)` with the offset `64 p`, and the result is the
//! canonical Montgomery form, bit-identical to the scalar product.

use super::{
    kernel::{canonical, canonical_vectors, mont, normalize},
    layout::{
        MASK,
        add,
        blend_halves,
        coefficient_words,
        limbs,
        limbs_shifted_32,
        low_half,
        modulus,
        permute,
        sub,
        swap_halves,
        to_array,
        vector,
        words,
    },
};
use crate::{Fp2Parameters, Fp12, Fp12Parameters, Fp384, Fp384Parameters, fp6_3over2::Fp6Parameters};

use std::arch::x86_64::*;

/// The base field of the tower of `P`.
type BaseField<P> = <<<P as Fp12Parameters>::Fp6Params as Fp6Parameters>::Fp2Params as Fp2Parameters>::Fp;

/// The 12 coefficients of `x`, in the order `c0.c0.c0`, `c0.c0.c1`, `c0.c1.c0`, ..., `c1.c2.c1`.
pub(super) fn coefficients<P: Fp12Parameters>(x: &Fp12<P>) -> [&BaseField<P>; 12] {
    let (x, y) = (&x.c0, &x.c1);
    [
        &x.c0.c0, &x.c0.c1, &x.c1.c0, &x.c1.c1, &x.c2.c0, &x.c2.c1, &y.c0.c0, &y.c0.c1, &y.c1.c0, &y.c1.c1, &y.c2.c0,
        &y.c2.c1,
    ]
}

/// The 12 coefficients of `x`, in the order of `coefficients`.
pub(super) fn coefficients_mut<P: Fp12Parameters>(x: &mut Fp12<P>) -> [&mut BaseField<P>; 12] {
    let (x, y) = (&mut x.c0, &mut x.c1);
    [
        &mut x.c0.c0,
        &mut x.c0.c1,
        &mut x.c1.c0,
        &mut x.c1.c1,
        &mut x.c2.c0,
        &mut x.c2.c1,
        &mut y.c0.c0,
        &mut y.c0.c1,
        &mut y.c1.c0,
        &mut y.c1.c1,
        &mut y.c2.c0,
        &mut y.c2.c1,
    ]
}

/// Sets `a` to `a * b` in Fp12, as `mul_assign_fp12`. Requires `2^366 <= p < 2^377`.
///
/// The product takes 72 products in Fp: Karatsuba multiplication in Fp12 over Fp6 and in Fp6
/// over Fp2, and schoolbook multiplication in Fp2. `mont` computes them in 9 groups of 8.
///
/// Write `x_0`, `x_1` and `x_2` for `a.c0`, `a.c1` and `a.c0 + a.c1`, and `x_{I,j}` for Fp2
/// coefficient `j` of `x_I`; likewise `y` for `b`. Group `3 I + m` multiplies `x_{I,m}` by
/// `y_{I,m}` in lanes 0 to 3, and `x_{I,m+1} + x_{I,m+2}` by `y_{I,m+1} + y_{I,m+2}` in lanes 4 to 7,
/// with indices mod 3. In each half, the lanes hold the 4 products `c0 c0`, `c1 c1`, `c0 c1` and
/// `c1 c0` of Fp coefficients `(x, y)`. Every later step adds or subtracts whole vectors, or moves
/// lanes within a vector.
///
/// # Safety
///
/// The CPU supports AVX-512F and AVX-512 IFMA.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(super) unsafe fn mul_assign_fp12_avx512<P: Fp384Parameters>(mut a: [&mut Fp384<P>; 12], b: [&Fp384<P>; 12]) {
    let p = modulus::<P>();
    let n0 = _mm512_set1_epi64((P::INV & MASK) as i64);

    let mut a_ref = [&*a[0]; 12];
    for (r, x) in a_ref.iter_mut().zip(&a) {
        *r = &**x;
    }
    let x = fp12_operand(
        &limbs_shifted_32(&coefficient_words(&a_ref, 0)),
        &limbs_shifted_32(&coefficient_words(&a_ref, 6)),
    );
    let y = fp12_operand(&limbs(&coefficient_words(&b, 0)), &limbs(&coefficient_words(&b, 6)));

    let (offset, estimate) = canonical_vectors::<P>();
    // SAFETY: this function enables both target features that `fp12_product` requires.
    let c = unsafe { fp12_product(&x, &y, &p, n0) };
    for (h, c) in c.iter().enumerate() {
        let mut w = [[0u64; 8]; 6];
        for (w, v) in w.iter_mut().zip(words(&canonical(c, &p, &offset, estimate))) {
            *w = to_array(v);
        }
        for (l, a) in a[8 * h..].iter_mut().take(8).enumerate() {
            for (j, a) in a.0.0.iter_mut().enumerate() {
                *a = w[j][l];
            }
        }
    }
}

/// Returns the 12 coefficients of the Fp12 product of the operands `x` and `y` of
/// `fp12_operand`, as `fp12_recombine` returns them.
///
/// Requires `x` and `y` with limbs below 2^52 and `x y < 2^416 p` in each lane of each group.
///
/// # Safety
///
/// The CPU supports AVX-512F and AVX-512 IFMA. This function has no `target_feature`, so that it
/// can be `inline(always)`: as an `inline` hint, LLVM stops inlining it once it has two callers.
#[inline(always)]
unsafe fn fp12_product(
    x: &[[__m512i; 8]; 6],
    y: &[[__m512i; 8]; 6],
    p: &[__m512i; 8],
    n0: __m512i,
) -> [[__m512i; 8]; 2] {
    // SAFETY: the caller guarantees both target features.
    unsafe {
        let zero = _mm512_setzero_si512();
        let mut products = [[zero; 8]; 9];
        for (g, product) in products.iter_mut().enumerate() {
            let (i, m) = (g / 3, g % 3);
            let lhs = permute(&x[i], vector(FP12_LHS[m]), &x[3 + i]);
            let rhs = permute(&y[i], vector(FP12_RHS[m]), &y[3 + i]);
            *product = mont(&lhs, &rhs, p, n0);
        }
        fp12_recombine(&products)
    }
}

/// The lanes of `permute` that make the kernel operands of group `3 I + m`, for `a` and `b`: lanes
/// `4 h + k` take Fp coefficients `[0, 1, 0, 1]` (for `a`) or `[0, 1, 1, 0]` (for `b`) of Fp2
/// coefficient `m` of `e` if `h = 0`, and of `f` if `h = 1`.
const FP12_LHS: [[u64; 8]; 3] = [[0, 1, 0, 1, 8, 9, 8, 9], [2, 3, 2, 3, 10, 11, 10, 11], [4, 5, 4, 5, 12, 13, 12, 13]];
const FP12_RHS: [[u64; 8]; 3] = [[0, 1, 1, 0, 8, 9, 9, 8], [2, 3, 3, 2, 10, 11, 11, 10], [4, 5, 5, 4, 12, 13, 13, 12]];

/// Returns `[e_0, e_1, e_2, f_0, f_1, f_2]` with limbs below 2^52, for Fp6 elements `x_0` and
/// `x_1` with limbs below 2^52, where `x_2 = x_0 + x_1`.
///
/// `e_I` holds the 6 Fp coefficients of `x_I` in lanes 0 to 5. Lanes `2 m` and `2 m + 1` of `f_I`
/// hold Fp2 coefficient `m + 1` plus Fp2 coefficient `m + 2` of `x_I`, indices mod 3. Lanes 6 and
/// 7 are zero.
#[inline]
#[target_feature(enable = "avx512f")]
fn fp12_operand(x0: &[__m512i; 8], x1: &[__m512i; 8]) -> [[__m512i; 8]; 6] {
    let x2 = normalize(&add(x0, x1));
    let rotate = |x: &[__m512i; 8]| {
        let (r1, r2) = (vector([2, 3, 4, 5, 0, 1, 6, 7]), vector([4, 5, 0, 1, 2, 3, 6, 7]));
        let mut v = [_mm512_setzero_si512(); 8];
        for k in 0..8 {
            v[k] = _mm512_add_epi64(_mm512_permutexvar_epi64(r1, x[k]), _mm512_permutexvar_epi64(r2, x[k]));
        }
        normalize(&v)
    };
    [*x0, *x1, x2, rotate(x0), rotate(x1), rotate(&x2)]
}

/// Returns the 12 coefficients of the Fp12 product, in lanes 0 to 7 of the first vector and 0 to
/// 3 of the second, whose lanes 4 to 7 repeat them, as signed limbs of integers in
/// `(-64 p, 64 p)`, from the 9 groups of products of `mul_assign_fp12_avx512`.
///
/// Each step takes Fp2 values in the 4 lanes of a half: `[t_00, t_11, t_01, t_10]` stands for
/// `(t_00 - 5 t_11) + (t_01 + t_10) u`.
///
/// # Safety
///
/// The CPU supports AVX-512F. This function has no `target_feature`, so that it can be
/// `inline(always)`: as an `inline` hint, LLVM stops inlining it once it has two callers.
#[inline(always)]
unsafe fn fp12_recombine(products: &[[__m512i; 8]; 9]) -> [[__m512i; 8]; 2] {
    // SAFETY: the caller guarantees the target feature.
    unsafe {
        // `z[I][j]` is Fp2 coefficient `j` of `x_I y_I`, as `s + u x` with `s` in lanes 0 to 3 and `x`
        // in lanes 4 to 7. With `t_m` and `s_m` the products in the low and high halves of group
        // `3 I + m` and `t = t_0 + t_1 + t_2`, Karatsuba multiplication in Fp6 gives:
        //   z_0 = t_0 + u (s_0 - t + t_0),
        //   z_1 = (s_2 - t + t_2) + u t_2,
        //   z_2 = s_1 - t + 2 t_1.
        let mut z = [[[_mm512_setzero_si512(); 8]; 3]; 3];
        for (i, z) in z.iter_mut().enumerate() {
            let [g0, g1, g2] = [&products[3 * i], &products[3 * i + 1], &products[3 * i + 2]];
            let t = add(&add(g0, g1), g2);
            let swapped = [swap_halves(g0), swap_halves(g1), swap_halves(g2), swap_halves(&t)];
            z[0] = blend_halves(g0, &add(&sub(g0, &swapped[3]), &swapped[0]));
            z[1] = blend_halves(&add(&sub(&swapped[2], &t), g2), &swapped[2]);
            z[2] = low_half(&add(&add(&sub(&swapped[1], &t), g1), g1));
        }
        // Karatsuba multiplication in Fp12 gives `c0 = z_0 + v z_1` and `c1 = z_2 - z_0 - z_1`, and
        // `v` maps `(z_{1,0}, z_{1,1}, z_{1,2})` to `(u z_{1,2}, z_{1,0}, z_{1,1})`.
        let c = [
            add(&z[0][0], &swap_halves(&z[1][2])),
            add(&z[0][1], &z[1][0]),
            add(&z[0][2], &z[1][1]),
            sub(&sub(&z[2][0], &z[0][0]), &z[1][0]),
            sub(&sub(&z[2][1], &z[0][1]), &z[1][1]),
            sub(&sub(&z[2][2], &z[0][2]), &z[1][2]),
        ];
        // `s + u x` is `(s_00 - 5 s_11 - 5 x_01 - 5 x_10) + (s_01 + s_10 + x_00 - 5 x_11) u`, from
        // lanes `[s_00, s_11, s_01, s_10, x_00, x_11, x_01, x_10]`: lane 0 and lane 2 of `fold` hold
        // the two Fp coefficients.
        let fold = |x: &[__m512i; 8]| {
            let mut v = [_mm512_setzero_si512(); 8];
            for k in 0..8 {
                let five = _mm512_add_epi64(x[k], _mm512_slli_epi64::<2>(x[k]));
                let w = _mm512_mask_sub_epi64(x[k], 0b1110_0010, _mm512_setzero_si512(), five);
                let w = _mm512_add_epi64(w, _mm512_permutex_epi64::<0b10_11_00_01>(w));
                v[k] = _mm512_add_epi64(w, _mm512_shuffle_i64x2::<0b01_00_10_11>(w, w));
            }
            v
        };
        let mut folded = [[_mm512_setzero_si512(); 8]; 6];
        for (folded, c) in folded.iter_mut().zip(&c) {
            *folded = fold(c);
        }
        let c = folded;
        let (lo, hi) = (vector([0, 2, 8, 10, 0, 2, 8, 10]), _mm512_setzero_si512());
        let mut out = [[hi; 8]; 2];
        for k in 0..8 {
            let c01 = _mm512_permutex2var_epi64(c[0][k], lo, c[1][k]);
            let c23 = _mm512_permutex2var_epi64(c[2][k], lo, c[3][k]);
            out[0][k] = _mm512_mask_blend_epi64(0xF0, c01, c23);
            out[1][k] = _mm512_permutex2var_epi64(c[4][k], lo, c[5][k]);
        }
        out
    }
}
