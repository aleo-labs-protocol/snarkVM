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

//! The Miller loop of a BLS12 curve with a D-type twist and affine G2 lines (`c0 = 1`), held in
//! lanes from the first squaring to the last line.
//!
//! The tower is Fp12 = Fp6[w] / (w^2 - v), Fp6 = Fp2[v] / (v^3 - u) and Fp2 = Fp[u] / (u^2 + 5),
//! and `2^366 <= p < 2^377`.
//!
//! # Layout
//!
//! Two vector groups hold `f`. Lane `k < 6` holds the Fp2 coefficient `F_k` of `w^k`, where
//! `w^2 = v` and `w^6 = u`: the first group holds the real parts and the second the imaginary
//! parts. Lane 6 holds `F_0 + F_1` and lane 7 `F_3 + F_4`, the operand sums every squaring takes.
//! With `z' = w^3`, Fp4 = Fp2[z'] / (z'^2 - u) and `G_i = F_i + F_{i+3} z'`,
//! `f = G_0 + G_1 w + G_2 w^2`.
//!
//! # Bounds
//!
//! Entry: `f`, and `s0` and `s1` of each pair, enter as `x 2^32`, below `2^32 p`, from `Fp384`'s
//! words, and `below_2p` with the offset `64 p` takes them to `[0, 2 p)`. Lanes 6 and 7 of `f`
//! are below `4 p` before the first squaring. From then on, every coefficient of `f` is an
//! integer in `[0, 2 p)` congruent to `x 2^416`, with limbs below 2^52, so `mont_n` multiplies
//! two of them into a third.
//!
//! A line's coefficients `c1` and `c2` enter as `c 2^32`, below `2^32 p`, and `miller_scale`
//! multiplies them by `s0` and `s1`, below `2 p`: each kernel product is below `2^33 p^2`, and
//! `miller_scale` returns `l3 = c1 s0` and `l4 = c2 s1` below `2 p` with limbs below 2^52. Each
//! kernel operand of `line_product` is below `8 p` from `f` and below `8 p` from the line, so each
//! kernel product is below `2^6 p^2 < 2^416 p`. Each kernel operand of `miller_square` is below
//! `8 p`, with `64 p` added to `x_0 - 5 x_1`, so each kernel product is below `2^11 p^2`. `mont_n`
//! returns every product below `2 p` with limbs below 2^57.
//!
//! Exit of a line: the coefficients lie in `(-40 p, 66 p)` with limbs below `15 2^52` in absolute
//! value, and `below_2p` with the offset `64 p` takes them to `[0, 2 p)`. Exit of a squaring: the
//! coefficients lie in `(-120 p, 90 p)` with limbs below `16 2^52`, and `below_2p` with the
//! offset `128 p` takes them to `[0, 2 p)`; the real part of `F_0` reaches `-60 p` for an `f`
//! whose 10 subtracted products are each near `p`. Exit of the loop: `f` leaves through `mont` by
//! `2^384 mod p`, in `[0, p)`, the canonical Montgomery form, bit-identical to the scalar loop.

use super::{
    MillerLoopPair,
    kernel::{below_2p, canonical_vectors, mont, mont_n, normalize, shift_left, signed_normalize},
    layout::{
        MASK,
        Z,
        add,
        element_words,
        limbs_shifted_32,
        mask_mov,
        mask_sub,
        maskz_sub,
        modulus,
        permute_z,
        radix_52,
        shift_left_limbs,
        splat,
        sub,
        times_5,
        to_array,
        words,
    },
};
use crate::{Fp2, Fp2Parameters, Fp384, Fp384Parameters, Zero};

use std::arch::x86_64::*;

/// The coefficients of an Fp12 element in the two vector groups of the Miller loop layout, by
/// their index in the order of `coefficients`: `c0.c0`, `c1.c0`, `c0.c1`, `c1.c1`, `c0.c2` and
/// `c1.c2` in lanes 0 to 5, real parts in the first group and imaginary parts in the second.
/// Lanes 6 and 7 list `F_0` and `F_3`, to which `MILLER_SUMS` adds the rest.
const MILLER_LANES: [[u64; 8]; 2] = [[0, 6, 2, 8, 4, 10, 0, 8], [1, 7, 3, 9, 5, 11, 1, 9]];

/// The `permute_z` base lanes `[F_0..F_5, F_0, F_3]` and the lanes added to lanes 6 and 7.
const MILLER_BASE: [u64; 8] = [0, 1, 2, 3, 4, 5, 0, 3];
const MILLER_SUMS: [u64; 8] = [Z, Z, Z, Z, Z, Z, 1, 4];

/// Sets `f` to the value `miller_loop_fp12` returns, over the bits of `x` from the second most
/// significant down to bit 0. Requires `2^366 <= p < 2^377`, a nonempty `x`, and at least as many
/// lines in each pair as the loop takes.
///
/// `miller_square` squares `f`. `miller_scale` computes `c1 s0` and `c2 s1` for the lines of two
/// pairs at a time, `line_operand` forms the kernel operands of each line, and `line_product`
/// multiplies `f` by `1 + (c1 s0) w + (c2 s1) w^3`.
///
/// # Safety
///
/// The CPU supports AVX-512F and AVX-512 IFMA.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(super) unsafe fn miller_loop_avx512<P, R>(f: [&mut Fp384<P>; 12], x: &[u64], pairs: &[MillerLoopPair<'_, R>])
where
    P: Fp384Parameters,
    R: Fp2Parameters<Fp = Fp384<P>>,
{
    let p = modulus::<P>();
    let n0 = _mm512_set1_epi64((P::INV & MASK) as i64);
    let (offset, estimate) = canonical_vectors::<P>();
    let p128 = splat(&const { radix_52(&shift_left(&P::MODULUS.0, 7)) });

    let mut state = [[_mm512_setzero_si512(); 8]; 2];
    for (state, lanes) in state.iter_mut().zip(MILLER_LANES) {
        let mut e = [&*f[0]; 8];
        for (e, i) in e.iter_mut().zip(lanes) {
            *e = &*f[i as usize];
        }
        let v = below_2p(&limbs_shifted_32(&element_words(e)), &p, &offset, estimate);
        *state = normalize(&add(&v, &permute_z(&v, MILLER_SUMS, &v)));
    }

    // The kernel operands `[s0, s0, s1, s1]` of `miller_scale` for pairs `2 j` and `2 j + 1`.
    let zero = Fp384::<P>::zero();
    let mut scale_rhs = Vec::with_capacity(pairs.len().div_ceil(2));
    for pair in pairs.chunks(2) {
        let [s0_0, s1_0] = pair[0].0;
        let [s0_1, s1_1] = if pair.len() > 1 { pair[1].0 } else { [&zero; 2] };
        let rhs = limbs_shifted_32(&element_words([s0_0, s0_0, s1_0, s1_0, s0_1, s0_1, s1_1, s1_1]));
        scale_rhs.push(below_2p(&rhs, &p, &offset, estimate));
    }

    let mut k = 0;
    for i in (0..64 * x.len() - 1).rev() {
        state = miller_square(&state, &p, n0, &offset, &p128, estimate);
        for _ in 0..1 + (x[i / 64] >> (i % 64) & 1) {
            for (pair, rhs) in pairs.chunks(2).zip(&scale_rhs) {
                let lines = [line(&pair[0].1[k]), if pair.len() > 1 { line(&pair[1].1[k]) } else { [&zero; 4] }];
                let s = miller_scale(lines, rhs, &p, n0);
                line_product(&mut state, &line_operand::<0>(&s), &p, n0, &offset, estimate);
                if pair.len() > 1 {
                    line_product(&mut state, &line_operand::<1>(&s), &p, n0, &offset, estimate);
                }
            }
            k += 1;
        }
    }

    let r = splat(&const { radix_52(&P::R.0) });
    for (state, lanes) in state.iter().zip(&MILLER_LANES) {
        // SAFETY: this function enables both target features that `mont` requires.
        let c = unsafe { mont(state, &r, &p, n0) };
        let mut w = [[0u64; 8]; 6];
        for (w, v) in w.iter_mut().zip(words(&c)) {
            *w = to_array(v);
        }
        for (l, index) in lanes[..6].iter().enumerate() {
            for (j, a) in f[*index as usize].0.0.iter_mut().enumerate() {
                *a = w[j][l];
            }
        }
    }
}

/// Returns the coefficients `[c1.c0, c1.c1, c2.c0, c2.c1]` of the affine line `(c1, c2)`.
#[inline(always)]
fn line<R: Fp2Parameters>((c1, c2): &(Fp2<R>, Fp2<R>)) -> [&R::Fp; 4] {
    [&c1.c0, &c1.c1, &c2.c0, &c2.c1]
}

/// The `permute_z` index pairs whose sums are the Fp2 values `g_0` and `g_1` of
/// `Gamma = [G_0, G_1, G_2, G_0 + G_1, G_1 + G_2, G_0 + G_2]` in lanes 0 to 5, from a part of the
/// Miller loop layout.
const MILLER_SQUARE_GAMMA: [[[u64; 8]; 2]; 2] =
    [[[0, 1, 2, 6, 1, 0, Z, Z], [Z, Z, Z, Z, 2, 2, Z, Z]], [[3, 4, 5, 7, 4, 3, Z, Z], [Z, Z, Z, Z, 5, 5, Z, Z]]];

/// The `permute_z` indices of the items of groups 0 and 1, of groups 2 and 3, and of group 4 of
/// `miller_square`: from `g_0` and the layer 2 sums, from `g_1` and those sums, and from those sums.
const MILLER_SQUARE_ITEMS: [[u64; 8]; 3] =
    [[0, 1, 2, 3, 4, 5, 8, 9], [0, 1, 2, 3, 4, 5, 10, 11], [4, 5, 4, 5, Z, Z, Z, Z]];

/// The `permute_z` indices of the layer 2 squares in lanes 0 to 5, from layers 0 and 1's squares,
/// and from group 4's.
const MILLER_SQUARE_LAYER_2: [[u64; 8]; 2] = [[6, 7, 14, 15, Z, Z, Z, Z], [Z, Z, Z, Z, 0, 1, Z, Z]];

/// The `permute_z` indices of the terms of `miller_square`'s result from `Q_0` and `Q_1` of one
/// part, then of the terms from `Q_1` of the other part. The lanes of `MILLER_SQUARE_NEGATIVE`
/// subtract the second term, and every lane subtracts the third and fourth; of the last three, the
/// first adds and the others subtract.
const MILLER_SQUARE_TERMS: [[u64; 8]; 7] = [
    [0, 3, 1, 8, 11, 9, 3, 4],
    [Z, 0, 5, 4, 2, 13, 1, 11],
    [Z, 1, 0, 1, 8, 8, Z, 1],
    [Z, Z, 2, 2, 9, 10, Z, 9],
    [4, 2, Z, Z, Z, Z, 4, Z],
    [1, Z, Z, Z, Z, Z, 1, Z],
    [2, Z, Z, Z, Z, Z, Z, Z],
];
const MILLER_SQUARE_NEGATIVE: __mmask8 = 0b0100_0010;

/// Returns the square of `z` in the Miller loop layout.
///
/// With `z = G_0 + G_1 w + G_2 w^2` and `S_j = Gamma_j^2` for
/// `Gamma = [G_0, G_1, G_2, G_0 + G_1, G_1 + G_2, G_0 + G_2]`, the square is
/// `H_0 + H_1 w + H_2 w^2` with
///   `H_0 = S_0 + z' (S_4 - S_1 - S_2)`, `H_1 = (S_3 - S_0 - S_1) + z' S_2`,
///   `H_2 = S_1 + S_5 - S_0 - S_2`.
/// Each `Gamma^2 = (g_0 + g_1 z')^2` is `(n_0 + u n_1) + (n_2 - n_0 - n_1) z'`, from the Fp2 squares
/// of layers 0, 1 and 2: `n_0 = g_0^2`, `n_1 = g_1^2` and `n_2 = (g_0 + g_1)^2`. Each Fp2 square
/// `x^2` is `(s + 4 t) + 2 t u`, from the Fp products `s = (x_0 + x_1)(x_0 - 5 x_1)` and
/// `t = x_0 x_1`. `mont_n` computes the 36 in 5 groups: groups 0 and 1 hold `s` and `t` of layer 0
/// in lanes 0 to 5 and of layer 2's `Gamma_0` and `Gamma_1` in lanes 6 and 7; groups 2 and 3 those
/// of layer 1 and of layer 2's `Gamma_2` and `Gamma_3`; group 4 holds `s` of layer 2's `Gamma_4` and
/// `Gamma_5` in lanes 0 and 1, and `t` in lanes 2 and 3.
///
/// The coefficients of `z` are below `2 p` (`4 p` in lanes 6 and 7), so each `x` part is below
/// `8 p`, `x_0 - 5 x_1` enters with `64 p` added from `p64`, and each kernel product is below
/// `2^11 p^2`. `mont_n` returns the products below `2 p` with limbs below 2^57. The result's
/// coefficients lie in `(-120 p, 90 p)` with limbs below `16 2^52`, and `below_2p` with the
/// offset `128 p` in `p128` takes them to `[0, 2 p)`.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn miller_square(
    z: &[[__m512i; 8]; 2],
    p: &[__m512i; 8],
    n0: __m512i,
    p64: &[__m512i; 8],
    p128: &[__m512i; 8],
    estimate: __m512i,
) -> [[__m512i; 8]; 2] {
    let mut x = [[[_mm512_setzero_si512(); 8]; 3]; 2];
    for (x, z) in x.iter_mut().zip(z) {
        let [[a0, b0], [a1, b1]] = MILLER_SQUARE_GAMMA;
        let g0 = normalize(&add(&permute_z(z, a0, z), &permute_z(z, b0, z)));
        let g1 = normalize(&add(&permute_z(z, a1, z), &permute_z(z, b1, z)));
        let g2 = normalize(&add(&g0, &g1));
        *x = [
            permute_z(&g0, MILLER_SQUARE_ITEMS[0], &g2),
            permute_z(&g1, MILLER_SQUARE_ITEMS[1], &g2),
            permute_z(&g2, MILLER_SQUARE_ITEMS[2], &g2),
        ];
    }
    let s_lhs = |j: usize| normalize(&add(&x[0][j], &x[1][j]));
    let s_rhs = |j: usize| signed_normalize(&sub(&add(&x[0][j], p64), &times_5(&x[1][j])));
    let (l0, r0, l1, r1) = (s_lhs(0), s_rhs(0), s_lhs(1), s_rhs(1));
    let (l4, r4) = (mask_mov(&x[0][2], 0b0011, &s_lhs(2)), mask_mov(&x[1][2], 0b0011, &s_rhs(2)));
    // SAFETY: this function enables both target features that `mont_n` requires.
    let [k0, k1, k2] = unsafe { mont_n([&l0, &x[0][0], &l1], [&r0, &x[1][0], &r1], p, n0) };
    // SAFETY: as above.
    let [k3, k4] = unsafe { mont_n([&x[0][1], &l4], [&x[1][1], &r4], p, n0) };

    // Fp2 squares `(s + 4 t, 2 t)`: `n_a` of groups 0 and 1, `n_b` of groups 2 and 3, `n_c` of group
    // 4 in lanes 0 and 1.
    let t4 = permute_z(&k4, [2, 3, Z, Z, Z, Z, Z, Z], &k4);
    let n_a = [add(&k0, &shift_left_limbs::<2>(&k1)), shift_left_limbs::<1>(&k1)];
    let n_b = [add(&k2, &shift_left_limbs::<2>(&k3)), shift_left_limbs::<1>(&k3)];
    let n_c = [add(&k4, &shift_left_limbs::<2>(&t4)), shift_left_limbs::<1>(&t4)];
    let [l2a, l2c] = MILLER_SQUARE_LAYER_2;
    let n2 = [
        add(&permute_z(&n_a[0], l2a, &n_b[0]), &permute_z(&n_c[0], l2c, &n_c[0])),
        add(&permute_z(&n_a[1], l2a, &n_b[1]), &permute_z(&n_c[1], l2c, &n_c[1])),
    ];

    // In lanes 0 to 5, `Q_0 + Q_1 z' = Gamma^2`.
    let q0 = [signed_normalize(&sub(&n_a[0], &times_5(&n_b[1]))), signed_normalize(&add(&n_a[1], &n_b[0]))];
    let q1 = [
        signed_normalize(&sub(&sub(&n2[0], &n_a[0]), &n_b[0])),
        signed_normalize(&sub(&sub(&n2[1], &n_a[1]), &n_b[1])),
    ];

    // Lanes 0 to 5 take `H_0`, `H_1` and `H_2`'s `Q_0` parts, then their `Q_1` parts; lane 6 the
    // sum of lanes 0 and 1, and lane 7 that of lanes 3 and 4. `u (re, im) = (-5 im, re)`.
    let (r, i) = (miller_square_terms(&q0[0], &q1[0]), miller_square_terms(&q0[1], &q1[1]));
    let (e_r, e_i) = (miller_square_terms_u(&q1[1]), miller_square_terms_u(&q1[0]));
    [below_2p(&sub(&r, &times_5(&e_r)), p, p128, estimate), below_2p(&add(&i, &e_i), p, p128, estimate)]
}

/// Returns the sum of the terms of `MILLER_SQUARE_TERMS[0..4]` from `Q_0` and `Q_1`, with their signs.
#[inline]
#[target_feature(enable = "avx512f")]
fn miller_square_terms(q0: &[__m512i; 8], q1: &[__m512i; 8]) -> [__m512i; 8] {
    let t0 = permute_z(q0, MILLER_SQUARE_TERMS[0], q1);
    let t1 = permute_z(q0, MILLER_SQUARE_TERMS[1], q1);
    let t2 = permute_z(q0, MILLER_SQUARE_TERMS[2], q1);
    let t3 = permute_z(q0, MILLER_SQUARE_TERMS[3], q1);
    sub(&sub(&mask_sub(&add(&t0, &t1), MILLER_SQUARE_NEGATIVE, &t0, &t1), &t2), &t3)
}

/// Returns the sum of the terms of `MILLER_SQUARE_TERMS[4..7]` from `Q_1`, with their signs.
#[inline]
#[target_feature(enable = "avx512f")]
fn miller_square_terms_u(q1: &[__m512i; 8]) -> [__m512i; 8] {
    let t0 = permute_z(q1, MILLER_SQUARE_TERMS[4], q1);
    let t1 = permute_z(q1, MILLER_SQUARE_TERMS[5], q1);
    let t2 = permute_z(q1, MILLER_SQUARE_TERMS[6], q1);
    sub(&sub(&t0, &t1), &t2)
}

/// Returns, for the affine lines `u = lines[0]` and `v = lines[1]` with coefficients
/// `[c1.c0, c1.c1, c2.c0, c2.c1]`, the scaled products `[c1.c0 s0, c1.c1 s0, c2.c0 s1, c2.c1 s1]`
/// of `u` in lanes 0 to 3 and of `v` in lanes 4 to 7, below `2 p` with limbs below 2^52. `rhs`
/// holds `[s0, s0, s1, s1]` of each line's pair in its 4 lanes, below `2 p`, so each kernel
/// product is below `2^33 p^2`.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn miller_scale<P: Fp384Parameters>(
    lines: [[&Fp384<P>; 4]; 2],
    rhs: &[__m512i; 8],
    p: &[__m512i; 8],
    n0: __m512i,
) -> [__m512i; 8] {
    let [u, v] = lines;
    let lhs = limbs_shifted_32(&element_words([u[0], u[1], u[2], u[3], v[0], v[1], v[2], v[3]]));
    // SAFETY: this function enables both target features that `mont_n` requires.
    let [s] = unsafe { mont_n([&lhs], [rhs], p, n0) };
    normalize(&s)
}

/// The `permute_z` index pairs whose sums are `[l3, l4, l3 + l4]` in lanes 0 to 2 from `s` of
/// `miller_scale`, in row `2 h + c` for the line in half `h` and its real (`c = 0`) or imaginary
/// (`c = 1`) part: `s` holds `l3` in lane `4 h + c` and `l4` in lane `4 h + 2 + c`.
const LINE_SUMS: [[[u64; 8]; 2]; 4] = [
    [[0, 2, 0, Z, Z, Z, Z, Z], [Z, Z, 2, Z, Z, Z, Z, Z]],
    [[1, 3, 1, Z, Z, Z, Z, Z], [Z, Z, 3, Z, Z, Z, Z, Z]],
    [[4, 6, 4, Z, Z, Z, Z, Z], [Z, Z, 6, Z, Z, Z, Z, Z]],
    [[5, 7, 5, Z, Z, Z, Z, Z], [Z, Z, 7, Z, Z, Z, Z, Z]],
];

/// The lanes of `[l3, l4, l3 + l4]` that make the kernel operands of groups 0 to 2 of
/// `line_product`, and the `permute_z` indices that assemble group 3 (`l4` in planes 0, 1 and 2)
/// from `r`, `i` and `both`.
const LINE_YA: [u64; 8] = [0, 0, 1, 1, 0, 0, 2, 2];
const LINE_YB: [[u64; 8]; 2] = [[1, 1, 9, 9, Z, Z, Z, Z], [0, 1, 2, 3, 9, 9, Z, Z]];

/// Returns the 4 kernel operands of the affine line in half `H` of `s` from `miller_scale`, in the
/// groups of `line_product`. Each is a sum of at most 4 of `s`'s values, below `8 p`, with limbs
/// below 2^52.
#[inline]
#[target_feature(enable = "avx512f")]
fn line_operand<const H: usize>(s: &[__m512i; 8]) -> [[__m512i; 8]; 4] {
    let sums = |[i0, i1]: [[u64; 8]; 2]| normalize(&add(&permute_z(s, i0, s), &permute_z(s, i1, s)));
    let (r, i) = (sums(LINE_SUMS[2 * H]), sums(LINE_SUMS[2 * H + 1]));
    let both = normalize(&add(&r, &i));
    [
        permute_z(&r, LINE_YA, &r),
        permute_z(&i, LINE_YA, &i),
        permute_z(&both, LINE_YA, &both),
        permute_z(&permute_z(&r, LINE_YB[0], &i), LINE_YB[1], &both),
    ]
}

/// The `permute_z` indices of the two terms whose sum makes the operands of `f` in groups 0 to 2
/// (`[F_0, F_1, F_2, F_3, F_4, F_5, F_0 + F_2, F_1 + F_3]`), and the indices that assemble group 3
/// (`[F_4, F_5]` in planes 0, 1 and 2) from `r`, `i` and `xa_both`.
const LINE_XA: [[u64; 8]; 2] = [[0, 1, 2, 3, 4, 5, 0, 1], [Z, Z, Z, Z, Z, Z, 2, 3]];
const LINE_XB: [[u64; 8]; 2] = [[4, 5, 12, 13, Z, Z, Z, Z], [0, 1, 2, 3, 12, 13, Z, Z]];

/// The lanes of group 3's plane 1 and plane 2 products `[P_4, Q_4]`, moved to lanes 0 and 1, and
/// the mask of those two items.
const LINE_P1: [u64; 8] = [2, 3, Z, Z, Z, Z, Z, Z];
const LINE_P2: [u64; 8] = [4, 5, Z, Z, Z, Z, Z, Z];
const LINE_MB_ITEMS: __mmask8 = 0b0000_0011;

/// The `permute_z` indices of the non-`u` terms of `line_product` in lanes 0 to 5 from `m_a`, and
/// of the `u`-multiplied terms in lanes 0 to 2 from `m_a` and `m_b`. The lanes of `LINE_NEGATIVE`
/// subtract the second non-`u` term, and every lane subtracts the third.
const LINE_TERMS: [[u64; 8]; 3] = [[Z, 0, 1, 6, 7, 2, Z, Z], [Z, Z, Z, 0, 1, 4, Z, Z], [Z, Z, Z, 2, 3, Z, Z, Z]];
const LINE_NEGATIVE: __mmask8 = 0b0001_1000;
const LINE_U_TERMS: [[u64; 8]; 2] = [[3, 8, 9, Z, Z, Z, Z, Z], [5, Z, Z, Z, Z, Z, Z, Z]];

/// Sets `z` to `z` times the affine line `1 + l3 w + l4 w^3` whose kernel operands `y` are
/// `line_operand`'s, in the Miller loop layout.
///
/// Writing `z = A + B w` with `A = F_0 + F_2 v + F_4 v^2`, `B = F_1 + F_3 v + F_5 v^2` and
/// `L_1 = l3 + l4 v`, the product is `(A + v (B L_1)) + (B + A L_1) w`. With the 10 Fp2 products
/// `P = [F_0 l3, F_2 l4, (F_0 + F_2)(l3 + l4), F_4 l3, F_4 l4]` for `A L_1` and
/// `Q = [F_1 l3, F_3 l4, (F_1 + F_3)(l3 + l4), F_5 l3, F_5 l4]` for `B L_1`,
///   `F'_0 = F_0 + u (Q_1 + Q_3)`,       `F'_1 = F_1 + P_0 + u P_4`,
///   `F'_2 = F_2 + Q_0 + u Q_4`,         `F'_3 = F_3 + P_2 - P_0 - P_1`,
///   `F'_4 = F_4 + Q_2 - Q_0 - Q_1`,     `F'_5 = F_5 + P_1 + P_3`.
/// Each of the 10 Fp2 products takes Karatsuba multiplication in Fp2 across planes 0, 1 and 2:
/// `x_0 y_0`, `x_1 y_1` and `(x_0 + x_1)(y_0 + y_1)`. `mont_n` computes the 30 Fp products in 4
/// groups via two `mont_n::<2>` calls: groups 0, 1 and 2 hold planes 0, 1 and 2 of
/// `[P_0, Q_0, P_1, Q_1, P_3, Q_3, P_2, Q_2]`, and group 3 holds planes 0, 1 and 2 of `[P_4, Q_4]`
/// in lanes 0 to 5.
///
/// Lanes 0 to 5 of `z` are below `2 p`, so `z`'s kernel operands are below `8 p` and each kernel
/// product is below `2^6 p^2 < 2^416 p`. `mont_n` returns the products below `2 p` with limbs below
/// 2^57. After assembling lanes 6 (`F'_0 + F'_1`) and 7 (`F'_3 + F'_4`), the coefficients lie in
/// `(-40 p, 66 p)` with limbs below `15 2^52` in absolute value, and `below_2p` with the offset
/// `64 p` in `offset` takes them to `[0, 2 p)`.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn line_product(
    z: &mut [[__m512i; 8]; 2],
    y: &[[__m512i; 8]; 4],
    p: &[__m512i; 8],
    n0: __m512i,
    offset: &[__m512i; 8],
    estimate: __m512i,
) {
    let [r, i] = &*z;
    let xa_r = normalize(&add(&permute_z(r, LINE_XA[0], r), &permute_z(r, LINE_XA[1], r)));
    let xa_i = normalize(&add(&permute_z(i, LINE_XA[0], i), &permute_z(i, LINE_XA[1], i)));
    // SAFETY: this function enables both target features that `mont_n` requires.
    let [k0, k1] = unsafe { mont_n([&xa_r, &xa_i], [&y[0], &y[1]], p, n0) };
    let xa_both = normalize(&add(&xa_r, &xa_i));
    let xb = permute_z(&permute_z(r, LINE_XB[0], i), LINE_XB[1], &xa_both);
    // SAFETY: as above.
    let [k2, k3] = unsafe { mont_n([&xa_both, &xb], [&y[2], &y[3]], p, n0) };

    // Each Fp2 product `(re, im)` is `(P_0 - 5 P_1, P_2 - P_0 - P_1)`, from its planes `P`. `m_a`
    // holds `[P_0, Q_0, P_1, Q_1, P_3, Q_3, P_2, Q_2]`, and `m_b` holds `[P_4, Q_4]` in lanes 0 and 1.
    let m_a = [signed_normalize(&sub(&k0, &times_5(&k1))), signed_normalize(&sub(&sub(&k2, &k0), &k1))];
    let p1 = permute_z(&k3, LINE_P1, &k3);
    let p2 = permute_z(&k3, LINE_P2, &k3);
    let m_b = [
        signed_normalize(&maskz_sub(LINE_MB_ITEMS, &k3, &times_5(&p1))),
        signed_normalize(&maskz_sub(LINE_MB_ITEMS, &sub(&p2, &k3), &p1)),
    ];

    let (nu_r, nu_i) = (line_terms(&m_a[0]), line_terms(&m_a[1]));
    let (up_r, up_i) = (line_u_terms(&m_a[0], &m_b[0]), line_u_terms(&m_a[1], &m_b[1]));
    let v_r = sub(&add(r, &nu_r), &times_5(&up_i));
    let v_i = add(&add(i, &nu_i), &up_r);

    let out_r = add(&permute_z(&v_r, MILLER_BASE, &v_r), &permute_z(&v_r, MILLER_SUMS, &v_r));
    let out_i = add(&permute_z(&v_i, MILLER_BASE, &v_i), &permute_z(&v_i, MILLER_SUMS, &v_i));
    z[0] = below_2p(&out_r, p, offset, estimate);
    z[1] = below_2p(&out_i, p, offset, estimate);
}

/// Returns the non-`u` sum in lanes 0 to 5 of `line_product` from `m_a`, with its signs.
#[inline]
#[target_feature(enable = "avx512f")]
fn line_terms(ma: &[__m512i; 8]) -> [__m512i; 8] {
    let t0 = permute_z(ma, LINE_TERMS[0], ma);
    let t1 = permute_z(ma, LINE_TERMS[1], ma);
    let t2 = permute_z(ma, LINE_TERMS[2], ma);
    sub(&mask_sub(&add(&t0, &t1), LINE_NEGATIVE, &t0, &t1), &t2)
}

/// Returns the `u`-multiplied sum in lanes 0 to 2 of `line_product` from `m_a` and `m_b`.
#[inline]
#[target_feature(enable = "avx512f")]
fn line_u_terms(ma: &[__m512i; 8], mb: &[__m512i; 8]) -> [__m512i; 8] {
    add(&permute_z(ma, LINE_U_TERMS[0], mb), &permute_z(ma, LINE_U_TERMS[1], ma))
}
