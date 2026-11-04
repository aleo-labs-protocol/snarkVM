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

//! The GLV ladder, 8 lanes of signed 4-bit windows over several slots of points, from the
//! operand words to the Jacobian result.
//!
//! The points are on a curve `y^2 = x^3 + b` over Fp with `2^366 <= p < 2^377`; the doubling and
//! mixed-addition formulas do not read `b`.
//!
//! Entry: each coordinate, `beta` and 1 enter as `x 2^384 2^32`, below `2^32 p`, from `Fp384`'s
//! words, and `below_2p` with the offset `64 p` takes them to `[0, 2 p)`. From then on every
//! value `x` is an integer congruent to `x 2^416` with limbs below 2^52, so `mont_n` multiplies
//! two of them into a third below `2 p`.
//!
//! Bounds: the accumulator stays below `34 p`, `18 p` and `4 p` in `X`, `Y` and `Z`, a table entry
//! below `10 p` in `x` and `8 p` in `y`, and each kernel operand product below `2^14 p^2`, which is
//! below the `2^416 p` that `mont_n` requires. Each subtraction adds the multiple of `p` named at
//! its line, at least the subtrahend's bound, so every normalized sum is non-negative. These
//! bounds hold for any number of windows: one doubling and one addition at the widest bounds
//! return values within them.
//!
//! Exit: the coordinates leave through `mont` by `2^384 mod p`, in `[0, p)`.

use super::{
    kernel::{below_2p, canonical_vectors, mont, mont_n, normalize, shift_left, signed_normalize},
    layout::{MASK, add, element_words, limbs_shifted_32, modulus, radix_52, splat, sub, to_array, words},
};
use crate::{Fp384, Fp384Parameters};

use std::arch::x86_64::*;

/// Sets `out` to the value `glv_mul_8` returns, for digits in `[-8, 8]`, nonempty `points` and one
/// slice of digits per entry of `points`, all of one length. Requires `2^366 <= p < 2^377`.
///
/// Slot `k` has a table of `i P_k` for `i` from 1 to 8, and all tables share one `Z`, `Z_c`: they
/// are the affine points `(X_i, Y_i)` of the curve `y^2 = x^3 + b Z_c^6`, the image of the curve
/// under `(x, y) -> (x Z_c^2, y Z_c^3)`. Doubling and mixed addition do not depend on `b`, so the
/// ladder runs on that curve with mixed additions, and its result `(X, Y, Z)` is `(X, Y, Z Z_c)` on
/// the curve. `phi` commutes with the map, so the second table of a slot is `(beta X_i, Y_i)`. The
/// table of slot `k` is built in Jacobian coordinates, and `Z_c` is the product over the slots of
/// the `Z` of `8 P_k`.
///
/// A lane starts at its first nonzero digit by taking the table entry, and adds each later nonzero
/// digit. A doubling multiplies `Z` by `2 Y` and an addition by `2 H`, with `H` the difference of
/// the `x` of the two points, so `Z` stays nonzero exactly while no doubling meets `Y = 0` and no
/// addition meets two points with the same `x`; and while it does, every formula gives the sum.
/// The `Z` of `8 P_k` comes from `P_k` by a doubling and 6 additions, so `Z_c` is zero exactly
/// where a table met such a case. A lane that never starts keeps `Z = 0`.
///
/// # Safety
///
/// The CPU supports AVX-512F and AVX-512 IFMA.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(super) unsafe fn glv_mul_8_avx512<P: Fp384Parameters>(
    points: &[[[Fp384<P>; 2]; 8]],
    beta: &Fp384<P>,
    digits: &[&[[[i8; 8]; 2]]],
    out: &mut [[Fp384<P>; 3]; 8],
) {
    let zero = _mm512_setzero_si512();
    let n0 = _mm512_set1_epi64((P::INV & MASK) as i64);
    let (offset, estimate) = canonical_vectors::<P>();
    // `m[s]` holds `2^s p`.
    let m = [
        modulus::<P>(),
        splat(&const { radix_52(&shift_left(&P::MODULUS.0, 1)) }),
        splat(&const { radix_52(&shift_left(&P::MODULUS.0, 2)) }),
        splat(&const { radix_52(&shift_left(&P::MODULUS.0, 3)) }),
        splat(&const { radix_52(&shift_left(&P::MODULUS.0, 4)) }),
        splat(&const { radix_52(&shift_left(&P::MODULUS.0, 5)) }),
        splat(&const { radix_52(&shift_left(&P::MODULUS.0, 6)) }),
    ];
    let p = &m[0];

    let one = below_2p(&limbs_shifted_32(&splat(&P::R.0)), p, &offset, estimate);
    let beta = below_2p(&limbs_shifted_32(&splat(&beta.0.0)), p, &offset, estimate);

    // `table[i - 1]` is `i P_k` in Jacobian coordinates, and `scale[i - 1]` the `Z` of `8 P_k` over
    // that of `i P_k`, for `i` up to 7.
    let jacobian: Vec<_> = points
        .iter()
        .map(|slot| {
            let x = below_2p(&limbs_shifted_32(&point_words(slot, 0)), p, &offset, estimate);
            let y = below_2p(&limbs_shifted_32(&point_words(slot, 1)), p, &offset, estimate);
            // `ratio[i - 1]` is the `Z` of `(i + 1) P_k` over that of `i P_k`.
            let mut table = [[[zero; 8]; 3]; 8];
            let mut ratio = [[zero; 8]; 7];
            table[0] = [x, y, one];
            table[1] = glv_double(&table[0], &m, n0);
            ratio[0] = table[1][2];
            for i in 2..8 {
                let (sum, h) = glv_add(&table[i - 1], &x, &y, &m, n0);
                table[i] = sum;
                ratio[i - 1] = normalize(&shift::<1>(&h));
            }
            let mut scale = ratio;
            for i in (0..6).rev() {
                // SAFETY: this function enables both target features that `mont_n` requires.
                let [s] = unsafe { mont_n([&ratio[i]], [&scale[i + 1]], p, n0) };
                scale[i] = normalize(&s);
            }
            (table, scale)
        })
        .collect();

    // `others[k]` is the product of the `Z` of `8 P_j` over the slots `j` other than `k`, and `z_c`
    // the product over all slots. With one slot, `others` is empty and `Z_c` is the slot's `Z`.
    let mut others = Vec::with_capacity(jacobian.len());
    let mut z_c = jacobian[0].0[7][2];
    if jacobian.len() > 1 {
        // `prefix` is the product over the slots before `k`, and `suffix` over those after it.
        let mut suffix = vec![[zero; 8]; jacobian.len()];
        suffix[jacobian.len() - 1] = one;
        for k in (0..jacobian.len() - 1).rev() {
            // SAFETY: this function enables both target features that `mont_n` requires.
            let [v] = unsafe { mont_n([&suffix[k + 1]], [&jacobian[k + 1].0[7][2]], p, n0) };
            suffix[k] = normalize(&v);
        }
        let mut prefix = one;
        for (k, suffix) in suffix.iter().enumerate() {
            // SAFETY: as above.
            let [other, next] = unsafe { mont_n([&prefix, &prefix], [suffix, &jacobian[k].0[7][2]], p, n0) };
            others.push(normalize(&other));
            prefix = normalize(&next);
        }
        z_c = prefix;
    }

    // `tables[k]` holds the `x`, `y` and `beta x` of `i P_k` on the curve scaled by `Z_c`, in entry
    // `i - 1`.
    let tables: Vec<[[[__m512i; 8]; 8]; 3]> = jacobian
        .iter()
        .enumerate()
        .map(|(k, (table, scale))| {
            let mut tx = [[zero; 8]; 8];
            let mut ty = [[zero; 8]; 8];
            let mut tphi = [[zero; 8]; 8];
            for i in 0..8 {
                // `s` is `Z_c` over the `Z` of `(i + 1) P_k`, or `None` where that is one.
                let s = match (others.get(k), i) {
                    (None, 7) => None,
                    (None, _) => Some(scale[i]),
                    (Some(other), 7) => Some(*other),
                    (Some(other), _) => {
                        // SAFETY: this function enables both target features that `mont_n` requires.
                        let [v] = unsafe { mont_n([&scale[i]], [other], p, n0) };
                        Some(normalize(&v))
                    }
                };
                (tx[i], ty[i]) = match s {
                    None => (table[i][0], table[i][1]),
                    Some(s) => {
                        // SAFETY: this function enables both target features that `mont_n` requires.
                        let [s2] = unsafe { mont_n([&s], [&s], p, n0) };
                        let s2 = normalize(&s2);
                        // SAFETY: as above.
                        let [s3, x] = unsafe { mont_n([&s2, &table[i][0]], [&s, &s2], p, n0) };
                        let s3 = normalize(&s3);
                        // SAFETY: as above.
                        let [y] = unsafe { mont_n([&table[i][1]], [&s3], p, n0) };
                        (normalize(&x), normalize(&y))
                    }
                };
                // SAFETY: this function enables both target features that `mont_n` requires.
                let [v] = unsafe { mont_n([&beta], [&tx[i]], p, n0) };
                tphi[i] = normalize(&v);
            }
            [tx, ty, tphi]
        })
        .collect();

    // A lane that has not started holds `(1, 1, 0)`.
    let mut acc = [[zero; 8]; 3];
    acc[0][0] = _mm512_set1_epi64(1);
    acc[1][0] = _mm512_set1_epi64(1);
    let mut started: __mmask8 = 0;
    for w in (0..digits[0].len()).rev() {
        if started != 0 {
            for _ in 0..4 {
                acc = glv_double(&acc, &m, n0);
            }
        }
        for ((half, d), [table_x, table_y, table_phi]) in
            digits.iter().zip(&tables).flat_map(|(slot, table)| slot[w].iter().enumerate().zip([table, table]))
        {
            // `by_abs[e]` holds the lanes whose digit is `e` or `-e`.
            let mut by_abs = [0u8; 9];
            let mut negative = 0u8;
            for (l, d) in d.iter().enumerate() {
                by_abs[d.unsigned_abs() as usize] |= 1 << l;
                negative |= u8::from(*d < 0) << l;
            }
            let nonzero = !by_abs[0];
            if nonzero == 0 {
                continue;
            }
            let xs = if half == 0 { table_x } else { table_phi };
            let (mut sx, mut sy) = (xs[0], table_y[0]);
            for e in 2..9 {
                for j in 0..8 {
                    sx[j] = _mm512_mask_mov_epi64(sx[j], by_abs[e], xs[e - 1][j]);
                    sy[j] = _mm512_mask_mov_epi64(sy[j], by_abs[e], table_y[e - 1][j]);
                }
            }
            // The negation is `8 p - y`, for `y` below `8 p`.
            let negated = signed_normalize(&sub(&m[3], &sy));
            for j in 0..8 {
                sy[j] = _mm512_mask_mov_epi64(sy[j], negative, negated[j]);
            }
            let (add, start) = (nonzero & started, nonzero & !started);
            if add != 0 {
                let (sum, _) = glv_add(&acc, &sx, &sy, &m, n0);
                for (acc, sum) in acc.iter_mut().zip(&sum) {
                    for j in 0..8 {
                        acc[j] = _mm512_mask_mov_epi64(acc[j], add, sum[j]);
                    }
                }
            }
            for (acc, v) in acc.iter_mut().zip([&sx, &sy, &one]) {
                for j in 0..8 {
                    acc[j] = _mm512_mask_mov_epi64(acc[j], start, v[j]);
                }
            }
            started |= nonzero;
        }
    }

    let r = splat(&const { radix_52(&P::R.0) });
    // SAFETY: this function enables both target features that `mont_n` and `mont` require.
    let [z] = unsafe { mont_n([&acc[2]], [&z_c], p, n0) };
    let z = normalize(&z);
    // SAFETY: as above.
    let coordinates = unsafe { [mont(&acc[0], &r, p, n0), mont(&acc[1], &r, p, n0), mont(&z, &r, p, n0)] };
    for (c, v) in coordinates.iter().enumerate() {
        let mut w = [[0u64; 8]; 6];
        for (w, v) in w.iter_mut().zip(words(v)) {
            *w = to_array(v);
        }
        for (l, out) in out.iter_mut().enumerate() {
            for (j, out) in out[c].0.0.iter_mut().enumerate() {
                *out = w[j][l];
            }
        }
    }
}

/// Returns `2 acc` for the accumulator `acc = (X, Y, Z)` in Jacobian coordinates on a curve
/// `y^2 = x^3 + b`, by the formulas of `Projective::double_in_place`:
///   `A = X^2`, `B = Y^2`, `C = B^2`, `D = 2 ((X + B)^2 - A - C)`, `E = 3 A`, `F = E^2`,
///   `X_3 = F - 2 D`, `Y_3 = E (D - X_3) - 8 C`, `Z_3 = 2 Y Z`.
///
/// `m[s]` holds `2^s p`, and `n0` holds `-p^-1 mod 2^52`. For `X`, `Y` and `Z` below `34 p`,
/// `18 p` and `4 p` with limbs below 2^52, it returns them below the same bounds, with limbs below
/// 2^52.
// Inlined into the ladder, this ran at half speed on Zen 5 in some builds: the ladder's size puts
// its placement at the mercy of each build.
#[inline(never)]
#[target_feature(enable = "avx512f,avx512ifma")]
fn glv_double(acc: &[[__m512i; 8]; 3], m: &[[__m512i; 8]; 7], n0: __m512i) -> [[__m512i; 8]; 3] {
    let [x, y, z] = acc;
    // SAFETY: this function enables both target features that `mont_n` requires.
    let [a, b, yz] = unsafe { mont_n([x, y, y], [x, y, z], &m[0], n0) };
    let b = normalize(&b);
    let xb = normalize(&add(x, &b));
    let e = normalize(&add(&a, &shift::<1>(&a)));
    // SAFETY: as above.
    let [c, t, f] = unsafe { mont_n([&b, &xb, &e], [&b, &xb, &e], &m[0], n0) };
    // `D` is below `12 p`, `X_3` is `F - 2 D + 32 p`, and `D - X_3` is `3 D - F` mod `p`.
    let d = signed_normalize(&add(&shift::<1>(&sub(&sub(&t, &a), &c)), &m[3]));
    let x3 = signed_normalize(&add(&sub(&f, &shift::<1>(&d)), &m[5]));
    let dx = signed_normalize(&add(&sub(&add(&d, &shift::<1>(&d)), &f), &m[1]));
    // SAFETY: as above.
    let [edx] = unsafe { mont_n([&e], [&dx], &m[0], n0) };
    let y3 = signed_normalize(&add(&sub(&edx, &shift::<3>(&c)), &m[4]));
    let z3 = normalize(&shift::<1>(&yz));
    [x3, y3, z3]
}

/// Returns `acc + (x, y)` and `H`, for the accumulator `acc = (X_1, Y_1, Z_1)` in Jacobian
/// coordinates and the affine point `(x, y)`, by the formulas of `Projective::add_assign_mixed`
/// for two points with different `x`:
///   `U = x Z_1^2`, `S = y Z_1^3`, `H = U - X_1`, `I = 4 H^2`, `J = H I`, `R = 2 (S - Y_1)`,
///   `V = X_1 I`, `X_3 = R^2 - J - 2 V`, `Y_3 = R (V - X_3) - 2 Y_1 J`, `Z_3 = 2 Z_1 H`.
///
/// `m` and `n0` are as in `glv_double`. For `X_1`, `Y_1` and `Z_1` below `34 p`, `18 p` and `4 p`,
/// and `x` and `y` below `10 p` and `8 p`, all with limbs below 2^52, it returns the sum below
/// `10 p`, `6 p` and `4 p`, and `H` below `66 p`, with limbs below 2^52.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn glv_add(
    acc: &[[__m512i; 8]; 3],
    x: &[__m512i; 8],
    y: &[__m512i; 8],
    m: &[[__m512i; 8]; 7],
    n0: __m512i,
) -> ([[__m512i; 8]; 3], [__m512i; 8]) {
    let [x1, y1, z1] = acc;
    // SAFETY: this function enables both target features that `mont_n` requires.
    let [zz, yz] = unsafe { mont_n([z1, y], [z1, z1], &m[0], n0) };
    let (zz, yz) = (normalize(&zz), normalize(&yz));
    // SAFETY: as above.
    let [u, s] = unsafe { mont_n([x, &yz], [&zz, &zz], &m[0], n0) };
    let h = signed_normalize(&add(&sub(&u, x1), &m[6]));
    let r = signed_normalize(&add(&shift::<1>(&sub(&s, y1)), &m[6]));
    // SAFETY: as above.
    let [hh, rr, zh] = unsafe { mont_n([&h, &r, z1], [&h, &r, &h], &m[0], n0) };
    let i = normalize(&shift::<2>(&hh));
    // SAFETY: as above.
    let [j, v] = unsafe { mont_n([&h, x1], [&i, &i], &m[0], n0) };
    let j = normalize(&j);
    let x3 = signed_normalize(&add(&sub(&sub(&rr, &j), &shift::<1>(&v)), &m[3]));
    let vx = signed_normalize(&add(&sub(&v, &x3), &m[4]));
    // SAFETY: as above.
    let [rvx, yj] = unsafe { mont_n([&r, y1], [&vx, &j], &m[0], n0) };
    let y3 = signed_normalize(&add(&sub(&rvx, &shift::<1>(&yj)), &m[2]));
    let z3 = normalize(&shift::<1>(&zh));
    ([x3, y3, z3], h)
}

/// Returns `x 2^S`, limb by limb.
#[inline]
#[target_feature(enable = "avx512f")]
fn shift<const S: u32>(x: &[__m512i; 8]) -> [__m512i; 8] {
    let mut v = [_mm512_setzero_si512(); 8];
    for k in 0..8 {
        v[k] = _mm512_slli_epi64::<S>(x[k]);
    }
    v
}

/// Returns the words of coordinate `c` of the 8 points: lane `l` of vector `w` holds word `w` of
/// `points[l][c]`.
#[inline]
#[target_feature(enable = "avx512f")]
fn point_words<P: Fp384Parameters>(points: &[[Fp384<P>; 2]; 8], c: usize) -> [__m512i; 6] {
    element_words(std::array::from_fn(|l| &points[l][c]))
}
