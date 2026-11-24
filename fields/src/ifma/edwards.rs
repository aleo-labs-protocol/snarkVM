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

//! Sums of table entries on a twisted Edwards curve `-x^2 + y^2 = 1 + d x^2 y^2` over `Fp256`,
//! on 8 points at once, held in lanes from the coordinate words to the canonical result.
//!
//! # Representation
//!
//! As in `poseidon`, a field element `x` is resident in a lane as an integer congruent to
//! `x 2^260 mod p`, in 5 limbs below 2^52. A coordinate of a point is below `2 p`. `Fp256` stores
//! `x 2^256 mod p`, so a table entry enters shifted left by 4 bits, as an integer below `16 p`. A
//! coordinate enters the same way, and one `mont_sum` by `2^260 mod p` takes it below `2 p`. It
//! leaves through one `mont_sum` by `2^256 mod p`, which divides by 2^260, and one subtraction of
//! `p`. A result is canonical, in `[0, p)`, when it is stored.
//!
//! # Formulas
//!
//! A point is held in extended coordinates `(X, Y, T, Z)` with `x = X / Z`, `y = Y / Z` and
//! `T = x y Z`. An entry holds `(y - x, y + x, 2 d x y)` of an affine point `(x, y)`. `add_entry`
//! is the mixed addition [madd-2008-hwcd-3] for `a = -1` with those three values precomputed: 3
//! independent products, then 4. The formulas are polynomials, so they return some integers for
//! any input, on the curve or not.
//!
//! # Bounds
//!
//! With `p < 2^253`, `p^2 / 2^260 < p / 128`, so `mont_sum` of a product below `c p^2` is below
//! `(c / 128 + 1) p`. `difference` adds `2 p` to a difference. With coordinates below `2 p` and
//! entry values below `16 p`:
//!
//! - `Y - X` and `Y + X` are below `4 p`, so `A` and `B` are below `3 p / 2`; `C` is below
//!   `5 p / 4`, and `D = 2 Z` is below `4 p`.
//! - `E = B - A` is below `7 p / 2`, `F = D - C` below `6 p`, `G = D + C` below `21 p / 4`, and
//!   `H = B + A` below `3 p`.
//! - `E F`, `G H`, `E H` and `F G` are below `32 p^2`, so the new coordinates are below
//!   `5 p / 4`.
//!
//! `16 p < 2^260`, so the top limb of every normalized value is below 2^52.
//!
//! [madd-2008-hwcd-3]: https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-madd-2008-hwcd-3

use super::{
    EdwardsStep,
    kernel::{normalize, subtract_p_below_2p},
    layout::{MASK, add, radix_52, splat},
    poseidon::{Lanes, limbs_shifted_4, mont_sum, mont_sums, store, words_shifted_4},
};
use crate::{Fp256, Fp256Parameters};

use std::arch::x86_64::*;

/// The number of steps between a step and the one whose entries it brings into the cache.
const PREFETCH_DISTANCE: usize = 2;

/// Returns limbs whose integer is `2 p`, each of limbs 0 to 3 at least `2^52 - 1` and below 2^54:
/// the limbs of `p` doubled, plus 2^52 in limb 0 and `2^52 - 1` in limbs 1 to 3, minus 1 in limb
/// 4, which wraps when the top limb of `p` is zero.
const fn difference_offset(p: &[u64; 4]) -> [u64; 5] {
    let p: [u64; 5] = radix_52(p);
    [2 * p[0] + (1 << 52), 2 * p[1] + MASK, 2 * p[2] + MASK, 2 * p[3] + MASK, (2 * p[4]).wrapping_sub(1)]
}

/// Returns `x + 2 p - y`, with limbs below 2^52, for `x` and `y` with limbs below 2^52 and
/// `y <= 2 p`. `offset` holds `difference_offset(p)` in every lane.
///
/// Limbs 0 to 3 of `x + offset - y` are in `[0, 2^55)`. The top limb is taken mod 2^64: it is
/// right after the carries, since the integer is not negative.
#[inline]
#[target_feature(enable = "avx512f")]
fn difference(x: &Lanes, y: &Lanes, offset: &Lanes) -> Lanes {
    let mut v = add(x, offset);
    for k in 0..5 {
        v[k] = _mm512_sub_epi64(v[k], y[k]);
    }
    normalize(&v)
}

/// Sets `point`, as `(X, Y, T, Z)`, to its sum with `entry`, as `(y - x, y + x, 2 d x y)`.
/// Requires coordinates below `2 p` and entry values below `16 p`, with limbs below 2^52, and
/// `p < 2^253`. Leaves coordinates below `2 p`, with limbs below 2^52.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn add_entry(point: &mut [Lanes; 4], entry: &[Lanes; 3], p: &Lanes, n0: __m512i, offset: &Lanes) {
    let [x, y, t, z] = point;
    // SAFETY: this function enables both target features that `mont_sums` requires.
    unsafe {
        let [a, b, c] = mont_sums(
            [[&difference(y, x, offset)], [&normalize(&add(y, x))], [t]],
            [[&entry[0]], [&entry[1]], [&entry[2]]],
            p,
            n0,
        );
        let d = normalize(&add(z, z));
        let e = difference(&b, &a, offset);
        let f = difference(&d, &c, offset);
        let g = normalize(&add(&d, &c));
        let h = normalize(&add(&b, &a));
        let [x3, y3, t3, z3] = mont_sums([[&e], [&g], [&e], [&f]], [[&f], [&h], [&h], [&g]], p, n0);
        *point = [x3, y3, t3, z3];
    }
}

/// Returns the word offset of entry `indices[l]` of a table in lane `l`.
#[inline]
#[target_feature(enable = "avx512f")]
fn entry_offsets(indices: &[u32; 8]) -> __m512i {
    // SAFETY: this reads 8 `u32` from `indices`, an array of 8 `u32`.
    let i = _mm512_cvtepu32_epi64(unsafe { _mm256_loadu_si256(indices.as_ptr().cast()) });
    // An entry is 12 words.
    _mm512_add_epi64(_mm512_slli_epi64::<3>(i), _mm512_slli_epi64::<2>(i))
}

/// Returns the three values of entry `indices[l]` of `table` in lane `l`, each as the limbs of
/// its `Fp256` words shifted left by 4 bits: below `16 p`, with limbs below 2^52.
///
/// # Safety
///
/// Every index is below `table.len()`.
#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn gather_entry<P: Fp256Parameters>(table: &[[Fp256<P>; 3]], indices: &[u32; 8]) -> [Lanes; 3] {
    let offsets = entry_offsets(indices);
    // `Fp256` and `BigInteger256` are `repr(transparent)` over `[u64; 4]`, so an entry is 12
    // words, and the table is `12 table.len()` words.
    let words = table.as_ptr().cast::<i64>();
    let mut entry = [[_mm512_setzero_si512(); 5]; 3];
    for (c, value) in entry.iter_mut().enumerate() {
        let mut w = [_mm512_setzero_si512(); 4];
        for (i, w) in w.iter_mut().enumerate() {
            // SAFETY: lane `l` reads word `12 indices[l] + 4 c + i` of the table, which is inside
            // it since `indices[l] < table.len()` and `4 c + i < 12`. For the same reason the
            // table is not empty, and holds word `4 c + i`.
            *w = unsafe { _mm512_i64gather_epi64::<8>(offsets, words.add(4 * c + i).cast()) };
        }
        *value = words_shifted_4(&w);
    }
    entry
}

/// Brings entry `indices[l]` of `table` into the cache, for each `l`.
#[inline]
#[target_feature(enable = "avx512f")]
fn prefetch_entry<P: Fp256Parameters>(table: &[[Fp256<P>; 3]], indices: &[u32; 8]) {
    for index in indices {
        // A prefetch reads nothing, so an address outside the table is harmless. An entry is 96
        // bytes at an address that is a multiple of 8, so it lies in the cache lines of its
        // bytes 0, 64 and 95.
        let entry = table.as_ptr().wrapping_add(*index as usize).cast::<i8>();
        _mm_prefetch::<_MM_HINT_T0>(entry);
        _mm_prefetch::<_MM_HINT_T0>(entry.wrapping_add(64));
        _mm_prefetch::<_MM_HINT_T0>(entry.wrapping_add(95));
    }
}

/// Adds to the 8 points of `points` one entry of each table of `steps`, as
/// `edwards_add_entries_8`. Requires `p < 2^253`.
///
/// # Safety
///
/// The CPU supports AVX-512F and AVX-512 IFMA, and in every step, every index is below the length
/// of the table.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(super) unsafe fn add_entries_8_avx512<P: Fp256Parameters>(
    points: &mut [[Fp256<P>; 8]; 4],
    steps: &[EdwardsStep<'_, Fp256<P>>],
) {
    let p = splat(&const { radix_52::<4, 5>(&P::MODULUS.0) });
    let n0 = _mm512_set1_epi64((P::INV & MASK) as i64);
    let offset = splat(&const { difference_offset(&P::MODULUS.0) });

    // `Fp256` stores `2^260 mod p`, which is one as a lane holds it, as the element 16. A
    // coordinate enters below `16 p`, so its product by `2^260 mod p` is below `2 p`.
    let one = splat(&radix_52::<4, 5>(&Fp256::<P>::from(16u64).0.0));
    let mut lanes = [[_mm512_setzero_si512(); 5]; 4];
    for (lanes, x) in lanes.iter_mut().zip(points.iter()) {
        // SAFETY: this function enables both target features that `mont_sum` requires.
        *lanes = unsafe { mont_sum([&limbs_shifted_4(x)], [&one], &p, n0) };
    }

    for (i, (table, indices)) in steps.iter().enumerate() {
        if let Some((table, indices)) = steps.get(i + PREFETCH_DISTANCE) {
            prefetch_entry(table, indices);
        }
        // SAFETY: the caller guarantees that every index is below `table.len()`.
        let entry = unsafe { gather_entry(table, indices) };
        add_entry(&mut lanes, &entry, &p, n0, &offset);
    }

    // A coordinate is below `2 p`, so its product by `2^256 mod p` is below `2 p`.
    let exit = splat(&radix_52::<4, 5>(&P::R.0));
    for (x, lanes) in points.iter_mut().zip(&lanes) {
        // SAFETY: this function enables both target features that `mont_sum` requires.
        let v = unsafe { mont_sum([lanes], [&exit], &p, n0) };
        store(x, &subtract_p_below_2p(&v, &p));
    }
}
