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

//! The Poseidon permutation of width 9 with the S-box `x^17` and sparse partial rounds over
//! `Fp256`, on 8 states at once, held in lanes from the state words to the canonical result.
//!
//! # Representation
//!
//! A limb group `[__m512i; 5]` holds 8 integers below 2^260: vector `k` holds limb `k`, in radix
//! 2^52, of each of the 8 lanes. A field element `x` is resident in a lane as an integer below
//! `70 p` congruent to `x 2^260 mod p`, with limbs below 2^52. `Fp256` stores `x 2^256 mod p`,
//! so an element enters a program shifted left by 4 bits, as an integer below `16 p`, and leaves
//! it through one `mont_sum` by `2^256 mod p`, which divides by 2^260, and one subtraction of
//! `p`. A result is canonical, in `[0, p)`, when it is stored. The constants of the permutation
//! are held as the limbs of `c 2^260 mod p`, in `[0, p)`.
//!
//! # Bounds
//!
//! With `p < 2^253`, `p^2 / 2^260 < p / 128`, so `mont_sum` of a sum below `c p^2` is below
//! `(c / 128 + 1) p`. A state element is below `69 p` at the start of every round:
//!
//! - It enters below `16 p`.
//! - A round constant takes it below `70 p`, and `s_box` returns less than `2 p`.
//! - A full round returns a sum of 9 products of a matrix entry by an S-box output, below
//!   `18 p^2`, so each element leaves below `2 p`.
//! - A partial round adds the product of a column entry by the S-box output, below
//!   `p + p / 64`, to each element but the first. A permutation has at most
//!   `MAX_PARTIAL_ROUNDS = 64` of them after a full round, so these elements are below `66 p`
//!   before each of them and below `2 p + 64 (p + p / 64) = 67 p` after the last. The first
//!   element is a sum of 9 products of a row entry by an element, below `(2 + 8 * 66) p^2`, so
//!   it is below `6 p`.
//!
//! `70 p < 2^260`, so the top limb of a normalized element is below 2^52.

use super::{
    kernel::{normalize, subtract_p_below_2p},
    layout::{MASK, add, join, radix_52, splat, to_array},
};
use crate::{Fp256, Fp256Parameters, PoseidonSparseRounds};

use std::arch::x86_64::*;

/// The state width.
const WIDTH: usize = 9;

/// The most partial rounds of a permutation that runs in lanes.
const MAX_PARTIAL_ROUNDS: usize = 64;

/// The limbs of an integer below 2^260, in radix 2^52.
type Limbs = [u64; 5];

/// The limbs of 8 integers below 2^260: lane `l` of vector `k` holds limb `k` of integer `l`.
pub(super) type Lanes = [__m512i; 5];

/// The constants of a Poseidon permutation of width 9 with the S-box `x^17`, each as the limbs of
/// `c 2^260 mod p`, with the limbs of `p`.
#[derive(Debug)]
pub(crate) struct LaneRounds {
    /// The limbs of `p`.
    modulus: Limbs,
    /// `-p^-1 mod 2^52`.
    n0: u64,
    /// The limbs of `2^256 mod p`.
    exit: Limbs,
    /// The round constants of each full round before the partial rounds.
    first_arks: Vec<[Limbs; WIDTH]>,
    /// The MDS matrix.
    mds: [[Limbs; WIDTH]; WIDTH],
    /// The matrix of the last full round before the partial rounds.
    first_matrix: [[Limbs; WIDTH]; WIDTH],
    /// The partial rounds, in order.
    partial_rounds: Vec<LanePartialRound>,
    /// The round constants of each full round after the partial rounds.
    last_arks: Vec<[Limbs; WIDTH]>,
}

/// The constant, the row and the column of a `PoseidonSparseRound`.
#[derive(Debug)]
struct LanePartialRound {
    constant: Limbs,
    row: [Limbs; WIDTH],
    column: [Limbs; WIDTH - 1],
}

impl LaneRounds {
    /// Returns the constants of `sparse_rounds`, or `None` if `P::MODULUS_BITS` is above 253, the
    /// rate is not 8, the S-box is not `x^17`, there are more than `MAX_PARTIAL_ROUNDS` partial
    /// rounds, or no full round runs before them.
    pub(super) fn new<P: Fp256Parameters, const RATE: usize>(
        sparse_rounds: &PoseidonSparseRounds<Fp256<P>, RATE>,
    ) -> Option<Self> {
        let parameters = sparse_rounds.parameters();
        if P::MODULUS_BITS > 253
            || RATE + 1 != WIDTH
            || parameters.alpha != 17
            || sparse_rounds.rounds().len() > MAX_PARTIAL_ROUNDS
        {
            return None;
        }
        // `Fp256` stores `c 2^260 mod p` as the element `16 c`.
        let sixteen = Fp256::<P>::from(16u64);
        let limbs = |c: &Fp256<P>| -> Limbs { radix_52(&(*c * sixteen).0.0) };
        fn array<P: Fp256Parameters, const N: usize>(
            row: &[Fp256<P>],
            limbs: impl Fn(&Fp256<P>) -> Limbs,
        ) -> Option<[Limbs; N]> {
            let mut out = [[0; 5]; N];
            if row.len() != N {
                return None;
            }
            for (out, c) in out.iter_mut().zip(row) {
                *out = limbs(c);
            }
            Some(out)
        }
        let matrix = |rows: &[Vec<Fp256<P>>]| -> Option<[[Limbs; WIDTH]; WIDTH]> {
            let mut out = [[[0; 5]; WIDTH]; WIDTH];
            if rows.len() != WIDTH {
                return None;
            }
            for (out, row) in out.iter_mut().zip(rows) {
                *out = array(row, limbs)?;
            }
            Some(out)
        };

        let first_partial_round = parameters.full_rounds / 2;
        let last_partial_round = first_partial_round + parameters.partial_rounds;
        let num_rounds = parameters.full_rounds + parameters.partial_rounds;
        let first_arks = parameters.ark.get(..first_partial_round)?;
        // The bounds need an element below `2 p` at the first partial round.
        if first_arks.is_empty() {
            return None;
        }
        let last_arks = parameters.ark.get(last_partial_round + 1..num_rounds)?;
        Some(Self {
            modulus: radix_52(&P::MODULUS.0),
            n0: P::INV & MASK,
            exit: radix_52(&P::R.0),
            first_arks: first_arks.iter().map(|ark| array(ark, limbs)).collect::<Option<_>>()?,
            mds: matrix(&parameters.mds)?,
            first_matrix: matrix(sparse_rounds.first_matrix())?,
            partial_rounds: sparse_rounds
                .rounds()
                .iter()
                .map(|round| {
                    Some(LanePartialRound {
                        constant: limbs(&round.constant()),
                        row: array(round.row(), limbs)?,
                        column: array(round.column(), limbs)?,
                    })
                })
                .collect::<Option<_>>()?,
            last_arks: std::iter::once(array(sparse_rounds.last_ark(), limbs))
                .chain(last_arks.iter().map(|ark| array(ark, limbs)))
                .collect::<Option<_>>()?,
        })
    }
}

/// Returns, in each lane, the integer `(a[0] b[0] + ... + a[K - 1] b[K - 1] + m p) / 2^260` with
/// `m = -(a[0] b[0] + ... + a[K - 1] b[K - 1]) p^-1 mod 2^260`. It is congruent to the sum times
/// `2^-260` mod `p` and below `sum / 2^260 + p`. All its limbs but the top one are below 2^52,
/// and so is the top one when the integer is below 2^260.
///
/// Requires limbs below 2^52, odd `p` in `p`, `-p^-1 mod 2^52` in `n0` and `K <= 400`.
///
/// The 5 rounds are written out by `round!`: as a loop, LLVM keeps the accumulator on the stack.
///
/// # Safety
///
/// The CPU supports AVX-512F and AVX-512 IFMA. This function has no `target_feature`, so that it
/// can be `inline(always)`: as an `inline` hint, LLVM stops inlining it once it has two callers.
#[inline(always)]
pub(super) unsafe fn mont_sum<const K: usize>(a: [&Lanes; K], b: [&Lanes; K], p: &Lanes, n0: __m512i) -> Lanes {
    // SAFETY: the caller guarantees both target features.
    unsafe {
        let zero = _mm512_setzero_si512();
        let mut t = [zero; 6];

        // Adds the low half of `x y` to `lo` and the high half to `hi`.
        macro_rules! madd {
            ($lo:expr, $hi:expr, $x:expr, $y:expr) => {
                $lo = _mm512_madd52lo_epu64($lo, $x, $y);
                $hi = _mm512_madd52hi_epu64($hi, $x, $y);
            };
        }

        // Adds `a[k] b[k]_i` for each `k`, and `m p`, to the accumulator
        // `t_0 + t_1 2^52 + ... + t_5 2^260`, with `m` chosen so that the sum is divisible by
        // 2^52, and divides it by 2^52. `t_0` is zero afterwards, and the next round takes it as
        // its top limb. A limb enters as `t_5` and moves down one place each round. A round adds
        // `K + 1` halves of products, each below 2^52, to `t_5` and to `t_0`, and `2 (K + 1)` to
        // each of `t_1` to `t_4`, and `t_1` takes one carry, below 2^12. So the limbs stay below
        // `10 (K + 1) 2^52 + 2^12`, which is below 2^64 for `K <= 400`.
        macro_rules! round {
            ($i:literal; $t0:literal, $t1:literal, $t2:literal, $t3:literal, $t4:literal, $t5:literal) => {
                for k in 0..K {
                    let (a, bi) = (a[k], b[k][$i]);
                    madd!(t[$t0], t[$t1], a[0], bi);
                    madd!(t[$t1], t[$t2], a[1], bi);
                    madd!(t[$t2], t[$t3], a[2], bi);
                    madd!(t[$t3], t[$t4], a[3], bi);
                    madd!(t[$t4], t[$t5], a[4], bi);
                }
                let m = _mm512_madd52lo_epu64(zero, t[$t0], n0);
                madd!(t[$t0], t[$t1], m, p[0]);
                madd!(t[$t1], t[$t2], m, p[1]);
                madd!(t[$t2], t[$t3], m, p[2]);
                madd!(t[$t3], t[$t4], m, p[3]);
                madd!(t[$t4], t[$t5], m, p[4]);
                t[$t1] = _mm512_add_epi64(t[$t1], _mm512_srli_epi64::<52>(t[$t0]));
                t[$t0] = zero;
            };
        }

        round!(0; 0, 1, 2, 3, 4, 5);
        round!(1; 1, 2, 3, 4, 5, 0);
        round!(2; 2, 3, 4, 5, 0, 1);
        round!(3; 3, 4, 5, 0, 1, 2);
        round!(4; 4, 5, 0, 1, 2, 3);

        // The result is `t_5 + t_0 2^52 + ... + t_3 2^208`: the last round zeroed `t_4`, its limb
        // at 2^260.
        normalize(&[t[5], t[0], t[1], t[2], t[3]])
    }
}

/// Returns an integer below `2 p` congruent to `x^17 2^260` in each lane, with limbs below 2^52,
/// for `x` below `70 p` congruent to `x 2^260`, with limbs below 2^52, and `p < 2^253`.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn s_box(x: &Lanes, p: &Lanes, n0: __m512i) -> Lanes {
    // The squares are below `(70^2 / 128 + 1) p < 40 p`, `14 p`, `3 p` and `9 p / 8`, and the
    // result is below `((9 / 8) 70 / 128 + 1) p`.
    // SAFETY: this function enables both target features that `mont_sum` requires.
    unsafe {
        let x2 = mont_sum([x], [x], p, n0);
        let x4 = mont_sum([&x2], [&x2], p, n0);
        let x8 = mont_sum([&x4], [&x4], p, n0);
        let x16 = mont_sum([&x8], [&x8], p, n0);
        mont_sum([&x16], [x], p, n0)
    }
}

/// Returns `state[0] row[0] + ... + state[8] row[8]` in each lane, as `mont_sum` returns it.
/// Requires limbs below 2^52.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn row_product(state: &[Lanes; WIDTH], row: &[Limbs; WIDTH], p: &Lanes, n0: __m512i) -> Lanes {
    let row = row.map(|c| splat(&c));
    // SAFETY: this function enables both target features that `mont_sum` requires.
    unsafe { mont_sum(state.each_ref(), row.each_ref(), p, n0) }
}

/// Adds `ark` to `state`, applies the S-box to every element, and multiplies by `matrix`.
/// Requires elements below `69 p`, and leaves them below `2 p`.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn full_round(
    state: &mut [Lanes; WIDTH],
    ark: &[Limbs; WIDTH],
    matrix: &[[Limbs; WIDTH]; WIDTH],
    p: &Lanes,
    n0: __m512i,
) {
    for (x, c) in state.iter_mut().zip(ark) {
        *x = s_box(&normalize(&add(x, &splat(c))), p, n0);
    }
    let mut next = *state;
    for (x, row) in next.iter_mut().zip(matrix) {
        *x = row_product(state, row, p, n0);
    }
    *state = next;
}

/// Applies `round`: adds its constant to the first element, applies the S-box to it, and
/// multiplies the state by the matrix of the round's row and column. Requires a first element
/// below `69 p` and the other elements below `66 p`, and adds less than `p + p / 64` to each of
/// those. Leaves the first element below `6 p`.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma")]
fn partial_round(state: &mut [Lanes; WIDTH], round: &LanePartialRound, p: &Lanes, n0: __m512i) {
    state[0] = s_box(&normalize(&add(&state[0], &splat(&round.constant))), p, n0);
    let first = row_product(state, &round.row, p, n0);
    let head = state[0];
    for (x, c) in state[1..].iter_mut().zip(&round.column) {
        // SAFETY: this function enables both target features that `mont_sum` requires.
        let product = unsafe { mont_sum([&head], [&splat(c)], p, n0) };
        *x = normalize(&add(x, &product));
    }
    state[0] = first;
}

/// Returns the limbs of `x[l] 2^4` in lane `l`, for the 256-bit integer `x[l]` in `Fp256`'s
/// words, below 2^256.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn limbs_shifted_4<P: Fp256Parameters>(x: &[Fp256<P>; 8]) -> Lanes {
    let mut w = [_mm512_setzero_si512(); 4];
    for (i, w) in w.iter_mut().enumerate() {
        let word = |l: usize| x[l].0.0[i] as i64;
        *w = _mm512_set_epi64(word(7), word(6), word(5), word(4), word(3), word(2), word(1), word(0));
    }
    words_shifted_4(&w)
}

/// Returns the limbs of `x 2^4` for the 256-bit integers `x` whose words are `w`: lane `l` of
/// vector `i` holds word `i` of integer `l`.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn words_shifted_4(w: &[__m512i; 4]) -> Lanes {
    let mask = _mm512_set1_epi64(MASK as i64);
    [
        _mm512_and_si512(_mm512_slli_epi64::<4>(w[0]), mask),
        join::<48, 16>(w[0], w[1]),
        join::<36, 28>(w[1], w[2]),
        join::<24, 40>(w[2], w[3]),
        _mm512_srli_epi64::<12>(w[3]),
    ]
}

/// Sets `x[l]` to the element whose words are the integer below 2^256 in lane `l` of `v`, with
/// limbs below 2^52.
#[inline]
#[target_feature(enable = "avx512f")]
pub(super) fn store<P: Fp256Parameters>(x: &mut [Fp256<P>; 8], v: &Lanes) {
    let w = [
        _mm512_or_si512(v[0], _mm512_slli_epi64::<52>(v[1])),
        _mm512_or_si512(_mm512_srli_epi64::<12>(v[1]), _mm512_slli_epi64::<40>(v[2])),
        _mm512_or_si512(_mm512_srli_epi64::<24>(v[2]), _mm512_slli_epi64::<28>(v[3])),
        _mm512_or_si512(_mm512_srli_epi64::<36>(v[3]), _mm512_slli_epi64::<16>(v[4])),
    ]
    .map(|w| to_array(w));
    for (l, x) in x.iter_mut().enumerate() {
        x.0.0 = [w[0][l], w[1][l], w[2][l], w[3][l]];
    }
}

/// Applies the permutation of `rounds` to the 8 states of `state`, as `poseidon_permute_8`.
/// Requires `p < 2^253` and at most `MAX_PARTIAL_ROUNDS` partial rounds, as `LaneRounds::new`
/// checks.
///
/// # Safety
///
/// The CPU supports AVX-512F and AVX-512 IFMA.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(super) unsafe fn permute_8_avx512<P: Fp256Parameters>(rounds: &LaneRounds, state: &mut [[Fp256<P>; 8]; WIDTH]) {
    let p = splat(&rounds.modulus);
    let n0 = _mm512_set1_epi64(rounds.n0 as i64);

    let mut lanes = [[_mm512_setzero_si512(); 5]; WIDTH];
    for (lanes, x) in lanes.iter_mut().zip(state.iter()) {
        *lanes = limbs_shifted_4(x);
    }

    for (round, ark) in rounds.first_arks.iter().enumerate() {
        let matrix = if round + 1 == rounds.first_arks.len() { &rounds.first_matrix } else { &rounds.mds };
        full_round(&mut lanes, ark, matrix, &p, n0);
    }
    for round in &rounds.partial_rounds {
        partial_round(&mut lanes, round, &p, n0);
    }
    for ark in &rounds.last_arks {
        full_round(&mut lanes, ark, &rounds.mds, &p, n0);
    }

    // An element is below `69 p`, so its product by `2^256 mod p` is below `2 p`.
    let exit = splat(&rounds.exit);
    for (x, lanes) in state.iter_mut().zip(&lanes) {
        // SAFETY: this function enables both target features that `mont_sum` requires.
        let v = unsafe { mont_sum([lanes], [&exit], &p, n0) };
        store(x, &subtract_p_below_2p(&v, &p));
    }
}
