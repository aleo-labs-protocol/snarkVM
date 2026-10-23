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

use crate::{FftField, FftParameters, Field, Fp256, Fp256Parameters, Fp384, Fp384Parameters, PrimeField};

/// The largest number of bits of the 2-adic logarithm that one table look-up recovers.
const WINDOW: u32 = 8;

/// The largest number of windows: the 2-adicity is less than 64.
const MAX_WINDOWS: usize = 64usize.div_ceil(WINDOW as usize);

/// Precomputed tables for square roots in a prime field `F`, with `p - 1 = 2^n * m` and `m` odd.
///
/// Notation follows Sarkar, "Computing square roots faster than the Tonelli-Shanks/Bernstein
/// algorithm", https://eprint.iacr.org/2020/1407.pdf, Section 2: `g` is the 2-adic root of unity,
/// `v = u^((m-1)/2)` and `x = u * v^2 = u^m`. For a square `u` there is an even `t` in `[0, 2^n)`
/// with `x * g^t = 1`, and `sqrt` returns `u * v * g^(t/2)`, which is the root that Algorithm 1 returns.
///
/// `sqrt` recovers `t` window by window, lowest bits first, with one table look-up per window. This is
/// Bernstein's table look-up method ("Faster square roots in annoying finite fields"), whose tables and
/// operation counts Section 3.4 of the paper gives.
pub struct SqrtTables<F> {
    /// Returns a limb of the internal representation of an element.
    key: fn(&F) -> u64,
    /// The windows of `t`, as `(first bit, number of bits)`, from the lowest bits up.
    /// Bit 0 of `t` is zero for a square and has no window.
    windows: Vec<(u32, u32)>,
    /// `powers[i][c] = g^(c * 2^e)` for one exponent `e` per table.
    powers: Vec<Vec<F>>,
    /// `corrections[j][i]` is the table in `powers` that removes the bits of window `i` from window `j`.
    corrections: Vec<Vec<usize>>,
    /// The windows of `t/2`, as `(first bit, number of bits, table in powers)`.
    half_windows: Vec<(u32, u32, usize)>,
    /// `roots[c] = h^(-c)`, where `h = g^(2^(n - max_window))` has order `2^max_window`.
    roots: Vec<F>,
    /// An open-addressing hash table from `key(roots[c])` to `c`; `u16::MAX` marks an empty slot.
    slots: Vec<(u64, u16)>,
    /// The sliding-window exponentiation by `(m-1)/2`.
    exponent: ExponentSchedule,
}

impl<P: Fp256Parameters> SqrtTables<Fp256<P>> {
    /// Computes the tables for `Fp256<P>`.
    ///
    /// # Panics
    ///
    /// Panics if the 2-adicity is 64 or more, if `p - 1` is a power of two, or if two roots of unity
    /// in the look-up table have the same lowest limb.
    pub fn new() -> Self {
        Self::with_key(|element| element.0.0[0])
    }
}

impl<P: Fp256Parameters> Default for SqrtTables<Fp256<P>> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Fp384Parameters> SqrtTables<Fp384<P>> {
    /// Computes the tables for `Fp384<P>`.
    ///
    /// # Panics
    ///
    /// Panics if the 2-adicity is 64 or more, if `p - 1` is a power of two, or if two roots of unity
    /// in the look-up table have the same lowest limb.
    pub fn new() -> Self {
        Self::with_key(|element| element.0.0[0])
    }
}

impl<P: Fp384Parameters> Default for SqrtTables<Fp384<P>> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField> SqrtTables<F> {
    /// Computes the tables with `key` as the hash of an element. `key` must be a function of the
    /// element's value, and must differ between the roots of unity in the look-up table.
    #[doc(hidden)]
    pub fn with_key(key: fn(&F) -> u64) -> Self {
        let n = <F as FftField>::FftParameters::TWO_ADICITY;
        assert!(n < 64, "the 2-adicity must be less than 64");
        let g = F::two_adic_root_of_unity();

        // Bits 1..n of `t`: a short lowest window, then full windows.
        let count = (n - 1).div_ceil(WINDOW);
        let mut windows = Vec::with_capacity(count as usize);
        if count > 0 {
            let lowest = n - 1 - (count - 1) * WINDOW;
            windows.push((1, lowest));
            windows.extend((0..count - 1).map(|i| (1 + lowest + i * WINDOW, WINDOW)));
        }
        let max_window = windows.iter().map(|&(_, bits)| bits).max().unwrap_or(0);

        // One table per exponent, as long as the largest digit it multiplies by.
        let mut exponents: Vec<(u32, u32)> = Vec::new();
        let mut table_for = |exponent: u32, digit_bits: u32| -> usize {
            match exponents.iter().position(|&(e, _)| e == exponent) {
                Some(index) => {
                    exponents[index].1 = exponents[index].1.max(digit_bits);
                    index
                }
                None => {
                    exponents.push((exponent, digit_bits));
                    exponents.len() - 1
                }
            }
        };
        // Window `j` looks at `x^(2^(n - end_j))`, in which window `i < j` of `t` sits at
        // `g^(t_i * 2^(start_i + n - end_j))`.
        let corrections = windows
            .iter()
            .enumerate()
            .map(|(j, &(start_j, bits_j))| {
                windows[..j]
                    .iter()
                    .map(|&(start_i, bits_i)| table_for(start_i + n - start_j - bits_j, bits_i))
                    .collect()
            })
            .collect();
        // `t/2` has bits 0..n-1. Its lowest window also takes the bit below the lowest window of `t`.
        let half_windows = windows
            .iter()
            .enumerate()
            .map(|(j, &(start, bits))| {
                let (start, bits) = if j == 0 { (0, bits + 1) } else { (start, bits) };
                (start, bits, table_for(start, bits))
            })
            .collect();
        let powers = exponents
            .iter()
            .map(|&(exponent, digit_bits)| {
                let base = (0..exponent).fold(g, |power, _| power.square());
                std::iter::successors(Some(F::one()), |power| Some(*power * base)).take(1 << digit_bits).collect()
            })
            .collect();

        // The look-up table for the `2^max_window`-th roots of unity.
        // `g` has order `2^n`, so every power of it is non-zero and has an inverse.
        let h_inverse = (0..n - max_window).fold(g, |power, _| power.square()).inverse().unwrap();
        let roots: Vec<F> =
            std::iter::successors(Some(F::one()), |power| Some(*power * h_inverse)).take(1 << max_window).collect();
        let mask = (4usize << max_window) - 1;
        let mut slots = vec![(0, u16::MAX); mask + 1];
        for (c, root) in roots.iter().enumerate() {
            let mut slot = key(root) as usize & mask;
            while slots[slot].1 != u16::MAX {
                assert_ne!(slots[slot].0, key(root), "two roots of unity share a key");
                slot = (slot + 1) & mask;
            }
            slots[slot] = (key(root), c as u16);
        }

        let exponent = ExponentSchedule::new(F::trace_minus_one_div_two().as_ref());

        Self { key, windows, powers, corrections, half_windows, roots, slots, exponent }
    }

    /// Returns `c` such that `element = h^(-c)`, if there is one.
    #[inline]
    fn log(&self, element: &F) -> Option<u64> {
        let key = (self.key)(element);
        let mask = self.slots.len() - 1;
        let mut slot = key as usize & mask;
        loop {
            let (slot_key, c) = self.slots[slot];
            if c == u16::MAX {
                return None;
            }
            if slot_key == key {
                return (self.roots[c as usize] == *element).then_some(c as u64);
            }
            slot = (slot + 1) & mask;
        }
    }

    /// Returns the square root of `u` that Algorithm 1 of the paper returns, or `None` if `u` is not
    /// a square.
    ///
    /// Its running time and table accesses depend on `u`.
    pub fn sqrt(&self, u: &F) -> Option<F> {
        if u.is_zero() {
            return Some(*u);
        }
        let v = self.exponent.pow(u);
        let uv = *u * v;
        let x = uv * v;
        if self.windows.is_empty() {
            return x.is_one().then_some(uv);
        }

        // `bases[j] = x^(2^(n - end_j))`, where window `j` ends at bit `end_j` of `t`.
        let k = self.windows.len();
        let max_window = self.roots.len().trailing_zeros();
        let mut bases = [x; MAX_WINDOWS];
        for j in (0..k - 1).rev() {
            bases[j] = bases[j + 1];
            for _ in 0..self.windows[j + 1].1 {
                bases[j].square_in_place();
            }
        }

        // Multiplying `bases[j]` by the corrections for windows `0..j` leaves `h^(-(t_j << (max_window - bits_j)))`,
        // where `t_j` holds the bits of window `j`. A non-square has odd `t`. Then the corrections
        // leave bit 0 of `t` in place, and window `j` leaves an element of order `2^end_j`. That element
        // is not in the look-up table once `end_j` exceeds `max_window`, which holds at the last window.
        let mut digits = [0u64; MAX_WINDOWS];
        let mut t = 0u64;
        for j in 0..k {
            let mut alpha = bases[j];
            for (i, &table) in self.corrections[j].iter().enumerate() {
                alpha *= self.powers[table][digits[i] as usize];
            }
            let (start, bits) = self.windows[j];
            digits[j] = self.log(&alpha)? >> (max_window - bits);
            t |= digits[j] << start;
        }

        let half_t = t >> 1;
        let mut root = uv;
        for &(start, bits, table) in &self.half_windows {
            root *= self.powers[table][((half_t >> start) & ((1 << bits) - 1)) as usize];
        }
        Some(root)
    }
}

/// The largest window of the exponentiation by `(m-1)/2`.
const MAX_EXPONENT_WINDOW: u32 = 6;

/// A sliding-window exponentiation by a fixed exponent. Odd power `i` is `u^(2i+1)`.
#[doc(hidden)]
pub struct ExponentSchedule {
    /// The number of odd powers to precompute.
    odd_powers: usize,
    /// The odd power that starts the exponentiation.
    first: usize,
    /// The `(squarings, odd power)` steps after the first.
    steps: Vec<(u32, usize)>,
    /// The squarings after the last step.
    trailing_squarings: u32,
}

impl ExponentSchedule {
    /// Returns the schedule with the fewest multiplications for the non-zero exponent `limbs`,
    /// in little-endian order.
    pub fn new(limbs: &[u64]) -> Self {
        let bits: Vec<bool> = snarkvm_utilities::BitIteratorBE::new_without_leading_zeros(limbs).collect();
        assert!(!bits.is_empty(), "the exponent must be non-zero");
        (1..=MAX_EXPONENT_WINDOW)
            .map(|width| {
                let mut windows = Vec::new();
                let mut squarings = 0;
                let mut i = 0;
                while i < bits.len() {
                    if !bits[i] {
                        squarings += 1;
                        i += 1;
                        continue;
                    }
                    let mut end = (i + width as usize).min(bits.len());
                    while !bits[end - 1] {
                        end -= 1;
                    }
                    let value = bits[i..end].iter().fold(0usize, |value, &bit| (value << 1) | bit as usize);
                    windows.push((squarings + (end - i) as u32, value / 2));
                    squarings = 0;
                    i = end;
                }
                // `bits` starts with a one, so `windows` is non-empty.
                let odd_powers = windows.iter().map(|&(_, odd_power)| odd_power).max().unwrap() + 1;
                let first = windows.remove(0).1;
                Self { odd_powers, first, steps: windows, trailing_squarings: squarings }
            })
            .min_by_key(|schedule| schedule.odd_powers + schedule.steps.len())
            // The range of window widths is non-empty.
            .unwrap()
    }

    #[inline]
    pub fn pow<F: Field>(&self, u: &F) -> F {
        let mut odd_powers = [*u; 1 << (MAX_EXPONENT_WINDOW - 1)];
        let u_squared = u.square();
        for i in 1..self.odd_powers {
            odd_powers[i] = odd_powers[i - 1] * u_squared;
        }
        let mut result = odd_powers[self.first];
        for &(squarings, odd_power) in &self.steps {
            for _ in 0..squarings {
                result.square_in_place();
            }
            result *= odd_powers[odd_power];
        }
        for _ in 0..self.trailing_squarings {
            result.square_in_place();
        }
        result
    }
}
