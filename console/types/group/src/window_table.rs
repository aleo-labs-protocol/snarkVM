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

use super::*;

/// Precomputed multiples of one group element, for fast multiplication by public scalars.
///
/// With `w = WINDOW_BITS`, window `i` holds `j * 2^(w * i) * base` for `j` in `1..=2^(w - 1)`, in affine form.
/// A product recodes the scalar into signed base-`2^w` digits and takes one mixed addition per nonzero digit,
/// with no doublings. A wider window takes fewer additions and a table about `2^w / w` times the base size.
///
/// The running time and the memory accessed depend on the scalar. Never use a table with a secret scalar.
#[derive(Clone)]
pub struct GroupWindowTable<E: Environment, const WINDOW_BITS: usize = 4> {
    /// The element whose multiples the table holds.
    base: Group<E>,
    /// The multiples, window by window.
    multiples: Vec<E::Affine>,
}

impl<E: Environment, const WINDOW_BITS: usize> GroupWindowTable<E, WINDOW_BITS> {
    /// The number of multiples stored per window: signed digits lie in `-2^(w - 1)..=2^(w - 1)`.
    const MULTIPLES_PER_WINDOW: usize = 1 << (WINDOW_BITS - 1);

    /// The number of windows: one per digit of a scalar, plus one for the final carry.
    fn num_windows() -> usize {
        E::Scalar::size_in_bits().div_ceil(WINDOW_BITS) + 1
    }

    /// Returns the table of multiples of `base`.
    pub fn new(base: &Group<E>) -> Self {
        const { assert!(WINDOW_BITS >= 2 && WINDOW_BITS <= 16, "the window must be 2 to 16 bits") };
        let mut multiples = Vec::with_capacity(Self::num_windows() * Self::MULTIPLES_PER_WINDOW);
        let mut window_base = base.group;
        for _ in 0..Self::num_windows() {
            let mut multiple = window_base;
            multiples.push(multiple);
            for _ in 1..Self::MULTIPLES_PER_WINDOW {
                multiple += window_base;
                multiples.push(multiple);
            }
            // `multiple` is `2^(w - 1) * window_base`, which doubles to the next window's base.
            window_base = multiple.double();
        }
        Self { base: *base, multiples: E::Projective::batch_normalization_into_affine(multiples) }
    }

    /// Returns the element whose multiples this table holds.
    pub const fn base(&self) -> Group<E> {
        self.base
    }

    /// Returns `base * scalar`, where `base` is the element this table was built from.
    pub fn mul(&self, scalar: &Scalar<E>) -> Group<E> {
        let scalar = scalar.to_bigint();
        let limbs = scalar.as_ref();
        let limb = |index: usize| limbs.get(index).copied().unwrap_or(0);
        let mut product = E::Projective::zero();
        let mut carry = 0;
        for (i, window) in self.multiples.chunks_exact(Self::MULTIPLES_PER_WINDOW).enumerate() {
            // Read the `w` bits of window `i`, which may straddle two limbs.
            let (index, shift) = ((i * WINDOW_BITS) / 64, (i * WINDOW_BITS) % 64);
            let mut bits = limb(index) >> shift;
            if shift + WINDOW_BITS > 64 {
                bits |= limb(index + 1) << (64 - shift);
            }
            // The mask keeps at most 16 bits, so the cast cannot truncate.
            #[allow(clippy::cast_possible_truncation)]
            let mut digit = (bits & ((1 << WINDOW_BITS) - 1)) as i32 + carry;
            carry = i32::from(digit >= 1 << (WINDOW_BITS - 1));
            digit -= carry << WINDOW_BITS;
            if digit != 0 {
                let multiple = window[digit.unsigned_abs() as usize - 1];
                product.add_assign_mixed(&if digit > 0 { multiple } else { -multiple });
            }
        }
        debug_assert_eq!(carry, 0, "the last window absorbs the final carry");
        Group::from_projective(product)
    }
}

impl<E: Environment, const WINDOW_BITS: usize> Debug for GroupWindowTable<E, WINDOW_BITS> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("GroupWindowTable")
            .field("window_bits", &WINDOW_BITS)
            .field("multiples", &self.multiples.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    type CurrentEnvironment = Console;

    const ITERATIONS: usize = 100;

    /// Checks the table against the double-and-add product.
    fn check<const W: usize>(table: &GroupWindowTable<CurrentEnvironment, W>, scalar: Scalar<CurrentEnvironment>) {
        assert_eq!(table.mul(&scalar), table.base() * scalar, "window {W}, scalar {scalar}");
    }

    /// Checks tables of `W`-bit windows over random bases.
    fn check_window<const W: usize>(rng: &mut TestRng) {
        for _ in 0..4 {
            let base = Group::<CurrentEnvironment>::rand(rng);
            let table = GroupWindowTable::<_, W>::new(&base);
            assert_eq!(table.base(), base);

            for _ in 0..ITERATIONS {
                check(&table, Scalar::rand(rng));
            }

            // Zero, one, the largest scalar, every power of two, and every run of low ones,
            // whose digits all carry.
            check(&table, Scalar::zero());
            check(&table, Scalar::one());
            check(&table, -Scalar::one());
            let mut power = Scalar::one();
            for _ in 0..<CurrentEnvironment as Environment>::Scalar::size_in_bits() {
                check(&table, power);
                check(&table, -power);
                check(&table, power - Scalar::one());
                power = power.double();
            }

            // Repeated byte patterns, whose digits carry in different places for each width.
            for byte in [0x55u8, 0x88, 0xAA, 0xCC, 0xF0, 0xFF] {
                let bytes = [byte; 32];
                check(
                    &table,
                    Scalar::new(<CurrentEnvironment as Environment>::Scalar::from_bytes_le_mod_order(&bytes)),
                );
            }
        }
    }

    #[test]
    fn test_mul_matches_double_and_add() {
        let rng = &mut TestRng::default();

        check_window::<2>(rng);
        check_window::<3>(rng);
        check_window::<4>(rng);
        check_window::<5>(rng);
        check_window::<6>(rng);
        check_window::<7>(rng);
        check_window::<8>(rng);
    }
}
