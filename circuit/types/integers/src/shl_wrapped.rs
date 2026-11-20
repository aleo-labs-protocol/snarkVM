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

impl<E: Environment, I: IntegerType, M: Magnitude> ShlWrapped<Integer<E, M>> for Integer<E, I> {
    type Output = Self;

    #[inline]
    fn shl_wrapped(&self, rhs: &Integer<E, M>) -> Self::Output {
        // Note: `unwrap()` is safe as the integer is at most 128 bits.
        let i_bits = usize::try_from(I::BITS).unwrap();

        // Determine the variable mode.
        if self.is_constant() && rhs.is_constant() {
            // Note: Casting `rhs` to a `u32` is safe since `Magnitude`s can only be `u8`, `u16`, or `u32`.
            witness!(|self, rhs| console::Integer::new(self.wrapping_shl(rhs.to_u32().unwrap())))
        } else {
            // Retrieve the index for the first upper bit from the RHS that we mask.
            let first_upper_bit_index = I::BITS.trailing_zeros() as usize;

            // Perform the left shift operation by exponentiation and multiplication.
            // By masking the upper bits, we have that rhs < I::BITS.
            // Therefore, 2^{rhs} < Integer::MAX.

            // Zero-extend `rhs` by `8`.
            let mut bits_le = rhs.bits_le[..first_upper_bit_index].to_vec();
            bits_le.extend(core::iter::repeat_n(Boolean::constant(false), 8));

            // Use U8 for the exponent as it costs fewer constraints.
            let rhs_as_u8 = U8 { bits_le, phantom: Default::default() };

            if rhs_as_u8.is_constant() {
                // If the shift amount is a constant, then we can manually shift in bits and truncate the result.
                let shift_amount = rhs_as_u8.eject_value();
                let mut bits_le = vec![Boolean::constant(false); *shift_amount as usize];

                bits_le.extend_from_slice(&self.bits_le);
                bits_le.truncate(i_bits);

                Self { bits_le, phantom: Default::default() }
            } else if 2 * I::BITS < E::BaseField::size_in_data_bits() as u64 {
                // Calculate the result directly in the field.
                // Since 2^{rhs} < Integer::MAX and 2 * I::BITS is less than E::BaseField::size in data bits,
                // we know that the operation will not overflow Integer::MAX or the field modulus.
                let mut result = self.to_field();
                for (i, bit) in rhs.bits_le[..first_upper_bit_index].iter().enumerate() {
                    // In each iteration, multiple the result by 2^(1<<i), if the bit is set.
                    // Note that instantiating the field from a u128 is safe since it is larger than all eligible integer types.
                    let constant = Field::constant(console::Field::from_u128(2u128.pow(1 << i)));
                    let product = &result * &constant;
                    result = Field::ternary(bit, &product, &result);
                }
                // Extract the bits of the result, including the carry bits.
                let bits_le = result.to_lower_bits_le(2 * i_bits);
                // Initialize the integer, ignoring the carry bits.
                Self { bits_le: bits_le[..i_bits].to_vec(), phantom: Default::default() }
            } else {
                // Calculate the value of the shift directly in the field.
                // Since 2^{rhs} < Integer::MAX, we know that the operation will not overflow Integer::MAX or the field modulus.
                let two = Field::one() + Field::one();
                let mut shift_in_field = Field::one();
                for bit in rhs.bits_le[..first_upper_bit_index].iter().rev() {
                    shift_in_field = shift_in_field.square();
                    shift_in_field = Field::ternary(bit, &(&shift_in_field * &two), &shift_in_field);
                }
                let shift_as_multiplicand =
                    Self { bits_le: shift_in_field.to_lower_bits_le(i_bits), phantom: Default::default() };
                self.mul_wrapped(&shift_as_multiplicand)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    use core::{ops::RangeInclusive, panic::RefUnwindSafe};

    const ITERATIONS: u64 = 10;

    fn check_shl<I: IntegerType + RefUnwindSafe, M: Magnitude + RefUnwindSafe>(
        name: &str,
        first: console::Integer<<Circuit as Environment>::Network, I>,
        second: console::Integer<<Circuit as Environment>::Network, M>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let expected = first.wrapping_shl(second.to_u32().unwrap());
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::<Circuit, M>::new(mode_b, second);
        Circuit::scope(name, || {
            let candidate = a.shl_wrapped(&b);
            assert_eq!(expected, *candidate.eject_value());
            assert_eq!(console::Integer::new(expected), candidate.eject_value());
            assert_scope!();
        });
        Circuit::reset();
    }

    fn run_test<I: IntegerType + RefUnwindSafe, M: Magnitude + RefUnwindSafe>(mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let name = format!("Shl: {mode_a} << {mode_b} {i}");
            check_shl::<I, M>(&name, first, second, mode_a, mode_b);

            // Check that shift left by one is computed correctly.
            let name = format!("Double: {mode_a} << {mode_b} {i}");
            check_shl::<I, M>(&name, first, console::Integer::one(), mode_a, mode_b);

            // Check that shift left by two is computed correctly.
            let name = format!("Quadruple: {mode_a} << {mode_b} {i}");
            check_shl::<I, M>(&name, first, console::Integer::one() + console::Integer::one(), mode_a, mode_b);

            // Check that zero shifted left by `second` is computed correctly.
            let name = format!("Zero: {mode_a} << {mode_b} {i}");
            check_shl::<I, M>(&name, console::Integer::zero(), second, mode_a, mode_b);
        }
    }

    fn run_exhaustive_test<I: IntegerType + RefUnwindSafe, M: Magnitude + RefUnwindSafe>(mode_a: Mode, mode_b: Mode)
    where
        RangeInclusive<I>: Iterator<Item = I>,
        RangeInclusive<M>: Iterator<Item = M>,
    {
        for first in I::MIN..=I::MAX {
            for second in M::MIN..=M::MAX {
                let first = console::Integer::<_, I>::new(first);
                let second = console::Integer::<_, M>::new(second);

                let name = format!("Shl: ({first} << {second})");
                check_shl::<I, M>(&name, first, second, mode_a, mode_b);
            }
        }
    }

    test_integer_binary!(run_test, i8, u8, shl);
    test_integer_binary!(run_test, i8, u16, shl);
    test_integer_binary!(run_test, i8, u32, shl);

    test_integer_binary!(run_test, i16, u8, shl);
    test_integer_binary!(run_test, i16, u16, shl);
    test_integer_binary!(run_test, i16, u32, shl);

    test_integer_binary!(run_test, i32, u8, shl);
    test_integer_binary!(run_test, i32, u16, shl);
    test_integer_binary!(run_test, i32, u32, shl);

    test_integer_binary!(run_test, i64, u8, shl);
    test_integer_binary!(run_test, i64, u16, shl);
    test_integer_binary!(run_test, i64, u32, shl);

    test_integer_binary!(run_test, i128, u8, shl);
    test_integer_binary!(run_test, i128, u16, shl);
    test_integer_binary!(run_test, i128, u32, shl);

    test_integer_binary!(run_test, u8, u8, shl);
    test_integer_binary!(run_test, u8, u16, shl);
    test_integer_binary!(run_test, u8, u32, shl);

    test_integer_binary!(run_test, u16, u8, shl);
    test_integer_binary!(run_test, u16, u16, shl);
    test_integer_binary!(run_test, u16, u32, shl);

    test_integer_binary!(run_test, u32, u8, shl);
    test_integer_binary!(run_test, u32, u16, shl);
    test_integer_binary!(run_test, u32, u32, shl);

    test_integer_binary!(run_test, u64, u8, shl);
    test_integer_binary!(run_test, u64, u16, shl);
    test_integer_binary!(run_test, u64, u32, shl);

    test_integer_binary!(run_test, u128, u8, shl);
    test_integer_binary!(run_test, u128, u16, shl);
    test_integer_binary!(run_test, u128, u32, shl);

    test_integer_binary!(#[ignore], run_exhaustive_test, u8, u8, shl, exhaustive);
    test_integer_binary!(#[ignore], run_exhaustive_test, i8, u8, shl, exhaustive);
}
