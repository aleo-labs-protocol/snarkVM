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

impl<E: Environment, I: IntegerType, M: Magnitude> ShrWrapped<Integer<E, M>> for Integer<E, I> {
    type Output = Self;

    #[inline]
    fn shr_wrapped(&self, rhs: &Integer<E, M>) -> Self::Output {
        // Determine the variable mode.
        if self.is_constant() && rhs.is_constant() {
            // Note: Casting `rhs` to `u32` is safe since `Magnitude`s can only be `u8`, `u16`, or `u32`.
            witness!(|self, rhs| console::Integer::new(self.wrapping_shr(rhs.to_u32().unwrap())))
        } else {
            // Retrieve the index for the first upper bit from the RHS that we mask.
            let first_upper_bit_index = I::BITS.trailing_zeros() as usize;

            // Perform the right shift operation by exponentiation and multiplication.
            // By masking the upper bits, we have that rhs < I::BITS.
            // Therefore, 2^{rhs} < Integer::MAX.
            let mut lower_rhs_bits = Vec::with_capacity(8);
            lower_rhs_bits.extend_from_slice(&rhs.bits_le[..first_upper_bit_index]);
            lower_rhs_bits.resize(8, Boolean::constant(false));

            // Use U8 for the exponent as it costs fewer constraints.
            let rhs_as_u8 = U8 { bits_le: lower_rhs_bits, phantom: Default::default() };

            if rhs_as_u8.is_constant() {
                // If the shift amount is a constant, then we can manually shift in bits and truncate the result.
                let shift_amount = *rhs_as_u8.eject_value() as usize;

                let mut bits_le = Vec::with_capacity(I::BITS as usize + shift_amount);
                bits_le.extend_from_slice(&self.bits_le);

                match I::is_signed() {
                    // Sign-extend `self` by `shift_amount`.
                    true => bits_le.extend(core::iter::repeat_n(self.msb().clone(), shift_amount)),
                    // Zero-extend `self` by `shift_amount`.
                    false => bits_le.extend(core::iter::repeat_n(Boolean::constant(false), shift_amount)),
                };

                bits_le.reverse();
                bits_le.truncate(I::BITS as usize);
                bits_le.reverse();

                Self { bits_le, phantom: Default::default() }
            } else if 2 * I::BITS < E::BaseField::size_in_data_bits() as u64 {
                if I::is_signed() {
                    // Initialize the msb of `self` as a field element.
                    let msb_field = Field::from((**self.msb()).clone());

                    // The signed right-shift is implemented as an unsigned right-shift followed by a sign-extension.
                    // Initialize the result from the reversed bits of `self`.
                    let mut result = Field::from_bits_be(&self.bits_le);

                    // Calculate the result directly in the field.
                    // Since 2^{rhs} < Integer::MAX and 2 * I::BITS is less than E::BaseField::size in data bits,
                    // we know that the operation will not overflow the field modulus.
                    for (i, bit) in rhs.bits_le[..first_upper_bit_index].iter().enumerate() {
                        // In each iteration, multiply the result by 2^(1<<i), if the bit is set.
                        // Note that instantiating the field from a u128 is safe since it is larger than all eligible integer types.
                        let constant = Field::constant(console::Field::from_u128(2u128.pow(1 << i)));
                        let product = &result * &constant;

                        // If `self` is negative, mask the value with 2^{1<<i} - 1.
                        // For example, in the first, second, and third iterations, the mask is 0b1, 0b11, and 0b111, respectively.
                        // This serves to appropriately sign-extend the result.
                        let mask = Field::constant(console::Field::from_u128(2u128.pow(1 << i) - 1));
                        let masked = product.add(mask * &msb_field);

                        result = Field::ternary(bit, &masked, &result);
                    }
                    // Extract the bits of the result, including the carry bits.
                    let mut bits_le = result.to_lower_bits_le(2 * I::BITS as usize)[..I::BITS as usize].to_vec();
                    // Reverse the bits.
                    bits_le.reverse();
                    // Initialize the integer, ignoring the carry bits.
                    Self { bits_le, phantom: Default::default() }
                } else {
                    // The unsigned right-shift is implemented as a left-shift over the reversed bits of `self`.
                    // Initialize the result from the reversed bits of `self`.
                    let mut result = Field::from_bits_be(&self.bits_le);
                    // Calculate the result directly in the field.
                    // Since 2^{rhs} < Integer::MAX and 2 * I::BITS is less than E::BaseField::size in data bits,
                    // we know that the operation will not overflow the field modulus.
                    for (i, bit) in rhs.bits_le[..first_upper_bit_index].iter().enumerate() {
                        // In each iteration, multiply the result by 2^(1<<i), if the bit is set.
                        // Note that instantiating the field from a u128 is safe since it is larger than all eligible integer types.
                        let constant = Field::constant(console::Field::from_u128(2u128.pow(1 << i)));
                        let product = &result * &constant;
                        result = Field::ternary(bit, &product, &result);
                    }
                    // Extract the bits of the result, including the carry bits.
                    let mut bits_le = result.to_lower_bits_le(2 * I::BITS as usize)[..I::BITS as usize].to_vec();
                    // Reverse the bits.
                    bits_le.reverse();
                    // Initialize the integer, ignoring the carry bits.
                    Self { bits_le, phantom: Default::default() }
                }
            } else {
                // Calculate the value of the shift directly in the field.
                // Since 2^{rhs} < Integer::MAX, we know that the operation will not overflow Integer::MAX or the field modulus.
                let two = Field::one() + Field::one();
                // Note that `shift_in_field` is always greater than zero and does not wrap around the field modulus.
                let mut shift_in_field = Field::one();
                for bit in rhs.bits_le[..first_upper_bit_index].iter().rev() {
                    shift_in_field = shift_in_field.square();
                    shift_in_field = Field::ternary(bit, &(&shift_in_field * &two), &shift_in_field);
                }

                let shift_as_divisor =
                    Self { bits_le: shift_in_field.to_lower_bits_le(I::BITS as usize), phantom: Default::default() };

                if I::is_signed() {
                    // Divide the absolute value of `self` and `shift` (as a divisor) in the base field.
                    let unsigned_divided = self.abs_wrapped().cast_as_dual();
                    // Note that `unsigned_divisor` is greater than zero since `shift_in_field` is greater than zero.
                    let unsigned_divisor = shift_as_divisor.cast_as_dual();

                    // Compute the quotient and remainder using wrapped, unsigned division.
                    // Note that we do not invoke `div_wrapped` since we need the quotient AND the remainder.
                    let (unsigned_quotient, unsigned_remainder) =
                        unsigned_divided.unsigned_division_via_witness(&unsigned_divisor);

                    // Note that quotient <= |console::Integer::MIN|, since the dividend <= |console::Integer::MIN| and 0 <= quotient <= dividend.
                    let quotient = Self { bits_le: unsigned_quotient.bits_le, phantom: Default::default() };
                    let negated_quotient = &(!&quotient).add_wrapped(&Self::one());

                    // Arithmetic shift uses a different rounding mode than division.
                    let rounded_negated_quotient = Self::ternary(
                        &unsigned_remainder.to_field().is_equal(&Field::zero()),
                        negated_quotient,
                        &(negated_quotient).sub_wrapped(&Self::one()),
                    );

                    Self::ternary(self.msb(), &rounded_negated_quotient, &quotient)
                } else {
                    self.div_wrapped(&shift_as_divisor)
                }
            }
        }
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> Metrics<dyn ShrWrapped<Integer<E, M>, Output = Integer<E, I>>>
    for Integer<E, I>
{
    type Case = (Mode, Mode);

    #[rustfmt::skip]
    fn count(case: &Self::Case) -> Count {
        // A quick hack that matches `(u8 -> 0, u16 -> 1, u32 -> 2, u64 -> 3, u128 -> 4)`.
        let index = |num_bits: u64| match [8, 16, 32, 64, 128].iter().position(|&bits| bits == num_bits) {
            Some(index) => index as u64,
            None => E::halt(format!("Integer of {num_bits} bits is not supported")),
        };

        match (case.0, case.1) {
            (Mode::Constant, Mode::Constant) => Count::is(I::BITS, 0, 0, 0),
            (_, Mode::Constant) => Count::is(0, 0, 0, 0),
            (Mode::Constant, _) => {
                match (I::is_signed(), 2 * I::BITS < E::BaseField::size_in_data_bits() as u64) {
                    (true, true) => Count::less_than((2 * I::BITS) + index(I::BITS) + 6, 0, (2 * I::BITS) + index(I::BITS) + 3, (2 * I::BITS) + index(I::BITS) + 4),
                    (true, false) => Count::less_than(5 * I::BITS, 0, 1622, 1633),
                    (false, true) => Count::less_than((2 * I::BITS) + index(I::BITS) + 3, 0, (2 * I::BITS) + index(I::BITS) + 3, (2 * I::BITS) + index(I::BITS) + 4),
                    (false, false) => Count::less_than(I::BITS, 0, 849, 857),
                }
            }
            (_, _) => match (I::is_signed(), 2 * I::BITS < E::BaseField::size_in_data_bits() as u64) {
                (true, true) => Count::is(6 + 2 * index(I::BITS), 0, (2 * I::BITS) + index(I::BITS) + 3, (2 * I::BITS) + index(I::BITS) + 4),
                (true, false) => Count::is(4 * I::BITS, 0, 1622, 1633),
                (false, true) => Count::is(3 + index(I::BITS), 0, (2 * I::BITS) + index(I::BITS) + 3, (2 * I::BITS) + index(I::BITS) + 4),
                (false, false) => Count::is(I::BITS, 0, 849, 857),
            },
        }
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> OutputMode<dyn ShrWrapped<Integer<E, M>, Output = Integer<E, I>>>
    for Integer<E, I>
{
    type Case = (Mode, Mode);

    fn output_mode(case: &Self::Case) -> Mode {
        match (case.0, case.1) {
            (Mode::Constant, Mode::Constant) => Mode::Constant,
            (mode_a, Mode::Constant) => mode_a,
            (_, _) => Mode::Private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    use core::{ops::RangeInclusive, panic::RefUnwindSafe};

    const ITERATIONS: u64 = 10;

    fn check_shr<I: IntegerType + RefUnwindSafe, M: Magnitude + RefUnwindSafe>(
        name: &str,
        first: console::Integer<<Circuit as Environment>::Network, I>,
        second: console::Integer<<Circuit as Environment>::Network, M>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let expected = first.wrapping_shr(second.to_u32().unwrap());
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::<Circuit, M>::new(mode_b, second);
        Circuit::scope(name, || {
            let candidate = a.shr_wrapped(&b);
            assert_eq!(expected, *candidate.eject_value());
            assert_eq!(console::Integer::new(expected), candidate.eject_value());
            assert_count!(ShrWrapped(Integer<I>, Integer<M>) => Integer<I>, &(mode_a, mode_b));
            // assert_output_mode!(ShrWrapped(Integer<I>, Integer<M>) => Integer<I>, &(mode_a, mode_b), candidate);
        });
        Circuit::reset();
    }

    fn run_test<I: IntegerType + RefUnwindSafe, M: Magnitude + RefUnwindSafe>(mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let name = format!("Shr: {mode_a} >> {mode_b} {i}");
            check_shr::<I, M>(&name, first, second, mode_a, mode_b);

            // Check that shift right by one is computed correctly.
            let name = format!("Half: {mode_a} >> {mode_b} {i}");
            check_shr::<I, M>(&name, first, console::Integer::one(), mode_a, mode_b);
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

                let name = format!("Shr: ({first} >> {second})");
                check_shr::<I, M>(&name, first, second, mode_a, mode_b);
            }
        }
    }

    test_integer_binary!(run_test, i8, u8, shr);
    test_integer_binary!(run_test, i8, u16, shr);
    test_integer_binary!(run_test, i8, u32, shr);

    test_integer_binary!(run_test, i16, u8, shr);
    test_integer_binary!(run_test, i16, u16, shr);
    test_integer_binary!(run_test, i16, u32, shr);

    test_integer_binary!(run_test, i32, u8, shr);
    test_integer_binary!(run_test, i32, u16, shr);
    test_integer_binary!(run_test, i32, u32, shr);

    test_integer_binary!(run_test, i64, u8, shr);
    test_integer_binary!(run_test, i64, u16, shr);
    test_integer_binary!(run_test, i64, u32, shr);

    test_integer_binary!(run_test, i128, u8, shr);
    test_integer_binary!(run_test, i128, u16, shr);
    test_integer_binary!(run_test, i128, u32, shr);

    test_integer_binary!(run_test, u8, u8, shr);
    test_integer_binary!(run_test, u8, u16, shr);
    test_integer_binary!(run_test, u8, u32, shr);

    test_integer_binary!(run_test, u16, u8, shr);
    test_integer_binary!(run_test, u16, u16, shr);
    test_integer_binary!(run_test, u16, u32, shr);

    test_integer_binary!(run_test, u32, u8, shr);
    test_integer_binary!(run_test, u32, u16, shr);
    test_integer_binary!(run_test, u32, u32, shr);

    test_integer_binary!(run_test, u64, u8, shr);
    test_integer_binary!(run_test, u64, u16, shr);
    test_integer_binary!(run_test, u64, u32, shr);

    test_integer_binary!(run_test, u128, u8, shr);
    test_integer_binary!(run_test, u128, u16, shr);
    test_integer_binary!(run_test, u128, u32, shr);

    test_integer_binary!(#[ignore], run_exhaustive_test, u8, u8, shr, exhaustive);
    test_integer_binary!(#[ignore], run_exhaustive_test, i8, u8, shr, exhaustive);
}
