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

impl<E: Environment, I: IntegerType, M: Magnitude> Shl<Integer<E, M>> for Integer<E, I> {
    type Output = Self;

    fn shl(self, rhs: Integer<E, M>) -> Self::Output {
        self << &rhs
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> Shl<Integer<E, M>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn shl(self, rhs: Integer<E, M>) -> Self::Output {
        self << &rhs
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> Shl<&Integer<E, M>> for Integer<E, I> {
    type Output = Self;

    fn shl(self, rhs: &Integer<E, M>) -> Self::Output {
        &self << rhs
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> Shl<&Integer<E, M>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn shl(self, rhs: &Integer<E, M>) -> Self::Output {
        let mut output = self.clone();
        output <<= rhs;
        output
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> ShlAssign<Integer<E, M>> for Integer<E, I> {
    fn shl_assign(&mut self, rhs: Integer<E, M>) {
        *self <<= &rhs
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> ShlAssign<&Integer<E, M>> for Integer<E, I> {
    fn shl_assign(&mut self, rhs: &Integer<E, M>) {
        // Stores the result of `self` << `other` in `self`.
        *self = self.shl_checked(rhs);
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> ShlChecked<Integer<E, M>> for Integer<E, I> {
    type Output = Self;

    #[inline]
    fn shl_checked(&self, rhs: &Integer<E, M>) -> Self::Output {
        // Retrieve the index for the first upper bit from the RHS that we mask.
        let first_upper_bit_index = I::BITS.trailing_zeros() as usize;
        // Initialize a constant `two`.
        let two = Self::one() + Self::one();
        match I::is_signed() {
            true => {
                if 3 * I::BITS < E::BaseField::size_in_data_bits() as u64 {
                    // Enforce that the upper bits of `rhs` are all zero.
                    Boolean::assert_bits_are_zero(&rhs.bits_le[first_upper_bit_index..]);

                    // Sign-extend `self` to 2 * I::BITS.
                    let mut bits_le = self.to_bits_le();
                    bits_le.resize(2 * I::BITS as usize, self.msb().clone());

                    // Calculate the result directly in the field.
                    // Since 2^{rhs} < Integer::MAX and 3 * I::BITS is less than E::BaseField::size in data bits,
                    // we know that the operation will not overflow the field modulus.
                    let mut result = Field::from_bits_le(&bits_le);
                    for (i, bit) in rhs.bits_le[..first_upper_bit_index].iter().enumerate() {
                        // In each iteration, multiple the result by 2^(1<<i), if the bit is set.
                        // Note that instantiating the field from a u128 is safe since it is larger than all eligible integer types.
                        let constant = Field::constant(console::Field::from_u128(2u128.pow(1 << i)));
                        let product = &result * &constant;
                        result = Field::ternary(bit, &product, &result);
                    }
                    // Extract the bits of the result, including the carry bits.
                    let bits_le = result.to_lower_bits_le(3 * I::BITS as usize);
                    // Split the bits into the lower and upper bits.
                    let (lower_bits_le, upper_bits_le) = bits_le.split_at(I::BITS as usize);
                    // Initialize the integer from the lower bits.
                    let result = Self { bits_le: lower_bits_le.to_vec(), phantom: Default::default() };
                    // Ensure that the sign of the first I::BITS upper bits match the sign of the result.
                    for bit in &upper_bits_le[..(I::BITS as usize)] {
                        E::assert_eq(bit, result.msb()).expect("Signed shift left overflow check failed");
                    }
                    // Return the result.
                    result
                } else {
                    // Compute 2 ^ `rhs` as unsigned integer of the size I::BITS.
                    // This is necessary to avoid a spurious overflow when `rhs` is I::BITS - 1.
                    // For example, 2i8 ^ 7i8 overflows, however -1i8 << 7i8 ==> -1i8 * 2i8 ^ 7i8 ==> -128i8, which is a valid i8 value.
                    let unsigned_two = two.cast_as_dual();
                    // Note that `pow_checked` is used to enforce that `rhs` < I::BITS.
                    let unsigned_factor = unsigned_two.pow_checked(rhs);
                    // For all values of `rhs` such that `rhs` < I::BITS,
                    //  - if `rhs` == I::BITS - 1, `signed_factor` == I::MIN,
                    //  - otherwise, `signed_factor` is the same as `unsigned_factor`.
                    let signed_factor = Self { bits_le: unsigned_factor.bits_le, phantom: Default::default() };

                    // If `signed_factor` is I::MIN, then negate `self` in order to balance the sign of I::MIN.
                    let signed_factor_is_min = &signed_factor.is_equal(&Self::constant(console::Integer::MIN));
                    let lhs = Self::ternary(signed_factor_is_min, &Self::zero().sub_wrapped(self), self);

                    // Compute `lhs` * `factor`, which is equivalent to `lhs` * 2 ^ `rhs`.
                    lhs.mul_checked(&signed_factor)
                }
            }
            false => {
                if 2 * I::BITS < E::BaseField::size_in_data_bits() as u64 {
                    // Enforce that the upper bits of `rhs` are all zero.
                    Boolean::assert_bits_are_zero(&rhs.bits_le[first_upper_bit_index..]);

                    // Calculate the result directly in the field.
                    // Since 2^{rhs} < Integer::MAX and 2 * I::BITS is less than E::BaseField::size in data bits,
                    // we know that the operation will not overflow Integer::MAX or the field modulus.
                    let mut result = self.to_field();
                    for (i, bit) in rhs.bits_le[..first_upper_bit_index].iter().enumerate() {
                        // In each iteration, multiply the result by 2^(1<<i), if the bit is set.
                        // Note that instantiating the field from a u128 is safe since it is larger than all eligible integer types.
                        let constant = Field::constant(console::Field::from_u128(2u128.pow(1 << i)));
                        let product = &result * &constant;
                        result = Field::ternary(bit, &product, &result);
                    }
                    // Extract the bits of the result, including the carry bits.
                    let bits_le = result.to_lower_bits_le(2 * I::BITS as usize);
                    // Split the bits into the lower and upper bits.
                    let (lower_bits_le, upper_bits_le) = bits_le.split_at(I::BITS as usize);
                    // Ensure that the carry bits are all zero.
                    Boolean::assert_bits_are_zero(upper_bits_le);
                    // Initialize the integer from the lower bits
                    Self { bits_le: lower_bits_le.to_vec(), phantom: Default::default() }
                } else {
                    // Compute `lhs` * 2 ^ `rhs`.
                    self.mul_checked(&two.pow_checked(rhs))
                }
            }
        }
    }
}

impl<E: Environment, I: IntegerType> Metrics<dyn Shl<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn count(case: &Self::Case) -> Count {
        <Self as Metrics<dyn DivChecked<Integer<E, I>, Output = Integer<E, I>>>>::count(case)
    }
}

impl<E: Environment, I: IntegerType> OutputMode<dyn Shl<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn output_mode(case: &Self::Case) -> Mode {
        <Self as OutputMode<dyn DivChecked<Integer<E, I>, Output = Integer<E, I>>>>::output_mode(case)
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> Metrics<dyn ShlChecked<Integer<E, M>, Output = Integer<E, I>>>
    for Integer<E, I>
{
    type Case = (Mode, Mode, bool, bool);

    #[rustfmt::skip]
    fn count(case: &Self::Case) -> Count {
        // A quick hack that matches `(u8 -> 0, u16 -> 1, u32 -> 2, u64 -> 3, u128 -> 4)`.
        let index = |num_bits: u64| match [8, 16, 32, 64, 128].iter().position(|&bits| bits == num_bits) {
            Some(index) => index as u64,
            None => E::halt(format!("Integer of {num_bits} bits is not supported")),
        };

        match (I::is_signed(), 3 * I::BITS < E::BaseField::size_in_data_bits() as u64, 2 * I::BITS < E::BaseField::size_in_data_bits() as u64) {
            (true, true, _) => match (case.0, case.1, case.2) {
                (Mode::Constant, Mode::Constant, _) => Count::is((6 * I::BITS) + index(I::BITS) + 3, 0, 0, 0),
                (Mode::Constant, _, true) => Count::is((6 * I::BITS) + index(I::BITS) + 3, 0, 0, 1),
                (Mode::Constant, _, false) => Count::is((3 * I::BITS) + index(I::BITS) + 3, 0, (3 * I::BITS) + index(I::BITS) + 2, (4 * I::BITS) + index(I::BITS) + 4),
                (_, Mode::Constant, _) => Count::is((3 * I::BITS) + index(I::BITS) + 3, 0, 3 * I::BITS, (4 * I::BITS) + 1),
                (_, _, _) => Count::is((3 * I::BITS) + index(I::BITS) + 3, 0, (3 * I::BITS) + index(I::BITS) + 3, (4 * I::BITS) + index(I::BITS) + 5),
            },
            (true, false, _) => match (case.0, case.1, case.2) {
                (Mode::Constant, Mode::Constant, _) => Count::is(8 * I::BITS, 0, 0, 0),
                (Mode::Constant, _, true) => Count::is(2051, 0, (520 * M::BITS) - 262, (525 * M::BITS) - 267),
                (Mode::Constant, _, false) => Count::less_than(1730, 0, (520 * M::BITS) + 579, (525 * M::BITS) + 581),
                (_, Mode::Constant, _) => Count::less_than(1280, 0, 966, 974),
                (_, _, _) => Count::is(1474, 0, (520 * M::BITS) + 836, (525 * M::BITS) + 839),
            },
            (false, _, true) => match (case.0, case.1, case.2) {
                (Mode::Constant, Mode::Constant, _) => Count::is((5 * I::BITS) + index(I::BITS) + 3, 0, 0, 0),
                (Mode::Constant, _, true) => Count::is((5 * I::BITS) + index(I::BITS) + 3, 0, 0, 1),
                (Mode::Constant, _, false) => Count::is((3 * I::BITS) + index(I::BITS) + 3, 0, (2 * I::BITS) + index(I::BITS) + 2, (2 * I::BITS) + index(I::BITS) + 5),
                (_, Mode::Constant, _) => Count::is((3 * I::BITS) + index(I::BITS) + 3, 0, 2 * I::BITS, (2 * I::BITS) + 2),
                (_, _, _) => Count::is((3 * I::BITS) + index(I::BITS) + 3, 0, (2 * I::BITS) + index(I::BITS) + 3, (2 * I::BITS) + index(I::BITS) + 6),
            },
            (false, _, false) => match (case.0, case.1, case.2) {
                (Mode::Constant, Mode::Constant, _) => Count::is(5 * I::BITS, 0, 0, 0),
                (Mode::Constant, _, true) => Count::is(1027, 0, (520 * M::BITS) - 521, (525 * M::BITS) - 527),
                (Mode::Constant, _, false) => Count::less_than(834, 0, (520 * M::BITS) - 328, (525 * M::BITS) - 331),
                (_, Mode::Constant, _) => Count::less_than(512, 0, 193, 196),
                (_, _, _) => Count::is(834, 0, (520 * M::BITS) - 325, (525 * M::BITS) - 328),
            },
        }
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> OutputMode<dyn ShlChecked<Integer<E, M>, Output = Integer<E, I>>>
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

    use test_utilities::*;

    use core::{ops::RangeInclusive, panic::RefUnwindSafe};

    const ITERATIONS: u64 = 10;

    fn check_shl<I: IntegerType + RefUnwindSafe, M: Magnitude + RefUnwindSafe + TryFrom<u64>>(
        name: &str,
        first: console::Integer<<Circuit as Environment>::Network, I>,
        second: console::Integer<<Circuit as Environment>::Network, M>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::<Circuit, M>::new(mode_b, second);
        let a_is_zero = a.is_zero().eject_value();
        let b_is_zero = b.is_zero().eject_value();

        match first.checked_shl(&second.to_u32().unwrap()) {
            Some(expected) => Circuit::scope(name, || {
                let candidate = a.shl_checked(&b);
                assert_eq!(expected, *candidate.eject_value());
                assert_eq!(console::Integer::new(expected), candidate.eject_value());
                assert_count!(ShlChecked(Integer<I>, Integer<M>) => Integer<I>, &(mode_a, mode_b, a_is_zero, b_is_zero));
                // assert_output_mode!(ShlChecked(Integer<I>, Integer<M>) => Integer<I>, &(mode_a, mode_b), candidate);
                assert!(Circuit::is_satisfied_in_scope(), "(is_satisfied_in_scope)");
            }),
            None => match (mode_a, mode_b) {
                (Mode::Constant, Mode::Constant) => check_operation_halts(&a, &b, Integer::shl_checked),
                (_, Mode::Constant) => {
                    // If `second` >= I::BITS, then the invocation to `pow_checked` will halt.
                    // Otherwise, the invocation to `mul_checked` will not be satisfied.
                    if *second >= M::try_from(I::BITS).unwrap_or_default() {
                        check_operation_halts(&a, &b, Integer::shl_checked);
                    } else {
                        Circuit::scope(name, || {
                            let _candidate = a.shl_checked(&b);
                            // assert_count_fails!(ShlChecked(Integer<I>, Integer<M>) => Integer<I>, &(mode_a, mode_b));
                            assert!(!Circuit::is_satisfied_in_scope(), "(!is_satisfied_in_scope)");
                        })
                    }
                }
                _ => Circuit::scope(name, || {
                    let _candidate = a.shl_checked(&b);
                    // assert_count_fails!(ShlChecked(Integer<I>, Integer<M>) => Integer<I>, &(mode_a, mode_b));
                    assert!(!Circuit::is_satisfied_in_scope(), "(!is_satisfied_in_scope)");
                }),
            },
        };
        Circuit::reset();
    }

    fn run_test<I: IntegerType + RefUnwindSafe, M: Magnitude + RefUnwindSafe + TryFrom<u64>>(
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let name = format!("Shl: {mode_a} << {mode_b} {i}");
            check_shl::<I, M>(&name, first, second, mode_a, mode_b);

            // Check that shift left by zero is computed correctly.
            let name = format!("Identity: {mode_a} << {mode_b} {i}");
            check_shl::<I, M>(&name, first, console::Integer::zero(), mode_a, mode_b);

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

    fn run_exhaustive_test<I: IntegerType + RefUnwindSafe, M: Magnitude + RefUnwindSafe + TryFrom<u64>>(
        mode_a: Mode,
        mode_b: Mode,
    ) where
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
