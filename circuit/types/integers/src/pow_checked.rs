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

impl<E: Environment, I: IntegerType, M: Magnitude> Pow<Integer<E, M>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `power` of `self` to the power of `other`.
    #[inline]
    fn pow(self, other: Integer<E, M>) -> Self::Output {
        self.pow_checked(&other)
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> Pow<&Integer<E, M>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns the `power` of `self` to the power of `other`.
    #[inline]
    fn pow(self, other: &Integer<E, M>) -> Self::Output {
        self.pow_checked(other)
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> PowChecked<Integer<E, M>> for Integer<E, I> {
    type Output = Self;

    /// Returns the `power` of `self` to the power of `other`.
    #[inline]
    fn pow_checked(&self, other: &Integer<E, M>) -> Self::Output {
        // Determine the variable mode.
        if self.is_constant() && other.is_constant() {
            // Compute the result and return the new constant.
            // This cast is safe since `Magnitude`s can only be `u8`, `u16`, or `u32`.
            match self.eject_value().checked_pow(&other.eject_value().to_u32().unwrap()) {
                Some(value) => Integer::new(Mode::Constant, console::Integer::new(value)),
                None => E::halt("Integer overflow on exponentiation of two constants"),
            }
        } else {
            let mut result = Self::one();

            for bit in other.bits_le.iter().rev() {
                result = result.mul_checked(&result);

                let result_times_self = if I::is_signed() {
                    // Multiply the absolute value of `self` and `other` in the base field.
                    // Note: it is safe to use `abs_wrapped` since we want `Integer::MIN` to be interpreted as an unsigned number.
                    let (product, overflow) = Self::mul_with_flags(&(&result).abs_wrapped(), &self.abs_wrapped());

                    // If the product should be positive, then it cannot exceed the signed maximum.
                    let operands_same_sign = &result.msb().is_equal(self.msb());
                    let positive_product_overflows = operands_same_sign & product.msb();

                    // If the product should be negative, then it cannot exceed the absolute value of the signed minimum.
                    let negative_product_underflows = {
                        let lower_product_bits_nonzero = product.bits_le[..(I::BITS as usize - 1)]
                            .iter()
                            .fold(Boolean::constant(false), |a, b| a | b);
                        let negative_product_lt_or_eq_signed_min =
                            !product.msb() | (product.msb() & !lower_product_bits_nonzero);
                        !operands_same_sign & !negative_product_lt_or_eq_signed_min
                    };

                    let overflow = overflow | positive_product_overflows | negative_product_underflows;
                    E::assert_eq(overflow & bit, E::zero()).expect("Integer power overflow check failed");

                    // Return the product of `self` and `other` with the appropriate sign.
                    Self::ternary(operands_same_sign, &product, &(!&product).add_wrapped(&Self::one()))
                } else {
                    let (product, overflow) = Self::mul_with_flags(&result, self);

                    // For unsigned multiplication, check that the overflow flag is not set.
                    E::assert_eq(overflow & bit, E::zero()).expect("Integer power overflow check failed");

                    // Return the product of `self` and `other`.
                    product
                };

                result = Self::ternary(bit, &result_times_self, &result);
            }
            result
        }
    }
}

impl<E: Environment, I: IntegerType> Integer<E, I> {
    /// Multiply the integer bits of `this` and `that`, returning a flag indicating whether the product overflowed.
    /// This method assumes that the `this` and `that` are both positive.
    ///
    /// For integer types below 128 bits, the flag is only constrained to indicate that
    /// the witnessed product differs from the product computed in the base field: a
    /// prover may witness any product, setting the flag even when the true product does
    /// not overflow. This is safe in the only caller, `pow_checked`, which asserts that
    /// the flag is unset exactly on the iterations whose product is selected, so a
    /// lying flag forces the witnessed product to equal the true product wherever the
    /// product is used.
    #[inline]
    fn mul_with_flags(this: &Integer<E, I>, that: &Integer<E, I>) -> (Integer<E, I>, Boolean<E>) {
        // Case 1 - 2 integers fit in 1 field element (u8, u16, u32, u64, i8, i16, i32, i64).
        if 2 * I::BITS < (E::BaseField::size_in_bits() - 1) as u64 {
            // Instead of multiplying the bits of `self` and `other`, witness the integer product.
            let product: Integer<E, I> = witness!(|this, that| this.mul_wrapped(&that));

            // Check that the computed product is not equal to witnessed product, in the base field.
            // Note: The multiplication is safe as the field twice as large as the maximum integer type supported.
            let computed_product = this.to_field() * that.to_field();
            let witnessed_product = product.to_field();
            let flag = computed_product.is_not_equal(&witnessed_product);

            // Return the product of `self` and `other` and the overflow flag.
            (product, flag)
        }
        // Case 2 - 1.5 integers fit in 1 field element (u128, i128).
        else if (I::BITS + I::BITS / 2) < (E::BaseField::size_in_bits() - 1) as u64 {
            // Use Karatsuba multiplication to compute the product of `self` and `other` and the carry bits.
            let (product, z_1_upper_bits, z2) = Self::karatsuba_multiply(this, that);
            // Reconstruct the upper bits of z_1 in the field.
            let z_1_upper_field = Field::from_bits_le(&z_1_upper_bits);
            // Compute whether the sum of z_1_field and z_2 is zero.
            let z_1_upper_field_plus_z_2 = &z_1_upper_field + &z2;
            let flag = z_1_upper_field_plus_z_2.is_not_equal(&Field::zero());

            // Return the product of `self` and `other` and the overflow flag.
            (product, flag)
        } else {
            E::halt(format!("Multiplication of integers of size {} is not supported", I::BITS))
        }
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> Metrics<dyn PowChecked<Integer<E, M>, Output = Integer<E, I>>>
    for Integer<E, I>
{
    type Case = (Mode, Mode, bool, bool);

    fn count(case: &Self::Case) -> Count {
        match (case.0, case.1) {
            (Mode::Constant, Mode::Constant) => Count::is(I::BITS, 0, 0, 0),
            (Mode::Constant, _) | (_, Mode::Constant) => {
                let mul_count = count!(Integer<E, I>, MulWrapped<Integer<E, I>, Output=Integer<E, I>>, case);
                (2 * M::BITS * mul_count) + Count::is(2 * I::BITS, 0, I::BITS, I::BITS)
            }
            (_, _) => {
                let mul_count = count!(Integer<E, I>, MulWrapped<Integer<E, I>, Output=Integer<E, I>>, case);
                (2 * M::BITS * mul_count) + Count::is(2 * I::BITS, 0, I::BITS, I::BITS)
            }
        }
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> OutputMode<dyn PowChecked<Integer<E, M>, Output = Integer<E, I>>>
    for Integer<E, I>
{
    type Case = (Mode, CircuitType<Integer<E, M>>);

    fn output_mode(case: &Self::Case) -> Mode {
        match (case.0, (case.1.mode(), &case.1)) {
            (Mode::Constant, (Mode::Constant, _)) => Mode::Constant,
            (Mode::Constant, (mode, _)) => match mode {
                Mode::Constant => Mode::Constant,
                _ => Mode::Private,
            },
            (_, (Mode::Constant, case)) => match case {
                // Determine if the constant is all zeros.
                CircuitType::Constant(constant) => match constant.eject_value().is_zero() {
                    true => Mode::Constant,
                    false => Mode::Private,
                },
                _ => E::halt("The constant is required for the output mode of `pow_wrapped` with a constant."),
            },
            (_, _) => Mode::Private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utilities::*;
    use snarkvm_circuit_environment::Circuit;

    use std::{ops::RangeInclusive, panic::RefUnwindSafe};

    // Lowered to 4; we run (~5 * ITERATIONS) cases for most tests.
    const ITERATIONS: u64 = 4;

    fn check_pow<I: IntegerType + RefUnwindSafe, M: Magnitude + RefUnwindSafe>(
        name: &str,
        first: console::Integer<<Circuit as Environment>::Network, I>,
        second: console::Integer<<Circuit as Environment>::Network, M>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::<Circuit, M>::new(mode_b, second);
        match first.checked_pow(&second.to_u32().unwrap()) {
            Some(expected) => Circuit::scope(name, || {
                let candidate = a.pow_checked(&b);
                assert_eq!(expected, *candidate.eject_value());
                assert_eq!(console::Integer::new(expected), candidate.eject_value());
                // assert_count!(PowChecked(Integer<I>, Integer<M>) => Integer<I>, &(mode_a, mode_b));
                // assert_output_mode!(PowChecked(Integer<I>, Integer<M>) => Integer<I>, &(mode_a, CircuitType::from(&b)), candidate);
                assert!(Circuit::is_satisfied_in_scope(), "(is_satisfied_in_scope)");
            }),
            None => {
                match (mode_a, mode_b) {
                    (Mode::Constant, Mode::Constant) => check_operation_halts(&a, &b, Integer::pow_checked),
                    _ => Circuit::scope(name, || {
                        let _candidate = a.pow_checked(&b);
                        // assert_count_fails!(PowChecked(Integer<I>, Integer<M>) => Integer<I>, &(mode_a, mode_b));A
                        assert!(!Circuit::is_satisfied_in_scope(), "(!is_satisfied_in_scope)");
                    }),
                }
            }
        }
        Circuit::reset();
    }

    fn run_test<I: IntegerType + RefUnwindSafe, M: Magnitude + RefUnwindSafe>(mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let name = format!("Pow: {mode_a} ** {mode_b} {i}");
            check_pow::<I, M>(&name, first, second, mode_a, mode_b);

            let name = format!("Pow Zero: {mode_a} ** {mode_b} {i}");
            check_pow::<I, M>(&name, first, console::Integer::zero(), mode_a, mode_b);

            let name = format!("Pow One: {mode_a} ** {mode_b} {i}");
            check_pow::<I, M>(&name, first, console::Integer::one(), mode_a, mode_b);

            // Check that the square is computed correctly.
            let name = format!("Square: {mode_a} ** {mode_b} {i}");
            check_pow::<I, M>(&name, first, console::Integer::one() + console::Integer::one(), mode_a, mode_b);

            // Check that the cube is computed correctly.
            let name = format!("Cube: {mode_a} ** {mode_b} {i}");
            check_pow::<I, M>(
                &name,
                first,
                console::Integer::one() + console::Integer::one() + console::Integer::one(),
                mode_a,
                mode_b,
            );
        }

        // Test corner cases for exponentiation.
        check_pow::<I, M>("MAX ** MAX", console::Integer::MAX, console::Integer::MAX, mode_a, mode_b);
        check_pow::<I, M>("MIN ** 0", console::Integer::MIN, console::Integer::zero(), mode_a, mode_b);
        check_pow::<I, M>("MAX ** 0", console::Integer::MAX, console::Integer::zero(), mode_a, mode_b);
        check_pow::<I, M>("MIN ** 1", console::Integer::MIN, console::Integer::one(), mode_a, mode_b);
        check_pow::<I, M>("MAX ** 1", console::Integer::MAX, console::Integer::one(), mode_a, mode_b);
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

                let name = format!("Pow: ({first} ** {second})");
                check_pow::<I, M>(&name, first, second, mode_a, mode_b);
            }
        }
    }

    test_integer_binary!(run_test, i8, u8, pow);
    test_integer_binary!(run_test, i8, u16, pow);
    test_integer_binary!(run_test, i8, u32, pow);

    test_integer_binary!(run_test, i16, u8, pow);
    test_integer_binary!(run_test, i16, u16, pow);
    test_integer_binary!(run_test, i16, u32, pow);

    test_integer_binary!(run_test, i32, u8, pow);
    test_integer_binary!(run_test, i32, u16, pow);
    test_integer_binary!(run_test, i32, u32, pow);

    test_integer_binary!(run_test, i64, u8, pow);
    test_integer_binary!(run_test, i64, u16, pow);
    test_integer_binary!(run_test, i64, u32, pow);

    test_integer_binary!(run_test, i128, u8, pow);
    test_integer_binary!(run_test, i128, u16, pow);
    test_integer_binary!(run_test, i128, u32, pow);

    test_integer_binary!(run_test, u8, u8, pow);
    test_integer_binary!(run_test, u8, u16, pow);
    test_integer_binary!(run_test, u8, u32, pow);

    test_integer_binary!(run_test, u16, u8, pow);
    test_integer_binary!(run_test, u16, u16, pow);
    test_integer_binary!(run_test, u16, u32, pow);

    test_integer_binary!(run_test, u32, u8, pow);
    test_integer_binary!(run_test, u32, u16, pow);
    test_integer_binary!(run_test, u32, u32, pow);

    test_integer_binary!(run_test, u64, u8, pow);
    test_integer_binary!(run_test, u64, u16, pow);
    test_integer_binary!(run_test, u64, u32, pow);

    test_integer_binary!(run_test, u128, u8, pow);
    test_integer_binary!(run_test, u128, u16, pow);
    test_integer_binary!(run_test, u128, u32, pow);

    test_integer_binary!(#[ignore], run_exhaustive_test, u8, u8, pow, exhaustive);
    test_integer_binary!(#[ignore], run_exhaustive_test, i8, u8, pow, exhaustive);
}
