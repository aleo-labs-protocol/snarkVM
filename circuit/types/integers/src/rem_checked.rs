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

impl<E: Environment, I: IntegerType> Rem<Integer<E, I>> for Integer<E, I> {
    type Output = Self;

    fn rem(self, other: Self) -> Self::Output {
        self % &other
    }
}

impl<E: Environment, I: IntegerType> Rem<Integer<E, I>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn rem(self, other: Integer<E, I>) -> Self::Output {
        self % &other
    }
}

impl<E: Environment, I: IntegerType> Rem<&Integer<E, I>> for Integer<E, I> {
    type Output = Self;

    fn rem(self, other: &Self) -> Self::Output {
        &self % other
    }
}

impl<E: Environment, I: IntegerType> Rem<&Integer<E, I>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn rem(self, other: &Integer<E, I>) -> Self::Output {
        let mut output = self.clone();
        output %= other;
        output
    }
}

impl<E: Environment, I: IntegerType> RemAssign<Integer<E, I>> for Integer<E, I> {
    fn rem_assign(&mut self, other: Integer<E, I>) {
        *self %= &other;
    }
}

impl<E: Environment, I: IntegerType> RemAssign<&Integer<E, I>> for Integer<E, I> {
    fn rem_assign(&mut self, other: &Integer<E, I>) {
        // Stores the remainder of `self` divided by `other` in `self`.
        *self = self.rem_checked(other);
    }
}

impl<E: Environment, I: IntegerType> RemChecked<Self> for Integer<E, I> {
    type Output = Self;

    #[inline]
    fn rem_checked(&self, other: &Integer<E, I>) -> Self::Output {
        match (self.is_constant(), other.is_constant()) {
            // If `other` is a constant and is zero, then halt.
            (_, true) if other.eject_value().is_zero() => E::halt("Attempted to divide by zero."),
            // If `self` and `other` are constants, and other is not zero, then directly return the remainder.
            (true, true) => match self.eject_value().checked_rem(&other.eject_value()) {
                None => E::halt("Overflow on division of two integer constants"),
                Some(value) => Integer::constant(console::Integer::new(value)),
            },
            // Handle the remaining cases.
            // Note that `other` is either a constant and non-zero, or not a constant.
            _ => {
                if I::is_signed() {
                    // Ensure that overflow cannot occur when computing the associated division operations.
                    // Signed integer division overflows when the dividend is Integer::MIN and the divisor is -1.
                    let min = Integer::constant(console::Integer::MIN);
                    let neg_one = Integer::constant(-console::Integer::one());
                    let overflows = self.is_equal(&min) & other.is_equal(&neg_one);
                    E::assert(!overflows).expect("Signed integer remainder overflow check failed");

                    // Divide the absolute value of `self` and `other` in the base field.
                    let unsigned_dividend = self.abs_wrapped().cast_as_dual();
                    // Note that `unsigned_divisor` is zero iff `other` is zero.
                    let unsigned_divisor = other.abs_wrapped().cast_as_dual();
                    // Note that this call to `rem_wrapped` checks that `unsigned_divisor` is not zero.
                    let unsigned_remainder = unsigned_dividend.rem_wrapped(&unsigned_divisor);

                    let signed_remainder = Self { bits_le: unsigned_remainder.bits_le, phantom: Default::default() };

                    // The remainder takes on the same sign as `self` because the division operation rounds towards zero.
                    Self::ternary(&!self.msb(), &signed_remainder, &Self::zero().sub_wrapped(&signed_remainder))
                } else {
                    // Return the remainder of `self` and `other`.
                    // Note that this call to `rem_wrapped` checks that `unsigned_divisor` is not zero.
                    self.rem_wrapped(other)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    use test_utilities::*;

    use std::{ops::RangeInclusive, panic::RefUnwindSafe};

    const ITERATIONS: u64 = 10;

    fn check_rem<I: IntegerType + RefUnwindSafe>(
        name: &str,
        first: console::Integer<<Circuit as Environment>::Network, I>,
        second: console::Integer<<Circuit as Environment>::Network, I>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::<Circuit, I>::new(mode_b, second);
        if second == console::Integer::zero() {
            match mode_b {
                Mode::Constant => check_operation_halts(&a, &b, Integer::rem_checked),
                _ => Circuit::scope(name, || {
                    let _candidate = a.rem_checked(&b);
                    assert!(!Circuit::is_satisfied_in_scope(), "(!is_satisfied_in_scope)");
                }),
            }
        } else {
            match first.checked_rem(&second) {
                Some(expected) => Circuit::scope(name, || {
                    let candidate = a.rem_checked(&b);
                    assert_eq!(expected, *candidate.eject_value());
                    assert_eq!(console::Integer::new(expected), candidate.eject_value());
                    assert!(Circuit::is_satisfied_in_scope(), "(is_satisfied_in_scope)");
                }),
                None => match (mode_a, mode_b) {
                    (Mode::Constant, Mode::Constant) => check_operation_halts(&a, &b, Integer::rem_checked),
                    _ => Circuit::scope(name, || {
                        let _candidate = a.rem_checked(&b);
                        assert!(!Circuit::is_satisfied_in_scope(), "(!is_satisfied_in_scope)");
                    }),
                },
            }
        }
        Circuit::reset();
    }

    fn run_test<I: IntegerType + RefUnwindSafe>(mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let name = format!("Rem: {first} % {second}");
            check_rem::<I>(&name, first, second, mode_a, mode_b);

            let name = format!("Rem by One: {first} % 1");
            check_rem::<I>(&name, first, console::Integer::one(), mode_a, mode_b);

            let name = format!("Rem by Self: {first} % {first}");
            check_rem::<I>(&name, first, first, mode_a, mode_b);

            let name = format!("Rem by Zero: {first} % 0");
            check_rem::<I>(&name, first, console::Integer::zero(), mode_a, mode_b);
        }

        // Check standard properties and corner cases.
        check_rem::<I>("MAX % 1", console::Integer::MAX, console::Integer::one(), mode_a, mode_b);
        check_rem::<I>("MIN % 1", console::Integer::MIN, console::Integer::one(), mode_a, mode_b);
        check_rem::<I>("1 % 1", console::Integer::one(), console::Integer::one(), mode_a, mode_b);
        check_rem::<I>("0 % 1", console::Integer::zero(), console::Integer::one(), mode_a, mode_b);
        check_rem::<I>("MAX % 0", console::Integer::MAX, console::Integer::zero(), mode_a, mode_b);
        check_rem::<I>("MIN % 0", console::Integer::MIN, console::Integer::zero(), mode_a, mode_b);
        check_rem::<I>("1 % 0", console::Integer::one(), console::Integer::zero(), mode_a, mode_b);
        check_rem::<I>("0 % 0", console::Integer::zero(), console::Integer::zero(), mode_a, mode_b);

        // Check some additional corner cases for signed integers.
        if I::is_signed() {
            check_rem::<I>("MAX % -1", console::Integer::MAX, -console::Integer::one(), mode_a, mode_b);
            check_rem::<I>("MIN % -1", console::Integer::MIN, -console::Integer::one(), mode_a, mode_b);
            check_rem::<I>("1 % -1", console::Integer::one(), -console::Integer::one(), mode_a, mode_b);
        }
    }

    fn run_exhaustive_test<I: IntegerType + RefUnwindSafe>(mode_a: Mode, mode_b: Mode)
    where
        RangeInclusive<I>: Iterator<Item = I>,
    {
        for first in I::MIN..=I::MAX {
            for second in I::MIN..=I::MAX {
                let first = console::Integer::<_, I>::new(first);
                let second = console::Integer::<_, I>::new(second);

                let name = format!("Rem: ({first} % {second})");
                check_rem::<I>(&name, first, second, mode_a, mode_b);
            }
        }
    }

    test_integer_binary!(run_test, i8, rem);
    test_integer_binary!(run_test, i16, rem);
    test_integer_binary!(run_test, i32, rem);
    test_integer_binary!(run_test, i64, rem);
    test_integer_binary!(run_test, i128, rem);

    test_integer_binary!(run_test, u8, rem);
    test_integer_binary!(run_test, u16, rem);
    test_integer_binary!(run_test, u32, rem);
    test_integer_binary!(run_test, u64, rem);
    test_integer_binary!(run_test, u128, rem);

    test_integer_binary!(#[ignore], run_exhaustive_test, u8, rem, exhaustive);
    test_integer_binary!(#[ignore], run_exhaustive_test, i8, rem, exhaustive);
}
