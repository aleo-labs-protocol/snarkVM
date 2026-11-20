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

impl<E: Environment, I: IntegerType> Div<Integer<E, I>> for Integer<E, I> {
    type Output = Self;

    fn div(self, other: Self) -> Self::Output {
        self / &other
    }
}

impl<E: Environment, I: IntegerType> Div<Integer<E, I>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn div(self, other: Integer<E, I>) -> Self::Output {
        self / &other
    }
}

impl<E: Environment, I: IntegerType> Div<&Integer<E, I>> for Integer<E, I> {
    type Output = Self;

    fn div(self, other: &Self) -> Self::Output {
        &self / other
    }
}

impl<E: Environment, I: IntegerType> Div<&Integer<E, I>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn div(self, other: &Integer<E, I>) -> Self::Output {
        let mut output = self.clone();
        output /= other;
        output
    }
}

impl<E: Environment, I: IntegerType> DivAssign<Integer<E, I>> for Integer<E, I> {
    fn div_assign(&mut self, other: Integer<E, I>) {
        *self /= &other;
    }
}

impl<E: Environment, I: IntegerType> DivAssign<&Integer<E, I>> for Integer<E, I> {
    fn div_assign(&mut self, other: &Integer<E, I>) {
        // Stores the quotient of `self` and `other` in `self`.
        *self = self.div_checked(other);
    }
}

impl<E: Environment, I: IntegerType> DivChecked<Self> for Integer<E, I> {
    type Output = Self;

    #[inline]
    fn div_checked(&self, other: &Integer<E, I>) -> Self::Output {
        match (self.is_constant(), other.is_constant()) {
            // If `other` is a constant and is zero, then halt.
            (_, true) if other.eject_value().is_zero() => E::halt("Attempted to divide by zero."),
            // If `self` and `other` are constants, and other is not zero, then directly return the value of the division.
            (true, true) => match self.eject_value().checked_div(&other.eject_value()) {
                Some(value) => Integer::constant(console::Integer::new(value)),
                None => E::halt("Overflow on division of two integer constants"),
            },
            // Handle the remaining cases.
            // Note that `other` is either a constant and non-zero, or not a constant.
            _ => {
                if I::is_signed() {
                    // Ensure that overflow cannot occur in this division.
                    // Signed integer division wraps when the dividend is Integer::MIN and the divisor is -1.
                    let min = Integer::constant(console::Integer::MIN);
                    let neg_one = Integer::constant(-console::Integer::one());
                    let overflows = self.is_equal(&min) & other.is_equal(&neg_one);
                    E::assert(!overflows).expect("Signed integer division overflow check failed");

                    // Divide the absolute value of `self` and `other` in the base field.
                    // Note that it is safe to use `abs_wrapped`, since the case for console::Integer::MIN is handled above.
                    let unsigned_dividend = self.abs_wrapped().cast_as_dual();
                    // Note that `unsigned_divisor` is zero iff `other` is zero.
                    let unsigned_divisor = other.abs_wrapped().cast_as_dual();
                    // Note that this call to `div_wrapped` checks that `unsigned_divisor` is not zero.
                    let unsigned_quotient = unsigned_dividend.div_wrapped(&unsigned_divisor);

                    // Note that quotient <= |console::Integer::MIN|, since the dividend <= |console::Integer::MIN| and 0 <= quotient <= dividend.
                    let signed_quotient = Integer { bits_le: unsigned_quotient.bits_le, phantom: Default::default() };
                    let operands_same_sign = &self.msb().is_equal(other.msb());

                    Self::ternary(operands_same_sign, &signed_quotient, &Self::zero().sub_wrapped(&signed_quotient))
                } else {
                    // Return the quotient of `self` and `other`.
                    // Note that this call to `div_wrapped` checks that `unsigned_divisor` is not zero.
                    self.div_wrapped(other)
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

    fn check_div<I: IntegerType + RefUnwindSafe>(
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
                Mode::Constant => check_operation_halts(&a, &b, Integer::div_checked),
                _ => Circuit::scope(name, || {
                    let _candidate = a.div_checked(&b);
                    assert_scope_fails!();
                }),
            }
        } else {
            match first.checked_div(&second) {
                Some(expected) => Circuit::scope(name, || {
                    let candidate = a.div_checked(&b);
                    assert_eq!(expected, *candidate.eject_value());
                    assert_eq!(console::Integer::new(expected), candidate.eject_value());
                    assert_scope!();
                }),
                None => match (mode_a, mode_b) {
                    (Mode::Constant, Mode::Constant) => check_operation_halts(&a, &b, Integer::div_checked),
                    _ => Circuit::scope(name, || {
                        let _candidate = a.div_checked(&b);
                        assert_scope_fails!();
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

            let name = format!("Div: {first} / {second}");
            check_div::<I>(&name, first, second, mode_a, mode_b);

            let name = format!("Div by One: {first} / 1");
            check_div::<I>(&name, first, console::Integer::one(), mode_a, mode_b);

            let name = format!("Div by Self: {first} / {first}");
            check_div::<I>(&name, first, first, mode_a, mode_b);

            let name = format!("Div by Zero: {first} / 0");
            check_div::<I>(&name, first, console::Integer::zero(), mode_a, mode_b);
        }

        // Check standard division properties and corner cases.
        check_div::<I>("MAX / 1", console::Integer::MAX, console::Integer::one(), mode_a, mode_b);
        check_div::<I>("MIN / 1", console::Integer::MIN, console::Integer::one(), mode_a, mode_b);
        check_div::<I>("1 / 1", console::Integer::one(), console::Integer::one(), mode_a, mode_b);
        check_div::<I>("0 / 1", console::Integer::zero(), console::Integer::one(), mode_a, mode_b);
        check_div::<I>("MAX / 0", console::Integer::MAX, console::Integer::zero(), mode_a, mode_b);
        check_div::<I>("MIN / 0", console::Integer::MIN, console::Integer::zero(), mode_a, mode_b);
        check_div::<I>("1 / 0", console::Integer::one(), console::Integer::zero(), mode_a, mode_b);
        check_div::<I>("0 / 0", console::Integer::zero(), console::Integer::zero(), mode_a, mode_b);

        // Check some additional corner cases for signed integer division.
        if I::is_signed() {
            check_div::<I>("MAX / -1", console::Integer::MAX, -console::Integer::one(), mode_a, mode_b);
            check_div::<I>("MIN / -1", console::Integer::MIN, -console::Integer::one(), mode_a, mode_b);
            check_div::<I>("1 / -1", console::Integer::one(), -console::Integer::one(), mode_a, mode_b);
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

                let name = format!("Div: ({first} / {second})");
                check_div::<I>(&name, first, second, mode_a, mode_b);
            }
        }
    }

    test_integer_binary!(run_test, i8, div);
    test_integer_binary!(run_test, i16, div);
    test_integer_binary!(run_test, i32, div);
    test_integer_binary!(run_test, i64, div);
    test_integer_binary!(run_test, i128, div);

    test_integer_binary!(run_test, u8, div);
    test_integer_binary!(run_test, u16, div);
    test_integer_binary!(run_test, u32, div);
    test_integer_binary!(run_test, u64, div);
    test_integer_binary!(run_test, u128, div);

    test_integer_binary!(#[ignore], run_exhaustive_test, u8, div, exhaustive);
    test_integer_binary!(#[ignore], run_exhaustive_test, i8, div, exhaustive);
}
