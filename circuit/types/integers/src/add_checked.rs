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

impl<E: Environment, I: IntegerType> Add<Integer<E, I>> for Integer<E, I> {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        self + &other
    }
}

impl<E: Environment, I: IntegerType> Add<Integer<E, I>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn add(self, other: Integer<E, I>) -> Self::Output {
        self + &other
    }
}

impl<E: Environment, I: IntegerType> Add<&Integer<E, I>> for Integer<E, I> {
    type Output = Self;

    fn add(self, other: &Self) -> Self::Output {
        &self + other
    }
}

impl<E: Environment, I: IntegerType> Add<&Integer<E, I>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn add(self, other: &Integer<E, I>) -> Self::Output {
        let mut output = self.clone();
        output += other;
        output
    }
}

impl<E: Environment, I: IntegerType> AddAssign<Integer<E, I>> for Integer<E, I> {
    fn add_assign(&mut self, other: Integer<E, I>) {
        *self += &other;
    }
}

impl<E: Environment, I: IntegerType> AddAssign<&Integer<E, I>> for Integer<E, I> {
    fn add_assign(&mut self, other: &Integer<E, I>) {
        // Stores the sum of `self` and `other` in `self`.
        *self = self.add_checked(other);
    }
}

impl<E: Environment, I: IntegerType> AddChecked<Self> for Integer<E, I> {
    type Output = Self;

    #[inline]
    fn add_checked(&self, other: &Integer<E, I>) -> Self::Output {
        // Note: `unwrap()` is safe as the integer is at most 128 bits.
        let i_bits = usize::try_from(I::BITS).unwrap();

        // Determine the variable mode.
        if self.is_constant() && other.is_constant() {
            // Compute the sum and return the new constant.
            match self.eject_value().checked_add(&other.eject_value()) {
                Some(value) => Integer::constant(console::Integer::new(value)),
                None => E::halt("Integer overflow on addition of two constants"),
            }
        } else if I::is_signed() {
            // Instead of adding the bits of `self` and `other` directly, the integers are
            // converted into a field elements, and summed, before converting back to integers.
            // Note: This is safe as the field is larger than the maximum integer type supported.
            let sum = self.to_field() + other.to_field();

            // Extract the integer bits from the field element, ignoring the carry bit as it is not relevant for signed addition.
            let sum = match sum.to_lower_bits_le(i_bits + 1).split_last() {
                Some((_, bits_le)) => Integer::from_bits_le(bits_le),
                // Note: `E::halt` should never be invoked as `i_bits + 1` is greater than zero.
                None => E::halt("Malformed sum detected during integer addition"),
            };

            // For signed addition, overflow and underflow conditions are:
            //   - a > 0 && b > 0 && a + b < 0 (Overflow)
            //   - a < 0 && b < 0 && a + b > 0 (Underflow)
            //   - Note: if sign(a) != sign(b) then over/underflow is impossible.
            //   - Note: the result of an overflow and underflow must be negative and positive, respectively.
            let is_same_sign = self.msb().is_equal(other.msb());
            let is_overflow = is_same_sign & sum.msb().is_not_equal(self.msb());
            E::assert_eq(is_overflow, E::zero()).expect("Signed integer addition overflow check failed");

            sum
        } else {
            // Instead of adding the bits of `self` and `other` directly, witness the integer sum.
            let sum: Integer<E, I> = witness!(|self, other| self.add_wrapped(&other));

            // Check that the computed sum is equal to the witnessed sum, in the base field.
            let computed_sum = self.to_field() + other.to_field();
            let witnessed_sum = sum.to_field();
            E::assert_eq(computed_sum, witnessed_sum).expect("Unsigned integer addition constraint unsatisfied");

            sum
        }
    }
}

impl<E: Environment, I: IntegerType> Metrics<dyn Add<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn count(case: &Self::Case) -> Count {
        <Self as Metrics<dyn AddChecked<Integer<E, I>, Output = Integer<E, I>>>>::count(case)
    }
}

impl<E: Environment, I: IntegerType> OutputMode<dyn Add<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn output_mode(case: &Self::Case) -> Mode {
        <Self as OutputMode<dyn AddChecked<Integer<E, I>, Output = Integer<E, I>>>>::output_mode(case)
    }
}

impl<E: Environment, I: IntegerType> Metrics<dyn AddChecked<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn count(case: &Self::Case) -> Count {
        match I::is_signed() {
            true => match (case.0, case.1) {
                (Mode::Constant, Mode::Constant) => Count::is(I::BITS, 0, 0, 0),
                (Mode::Constant, _) => Count::is(0, 0, I::BITS + 2, I::BITS + 4),
                (_, Mode::Constant) => Count::is(0, 0, I::BITS + 3, I::BITS + 5),
                (_, _) => Count::is(0, 0, I::BITS + 4, I::BITS + 6),
            },
            false => match (case.0, case.1) {
                (Mode::Constant, Mode::Constant) => Count::is(I::BITS, 0, 0, 0),
                (_, _) => Count::is(0, 0, I::BITS, I::BITS + 1),
            },
        }
    }
}

impl<E: Environment, I: IntegerType> OutputMode<dyn AddChecked<Integer<E, I>, Output = Integer<E, I>>>
    for Integer<E, I>
{
    type Case = (Mode, Mode);

    fn output_mode(case: &Self::Case) -> Mode {
        match (case.0, case.1) {
            (Mode::Constant, Mode::Constant) => Mode::Constant,
            (_, _) => Mode::Private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_integer_binary;
    use snarkvm_circuit_environment::Circuit;

    use test_utilities::*;

    use core::{ops::RangeInclusive, panic::RefUnwindSafe};

    const ITERATIONS: u64 = 10;

    fn check_add<I: IntegerType + RefUnwindSafe>(
        name: &str,
        first: console::Integer<<Circuit as Environment>::Network, I>,
        second: console::Integer<<Circuit as Environment>::Network, I>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::new(mode_b, second);
        match first.checked_add(&second) {
            Some(expected) => Circuit::scope(name, || {
                let candidate = a.add_checked(&b);
                assert_eq!(expected, *candidate.eject_value());
                assert_eq!(console::Integer::new(expected), candidate.eject_value());
                assert_count!(Add(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b));
                assert_output_mode!(Add(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b), candidate);
            }),
            None => match mode_a.is_constant() && mode_b.is_constant() {
                true => check_operation_halts(&a, &b, Integer::add_checked),
                false => Circuit::scope(name, || {
                    let _candidate = a.add_checked(&b);
                    assert_count_fails!(Add(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b));
                }),
            },
        }
        Circuit::reset();
    }

    fn run_test<I: IntegerType + RefUnwindSafe>(mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let name = format!("Add: {mode_a} + {mode_b} {i}");
            check_add::<I>(&name, first, second, mode_a, mode_b);
            check_add::<I>(&name, second, first, mode_a, mode_b); // Commute the operation.
        }

        // Overflow
        check_add::<I>("MAX + 1", console::Integer::MAX, console::Integer::one(), mode_a, mode_b);
        check_add::<I>("1 + MAX", console::Integer::one(), console::Integer::MAX, mode_a, mode_b);

        // Underflow
        if I::is_signed() {
            check_add::<I>("MIN + (-1)", console::Integer::MIN, -console::Integer::one(), mode_a, mode_b);
            check_add::<I>("-1 + MIN", -console::Integer::one(), console::Integer::MIN, mode_a, mode_b);
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

                let name = format!("Add: ({first} + {second})");
                check_add::<I>(&name, first, second, mode_a, mode_b);
            }
        }
    }

    test_integer_binary!(run_test, i8, plus);
    test_integer_binary!(run_test, i16, plus);
    test_integer_binary!(run_test, i32, plus);
    test_integer_binary!(run_test, i64, plus);
    test_integer_binary!(run_test, i128, plus);

    test_integer_binary!(run_test, u8, plus);
    test_integer_binary!(run_test, u16, plus);
    test_integer_binary!(run_test, u32, plus);
    test_integer_binary!(run_test, u64, plus);
    test_integer_binary!(run_test, u128, plus);

    test_integer_binary!(#[ignore], run_exhaustive_test, u8, plus, exhaustive);
    test_integer_binary!(#[ignore], run_exhaustive_test, i8, plus, exhaustive);
}
