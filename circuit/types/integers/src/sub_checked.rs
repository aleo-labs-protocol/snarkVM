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

impl<E: Environment, I: IntegerType> Sub<Integer<E, I>> for Integer<E, I> {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        self - &other
    }
}

impl<E: Environment, I: IntegerType> Sub<Integer<E, I>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn sub(self, other: Integer<E, I>) -> Self::Output {
        self - &other
    }
}

impl<E: Environment, I: IntegerType> Sub<&Integer<E, I>> for Integer<E, I> {
    type Output = Self;

    fn sub(self, other: &Self) -> Self::Output {
        &self - other
    }
}

impl<E: Environment, I: IntegerType> Sub<&Integer<E, I>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn sub(self, other: &Integer<E, I>) -> Self::Output {
        let mut output = self.clone();
        output -= other;
        output
    }
}

impl<E: Environment, I: IntegerType> SubAssign<Integer<E, I>> for Integer<E, I> {
    fn sub_assign(&mut self, other: Integer<E, I>) {
        *self -= &other;
    }
}

impl<E: Environment, I: IntegerType> SubAssign<&Integer<E, I>> for Integer<E, I> {
    fn sub_assign(&mut self, other: &Integer<E, I>) {
        // Stores the difference of `self` and `other` in `self`.
        *self = self.sub_checked(other);
    }
}

impl<E: Environment, I: IntegerType> SubChecked<Self> for Integer<E, I> {
    type Output = Self;

    #[inline]
    fn sub_checked(&self, other: &Integer<E, I>) -> Self::Output {
        // Note: `unwrap()` is safe as the integer is at most 128 bits.
        let i_bits = usize::try_from(I::BITS).unwrap();

        // Determine the variable mode.
        if self.is_constant() && other.is_constant() {
            // Compute the difference and return the new constant.
            match self.eject_value().checked_sub(&other.eject_value()) {
                Some(value) => Integer::constant(console::Integer::new(value)),
                None => E::halt("Integer underflow on subtraction of two constants"),
            }
        } else {
            // Instead of subtracting the bits of `self` and `other` directly, the integers are
            // converted into a field elements, and subtracted, before converting back to integers.
            // Note: This is safe as the field is larger than the maximum integer type supported.
            let difference = self.to_field() + (!other).to_field() + Field::one();

            // Extract the integer bits from the field element, with a carry bit.
            let (difference, carry) = match difference.to_lower_bits_le(i_bits + 1).split_last() {
                Some((carry, bits_le)) => (Integer::from_bits_le(bits_le), carry.clone()),
                // Note: `E::halt` should never be invoked as `i_bits + 1` is greater than zero.
                None => E::halt("Malformed difference detected during integer subtraction"),
            };

            // Check for underflow.
            match I::is_signed() {
                // For signed subtraction, overflow and underflow conditions are:
                //   - a > 0 && b < 0 && a - b > 0 (Overflow)
                //   - a < 0 && b > 0 && a - b < 0 (Underflow)
                //   - Note: if sign(a) == sign(b) then over/underflow is impossible.
                //   - Note: the result of an overflow and underflow must be negative and positive, respectively.
                true => {
                    let is_different_signs = self.msb().is_not_equal(other.msb());
                    let is_underflow = is_different_signs & difference.msb().is_equal(other.msb());
                    E::assert_eq(is_underflow, E::zero())
                }
                // For unsigned subtraction, ensure the carry bit is one.
                false => E::assert_eq(carry, E::one()),
            }
            .expect("Integer subtraction constraint unsatisfied");

            // Return the difference of `self` and `other`.
            difference
        }
    }
}

impl<E: Environment, I: IntegerType> Metrics<dyn Sub<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn count(case: &Self::Case) -> Count {
        <Self as Metrics<dyn SubChecked<Integer<E, I>, Output = Integer<E, I>>>>::count(case)
    }
}

impl<E: Environment, I: IntegerType> OutputMode<dyn Sub<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn output_mode(case: &Self::Case) -> Mode {
        <Self as OutputMode<dyn SubChecked<Integer<E, I>, Output = Integer<E, I>>>>::output_mode(case)
    }
}

impl<E: Environment, I: IntegerType> Metrics<dyn SubChecked<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn count(case: &Self::Case) -> Count {
        match I::is_signed() {
            true => match (case.0, case.1) {
                (Mode::Constant, Mode::Constant) => Count::is(I::BITS, 0, 0, 0),
                (Mode::Constant, _) => Count::is(0, 0, I::BITS + 3, I::BITS + 5),
                (_, Mode::Constant) => Count::is(0, 0, I::BITS + 2, I::BITS + 4),
                (_, _) => Count::is(0, 0, I::BITS + 4, I::BITS + 6),
            },
            false => match (case.0, case.1) {
                (Mode::Constant, Mode::Constant) => Count::is(I::BITS, 0, 0, 0),
                (_, _) => Count::is(0, 0, I::BITS + 1, I::BITS + 3),
            },
        }
    }
}

impl<E: Environment, I: IntegerType> OutputMode<dyn SubChecked<Integer<E, I>, Output = Integer<E, I>>>
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
    use snarkvm_circuit_environment::Circuit;

    use test_utilities::*;

    use core::{ops::RangeInclusive, panic::RefUnwindSafe};

    const ITERATIONS: u64 = 10;

    fn check_sub<I: IntegerType + RefUnwindSafe>(
        name: &str,
        first: console::Integer<<Circuit as Environment>::Network, I>,
        second: console::Integer<<Circuit as Environment>::Network, I>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::<Circuit, I>::new(mode_b, second);
        match first.checked_sub(&second) {
            Some(expected) => Circuit::scope(name, || {
                let candidate = a.sub_checked(&b);
                assert_eq!(expected, *candidate.eject_value());
                assert_eq!(console::Integer::new(expected), candidate.eject_value());
                assert_count!(Sub(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b));
                assert_output_mode!(Sub(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b), candidate);
            }),
            None => match mode_a.is_constant() && mode_b.is_constant() {
                true => check_operation_halts(&a, &b, Integer::sub_checked),
                false => Circuit::scope(name, || {
                    let _candidate = a.sub_checked(&b);
                    assert_count_fails!(Sub(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b));
                }),
            },
        }
        Circuit::reset();
    }

    fn run_test<I: IntegerType + RefUnwindSafe>(mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let name = format!("Sub: {mode_a} - {mode_b} {i}");
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);
            check_sub::<I>(&name, first, second, mode_a, mode_b);
        }

        // Overflow
        if I::is_signed() {
            check_sub::<I>("MAX - (-1)", console::Integer::MAX, -console::Integer::one(), mode_a, mode_b);
        }
        // Underflow
        check_sub::<I>("MIN - 1", console::Integer::MIN, console::Integer::one(), mode_a, mode_b);
    }

    fn run_exhaustive_test<I: IntegerType + RefUnwindSafe>(mode_a: Mode, mode_b: Mode)
    where
        RangeInclusive<I>: Iterator<Item = I>,
    {
        for first in I::MIN..=I::MAX {
            for second in I::MIN..=I::MAX {
                let first = console::Integer::<_, I>::new(first);
                let second = console::Integer::<_, I>::new(second);

                let name = format!("Sub: ({first} - {second})");
                check_sub::<I>(&name, first, second, mode_a, mode_b);
            }
        }
    }

    test_integer_binary!(run_test, i8, minus);
    test_integer_binary!(run_test, i16, minus);
    test_integer_binary!(run_test, i32, minus);
    test_integer_binary!(run_test, i64, minus);
    test_integer_binary!(run_test, i128, minus);

    test_integer_binary!(run_test, u8, minus);
    test_integer_binary!(run_test, u16, minus);
    test_integer_binary!(run_test, u32, minus);
    test_integer_binary!(run_test, u64, minus);
    test_integer_binary!(run_test, u128, minus);

    test_integer_binary!(#[ignore], run_exhaustive_test, u8, minus, exhaustive);
    test_integer_binary!(#[ignore], run_exhaustive_test, i8, minus, exhaustive);
}
