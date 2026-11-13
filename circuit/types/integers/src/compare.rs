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

impl<E: Environment, I: IntegerType> Compare<Self> for Integer<E, I> {
    type Output = Boolean<E>;

    /// Returns `true` if `self` is less than `other`.
    fn is_less_than(&self, other: &Self) -> Self::Output {
        // Note: `unwrap()` is safe as the integer is at most 128 bits.
        let i_bits = usize::try_from(I::BITS).unwrap();

        // Determine the variable mode.
        if self.is_constant() && other.is_constant() {
            // Compute the comparison and return the new constant.
            witness!(|self, other| self < other)
        } else if I::is_signed() {
            // Compute the less than operation via a sign and overflow check.
            // If sign(a) != sign(b), then a < b, if a is negative and b is positive.
            // If sign(b) == sign(a), then a < b if the carry bit of I::NEG_ONE + a - b + 1 is set.
            let same_sign = self.msb().is_equal(other.msb());
            let self_is_negative_and_other_is_positive = self.msb() & !other.msb();
            let negative_one_plus_difference_plus_one =
                Integer::<E, I>::constant(-console::Integer::one()).to_field() + self.to_field() - other.to_field()
                    + Field::one();
            match negative_one_plus_difference_plus_one.to_lower_bits_le(i_bits + 1).last() {
                Some(bit) => Self::Output::ternary(&same_sign, &!bit, &self_is_negative_and_other_is_positive),
                // Note: `E::halt` should never be invoked as `i_bits + 1` is greater than zero.
                None => E::halt("Malformed expression detected during signed integer comparison."),
            }
        } else {
            // Compute the less than operation via an overflow check.
            // If Integer::MAX + a - b + 1 overflows, then a >= b, otherwise a < b.
            let max_plus_difference_plus_one =
                Integer::<E, I>::constant(console::Integer::MAX).to_field() + self.to_field() - other.to_field()
                    + Field::one();
            match max_plus_difference_plus_one.to_lower_bits_le(i_bits + 1).last() {
                Some(bit) => !bit,
                // Note: `E::halt` should never be invoked as `i_bits + 1` is greater than zero.
                None => E::halt("Malformed expression detected during unsigned integer comparison."),
            }
        }
    }

    /// Returns `true` if `self` is greater than `other`.
    fn is_greater_than(&self, other: &Self) -> Self::Output {
        other.is_less_than(self)
    }

    /// Returns `true` if `self` is less than or equal to `other`.
    fn is_less_than_or_equal(&self, other: &Self) -> Self::Output {
        other.is_greater_than_or_equal(self)
    }

    /// Returns `true` if `self` is greater than or equal to `other`.
    fn is_greater_than_or_equal(&self, other: &Self) -> Self::Output {
        !self.is_less_than(other)
    }
}

impl<E: Environment, I: IntegerType> Metrics<dyn Compare<Integer<E, I>, Output = Boolean<E>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn count(case: &Self::Case) -> Count {
        match I::is_signed() {
            true => match (case.0, case.1) {
                (Mode::Constant, Mode::Constant) => Count::is(1, 0, 0, 0),
                (Mode::Constant, _) | (_, Mode::Constant) => Count::is(I::BITS, 0, I::BITS + 2, I::BITS + 3),
                (_, _) => Count::is(I::BITS, 0, I::BITS + 4, I::BITS + 5),
            },
            false => match (case.0, case.1) {
                (Mode::Constant, Mode::Constant) => Count::is(1, 0, 0, 0),
                (_, _) => Count::is(I::BITS, 0, I::BITS + 1, I::BITS + 2),
            },
        }
    }
}

impl<E: Environment, I: IntegerType> OutputMode<dyn Compare<Integer<E, I>, Output = Boolean<E>>> for Integer<E, I> {
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

    use core::ops::RangeInclusive;

    const ITERATIONS: u64 = 10;

    fn check_compare<I: IntegerType>(
        name: &str,
        first: console::Integer<<Circuit as Environment>::Network, I>,
        second: console::Integer<<Circuit as Environment>::Network, I>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::<Circuit, I>::new(mode_b, second);

        // Check `is_less_than`.
        let expected = first < second;
        Circuit::scope(name, || {
            let candidate = a.is_less_than(&b);
            assert_eq!(expected, candidate.eject_value());
            assert_count!(Compare(Integer<I>, Integer<I>) => Boolean, &(mode_a, mode_b));
            assert_output_mode!(Compare(Integer<I>, Integer<I>) => Boolean, &(mode_a, mode_b), candidate);
        });
        Circuit::reset();

        // Check `is_less_than_or_equal`
        let expected = first <= second;
        Circuit::scope(name, || {
            let candidate = a.is_less_than_or_equal(&b);
            assert_eq!(expected, candidate.eject_value());
            assert_count!(Compare(Integer<I>, Integer<I>) => Boolean, &(mode_a, mode_b));
            assert_output_mode!(Compare(Integer<I>, Integer<I>) => Boolean, &(mode_a, mode_b), candidate);
        });
        Circuit::reset();

        // Check `is_greater_than`
        let expected = first > second;
        Circuit::scope(name, || {
            let candidate = a.is_greater_than(&b);
            assert_eq!(expected, candidate.eject_value());
            assert_count!(Compare(Integer<I>, Integer<I>) => Boolean, &(mode_a, mode_b));
            assert_output_mode!(Compare(Integer<I>, Integer<I>) => Boolean, &(mode_a, mode_b), candidate);
        });
        Circuit::reset();

        // Check `is_greater_than_or_equal`
        let expected = first >= second;
        Circuit::scope(name, || {
            let candidate = a.is_greater_than_or_equal(&b);
            assert_eq!(expected, candidate.eject_value());
            assert_count!(Compare(Integer<I>, Integer<I>) => Boolean, &(mode_a, mode_b));
            assert_output_mode!(Compare(Integer<I>, Integer<I>) => Boolean, &(mode_a, mode_b), candidate);
        });
        Circuit::reset();
    }

    fn run_test<I: IntegerType>(mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let name = format!("Compare: ({mode_a}, {mode_b}) - {i}th iteration");
            check_compare::<I>(&name, first, second, mode_a, mode_b);
        }
    }

    fn run_exhaustive_test<I: IntegerType>(mode_a: Mode, mode_b: Mode)
    where
        RangeInclusive<I>: Iterator<Item = I>,
    {
        for first in I::MIN..=I::MAX {
            for second in I::MIN..=I::MAX {
                let first = console::Integer::<_, I>::new(first);
                let second = console::Integer::<_, I>::new(second);

                let name = format!("Compare: ({first}, {second})");
                check_compare::<I>(&name, first, second, mode_a, mode_b);
            }
        }
    }

    test_integer_binary!(run_test, i8, compare_with);
    test_integer_binary!(run_test, i16, compare_with);
    test_integer_binary!(run_test, i32, compare_with);
    test_integer_binary!(run_test, i64, compare_with);
    test_integer_binary!(run_test, i128, compare_with);

    test_integer_binary!(run_test, u8, compare_with);
    test_integer_binary!(run_test, u16, compare_with);
    test_integer_binary!(run_test, u32, compare_with);
    test_integer_binary!(run_test, u64, compare_with);
    test_integer_binary!(run_test, u128, compare_with);

    test_integer_binary!(#[ignore], run_exhaustive_test, u8, bitand, exhaustive);
    test_integer_binary!(#[ignore], run_exhaustive_test, i8, bitand, exhaustive);
}
