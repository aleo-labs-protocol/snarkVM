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

impl<E: Environment, I: IntegerType> AddWrapped<Self> for Integer<E, I> {
    type Output = Self;

    #[inline]
    fn add_wrapped(&self, other: &Integer<E, I>) -> Self::Output {
        // Note: `unwrap()` is safe as the integer is at most 128 bits.
        let i_bits = usize::try_from(I::BITS).unwrap();

        // Determine the variable mode.
        if self.is_constant() && other.is_constant() {
            // Compute the sum and return the new constant.
            witness!(|self, other| console::Integer::new(self.wrapping_add(&other)))
        } else {
            // Instead of adding the bits of `self` and `other` directly, the integers are
            // converted into a field elements, and summed, before converting back to integers.
            // Note: This is safe as the field is larger than the maximum integer type supported.
            let sum = self.to_field() + other.to_field();

            // Extract the integer bits from the field element, with a carry bit.
            let mut bits_le = sum.to_lower_bits_le(i_bits + 1);
            // Drop the carry bit as the operation is wrapped addition.
            bits_le.pop();

            // Return the sum of `self` and `other`.
            Integer { bits_le, phantom: Default::default() }
        }
    }
}

impl<E: Environment, I: IntegerType> Metrics<dyn AddWrapped<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn count(case: &Self::Case) -> Count {
        match (case.0, case.1) {
            (Mode::Constant, Mode::Constant) => Count::is(I::BITS, 0, 0, 0),
            (_, _) => Count::is(0, 0, I::BITS + 1, I::BITS + 2),
        }
    }
}

impl<E: Environment, I: IntegerType> OutputMode<dyn AddWrapped<Integer<E, I>, Output = Integer<E, I>>>
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

    use core::ops::RangeInclusive;

    const ITERATIONS: u64 = 10;

    fn check_add<I: IntegerType>(
        name: &str,
        first: console::Integer<<Circuit as Environment>::Network, I>,
        second: console::Integer<<Circuit as Environment>::Network, I>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::new(mode_b, second);
        let expected = first.wrapping_add(&second);
        Circuit::scope(name, || {
            let candidate = a.add_wrapped(&b);
            assert_eq!(expected, *candidate.eject_value());
            assert_eq!(console::Integer::new(expected), candidate.eject_value());
            assert_count!(AddWrapped(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b));
            assert_output_mode!(AddWrapped(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b), candidate);
        });
        Circuit::reset();
    }

    fn run_test<I: IntegerType>(mode_a: Mode, mode_b: Mode) {
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

    fn run_exhaustive_test<I: IntegerType>(mode_a: Mode, mode_b: Mode)
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
