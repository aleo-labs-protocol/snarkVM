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

impl<E: Environment, I: IntegerType> SubWrapped<Self> for Integer<E, I> {
    type Output = Self;

    #[inline]
    fn sub_wrapped(&self, other: &Integer<E, I>) -> Self::Output {
        // Note: `unwrap()` is safe as the integer is at most 128 bits.
        let i_bits = usize::try_from(I::BITS).unwrap();

        // Determine the variable mode.
        if self.is_constant() && other.is_constant() {
            // Compute the difference and return the new constant.
            witness!(|self, other| console::Integer::new(self.wrapping_sub(&other)))
        } else {
            // Instead of subtracting the bits of `self` and `other` directly, the integers are
            // converted into field elements to perform the operation, before converting back to integers.
            // Note: This is safe as the field is larger than the maximum integer type supported.
            let difference = self.to_field() + (!other).to_field() + Field::one();

            // Extract the integer bits from the field element, with a carry bit.
            let mut bits_le = difference.to_lower_bits_le(i_bits + 1);
            // Drop the carry bit as the operation is wrapped subtraction.
            bits_le.pop();

            // Return the difference of `self` and `other`.
            Integer { bits_le, phantom: Default::default() }
        }
    }
}

impl<E: Environment, I: IntegerType> Metrics<dyn SubWrapped<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn count(case: &Self::Case) -> Count {
        match (case.0, case.1) {
            (Mode::Constant, Mode::Constant) => Count::is(I::BITS, 0, 0, 0),
            (_, _) => Count::is(0, 0, I::BITS + 1, I::BITS + 2),
        }
    }
}

impl<E: Environment, I: IntegerType> OutputMode<dyn SubWrapped<Integer<E, I>, Output = Integer<E, I>>>
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

    use std::ops::RangeInclusive;

    const ITERATIONS: u64 = 10;

    fn check_sub<I: IntegerType>(
        name: &str,
        first: console::Integer<<Circuit as Environment>::Network, I>,
        second: console::Integer<<Circuit as Environment>::Network, I>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::new(mode_b, second);
        let expected = first.wrapping_sub(&second);
        Circuit::scope(name, || {
            let candidate = a.sub_wrapped(&b);
            assert_eq!(expected, *candidate.eject_value());
            assert_eq!(console::Integer::new(expected), candidate.eject_value());
            assert_count!(SubWrapped(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b));
            assert_output_mode!(SubWrapped(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b), candidate);
        });
        Circuit::reset();
    }

    fn run_test<I: IntegerType>(mode_a: Mode, mode_b: Mode) {
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

    fn run_exhaustive_test<I: IntegerType>(mode_a: Mode, mode_b: Mode)
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
