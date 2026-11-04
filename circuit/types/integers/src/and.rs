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

impl<E: Environment, I: IntegerType> BitAnd<Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns `(self AND other)`.
    fn bitand(self, other: Integer<E, I>) -> Self::Output {
        self & &other
    }
}

impl<E: Environment, I: IntegerType> BitAnd<Integer<E, I>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns `(self AND other)`.
    fn bitand(self, other: Integer<E, I>) -> Self::Output {
        self & &other
    }
}

impl<E: Environment, I: IntegerType> BitAnd<&Integer<E, I>> for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns `(self AND other)`.
    fn bitand(self, other: &Integer<E, I>) -> Self::Output {
        &self & other
    }
}

impl<E: Environment, I: IntegerType> BitAnd<&Integer<E, I>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns `(self AND other)`.
    fn bitand(self, other: &Integer<E, I>) -> Self::Output {
        let mut output = self.clone();
        output &= other;
        output
    }
}

impl<E: Environment, I: IntegerType> BitAndAssign<Integer<E, I>> for Integer<E, I> {
    /// Sets `self` as `(self AND other)`.
    fn bitand_assign(&mut self, other: Integer<E, I>) {
        *self &= &other;
    }
}

impl<E: Environment, I: IntegerType> BitAndAssign<&Integer<E, I>> for Integer<E, I> {
    /// Sets `self` as `(self AND other)`.
    fn bitand_assign(&mut self, other: &Integer<E, I>) {
        // Stores the bitwise AND of `self` and `other` in `self`.
        *self = Self {
            bits_le: self.bits_le.iter().zip_eq(other.bits_le.iter()).map(|(a, b)| a & b).collect(),
            phantom: Default::default(),
        }
    }
}

impl<E: Environment, I: IntegerType> Metrics<dyn BitAnd<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn count(case: &Self::Case) -> Count {
        match (case.0, case.1) {
            (Mode::Constant, _) | (_, Mode::Constant) => Count::is(0, 0, 0, 0),
            (_, _) => Count::is(0, 0, I::BITS, I::BITS),
        }
    }
}

impl<E: Environment, I: IntegerType> OutputMode<dyn BitAnd<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (CircuitType<Integer<E, I>>, CircuitType<Integer<E, I>>);

    fn output_mode(case: &Self::Case) -> Mode {
        match (case.0.mode(), case.1.mode()) {
            (Mode::Constant, Mode::Constant) => Mode::Constant,
            (Mode::Constant, mode_b) => match &case.0 {
                // Determine if the constant is all zeros.
                CircuitType::Constant(constant) => match constant.eject_value().is_zero() {
                    true => Mode::Constant,
                    false => mode_b,
                },
                _ => E::halt(format!("The constant is required to determine the output mode of Constant AND {mode_b}")),
            },
            (mode_a, Mode::Constant) => match &case.1 {
                // Determine if the constant is all zeros.
                CircuitType::Constant(constant) => match constant.eject_value().is_zero() {
                    true => Mode::Constant,
                    false => mode_a,
                },
                _ => E::halt(format!("The constant is required to determine the output mode of {mode_a} AND Constant")),
            },
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

    #[allow(clippy::needless_borrow)]
    fn check_and<I: IntegerType + BitAnd<Output = I>>(
        name: &str,
        first: console::Integer<<Circuit as Environment>::Network, I>,
        second: console::Integer<<Circuit as Environment>::Network, I>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::new(mode_b, second);
        let expected = first & second;
        Circuit::scope(name, || {
            let candidate = (&a).bitand(&b);
            assert_eq!(expected, candidate.eject_value());
            assert_count!(BitAnd(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b));
            assert_output_mode!(BitAnd(Integer<I>, Integer<I>) => Integer<I>, &(CircuitType::from(&a), CircuitType::from(&b)), candidate);
        });
        Circuit::reset();
    }

    fn run_test<I: IntegerType + BitAnd<Output = I>>(mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let name = format!("BitAnd: ({mode_a} & {mode_b}) {i}");
            check_and::<I>(&name, first, second, mode_a, mode_b);
            check_and::<I>(&name, second, first, mode_a, mode_b); // Commute the operation.

            let name = format!("BitAnd Identity: ({mode_a} & {mode_b}) {i}");
            let identity = if I::is_signed() { -console::Integer::one() } else { console::Integer::MAX };
            check_and::<I>(&name, identity, first, mode_a, mode_b);
            check_and::<I>(&name, first, identity, mode_a, mode_b); // Commute the operation.
        }

        // Check cases common to signed and unsigned integers.
        check_and::<I>("0 & MAX", console::Integer::zero(), console::Integer::MAX, mode_a, mode_b);
        check_and::<I>("MAX & 0", console::Integer::MAX, console::Integer::zero(), mode_a, mode_b);
        check_and::<I>("0 & MIN", console::Integer::zero(), console::Integer::MIN, mode_a, mode_b);
        check_and::<I>("MIN & 0", console::Integer::MIN, console::Integer::zero(), mode_a, mode_b);
    }

    fn run_exhaustive_test<I: IntegerType + BitAnd<Output = I>>(mode_a: Mode, mode_b: Mode)
    where
        RangeInclusive<I>: Iterator<Item = I>,
    {
        for first in I::MIN..=I::MAX {
            for second in I::MIN..=I::MAX {
                let first = console::Integer::<_, I>::new(first);
                let second = console::Integer::<_, I>::new(second);

                let name = format!("BitAnd: ({first} & {second})");
                check_and::<I>(&name, first, second, mode_a, mode_b);
            }
        }
    }

    test_integer_binary!(run_test, i8, bitand);
    test_integer_binary!(run_test, i16, bitand);
    test_integer_binary!(run_test, i32, bitand);
    test_integer_binary!(run_test, i64, bitand);
    test_integer_binary!(run_test, i128, bitand);

    test_integer_binary!(run_test, u8, bitand);
    test_integer_binary!(run_test, u16, bitand);
    test_integer_binary!(run_test, u32, bitand);
    test_integer_binary!(run_test, u64, bitand);
    test_integer_binary!(run_test, u128, bitand);

    test_integer_binary!(#[ignore], run_exhaustive_test, u8, bitand, exhaustive);
    test_integer_binary!(#[ignore], run_exhaustive_test, i8, bitand, exhaustive);
}
