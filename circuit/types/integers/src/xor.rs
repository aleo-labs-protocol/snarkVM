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

impl<E: Environment, I: IntegerType> BitXor<Integer<E, I>> for Integer<E, I> {
    type Output = Self;

    /// Returns `(self != other)`.
    fn bitxor(self, other: Self) -> Self::Output {
        self ^ &other
    }
}

impl<E: Environment, I: IntegerType> BitXor<Integer<E, I>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns `(self != other)`.
    fn bitxor(self, other: Integer<E, I>) -> Self::Output {
        self ^ &other
    }
}

impl<E: Environment, I: IntegerType> BitXor<&Integer<E, I>> for Integer<E, I> {
    type Output = Self;

    /// Returns `(self != other)`.
    fn bitxor(self, other: &Self) -> Self::Output {
        &self ^ other
    }
}

impl<E: Environment, I: IntegerType> BitXor<&Integer<E, I>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    /// Returns `(self != other)`.
    fn bitxor(self, other: &Integer<E, I>) -> Self::Output {
        let mut output = self.clone();
        output ^= other;
        output
    }
}

impl<E: Environment, I: IntegerType> BitXorAssign<Integer<E, I>> for Integer<E, I> {
    /// Sets `self` as `(self != other)`.
    fn bitxor_assign(&mut self, other: Integer<E, I>) {
        *self ^= &other;
    }
}

impl<E: Environment, I: IntegerType> BitXorAssign<&Integer<E, I>> for Integer<E, I> {
    /// Sets `self` as `(self != other)`.
    fn bitxor_assign(&mut self, other: &Integer<E, I>) {
        // Stores the bitwise XOR of `self` and `other` in `self`.
        *self = Self {
            bits_le: self.bits_le.iter().zip_eq(other.bits_le.iter()).map(|(a, b)| a ^ b).collect(),
            phantom: Default::default(),
        }
    }
}

impl<E: Environment, I: IntegerType> Metrics<dyn BitXor<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn count(case: &Self::Case) -> Count {
        match (case.0, case.1) {
            (Mode::Constant, _) | (_, Mode::Constant) => Count::is(0, 0, 0, 0),
            (_, _) => Count::is(0, 0, I::BITS, I::BITS),
        }
    }
}

impl<E: Environment, I: IntegerType> OutputMode<dyn BitXor<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (CircuitType<Integer<E, I>>, CircuitType<Integer<E, I>>);

    fn output_mode(case: &Self::Case) -> Mode {
        match ((case.0.mode(), &case.0), (case.1.mode(), &case.1)) {
            ((Mode::Constant, _), (Mode::Constant, _)) => Mode::Constant,
            ((Mode::Constant, case), (mode, _)) | ((mode, _), (Mode::Constant, case)) => match case {
                // Determine if the constant is all zeros.
                CircuitType::Constant(constant) => match constant.eject_value().is_zero() {
                    true => mode,
                    false => Mode::Private,
                },
                _ => E::halt(format!("The constant is required to determine the output mode of Constant OR {mode}")),
            },
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

    #[allow(clippy::needless_borrow)]
    fn check_bitxor<I: IntegerType + BitXor<Output = I>>(
        name: &str,
        first: console::Integer<<Circuit as Environment>::Network, I>,
        second: console::Integer<<Circuit as Environment>::Network, I>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::<Circuit, I>::new(mode_b, second);
        let expected = first ^ second;
        Circuit::scope(name, || {
            let candidate = (&a).bitxor(&b);
            assert_eq!(expected, candidate.eject_value());
            assert_count!(BitXor(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b));
            assert_output_mode!(BitXor(Integer<I>, Integer<I>) => Integer<I>, &(CircuitType::from(&a), CircuitType::from(&b)), candidate);
        });
        Circuit::reset();
    }

    fn run_test<I: IntegerType + BitXor<Output = I>>(mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let name = format!("BitXor: ({mode_a} ^ {mode_b}) {i}");
            check_bitxor::<I>(&name, first, second, mode_a, mode_b);
            check_bitxor::<I>(&name, second, first, mode_a, mode_b); // Commute the operation.

            let name = format!("BitXor Identity: ({mode_a} ^ {mode_b}) {i}");
            check_bitxor::<I>(&name, console::Integer::zero(), first, mode_a, mode_b);
            check_bitxor::<I>(&name, first, console::Integer::zero(), mode_a, mode_b); // Commute the operation.

            let name = format!("BitXor Inverse Identity: ({mode_a} ^ {mode_b}) {i}");
            let inverse = if I::is_signed() { -console::Integer::one() } else { console::Integer::MAX };
            check_bitxor::<I>(&name, inverse, first, mode_a, mode_b);
            check_bitxor::<I>(&name, first, inverse, mode_a, mode_b); // Commute the operation.
        }

        // Check cases common to signed and unsigned integers.
        check_bitxor::<I>("0 ^ MAX", console::Integer::zero(), console::Integer::MAX, mode_a, mode_b);
        check_bitxor::<I>("MAX ^ 0", console::Integer::MAX, console::Integer::zero(), mode_a, mode_b);
        check_bitxor::<I>("0 ^ MIN", console::Integer::zero(), console::Integer::MIN, mode_a, mode_b);
        check_bitxor::<I>("MIN ^ 0", console::Integer::MIN, console::Integer::zero(), mode_a, mode_b);
    }

    fn run_exhaustive_test<I: IntegerType + BitXor<Output = I>>(mode_a: Mode, mode_b: Mode)
    where
        RangeInclusive<I>: Iterator<Item = I>,
    {
        for first in I::MIN..=I::MAX {
            for second in I::MIN..=I::MAX {
                let first = console::Integer::<_, I>::new(first);
                let second = console::Integer::<_, I>::new(second);

                let name = format!("BitXor: ({first} ^ {second})");
                check_bitxor::<I>(&name, first, second, mode_a, mode_b);
            }
        }
    }

    test_integer_binary!(run_test, i8, bitxor);
    test_integer_binary!(run_test, i16, bitxor);
    test_integer_binary!(run_test, i32, bitxor);
    test_integer_binary!(run_test, i64, bitxor);
    test_integer_binary!(run_test, i128, bitxor);

    test_integer_binary!(run_test, u8, bitxor);
    test_integer_binary!(run_test, u16, bitxor);
    test_integer_binary!(run_test, u32, bitxor);
    test_integer_binary!(run_test, u64, bitxor);
    test_integer_binary!(run_test, u128, bitxor);

    test_integer_binary!(#[ignore], run_exhaustive_test, u8, bitxor, exhaustive);
    test_integer_binary!(#[ignore], run_exhaustive_test, i8, bitxor, exhaustive);
}
