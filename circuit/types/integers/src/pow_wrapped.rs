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

impl<E: Environment, I: IntegerType, M: Magnitude> PowWrapped<Integer<E, M>> for Integer<E, I> {
    type Output = Self;

    #[inline]
    fn pow_wrapped(&self, other: &Integer<E, M>) -> Self::Output {
        // Determine the variable mode.
        if self.is_constant() && other.is_constant() {
            // Compute the result and return the new constant.
            // This cast is safe since Magnitude other can only be `u8`, `u16`, or `u32`.
            witness!(|self, other| console::Integer::new(self.wrapping_pow(&other.to_u32().unwrap())))
        } else {
            let mut result = Self::one();
            for bit in other.bits_le.iter().rev() {
                result = result.mul_wrapped(&result);
                result = Self::ternary(bit, &result.mul_wrapped(self), &result);
            }
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    use core::{ops::RangeInclusive, panic::RefUnwindSafe};

    // Lowered to 4; we run (~6 * ITERATIONS) cases for most tests.
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
        let expected = first.wrapping_pow(&second.to_u32().unwrap());
        Circuit::scope(name, || {
            let candidate = a.pow_wrapped(&b);
            assert_eq!(expected, *candidate.eject_value());
            assert_eq!(console::Integer::new(expected), candidate.eject_value());
            assert!(Circuit::is_satisfied_in_scope(), "(is_satisfied_in_scope)");
        });
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
