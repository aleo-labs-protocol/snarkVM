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

impl<E: Environment, I: IntegerType, M: Magnitude> Metrics<dyn PowWrapped<Integer<E, M>, Output = Integer<E, I>>>
    for Integer<E, I>
{
    type Case = (CircuitType<Integer<E, I>>, CircuitType<Integer<E, M>>);

    #[rustfmt::skip]
    fn count(case: &Self::Case) -> Count {
        let (n, m) = (I::BITS, M::BITS);

        // The cost of one loop iteration with a variable `self`, as `(constants, private, constraints)`:
        //  - `lead`: `result` is still the constant one.
        //  - `step`: `result` is a variable and `bit` is a constant.
        // A variable `bit` adds `n` private variables and `n` constraints to each iteration.
        let (lead, step) = ((n, (3 * n / 2) + 1, (3 * n / 2) + 2), (0, (3 * n) + 8, (3 * n) + 10));

        match (&case.0, &case.1) {
            (CircuitType::Constant(_), CircuitType::Constant(_)) => Count::is(n, 0, 0, 0),
            (_, CircuitType::Constant(exponent)) => {
                // `result` is the constant one up to and including the iteration of the top set bit, or throughout for zero.
                let num_lead = m - exponent.eject_value().to_bits_le().iter().rposition(|bit| *bit).unwrap_or(0) as u64;
                let num_steps = m - num_lead;
                Count::is(
                    n + (num_lead * lead.0) + (num_steps * step.0),
                    0,
                    (num_lead * lead.1) + (num_steps * step.1),
                    (num_lead * lead.2) + (num_steps * step.2),
                )
            }
            (CircuitType::Constant(base), _) => {
                // After the first iteration, the bits of `result` are constant where `self` and one agree.
                // A constant half of `result` makes the second squaring cheaper.
                // A zero `self` makes each product with `self` a constant.
                let bits = base.eject_value().to_bits_le();
                let (lower, upper) = bits.split_at(bits.len() / 2);
                let upper_is_zero = upper.iter().all(|bit| !bit);
                let lower_is_one = lower.iter().enumerate().all(|(i, bit)| *bit == (i == 0));
                let is_zero = upper_is_zero && lower.iter().all(|bit| !bit);

                match (lower_is_one, upper_is_zero, is_zero) {
                    (true, true, _) => Count::is((3 * n) + ((m - 1) * 2 * n), 0, 0, 0),
                    (_, _, true) => Count::is((3 * n) + ((m - 1) * ((3 * n / 2) + 1)), 0, ((m - 1) * ((5 * n / 2) + 4)) - 2, ((m - 1) * ((5 * n / 2) + 5)) - 2),
                    (true, false, _) => Count::is(3 * n, 0, ((m - 1) * ((4 * n) + 5)) - 3, ((m - 1) * ((4 * n) + 7)) - 3),
                    (false, true, _) => Count::is(3 * n, 0, ((m - 1) * ((4 * n) + 5)) - 2, ((m - 1) * ((4 * n) + 7)) - 2),
                    (false, false, _) => Count::is(3 * n, 0, (m - 1) * ((4 * n) + 5), (m - 1) * ((4 * n) + 7)),
                }
            }
            (_, _) => Count::is(
                n + lead.0 + ((m - 1) * step.0),
                0,
                lead.1 + ((m - 1) * step.1) + (m * n),
                lead.2 + ((m - 1) * step.2) + (m * n),
            ),
        }
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> OutputMode<dyn PowWrapped<Integer<E, M>, Output = Integer<E, I>>>
    for Integer<E, I>
{
    type Case = (CircuitType<Integer<E, I>>, CircuitType<Integer<E, M>>);

    fn output_mode(case: &Self::Case) -> Mode {
        match (&case.0, &case.1) {
            (CircuitType::Constant(_), CircuitType::Constant(_)) => Mode::Constant,
            // `result` stays the constant one.
            (CircuitType::Constant(base), _) if base.eject_value().is_one() => Mode::Constant,
            (_, CircuitType::Constant(exponent)) if exponent.eject_value().is_zero() => Mode::Constant,
            (_, _) => Mode::Private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    use core::{ops::RangeInclusive, panic::RefUnwindSafe};

    // Lowered to 4; we run (~7 * ITERATIONS) cases for most tests.
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
            assert_count!(PowWrapped(Integer<I>, Integer<M>) => Integer<I>, &(CircuitType::from(&a), CircuitType::from(&b)));
            assert_output_mode!(PowWrapped(Integer<I>, Integer<M>) => Integer<I>, &(CircuitType::from(&a), CircuitType::from(&b)), candidate);
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

            let name = format!("Zero Base: {mode_a} ** {mode_b} {i}");
            check_pow::<I, M>(&name, console::Integer::zero(), second, mode_a, mode_b);

            let name = format!("One Base: {mode_a} ** {mode_b} {i}");
            check_pow::<I, M>(&name, console::Integer::one(), second, mode_a, mode_b);

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
