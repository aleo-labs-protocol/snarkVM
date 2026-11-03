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

impl<E: Environment, I: IntegerType> MulWrapped<Self> for Integer<E, I> {
    type Output = Self;

    #[inline]
    fn mul_wrapped(&self, other: &Integer<E, I>) -> Self::Output {
        // Determine the variable mode.
        if self.is_constant() && other.is_constant() {
            // Compute the product and return the new constant.
            witness!(|self, other| console::Integer::new(self.wrapping_mul(&other)))
        } else {
            // Perform multiplication by decomposing it into operations on its upper and lower bits.
            // See this page for reference: https://en.wikipedia.org/wiki/Karatsuba_algorithm.
            // We follow the naming convention given in the `Basic Step` section of the cited page.
            // Note that currently here we perform Babbage multiplication, not Karatsuba multiplication;
            // however, since we do not need to calculate z2 here,
            // Babbage involves three multiplication, same as Karatsuba.
            // For integers with size less than 128, this algorithm saves approximately 0.5 * I::BITS
            // constraints compared to a field multiplication.
            let x_1 = Field::from_bits_le(&self.bits_le[(I::BITS as usize / 2)..]);
            let x_0 = Field::from_bits_le(&self.bits_le[..(I::BITS as usize / 2)]);
            let y_1 = Field::from_bits_le(&other.bits_le[(I::BITS as usize / 2)..]);
            let y_0 = Field::from_bits_le(&other.bits_le[..(I::BITS as usize / 2)]);

            let z_0 = &x_0 * &y_0;
            let z_1 = (&x_1 * &y_0) + (&x_0 * &y_1);

            let mut b_m_bits = vec![Boolean::constant(false); I::BITS as usize / 2];
            b_m_bits.push(Boolean::constant(true));

            let b_m = Field::from_bits_le(&b_m_bits);
            let z_0_plus_scaled_z_1 = &z_0 + (&z_1 * &b_m);

            let mut bits_le = z_0_plus_scaled_z_1.to_lower_bits_le(I::BITS as usize + I::BITS as usize / 2 + 1);

            // Remove any carry bits.
            bits_le.truncate(I::BITS as usize);

            // Return the product of `self` and `other`, without the carry bits.
            Integer { bits_le, phantom: Default::default() }
        }
    }
}

impl<E: Environment, I: IntegerType> Metrics<dyn MulWrapped<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode, bool, bool);

    fn count(case: &Self::Case) -> Count {
        match (case.0, case.1, case.2, case.3) {
            (Mode::Constant, Mode::Constant, _, _) => Count::is(I::BITS, 0, 0, 0),
            (Mode::Constant, _, true, _) | (_, Mode::Constant, _, true) => {
                Count::is(I::BITS + (I::BITS / 2) + 1, 0, 0, 0)
            }
            (Mode::Constant, _, false, _) | (_, Mode::Constant, _, false) => {
                Count::is(0, 0, I::BITS + (I::BITS / 2) + 1, I::BITS + (I::BITS / 2) + 2)
            }
            (_, _, _, _) => Count::is(0, 0, I::BITS + (I::BITS / 2) + 4, I::BITS + (I::BITS / 2) + 5),
        }
    }
}

impl<E: Environment, I: IntegerType> OutputMode<dyn MulWrapped<Integer<E, I>, Output = Integer<E, I>>>
    for Integer<E, I>
{
    type Case = (Mode, Mode, bool, bool);

    fn output_mode(case: &Self::Case) -> Mode {
        match (case.0, case.1, case.2, case.3) {
            (Mode::Constant, _, true, _) | (_, Mode::Constant, _, true) => Mode::Constant,
            (Mode::Constant, Mode::Constant, _, _) => Mode::Constant,
            (_, _, _, _) => Mode::Private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    use core::ops::RangeInclusive;

    const ITERATIONS: u64 = 10;

    fn check_mul<I: IntegerType>(
        name: &str,
        first: console::Integer<<Circuit as Environment>::Network, I>,
        second: console::Integer<<Circuit as Environment>::Network, I>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::<Circuit, I>::new(mode_b, second);
        let a_is_zero = a.is_zero().eject_value();
        let b_is_zero = b.is_zero().eject_value();
        let expected = first.wrapping_mul(&second);
        Circuit::scope(name, || {
            let candidate = a.mul_wrapped(&b);
            assert_eq!(expected, *candidate.eject_value());
            assert_eq!(console::Integer::new(expected), candidate.eject_value());
            assert_count!(MulWrapped(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b, a_is_zero, b_is_zero));
            assert_output_mode!(MulWrapped(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b, a_is_zero, b_is_zero), candidate);
        });
        Circuit::reset();
    }

    fn run_test<I: IntegerType>(mode_a: Mode, mode_b: Mode) {
        let rng = &mut TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(rng);
            let second = Uniform::rand(rng);

            let name = format!("Mul: {mode_a} * {mode_b} {i}");
            check_mul::<I>(&name, first, second, mode_a, mode_b);
            check_mul::<I>(&name, second, first, mode_a, mode_b); // Commute the operation.

            let name = format!("Double: {mode_a} * {mode_b} {i}");
            check_mul::<I>(&name, first, console::Integer::one() + console::Integer::one(), mode_a, mode_b);
            check_mul::<I>(&name, console::Integer::one() + console::Integer::one(), first, mode_a, mode_b); // Commute the operation.

            let name = format!("Square: {mode_a} * {mode_b} {i}");
            check_mul::<I>(&name, first, first, mode_a, mode_b);
        }

        // Check specific cases common to signed and unsigned integers.
        check_mul::<I>("1 * MAX", console::Integer::one(), console::Integer::MAX, mode_a, mode_b);
        check_mul::<I>("MAX * 1", console::Integer::MAX, console::Integer::one(), mode_a, mode_b);
        check_mul::<I>("1 * MIN", console::Integer::one(), console::Integer::MIN, mode_a, mode_b);
        check_mul::<I>("MIN * 1", console::Integer::MIN, console::Integer::one(), mode_a, mode_b);
        check_mul::<I>("0 * MAX", console::Integer::zero(), console::Integer::MAX, mode_a, mode_b);
        check_mul::<I>("MAX * 0", console::Integer::MAX, console::Integer::zero(), mode_a, mode_b);
        check_mul::<I>("0 * MIN", console::Integer::zero(), console::Integer::MIN, mode_a, mode_b);
        check_mul::<I>("MIN * 0", console::Integer::MIN, console::Integer::zero(), mode_a, mode_b);
        check_mul::<I>("1 * 1", console::Integer::one(), console::Integer::one(), mode_a, mode_b);

        // Check common overflow cases.
        check_mul::<I>(
            "MAX * 2",
            console::Integer::MAX,
            console::Integer::one() + console::Integer::one(),
            mode_a,
            mode_b,
        );
        check_mul::<I>(
            "2 * MAX",
            console::Integer::one() + console::Integer::one(),
            console::Integer::MAX,
            mode_a,
            mode_b,
        );

        // Check additional corner cases for signed integers.
        if I::is_signed() {
            check_mul::<I>("MAX * -1", console::Integer::MAX, -console::Integer::one(), mode_a, mode_b);
            check_mul::<I>("-1 * MAX", -console::Integer::one(), console::Integer::MAX, mode_a, mode_b);
            check_mul::<I>("MIN * -1", console::Integer::MIN, -console::Integer::one(), mode_a, mode_b);
            check_mul::<I>("-1 * MIN", -console::Integer::one(), console::Integer::MIN, mode_a, mode_b);
            check_mul::<I>(
                "MIN * -2",
                console::Integer::MIN,
                -console::Integer::one() - console::Integer::one(),
                mode_a,
                mode_b,
            );
            check_mul::<I>(
                "-2 * MIN",
                -console::Integer::one() - console::Integer::one(),
                console::Integer::MIN,
                mode_a,
                mode_b,
            );
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

                let name = format!("Mul: ({first} * {second})");
                check_mul::<I>(&name, first, second, mode_a, mode_b);
            }
        }
    }

    test_integer_binary!(run_test, i8, times);
    test_integer_binary!(run_test, i16, times);
    test_integer_binary!(run_test, i32, times);
    test_integer_binary!(run_test, i64, times);
    test_integer_binary!(run_test, i128, times);

    test_integer_binary!(run_test, u8, times);
    test_integer_binary!(run_test, u16, times);
    test_integer_binary!(run_test, u32, times);
    test_integer_binary!(run_test, u64, times);
    test_integer_binary!(run_test, u128, times);

    test_integer_binary!(#[ignore], run_exhaustive_test, u8, times, exhaustive);
    test_integer_binary!(#[ignore], run_exhaustive_test, i8, times, exhaustive);
}
