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

impl<E: Environment, I: IntegerType, M: Magnitude> Shr<Integer<E, M>> for Integer<E, I> {
    type Output = Self;

    fn shr(self, rhs: Integer<E, M>) -> Self::Output {
        self >> &rhs
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> Shr<Integer<E, M>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn shr(self, rhs: Integer<E, M>) -> Self::Output {
        self >> &rhs
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> Shr<&Integer<E, M>> for Integer<E, I> {
    type Output = Self;

    fn shr(self, rhs: &Integer<E, M>) -> Self::Output {
        &self >> rhs
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> Shr<&Integer<E, M>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn shr(self, rhs: &Integer<E, M>) -> Self::Output {
        let mut output = self.clone();
        output >>= rhs;
        output
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> ShrAssign<Integer<E, M>> for Integer<E, I> {
    fn shr_assign(&mut self, rhs: Integer<E, M>) {
        *self >>= &rhs
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> ShrAssign<&Integer<E, M>> for Integer<E, I> {
    fn shr_assign(&mut self, rhs: &Integer<E, M>) {
        // Stores the result of `self` >> `other` in `self`.
        *self = self.shr_checked(rhs);
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> ShrChecked<Integer<E, M>> for Integer<E, I> {
    type Output = Self;

    #[inline]
    fn shr_checked(&self, rhs: &Integer<E, M>) -> Self::Output {
        // Determine the variable mode.
        if self.is_constant() && rhs.is_constant() {
            // This cast is safe since `Magnitude`s can only be `u8`, `u16`, or `u32`.
            match self.eject_value().checked_shr(rhs.eject_value().to_u32().unwrap()) {
                Some(value) => Integer::new(Mode::Constant, console::Integer::new(value)),
                None => E::halt("Constant shifted by constant exceeds the allowed bitwidth."),
            }
        } else {
            // Determine the index where the first upper bit of the RHS must be zero.
            // There is at least one trailing zero, as I::BITS = 8, 16, 32, 64, or 128.
            let trailing_zeros_index = I::BITS.trailing_zeros() as usize;

            // Check that the upper bits of the RHS are nonzero.
            Boolean::assert_bits_are_zero(&rhs.bits_le[trailing_zeros_index..]);

            // Perform a wrapping shift right.
            self.shr_wrapped(rhs)
        }
    }
}

impl<E: Environment, I: IntegerType> Metrics<dyn Shr<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn count(case: &Self::Case) -> Count {
        <Self as Metrics<dyn DivChecked<Integer<E, I>, Output = Integer<E, I>>>>::count(case)
    }
}

impl<E: Environment, I: IntegerType> OutputMode<dyn Shr<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn output_mode(case: &Self::Case) -> Mode {
        <Self as OutputMode<dyn DivChecked<Integer<E, I>, Output = Integer<E, I>>>>::output_mode(case)
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> Metrics<dyn ShrChecked<Integer<E, M>, Output = Integer<E, I>>>
    for Integer<E, I>
{
    /// `(mode of self, mode of rhs, self is zero, rhs is zero)`, passed on to the `ShrWrapped` count.
    type Case = (Mode, Mode, bool, bool);

    fn count(case: &Self::Case) -> Count {
        match (case.0, case.1) {
            // Both constant: the output is a new constant.
            (Mode::Constant, Mode::Constant) => Count::is(I::BITS, 0, 0, 0),
            // Constant `rhs`: the check on `rhs` and the shift are free.
            (_, Mode::Constant) => Count::is(0, 0, 0, 0),
            // `shr_wrapped`, plus one constraint that the upper bits of `rhs` are zero.
            (_, _) => {
                let wrapped_count = count!(Integer<E, I>, ShrWrapped<Integer<E, M>, Output=Integer<E, I>>, case);
                wrapped_count + Count::is(0, 0, 0, 1)
            }
        }
    }
}

impl<E: Environment, I: IntegerType, M: Magnitude> OutputMode<dyn ShrChecked<Integer<E, M>, Output = Integer<E, I>>>
    for Integer<E, I>
{
    type Case = (Mode, Mode);

    fn output_mode(case: &Self::Case) -> Mode {
        match (case.0, case.1) {
            (Mode::Constant, Mode::Constant) => Mode::Constant,
            (mode_a, Mode::Constant) => mode_a,
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

    fn check_shr<I: IntegerType + RefUnwindSafe, M: Magnitude + RefUnwindSafe>(
        name: &str,
        first: console::Integer<<Circuit as Environment>::Network, I>,
        second: console::Integer<<Circuit as Environment>::Network, M>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::<Circuit, M>::new(mode_b, second);
        let a_is_zero = a.is_zero().eject_value();
        let b_is_zero = b.is_zero().eject_value();
        match first.checked_shr(second.to_u32().unwrap()) {
            Some(expected) => Circuit::scope(name, || {
                let candidate = a.shr_checked(&b);
                assert_eq!(expected, *candidate.eject_value());
                assert_eq!(console::Integer::new(expected), candidate.eject_value());
                assert_count!(ShrChecked(Integer<I>, Integer<M>) => Integer<I>, &(mode_a, mode_b, a_is_zero, b_is_zero));
                // assert_output_mode!(ShrChecked(Integer<I>, Integer<M>) => Integer<I>, &(mode_a, mode_b), candidate);
                assert!(Circuit::is_satisfied_in_scope(), "(is_satisfied_in_scope)");
            }),
            None => match (mode_a, mode_b) {
                (_, Mode::Constant) => check_operation_halts(&a, &b, Integer::shr_checked),
                _ => Circuit::scope(name, || {
                    let _candidate = a.shr_checked(&b);
                    // assert_count_fails!(ShrChecked(Integer<I>, Integer<M>) => Integer<I>, &(mode_a, mode_b));
                    assert!(!Circuit::is_satisfied_in_scope(), "(!is_satisfied_in_scope)");
                }),
            },
        };
        Circuit::reset();
    }

    fn run_test<I: IntegerType + RefUnwindSafe, M: Magnitude + RefUnwindSafe>(mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let name = format!("Shr: {mode_a} >> {mode_b} {i}");
            check_shr::<I, M>(&name, first, second, mode_a, mode_b);

            // Check that shift right by one is computed correctly.
            let name = format!("Half: {mode_a} >> {mode_b} {i}");
            check_shr::<I, M>(&name, first, console::Integer::one(), mode_a, mode_b);

            // Check that zero shifted right by `second` is computed correctly.
            let name = format!("Zero: {mode_a} >> {mode_b} {i}");
            check_shr::<I, M>(&name, console::Integer::zero(), second, mode_a, mode_b);
        }
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

                let name = format!("Shr: ({first} >> {second})");
                check_shr::<I, M>(&name, first, second, mode_a, mode_b);
            }
        }
    }

    test_integer_binary!(run_test, i8, u8, shr);
    test_integer_binary!(run_test, i8, u16, shr);
    test_integer_binary!(run_test, i8, u32, shr);

    test_integer_binary!(run_test, i16, u8, shr);
    test_integer_binary!(run_test, i16, u16, shr);
    test_integer_binary!(run_test, i16, u32, shr);

    test_integer_binary!(run_test, i32, u8, shr);
    test_integer_binary!(run_test, i32, u16, shr);
    test_integer_binary!(run_test, i32, u32, shr);

    test_integer_binary!(run_test, i64, u8, shr);
    test_integer_binary!(run_test, i64, u16, shr);
    test_integer_binary!(run_test, i64, u32, shr);

    test_integer_binary!(run_test, i128, u8, shr);
    test_integer_binary!(run_test, i128, u16, shr);
    test_integer_binary!(run_test, i128, u32, shr);

    test_integer_binary!(run_test, u8, u8, shr);
    test_integer_binary!(run_test, u8, u16, shr);
    test_integer_binary!(run_test, u8, u32, shr);

    test_integer_binary!(run_test, u16, u8, shr);
    test_integer_binary!(run_test, u16, u16, shr);
    test_integer_binary!(run_test, u16, u32, shr);

    test_integer_binary!(run_test, u32, u8, shr);
    test_integer_binary!(run_test, u32, u16, shr);
    test_integer_binary!(run_test, u32, u32, shr);

    test_integer_binary!(run_test, u64, u8, shr);
    test_integer_binary!(run_test, u64, u16, shr);
    test_integer_binary!(run_test, u64, u32, shr);

    test_integer_binary!(run_test, u128, u8, shr);
    test_integer_binary!(run_test, u128, u16, shr);
    test_integer_binary!(run_test, u128, u32, shr);

    test_integer_binary!(#[ignore], run_exhaustive_test, u8, u8, shr, exhaustive);
    test_integer_binary!(#[ignore], run_exhaustive_test, i8, u8, shr, exhaustive);
}
