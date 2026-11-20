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

impl<E: Environment, I: IntegerType> AbsWrapped for Integer<E, I> {
    type Output = Integer<E, I>;

    fn abs_wrapped(self) -> Self::Output {
        (&self).abs_wrapped()
    }
}

impl<E: Environment, I: IntegerType> AbsWrapped for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn abs_wrapped(self) -> Self::Output {
        match I::is_signed() {
            true => Integer::ternary(self.msb(), &Integer::zero().sub_wrapped(self), self),
            false => self.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    use core::{ops::RangeInclusive, panic::UnwindSafe};

    const ITERATIONS: u64 = 10;

    fn check_abs<I: IntegerType + UnwindSafe>(
        name: &str,
        value: console::Integer<<Circuit as Environment>::Network, I>,
        mode: Mode,
    ) {
        let a = Integer::<Circuit, I>::new(mode, value);
        let expected = value.wrapping_abs();
        Circuit::scope(name, || {
            let candidate = a.abs_wrapped();
            assert_eq!(expected, *candidate.eject_value());
            assert_eq!(console::Integer::new(expected), candidate.eject_value());
            assert_scope!();
        });
        Circuit::reset();
    }

    fn run_test<I: IntegerType + UnwindSafe>(mode: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let name = format!("Abs: {mode} {i}");
            let value = Uniform::rand(&mut rng);
            check_abs::<I>(&name, value, mode);
        }

        // Check the 0 case.
        let name = format!("Abs: {mode} zero");
        check_abs::<I>(&name, console::Integer::zero(), mode);

        // Check the 1 case.
        let name = format!("Abs: {mode} one");
        check_abs::<I>(&name, console::Integer::one(), mode);

        // Check the console::Integer::MIN (wrapped) case.
        let name = format!("Abs: {mode} one");
        check_abs::<I>(&name, console::Integer::MIN, mode);
    }

    fn run_exhaustive_test<I: IntegerType + UnwindSafe>(mode: Mode)
    where
        RangeInclusive<I>: Iterator<Item = I>,
    {
        for value in I::MIN..=I::MAX {
            let value = console::Integer::<_, I>::new(value);

            let name = format!("Abs: {mode}");
            check_abs::<I>(&name, value, mode);
        }
    }

    test_integer_unary!(run_test, i8, equals);
    test_integer_unary!(run_test, i16, equals);
    test_integer_unary!(run_test, i32, equals);
    test_integer_unary!(run_test, i64, equals);
    test_integer_unary!(run_test, i128, equals);

    test_integer_unary!(run_test, u8, equals);
    test_integer_unary!(run_test, u16, equals);
    test_integer_unary!(run_test, u32, equals);
    test_integer_unary!(run_test, u64, equals);
    test_integer_unary!(run_test, u128, equals);

    test_integer_unary!(#[ignore], run_exhaustive_test, u8, equals, exhaustive);
    test_integer_unary!(#[ignore], run_exhaustive_test, i8, equals, exhaustive);
}
