// Copyright (c) 2019-2025 Provable Inc.
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

impl<E: Environment, I: IntegerType> SquareRoot for Integer<E, I> {
    type Output = Self;

    /// Returns the square root of `self`.
    fn square_root(&self) -> Self::Output {
        // If the value is constant, eject it an compute it directly.
        if self.is_constant() {
            match self.eject_value().square_root() {
                Ok(value) => return Integer::constant(value),
                Err(e) => E::halt(e.to_string()),
            }
        }

        // A helper function to check that a square root is valid.
        fn check_unsigned_square_root_is_valid<E: Environment, I: IntegerType>(
            root: &Integer<E, I>,
            square: &Integer<E, I>,
        ) {
            // Check that the integer type is unsigned.
            debug_assert!(!I::is_signed());

            // Ensure `root` * `root` <= `square`.
            let root_squared = root.mul_checked(root);
            let root_squared_less_than_or_equal_sqaure = root_squared.is_less_than_or_equal(square);
            E::assert(root_squared_less_than_or_equal_sqaure);

            // Ensure (`root` + 1) * (`root` + 1) > `square`.
            // The computed value will overflow for the largest valid square root.
            // In that case we know that `(root` + 1) * (`root` + 1) equals 0.
            // Concretely,
            // - for u8, the largest square root is 15. 16^2 = 256 which overflows to 0.
            // - for u16, the largest square root is 255. 256^2 = 65536 which overflows to 0.
            // - for u32, the largest square root is 65535. 65536^2 = 4294967296 which overflows to 0.
            // - for u64, the largest square root is 4294967295. 4294967296^2 = 18446744073709551616 which overflows to 0.
            // - for u128, the largest square root is 18446744073709551615. 18446744073709551616^2 = 340282366920938463463374607431768211456 which overflows to 0.
            let root_plus_one = root.add_checked(&Integer::one());
            let root_plus_one_squared = root_plus_one.mul_wrapped(&root_plus_one);
            let root_plus_one_squared_greater_than_square = root_plus_one_squared.is_greater_than(square);
            let root_plus_one_squared_equals_zero = root_plus_one_squared.is_equal(&Integer::zero());
            E::assert(root_plus_one_squared_greater_than_square | root_plus_one_squared_equals_zero);
        }

        match I::is_signed() {
            false => {
                // Witness the square root.
                let square_root: Integer<E, I> = witness!(|self| match self.square_root() {
                    Ok(square_root) => square_root,
                    _ => console::Integer::zero(),
                });
                // Enforce that the square root is valid.
                check_unsigned_square_root_is_valid(&square_root, self);

                square_root
            }
            true => {
                // Ensure that the input is non-negative.
                E::assert(self.is_greater_than_or_equal(&Integer::zero()));
                // Cast the signed itneger to its unsigned variant.
                let unsigned_self = self.clone().cast_as_dual();
                // Witness the square root.
                let square_root_unsigned: Integer<E, I::Dual> =
                    witness!(|unsigned_self| match unsigned_self.square_root() {
                        Ok(square_root) => square_root,
                        _ => console::Integer::zero(),
                    });
                // Enforce that the square root is valid.
                check_unsigned_square_root_is_valid(&square_root_unsigned, &unsigned_self);
                // Cast the unsigned square root back to signed.
                Self::from_bits_le(&square_root_unsigned.to_bits_le())
            }
        }
    }
}

impl<E: Environment, I: IntegerType> Metrics<dyn SquareRoot<Output = Integer<E, I>>> for Integer<E, I> {
    type Case = Mode;

    fn count(case: &Self::Case) -> Count {
        // For 128-bit integers, `mul_checked` uses Karatsuba multiplication which has an additional 68 private variables and 70 constraints.
        let mul_checked_adjustment = if I::BITS == 128 { (68, 70) } else { (0, 0) };

        match I::is_signed() {
            true => match case {
                Mode::Constant => Count::is(I::BITS, 0, 0, 0),
                _ => Count::is(
                    6 * I::BITS,
                    0,
                    (15 * I::BITS + 22) / 2 + mul_checked_adjustment.0,
                    (15 * I::BITS + 40) / 2 + mul_checked_adjustment.1,
                ),
            },
            false => match case {
                Mode::Constant => Count::is(I::BITS, 0, 0, 0),
                _ => Count::is(
                    4 * I::BITS,
                    0,
                    (13 * I::BITS + 18) / 2 + mul_checked_adjustment.0,
                    (13 * I::BITS + 32) / 2 + mul_checked_adjustment.1,
                ),
            },
        }
    }
}

impl<E: Environment, I: IntegerType> OutputMode<dyn SquareRoot<Output = Integer<E, I>>> for Integer<E, I> {
    type Case = Mode;

    fn output_mode(case: &Self::Case) -> Mode {
        match case.is_constant() {
            true => Mode::Constant,
            false => Mode::Private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    use test_utilities::*;

    use core::{ops::RangeInclusive, panic::UnwindSafe};

    const ITERATIONS: u64 = 1000;

    fn check_square_root<I: IntegerType + UnwindSafe>(
        name: &str,
        value: console::Integer<<Circuit as Environment>::Network, I>,
        mode: Mode,
    ) {
        let a = Integer::<Circuit, I>::new(mode, value);
        match value.square_root() {
            Ok(expected) => Circuit::scope(name, || {
                let candidate = a.square_root();
                assert_eq!(*expected, *candidate.eject_value());
                assert_eq!(expected, candidate.eject_value());
                assert_count!(SquareRoot(Integer<I>) => Integer<I>, &mode);
                assert_output_mode!(SquareRoot(Integer<I>) => Integer<I>, &mode, candidate);
            }),
            Err(_) => match mode {
                Mode::Constant => check_unary_operation_halts(a, |a: Integer<Circuit, I>| a.square_root()),
                _ => Circuit::scope(name, || {
                    let _candidate = a.square_root();
                    assert_count_fails!(SquareRoot(Integer<I>) => Integer<I>, &mode);
                }),
            },
        }
        Circuit::reset();
    }

    fn run_test<I: IntegerType + UnwindSafe>(mode: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let name = format!("Square Root: {mode} {i}");
            let value = Uniform::rand(&mut rng);
            check_square_root::<I>(&name, value, mode);
        }

        // Check the 0 case.
        let name = format!("Square Root: {mode} zero");
        check_square_root::<I>(&name, console::Integer::zero(), mode);

        // Check the 1 case.
        let name = format!("Square Root: {mode} one");
        check_square_root::<I>(&name, console::Integer::one(), mode);

        // Check the console::Integer::MIN case.
        let name = format!("Square Root: {mode} one");
        check_square_root::<I>(&name, console::Integer::MIN, mode);

        // Check the console::Integer::MAX case.
        let name = format!("Square Root: {mode} max");
        check_square_root::<I>(&name, console::Integer::MAX, mode);
    }

    fn run_exhaustive_test<I: IntegerType + UnwindSafe>(mode: Mode)
    where
        RangeInclusive<I>: Iterator<Item = I>,
    {
        for value in I::MIN..=I::MAX {
            let value = console::Integer::<_, I>::new(value);

            let name = format!("Square Root: {mode}");
            check_square_root::<I>(&name, value, mode);
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
