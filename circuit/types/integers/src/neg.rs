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

impl<E: Environment, I: IntegerType> Neg for Integer<E, I> {
    type Output = Integer<E, I>;

    /// Performs the unary `-` operation.
    fn neg(self) -> Self::Output {
        (&self).neg()
    }
}

impl<E: Environment, I: IntegerType> Neg for &Integer<E, I> {
    type Output = Integer<E, I>;

    /// Performs the unary `-` operation.
    fn neg(self) -> Self::Output {
        match I::is_signed() {
            // Note: This addition must be checked as `-Integer::MIN` is an invalid operation.
            true => Integer::one().add_checked(&!self),
            // Note: `halt` is necessary since negation is not defined for unsigned integers.
            false => E::halt("Attempted to negate an unsigned integer"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    use test_utilities::*;

    use core::{ops::RangeInclusive, panic::UnwindSafe};

    const ITERATIONS: u64 = 10;

    fn check_neg<I: IntegerType + UnwindSafe + Neg<Output = I>>(
        name: &str,
        value: console::Integer<<Circuit as Environment>::Network, I>,
        mode: Mode,
    ) {
        let a = Integer::<Circuit, I>::new(mode, value);
        match value.checked_neg() {
            Some(expected) => Circuit::scope(name, || {
                let candidate = a.neg();
                assert_eq!(expected, *candidate.eject_value());
                assert_eq!(console::Integer::new(expected), candidate.eject_value());
                assert_scope!();
            }),
            None => match mode {
                Mode::Constant => check_unary_operation_halts(a, |a: Integer<Circuit, I>| a.neg()),
                _ => Circuit::scope(name, || {
                    let _candidate = a.neg();
                    assert_scope_fails!();
                }),
            },
        }
        Circuit::reset();
    }

    fn run_test<I: IntegerType + UnwindSafe + Neg<Output = I>>(mode: Mode) {
        // Check the 0 case.
        check_neg::<I>(&format!("Neg: {mode} zero"), console::Integer::zero(), mode);
        // Check the 1 case.
        check_neg::<I>(&format!("Neg: {mode} one"), -console::Integer::one(), mode);
        // Check random values.
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let value = Uniform::rand(&mut rng);
            check_neg::<I>(&format!("Neg: {mode} {i}"), value, mode);
        }
    }

    fn assert_unsigned_neg_halts<I: IntegerType + UnwindSafe>(mode: Mode) {
        let candidate = Integer::<Circuit, I>::new(mode, Uniform::rand(&mut TestRng::default()));
        let operation = std::panic::catch_unwind(|| candidate.neg());
        assert!(operation.is_err());
    }

    fn run_exhaustive_test<I: IntegerType + UnwindSafe + Neg<Output = I>>(mode: Mode)
    where
        RangeInclusive<I>: Iterator<Item = I>,
    {
        for value in I::MIN..=I::MAX {
            let value = console::Integer::<_, I>::new(value);

            let name = format!("Neg: {mode}");
            check_neg::<I>(&name, value, mode);
        }
    }

    test_integer_unary!(run_test, i8, neg);
    test_integer_unary!(run_test, i16, neg);
    test_integer_unary!(run_test, i32, neg);
    test_integer_unary!(run_test, i64, neg);
    test_integer_unary!(run_test, i128, neg);

    test_integer_unary!(assert_unsigned_neg_halts, u8, neg);
    test_integer_unary!(assert_unsigned_neg_halts, u16, neg);
    test_integer_unary!(assert_unsigned_neg_halts, u32, neg);
    test_integer_unary!(assert_unsigned_neg_halts, u64, neg);
    test_integer_unary!(assert_unsigned_neg_halts, u128, neg);

    test_integer_unary!(#[ignore], assert_unsigned_neg_halts, u8, neg, exhaustive);
    test_integer_unary!(#[ignore], run_exhaustive_test, i8, neg, exhaustive);
}
