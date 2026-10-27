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

impl<A: Aleo> Ternary for Plaintext<A> {
    type Boolean = Boolean<A>;
    type Output = Self;

    /// Returns `first` if `condition` is `true`, otherwise returns `second`.
    /// The `first` and `second` plaintexts must have the same shape: same variant, arrays of equal
    /// length with matching element shapes, or structs with matching keys in the same order.
    /// Callers are expected to enforce this via type-checking before invocation; mismatched shapes
    /// are treated as unreachable.
    fn ternary(condition: &<Self as Ternary>::Boolean, first: &Self, second: &Self) -> <Self as Ternary>::Output {
        match (first, second) {
            (Self::Literal(a, _), Self::Literal(b, _)) => {
                Self::Literal(Literal::ternary(condition, a, b), OnceCell::new())
            }
            (Self::Array(a, _), Self::Array(b, _)) if a.len() == b.len() => {
                let elements = a.iter().zip_eq(b.iter()).map(|(x, y)| Plaintext::ternary(condition, x, y)).collect();
                Self::Array(elements, OnceCell::new())
            }
            (Self::Struct(a, _), Self::Struct(b, _))
                if a.len() == b.len() && a.keys().zip(b.keys()).all(|(ka, kb)| ka == kb) =>
            {
                let fields = a
                    .iter()
                    .zip_eq(b.iter())
                    .map(|((key, x), (_, y))| (key.clone(), Plaintext::ternary(condition, x, y)))
                    .collect();
                Self::Struct(fields, OnceCell::new())
            }
            _ => unreachable!("ternary operands must have equivalent shape after type-checking"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Circuit;

    fn sample(mode: Mode, literal: &str) -> Plaintext<Circuit> {
        let primitive = console::Plaintext::<<Circuit as Environment>::Network>::from_str(literal).unwrap();
        Plaintext::new(mode, primitive)
    }

    fn check_both_branches(first: &Plaintext<Circuit>, second: &Plaintext<Circuit>) {
        let true_ = Boolean::<Circuit>::new(Mode::Private, true);
        let false_ = Boolean::<Circuit>::new(Mode::Private, false);
        assert_eq!(first.eject_value(), Plaintext::ternary(&true_, first, second).eject_value());
        assert_eq!(second.eject_value(), Plaintext::ternary(&false_, first, second).eject_value());
    }

    #[test]
    fn test_plaintext_ternary_literal() {
        let first = sample(Mode::Private, "1field");
        let second = sample(Mode::Private, "2field");
        check_both_branches(&first, &second);
    }

    #[test]
    fn test_plaintext_ternary_flat_array() {
        let first = sample(Mode::Private, "[ 1field, 2field, 3field ]");
        let second = sample(Mode::Private, "[ 4field, 5field, 6field ]");
        check_both_branches(&first, &second);
    }

    #[test]
    fn test_plaintext_ternary_nested_array() {
        let first = sample(Mode::Private, "[ [ 1u8, 2u8 ], [ 3u8, 4u8 ] ]");
        let second = sample(Mode::Private, "[ [ 5u8, 6u8 ], [ 7u8, 8u8 ] ]");
        check_both_branches(&first, &second);
    }

    #[test]
    fn test_plaintext_ternary_struct() {
        let first = sample(Mode::Private, "{ x: 1field, y: 2field }");
        let second = sample(Mode::Private, "{ x: 3field, y: 4field }");
        check_both_branches(&first, &second);
    }

    #[test]
    fn test_plaintext_ternary_struct_of_arrays() {
        let first = sample(Mode::Private, "{ a: [ 1u8, 2u8 ], b: 3field }");
        let second = sample(Mode::Private, "{ a: [ 4u8, 5u8 ], b: 6field }");
        check_both_branches(&first, &second);
    }

    #[test]
    fn test_plaintext_ternary_array_of_structs() {
        let first = sample(Mode::Private, "[ { x: 1field, y: 2field }, { x: 3field, y: 4field } ]");
        let second = sample(Mode::Private, "[ { x: 5field, y: 6field }, { x: 7field, y: 8field } ]");
        check_both_branches(&first, &second);
    }

    #[test]
    fn test_plaintext_ternary_array_constraint_counts() {
        let first = sample(Mode::Private, "[ 1field, 2field, 3field ]");
        let second = sample(Mode::Private, "[ 4field, 5field, 6field ]");
        let condition = Boolean::<Circuit>::new(Mode::Private, true);

        let expected_constraints = Circuit::scope("literal selections", || {
            let (Plaintext::Array(first, _), Plaintext::Array(second, _)) = (&first, &second) else {
                panic!("The test inputs must be arrays.");
            };
            for (first, second) in first.iter().zip_eq(second) {
                let (Plaintext::Literal(first, _), Plaintext::Literal(second, _)) = (first, second) else {
                    panic!("The test array elements must be literals.");
                };
                let _ = Literal::ternary(&condition, first, second);
            }
            assert!(Circuit::is_satisfied());
            Circuit::num_constraints_in_scope()
        });
        Circuit::scope("array selection", || {
            let candidate = Plaintext::ternary(&condition, &first, &second);
            assert_eq!(first.eject_value(), candidate.eject_value());
            assert_eq!(expected_constraints, Circuit::num_constraints_in_scope());
            assert!(Circuit::is_satisfied());
        });
        Circuit::reset();
    }

    #[test]
    #[should_panic(expected = "ternary operands must have equivalent shape")]
    fn test_plaintext_ternary_array_length_mismatch_panics() {
        let first = sample(Mode::Private, "[ 1field, 2field ]");
        let second = sample(Mode::Private, "[ 3field, 4field, 5field ]");
        let cond = Boolean::<Circuit>::new(Mode::Private, false);
        let _ = Plaintext::ternary(&cond, &first, &second);
    }

    #[test]
    #[should_panic(expected = "ternary operands must have equivalent shape")]
    fn test_plaintext_ternary_struct_key_order_mismatch_panics() {
        let first = sample(Mode::Private, "{ x: 1field, y: 2field }");
        let second = sample(Mode::Private, "{ y: 3field, x: 4field }");
        let cond = Boolean::<Circuit>::new(Mode::Private, false);
        let _ = Plaintext::ternary(&cond, &first, &second);
    }

    #[test]
    #[should_panic(expected = "ternary operands must have equivalent shape")]
    fn test_plaintext_ternary_variant_mismatch_panics() {
        let first = sample(Mode::Private, "1field");
        let second = sample(Mode::Private, "[ 1field ]");
        let cond = Boolean::<Circuit>::new(Mode::Private, false);
        let _ = Plaintext::ternary(&cond, &first, &second);
    }
}
