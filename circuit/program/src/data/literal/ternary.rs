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

impl<A: Aleo> Ternary for Literal<A> {
    type Boolean = Boolean<A>;
    type Output = Self;

    /// Returns `first` if `condition` is `true`, otherwise returns `second`.
    /// The `first` and `second` literals must be the same variant, and must be a variant for which
    /// ternary selection is supported. Callers are expected to enforce this via type-checking
    /// before invocation; mismatched or unsupported variants are treated as unreachable.
    fn ternary(condition: &<Self as Ternary>::Boolean, first: &Self, second: &Self) -> <Self as Ternary>::Output {
        match (first, second) {
            (Self::Address(a), Self::Address(b)) => Self::Address(Address::ternary(condition, a, b)),
            (Self::Boolean(a), Self::Boolean(b)) => Self::Boolean(Boolean::ternary(condition, a, b)),
            (Self::Field(a), Self::Field(b)) => Self::Field(Field::ternary(condition, a, b)),
            (Self::Group(a), Self::Group(b)) => Self::Group(Group::ternary(condition, a, b)),
            (Self::I8(a), Self::I8(b)) => Self::I8(I8::ternary(condition, a, b)),
            (Self::I16(a), Self::I16(b)) => Self::I16(I16::ternary(condition, a, b)),
            (Self::I32(a), Self::I32(b)) => Self::I32(I32::ternary(condition, a, b)),
            (Self::I64(a), Self::I64(b)) => Self::I64(I64::ternary(condition, a, b)),
            (Self::I128(a), Self::I128(b)) => Self::I128(I128::ternary(condition, a, b)),
            (Self::U8(a), Self::U8(b)) => Self::U8(U8::ternary(condition, a, b)),
            (Self::U16(a), Self::U16(b)) => Self::U16(U16::ternary(condition, a, b)),
            (Self::U32(a), Self::U32(b)) => Self::U32(U32::ternary(condition, a, b)),
            (Self::U64(a), Self::U64(b)) => Self::U64(U64::ternary(condition, a, b)),
            (Self::U128(a), Self::U128(b)) => Self::U128(U128::ternary(condition, a, b)),
            (Self::Scalar(a), Self::Scalar(b)) => Self::Scalar(Scalar::ternary(condition, a, b)),
            (Self::Signature(a), Self::Signature(b)) => Self::Signature(Ternary::ternary(condition, a, b)),
            (Self::Identifier(a), Self::Identifier(b)) => Self::Identifier(Ternary::ternary(condition, a, b)),
            _ => unreachable!("ternary operands must be the same literal variant after type-checking"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Circuit;
    use snarkvm_utilities::{TestRng, Uniform};

    fn check_dispatch(
        first: console::Literal<<Circuit as Environment>::Network>,
        second: console::Literal<<Circuit as Environment>::Network>,
    ) {
        for condition in [false, true] {
            let expected = console::Literal::ternary(&console::Boolean::new(condition), &first, &second);
            assert_eq!(if condition { &first } else { &second }, &expected);
            for condition_mode in [Mode::Constant, Mode::Public, Mode::Private] {
                for first_mode in [Mode::Constant, Mode::Public, Mode::Private] {
                    for second_mode in [Mode::Constant, Mode::Public, Mode::Private] {
                        let condition = Boolean::<Circuit>::new(condition_mode, condition);
                        let first = Literal::<Circuit>::new(first_mode, first.clone());
                        let second = Literal::<Circuit>::new(second_mode, second.clone());
                        Circuit::scope("literal ternary", || {
                            let candidate = Literal::ternary(&condition, &first, &second);
                            assert_eq!(expected, candidate.eject_value());
                            assert!(Circuit::is_satisfied());
                        });
                        Circuit::reset();
                    }
                }
            }
        }
    }

    #[test]
    fn test_literal_ternary_dispatches_all_supported_variants() {
        let mut rng = TestRng::default();
        for literal_type in [
            console::LiteralType::Address,
            console::LiteralType::Boolean,
            console::LiteralType::Field,
            console::LiteralType::Group,
            console::LiteralType::I8,
            console::LiteralType::I16,
            console::LiteralType::I32,
            console::LiteralType::I64,
            console::LiteralType::I128,
            console::LiteralType::U8,
            console::LiteralType::U16,
            console::LiteralType::U32,
            console::LiteralType::U64,
            console::LiteralType::U128,
            console::LiteralType::Scalar,
            console::LiteralType::Signature,
            console::LiteralType::Identifier,
        ] {
            check_dispatch(
                console::Literal::sample(literal_type, &mut rng),
                console::Literal::sample(literal_type, &mut rng),
            );
        }
    }

    #[test]
    #[should_panic(expected = "ternary operands must be the same literal variant")]
    fn test_literal_ternary_variant_mismatch_panics() {
        let mut rng = TestRng::default();
        let first = Literal::<Circuit>::Field(Field::new(Mode::Private, Uniform::rand(&mut rng)));
        let second = Literal::<Circuit>::Boolean(Boolean::new(Mode::Private, true));
        let cond = Boolean::<Circuit>::new(Mode::Private, false);
        let _ = Literal::ternary(&cond, &first, &second);
    }
}
