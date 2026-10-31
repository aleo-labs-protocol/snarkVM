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

    fn check_dispatch(first: Literal<Circuit>, second: Literal<Circuit>) {
        let true_ = Boolean::<Circuit>::new(Mode::Private, true);
        let false_ = Boolean::<Circuit>::new(Mode::Private, false);
        assert_eq!(first.eject_value(), Literal::ternary(&true_, &first, &second).eject_value());
        assert_eq!(second.eject_value(), Literal::ternary(&false_, &first, &second).eject_value());
    }

    #[test]
    fn test_literal_ternary_dispatches_all_supported_variants() {
        let mut rng = TestRng::default();

        check_dispatch(
            Literal::Address(Address::new(Mode::Private, Uniform::rand(&mut rng))),
            Literal::Address(Address::new(Mode::Private, Uniform::rand(&mut rng))),
        );
        check_dispatch(
            Literal::Boolean(Boolean::new(Mode::Private, true)),
            Literal::Boolean(Boolean::new(Mode::Private, false)),
        );
        check_dispatch(
            Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
            Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
        );
        check_dispatch(
            Literal::Group(Group::new(Mode::Private, Uniform::rand(&mut rng))),
            Literal::Group(Group::new(Mode::Private, Uniform::rand(&mut rng))),
        );
        check_dispatch(
            Literal::I8(I8::new(Mode::Private, Uniform::rand(&mut rng))),
            Literal::I8(I8::new(Mode::Private, Uniform::rand(&mut rng))),
        );
        check_dispatch(
            Literal::I16(I16::new(Mode::Private, Uniform::rand(&mut rng))),
            Literal::I16(I16::new(Mode::Private, Uniform::rand(&mut rng))),
        );
        check_dispatch(
            Literal::I32(I32::new(Mode::Private, Uniform::rand(&mut rng))),
            Literal::I32(I32::new(Mode::Private, Uniform::rand(&mut rng))),
        );
        check_dispatch(
            Literal::I64(I64::new(Mode::Private, Uniform::rand(&mut rng))),
            Literal::I64(I64::new(Mode::Private, Uniform::rand(&mut rng))),
        );
        check_dispatch(
            Literal::I128(I128::new(Mode::Private, Uniform::rand(&mut rng))),
            Literal::I128(I128::new(Mode::Private, Uniform::rand(&mut rng))),
        );
        check_dispatch(
            Literal::U8(U8::new(Mode::Private, Uniform::rand(&mut rng))),
            Literal::U8(U8::new(Mode::Private, Uniform::rand(&mut rng))),
        );
        check_dispatch(
            Literal::U16(U16::new(Mode::Private, Uniform::rand(&mut rng))),
            Literal::U16(U16::new(Mode::Private, Uniform::rand(&mut rng))),
        );
        check_dispatch(
            Literal::U32(U32::new(Mode::Private, Uniform::rand(&mut rng))),
            Literal::U32(U32::new(Mode::Private, Uniform::rand(&mut rng))),
        );
        check_dispatch(
            Literal::U64(U64::new(Mode::Private, Uniform::rand(&mut rng))),
            Literal::U64(U64::new(Mode::Private, Uniform::rand(&mut rng))),
        );
        check_dispatch(
            Literal::U128(U128::new(Mode::Private, Uniform::rand(&mut rng))),
            Literal::U128(U128::new(Mode::Private, Uniform::rand(&mut rng))),
        );
        check_dispatch(
            Literal::Scalar(Scalar::new(Mode::Private, Uniform::rand(&mut rng))),
            Literal::Scalar(Scalar::new(Mode::Private, Uniform::rand(&mut rng))),
        );
        check_dispatch(
            Literal::Identifier(Box::new(IdentifierLiteral::new(
                Mode::Private,
                console::IdentifierLiteral::rand(&mut rng),
            ))),
            Literal::Identifier(Box::new(IdentifierLiteral::new(
                Mode::Private,
                console::IdentifierLiteral::rand(&mut rng),
            ))),
        );
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
