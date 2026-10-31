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

impl<N: Network> Ternary for Literal<N> {
    type Boolean = Boolean<N>;
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
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    fn check_dispatch(first: Literal<CurrentNetwork>, second: Literal<CurrentNetwork>) {
        let true_ = Boolean::<CurrentNetwork>::new(true);
        let false_ = Boolean::<CurrentNetwork>::new(false);
        assert_eq!(first, Literal::ternary(&true_, &first, &second));
        assert_eq!(second, Literal::ternary(&false_, &first, &second));
    }

    #[test]
    fn test_literal_ternary_dispatches_all_supported_variants() {
        let mut rng = TestRng::default();
        check_dispatch(Literal::Address(Address::rand(&mut rng)), Literal::Address(Address::rand(&mut rng)));
        check_dispatch(Literal::Boolean(Boolean::new(true)), Literal::Boolean(Boolean::new(false)));
        check_dispatch(Literal::Field(Field::rand(&mut rng)), Literal::Field(Field::rand(&mut rng)));
        check_dispatch(Literal::Group(Group::rand(&mut rng)), Literal::Group(Group::rand(&mut rng)));
        check_dispatch(Literal::I8(I8::rand(&mut rng)), Literal::I8(I8::rand(&mut rng)));
        check_dispatch(Literal::I16(I16::rand(&mut rng)), Literal::I16(I16::rand(&mut rng)));
        check_dispatch(Literal::I32(I32::rand(&mut rng)), Literal::I32(I32::rand(&mut rng)));
        check_dispatch(Literal::I64(I64::rand(&mut rng)), Literal::I64(I64::rand(&mut rng)));
        check_dispatch(Literal::I128(I128::rand(&mut rng)), Literal::I128(I128::rand(&mut rng)));
        check_dispatch(Literal::U8(U8::rand(&mut rng)), Literal::U8(U8::rand(&mut rng)));
        check_dispatch(Literal::U16(U16::rand(&mut rng)), Literal::U16(U16::rand(&mut rng)));
        check_dispatch(Literal::U32(U32::rand(&mut rng)), Literal::U32(U32::rand(&mut rng)));
        check_dispatch(Literal::U64(U64::rand(&mut rng)), Literal::U64(U64::rand(&mut rng)));
        check_dispatch(Literal::U128(U128::rand(&mut rng)), Literal::U128(U128::rand(&mut rng)));
        check_dispatch(Literal::Scalar(Scalar::rand(&mut rng)), Literal::Scalar(Scalar::rand(&mut rng)));
        check_dispatch(
            Literal::sample(LiteralType::Signature, &mut rng),
            Literal::sample(LiteralType::Signature, &mut rng),
        );
        check_dispatch(
            Literal::sample(LiteralType::Identifier, &mut rng),
            Literal::sample(LiteralType::Identifier, &mut rng),
        );
    }

    #[test]
    #[should_panic(expected = "ternary operands must be the same literal variant")]
    fn test_literal_ternary_variant_mismatch_panics() {
        let mut rng = TestRng::default();
        let first = Literal::<CurrentNetwork>::Field(Field::rand(&mut rng));
        let second = Literal::<CurrentNetwork>::Boolean(Boolean::new(true));
        let cond = Boolean::<CurrentNetwork>::new(false);
        let _ = Literal::ternary(&cond, &first, &second);
    }
}
