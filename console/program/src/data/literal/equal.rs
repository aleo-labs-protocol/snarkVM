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

impl<N: Network> Eq for Literal<N> {}

impl<N: Network> PartialEq for Literal<N> {
    /// Returns `true` if `self` and `other` are equal.
    fn eq(&self, other: &Self) -> bool {
        *self.is_equal(other)
    }
}

impl<N: Network> core::hash::Hash for Literal<N> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::Address(a) => a.hash(state),
            Self::Boolean(a) => a.hash(state),
            Self::Field(a) => a.hash(state),
            Self::Group(a) => a.hash(state),
            Self::I8(a) => a.hash(state),
            Self::I16(a) => a.hash(state),
            Self::I32(a) => a.hash(state),
            Self::I64(a) => a.hash(state),
            Self::I128(a) => a.hash(state),
            Self::U8(a) => a.hash(state),
            Self::U16(a) => a.hash(state),
            Self::U32(a) => a.hash(state),
            Self::U64(a) => a.hash(state),
            Self::U128(a) => a.hash(state),
            Self::Scalar(a) => a.hash(state),
            Self::Signature(a) => a.hash(state),
            Self::String(a) => a.hash(state),
            Self::Identifier(a) => a.hash(state),
        }
    }
}

impl<N: Network> Equal for Literal<N> {
    type Output = Boolean<N>;

    /// Returns `true` if `self` and `other` are equal.
    fn is_equal(&self, other: &Self) -> Self::Output {
        match (self, other) {
            (Self::Address(a), Self::Address(b)) => a.is_equal(b),
            (Self::Boolean(a), Self::Boolean(b)) => a.is_equal(b),
            (Self::Field(a), Self::Field(b)) => a.is_equal(b),
            (Self::Group(a), Self::Group(b)) => a.is_equal(b),
            (Self::I8(a), Self::I8(b)) => a.is_equal(b),
            (Self::I16(a), Self::I16(b)) => a.is_equal(b),
            (Self::I32(a), Self::I32(b)) => a.is_equal(b),
            (Self::I64(a), Self::I64(b)) => a.is_equal(b),
            (Self::I128(a), Self::I128(b)) => a.is_equal(b),
            (Self::U8(a), Self::U8(b)) => a.is_equal(b),
            (Self::U16(a), Self::U16(b)) => a.is_equal(b),
            (Self::U32(a), Self::U32(b)) => a.is_equal(b),
            (Self::U64(a), Self::U64(b)) => a.is_equal(b),
            (Self::U128(a), Self::U128(b)) => a.is_equal(b),
            (Self::Scalar(a), Self::Scalar(b)) => a.is_equal(b),
            (Self::Signature(a), Self::Signature(b)) => a.is_equal(b),
            (Self::String(a), Self::String(b)) => a.is_equal(b),
            (Self::Identifier(a), Self::Identifier(b)) => a.is_equal(b),
            _ => Boolean::new(false),
        }
    }

    /// Returns `true` if `self` and `other` are *not* equal.
    fn is_not_equal(&self, other: &Self) -> Self::Output {
        match (self, other) {
            (Self::Address(a), Self::Address(b)) => a.is_not_equal(b),
            (Self::Boolean(a), Self::Boolean(b)) => a.is_not_equal(b),
            (Self::Field(a), Self::Field(b)) => a.is_not_equal(b),
            (Self::Group(a), Self::Group(b)) => a.is_not_equal(b),
            (Self::I8(a), Self::I8(b)) => a.is_not_equal(b),
            (Self::I16(a), Self::I16(b)) => a.is_not_equal(b),
            (Self::I32(a), Self::I32(b)) => a.is_not_equal(b),
            (Self::I64(a), Self::I64(b)) => a.is_not_equal(b),
            (Self::I128(a), Self::I128(b)) => a.is_not_equal(b),
            (Self::U8(a), Self::U8(b)) => a.is_not_equal(b),
            (Self::U16(a), Self::U16(b)) => a.is_not_equal(b),
            (Self::U32(a), Self::U32(b)) => a.is_not_equal(b),
            (Self::U64(a), Self::U64(b)) => a.is_not_equal(b),
            (Self::U128(a), Self::U128(b)) => a.is_not_equal(b),
            (Self::Scalar(a), Self::Scalar(b)) => a.is_not_equal(b),
            (Self::Signature(a), Self::Signature(b)) => a.is_not_equal(b),
            (Self::String(a), Self::String(b)) => a.is_not_equal(b),
            (Self::Identifier(a), Self::Identifier(b)) => a.is_not_equal(b),
            _ => Boolean::new(true),
        }
    }
}
