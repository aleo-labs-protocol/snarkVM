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

impl<N: Network> Cast<Address<N>> for IdentifierLiteral<N> {
    /// Casts an `IdentifierLiteral` to an `Address`.
    #[inline]
    fn cast(&self) -> Result<Address<N>> {
        self.to_field()?.cast()
    }
}

impl<N: Network> Cast<Boolean<N>> for IdentifierLiteral<N> {
    /// Casts an `IdentifierLiteral` to a `Boolean`.
    ///
    /// Note: This cast always fails because valid identifier literals start with
    /// a letter (first byte >= 0x41), which cannot represent a boolean field value
    /// (0 or 1). This implementation exists for uniformity with the `impl_cast_body!`
    /// macro used by all literal types.
    #[inline]
    fn cast(&self) -> Result<Boolean<N>> {
        self.to_field()?.cast()
    }
}

impl<N: Network> Cast<Field<N>> for IdentifierLiteral<N> {
    /// Casts an `IdentifierLiteral` to a `Field`.
    #[inline]
    fn cast(&self) -> Result<Field<N>> {
        self.to_field()
    }
}

impl<N: Network> Cast<Group<N>> for IdentifierLiteral<N> {
    /// Casts an `IdentifierLiteral` to a `Group`.
    #[inline]
    fn cast(&self) -> Result<Group<N>> {
        self.to_field()?.cast()
    }
}

impl<N: Network, I: IntegerType> Cast<Integer<N, I>> for IdentifierLiteral<N> {
    /// Casts an `IdentifierLiteral` to an `Integer`.
    #[inline]
    fn cast(&self) -> Result<Integer<N, I>> {
        self.to_field()?.cast()
    }
}

impl<N: Network> Cast<Scalar<N>> for IdentifierLiteral<N> {
    /// Casts an `IdentifierLiteral` to a `Scalar`.
    #[inline]
    fn cast(&self) -> Result<Scalar<N>> {
        self.to_field()?.cast()
    }
}

impl<N: Network> Cast<IdentifierLiteral<N>> for IdentifierLiteral<N> {
    /// Casts an `IdentifierLiteral` to itself.
    #[inline]
    fn cast(&self) -> Result<IdentifierLiteral<N>> {
        Ok(*self)
    }
}
