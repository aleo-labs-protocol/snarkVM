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

use crate::{Field, LegendreSymbol};

/// The interface for a field that supports an efficient square-root operation.
///
/// Implementing this trait outside snarkVM is not supported. The next major release seals it,
/// which breaks such implementations. Code that needs to implement it should define its own
/// trait instead. Bounds on it and calls through it are unaffected.
pub trait SquareRootField: Field {
    /// Returns the Legendre symbol.
    fn legendre(&self) -> LegendreSymbol;

    /// Returns the square root of self, if it exists.
    #[must_use]
    fn sqrt(&self) -> Option<Self>;

    /// Sets `self` to be the square root of `self`, if it exists.
    fn sqrt_in_place(&mut self) -> Option<&mut Self>;
}
