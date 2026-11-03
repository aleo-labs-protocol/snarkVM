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

mod bytes;
mod parse;

use console::{
    network::prelude::*,
    program::{FinalizeType, Register},
};

/// An input statement defines an input argument to a view function, of the form
/// `input {register} as {finalize_type};`.
///
/// View inputs reuse the finalize input shape because view bodies share the finalize
/// command set and therefore the same plaintext-only register model.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Input<N: Network> {
    /// The input register.
    register: Register<N>,
    /// The input finalize type.
    finalize_type: FinalizeType<N>,
}

impl<N: Network> Input<N> {
    /// Returns the input register.
    #[inline]
    pub const fn register(&self) -> &Register<N> {
        &self.register
    }

    /// Returns the input finalize type.
    #[inline]
    pub const fn finalize_type(&self) -> &FinalizeType<N> {
        &self.finalize_type
    }
}

impl<N: Network> TypeName for Input<N> {
    /// Returns the type name as a string.
    #[inline]
    fn type_name() -> &'static str {
        "input"
    }
}

impl<N: Network> Ord for Input<N> {
    /// Ordering is determined by the register (the finalize type is ignored).
    fn cmp(&self, other: &Self) -> Ordering {
        self.register().cmp(other.register())
    }
}

impl<N: Network> PartialOrd for Input<N> {
    /// Ordering is determined by the register (the finalize type is ignored).
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
