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

use crate::Operand;

use console::{network::prelude::*, program::FinalizeType};

/// An output statement defines an output of a view function.
/// An output statement is of the form `output {operand} as {finalize_type};`.
///
/// The finalize type carries the same plaintext-only constraints as finalize inputs:
/// futures and dynamic futures are rejected at construction time.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Output<N: Network> {
    /// The output operand.
    operand: Operand<N>,
    /// The output finalize type.
    finalize_type: FinalizeType<N>,
}

impl<N: Network> Output<N> {
    /// Returns the output operand.
    #[inline]
    pub const fn operand(&self) -> &Operand<N> {
        &self.operand
    }

    /// Returns the output finalize type.
    #[inline]
    pub const fn finalize_type(&self) -> &FinalizeType<N> {
        &self.finalize_type
    }
}

impl<N: Network> TypeName for Output<N> {
    #[inline]
    fn type_name() -> &'static str {
        "output"
    }
}
